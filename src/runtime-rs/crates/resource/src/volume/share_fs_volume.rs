// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use agent::Agent;
use agent::{
    CommitVolumeRevisionRequest, CopySingleFileRequest, InitVolumeRequest, PutVolumeFileRevisionRequest,
    SingleFileType,
};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use inotify::{EventMask, Inotify, WatchMask};
use kata_sys_util::mount::{get_mount_options, get_mount_path, get_mount_type};
use nix::sys::stat::SFlag;
use rand::rng;
use rand::Rng;
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time::Instant,
};
use walkdir::WalkDir;

use super::Volume;
use crate::share_fs::kata_guest_share_dir;
use crate::share_fs::{MountedInfo, ShareFs, ShareFsVolumeConfig};
use kata_types::{
    k8s::{is_configmap, is_downward_api, is_projected, is_secret},
    mount,
};
use oci_spec::runtime as oci;

const SYS_MOUNT_PREFIX: [&str; 2] = ["/proc", "/sys"];
const MONITOR_INTERVAL: Duration = Duration::from_millis(100);
const DEBOUNCE_TIME: Duration = Duration::from_millis(500);

const COPY_VOLUME_NETWORK_FILES: &str = "network-files";
const COPY_VOLUME_OTHER_FILES: &str = "other-files";
const COPY_VOLUME_PROJECTED_VOLUMES: &str = "projected-volumes";
const COPY_VOLUME_CONFIGMAP_VOLUMES: &str = "configmap-volumes";
const COPY_VOLUME_SECRET_VOLUMES: &str = "secret-volumes";
const COPY_VOLUME_DOWNWARD_API_VOLUMES: &str = "downward-api-volumes";
const COPY_VOLUME_OTHER_DIRECTORIES: &str = "other-directories";
const NETWORK_FILE_NAMES: [&str; 3] = ["resolv.conf", "hosts", "hostname"];
const TERMINATION_LOG_DESTINATION: &str = "/dev/termination-log";
const BIND_SAFER_PATH: &str = "bind-safer-path";
const WATCHABLE_DATA_SYMLINK: &str = "..data";

// Corresponds to os.FileMode(0750) | os.ModeDir in Go
// So, it's (permission bits 0o750) ORed with (file type bit S_IFDIR).
// We use u32 here because `file_mode` in CopyFileRequest is u32
const DIR_MODE_PERMS: u32 = SFlag::S_IFDIR.bits() | 0o750;

// copy file to container's rootfs if filesystem sharing is not supported, otherwise
// bind mount it in the shared directory.
// Ignore /dev, directories and all other device files. We handle
// only regular files in /dev. It does not make sense to pass the host
// device nodes to the guest.
// skip the volumes whose source had already set to guest share dir.
pub(crate) struct ShareFsVolume {
    share_fs: Option<Arc<dyn ShareFs>>,
    mounts: Vec<oci::Mount>,
    storages: Vec<agent::Storage>,

    // Add volume manager reference
    volume_manager: Option<Arc<VolumeManager>>,
    // Record the source path for cleanup
    source_path: Option<String>,
    // Record the container ID
    container_id: String,
}

/// Directory Monitor Config
/// path: the to be watched target directory
/// recursive: recursively monitor sub-dirs or not,
/// follow_symlinks: track symlinks or not,
/// exclude_hidden: exclude hidden files or not,
/// watch_events: Watcher Event types with CREATE/DELETE/MODIFY/MOVED_FROM/MOVED_TO
#[derive(Clone, Debug)]
struct MonitorConfig {
    path: PathBuf,
    recursive: bool,
    follow_symlinks: bool,
    exclude_hidden: bool,
    watch_events: WatchMask,
}

impl MonitorConfig {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            recursive: true,
            follow_symlinks: false,
            exclude_hidden: true,
            watch_events: WatchMask::CREATE
                | WatchMask::DELETE
                | WatchMask::MODIFY
                | WatchMask::MOVED_FROM
                | WatchMask::MOVED_TO
                | WatchMask::CLOSE_WRITE,
        }
    }
}

#[derive(Clone)]
struct FsWatcher {
    config: MonitorConfig,
    inotify: Arc<Mutex<Inotify>>,
    watch_dirs: Arc<Mutex<HashSet<PathBuf>>>,
    pending_events: Arc<Mutex<HashSet<PathBuf>>>,
    need_sync: Arc<Mutex<bool>>,
}

impl FsWatcher {
    async fn new(source_path: &Path) -> Result<Self> {
        let inotify = Inotify::init()?;
        let mon_cfg = MonitorConfig::new(source_path);
        let mut watcher = Self {
            config: mon_cfg,
            inotify: Arc::new(Mutex::new(inotify)),
            pending_events: Arc::new(Mutex::new(HashSet::new())),
            watch_dirs: Arc::new(Mutex::new(HashSet::new())),
            need_sync: Arc::new(Mutex::new(false)),
        };

        watcher.add_watchers().await?;

        Ok(watcher)
    }

    /// add watched directory recursively
    async fn add_watchers(&mut self) -> Result<()> {
        let mut watched_dirs = self.watch_dirs.lock().await;
        let config: &MonitorConfig = &self.config;
        let walker = WalkDir::new(&config.path)
            .follow_links(config.follow_symlinks)
            .min_depth(0)
            .max_depth(if config.recursive { usize::MAX } else { 1 })
            .into_iter()
            .filter_entry(|e| {
                !(config.exclude_hidden
                    && e.file_name()
                        .to_str()
                        .map(|s| s.starts_with('.'))
                        .unwrap_or(false))
            });

        for entry in walker.filter_map(|e| e.ok()) {
            if entry.file_type().is_dir() {
                let path = entry.path();
                if watched_dirs.insert(path.to_path_buf()) {
                    self.inotify
                        .lock()
                        .await
                        .watches()
                        .add(path, config.watch_events)?; // we don't use WatchMask::ALL_EVENTS
                }
            }
        }

        Ok(())
    }

    pub async fn start_watchable_monitor(
        &self,
        agent: Arc<dyn Agent>,
        src: PathBuf,
        agent_volume_id: String,
    ) -> JoinHandle<()> {
        let need_sync = self.need_sync.clone();
        let pending_events = self.pending_events.clone();
        let inotify = self.inotify.clone();
        let monitor_config = self.config.clone();

        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            let mut last_event_time = None;

            loop {
                match inotify.lock().await.read_events(&mut buffer) {
                    Ok(events) => {
                        for event in events {
                            if !event.mask.intersects(
                                EventMask::CREATE
                                    | EventMask::MODIFY
                                    | EventMask::DELETE
                                    | EventMask::MOVED_FROM
                                    | EventMask::MOVED_TO
                                    | EventMask::CLOSE_WRITE,
                            ) {
                                continue;
                            }

                            if let Some(file_name) = event.name {
                                let full_path = &monitor_config.path.join(file_name);
                                pending_events.lock().await.insert(full_path.clone());
                            }
                        }
                    }
                    Err(e) => eprintln!("inotify error: {e}"),
                }

                let events_paths = {
                    let mut pending = pending_events.lock().await;
                    pending.drain().collect::<Vec<_>>()
                };
                if !events_paths.is_empty() {
                    *need_sync.lock().await = true;
                    last_event_time = Some(Instant::now());
                }

                if let Some(t) = last_event_time {
                    if Instant::now().duration_since(t) > DEBOUNCE_TIME && *need_sync.lock().await {
                        if let Err(e) =
                            sync_watchable_volume_revision(&src, &agent_volume_id, &agent).await
                        {
                            error!(
                                sl!(),
                                "watchable volume sync failed for {:?}: {:?}", &src, e
                            );
                        }
                        *need_sync.lock().await = false;
                        last_event_time = None;
                    }
                }

                tokio::time::sleep(MONITOR_INTERVAL).await;
            }
        })
    }
}

//==========volume manager==============
/// Sandbox-level volume state manager
/// Tracks which paths have been copied to the guest on the runtime side
#[derive(Clone, Default)]
pub struct VolumeManager {
    // Mapping of source path -> volume state
    volume_states: Arc<RwLock<HashMap<String, VolumeState>>>,
}

#[derive(Clone, Debug, Default)]
struct VolumeState {
    // Source path (on the host)
    source_path: String,
    // Guest path
    guest_path: String,
    // Reference count (how many containers are using it)
    ref_count: usize,
    // List of container IDs using this volume
    containers: HashSet<String>,
    // Monitor task handle (if any)
    monitor_task: Option<Arc<JoinHandle<()>>>,
}

#[allow(dead_code)]
impl VolumeManager {
    pub fn new() -> Self {
        Self {
            volume_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Gets or creates the volume's guest path
    pub async fn get_or_create_volume(
        &self,
        canonical_source: &str,
        container_id: &str,
        mount_destination: &Path,
    ) -> Result<String> {
        let mut states = self.volume_states.write().await;

        if let Some(state) = states.get_mut(canonical_source) {
            // Existing volume and update reference
            state.ref_count += 1;
            state.containers.insert(container_id.to_string());

            info!(
                sl!(),
                "Existing volume: source={:?}, guest={:?}, ref_count={}",
                canonical_source,
                state.guest_path,
                state.ref_count,
            );
        }

        // Create a new volume state
        let guest_path =
            generate_guest_path(container_id, mount_destination).context("generate path failed")?;

        let mut containers = HashSet::new();
        containers.insert(container_id.to_string());

        let state = VolumeState {
            source_path: canonical_source.to_string(),
            guest_path: guest_path.clone(),
            ref_count: 1,
            containers,
            monitor_task: None,
        };

        states.insert(state.source_path.clone(), state.clone());

        info!(
            sl!(),
            "Created new volume state: source={:?}, guest={:?}",
            state.source_path,
            state.guest_path,
        );

        // Return guest path
        Ok(guest_path)
    }

    /// Register monitor task into the volume manager
    pub async fn register_monitor(
        &self,
        canonical_source: &str,
        monitor_task: Option<JoinHandle<()>>,
    ) -> Result<()> {
        let mut states = self.volume_states.write().await;

        if let Some(state) = states.get_mut(canonical_source) {
            if let Some(handle) = monitor_task {
                state.monitor_task = Some(Arc::new(handle));
            }
        }

        Ok(())
    }

    /// Releases a volume reference
    pub async fn release_volume(&self, source_path: &str, container_id: &str) -> Result<bool> {
        let mut states = self.volume_states.write().await;

        let canonical_source = std::fs::canonicalize(source_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| source_path.to_string());

        if let Some(state) = states.get_mut(&canonical_source) {
            state.containers.remove(container_id);
            state.ref_count = state.ref_count.saturating_sub(1);

            if state.ref_count == 0 {
                // Abort the monitor task
                if let Some(handle) = &state.monitor_task {
                    handle.abort();
                }

                info!(
                    sl!(),
                    "Volume has no more references, source={:?}, guest={:?}",
                    canonical_source,
                    state.guest_path
                );

                return Ok(true); // Can be cleaned up
            }
        }

        Ok(false)
    }
}

impl ShareFsVolume {
    async fn copy_single_file_to_guest(
        src: &Path,
        sid: &str,
        agent: &Arc<dyn Agent>,
        copy_data: bool,
    ) -> Result<String> {
        let file_metadata = regular_file_metadata(src)?;

        let mut buffer = Vec::new();
        if copy_data {
            let mut file = File::open(src).with_context(|| format!("Failed to open file: {src:?}"))?;
            file.read_to_end(&mut buffer)
                .with_context(|| format!("Failed to read file: {src:?}"))?;
        }

        let req = CopySingleFileRequest {
            sandbox_id: sid.to_string(),
            file_type: if copy_data {
                single_file_type_from_mount(src)?
            } else {
                SingleFileType::Unspecified
            },
            uid: file_metadata.uid() as i32,
            gid: file_metadata.gid() as i32,
            data_size: if copy_data { file_metadata.len() as i64 } else { 0 },
            data: buffer,
            file_mode: file_metadata.mode(),
        };

        let resp = agent
            .copy_single_file(req)
            .await
            .with_context(|| format!("copy single file request failed for {src:?}"))?;

        Ok(resp.agent_file_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        share_fs: &Option<Arc<dyn ShareFs>>,
        m: &oci::Mount,
        cid: &str,
        sid: &str,
        readonly: bool,
        agent: Arc<dyn Agent>,
        volume_manager: Arc<VolumeManager>,
        copy_volume_types: Option<&HashSet<String>>,
    ) -> Result<Self> {
        // The file_name is in the format of "sandbox-{uuid}-{file_name}"
        let source_path = get_mount_path(m.source());
        let file_name = Path::new(&source_path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        let file_name = generate_mount_path("sandbox", file_name);

        let mut volume = Self {
            share_fs: share_fs.as_ref().map(Arc::clone),
            mounts: vec![],
            storages: vec![],
            volume_manager: Some(volume_manager.clone()),
            source_path: Some(source_path.clone()),
            container_id: cid.to_string(),
        };

        match share_fs {
            None => {
                let src = match std::fs::canonicalize(&source_path) {
                    Err(err) => {
                        return Err(anyhow!(format!(
                            "failed to canonicalize file {} {:?}",
                            &source_path, err
                        )))
                    }
                    Ok(src) => src,
                };

                let copy_empty_other_file = should_copy_empty_other_file(
                    &src,
                    m.destination(),
                    copy_volume_types,
                );
                if !should_copy_volume(&src, m.destination(), copy_volume_types)
                    && !copy_empty_other_file
                {
                    info!(
                        sl!(),
                        "skipping host->guest copy for {:?} because it is disabled by copy_volumes",
                        &src
                    );
                    return Ok(volume);
                }

                // append oci::Mount structure to volume mounts
                let mut oci_mount = oci::Mount::default();
                oci_mount.set_destination(m.destination().clone());
                oci_mount.set_typ(Some("bind".to_string()));
                oci_mount.set_options(m.options().clone());

                // If the mount source is a file, we can copy it to the sandbox
                if src.is_file() {
                    let agent_file_id = Self::copy_single_file_to_guest(
                        Path::new(&source_path),
                        sid,
                        &agent,
                        !copy_empty_other_file,
                    )
                    .await
                    .context("copy single file to guest")?;

                    oci_mount.set_typ(Some(BIND_SAFER_PATH.to_string()));
                    oci_mount.set_source(Some(PathBuf::from(agent_file_id)));
                    volume.mounts.push(oci_mount);
                } else if src.is_dir() {
                    let init_resp = agent
                        .init_volume(InitVolumeRequest {
                            host_volume_id: src.to_string_lossy().to_string(),
                        })
                        .await
                        .context("init watchable volume")?;

                    sync_watchable_volume_revision(&src, &init_resp.agent_volume_id, &agent)
                        .await
                        .context("sync watchable volume")?;

                    oci_mount.set_typ(Some(BIND_SAFER_PATH.to_string()));
                    oci_mount.set_source(Some(PathBuf::from(&init_resp.agent_volume_id)));
                    volume.mounts.push(oci_mount);

                    let watcher = FsWatcher::new(&src).await?;
                    let handle = watcher
                        .start_watchable_monitor(
                            agent.clone(),
                            src.clone(),
                            init_resp.agent_volume_id.clone(),
                        )
                        .await;

                    volume_manager
                        .register_monitor(&src.to_string_lossy(), Some(handle))
                        .await?;
                } else {
                    // If not, we can ignore it. Let's issue a warning so that the user knows.
                    warn!(
                        sl!(),
                        "Ignoring non-regular file as FS sharing not supported. mount: {:?}", m
                    );
                }
            }
            Some(share_fs) => {
                let share_fs_mount = share_fs.get_share_fs_mount();
                let mounted_info_set = share_fs.mounted_info_set();
                let mut mounted_info_set = mounted_info_set.lock().await;
                if let Some(mut mounted_info) = mounted_info_set.get(&source_path).cloned() {
                    // Mounted at least once
                    let guest_path = mounted_info
                        .guest_path
                        .clone()
                        .as_os_str()
                        .to_str()
                        .unwrap()
                        .to_owned();
                    if !readonly && mounted_info.readonly() {
                        // The current mount should be upgraded to readwrite permission
                        info!(
                            sl!(),
                            "The mount will be upgraded, mount = {:?}, cid = {}", m, cid
                        );
                        share_fs_mount
                            .upgrade_to_rw(
                                &mounted_info
                                    .file_name()
                                    .context("get name of mounted info")?,
                            )
                            .await
                            .context("upgrade mount")?;
                    }
                    if readonly {
                        mounted_info.ro_ref_count += 1;
                    } else {
                        mounted_info.rw_ref_count += 1;
                    }
                    mounted_info_set.insert(source_path.clone(), mounted_info);

                    let mut oci_mount = oci::Mount::default();
                    oci_mount.set_destination(m.destination().clone());
                    oci_mount.set_typ(Some("bind".to_string()));
                    oci_mount.set_source(Some(PathBuf::from(&guest_path)));
                    oci_mount.set_options(m.options().clone());

                    volume.mounts.push(oci_mount);
                } else {
                    // Not mounted ever
                    let mount_result = share_fs_mount
                        .share_volume(&ShareFsVolumeConfig {
                            // The scope of shared volume is sandbox
                            cid: String::from(""),
                            source: source_path.clone(),
                            target: file_name.clone(),
                            readonly,
                            mount_options: get_mount_options(m.options()).clone(),
                            mount: m.clone(),
                            is_rafs: false,
                        })
                        .await
                        .context("mount shared volume")?;
                    let mounted_info = MountedInfo::new(
                        PathBuf::from_str(&mount_result.guest_path)
                            .context("convert guest path")?,
                        readonly,
                    );
                    mounted_info_set.insert(source_path.clone(), mounted_info);
                    // set storages for the volume
                    volume.storages = mount_result.storages;

                    // set mount for the volume
                    let mut oci_mount = oci::Mount::default();
                    oci_mount.set_destination(m.destination().clone());
                    oci_mount.set_typ(Some("bind".to_string()));
                    oci_mount.set_source(Some(PathBuf::from(&mount_result.guest_path)));
                    oci_mount.set_options(m.options().clone());

                    volume.mounts.push(oci_mount);
                }
            }
        }
        Ok(volume)
    }
}

fn regular_file_metadata(src: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(src)
        .with_context(|| format!("Failed to read metadata from file: {src:?}"))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "copy single file source is not a regular file: {src:?}"
        ));
    }

    Ok(metadata)
}

fn single_file_type_from_mount(src: &Path) -> Result<SingleFileType> {
    let file_name = src
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("get file name failed for {src:?}"))?;

    let file_type = match file_name {
        "resolv.conf" => SingleFileType::ResolvConf,
        "hosts" => SingleFileType::EtcHosts,
        "hostname" => SingleFileType::Hostname,
        _ => SingleFileType::Unspecified,
    };

    Ok(file_type)
}

async fn sync_watchable_volume_revision(
    src: &Path,
    agent_volume_id: &str,
    agent: &Arc<dyn Agent>,
) -> Result<()> {
    let revision_link = src.join(WATCHABLE_DATA_SYMLINK);
    let revision = std::fs::read_link(&revision_link)
        .with_context(|| format!("read watchable data symlink: {revision_link:?}"))?;
    let revision_str = revision
        .to_str()
        .ok_or_else(|| anyhow!("revision is not valid UTF-8: {revision:?}"))?
        .to_string();

    let revision_dir = src.join(&revision);
    let walker = WalkDir::new(&revision_dir)
        .follow_links(false)
        .min_depth(1)
        .into_iter();

    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }

        let entry_path = entry.path().to_path_buf();
        let metadata = std::fs::metadata(&entry_path)
            .with_context(|| format!("read metadata for watchable file {entry_path:?}"))?;

        let rel_path = entry_path
            .strip_prefix(&revision_dir)
            .with_context(|| format!("strip prefix for watchable file {entry_path:?}"))?
            .to_string_lossy()
            .to_string();

        let mut file = tokio::fs::File::open(&entry_path)
            .await
            .with_context(|| format!("open watchable file {entry_path:?}"))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .await
            .with_context(|| format!("read watchable file {entry_path:?}"))?;

        agent
            .put_volume_file_revision(PutVolumeFileRevisionRequest {
                agent_volume_id: agent_volume_id.to_string(),
                file_name: rel_path,
                file_size: metadata.len() as i64,
                file_mode: metadata.mode(),
                uid: metadata.uid() as i32,
                gid: metadata.gid() as i32,
                offset: 0,
                data,
                revision: revision_str.clone(),
                dir_mode: DIR_MODE_PERMS,
            })
            .await
            .with_context(|| format!("put watchable file {entry_path:?}"))?;
    }

    agent
        .commit_volume_revision(CommitVolumeRevisionRequest {
            agent_volume_id: agent_volume_id.to_string(),
            garbage_collect_previous: true,
        })
        .await
        .context("commit watchable revision")?;

    Ok(())
}

fn should_copy_volume(
    src: &Path,
    destination: &Path,
    copy_volume_types: Option<&HashSet<String>>,
) -> bool {
    let Some(enabled_types) = copy_volume_types else {
        return true;
    };

    enabled_types.contains(classify_copy_volume(src, destination))
}

fn should_copy_empty_other_file(
    src: &Path,
    destination: &Path,
    copy_volume_types: Option<&HashSet<String>>,
) -> bool {
    if !src.is_file() {
        return false;
    }

    if destination == Path::new(TERMINATION_LOG_DESTINATION) {
        return true;
    }

    if classify_copy_volume(src, destination) != COPY_VOLUME_OTHER_FILES {
        return false;
    }

    copy_volume_types.is_some_and(|enabled_types| {
        !enabled_types.contains(COPY_VOLUME_OTHER_FILES)
    })
}

fn classify_copy_volume(src: &Path, _destination: &Path) -> &'static str {
    if src.is_file() {
        let file_name = src
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if NETWORK_FILE_NAMES.contains(&file_name) {
            return COPY_VOLUME_NETWORK_FILES;
        }
        return COPY_VOLUME_OTHER_FILES;
    }

    if is_projected(src) {
        return COPY_VOLUME_PROJECTED_VOLUMES;
    }
    if is_configmap(src) {
        return COPY_VOLUME_CONFIGMAP_VOLUMES;
    }
    if is_secret(src) {
        return COPY_VOLUME_SECRET_VOLUMES;
    }
    if is_downward_api(src) {
        return COPY_VOLUME_DOWNWARD_API_VOLUMES;
    }

    COPY_VOLUME_OTHER_DIRECTORIES
}

#[async_trait]
impl Volume for ShareFsVolume {
    fn get_volume_mount(&self) -> anyhow::Result<Vec<oci::Mount>> {
        Ok(self.mounts.clone())
    }

    fn get_storage(&self) -> Result<Vec<agent::Storage>> {
        Ok(self.storages.clone())
    }

    async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
        let share_fs = match self.share_fs.as_ref() {
            Some(fs) => fs,
            None => {
                return {
                    // Release volume reference
                    if let (Some(manager), Some(source)) = (&self.volume_manager, &self.source_path)
                    {
                        let should_cleanup =
                            manager.release_volume(source, &self.container_id).await?;

                        if should_cleanup {
                            info!(
                                sl!(),
                                "Volume {:?} has no more references, can be cleaned up", source
                            );
                            // NOTE: We cannot delete files from the guest because there is no corresponding API
                            // Files will be cleaned up automatically when the sandbox is destroyed
                        }
                    }
                    Ok(())
                };
            }
        };

        let mounted_info_set = share_fs.mounted_info_set();
        let mut mounted_info_set = mounted_info_set.lock().await;
        for m in self.mounts.iter() {
            let (host_source, mut mounted_info) = match mounted_info_set
                .iter()
                .find(|entry| {
                    entry.1.guest_path.as_os_str().to_str().unwrap() == get_mount_path(m.source())
                })
                .map(|entry| (entry.0.to_owned(), entry.1.clone()))
            {
                Some(entry) => entry,
                None => {
                    warn!(
                        sl!(),
                        "The mounted info for guest path {} not found",
                        &get_mount_path(m.source())
                    );
                    continue;
                }
            };

            let old_readonly = mounted_info.readonly();
            if get_mount_options(m.options()).contains(&"ro".to_owned()) {
                mounted_info.ro_ref_count -= 1;
            } else {
                mounted_info.rw_ref_count -= 1;
            }

            debug!(
                sl!(),
                "Ref count for {} was updated to {} due to volume cleanup",
                host_source,
                mounted_info.ref_count()
            );
            let share_fs_mount = share_fs.get_share_fs_mount();
            let file_name = mounted_info.file_name()?;

            if mounted_info.ref_count() > 0 {
                // Downgrade to readonly if no container needs readwrite permission
                if !old_readonly && mounted_info.readonly() {
                    info!(sl!(), "Downgrade {} to readonly due to no container that needs readwrite permission", host_source);
                    share_fs_mount
                        .downgrade_to_ro(&file_name)
                        .await
                        .context("Downgrade volume")?;
                }
                mounted_info_set.insert(host_source.clone(), mounted_info);
            } else {
                info!(
                    sl!(),
                    "The path will be umounted due to no references, host_source = {}", host_source
                );
                mounted_info_set.remove(&host_source);
                // Umount the volume
                share_fs_mount
                    .umount_volume(&file_name)
                    .await
                    .context("Umount volume")?
            }
        }

        Ok(())
    }

    fn get_device_id(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

pub(crate) fn is_share_fs_volume(m: &oci::Mount) -> bool {
    let mount_type = get_mount_type(m);
    (mount_type == "bind" || mount_type == mount::KATA_EPHEMERAL_VOLUME_TYPE)
        && !is_host_device(&get_mount_path(&Some(m.destination().clone())))
        && !is_system_mount(&get_mount_path(m.source()))
}

fn is_host_device(dest: &str) -> bool {
    if dest == "/dev" {
        return true;
    }

    if dest.starts_with("/dev/") {
        let src = match std::fs::canonicalize(dest) {
            Err(_) => return false,
            Ok(src) => src,
        };

        if src.is_file() {
            return false;
        }

        return true;
    }

    false
}

// Skip mounting certain system paths("/sys/*", "/proc/*")
// from source on the host side into the container as it does not
// make sense to do so.
// Agent will support this kind of bind mount.
fn is_system_mount(src: &str) -> bool {
    for p in SYS_MOUNT_PREFIX {
        let sub_dir_p = format!("{p}/");
        if src == p || src.contains(sub_dir_p.as_str()) {
            return true;
        }
    }
    false
}

// Note, don't generate random name, attaching rafs depends on the predictable name.
pub fn generate_mount_path(id: &str, file_name: &str) -> String {
    let mut nid = String::from(id);
    if nid.len() > 10 {
        nid = nid.chars().take(10).collect();
    }

    let mut uid = uuid::Uuid::new_v4().to_string();
    let uid_vec: Vec<&str> = uid.splitn(2, '-').collect();
    uid = String::from(uid_vec[0]);

    format!("{nid}-{uid}-{file_name}")
}

/// Generates a guest path related to mount dest
fn generate_guest_path(cid: &str, mount_destination: &Path) -> Result<String> {
    let mut data = vec![0u8; 8];
    let mut rng = rng(); // Get a thread-local RNG
    rng.fill_bytes(&mut data);

    let hex_str = hex::encode(data);
    let dest_base = mount_destination
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("get mount destination failed"))?;

    Ok(format!(
        "{}{}-{}-{}",
        kata_guest_share_dir(),
        cid,
        hex_str,
        dest_base
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_path(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::new();
        for p in parts {
            path.push(p);
        }
        path
    }

    #[test]
    fn test_is_system_mount() {
        let sys_dir = "/sys";
        let proc_dir = "/proc";
        let sys_sub_dir = "/sys/fs/cgroup";
        let proc_sub_dir = "/proc/cgroups";
        let not_sys_dir = "/root";

        assert!(is_system_mount(sys_dir));
        assert!(is_system_mount(proc_dir));
        assert!(is_system_mount(sys_sub_dir));
        assert!(is_system_mount(proc_sub_dir));
        assert!(!is_system_mount(not_sys_dir));
    }

    #[test]
    fn test_classify_copy_volume() {
        let temp_dir = tempfile::tempdir().unwrap();

        let network_file = temp_dir.path().join("resolv.conf");
        std::fs::write(&network_file, b"nameserver 1.1.1.1\n").unwrap();

        let other_file = temp_dir.path().join("termination-log");
        std::fs::write(&other_file, b"terminated\n").unwrap();

        let projected = temp_dir.path().join(test_path(&[
            "var",
            "lib",
            "kubelet",
            "pods",
            "1000",
            "volumes",
            "kubernetes.io~projected",
            "kube-api-access-8s2nl",
        ]));
        std::fs::create_dir_all(&projected).unwrap();

        let configmap = temp_dir.path().join(test_path(&[
            "var",
            "lib",
            "kubelet",
            "pods",
            "1000",
            "volumes",
            "kubernetes.io~configmap",
            "kube-configmap-0s2no",
        ]));
        std::fs::create_dir_all(&configmap).unwrap();

        let secret = temp_dir.path().join(test_path(&[
            "var",
            "lib",
            "kubelet",
            "pods",
            "1000",
            "volumes",
            "kubernetes.io~secret",
            "kube-secret-2s2np",
        ]));
        std::fs::create_dir_all(&secret).unwrap();

        let downward_api = temp_dir.path().join(test_path(&[
            "var",
            "lib",
            "kubelet",
            "pods",
            "1000",
            "volumes",
            "kubernetes.io~downward-api",
            "downward-api-xxxx",
        ]));
        std::fs::create_dir_all(&downward_api).unwrap();

        let other_directory = temp_dir.path().join(test_path(&["mnt", "nfs", "data"]));
        std::fs::create_dir_all(&other_directory).unwrap();

        assert_eq!(
            classify_copy_volume(&network_file, Path::new("/etc/resolv.conf")),
            COPY_VOLUME_NETWORK_FILES
        );
        assert_eq!(
            classify_copy_volume(&other_file, Path::new("/tmp/termination-log")),
            COPY_VOLUME_OTHER_FILES
        );
        assert_eq!(
            classify_copy_volume(&other_file, Path::new(TERMINATION_LOG_DESTINATION)),
            COPY_VOLUME_OTHER_FILES
        );
        assert_eq!(
            classify_copy_volume(&projected, Path::new("/var/run/projected")),
            COPY_VOLUME_PROJECTED_VOLUMES
        );
        assert_eq!(
            classify_copy_volume(&configmap, Path::new("/config")),
            COPY_VOLUME_CONFIGMAP_VOLUMES
        );
        assert_eq!(
            classify_copy_volume(&secret, Path::new("/secret")),
            COPY_VOLUME_SECRET_VOLUMES
        );
        assert_eq!(
            classify_copy_volume(&downward_api, Path::new("/downward")),
            COPY_VOLUME_DOWNWARD_API_VOLUMES
        );
        assert_eq!(
            classify_copy_volume(&other_directory, Path::new("/mnt")),
            COPY_VOLUME_OTHER_DIRECTORIES
        );
    }

    #[test]
    fn test_should_copy_volume() {
        let mut enabled = HashSet::new();
        enabled.insert(COPY_VOLUME_NETWORK_FILES.to_string());
        enabled.insert(COPY_VOLUME_PROJECTED_VOLUMES.to_string());

        let temp_dir = tempfile::tempdir().unwrap();

        let resolv = temp_dir.path().join("resolv.conf");
        std::fs::write(&resolv, b"nameserver 1.1.1.1\n").unwrap();

        let other_file = temp_dir.path().join("termination-log");
        std::fs::write(&other_file, b"terminated\n").unwrap();

        let projected = temp_dir.path().join(test_path(&[
            "var",
            "lib",
            "kubelet",
            "pods",
            "1000",
            "volumes",
            "kubernetes.io~projected",
            "kube-api-access-8s2nl",
        ]));
        std::fs::create_dir_all(&projected).unwrap();

        assert!(should_copy_volume(
            &resolv,
            Path::new("/etc/resolv.conf"),
            Some(&enabled)
        ));
        assert!(should_copy_volume(
            &projected,
            Path::new("/projected"),
            Some(&enabled)
        ));
        assert!(!should_copy_volume(
            &other_file,
            Path::new("/tmp/termination-log"),
            Some(&enabled)
        ));
        assert!(should_copy_volume(
            &other_file,
            Path::new("/tmp/termination-log"),
            None
        ));

        assert!(should_copy_volume(
            &other_file,
            Path::new(TERMINATION_LOG_DESTINATION),
            None
        ));
    }

    #[test]
    fn test_termination_log_uses_empty_single_file_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source = temp_dir.path().join("termination-log");
        std::fs::write(&source, b"host content").unwrap();
        let destination = PathBuf::from(TERMINATION_LOG_DESTINATION);

        assert_eq!(
            single_file_type_from_mount(&source).unwrap(),
            SingleFileType::Unspecified
        );

        let mut enabled = HashSet::new();
        enabled.insert(COPY_VOLUME_OTHER_FILES.to_string());
        assert!(should_copy_empty_other_file(
            &source,
            &destination,
            Some(&enabled)
        ));
    }

    #[test]
    fn test_termination_log_no_longer_uses_a_dedicated_single_file_type() {
        // The termination log is handled on the other-files path now, so it is
        // no longer mapped to SingleFileType::TerminationLog.
        let source = PathBuf::from("/var/lib/kubelet/pods/1000/termination-log");

        assert_eq!(
            single_file_type_from_mount(&source).unwrap(),
            SingleFileType::Unspecified
        );
    }

    #[test]
    fn test_other_file_gets_an_unspecified_kind() {
        let source = PathBuf::from("/var/lib/kubelet/pods/1000/payload.bin");

        assert_eq!(
            single_file_type_from_mount(&source).unwrap(),
            SingleFileType::Unspecified
        );
    }

    #[test]
    fn test_disabled_other_file_uses_empty_single_file_path() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source = temp_dir.path().join("other-file");
        std::fs::write(&source, b"content").unwrap();
        let destination = Path::new("/tmp/other-file");

        assert!(should_copy_empty_other_file(
            &source,
            destination,
            Some(&HashSet::new())
        ));
        assert!(!should_copy_empty_other_file(&source, destination, None));

        let mut enabled = HashSet::new();
        enabled.insert(COPY_VOLUME_OTHER_FILES.to_string());
        assert!(!should_copy_empty_other_file(
            &source,
            destination,
            Some(&enabled)
        ));
    }

    #[test]
    fn test_copy_single_file_rejects_symlink() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        let source = temp_dir.path().join("resolv.conf");
        std::fs::write(&target, b"nameserver 1.1.1.1\n").unwrap();
        std::os::unix::fs::symlink(&target, &source).unwrap();

        assert!(regular_file_metadata(&source).is_err());
    }
}
