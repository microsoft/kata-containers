// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use agent::Agent;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use inotify::{EventMask, Inotify, WatchMask};
use kata_sys_util::mount::{get_mount_options, get_mount_path, get_mount_type};
use nix::sys::stat::SFlag;
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time::Instant,
};
use walkdir::WalkDir;

use super::Volume;
use crate::share_fs::{MountedInfo, ShareFs, ShareFsVolumeConfig};
use kata_types::{
    k8s::{is_configmap, is_downward_api, is_projected, is_secret},
    mount,
};
use oci_spec::runtime as oci;

const SYS_MOUNT_PREFIX: [&str; 2] = ["/proc", "/sys"];
const MONITOR_INTERVAL: Duration = Duration::from_millis(100);
const DEBOUNCE_TIME: Duration = Duration::from_millis(500);

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
    agent: Arc<dyn Agent>,

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

    /// start monitor
    pub async fn start_monitor(
        &self,
        agent: Arc<dyn Agent>,
        src: PathBuf,
        agent_volume_id: String,
    ) -> JoinHandle<()> {
        let need_sync = self.need_sync.clone();
        let pending_events = self.pending_events.clone();
        let inotify = self.inotify.clone();
        let monitor_config = self.config.clone();

        // Perform a full sync before starting monitoring to ensure that files which exist before monitoring starts are also synced.
        let agent_sync = agent.clone();
        let src_sync = src.clone();
        let volume_id_sync = agent_volume_id.clone();

        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            let mut last_event_time = None;

            // Initial sync: ensure existing contents in the directory are synchronized.
            // start_monitor is only called for AtomicK8s (watchable) volumes, so we
            // always skip symlinks and let the agent reconstruct them.
            {
                info!(
                    sl!(),
                    "Initial sync from {:?} to managed volume {:?}", &src_sync, &volume_id_sync
                );
                if let Err(e) =
                    copy_dir_recursively(&src_sync, &src_sync, &volume_id_sync, &agent_sync, true)
                        .await
                {
                    error!(sl!(), "Initial sync failed: {:?}", e);
                } else {
                    let commit_req = agent::CommitVolumeRevisionRequest {
                        agent_volume_id: volume_id_sync.clone(),
                        garbage_collect_previous: true,
                    };
                    if let Err(e) = agent_sync.commit_volume_revision(commit_req).await {
                        error!(sl!(), "Initial commit_volume_revision failed: {:?}", e);
                    }
                }
            }

            loop {
                // use cloned inotify instance
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
                                let event_types: Vec<&str> = event
                                    .mask
                                    .iter()
                                    .map(|m| match m {
                                        EventMask::CREATE => "CREATE",
                                        EventMask::DELETE => "DELETE",
                                        EventMask::MODIFY => "MODIFY",
                                        EventMask::MOVED_FROM => "MOVED_FROM",
                                        EventMask::MOVED_TO => "MOVED_TO",
                                        EventMask::CLOSE_WRITE => "CLOSE_WRITE",
                                        _ => "OTHER",
                                    })
                                    .collect();

                                info!(
                                    sl!(),
                                    "handle events [{}] {:?} -> {:?}",
                                    event_types.join("|"),
                                    event.mask,
                                    full_path
                                );
                                pending_events.lock().await.insert(full_path.clone());
                            }
                        }
                    }
                    Err(e) => eprintln!("inotify error: {e}"),
                }

                // handle events to be synchronized
                let events_paths = {
                    let mut pending = pending_events.lock().await;
                    pending.drain().collect::<Vec<_>>()
                };
                if !events_paths.is_empty() {
                    *need_sync.lock().await = true;
                    last_event_time = Some(Instant::now());
                }

                // Debounce handling
                // It is used to prevent unnecessary repeated copies when file changes are triggered
                // multiple times in a short period; we only execute the last one.
                if let Some(t) = last_event_time {
                    if Instant::now().duration_since(t) > DEBOUNCE_TIME && *need_sync.lock().await {
                        info!(
                            sl!(),
                            "debounce sync {:?} -> managed volume {:?}", &src, &agent_volume_id
                        );
                        // Skip symlinks: agent reconstructs them from the file paths.
                        let sync_ok = copy_dir_recursively(
                            &src,
                            &src,
                            &agent_volume_id,
                            &agent,
                            true,
                        )
                        .await;
                        match sync_ok {
                            Err(e) => {
                                error!(
                                    sl!(),
                                    "debounce volume sync {:?} -> {:?} failed with error: {:?}",
                                    &src,
                                    &agent_volume_id,
                                    e
                                );
                                eprintln!("sync host/guest files failed: {e}");
                            }
                            Ok(()) => {
                                let commit_req = agent::CommitVolumeRevisionRequest {
                                    agent_volume_id: agent_volume_id.clone(),
                                    garbage_collect_previous: true,
                                };
                                if let Err(e) =
                                    agent.commit_volume_revision(commit_req).await
                                {
                                    error!(
                                        sl!(),
                                        "debounce commit_volume_revision for {:?} failed: {:?}",
                                        &agent_volume_id,
                                        e
                                    );
                                }
                            }
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
    // Agent-side managed volume identifier
    agent_volume_id: String,
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

    /// Gets or creates the managed volume identifier
    pub async fn get_or_create_volume(
        &self,
        canonical_source: &str,
        container_id: &str,
        agent_volume_id: &str,
    ) -> Result<(String, bool)> {
        let mut states = self.volume_states.write().await;

        if let Some(state) = states.get_mut(canonical_source) {
            // Existing volume and update reference
            state.ref_count += 1;
            state.containers.insert(container_id.to_string());

            info!(
                sl!(),
                "Existing volume: source={:?}, managed_volume={:?}, ref_count={}",
                canonical_source,
                state.agent_volume_id,
                state.ref_count,
            );

            return Ok((state.agent_volume_id.clone(), false));
        }

        let mut containers = HashSet::new();
        containers.insert(container_id.to_string());

        let state = VolumeState {
            source_path: canonical_source.to_string(),
            agent_volume_id: agent_volume_id.to_string(),
            ref_count: 1,
            containers,
            monitor_task: None,
        };

        states.insert(state.source_path.clone(), state.clone());

        info!(
            sl!(),
            "Created new volume state: source={:?}, managed_volume={:?}",
            state.source_path,
            state.agent_volume_id,
        );

        Ok((state.agent_volume_id.clone(), true))
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
    pub async fn release_volume(
        &self,
        source_path: &str,
        container_id: &str,
    ) -> Result<Option<String>> {
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
                    "Volume has no more references, source={:?}, managed_volume={:?}",
                    canonical_source,
                    state.agent_volume_id
                );

                let state = states
                    .remove(&canonical_source)
                    .ok_or_else(|| anyhow!("missing volume state during cleanup"))?;

                return Ok(Some(state.agent_volume_id));
            }
        }

        Ok(None)
    }
}

impl ShareFsVolume {
    pub(crate) async fn new(
        share_fs: &Option<Arc<dyn ShareFs>>,
        m: &oci::Mount,
        cid: &str,
        readonly: bool,
        copy_other_directories: bool,
        agent: Arc<dyn Agent>,
        volume_manager: Arc<VolumeManager>,
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
            agent: agent.clone(),
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

                // append oci::Mount structure to volume mounts
                let mut oci_mount = oci::Mount::default();
                oci_mount.set_destination(m.destination().clone());
                oci_mount.set_typ(Some(mount::KATA_MANAGED_VOLUME_BIND_TYPE.to_string()));
                oci_mount.set_options(m.options().clone());
                let host_volume_id = src.to_string_lossy().to_string();

                // If the mount source is a file, we can copy it to the sandbox
                if src.is_file() {
                    let source = Self::init_volume_source(
                        &host_volume_id,
                        agent::VolumeSourceType::SingleFile,
                        readonly,
                        &agent,
                    )
                    .await
                    .context("init single-file volume source")?;

                    info!(
                        sl!(),
                        "fsshare: file {:?} to managed volume {}", &src, &source.agent_volume_id
                    );

                    Self::copy_file_to_guest(&src, &source.agent_volume_id, &agent)
                        .await
                        .context("copy file to guest")?;

                    oci_mount.set_source(Some(PathBuf::from(&source.agent_volume_id)));
                    volume.mounts.push(oci_mount);
                } else if src.is_dir() {
                    // We allow directory copying wildly
                    // source path: "/var/lib/kubelet/pods/6dad7281-57ff-49e4-b844-c588ceabec16/volumes/kubernetes.io~projected/kube-api-access-8s2nl"
                    let watchable_volume = is_watchable_volume(&src);
                    let volume_type = if watchable_volume {
                        agent::VolumeSourceType::AtomicK8s
                    } else {
                        agent::VolumeSourceType::EmptyDir
                    };

                    let source =
                        Self::init_volume_source(&host_volume_id, volume_type, readonly, &agent)
                            .await
                            .context("init directory volume source")?;

                    // Get or create the managed volume id
                    let (agent_volume_id, is_new) = volume_manager
                        .get_or_create_volume(
                            &host_volume_id,
                            cid,
                            &source.agent_volume_id,
                        )
                        .await
                        .context("get or create volume")?;

                    if is_new
                        && should_copy_directory_to_guest(watchable_volume, copy_other_directories)
                    {
                        info!(
                            sl!(),
                            "fsshare: new directory {:?} to managed volume {}",
                            &src,
                            &agent_volume_id
                        );

                        Self::copy_directory_to_guest(
                            &src,
                            &agent_volume_id,
                            &agent,
                            watchable_volume,
                        )
                        .await
                        .context("copy directory to guest")?;
                    } else if is_new {
                        info!(
                            sl!(),
                            "skip copying contents for non-watchable directory {:?}: copy_volumes does not contain other-directories",
                            &src
                        );
                    }

                    oci_mount.set_source(Some(PathBuf::from(&agent_volume_id)));
                    volume.mounts.push(oci_mount);

                    // Start monitoring (only for watchable volumes)
                    let mut monitor_task = None;
                    if is_new && watchable_volume {
                        let watcher = FsWatcher::new(&src).await?;
                        let handle = watcher
                            .start_monitor(agent.clone(), src.clone(), agent_volume_id.clone())
                            .await;
                        monitor_task = Some(handle);
                    }

                    // Register monitor into Volume Manager
                    volume_manager
                        .register_monitor(&host_volume_id, monitor_task)
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

    async fn copy_file_to_guest(
        src: &Path,
        agent_volume_id: &str,
        agent: &Arc<dyn Agent>,
    ) -> Result<()> {
        // Read file metadata
        let file_metadata = std::fs::metadata(src)
            .with_context(|| format!("Failed to read metadata from file: {src:?}"))?;

        // Open file
        let mut file = File::open(src).with_context(|| format!("Failed to open file: {src:?}"))?;

        // Open read file contents to buffer
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .with_context(|| format!("Failed to read file: {src:?}"))?;

        // Create RPC request
        let r = agent::PutVolumeFileRequest {
            agent_volume_id: agent_volume_id.to_string(),
            relative_path: String::new(),
            file_size: file_metadata.len() as i64,
            uid: file_metadata.uid() as i32,
            gid: file_metadata.gid() as i32,
            file_mode: file_metadata.mode(),
            dir_mode: DIR_MODE_PERMS,
            data: buffer,
            ..Default::default()
        };

        // debug!(sl!(), "copy_file: {:?} to managed source {:?}", &src, agent_volume_id);

        // Issue RPC request to agent
        agent.put_volume_file(r).await.with_context(|| {
            format!("put file request failed: src: {src:?}, volume: {agent_volume_id:?}")
        })?;
        Ok(())
    }

    async fn copy_directory_to_guest(
        src: &Path,
        agent_volume_id: &str,
        agent: &Arc<dyn Agent>,
        is_atomic_k8s: bool,
    ) -> Result<()> {
        // For AtomicK8s volumes, skip symlinks: agent reconstructs them from
        // the known path structure, preventing the host from sending arbitrary
        // symlink destinations into the guest.
        copy_dir_recursively(src, src, agent_volume_id, agent, is_atomic_k8s)
            .await
            .context(format!("failed to copy directory contents: {src:?}"))?;

        if is_atomic_k8s {
            // Trigger atomic commit. The agent derives the revision directory
            // name and visible-file list from the file paths it received, so
            // runtime-rs does not supply them here.
            let req = agent::CommitVolumeRevisionRequest {
                agent_volume_id: agent_volume_id.to_string(),
                garbage_collect_previous: true,
            };
            agent
                .commit_volume_revision(req)
                .await
                .context(format!(
                    "failed to commit atomic K8s volume revision for {agent_volume_id}"
                ))?;
        }

        Ok(())
    }

    async fn init_volume_source(
        host_volume_id: &str,
        volume_type: agent::VolumeSourceType,
        read_only: bool,
        agent: &Arc<dyn Agent>,
    ) -> Result<agent::InitVolumeSourceResponse> {
        let req = agent::InitVolumeSourceRequest {
            host_volume_id: host_volume_id.to_string(),
            volume_type,
            read_only,
        };

        let response = agent
            .init_volume_source(req)
            .await
            .with_context(|| format!("init volume source for host path {host_volume_id}"));

        if let Ok(ref r) = response {
            info!(
                sl!(),
                "fsshare: host volume {host_volume_id} -> guest volume {}", &r.agent_volume_id
            );
        }

        response
    }
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
                        let volume_id = manager.release_volume(source, &self.container_id).await?;

                        if let Some(agent_volume_id) = volume_id {
                            info!(
                                sl!(),
                                "Volume {:?} has no more references, can be cleaned up", source
                            );

                            let req = agent::RemoveVolumeSourceRequest { agent_volume_id };
                            self.agent
                                .remove_volume_source(req)
                                .await
                                .with_context(|| {
                                    format!(
                                        "remove managed volume source for host source {:?}",
                                        source
                                    )
                                })?;
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

#[allow(dead_code)]
async fn copy_dir_recursively<P: AsRef<Path>>(
    src_dir: P,
    source_root: &Path,
    agent_volume_id: &str,
    agent: &Arc<dyn Agent>,
    // When true, symlinks are skipped: agent will reconstruct them from the
    // well-known AtomicK8s path structure rather than trusting host-supplied
    // link destinations.
    skip_symlinks: bool,
) -> Result<()> {
    let mut queue = VecDeque::new();
    queue.push_back(src_dir.as_ref().to_path_buf());

    while let Some(current_src) = queue.pop_front() {
        let mut entries = tokio::fs::read_dir(&current_src)
            .await
            .context(format!("read directory: {current_src:?}"))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .context(format!("read directory entry in {current_src:?}"))?
        {
            let entry_path = entry.path();
            let relative_path = entry_path
                .strip_prefix(source_root)
                .context("resolve relative path for managed volume sync")?
                .to_string_lossy()
                .to_string();

            let metadata = entry
                .metadata()
                .await
                .context(format!("read metadata for {entry_path:?}"))?;

            if metadata.is_symlink() {
                if skip_symlinks {
                    // For AtomicK8s volumes, symlinks are never sent to the
                    // agent. The agent derives them from the known K8s atomic
                    // volume path structure, preventing the host from
                    // specifying arbitrary symlink destinations inside the
                    // guest.
                    info!(
                        sl!(),
                        "fsshare: skipping symlink {:?} (agent will reconstruct)",
                        &relative_path
                    );
                    continue;
                }

                // handle symlinks (EmptyDir volumes only)
                let entry_path_err = entry_path.clone();
                let entry_path_clone = entry_path.clone();
                let link_target =
                    tokio::task::spawn_blocking(move || std::fs::read_link(&entry_path_clone))
                        .await
                        .context(format!(
                            "failed to spawn blocking task for symlink: {entry_path_err:?}"
                        ))??;

                let link_target_str = link_target.to_string_lossy().into_owned();

                info!(
                    sl!(),
                    "fsshare: symlink {:?} -> {link_target_str}", &relative_path
                );

                let symlink_request = agent::PutVolumeFileRequest {
                    agent_volume_id: agent_volume_id.to_string(),
                    relative_path: relative_path.clone(),
                    file_size: link_target_str.len() as i64,
                    uid: metadata.uid() as i32,
                    gid: metadata.gid() as i32,
                    file_mode: SFlag::S_IFLNK.bits(),
                    dir_mode: DIR_MODE_PERMS,
                    data: link_target_str.clone().into_bytes(),
                    ..Default::default()
                };
                info!(
                    sl!(),
                    "syncing symlink {:?} to managed volume {} with file_mode: {:?}",
                    relative_path,
                    agent_volume_id,
                    symlink_request.file_mode
                );

                agent
                    .put_volume_file(symlink_request)
                    .await
                    .context(format!(
                        "failed to sync symlink: {relative_path:?} -> {link_target_str:?}"
                    ))?;
            } else if metadata.is_dir() {
                // handle directory
                let dir_request = agent::CreateVolumeSubdirRequest {
                    agent_volume_id: agent_volume_id.to_string(),
                    subdir: relative_path.clone(),
                    uid: metadata.uid() as i32,
                    gid: metadata.gid() as i32,
                    dir_mode: metadata.mode() | SFlag::S_IFDIR.bits(),
                    ..Default::default()
                };
                info!(
                    sl!(),
                    "syncing subdirectory {:?} to managed volume {}",
                    dir_request.subdir,
                    agent_volume_id
                );
                agent
                    .create_volume_subdir(dir_request)
                    .await
                    .context(format!("failed to create subdirectory: {relative_path:?}"))?;

                // push back the sub-dir into queue to handle it in time
                queue.push_back(entry_path);
            } else if metadata.is_file() {
                // async read file
                let mut file = tokio::fs::File::open(&entry_path)
                    .await
                    .context(format!("open file: {entry_path:?}"))?;

                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)
                    .await
                    .context(format!("read file: {entry_path:?}"))?;

                let file_request = agent::PutVolumeFileRequest {
                    agent_volume_id: agent_volume_id.to_string(),
                    relative_path: relative_path.clone(),
                    file_size: metadata.len() as i64,
                    uid: metadata.uid() as i32,
                    gid: metadata.gid() as i32,
                    file_mode: metadata.mode(),
                    dir_mode: DIR_MODE_PERMS,
                    data: buffer,
                    ..Default::default()
                };

                info!(
                    sl!(),
                    "sync file {:?} to managed volume {}", relative_path, agent_volume_id
                );
                agent
                    .put_volume_file(file_request)
                    .await
                    .context(format!("sync file: {entry_path:?} -> {relative_path:?}"))?;
            }
        }
    }

    Ok(())
}

pub(crate) fn is_share_fs_volume(m: &oci::Mount) -> bool {
    let mount_type = get_mount_type(m);
    (mount_type == "bind"
        || mount_type == mount::KATA_EPHEMERAL_VOLUME_TYPE
        || mount_type == mount::KATA_MANAGED_VOLUME_BIND_TYPE)
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

/// This function is used to check whether a given volume is a watchable volume.
/// More specifically, it determines whether the volume's path is located under
/// a predefined list of allowed copy directories.
pub(crate) fn is_watchable_volume(source_path: &PathBuf) -> bool {
    if !source_path.is_dir() {
        return false;
    }
    // watchable list: { kubernetes.io~projected, kubernetes.io~configmap, kubernetes.io~secret, kubernetes.io~downward-api }
    is_projected(source_path)
        || is_downward_api(source_path)
        || is_secret(source_path)
        || is_configmap(source_path)
}

fn should_copy_directory_to_guest(watchable_volume: bool, copy_other_directories: bool) -> bool {
    watchable_volume || copy_other_directories
}

#[cfg(test)]
mod test {
    use super::*;

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
    fn test_is_watchable_volume() {
        // The configmap is /var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~configmap/kube-configmap-0s2no/{..data, key1, key2,...}
        // The secret is /var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~secret/kube-secret-2s2np/{..data, key1, key2,...}
        // The projected is /var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~projected/kube-api-access-8s2nl/{..data, key1, key2,...}
        // The downward-api is /var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~downward-api/downward-api-xxxx/{..data, key1, key2,...}
        let configmap =
            "var/lib/kubelet/pods/1000/volumes/kubernetes.io~configmap/kube-configmap-0s2no";
        let secret = "var/lib/kubelet/pods/1000/volumes/kubernetes.io~secret/kube-secret-2s2np";
        let projected =
            "var/lib/kubelet/1000/<uid>/volumes/kubernetes.io~projected/kube-api-access-8s2nl";
        let downward_api =
            "var/lib/kubelet/1000/<uid>/volumes/kubernetes.io~downward-api/downward-api-xxxx";

        let temp_dir = tempfile::tempdir().unwrap();
        let cm_path = temp_dir.path().join(configmap);
        std::fs::create_dir_all(&cm_path).unwrap();
        let secret_path = temp_dir.path().join(secret);
        std::fs::create_dir_all(&secret_path).unwrap();
        let projected_path = temp_dir.path().join(projected);
        std::fs::create_dir_all(&projected_path).unwrap();
        let downward_api_path = temp_dir.path().join(downward_api);
        std::fs::create_dir_all(&downward_api_path).unwrap();

        assert!(is_watchable_volume(&cm_path));
        assert!(is_watchable_volume(&secret_path));
        assert!(is_watchable_volume(&projected_path));
        assert!(is_watchable_volume(&downward_api_path));
    }

    #[test]
    fn test_should_copy_directory_to_guest() {
        assert!(should_copy_directory_to_guest(true, false));
        assert!(should_copy_directory_to_guest(false, true));
        assert!(!should_copy_directory_to_guest(false, false));
    }
}
