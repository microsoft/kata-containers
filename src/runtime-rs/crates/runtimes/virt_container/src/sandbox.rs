// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::health_check::HealthCheck;
use crate::restore::{
    RestoreCompletedSlot, RestoreContext, RestoreGuestMount, RestoreIdentity, RestoreLiveSlot,
};
use agent::kata::KataAgent;
use agent::types::{KernelModule, SetPolicyRequest};
use agent::{
    self, Agent, GetGuestDetailsRequest, GetIPTablesRequest, SetIPTablesRequest, VolumeStatsRequest,
};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use common::error::is_normal_oom_shutdown_error;
use common::types::utils::option_system_time_into;
use common::types::ContainerProcess;
use common::{
    message::{Action, Message},
    types::DEFAULT_SHM_SIZE,
};
use common::{
    types::{SandboxConfig, SandboxExitInfo, SandboxStatus},
    ContainerManager, Sandbox, SandboxNetworkEnv,
};

use containerd_shim_protos::events::task::{TaskExit, TaskOOM};
#[cfg(all(
    feature = "cloud-hypervisor",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use hypervisor::ch::CloudHypervisor;
use hypervisor::device::topology::PCIePort;
use hypervisor::device::util::{get_host_path, DEVICE_TYPE_CHAR};
use hypervisor::remote::Remote;
use hypervisor::VsockConfig;
use hypervisor::HYPERVISOR_REMOTE;
#[cfg(all(
    feature = "dragonball",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use hypervisor::{dragonball::Dragonball, HYPERVISOR_DRAGONBALL};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use hypervisor::{firecracker::Firecracker, HYPERVISOR_FIRECRACKER};
use hypervisor::{
    is_vfio_ap_device, BlockConfigModern, Hypervisor, RestoreVmRequest, VfioDeviceBase,
};
#[cfg(all(
    feature = "openvmm",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use hypervisor::{openvmm::OpenVmm, HYPERVISOR_NAME_OPENVMM};
use hypervisor::{qemu::Qemu, HYPERVISOR_QEMU};
use hypervisor::{
    utils::{
        get_hvsock_path, remove_vmm_user_runtime_dir, uses_native_ccw_bus, vmm_user_runtime_dir,
    },
    HybridVsockConfig, DEFAULT_GUEST_VSOCK_CID,
};
use hypervisor::{BlockDeviceAio, PortDeviceConfig};
use hypervisor::{ProtectionDeviceConfig, SevSnpConfig, TdxConfig};
use kata_sys_util::fs::reflink_copy;
use kata_sys_util::hooks::HookStates;
use kata_sys_util::protection::{available_guest_protection, GuestProtection};
use kata_sys_util::spec::load_oci_spec;
use kata_types::capabilities::CapabilityBits;
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
#[cfg(all(
    feature = "cloud-hypervisor",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use kata_types::config::hypervisor::HYPERVISOR_NAME_CH;
use kata_types::config::hypervisor::{MemoryRestoreMode, VIRTIO_BLK_CCW, VIRTIO_BLK_PCI};
use kata_types::config::{hypervisor::Factory, TomlConfig};
use kata_types::initdata::{calculate_initdata_digest, ProtectedPlatform};
use oci_spec::runtime as oci;
use persist::{self, sandbox_persist::Persist};
use pod_resources_rs::handle_cdi_devices;
use protobuf::SpecialFields;
use resource::coco_data::initdata::{
    kata_shared_init_data_path, InitDataConfig, KATA_INIT_DATA_IMAGE,
};
use resource::coco_data::initdata_block;
use resource::manager::ManagerArgs;
use resource::network::{dan_config_path, DanNetworkConfig, NetworkConfig, NetworkWithNetNsConfig};
use resource::{ResourceConfig, ResourceManager};
use runtime_spec as spec;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use strum::Display;
use tokio::sync::{mpsc::Sender, watch, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

pub(crate) const VIRTCONTAINER: &str = "virt_container";
const VMM_START_TIMEOUT_SECS: i32 = 10_000;
const SOURCE_AGENT_LISTEN_GRACE: Duration = Duration::from_secs(2);
const SNAPSHOT_BASE_DIR: &str = "/run/vc/vm/snapshots";
const SNAPSHOT_MANIFEST_FILE: &str = "kata-snapshot.json";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotFileManifest {
    // Structural inventory only; transfer integrity belongs to artifact ingestion.
    path: String,
    size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotLiveContainerManifest {
    cri_name: String,
    // Source host ID keys packaged storage; guest ID addresses captured state.
    source_host_id: String,
    snapshot_guest_id: String,
    oci_identity_version: u32,
    oci_identity_sha256: String,
    node_local_mounts: Vec<SnapshotMountManifest>,
    readonly_disk_id: String,
    readonly_disk: String,
    writable_disk_id: Option<String>,
    writable_disk: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotMountManifest {
    // Destination is semantic OCI identity; guest_source is captured backing.
    destination: String,
    guest_source: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotCompletedContainerManifest {
    cri_name: String,
    exit_code: i32,
    oci_identity_version: u32,
    oci_identity_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotAgentTransportManifest {
    contract_version: u32,
    state: String,
    server_port: u32,
    log_port: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotManifest {
    format_version: u32,
    producer: String,
    hypervisor: String,
    source_sandbox_id: String,
    agent_transport: SnapshotAgentTransportManifest,
    live_containers: Vec<SnapshotLiveContainerManifest>,
    completed_containers: Vec<SnapshotCompletedContainerManifest>,
    files: Vec<SnapshotFileManifest>,
}

struct SavedRestoreNetwork {
    id: String,
    tap_queue_count: usize,
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn relative_snapshot_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "snapshot path {} escapes {}",
            path.display(),
            root.display()
        )
    })?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(anyhow!(
            "snapshot manifest path is not a clean relative path: {}",
            relative.display()
        ));
    }
    Ok(relative.to_string_lossy().to_string())
}

fn snapshot_file_manifest(root: &Path, path: &Path) -> Result<SnapshotFileManifest> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "snapshot artifact is not a regular file: {}",
            path.display()
        ));
    }
    Ok(SnapshotFileManifest {
        path: relative_snapshot_path(root, path)?,
        size: metadata.len(),
    })
}

fn snapshot_disk_id(config: &serde_json::Value, path: &Path) -> Result<String> {
    let matches = config
        .get("disks")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("snapshot config missing disks"))?
        .iter()
        .filter(|disk| disk.get("path").and_then(serde_json::Value::as_str) == path.to_str())
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(anyhow!(
            "snapshot config has {} entries for disk {}",
            matches.len(),
            path.display()
        ));
    }
    matches[0]
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("snapshot disk {} has no ID", path.display()))
}

fn clean_relative_snapshot_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(anyhow!(
            "snapshot manifest path is not a clean relative path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validated_snapshot_file(snapshot_dir: &Path, relative: &Path) -> Result<PathBuf> {
    clean_relative_snapshot_path(relative)?;
    let path = snapshot_dir.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("snapshot file is unavailable: {}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "snapshot artifact is not a regular file: {}",
            path.display()
        ));
    }
    if path.canonicalize()? != path {
        return Err(anyhow!(
            "snapshot artifact contains a symlinked component: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn restore_source_from_annotations(
    annotations: &std::collections::HashMap<String, String>,
) -> Result<Option<PathBuf>> {
    let Some(value) = annotations.get(kata_types::annotations::KATA_ANNO_RESTORE_FROM) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Err(anyhow!("restore-from annotation is empty"));
    }
    let annotation_path = Path::new(value);
    let restore_source = if annotation_path.is_absolute() {
        if annotation_path == Path::new("/")
            || annotation_path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(anyhow!("restore-from path is not lexically clean"));
        }
        annotation_path.to_path_buf()
    } else {
        clean_relative_snapshot_path(annotation_path)?;
        Path::new(SNAPSHOT_BASE_DIR).join(annotation_path)
    };
    let metadata = fs::symlink_metadata(&restore_source).with_context(|| {
        format!(
            "restore-from snapshot is unavailable: {}",
            restore_source.display()
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(anyhow!(
            "restore-from snapshot is not a directory: {}",
            restore_source.display()
        ));
    }
    if restore_source.canonicalize()? != restore_source {
        return Err(anyhow!(
            "restore-from path contains a symlink or non-canonical component: {}",
            restore_source.display()
        ));
    }
    Ok(Some(restore_source))
}

fn load_restore_manifest(snapshot_dir: &Path) -> Result<SnapshotManifest> {
    let manifest_path = snapshot_dir.join(SNAPSHOT_MANIFEST_FILE);
    let metadata = fs::symlink_metadata(&manifest_path).with_context(|| {
        format!(
            "snapshot manifest is unavailable: {}",
            manifest_path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "snapshot manifest is not a regular file: {}",
            manifest_path.display()
        ));
    }
    let manifest: SnapshotManifest = serde_json::from_reader(fs::File::open(&manifest_path)?)
        .with_context(|| format!("parse snapshot manifest {}", manifest_path.display()))?;
    if manifest.format_version != 1
        || manifest.producer != "runtime-rs"
        || manifest.hypervisor != "cloud-hypervisor"
        || manifest.source_sandbox_id.is_empty()
    {
        return Err(anyhow!("unsupported snapshot manifest contract"));
    }
    if manifest.agent_transport.contract_version != 1
        || manifest.agent_transport.state != "disconnected-listening"
        || manifest.agent_transport.server_port == 0
        || manifest.agent_transport.log_port == 0
    {
        return Err(anyhow!("unsupported snapshot agent transport contract"));
    }

    let mut declared_files = HashSet::new();
    for file in &manifest.files {
        let relative = Path::new(&file.path);
        if !declared_files.insert(file.path.as_str()) {
            return Err(anyhow!("duplicate snapshot file {}", file.path));
        }
        let path = validated_snapshot_file(snapshot_dir, relative)?;
        if fs::metadata(&path)?.len() != file.size {
            return Err(anyhow!(
                "snapshot artifact metadata mismatch for {}",
                file.path
            ));
        }
    }
    for required in ["clh/config.json", "clh/state.json", "runtime-state.json"] {
        if !declared_files.contains(required) {
            return Err(anyhow!("snapshot manifest does not declare {required}"));
        }
    }

    // CRI names select restore slots, host IDs key packaged storage, and guest
    // IDs address the captured processes. Each namespace must be unambiguous.
    let mut names = HashSet::new();
    let mut host_ids = HashSet::new();
    let mut guest_ids = HashSet::new();
    let mut pause_count = 0;
    for container in &manifest.live_containers {
        if container.cri_name.is_empty()
            || container.source_host_id.is_empty()
            || container.snapshot_guest_id.is_empty()
            || container.oci_identity_version != crate::restore::OCI_IDENTITY_VERSION
            || !valid_sha256_digest(&container.oci_identity_sha256)
            || !host_ids.insert(container.source_host_id.as_str())
            || !guest_ids.insert(container.snapshot_guest_id.as_str())
            || container.readonly_disk_id.trim().is_empty()
            || container.writable_disk_id.is_some() != container.writable_disk.is_some()
            || container
                .writable_disk_id
                .as_ref()
                .is_some_and(|id| id.trim().is_empty())
            || !names.insert(container.cri_name.as_str())
        {
            return Err(anyhow!("snapshot live container contract is invalid"));
        }
        kata_sys_util::validate::verify_id(&container.source_host_id)
            .context("validate snapshot source host ID")?;
        kata_sys_util::validate::verify_id(&container.snapshot_guest_id)
            .context("validate snapshot guest ID")?;
        if container.cri_name == "POD" {
            pause_count += 1;
            if container.source_host_id != manifest.source_sandbox_id {
                return Err(anyhow!(
                    "snapshot pause container does not match sandbox ID"
                ));
            }
        }
        let mut mount_destinations = HashSet::new();
        for mount in &container.node_local_mounts {
            let destination = Path::new(&mount.destination);
            let guest_source = Path::new(&mount.guest_source);
            let trusted_guest_root = Path::new("/run/kata-containers");
            if !destination.is_absolute()
                || destination
                    .components()
                    .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
                || guest_source == trusted_guest_root
                || !guest_source.starts_with(trusted_guest_root)
                || guest_source
                    .components()
                    .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
                || !mount_destinations.insert(mount.destination.as_str())
            {
                return Err(anyhow!("snapshot node-local mount mapping is invalid"));
            }
        }
        for disk in std::iter::once(container.readonly_disk.as_str())
            .chain(container.writable_disk.as_deref())
        {
            validated_snapshot_file(snapshot_dir, Path::new(disk))?;
            if !declared_files.contains(disk) {
                return Err(anyhow!("snapshot manifest does not declare disk {disk}"));
            }
        }
    }
    for container in &manifest.completed_containers {
        if container.cri_name.is_empty()
            || container.oci_identity_version != crate::restore::OCI_IDENTITY_VERSION
            || !valid_sha256_digest(&container.oci_identity_sha256)
            || !names.insert(container.cri_name.as_str())
        {
            return Err(anyhow!("snapshot completed container contract is invalid"));
        }
    }
    if pause_count != 1 {
        return Err(anyhow!(
            "snapshot requires exactly one live pause container, found {pause_count}"
        ));
    }
    Ok(manifest)
}

fn prepare_restore_source(
    snapshot_dir: &Path,
    private_dir: &Path,
    manifest: &SnapshotManifest,
) -> Result<PathBuf> {
    // Immutable snapshot state remains caller-owned. The target gets a private
    // CLH config and private writable disks so one restore cannot mutate the
    // source artifact or another clone.
    fs::create_dir(private_dir)
        .with_context(|| format!("create private restore directory {}", private_dir.display()))?;
    fs::set_permissions(private_dir, fs::Permissions::from_mode(0o700))?;
    let restore_source = private_dir.join("clh");
    fs::create_dir(&restore_source)?;
    fs::set_permissions(&restore_source, fs::Permissions::from_mode(0o700))?;
    let private_config_path = restore_source.join("config.json");
    let snapshot_config = validated_snapshot_file(snapshot_dir, Path::new("clh/config.json"))?;
    reflink_copy(&snapshot_config, &private_config_path).context("copy private restore config")?;
    fs::set_permissions(&private_config_path, fs::Permissions::from_mode(0o600))?;
    let snapshot_state = validated_snapshot_file(snapshot_dir, Path::new("clh/state.json"))?;
    std::os::unix::fs::symlink(snapshot_state, restore_source.join("state.json"))
        .context("link immutable restore state")?;
    let memory_ranges = snapshot_dir.join("clh/memory-ranges");
    if fs::symlink_metadata(&memory_ranges).is_ok() {
        let memory_ranges = validated_snapshot_file(snapshot_dir, Path::new("clh/memory-ranges"))?;
        std::os::unix::fs::symlink(&memory_ranges, restore_source.join("memory-ranges"))
            .context("link immutable restore memory")?;
    }

    let mut replacements = HashMap::<String, PathBuf>::new();
    let mut private_writable_ids = HashSet::new();
    for container in &manifest.live_containers {
        let readonly = validated_snapshot_file(snapshot_dir, Path::new(&container.readonly_disk))?;
        if replacements
            .insert(container.readonly_disk_id.clone(), readonly)
            .is_some()
        {
            return Err(anyhow!(
                "duplicate snapshot disk ID {}",
                container.readonly_disk_id
            ));
        }
        if let (Some(writable_id), Some(writable)) = (
            container.writable_disk_id.as_ref(),
            container.writable_disk.as_ref(),
        ) {
            let private_container = private_dir
                .join("containers")
                .join(&container.source_host_id);
            fs::create_dir_all(&private_container)?;
            fs::set_permissions(&private_container, fs::Permissions::from_mode(0o700))?;
            let private_writable = private_container.join("rwlayer.img");
            let source_writable = validated_snapshot_file(snapshot_dir, Path::new(writable))?;
            reflink_copy(&source_writable, &private_writable)
                .with_context(|| format!("clone private writable disk {writable}"))?;
            fs::set_permissions(&private_writable, fs::Permissions::from_mode(0o600))?;
            if replacements
                .insert(writable_id.clone(), private_writable)
                .is_some()
            {
                return Err(anyhow!("duplicate snapshot disk ID {writable_id}"));
            }
            private_writable_ids.insert(writable_id.clone());
        }
    }

    let mut config: serde_json::Value = serde_json::from_slice(&fs::read(&private_config_path)?)
        .context("parse private restore config")?;
    let disks = config
        .get_mut("disks")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| anyhow!("snapshot config missing disks"))?;
    let mut rewritten = HashSet::new();
    for disk in disks {
        let Some(id) = disk
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
        else {
            continue;
        };
        let Some(path) = replacements.get(&id) else {
            continue;
        };
        if !rewritten.insert(id.clone()) {
            return Err(anyhow!("snapshot config contains duplicate disk ID {id}"));
        }
        let disk = disk
            .as_object_mut()
            .ok_or_else(|| anyhow!("snapshot config has invalid disk"))?;
        disk.insert(
            "path".to_string(),
            serde_json::Value::String(path.display().to_string()),
        );
        if private_writable_ids.contains(&id) {
            disk.insert("sparse".to_string(), serde_json::Value::Bool(true));
        }
    }
    let expected = replacements.keys().cloned().collect::<HashSet<_>>();
    if rewritten != expected {
        return Err(anyhow!(
            "snapshot config did not reference manifest disk IDs: {:?}",
            expected.difference(&rewritten).collect::<Vec<_>>()
        ));
    }
    fs::write(&private_config_path, serde_json::to_vec(&config)?)?;
    Ok(restore_source)
}

fn restored_rootfs_configs(
    snapshot_dir: &Path,
    private_dir: &Path,
    manifest: &SnapshotManifest,
) -> Result<Vec<resource::rootfs::RestoredRootfsConfig>> {
    manifest
        .live_containers
        .iter()
        .map(|container| {
            let prefix = PathBuf::from("containers").join(&container.source_host_id);
            let readonly = PathBuf::from(&container.readonly_disk);
            let writable = container.writable_disk.as_ref().map(PathBuf::from);
            let private_writable = writable.as_ref().map(|_| {
                private_dir
                    .join("containers")
                    .join(&container.source_host_id)
                    .join("rwlayer.img")
            });
            let files = manifest
                .files
                .iter()
                .map(|file| PathBuf::from(&file.path))
                .filter(|path| path.starts_with(&prefix))
                .map(|path| {
                    if writable.as_ref() == Some(&path) {
                        private_writable
                            .clone()
                            .ok_or_else(|| anyhow!("restored writable disk is unavailable"))
                    } else {
                        Ok(snapshot_dir.join(path))
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(resource::rootfs::RestoredRootfsConfig {
                cri_name: container.cri_name.clone(),
                host_id: container.source_host_id.clone(),
                guest_id: container.snapshot_guest_id.clone(),
                readonly_disk: snapshot_dir.join(readonly),
                writable_disk: private_writable,
                files,
            })
        })
        .collect()
}

fn saved_restore_network(snapshot_dir: &Path) -> Result<SavedRestoreNetwork> {
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(snapshot_dir.join("clh/config.json"))?)
            .context("parse saved CLH network config")?;
    let networks = config
        .get("net")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("snapshot config missing network devices"))?;
    if networks.len() != 1 {
        return Err(anyhow!(
            "snapshot restore requires exactly one saved network device, found {}",
            networks.len()
        ));
    }
    let network = &networks[0];
    if network
        .get("vhost_user")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(anyhow!("vhost-user snapshot restore is not supported"));
    }
    let id = network
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| anyhow!("saved restore network has no device ID"))?;
    let virtio_queue_count = network
        .get("num_queues")
        .and_then(serde_json::Value::as_u64)
        .and_then(|queues| usize::try_from(queues).ok())
        .filter(|queues| *queues > 0 && *queues % 2 == 0)
        .ok_or_else(|| anyhow!("saved restore network has invalid virtio queue count"))?;
    Ok(SavedRestoreNetwork {
        id: id.to_string(),
        tap_queue_count: virtio_queue_count / 2,
    })
}

#[cfg(test)]
mod snapshot_manifest_tests {
    use super::*;

    fn write_restore_fixture(root: &Path) -> SnapshotManifest {
        let clh = root.join("clh");
        let container = root.join("containers/source");
        fs::create_dir_all(&clh).unwrap();
        fs::create_dir_all(&container).unwrap();
        let readonly = container.join("rootfs.vmdk");
        let writable = container.join("rwlayer.img");
        fs::write(&readonly, b"descriptor").unwrap();
        fs::write(&writable, b"writable").unwrap();
        fs::write(clh.join("state.json"), b"state").unwrap();
        fs::write(clh.join("memory-ranges"), b"memory").unwrap();
        fs::write(root.join("runtime-state.json"), b"runtime").unwrap();
        fs::write(
            clh.join("config.json"),
            serde_json::to_vec(&serde_json::json!({
                "memory": {"size": 1},
                "disks": [
                    {"id": "ro", "path": readonly.display().to_string()},
                    {"id": "rw", "path": writable.display().to_string()}
                ],
                "net": [{"id": "net0", "num_queues": 2}]
            }))
            .unwrap(),
        )
        .unwrap();
        let file_paths = [
            "clh/config.json",
            "clh/state.json",
            "clh/memory-ranges",
            "runtime-state.json",
            "containers/source/rootfs.vmdk",
            "containers/source/rwlayer.img",
        ];
        SnapshotManifest {
            format_version: 1,
            producer: "runtime-rs".to_string(),
            hypervisor: "cloud-hypervisor".to_string(),
            source_sandbox_id: "source".to_string(),
            agent_transport: SnapshotAgentTransportManifest {
                contract_version: 1,
                state: "disconnected-listening".to_string(),
                server_port: 1024,
                log_port: 1025,
            },
            live_containers: vec![SnapshotLiveContainerManifest {
                cri_name: "POD".to_string(),
                source_host_id: "source".to_string(),
                snapshot_guest_id: "source".to_string(),
                oci_identity_version: crate::restore::OCI_IDENTITY_VERSION,
                oci_identity_sha256: format!("sha256:{}", "1".repeat(64)),
                node_local_mounts: Vec::new(),
                readonly_disk_id: "ro".to_string(),
                readonly_disk: "containers/source/rootfs.vmdk".to_string(),
                writable_disk_id: Some("rw".to_string()),
                writable_disk: Some("containers/source/rwlayer.img".to_string()),
            }],
            completed_containers: Vec::new(),
            files: file_paths
                .iter()
                .map(|path| SnapshotFileManifest {
                    path: (*path).to_string(),
                    size: fs::metadata(root.join(path)).unwrap().len(),
                })
                .collect(),
        }
    }

    #[test]
    fn agent_transport_contract_is_required_in_manifest() {
        let manifest = SnapshotManifest {
            format_version: 1,
            producer: "runtime-rs".to_string(),
            hypervisor: "cloud-hypervisor".to_string(),
            source_sandbox_id: "sandbox".to_string(),
            agent_transport: SnapshotAgentTransportManifest {
                contract_version: 1,
                state: "disconnected-listening".to_string(),
                server_port: 1024,
                log_port: 1025,
            },
            live_containers: Vec::new(),
            completed_containers: Vec::new(),
            files: Vec::new(),
        };

        let value = serde_json::to_value(manifest).unwrap();
        assert_eq!(value["agent_transport"]["contract_version"], 1);
        assert_eq!(value["agent_transport"]["state"], "disconnected-listening");
        assert_eq!(value["agent_transport"]["server_port"], 1024);
        assert_eq!(value["agent_transport"]["log_port"], 1025);
    }

    #[test]
    fn manifest_separates_live_and_completed_containers_without_payload_hashes() {
        let manifest = SnapshotManifest {
            format_version: 1,
            producer: "runtime-rs".to_string(),
            hypervisor: "cloud-hypervisor".to_string(),
            source_sandbox_id: "sandbox".to_string(),
            agent_transport: SnapshotAgentTransportManifest {
                contract_version: 1,
                state: "disconnected-listening".to_string(),
                server_port: 1024,
                log_port: 1025,
            },
            live_containers: vec![SnapshotLiveContainerManifest {
                cri_name: "app".to_string(),
                source_host_id: "host-app".to_string(),
                snapshot_guest_id: "guest-app".to_string(),
                oci_identity_version: crate::restore::OCI_IDENTITY_VERSION,
                oci_identity_sha256: format!("sha256:{}", "2".repeat(64)),
                node_local_mounts: Vec::new(),
                readonly_disk_id: "app-ro".to_string(),
                readonly_disk: "containers/host-app/rootfs.vmdk".to_string(),
                writable_disk_id: None,
                writable_disk: None,
            }],
            completed_containers: vec![SnapshotCompletedContainerManifest {
                cri_name: "setup".to_string(),
                exit_code: 0,
                oci_identity_version: crate::restore::OCI_IDENTITY_VERSION,
                oci_identity_sha256: format!("sha256:{}", "3".repeat(64)),
            }],
            files: vec![SnapshotFileManifest {
                path: "clh/state.json".to_string(),
                size: 42,
            }],
        };

        let value = serde_json::to_value(manifest).unwrap();
        assert!(value.get("containers").is_none());
        assert_eq!(value["live_containers"][0]["cri_name"], "app");
        assert_eq!(value["completed_containers"][0]["cri_name"], "setup");
        assert_eq!(value["completed_containers"][0]["exit_code"], 0);
        assert!(value["files"][0].get("sha256").is_none());
    }

    #[test]
    fn disk_id_requires_one_matching_config_entry() {
        let config = serde_json::json!({
            "disks": [
                {"id": "app-ro", "path": "/snapshot/containers/app/rootfs.vmdk"},
                {"id": "app-rw", "path": "/snapshot/containers/app/rwlayer.img"}
            ]
        });

        assert_eq!(
            snapshot_disk_id(&config, Path::new("/snapshot/containers/app/rootfs.vmdk")).unwrap(),
            "app-ro"
        );
        assert!(snapshot_disk_id(&config, Path::new("/snapshot/missing.img")).is_err());

        let duplicate = serde_json::json!({
            "disks": [
                {"id": "first", "path": "/snapshot/disk.img"},
                {"id": "second", "path": "/snapshot/disk.img"}
            ]
        });
        assert!(snapshot_disk_id(&duplicate, Path::new("/snapshot/disk.img")).is_err());
    }

    #[test]
    fn restore_manifest_requires_disk_ids_and_declared_files() {
        let snapshot = tempfile::tempdir().unwrap();
        let manifest = write_restore_fixture(snapshot.path());
        fs::write(
            snapshot.path().join(SNAPSHOT_MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let loaded = load_restore_manifest(snapshot.path()).unwrap();
        assert_eq!(loaded.live_containers[0].readonly_disk_id, "ro");

        let mut invalid = manifest;
        invalid.live_containers[0].readonly_disk_id.clear();
        fs::write(
            snapshot.path().join(SNAPSHOT_MANIFEST_FILE),
            serde_json::to_vec(&invalid).unwrap(),
        )
        .unwrap();
        assert!(load_restore_manifest(snapshot.path()).is_err());
    }

    #[test]
    fn prepare_restore_source_clones_writable_and_rewrites_by_id() {
        let snapshot = tempfile::tempdir().unwrap();
        let private_parent = tempfile::tempdir().unwrap();
        let manifest = write_restore_fixture(snapshot.path());
        let restore_source = prepare_restore_source(
            snapshot.path(),
            &private_parent.path().join("restore"),
            &manifest,
        )
        .unwrap();

        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(restore_source.join("config.json")).unwrap()).unwrap();
        assert_eq!(
            config["disks"][0]["path"],
            snapshot
                .path()
                .join("containers/source/rootfs.vmdk")
                .display()
                .to_string()
        );
        let private_writable = private_parent
            .path()
            .join("restore/containers/source/rwlayer.img");
        assert_eq!(
            config["disks"][1]["path"],
            private_writable.display().to_string()
        );
        assert_eq!(config["disks"][1]["sparse"], true);
        assert_eq!(fs::read(private_writable).unwrap(), b"writable");
    }
}

pub struct SandboxRestoreArgs {
    pub sid: String,
    pub toml_config: TomlConfig,
    pub sender: Sender<Message>,
}

#[derive(Clone, Copy, PartialEq, Debug, Display)]
pub enum SandboxState {
    Init,
    Running,
    Stopped,
}

impl SandboxState {
    fn to_cri_state(self) -> &'static str {
        match self {
            SandboxState::Running => "SANDBOX_READY",
            SandboxState::Init | SandboxState::Stopped => "SANDBOX_NOTREADY",
        }
    }
}

struct SandboxInner {
    state: SandboxState,
    exit_info: Option<SandboxExitInfo>,
    created_at: Option<SystemTime>,
    // Whether sandbox resources (cgroup, network, mounts, ...) have already
    // been released.  Teardown can be driven both by the sandbox container
    // exiting and by an explicit shutdown RPC, so guard against running the
    // cleanup twice.
    cleaned: bool,
}

impl SandboxInner {
    pub fn new() -> Self {
        Self {
            state: SandboxState::Init,
            exit_info: None,
            created_at: None,
            cleaned: false,
        }
    }
}

#[derive(Clone)]
pub struct VirtSandbox {
    sid: String,
    msg_sender: Arc<Mutex<Sender<Message>>>,
    inner: Arc<RwLock<SandboxInner>>,
    resource_manager: Arc<ResourceManager>,
    agent: Arc<dyn Agent>,
    hypervisor: Arc<dyn Hypervisor>,
    monitor: Arc<HealthCheck>,
    exit_notify_tx: watch::Sender<bool>,
    sandbox_config: Option<SandboxConfig>,
    shm_size: u64,
    factory: Option<Factory>,
    cancel_token: CancellationToken,
    restore_context: Arc<RestoreContext>,
}

impl std::fmt::Debug for VirtSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtSandbox")
            .field("sid", &self.sid)
            .field("msg_sender", &self.msg_sender)
            .field("inner", &"<SandboxInner>")
            .field("resource_manager", &self.resource_manager)
            .field("agent", &"<Agent>")
            .field("hypervisor", &self.hypervisor)
            .field("monitor", &"<HealthCheck>")
            .field("exit_notify_tx", &"<watch::Sender<bool>>")
            .field("sandbox_config", &self.sandbox_config)
            .field("factory", &self.factory)
            .finish()
    }
}

impl VirtSandbox {
    fn start_oom_watcher(&self) {
        let agent = self.agent.clone();
        let sender = self.msg_sender.clone();
        let cancel_token = self.cancel_token.clone();
        let restore_context = self.restore_context.clone();

        info!(sl!(), "oom watcher start");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        info!(sl!(), "oom watcher cancelled, sandbox is stopping");
                        break;
                    }
                    res = agent.get_oom_event(agent::Empty::new()) => {
                        match res.context("get oom event") {
                            Ok(resp) => {
                                let guest_id = &resp.container_id;
                                // The guest reports its stable captured ID;
                                // containerd expects this generation's host ID.
                                let cid = restore_context
                                    .resolve_host_id(guest_id)
                                    .await
                                    .unwrap_or_else(|| guest_id.to_string());
                                warn!(sl!(), "send oom event for container {}", &cid);
                                let event = TaskOOM {
                                    container_id: cid.clone(),
                                    ..Default::default()
                                };
                                let msg = Message::new(Action::Event(Arc::new(event)));
                                let lock_sender = sender.lock().await;
                                if let Err(err) = lock_sender.send(msg).await.context("send event") {
                                    error!(
                                        sl!(),
                                        "failed to send oom event for {} error {:?}", cid, err
                                    );
                                }
                            }
                            Err(err) => {
                                if is_normal_oom_shutdown_error(&err) {
                                    info!(sl!(), "oom watcher exit on sandbox shutdown: {:?}", err);
                                    break;
                                }
                                warn!(sl!(), "failed to get oom event error {:?}", err);
                            }
                        }
                    }
                }
            }
        });
    }

    pub(crate) async fn new(
        sid: &str,
        msg_sender: Sender<Message>,
        agent: Arc<dyn Agent>,
        hypervisor: Arc<dyn Hypervisor>,
        resource_manager: Arc<ResourceManager>,
        sandbox_config: SandboxConfig,
        factory: Factory,
        restore_context: Arc<RestoreContext>,
    ) -> Result<Self> {
        let config = resource_manager.config().await;
        let keep_abnormal = config.runtime.keep_abnormal;
        let (exit_notify_tx, _) = watch::channel(false);
        let cancel_token = CancellationToken::new();
        Ok(Self {
            sid: sid.to_string(),
            msg_sender: Arc::new(Mutex::new(msg_sender)),
            inner: Arc::new(RwLock::new(SandboxInner::new())),
            agent,
            hypervisor,
            resource_manager,
            monitor: Arc::new(HealthCheck::new(true, keep_abnormal)),
            exit_notify_tx,
            shm_size: sandbox_config.shm_size,
            sandbox_config: Some(sandbox_config),
            factory: Some(factory),
            cancel_token,
            restore_context,
        })
    }

    pub fn get_agent(&self) -> Arc<dyn Agent> {
        self.agent.clone()
    }

    pub fn get_sid(&self) -> String {
        self.sid.clone()
    }

    pub fn get_hypervisor(&self) -> Arc<dyn Hypervisor> {
        self.hypervisor.clone()
    }

    fn restore_private_dir(&self) -> PathBuf {
        PathBuf::from(kata_types::prefix_with_rootless_dir(
            kata_types::config::KATA_PATH,
        ))
        .join(&self.sid)
        .join("restore")
    }

    async fn start_restore_if_requested(
        &self,
        sandbox_config: &SandboxConfig,
        inner: &mut SandboxInner,
    ) -> Result<bool> {
        let Some(snapshot_dir) = restore_source_from_annotations(&sandbox_config.annotations)?
        else {
            return Ok(false);
        };
        if sandbox_config.hooks.is_some() {
            return Err(anyhow!(
                "sandbox OCI hooks are not supported for snapshot restore"
            ));
        }
        let runtime_config = self.resource_manager.config().await;
        if runtime_config.runtime.hypervisor_name != HYPERVISOR_NAME_CH {
            return Err(anyhow!(
                "snapshot restore requires cloud-hypervisor, configured {}",
                runtime_config.runtime.hypervisor_name
            ));
        }

        let manifest = load_restore_manifest(&snapshot_dir)?;
        let saved_network = saved_restore_network(&snapshot_dir)?;
        let live_slots = manifest
            .live_containers
            .iter()
            .map(|container| RestoreLiveSlot {
                cri_name: container.cri_name.clone(),
                guest_id: container.snapshot_guest_id.clone(),
                identity: RestoreIdentity {
                    oci_identity_version: container.oci_identity_version,
                    oci_identity_sha256: container.oci_identity_sha256.clone(),
                },
                node_local_mounts: container
                    .node_local_mounts
                    .iter()
                    .map(|mount| RestoreGuestMount {
                        destination: mount.destination.clone(),
                        guest_source: mount.guest_source.clone(),
                    })
                    .collect(),
            })
            .collect();
        let completed_slots = manifest
            .completed_containers
            .iter()
            .map(|container| RestoreCompletedSlot {
                cri_name: container.cri_name.clone(),
                exit_code: container.exit_code,
                identity: RestoreIdentity {
                    oci_identity_version: container.oci_identity_version,
                    oci_identity_sha256: container.oci_identity_sha256.clone(),
                },
            })
            .collect();
        self.restore_context
            .begin(&manifest.source_sandbox_id, live_slots, completed_slots)
            .await?;
        let private_dir = self.restore_private_dir();
        let result: Result<()> = async {
            fs::create_dir_all(private_dir.parent().unwrap())?;
            let restore_source = prepare_restore_source(&snapshot_dir, &private_dir, &manifest)?;
            self.resource_manager
                .register_restored_rootfs(restored_rootfs_configs(
                    &snapshot_dir,
                    &private_dir,
                    &manifest,
                )?)
                .await
                .context("register restored rootfs graph")?;
            let selinux_label = load_oci_spec().ok().and_then(|spec| {
                spec.process()
                    .as_ref()
                    .and_then(|process| process.selinux_label().clone())
            });
            self.hypervisor
                .prepare_vm(
                    &self.sid,
                    sandbox_config.network_env.netns.clone(),
                    &sandbox_config.annotations,
                    selinux_label,
                )
                .await
                .context("prepare restored VM")?;
            let target_network = self
                .prepare_network_resource(&sandbox_config.network_env)
                .await
                .ok_or_else(|| anyhow!("target network is required for snapshot restore"))?;
            let target_network = match target_network {
                ResourceConfig::Network(network) => network,
                _ => unreachable!(),
            };
            let restore_network = self
                .resource_manager
                .prepare_restore_network(
                    target_network,
                    saved_network.id,
                    saved_network.tap_queue_count,
                )
                .await
                .context("prepare fenced restore network")?;
            let hypervisor_config = self.hypervisor.hypervisor_config().await;
            if hypervisor_config.memory_info.enable_virtio_mem
                && hypervisor_config.memory_info.memory_restore_mode
                    == MemoryRestoreMode::CopyOnWrite
            {
                return Err(anyhow!(
                    "copy-on-write snapshot restore is incompatible with virtio-mem"
                ));
            }
            self.hypervisor
                .restore_vm(RestoreVmRequest {
                    snapshot_dir: restore_source,
                    memory_restore_mode: hypervisor_config.memory_info.memory_restore_mode,
                    network: vec![restore_network],
                    timeout_secs: VMM_START_TIMEOUT_SECS,
                })
                .await
                .context("restore workload VM paused")?;
            self.restore_context.prepared_paused().await?;
            inner.created_at = Some(SystemTime::now());
            self.save()
                .await
                .context("persist paused restored sandbox")?;
            Ok(())
        }
        .await;
        if let Err(error) = result {
            self.restore_context.fail().await;
            if let Err(stop_error) = self.hypervisor.stop_vm().await {
                return Err(error.context(format!(
                    "failed to stop restored VMM; preserving private restore storage: {stop_error:#}"
                )));
            }
            let _ = self.resource_manager.cleanup().await;
            let _ = fs::remove_dir_all(&private_dir);
            return Err(error);
        }

        let sandbox = self.clone();
        tokio::spawn(async move {
            match sandbox.hypervisor.wait_vm().await {
                Ok(exit_code) => {
                    sandbox
                        .record_stop(exit_code as u32, SystemTime::now())
                        .await
                }
                Err(error) => {
                    warn!(sl!(), "failed waiting for restored VM exit: {:?}", error);
                    sandbox.record_stop(255, SystemTime::now()).await;
                }
            }
        });
        info!(
            sl!(),
            "restored workload VM is paused and awaiting sandbox start"
        );
        Ok(true)
    }

    async fn activate_restore_transaction(
        &self,
        container_manager: Arc<dyn ContainerManager>,
        target_id: &str,
    ) -> Result<bool> {
        let _activation_guard = self.restore_context.activation_guard().await;
        if !self.restore_context.begin_activation(target_id).await? {
            return Ok(false);
        }
        if !self.restore_context.needs_activation().await {
            return Ok(true);
        }

        let result: Result<()> = async {
            self.hypervisor
                .resume_vm()
                .await
                .context("resume restored VM")?;
            let address = self
                .hypervisor
                .get_agent_socket()
                .await
                .context("get restored agent socket")?;
            self.agent
                .start(&address)
                .await
                .context("dial restored agent")?;
            self.agent
                .check(agent::CheckRequest::new(""))
                .await
                .context("health-check restored agent")?;

            self.agent
                .reseed_random_dev(agent::ReseedRandomDevRequest {
                    data: kata_sys_util::rand::RandomBytes::new(512).bytes,
                })
                .await
                .context("reseed restored guest RNG")?;
            let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
            self.agent
                .set_guest_date_time(agent::SetGuestDateTimeRequest {
                    sec: now.as_secs() as i64,
                    usec: now.subsec_micros() as i64,
                })
                .await
                .context("synchronize restored guest time")?;

            let before = self.agent.list_interfaces(agent::Empty::new()).await?;
            let source_interfaces = before
                .interfaces
                .into_iter()
                .filter(|interface| interface.name != "lo")
                .collect::<Vec<_>>();
            if source_interfaces.len() != 1 {
                return Err(anyhow!(
                    "restored guest has {} non-loopback interfaces",
                    source_interfaces.len()
                ));
            }
            let source = &source_interfaces[0];
            let source_addresses = source
                .ip_addresses
                .iter()
                .map(|address| format!("{}/{}", address.address, address.mask))
                .collect::<HashSet<_>>();
            let (mut target, mut routes) =
                self.resource_manager.restore_network_identity().await?;
            let target_interface_name = target.name.clone();
            target.name = source.name.clone();
            target.device = source.name.clone();
            let target_addresses = target
                .ip_addresses
                .iter()
                .map(|address| format!("{}/{}", address.address, address.mask))
                .collect::<HashSet<_>>();
            self.agent
                .update_interface(agent::UpdateInterfaceRequest {
                    interface: Some(target.clone()),
                })
                .await
                .context("replace restored guest interface")?;
            for route in &mut routes {
                if route.device == target_interface_name {
                    route.device = source.name.clone();
                }
            }
            if !routes.is_empty() {
                self.agent
                    .update_routes(agent::UpdateRoutesRequest {
                        route: Some(agent::Routes { routes }),
                    })
                    .await
                    .context("install restored guest routes")?;
            }
            let after = self.agent.list_interfaces(agent::Empty::new()).await?;
            let restored = after
                .interfaces
                .iter()
                .find(|interface| interface.name == source.name)
                .ok_or_else(|| anyhow!("restored guest interface disappeared"))?;
            if !restored.hw_addr.eq_ignore_ascii_case(&target.hw_addr) {
                return Err(anyhow!("restored guest interface MAC verification failed"));
            }
            let restored_addresses = restored
                .ip_addresses
                .iter()
                .map(|address| format!("{}/{}", address.address, address.mask))
                .collect::<HashSet<_>>();
            if !target_addresses.is_subset(&restored_addresses)
                || source_addresses
                    .difference(&target_addresses)
                    .any(|address| restored_addresses.contains(address))
            {
                return Err(anyhow!(
                    "restored guest address verification failed: source {source_addresses:?}, target {target_addresses:?}, restored {restored_addresses:?}"
                ));
            }
            // Do not release fenced traffic until readback proves target
            // identity is present and every source-only address is gone.
            self.resource_manager
                .activate_restore_network()
                .await
                .context("activate restored network")?;

            let pause_guest_id = self.restore_context.source_pause_guest_id().await?;
            if let Some(target_pause_id) = self.restore_context.target_pause_id().await {
                container_manager
                    .prepare_restored_container(&target_pause_id, &pause_guest_id)
                    .await
                    .context("prepare restored pause I/O and waiter")?;
            }
            self.agent
                .resume_container(agent::ContainerID {
                    container_id: pause_guest_id,
                })
                .await
                .context("resume restored pause container")?;
            if let Some(target_pause_id) = self.restore_context.target_pause_id().await {
                container_manager
                    .mark_restored_container_running(&target_pause_id)
                    .await
                    .context("mark restored pause running")?;
            }
            self.start_oom_watcher();
            self.monitor.start(&self.sid, self.agent.clone());
            self.restore_context.activate().await?;
            self.inner.write().await.state = SandboxState::Running;
            self.save().await.context("persist active restored sandbox")?;
            Ok(())
        }
        .await;

        if let Err(error) = result {
            self.restore_context.fail().await;
            let _ = self.agent.disconnect().await;
            if let Err(stop_error) = self.hypervisor.stop_vm().await {
                return Err(error.context(format!(
                    "failed to stop restored VMM after activation error: {stop_error:#}"
                )));
            }
            let _ = self.resource_manager.cleanup().await;
            let private_restore = self.restore_private_dir();
            if private_restore.exists() {
                fs::remove_dir_all(&private_restore).with_context(|| {
                    format!(
                        "remove private restore directory {} after activation error",
                        private_restore.display()
                    )
                })?;
            }
            return Err(error);
        }
        Ok(true)
    }

    async fn record_stop(&self, exit_status: u32, exited_at: std::time::SystemTime) {
        let mut inner = self.inner.write().await;
        if inner.state == SandboxState::Stopped {
            return;
        }

        inner.state = SandboxState::Stopped;
        inner.exit_info = Some(SandboxExitInfo {
            exit_status,
            exited_at: Some(exited_at),
        });
        let _ = self.exit_notify_tx.send(true);
    }

    #[instrument]
    async fn prepare_for_start_sandbox(
        &self,
        id: &str,
        sandbox_config: &SandboxConfig,
    ) -> Result<Vec<ResourceConfig>> {
        let mut resource_configs = vec![];

        info!(sl!(), "prepare vm socket config for sandbox.");
        let vm_socket_config = self
            .prepare_vm_socket_config()
            .await
            .context("failed to prepare vm socket config")?;
        resource_configs.push(vm_socket_config);

        let network_env: SandboxNetworkEnv = sandbox_config.network_env.clone();
        // prepare network config
        if !network_env.network_created && !self.should_defer_network().await? {
            if let Some(network_resource) = self.prepare_network_resource(&network_env).await {
                resource_configs.push(network_resource);
            }
        }

        // prepare sharefs device config
        let shared_fs = self.hypervisor.hypervisor_config().await.shared_fs;
        if shared_fs.shared_fs.is_some() {
            resource_configs.push(ResourceConfig::ShareFs(shared_fs));
        }

        // prepare VM rootfs device config
        if let Some(block_config) = self
            .prepare_rootfs_config()
            .await
            .context("failed to prepare rootfs device config")?
        {
            let vm_rootfs = ResourceConfig::VmRootfs(block_config);
            resource_configs.push(vm_rootfs);
        }

        // prepare extra extension image device configs (e.g. CoCo extension)
        let extra_configs = self
            .prepare_guest_extension_images_config()
            .await
            .context("failed to prepare extra images device config")?;
        for block_config in extra_configs {
            resource_configs.push(ResourceConfig::GuestExtensionImage(block_config));
        }

        // prepare protection device config
        let init_data = if let Some(initdata) = self
            .prepare_initdata_device_config(&self.hypervisor.hypervisor_config().await)
            .await
            .context("failed to prepare initdata device config")?
        {
            resource_configs.push(ResourceConfig::InitData(initdata.0));

            Some(initdata.1)
        } else {
            None
        };

        // Cold-plug VFIO devices using two mutually exclusive paths:
        // 1. CDI path: Query Kubernetes Pod Resources API for devices managed by device plugins
        //    (typical in K8s environments with device plugins)
        // 2. Raw VFIO path: Parse OCI spec's linux.devices for directly specified VFIO devices
        //    (typical in standalone containers like `ctr --device /dev/vfio/0`)
        //
        // These paths are mutually exclusive from a user perspective:
        // - In K8s, devices come through device plugins, not raw OCI device specs
        // - In standalone containers, there's no Pod Resources API available
        //
        // Therefore, we only attempt the raw VFIO path if CDI finds no devices,
        // avoiding unnecessary file I/O and OCI spec parsing in the common K8s case.
        let mut vfio_devices = self.prepare_coldplug_cdi_devices(sandbox_config).await?;
        if vfio_devices.is_empty() {
            let raw_vfio = self
                .prepare_coldplug_raw_vfio_devices(sandbox_config)
                .await?;
            vfio_devices.extend(raw_vfio);
        }
        if !vfio_devices.is_empty() {
            info!(
                sl!(),
                "prepare pod devices {vfio_devices:?} for sandbox done."
            );
            resource_configs.extend(vfio_devices);
        } else {
            info!(sl!(), "no pod devices to prepare for sandbox.");
        }

        // prepare protection device config
        if let Some(protection_dev_config) = self
            .prepare_protection_device_config(&self.hypervisor.hypervisor_config().await, init_data)
            .await
            .context("failed to prepare protection device config")?
        {
            resource_configs.push(ResourceConfig::Protection(protection_dev_config));
        }

        // prepare pcie port device config
        if let Some(port_dev_config) = self.prepare_pcie_port_devices().await {
            resource_configs.push(ResourceConfig::PortDevice(port_dev_config));
        }

        Ok(resource_configs)
    }

    async fn prepare_pcie_port_devices(&self) -> Option<PortDeviceConfig> {
        // Fetch the device manager and read the PCIe topology
        let device_manager = self.resource_manager.get_device_manager().await;
        let dm = device_manager.read().await;

        // Get the PCIe topology and port information
        match dm.get_pcie_topology().and_then(|t| t.get_pcie_port()) {
            Some((port_type, total_ports)) if total_ports > 0 => {
                info!(
                    sl!(),
                    "Preparing PCIe {:?} with {} devices for VM.", port_type, total_ports
                );
                Some(PortDeviceConfig::new(port_type, total_ports))
            }
            Some((_, 0)) => {
                info!(sl!(), "No PCIe ports available for VM.");
                None
            }
            _ => {
                info!(
                    sl!(),
                    "Invalid PCIe configuration or no topology available."
                );
                None
            }
        }
    }

    async fn prepare_coldplug_cdi_devices(
        &self,
        sandbox_config: &SandboxConfig,
    ) -> Result<Vec<ResourceConfig>> {
        let hypervisor_config = self.hypervisor.hypervisor_config().await;
        let cold_plug_vfio = &hypervisor_config.device_info.cold_plug_vfio;
        if cold_plug_vfio.is_empty() || cold_plug_vfio == "no-port" {
            return Ok(Vec::new());
        }

        let port = match cold_plug_vfio.as_str() {
            "root-port" => PCIePort::RootPort,
            other => {
                return Err(anyhow!(
                    "unsupported cold_plug_vfio value {:?}; only \"root-port\" is supported",
                    other
                ))
            }
        };

        let config = self.resource_manager.config().await;

        // Collect the VFIO device nodes to cold-plug from two sources so that Kubernetes, docker,
        // and nerdctl are handled by the same path:
        //
        //   1. Kubernetes: the kubelet PodResources API enumerates the CDI devices allocated to the
        //      pod.
        //   2. Docker/nerdctl: the CDI runtime applies the device's containerEdits directly to the
        //      OCI spec, so the VFIO nodes show up in linux.devices (e.g. /dev/vfio/devices/vfio0).
        let mut paths: Vec<String> = Vec::new();

        let pod_resource_socket = &config.runtime.pod_resource_api_sock;
        info!(
            sl!(),
            "sandbox pod_resource_socket: {:?}", pod_resource_socket
        );
        if !pod_resource_socket.is_empty() && Path::new(pod_resource_socket).exists() {
            let annotations = &sandbox_config.annotations;
            debug!(
                sl!(),
                "cold-plug: sandbox-name={:?} sandbox-namespace={:?}",
                annotations.get("io.kubernetes.cri.sandbox-name"),
                annotations.get("io.kubernetes.cri.sandbox-namespace")
            );

            let cdi_devices = pod_resources_rs::pod_resources::get_pod_cdi_devices(
                pod_resource_socket,
                annotations,
            )
            .await
            .context("failed to query Pod Resources CDI devices")?;
            info!(sl!(), "pod cdi devices: {:?}", cdi_devices);

            let device_nodes = handle_cdi_devices(&cdi_devices).await?;
            paths.extend(
                device_nodes
                    .iter()
                    .filter_map(pod_resources_rs::device_node_host_path),
            );
        }

        paths.extend(oci_spec_vfio_device_paths());

        // De-duplicate while preserving discovery order.
        let mut seen = HashSet::new();
        paths.retain(|path| seen.insert(path.clone()));

        if paths.is_empty() {
            return Ok(Vec::new());
        }

        let mut vfio_configs = Vec::new();
        for path in paths.iter() {
            let dev_info = VfioDeviceBase {
                host_path: path.clone(),
                iommu_group_devnode: PathBuf::from(path),
                dev_type: "c".to_string(),
                port,
                hostdev_prefix: "vfio_device".to_owned(),
                ..Default::default()
            };
            vfio_configs.push(dev_info);
        }

        Ok(vfio_configs
            .into_iter()
            .map(ResourceConfig::VfioDeviceModern)
            .collect())
    }

    // Fallback cold-plug path for standalone containers (e.g. `ctr --device /dev/vfio/0`).
    // Reads the OCI spec from the bundle and cold-plugs any VFIO char devices found in
    // linux.devices before VM boot, mirroring Go's coldOrHotPlugVFIO().
    // Returns empty when the pod resources API path already handles devices (K8s) or
    // when cold_plug_vfio is not configured.
    async fn prepare_coldplug_raw_vfio_devices(
        &self,
        sandbox_config: &SandboxConfig,
    ) -> Result<Vec<ResourceConfig>> {
        let hypervisor_config = self.hypervisor.hypervisor_config().await;
        let cold_plug_vfio = &hypervisor_config.device_info.cold_plug_vfio;
        if cold_plug_vfio.is_empty() || cold_plug_vfio == "no-port" {
            return Ok(Vec::new());
        }

        let port = match cold_plug_vfio.as_str() {
            "root-port" => PCIePort::RootPort,
            other => {
                return Err(anyhow!(
                    "unsupported cold_plug_vfio value {:?}; only \"root-port\" is supported",
                    other
                ))
            }
        };

        let bundle = &sandbox_config.state.bundle;
        if bundle.is_empty() {
            return Ok(Vec::new());
        }

        let spec_path = format!("{}/{}", bundle, spec::OCI_SPEC_CONFIG_FILE_NAME);
        let oci_spec = match oci::Spec::load(&spec_path) {
            Ok(s) => s,
            Err(e) => {
                info!(
                    sl!(),
                    "no OCI spec at {:?}: {:?}, skipping raw VFIO cold-plug", spec_path, e
                );
                return Ok(Vec::new());
            }
        };

        let linux_devices = oci_spec
            .linux()
            .as_ref()
            .and_then(|l| l.devices().as_ref())
            .cloned()
            .unwrap_or_default();

        let mut vfio_configs = Vec::new();
        for d in linux_devices.iter() {
            if d.typ() != oci::LinuxDeviceType::C {
                continue;
            }
            let host_path = match get_host_path(DEVICE_TYPE_CHAR, d.major(), d.minor()) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        sl!(),
                        "failed to resolve host path for {:?}: {:?}",
                        d.path(),
                        e
                    );
                    continue;
                }
            };
            // Only process VFIO passthrough devices under /dev/vfio/*.
            // Skip non-VFIO devices and the legacy VFIO control node (/dev/vfio/vfio).
            if !host_path.starts_with("/dev/vfio/") || host_path == "/dev/vfio/vfio" {
                continue;
            }
            let device_port = if is_vfio_ap_device(Path::new(&host_path)) {
                PCIePort::NoPort
            } else {
                port
            };
            vfio_configs.push(VfioDeviceBase {
                host_path: host_path.clone(),
                iommu_group_devnode: PathBuf::from(&host_path),
                dev_type: "c".to_string(),
                port: device_port,
                hostdev_prefix: "vfio_device".to_owned(),
                ..Default::default()
            });
        }
        info!(sl!(), "raw VFIO cold-plug candidates: {:?}", vfio_configs);

        Ok(vfio_configs
            .into_iter()
            .map(ResourceConfig::VfioDeviceModern)
            .collect())
    }

    async fn prepare_network_resource(
        &self,
        network_env: &SandboxNetworkEnv,
    ) -> Option<ResourceConfig> {
        let config = self.resource_manager.config().await;
        let dan_path = dan_config_path(&config, &self.sid);

        // Network priority: DAN > NetNS
        if dan_path.exists() {
            Some(ResourceConfig::Network(NetworkConfig::Dan(
                DanNetworkConfig {
                    dan_conf_path: dan_path,
                    network_queues: self
                        .hypervisor
                        .hypervisor_config()
                        .await
                        .network_info
                        .network_queues as usize,
                },
            )))
        } else if let Some(netns_path) = network_env.netns.as_ref() {
            Some(ResourceConfig::Network(NetworkConfig::NetNs(
                NetworkWithNetNsConfig {
                    network_model: config.runtime.internetworking_model.clone(),
                    netns_path: netns_path.to_owned(),
                    queues: self
                        .hypervisor
                        .hypervisor_config()
                        .await
                        .network_info
                        .network_queues as usize,
                    network_created: network_env.network_created,
                },
            )))
        } else {
            None
        }
    }

    async fn execute_oci_hook_functions(
        &self,
        prestart_hooks: &[oci::Hook],
        create_runtime_hooks: &[oci::Hook],
        state: &spec::State,
    ) -> Result<()> {
        let mut st = state.clone();
        // for dragonball, we use vmm_master_tid
        let vmm_pid = self
            .hypervisor
            .get_vmm_master_tid()
            .await
            .context("get vmm master tid")?;
        st.pid = vmm_pid as i32;

        // Prestart Hooks [DEPRECATED in newest oci spec]:
        // * should be run in runtime namespace
        // * should be run after vm is started, but before container is created
        //      if Prestart Hook and CreateRuntime Hook are both supported
        // * spec details: https://github.com/opencontainers/runtime-spec/blob/c1662686cff159595277b79322d0272f5182941b/config.md#prestart
        let mut prestart_hook_states = HookStates::new();
        prestart_hook_states.execute_hooks(prestart_hooks, Some(st.clone()))?;

        // CreateRuntime Hooks:
        // * should be run in runtime namespace
        // * should be run when creating the runtime
        // * spec details: https://github.com/opencontainers/runtime-spec/blob/c1662686cff159595277b79322d0272f5182941b/config.md#createruntime-hooks
        let mut create_runtime_hook_states = HookStates::new();
        create_runtime_hook_states.execute_hooks(create_runtime_hooks, Some(st.clone()))?;
        Ok(())
    }

    // store_guest_details will get the information from the guest OS, like memory block size, agent details and is memory hotplug probe support
    async fn store_guest_details(&self) -> Result<()> {
        // get the information from agent
        let guest_details = self
            .agent
            .get_guest_details(GetGuestDetailsRequest {
                mem_block_size: true,
                mem_hotplug_probe: true,
            })
            .await
            .context("failed to store guest details")?;

        // set memory block size
        self.hypervisor
            .set_guest_memory_block_size(guest_details.mem_block_size_bytes as u32)
            .await;

        // set memory hotplug probe
        if guest_details.support_mem_hotplug_probe {
            self.hypervisor
                .set_capabilities(CapabilityBits::GuestMemoryProbe)
                .await;
        }
        info!(
            sl!(),
            "memory block size is {}, memory probe support {}",
            self.hypervisor.guest_memory_block_size().await,
            self.hypervisor
                .capabilities()
                .await?
                .is_mem_hotplug_probe_supported()
        );
        Ok(())
    }

    async fn prepare_rootfs_config(&self) -> Result<Option<BlockConfigModern>> {
        let boot_info = self.hypervisor.hypervisor_config().await.boot_info;
        let security_info = self.hypervisor.hypervisor_config().await.security_info;

        if !boot_info.initrd.is_empty() {
            return Ok(None);
        }

        if boot_info.image.is_empty() {
            let is_remote_hypervisor = Arc::clone(&self.resource_manager.config().await)
                .runtime
                .hypervisor_name
                == "remote";
            if (uses_native_ccw_bus() && security_info.confidential_guest) || is_remote_hypervisor {
                return Ok(None);
            } else {
                return Err(anyhow!("both of image and initrd isn't set"));
            }
        }

        Ok(Some(BlockConfigModern {
            path_on_host: boot_info.image.clone(),
            is_readonly: true,
            driver_option: boot_info.vm_rootfs_driver,
            ..Default::default()
        }))
    }

    async fn prepare_guest_extension_images_config(&self) -> Result<Vec<BlockConfigModern>> {
        let hv_config = self.hypervisor.hypervisor_config().await;
        let mut configs = Vec::new();

        // Extension images must be cold-plugged as virtio-blk, because the
        // guest discovers each extension by its deterministic serial
        // (extension-<name>), and only virtio-blk devices carry that serial.
        // We therefore always enforce a virtio-blk transport here (the
        // architecture's virtio-blk-ccw on s390x, virtio-blk-pci elsewhere)
        // rather than reusing vm_rootfs_driver or block_device_driver: those
        // may resolve to a non-virtio-blk transport such as virtio-pmem
        // (NVDIMM, no serial) or virtio-scsi, which would leave the extension
        // undiscoverable and its mount unit would fail closed.
        let block_driver = if uses_native_ccw_bus() {
            VIRTIO_BLK_CCW.to_string()
        } else {
            VIRTIO_BLK_PCI.to_string()
        };
        for extra in &hv_config.guest_extension_images {
            if extra.path.is_empty() {
                continue;
            }
            configs.push(BlockConfigModern {
                path_on_host: extra.path.clone(),
                is_readonly: true,
                driver_option: block_driver.clone(),
                serial_override: format!("extension-{}", extra.name),
                ..Default::default()
            });
        }

        Ok(configs)
    }

    async fn set_agent_policy(&self) -> Result<()> {
        // TODO: Exclude policy-related items from the annotations.
        let toml_config = self.resource_manager.config().await;
        if let Some(agent_config) = toml_config.agent.get(&toml_config.runtime.agent_name) {
            // If a Policy has been specified, send it to the agent.
            if !agent_config.policy.is_empty() {
                info!(
                    sl!(),
                    "Setting Agent Policy with {:?}.", &agent_config.policy
                );
                self.agent
                    .set_policy(SetPolicyRequest {
                        policy: agent_config.policy.clone(),
                    })
                    .await
                    .context("sandbox: set policy failed")?;
            }
        }

        Ok(())
    }

    async fn prepare_vm_socket_config(&self) -> Result<ResourceConfig> {
        // It will check the hypervisor's capabilities to see if it supports hybrid-vsock.
        // If it does not, it'll assume that it only supports legacy vsock.
        let vm_socket = if self
            .hypervisor
            .capabilities()
            .await?
            .is_hybrid_vsock_supported()
        {
            // Firecracker/Dragonball/CLH use the hybrid-vsock device model.
            ResourceConfig::HybridVsock(HybridVsockConfig {
                guest_cid: DEFAULT_GUEST_VSOCK_CID,
                uds_path: get_hvsock_path(&self.sid),
            })
        } else {
            // Qemu uses the vsock device model.
            ResourceConfig::Vsock(VsockConfig {
                guest_cid: libc::VMADDR_CID_ANY,
            })
        };

        Ok(vm_socket)
    }

    async fn prepare_protection_device_config(
        &self,
        hypervisor_config: &HypervisorConfig,
        init_data: Option<String>,
    ) -> Result<Option<ProtectionDeviceConfig>> {
        // No guest protection requested: skip host detection and run without
        // a protection device (also avoids failing on hosts that advertise a
        // protection they cannot use, e.g. SEV without SEV-SNP).
        if !hypervisor_config.security_info.confidential_guest {
            return Ok(None);
        }

        let available_protection = available_guest_protection()?;
        info!(
            sl!(),
            "sandbox: available protection: {:?}", available_protection
        );

        match available_protection {
            GuestProtection::Sev(details) => {
                if hypervisor_config.boot_info.firmware.is_empty() {
                    return Err(anyhow!("SEV protection requires a path to firmaware"));
                }

                Ok(Some(ProtectionDeviceConfig::SevSnp(SevSnpConfig {
                    is_snp: false,
                    cbitpos: details.cbitpos,
                    phys_addr_reduction: details.phys_addr_reduction,
                    firmware: hypervisor_config.boot_info.firmware.clone(),
                    host_data: None,
                })))
            }
            GuestProtection::Snp(details) => {
                if hypervisor_config.boot_info.firmware.is_empty() {
                    return Err(anyhow!("SEV-SNP protection requires a path to firmaware"));
                }

                // If we got here SEV-SNP is available.  However, if
                // 'sev_snp_guest' is 'false' in the configuration file we
                // still have to revert to SEV.
                let is_snp = hypervisor_config.security_info.sev_snp_guest;
                if !is_snp {
                    info!(sl!(), "reverting to SEV even though SEV-SNP is available as requested by 'sev_snp_guest'");
                }

                Ok(Some(ProtectionDeviceConfig::SevSnp(SevSnpConfig {
                    is_snp,
                    cbitpos: details.cbitpos,
                    phys_addr_reduction: details.phys_addr_reduction,
                    firmware: hypervisor_config.boot_info.firmware.clone(),
                    host_data: init_data,
                })))
            }
            GuestProtection::Se => {
                Ok(Some(ProtectionDeviceConfig::Se))
            }
            GuestProtection::Tdx => {
                Ok(Some(ProtectionDeviceConfig::Tdx(TdxConfig {
                    id: "tdx".to_owned(),
                    firmware: hypervisor_config.boot_info.firmware.clone(),
                    qgs_port: hypervisor_config.security_info.qgs_port,
                    mrconfigid: init_data,
                    debug: false,
                })))
            },
            GuestProtection::NoProtection => Ok(None),
            _ => Err(anyhow!("confidential_guest requested by configuration but no supported protection available"))
        }
    }

    async fn prepare_initdata_device_config(
        &self,
        hypervisor_config: &HypervisorConfig,
    ) -> Result<Option<InitDataConfig>> {
        let initdata = hypervisor_config.security_info.initdata.clone();
        if initdata.is_empty() {
            return Ok(None);
        }
        debug!(sl!(), "Init Data Content String: {:?}", &initdata);
        let available_protection = available_guest_protection()?;
        info!(
            sl!(),
            "sandbox: available protection: {:?}", available_protection
        );
        let initdata_digest = match available_protection {
            GuestProtection::Tdx => calculate_initdata_digest(&initdata, ProtectedPlatform::Tdx)?,
            GuestProtection::Snp(_details) => {
                calculate_initdata_digest(&initdata, ProtectedPlatform::Snp)?
            }
            GuestProtection::Se => calculate_initdata_digest(&initdata, ProtectedPlatform::Se)?,
            GuestProtection::NoProtection => {
                calculate_initdata_digest(&initdata, ProtectedPlatform::NoProtection)?
            }
            // TODO: there's more `GuestProtection` types to be supported.
            _ => return Ok(None),
        };
        info!(sl!(), "initdata  digest {:?}", &initdata_digest);

        // initdata within compressed rawblock
        let image_path = Path::new(kata_shared_init_data_path().as_str())
            .join(&self.sid)
            .join(KATA_INIT_DATA_IMAGE);
        initdata_block::push_data(&image_path, &initdata)?;
        info!(
            sl!(),
            "initdata push data into compressed block: {:?}", &image_path
        );
        let block_driver = &hypervisor_config.blockdev_info.block_device_driver;
        let block_config = BlockConfigModern {
            path_on_host: image_path.display().to_string(),
            is_readonly: true,
            driver_option: block_driver.clone(),
            blkdev_aio: BlockDeviceAio::Native,
            ..Default::default()
        };
        let initdata_config = InitDataConfig(block_config, initdata_digest);
        info!(sl!(), "initdata config: {:?}", initdata_config.clone());

        Ok(Some(initdata_config))
    }

    fn has_prestart_hooks(
        &self,
        prestart_hooks: &[oci::Hook],
        create_runtime_hooks: &[oci::Hook],
    ) -> bool {
        !prestart_hooks.is_empty() || !create_runtime_hooks.is_empty()
    }

    fn is_factory_enabled(&self) -> bool {
        self.factory
            .as_ref()
            .map(|factory| factory.enable_template)
            .unwrap_or(false)
    }

    async fn should_defer_network(&self) -> Result<bool> {
        if !self.is_factory_enabled() {
            return Ok(false);
        }

        Ok(self
            .hypervisor
            .capabilities()
            .await?
            .is_network_device_hotplug_supported())
    }

    async fn setup_deferred_network_after_start(
        &self,
        sandbox_config: &SandboxConfig,
    ) -> Result<()> {
        if let Some(ResourceConfig::Network(network_resource)) = self
            .prepare_network_resource(&sandbox_config.network_env)
            .await
        {
            self.resource_manager
                .handle_network(network_resource)
                .await
                .context("set up factory network after start vm")?;
        }

        Ok(())
    }

    /// Build a network rescan config targeting the hypervisor's network
    /// namespace.  Docker 26+ bind-mounts `/proc/<vmm_pid>/ns/net` and
    /// configures veth pairs there between Create and Start, so the
    /// hypervisor netns is where the interfaces will appear — regardless
    /// of whether we earlier created a placeholder netns (network_created)
    /// or not.  This mirrors the Go shim's `detectHypervisorNetns` logic
    /// inside `addAllEndpoints` (commit f7878cc).
    async fn netns_rescan_config(&self) -> Option<NetworkWithNetNsConfig> {
        let toml = self.resource_manager.config().await;
        if toml.runtime.disable_new_netns {
            return None;
        }
        if dan_config_path(&toml, &self.sid).exists() {
            return None;
        }
        self.sandbox_config.as_ref()?;

        let vmm_pid = match self.hypervisor.get_vmm_master_tid().await {
            Ok(pid) => pid,
            Err(e) => {
                warn!(sl!(), "netns_rescan_config: cannot get VMM PID: {:?}", e);
                return None;
            }
        };
        let netns_path = format!("/proc/{}/ns/net", vmm_pid);

        let queues = self
            .hypervisor
            .hypervisor_config()
            .await
            .network_info
            .network_queues as usize;
        Some(NetworkWithNetNsConfig {
            network_model: toml.runtime.internetworking_model.clone(),
            netns_path,
            queues,
            network_created: false,
        })
    }

    async fn create_portable_snapshot(
        &self,
        container_manager: Arc<dyn ContainerManager>,
        destination: &Path,
    ) -> Result<()> {
        if !destination.is_absolute() || destination == Path::new("/") {
            return Err(anyhow!(
                "snapshot destination must be absolute and non-root"
            ));
        }
        if destination
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(anyhow!("snapshot destination must be lexically clean"));
        }
        if destination.exists() {
            return Err(anyhow!(
                "snapshot destination already exists: {}",
                destination.display()
            ));
        }
        let parent = destination
            .parent()
            .ok_or_else(|| anyhow!("snapshot destination has no parent"))?;
        let canonical_parent = parent
            .canonicalize()
            .with_context(|| format!("snapshot parent must already exist: {}", parent.display()))?;
        if canonical_parent != parent {
            return Err(anyhow!(
                "snapshot parent contains a symlink or non-canonical component: {}",
                parent.display()
            ));
        }
        let file_name = destination
            .file_name()
            .ok_or_else(|| anyhow!("snapshot destination has no filename"))?
            .to_string_lossy();
        // Keep an incomplete transaction invisible at the requested path. The
        // sibling staging tree is renamed there only after source recovery.
        let staging = parent.join(format!(".{file_name}.partial-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&staging)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;

        let inventory = container_manager.snapshot_inventory().await?;
        let active_host_ids = inventory
            .live_containers
            .iter()
            .map(|container| container.host_id.clone())
            .collect::<HashSet<_>>();
        // These flags record completed stages so recovery reverses only work
        // that actually happened.
        let mut paused_containers = Vec::new();
        let mut monitor_suspended = false;
        let mut agent_disconnected = false;
        let mut disconnect_token = None;
        let mut vm_paused = false;
        // Ordering is part of the snapshot protocol:
        // 1. stop health RPCs and pause containers while the agent is reachable;
        // 2. drain writes, disconnect, and let the guest agent return to listen;
        // 3. pause the VM and capture a disconnected-listening checkpoint.
        let operation: Result<Vec<resource::rootfs::RootfsSnapshotArtifacts>> = async {
            self.monitor.suspend().await;
            monitor_suspended = true;
            for container in &inventory.live_containers {
                let container_id = common::types::ContainerID::new(&container.host_id)?;
                container_manager
                    .pause_container(&container_id)
                    .await
                    .with_context(|| format!("pause container {}", container_id.container_id))?;
                paused_containers.push(container_id);
            }

            let token = self
                .agent
                .prepare_disconnect()
                .await
                .context("prepare planned agent disconnect")?;
            disconnect_token = Some(token);
            agent_disconnected = true;
            self.agent
                .disconnect()
                .await
                .context("disconnect source agent")?;
            tokio::time::sleep(SOURCE_AGENT_LISTEN_GRACE).await;

            self.hypervisor.pause_vm().await.context("pause VM")?;
            vm_paused = true;

            self.save().await.context("persist sandbox state")?;
            let clh_staging = staging.join("clh");
            fs::create_dir(&clh_staging)?;
            fs::set_permissions(&clh_staging, fs::Permissions::from_mode(0o700))?;
            self.hypervisor
                .save_vm(&clh_staging)
                .await
                .context("save VM snapshot")?;
            let artifacts = self
                .resource_manager
                .snapshot_rootfs_artifacts(&staging, destination, &active_host_ids)
                .await
                .context("package rootfs snapshot artifacts")?;
            resource::rootfs::snapshot::finalize_snapshot_config(&clh_staging, &artifacts)
                .context("finalize snapshot config")?;

            let persist_source = PathBuf::from(kata_types::prefix_with_rootless_dir(
                kata_types::config::KATA_PATH,
            ))
            .join(&self.sid)
            .join(persist::PERSIST_FILE);
            if !persist_source.is_file() {
                return Err(anyhow!(
                    "runtime state is unavailable: {}",
                    persist_source.display()
                ));
            }
            let persist_destination = staging.join("runtime-state.json");
            reflink_copy(&persist_source, &persist_destination)?;
            fs::set_permissions(&persist_destination, fs::Permissions::from_mode(0o600))?;
            Ok(artifacts)
        }
        .await;

        // Recover in the opposite dependency order. The VM must run before the
        // agent can reconnect, and containers/monitor must remain paused until
        // reconnectable RPCs have acquired the new healthy generation.
        let mut recovery_error: Option<anyhow::Error> = None;
        let mut vm_ready = !vm_paused;
        if vm_paused {
            match self.hypervisor.resume_vm().await.context("resume VM") {
                Ok(()) => vm_ready = true,
                Err(error) => recovery_error = Some(error),
            }
        }

        let mut agent_ready = !agent_disconnected;
        if agent_disconnected && vm_ready {
            let reconnect_result: Result<()> = async {
                let token = disconnect_token
                    .ok_or_else(|| anyhow!("missing source agent disconnect token"))?;
                let address = self
                    .hypervisor
                    .get_agent_socket()
                    .await
                    .context("get source agent socket")?;
                self.agent
                    .reconnect(&address, token)
                    .await
                    .context("reconnect source agent")?;
                self.agent
                    .check(agent::CheckRequest::new(""))
                    .await
                    .context("health-check reconnected source agent")?;
                Ok(())
            }
            .await;
            match reconnect_result {
                Ok(()) => agent_ready = true,
                Err(error) => {
                    recovery_error = Some(match recovery_error {
                        Some(previous) => previous.context(error.to_string()),
                        None => error,
                    });
                }
            }
        }

        if agent_ready {
            for container_id in paused_containers.iter().rev() {
                if let Err(error) = container_manager
                    .resume_container(container_id)
                    .await
                    .with_context(|| format!("resume container {}", container_id.container_id))
                {
                    recovery_error = Some(match recovery_error {
                        Some(previous) => previous.context(error.to_string()),
                        None => error,
                    });
                }
            }
        }
        if monitor_suspended && agent_ready {
            self.monitor.resume();
        }

        // Never publish an artifact unless both capture and source recovery
        // succeeded. A failed recovery is a failed snapshot transaction.
        let artifacts = match (operation, recovery_error) {
            (Ok(artifacts), None) => artifacts,
            (Err(primary), None) => {
                let _ = fs::remove_dir_all(&staging);
                return Err(primary);
            }
            (Ok(_), Some(recovery)) => {
                let _ = fs::remove_dir_all(&staging);
                return Err(recovery);
            }
            (Err(primary), Some(recovery)) => {
                let _ = fs::remove_dir_all(&staging);
                return Err(primary.context(format!("snapshot recovery failed: {recovery:#}")));
            }
        };

        let agent_config = self.agent.agent_config().await;

        let publication: Result<()> = (|| {
            let clh_staging = staging.join("clh");
            let mut file_paths = vec![
                clh_staging.join("config.json"),
                clh_staging.join("state.json"),
                staging.join("runtime-state.json"),
            ];
            for optional in ["memory-ranges"] {
                let path = clh_staging.join(optional);
                if path.is_file() {
                    file_paths.push(path);
                }
            }
            for artifact in &artifacts {
                file_paths.extend(artifact.files.iter().cloned());
            }
            file_paths.sort();
            file_paths.dedup();
            let files = file_paths
                .iter()
                .map(|path| snapshot_file_manifest(&staging, path))
                .collect::<Result<Vec<_>>>()?;
            let clh_config: serde_json::Value =
                serde_json::from_slice(&fs::read(clh_staging.join("config.json"))?)
                    .context("parse finalized snapshot config")?;
            // Rootfs artifacts and live identity inventory are independently
            // produced; current host ID is their common snapshot-generation key.
            let identities_by_host = inventory
                .live_containers
                .iter()
                .map(|container| (container.host_id.as_str(), container))
                .collect::<HashMap<_, _>>();
            let live_containers = artifacts
                .iter()
                .map(|artifact| {
                    let identity = identities_by_host
                        .get(artifact.source_host_id.as_str())
                        .ok_or_else(|| {
                            anyhow!(
                                "snapshot storage has no live identity for host container {}",
                                artifact.source_host_id
                            )
                        })?;
                    if identity.cri_name != artifact.cri_name {
                        return Err(anyhow!(
                            "snapshot identity name {} does not match storage name {}",
                            identity.cri_name,
                            artifact.cri_name
                        ));
                    }
                    Ok(SnapshotLiveContainerManifest {
                        cri_name: identity.cri_name.clone(),
                        source_host_id: identity.host_id.clone(),
                        snapshot_guest_id: identity.guest_id.clone(),
                        oci_identity_version: identity.oci_identity_version,
                        oci_identity_sha256: identity.oci_identity_sha256.clone(),
                        node_local_mounts: identity
                            .node_local_mounts
                            .iter()
                            .map(|mount| SnapshotMountManifest {
                                destination: mount.destination.clone(),
                                guest_source: mount.guest_source.clone(),
                            })
                            .collect(),
                        readonly_disk_id: snapshot_disk_id(
                            &clh_config,
                            &artifact.readonly_disk.snapshot_path,
                        )?,
                        readonly_disk: relative_snapshot_path(
                            destination,
                            &artifact.readonly_disk.snapshot_path,
                        )?,
                        writable_disk_id: artifact
                            .writable_disk
                            .as_ref()
                            .map(|disk| snapshot_disk_id(&clh_config, &disk.snapshot_path))
                            .transpose()?,
                        writable_disk: artifact
                            .writable_disk
                            .as_ref()
                            .map(|disk| relative_snapshot_path(destination, &disk.snapshot_path))
                            .transpose()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let mut container_names = HashSet::new();
            for container in &live_containers {
                if !container_names.insert(container.cri_name.as_str()) {
                    return Err(anyhow!(
                        "snapshot has duplicate live container name {}",
                        container.cri_name
                    ));
                }
            }
            let completed_containers = inventory
                .completed_containers
                .iter()
                .map(|container| {
                    if !container_names.insert(container.cri_name.as_str()) {
                        return Err(anyhow!(
                            "snapshot container name {} is both live and completed",
                            container.cri_name
                        ));
                    }
                    Ok(SnapshotCompletedContainerManifest {
                        cri_name: container.cri_name.clone(),
                        exit_code: container.exit_code,
                        oci_identity_version: container.oci_identity_version,
                        oci_identity_sha256: container.oci_identity_sha256.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let manifest = SnapshotManifest {
                format_version: 1,
                producer: "runtime-rs".to_string(),
                hypervisor: "cloud-hypervisor".to_string(),
                source_sandbox_id: self.sid.clone(),
                agent_transport: SnapshotAgentTransportManifest {
                    contract_version: 1,
                    state: "disconnected-listening".to_string(),
                    server_port: agent_config.server_port,
                    log_port: agent_config.log_port,
                },
                live_containers,
                completed_containers,
                files,
            };
            let manifest_path = staging.join("kata-snapshot.json");
            fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
            fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))?;
            fs::rename(&staging, destination).with_context(|| {
                format!(
                    "publish snapshot {} to {}",
                    staging.display(),
                    destination.display()
                )
            })?;
            Ok(())
        })();
        if publication.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        publication
    }
}

/// Collect VFIO character device nodes (e.g. /dev/vfio/devices/vfio0) that a CDI
/// runtime injected directly into the OCI spec for the Docker/nerdctl/podman
/// flow, where there is no kubelet PodResources API to query. The legacy
/// `/dev/vfio/vfio` control node is skipped as it is not a pass-through device.
fn oci_spec_vfio_device_paths() -> Vec<String> {
    let Ok(spec) = load_oci_spec() else {
        return Vec::new();
    };
    let Some(linux) = spec.linux() else {
        return Vec::new();
    };
    let Some(devices) = linux.devices() else {
        return Vec::new();
    };

    devices
        .iter()
        .filter(|dev| dev.typ() == oci::LinuxDeviceType::C)
        .map(|dev| dev.path().display().to_string())
        .filter(|path| path.starts_with("/dev/vfio") && path != "/dev/vfio/vfio")
        .collect()
}

#[async_trait]
impl Sandbox for VirtSandbox {
    #[instrument(name = "sb: start")]
    async fn start(&self) -> Result<()> {
        let id = &self.sid;

        if self.sandbox_config.is_none() {
            return Err(anyhow!("sandbox config is missing"));
        }
        let sandbox_config = self.sandbox_config.as_ref().unwrap();

        // if sandbox is not in SandboxState::Init then return,
        // otherwise try to create sandbox

        let mut inner = self.inner.write().await;
        if inner.state != SandboxState::Init {
            warn!(sl!(), "sandbox is started");
            return Ok(());
        }
        // Annotation-driven packaged restore supersedes factory cloning and
        // cold boot. It returns with CLH paused for the sandbox-start barrier.
        if self
            .start_restore_if_requested(sandbox_config, &mut inner)
            .await?
        {
            return Ok(());
        }
        let selinux_label = load_oci_spec().ok().and_then(|spec| {
            spec.process()
                .as_ref()
                .and_then(|process| process.selinux_label().clone())
        });

        self.hypervisor
            .prepare_vm(
                id,
                sandbox_config.network_env.netns.clone(),
                &sandbox_config.annotations,
                selinux_label,
            )
            .await
            .context("prepare vm")?;

        let defer_network = self.should_defer_network().await?;

        // generate device and setup before start vm
        // should after hypervisor.prepare_vm
        let resources = self.prepare_for_start_sandbox(id, sandbox_config).await?;

        self.resource_manager
            .prepare_before_start_vm(resources)
            .await
            .context("set up device before start vm")?;

        // Factory clones restore through the generic hypervisor primitive;
        // ordinary sandboxes cold boot.
        if self.is_factory_enabled() {
            let hypervisor_config = self.hypervisor.hypervisor_config().await;
            self.hypervisor
                .restore_vm(RestoreVmRequest {
                    snapshot_dir: PathBuf::from(&hypervisor_config.factory.template_path),
                    memory_restore_mode: hypervisor_config.memory_info.memory_restore_mode,
                    network: Vec::new(),
                    timeout_secs: VMM_START_TIMEOUT_SECS,
                })
                .await
                .context("restore factory vm")?;
            self.hypervisor
                .resume_vm()
                .await
                .context("resume factory vm")?;
        } else {
            self.hypervisor
                .start_vm(VMM_START_TIMEOUT_SECS)
                .await
                .context("start vm")?;
        }
        info!(sl!(), "start vm");

        let sandbox = self.clone();
        // wait for vm exit in background, and record the exit status and time when vm exited.
        tokio::spawn(async move {
            match sandbox.hypervisor.wait_vm().await {
                Ok(exit_code) => {
                    sandbox
                        .record_stop(exit_code as u32, SystemTime::now())
                        .await;
                }
                Err(err) => {
                    warn!(sl!(), "failed waiting for sandbox VM exit: {:?}", err);
                    sandbox.record_stop(255, SystemTime::now()).await;
                }
            }
        });

        // execute pre-start hook functions, including Prestart Hooks and CreateRuntime Hooks
        let (prestart_hooks, create_runtime_hooks) =
            if let Some(hooks) = sandbox_config.hooks.as_ref() {
                (
                    hooks.prestart().clone().unwrap_or_default(),
                    hooks.create_runtime().clone().unwrap_or_default(),
                )
            } else {
                (Vec::new(), Vec::new())
            };

        self.execute_oci_hook_functions(
            &prestart_hooks,
            &create_runtime_hooks,
            &sandbox_config.state,
        )
        .await?;

        // 1. if there are pre-start hook functions, network config might have been changed.
        //    We need to rescan the netns to handle the change.
        // 2. Do not scan the netns if we want no network for the VM.
        // QEMU and Cloud Hypervisor advertise network hotplug support, so
        // factory VMs using them defer network setup until after VM startup.
        // Backends without this capability retain pre-start setup.
        let config = self.resource_manager.config().await;
        if self.has_prestart_hooks(&prestart_hooks, &create_runtime_hooks)
            && !defer_network
            && !config.runtime.disable_new_netns
            && !dan_config_path(&config, &self.sid).exists()
        {
            if let Some(netns_path) = &sandbox_config.network_env.netns {
                let network_resource = NetworkConfig::NetNs(NetworkWithNetNsConfig {
                    network_model: config.runtime.internetworking_model.clone(),
                    netns_path: netns_path.to_owned(),
                    queues: self
                        .hypervisor
                        .hypervisor_config()
                        .await
                        .network_info
                        .network_queues as usize,
                    network_created: sandbox_config.network_env.network_created,
                });
                self.resource_manager
                    .handle_network(network_resource)
                    .await
                    .context("set up device after start vm")?;
            }
        }

        if defer_network {
            self.setup_deferred_network_after_start(sandbox_config)
                .await?;
        }

        // connect agent
        // set agent socket
        let address = self
            .hypervisor
            .get_agent_socket()
            .await
            .context("get agent socket")?;
        self.agent
            .start(&address)
            .await
            .context(format!("connect to address {:?}", &address))?;
        self.set_agent_policy().await.context("set agent policy")?;

        self.resource_manager
            .setup_after_start_vm()
            .await
            .context("setup device after start vm")?;

        // create sandbox in vm
        let agent_config = self.agent.agent_config().await;
        let kernel_modules = KernelModule::set_kernel_modules(agent_config.kernel_modules)?;
        let req = agent::CreateSandboxRequest {
            hostname: sandbox_config.hostname.clone(),
            dns: sandbox_config.dns.clone(),
            storages: self
                .resource_manager
                .get_storage_for_sandbox(self.shm_size)
                .await
                .context("get storages for sandbox")?,
            sandbox_pidns: false,
            sandbox_id: id.to_string(),
            guest_hook_path: self
                .hypervisor
                .hypervisor_config()
                .await
                .security_info
                .guest_hook_path,
            kernel_modules,
        };

        self.agent
            .create_sandbox(req)
            .await
            .context("create sandbox")?;

        inner.state = SandboxState::Running;
        inner.created_at = Some(std::time::SystemTime::now());

        // get and store guest details
        self.store_guest_details()
            .await
            .context("failed to store guest details")?;

        self.start_oom_watcher();

        self.monitor.start(id, self.agent.clone());
        self.save().await.context("save state")?;

        Ok(())
    }

    async fn snapshot(
        &self,
        container_manager: Arc<dyn ContainerManager>,
        destination: &Path,
    ) -> Result<()> {
        self.create_portable_snapshot(container_manager, destination)
            .await
    }

    async fn activate_restore(
        &self,
        container_manager: Arc<dyn ContainerManager>,
        target_id: &str,
    ) -> Result<bool> {
        self.activate_restore_transaction(container_manager, target_id)
            .await
    }

    async fn persist_runtime_state(&self) -> Result<()> {
        self.save().await.map(drop)
    }

    /// Core function for starting a VM from a template
    ///
    /// This function is responsible for creating and starting a VM sandbox from a predefined template,
    /// serving as the core implementation of the template mechanism.
    async fn start_template(&self) -> Result<()> {
        info!(sl!(), "sandbox::start_template()"; "sandbox:" => format!("{:?}", self));
        let id = &self.sid;

        let sandbox_config = self.sandbox_config.as_ref().unwrap();

        // if sandbox is not in SandboxState::Init then return,
        // otherwise try to create sandbox
        let inner = self.inner.write().await;
        if inner.state != SandboxState::Init {
            return Ok(());
        }
        let selinux_label = load_oci_spec().ok().and_then(|spec| {
            spec.process()
                .as_ref()
                .and_then(|process| process.selinux_label().clone())
        });

        self.hypervisor
            .prepare_vm(
                id,
                sandbox_config.network_env.netns.clone(),
                &sandbox_config.annotations,
                selinux_label,
            )
            .await
            .context("prepare vm")?;

        // generate device and setup before start vm
        // should after hypervisor.prepare_vm
        let resources = self
            .prepare_for_start_sandbox(id, sandbox_config)
            .await
            .context("prepare resources before start vm")?;

        self.resource_manager
            .prepare_before_start_vm(resources)
            .await
            .context("set up device before start vm")?;

        self.hypervisor
            .start_vm(VMM_START_TIMEOUT_SECS)
            .await
            .context("start template vm")?;
        info!(sl!(), "vm started from template");

        let sandbox = self.clone();
        tokio::spawn(async move {
            match sandbox.hypervisor.wait_vm().await {
                Ok(exit_code) => {
                    sandbox
                        .record_stop(exit_code as u32, SystemTime::now())
                        .await;
                }
                Err(err) => {
                    warn!(sl!(), "failed waiting for sandbox VM exit: {:?}", err);
                    sandbox.record_stop(255, SystemTime::now()).await;
                }
            }
        });

        Ok(())
    }

    async fn status(&self) -> Result<SandboxStatus> {
        let inner = self.inner.read().await;
        let state = inner.state.to_cri_state().to_string();

        Ok(SandboxStatus {
            sandbox_id: self.sid.clone(),
            pid: std::process::id(),
            state,
            info: std::collections::HashMap::new(),
            created_at: inner.created_at,
        })
    }

    async fn wait(&self) -> Result<SandboxExitInfo> {
        info!(sl!(), "wait sandbox");
        {
            let inner = self.inner.read().await;
            if inner.state == SandboxState::Stopped {
                return Ok(inner.exit_info.clone().unwrap_or_default());
            }
        }

        let mut exit_notify_rx = self.exit_notify_tx.subscribe();
        while !*exit_notify_rx.borrow() {
            exit_notify_rx
                .changed()
                .await
                .context("wait for sandbox stop notification")?;
        }

        let inner = self.inner.read().await;
        Ok(inner.exit_info.clone().unwrap_or_default())
    }

    async fn stop(&self) -> Result<()> {
        let state = {
            let sandbox_inner = self.inner.read().await;
            sandbox_inner.state
        };

        if state == SandboxState::Stopped {
            return Ok(());
        }

        // Cancel the OOM watcher before tearing down the VM so it exits
        // cleanly instead of hitting ECONNRESET/EOF on a closed channel.
        self.cancel_token.cancel();

        info!(sl!(), "begin stop sandbox");
        if state == SandboxState::Init {
            let _ = self.hypervisor.stop_vm().await;
            self.record_stop(0, SystemTime::now()).await;
            info!(sl!(), "sandbox stopped during Init");
            return Ok(());
        }

        self.hypervisor.stop_vm().await.context("stop vm")?;
        self.wait().await.context("wait for vm exit after stop")?;
        info!(sl!(), "sandbox stopped");

        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        info!(sl!(), "shutdown");

        self.stop().await.context("stop")?;

        self.cleanup().await.context("do the clean up")?;

        info!(sl!(), "stop monitor");
        self.monitor.stop().await;

        info!(sl!(), "stop agent");
        self.agent.stop().await;

        // stop server
        info!(sl!(), "send shutdown message");
        let msg = Message::new(Action::Shutdown);
        let sender = self.msg_sender.clone();
        let sender = sender.lock().await;
        sender.send(msg).await.context("send shutdown msg")?;
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        // Teardown may be triggered both when the sandbox container exits and
        // by a later shutdown RPC; only release the resources once.
        {
            let mut inner = self.inner.write().await;
            if inner.cleaned {
                return Ok(());
            }
            inner.cleaned = true;
        }

        let rootless_uid = self
            .hypervisor
            .hypervisor_config()
            .await
            .security_info
            .rootless_user
            .map(|user| user.uid);

        info!(sl!(), "delete hypervisor");
        self.hypervisor
            .cleanup()
            .await
            .context("delete hypervisor")?;

        info!(sl!(), "resource clean up");
        self.resource_manager
            .cleanup()
            .await
            .context("resource clean up")?;

        if let Some(uid) = rootless_uid {
            let path = vmm_user_runtime_dir(uid);
            if let Err(err) = remove_vmm_user_runtime_dir(uid) {
                warn!(
                    sl!(),
                    "failed to remove rootless runtime directory {}: {}",
                    path.display(),
                    err
                );
            }
        }

        // TODO: cleanup other sandbox resource
        Ok(())
    }

    async fn rescan_network(&self) -> Result<()> {
        if let Some(net_cfg) = self.netns_rescan_config().await {
            info!(
                sl!(),
                "rescan_network: scanning netns={}", net_cfg.netns_path
            );
            self.resource_manager
                .rescan_network_if_unconfigured(net_cfg)
                .await
                .context("network rescan during start")?;
        }
        Ok(())
    }

    async fn wait_process(
        &self,
        cm: Arc<dyn ContainerManager>,
        process_id: ContainerProcess,
        shim_pid: u32,
    ) -> Result<()> {
        let exit_status = cm.wait_process(&process_id).await?;
        info!(sl!(), "container process exited with {:?}", exit_status);

        if cm.is_sandbox_container(&process_id).await {
            self.stop().await.context("stop sandbox")?;
        }

        let cid = process_id.container_id();
        if cid.is_empty() {
            return Err(anyhow!("container id is empty"));
        }
        let eid = process_id.exec_id();
        let id = if eid.is_empty() {
            cid.to_string()
        } else {
            eid.to_string()
        };

        let event = TaskExit {
            container_id: cid.to_string(),
            id,
            pid: shim_pid,
            exit_status: exit_status.exit_code as u32,
            exited_at: option_system_time_into(exit_status.exit_time),
            special_fields: SpecialFields::new(),
        };
        let msg = Message::new(Action::Event(Arc::new(event)));
        let lock_sender = self.msg_sender.lock().await;
        lock_sender.send(msg).await.context("send exit event")?;
        Ok(())
    }

    async fn agent_sock(&self) -> Result<String> {
        self.agent.agent_sock().await
    }

    async fn direct_volume_stats(&self, volume_guest_path: &str) -> Result<String> {
        let req: agent::VolumeStatsRequest = VolumeStatsRequest {
            volume_guest_path: volume_guest_path.to_string(),
        };
        let result = self
            .agent
            .get_volume_stats(req)
            .await
            .context("sandbox: failed to process direct volume stats query")?;
        Ok(result.data)
    }

    async fn direct_volume_resize(&self, resize_req: agent::ResizeVolumeRequest) -> Result<()> {
        self.agent
            .resize_volume(resize_req)
            .await
            .context("sandbox: failed to resize direct-volume")?;
        Ok(())
    }

    async fn set_iptables(&self, is_ipv6: bool, data: Vec<u8>) -> Result<Vec<u8>> {
        info!(sl!(), "sb: set_iptables invoked");
        let req = SetIPTablesRequest { is_ipv6, data };
        let resp = self
            .agent
            .set_ip_tables(req)
            .await
            .context("sandbox: failed to set iptables")?;
        Ok(resp.data)
    }

    async fn get_iptables(&self, is_ipv6: bool) -> Result<Vec<u8>> {
        info!(sl!(), "sb: get_iptables invoked");
        let req = GetIPTablesRequest { is_ipv6 };
        let resp = self
            .agent
            .get_ip_tables(req)
            .await
            .context("sandbox: failed to get iptables")?;
        Ok(resp.data)
    }

    async fn agent_metrics(&self) -> Result<String> {
        self.agent
            .get_metrics(agent::Empty::new())
            .await
            .map_err(|err| anyhow!("failed to get agent metrics {:?}", err))
            .map(|resp| resp.metrics)
    }

    async fn hypervisor_metrics(&self) -> Result<String> {
        self.hypervisor.get_hypervisor_metrics().await
    }

    async fn set_policy(&self, policy: &str) -> Result<()> {
        if policy.is_empty() {
            debug!(sl!(), "sb: set_policy skipped without policy");
            return Ok(());
        }

        info!(sl!(), "sb: set_policy invoked");
        let policy_req = SetPolicyRequest {
            policy: policy.to_string(),
        };
        self.agent
            .set_policy(policy_req)
            .await
            .context("sandbox: failed to set policy")?;

        Ok(())
    }
}

#[async_trait]
impl Persist for VirtSandbox {
    type State = crate::sandbox_persist::SandboxState;
    type ConstructorArgs = SandboxRestoreArgs;

    /// Save a state of Sandbox
    async fn save(&self) -> Result<Self::State> {
        let hypervisor_state = self.hypervisor.save_state().await?;
        let sandbox_state = crate::sandbox_persist::SandboxState {
            sandbox_type: VIRTCONTAINER.to_string(),
            resource: Some(self.resource_manager.save().await?),
            hypervisor: match hypervisor_state.hypervisor_type.as_str() {
                #[cfg(all(
                    feature = "dragonball",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                HYPERVISOR_DRAGONBALL => Ok(Some(hypervisor_state)),
                #[cfg(all(
                    feature = "cloud-hypervisor",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                HYPERVISOR_NAME_CH => Ok(Some(hypervisor_state)),
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                HYPERVISOR_FIRECRACKER => Ok(Some(hypervisor_state)),
                HYPERVISOR_QEMU => Ok(Some(hypervisor_state)),
                HYPERVISOR_REMOTE => Ok(Some(hypervisor_state)),
                #[cfg(all(
                    feature = "openvmm",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                HYPERVISOR_NAME_OPENVMM => Ok(Some(hypervisor_state)),
                _ => Err(anyhow!(
                    "Unsupported hypervisor {}",
                    hypervisor_state.hypervisor_type
                )),
            }?,
            restore: Some(self.restore_context.persist_state().await),
        };
        // FIXME: properly handle jailed case
        // eg: Determine if we are running jailed:
        // let h = sandbox_state.hypervisor.clone().unwrap_or_default();
        // Figure out the jailed path:
        // jailed_path = h.<>
        // and somehow store the sandbox state into the jail:
        // persist::to_disk(&sandbox_state, &self.sid, jailed_path)?;
        // Issue is, how to handle restore.
        let h = sandbox_state.hypervisor.as_ref().unwrap();
        let vmpath = match h.jailed {
            true => h.vm_path.clone(),
            false => "".to_string(),
        };
        persist::to_disk(&sandbox_state, &self.sid, vmpath.as_str())?;
        Ok(sandbox_state)
    }
    /// Restore Sandbox
    async fn restore(
        sandbox_args: Self::ConstructorArgs,
        sandbox_state: Self::State,
    ) -> Result<Self> {
        let config = sandbox_args.toml_config;
        let restore_state = sandbox_state.restore;
        let r = sandbox_state.resource.unwrap_or_default();
        let h = sandbox_state.hypervisor.unwrap_or_default();
        let hypervisor = match h.hypervisor_type.as_str() {
            #[cfg(all(
                feature = "dragonball",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            HYPERVISOR_DRAGONBALL => {
                let hypervisor = Arc::new(Dragonball::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            #[cfg(all(
                feature = "cloud-hypervisor",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            HYPERVISOR_NAME_CH => {
                let hypervisor =
                    Arc::new(CloudHypervisor::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            HYPERVISOR_FIRECRACKER => {
                let hypervisor =
                    Arc::new(Firecracker::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            HYPERVISOR_QEMU => {
                let hypervisor = Arc::new(Qemu::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            HYPERVISOR_REMOTE => {
                let hypervisor = Arc::new(Remote::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            #[cfg(all(
                feature = "openvmm",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            HYPERVISOR_NAME_OPENVMM => {
                let hypervisor = Arc::new(OpenVmm::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            _ => Err(anyhow!("Unsupported hypervisor {}", &h.hypervisor_type)),
        }?;
        let agent = Arc::new(KataAgent::new(kata_types::config::Agent::default()));
        let sid = sandbox_args.sid;
        let keep_abnormal = config.runtime.keep_abnormal;
        let args = ManagerArgs {
            sid: sid.clone(),
            agent: agent.clone(),
            hypervisor: hypervisor.clone(),
            config,
        };
        let resource_manager = Arc::new(ResourceManager::restore(args, r).await?);
        let restore_context = Arc::new(RestoreContext::from_persist(&sid, restore_state)?);
        Ok(Self {
            sid: sid.to_string(),
            msg_sender: Arc::new(Mutex::new(sandbox_args.sender)),
            inner: Arc::new(RwLock::new(SandboxInner::new())),
            agent,
            hypervisor,
            resource_manager,
            monitor: Arc::new(HealthCheck::new(true, keep_abnormal)),
            exit_notify_tx: watch::channel(false).0,
            sandbox_config: None,
            shm_size: DEFAULT_SHM_SIZE,
            factory: None,
            cancel_token: CancellationToken::default(),
            restore_context,
        })
    }
}
