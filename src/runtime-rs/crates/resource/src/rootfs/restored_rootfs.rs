// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use agent::Storage;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use kata_sys_util::fs::reflink_copy;
use oci_spec::runtime as oci;
use tokio::sync::{Mutex, RwLock};

use super::{Rootfs, RootfsSnapshotArtifacts, SnapshotDiskPath};

#[derive(Clone, Debug)]
pub struct RestoredRootfsConfig {
    pub cri_name: String,
    pub host_id: String,
    pub guest_id: String,
    pub device_ids: Vec<String>,
    pub readonly_disk: PathBuf,
    pub writable_disk: Option<PathBuf>,
    pub files: Vec<PathBuf>,
}

#[derive(Debug)]
struct RestoredRootfsIdentity {
    host_id: String,
    guest_id: String,
}

#[derive(Debug)]
struct RestoredDeviceReferences {
    counts: HashMap<String, usize>,
}

impl RestoredDeviceReferences {
    fn new(configs: &[RestoredRootfsConfig]) -> Result<Self> {
        let mut counts = HashMap::<String, usize>::new();
        for config in configs {
            let unique = config.device_ids.iter().collect::<HashSet<_>>();
            if unique.len() != config.device_ids.len() {
                return Err(anyhow!(
                    "restored rootfs {} contains duplicate device IDs",
                    config.cri_name
                ));
            }
            for device_id in &config.device_ids {
                let count = counts.entry(device_id.clone()).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("restored device reference count overflow"))?;
            }
        }
        Ok(Self { counts })
    }

    fn release(&mut self, device_id: &str) -> Result<bool> {
        let count = self
            .counts
            .get_mut(device_id)
            .ok_or_else(|| anyhow!("restored device {device_id} has no reference count"))?;
        if *count > 1 {
            *count -= 1;
            return Ok(false);
        }
        self.counts.remove(device_id);
        Ok(true)
    }

    fn retain(&mut self, device_id: &str) -> Result<()> {
        let count = self.counts.entry(device_id.to_string()).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| anyhow!("restored device reference count overflow"))?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RestoredRootfs {
    cri_name: String,
    identity: Arc<RwLock<RestoredRootfsIdentity>>,
    device_ids: Vec<String>,
    readonly_disk: PathBuf,
    writable_disk: Option<PathBuf>,
    files: Vec<PathBuf>,
    device_references: Arc<Mutex<RestoredDeviceReferences>>,
}

impl RestoredRootfs {
    fn new(
        config: RestoredRootfsConfig,
        device_references: Arc<Mutex<RestoredDeviceReferences>>,
    ) -> Result<Self> {
        if config.cri_name.is_empty()
            || config.host_id.is_empty()
            || config.guest_id.is_empty()
            || config.device_ids.is_empty()
            || config.device_ids.iter().any(String::is_empty)
        {
            return Err(anyhow!("restored rootfs identity is incomplete"));
        }
        if config.files.is_empty() || !config.readonly_disk.is_file() {
            return Err(anyhow!("restored rootfs file graph is incomplete"));
        }
        if config
            .writable_disk
            .as_ref()
            .is_some_and(|path| !path.is_file())
        {
            return Err(anyhow!("restored writable disk is unavailable"));
        }
        Ok(Self {
            cri_name: config.cri_name,
            identity: Arc::new(RwLock::new(RestoredRootfsIdentity {
                host_id: config.host_id,
                guest_id: config.guest_id,
            })),
            device_ids: config.device_ids,
            readonly_disk: config.readonly_disk,
            writable_disk: config.writable_disk,
            files: config.files,
            device_references,
        })
    }

    pub(super) fn from_configs(configs: Vec<RestoredRootfsConfig>) -> Result<Vec<Self>> {
        let references = Arc::new(Mutex::new(RestoredDeviceReferences::new(&configs)?));
        configs
            .into_iter()
            .map(|config| Self::new(config, references.clone()))
            .collect()
    }

    fn file_name(path: &Path) -> Result<&std::ffi::OsStr> {
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        {
            return Err(anyhow!("restored rootfs path is not clean"));
        }
        path.file_name()
            .ok_or_else(|| anyhow!("restored rootfs path has no filename"))
    }
}

#[async_trait]
impl Rootfs for RestoredRootfs {
    async fn get_guest_rootfs_path(&self) -> Result<String> {
        Ok("/run/kata-containers/shared/containers/restored/rootfs".to_string())
    }

    async fn get_rootfs_mount(&self) -> Result<Vec<oci::Mount>> {
        Ok(Vec::new())
    }

    async fn get_storage(&self) -> Option<Vec<Storage>> {
        None
    }

    async fn cleanup(&self, device_manager: &RwLock<DeviceManager>) -> Result<()> {
        let device_manager = device_manager.read().await;
        let mut references = self.device_references.lock().await;
        for device_id in self.device_ids.iter().rev() {
            if references.release(device_id)? {
                if let Err(error) = device_manager.remove_restored_device(device_id).await {
                    references.retain(device_id)?;
                    return Err(error)
                        .with_context(|| format!("remove restored rootfs device {device_id}"));
                }
            }
        }
        Ok(())
    }

    async fn get_device_id(&self) -> Result<Option<String>> {
        Ok(None)
    }

    fn restored_cri_name(&self) -> Option<&str> {
        Some(&self.cri_name)
    }

    async fn rebind_restored(&self, target_id: &str) -> Result<()> {
        if target_id.is_empty() {
            return Err(anyhow!("restored target ID is empty"));
        }
        // Rekey host ownership for this generation but retain guest_id, which
        // still names the disk/process relationships captured inside the VM.
        self.identity.write().await.host_id = target_id.to_string();
        Ok(())
    }

    async fn snapshot_host_id(&self) -> Option<String> {
        Some(self.identity.read().await.host_id.clone())
    }

    async fn snapshot_artifacts(
        &self,
        staging: &Path,
        final_destination: &Path,
    ) -> Result<Option<RootfsSnapshotArtifacts>> {
        let identity = self.identity.read().await;
        // Write this generation's copies under the transaction staging tree.
        let directory = staging.join("containers").join(&identity.host_id);
        std::fs::create_dir_all(&directory)?;
        let mut copied = Vec::new();
        for source in &self.files {
            if self.writable_disk.as_ref() == Some(source) {
                continue;
            }
            let destination = directory.join(Self::file_name(source)?);
            reflink_copy(source, &destination)
                .with_context(|| format!("copy restored rootfs artifact {}", source.display()))?;
            copied.push(destination);
        }
        let readonly_name = Self::file_name(&self.readonly_disk)?;
        // Confirm the readonly disk was included in the staged file graph.
        let readonly_staging = directory.join(readonly_name);
        if !readonly_staging.is_file() {
            return Err(anyhow!("restored readonly disk was not copied"));
        }
        let writable = self
            .writable_disk
            .as_ref()
            .map(|source| -> Result<SnapshotDiskPath> {
                let name = Self::file_name(source)?;
                let destination = directory.join(name);
                reflink_copy(source, &destination)
                    .with_context(|| format!("copy restored writable disk {}", source.display()))?;
                copied.push(destination);
                Ok(SnapshotDiskPath {
                    // Current private disk path used by the running restored VM.
                    live_path: source.clone(),
                    // Path CLH will use after staging is published atomically.
                    snapshot_path: final_destination
                        .join("containers")
                        .join(&identity.host_id)
                        .join(name),
                })
            })
            .transpose()?;
        Ok(Some(RootfsSnapshotArtifacts {
            cri_name: self.cri_name.clone(),
            source_host_id: identity.host_id.clone(),
            snapshot_guest_id: identity.guest_id.clone(),
            readonly_disk: SnapshotDiskPath {
                // Current packaged disk path referenced by the restored CLH config.
                live_path: self.readonly_disk.clone(),
                // Path CLH will use after staging is published atomically.
                snapshot_path: final_destination
                    .join("containers")
                    .join(&identity.host_id)
                    .join(readonly_name),
            },
            writable_disk: writable,
            files: copied,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(root: &Path, cri_name: &str, device_ids: &[&str]) -> RestoredRootfsConfig {
        let directory = root.join(cri_name);
        std::fs::create_dir_all(&directory).unwrap();
        let readonly = directory.join("readonly.img");
        std::fs::write(&readonly, b"readonly").unwrap();
        RestoredRootfsConfig {
            cri_name: cri_name.to_string(),
            host_id: format!("{cri_name}-host"),
            guest_id: format!("{cri_name}-guest"),
            device_ids: device_ids.iter().map(|id| (*id).to_string()).collect(),
            readonly_disk: readonly.clone(),
            writable_disk: None,
            files: vec![readonly],
        }
    }

    #[test]
    fn shared_restored_device_is_removed_only_after_final_release() {
        let source = tempfile::tempdir().unwrap();
        let configs = vec![
            config(source.path(), "first", &["shared", "first-rw"]),
            config(source.path(), "second", &["shared", "second-rw"]),
        ];
        let mut references = RestoredDeviceReferences::new(&configs).unwrap();

        assert!(references.release("first-rw").unwrap());
        assert!(!references.release("shared").unwrap());
        assert!(references.release("second-rw").unwrap());
        assert!(references.release("shared").unwrap());
        assert!(references.release("shared").is_err());
    }

    #[test]
    fn restored_rootfs_rejects_duplicate_device_ids() {
        let source = tempfile::tempdir().unwrap();
        let error = RestoredRootfs::from_configs(vec![config(
            source.path(),
            "duplicate",
            &["shared", "shared"],
        )])
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "restored rootfs duplicate contains duplicate device IDs"
        );
    }

    #[tokio::test]
    async fn recursive_snapshot_rekeys_host_but_preserves_guest_id() {
        let source = tempfile::tempdir().unwrap();
        let source_container = source.path().join("containers/source-id");
        std::fs::create_dir_all(&source_container).unwrap();
        let lower = source_container.join("lower-0000.erofs");
        let descriptor = source_container.join("rootfs.vmdk");
        let writable = source.path().join("private/rwlayer.img");
        std::fs::create_dir_all(writable.parent().unwrap()).unwrap();
        std::fs::write(&lower, b"immutable-layer").unwrap();
        std::fs::write(&descriptor, b"RW 1 FLAT \"lower-0000.erofs\" 0\n").unwrap();
        std::fs::write(&writable, b"target-generation-write").unwrap();

        let rootfs = RestoredRootfs::from_configs(vec![RestoredRootfsConfig {
            cri_name: "app".to_string(),
            host_id: "source-host".to_string(),
            guest_id: "stable-guest".to_string(),
            device_ids: vec!["readonly".to_string(), "writable".to_string()],
            readonly_disk: descriptor.clone(),
            writable_disk: Some(writable.clone()),
            files: vec![lower, descriptor.clone(), writable.clone()],
        }])
        .unwrap()
        .remove(0);
        rootfs.rebind_restored("target-host").await.unwrap();

        let staging = tempfile::tempdir().unwrap();
        let published = source.path().join("published");
        let artifacts = rootfs
            .snapshot_artifacts(staging.path(), &published)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(artifacts.source_host_id, "target-host");
        assert_eq!(artifacts.snapshot_guest_id, "stable-guest");
        assert_eq!(artifacts.readonly_disk.live_path, descriptor);
        assert_eq!(
            artifacts.readonly_disk.snapshot_path,
            published.join("containers/target-host/rootfs.vmdk")
        );
        assert_eq!(
            artifacts.writable_disk.unwrap().snapshot_path,
            published.join("containers/target-host/rwlayer.img")
        );
    }
}
