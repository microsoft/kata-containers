// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use agent::Storage;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use kata_sys_util::fs::reflink_copy;
use oci_spec::runtime as oci;
use tokio::sync::RwLock;

use super::{Rootfs, RootfsSnapshotArtifacts, SnapshotDiskPath};

#[derive(Clone, Debug)]
pub struct RestoredRootfsConfig {
    pub cri_name: String,
    pub host_id: String,
    pub guest_id: String,
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
pub struct RestoredRootfs {
    cri_name: String,
    identity: Arc<RwLock<RestoredRootfsIdentity>>,
    readonly_disk: PathBuf,
    writable_disk: Option<PathBuf>,
    files: Vec<PathBuf>,
}

impl RestoredRootfs {
    pub fn new(config: RestoredRootfsConfig) -> Result<Self> {
        if config.cri_name.is_empty() || config.host_id.is_empty() || config.guest_id.is_empty() {
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
            readonly_disk: config.readonly_disk,
            writable_disk: config.writable_disk,
            files: config.files,
        })
    }

    pub async fn rebind(&self, target_id: &str) -> Result<()> {
        if target_id.is_empty() {
            return Err(anyhow!("restored target ID is empty"));
        }
        let mut identity = self.identity.write().await;
        identity.host_id = target_id.to_string();
        identity.guest_id = target_id.to_string();
        Ok(())
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

    async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
        Ok(())
    }

    async fn get_device_id(&self) -> Result<Option<String>> {
        Ok(None)
    }

    fn restored_cri_name(&self) -> Option<&str> {
        Some(&self.cri_name)
    }

    async fn rebind_restored(&self, target_id: &str) -> Result<()> {
        self.rebind(target_id).await
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
        let readonly_staging = directory.join(readonly_name);
        if !readonly_staging.is_file() {
            return Err(anyhow!("restored readonly disk was not copied"));
        }
        let writable = if let Some(source) = &self.writable_disk {
            let destination = directory.join(Self::file_name(source)?);
            reflink_copy(source, &destination)
                .with_context(|| format!("copy restored writable disk {}", source.display()))?;
            copied.push(destination.clone());
            Some(SnapshotDiskPath {
                live_path: source.clone(),
                snapshot_path: final_destination
                    .join("containers")
                    .join(&identity.host_id)
                    .join(Self::file_name(source)?),
            })
        } else {
            None
        };
        Ok(Some(RootfsSnapshotArtifacts {
            cri_name: self.cri_name.clone(),
            source_host_id: identity.host_id.clone(),
            snapshot_guest_id: identity.guest_id.clone(),
            readonly_disk: SnapshotDiskPath {
                live_path: self.readonly_disk.clone(),
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

    #[tokio::test]
    async fn recursive_snapshot_uses_rebound_ids_and_private_writable_disk() {
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

        let rootfs = RestoredRootfs::new(RestoredRootfsConfig {
            cri_name: "app".to_string(),
            host_id: "source-host".to_string(),
            guest_id: "source-guest".to_string(),
            readonly_disk: descriptor.clone(),
            writable_disk: Some(writable.clone()),
            files: vec![lower, descriptor.clone(), writable.clone()],
        })
        .unwrap();
        rootfs.rebind("target-id").await.unwrap();

        let staging = tempfile::tempdir().unwrap();
        let published = source.path().join("published");
        let artifacts = rootfs
            .snapshot_artifacts(staging.path(), &published)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(artifacts.source_host_id, "target-id");
        assert_eq!(artifacts.snapshot_guest_id, "target-id");
        assert_eq!(artifacts.readonly_disk.live_path, descriptor);
        assert_eq!(
            artifacts.readonly_disk.snapshot_path,
            published.join("containers/target-id/rootfs.vmdk")
        );
        assert_eq!(
            artifacts.writable_disk.unwrap().snapshot_path,
            published.join("containers/target-id/rwlayer.img")
        );
        assert_eq!(
            std::fs::read(staging.path().join("containers/target-id/rootfs.vmdk")).unwrap(),
            b"RW 1 FLAT \"lower-0000.erofs\" 0\n"
        );
        assert_eq!(
            std::fs::read(staging.path().join("containers/target-id/rwlayer.img")).unwrap(),
            b"target-generation-write"
        );
    }
}
