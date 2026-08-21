// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

mod nydus_rootfs;
mod share_fs_rootfs;
pub mod snapshot;
use agent::Storage;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use kata_types::mount::Mount;
mod block_rootfs;
mod erofs_rootfs;
pub mod virtual_volume;

use hypervisor::{device::device_manager::DeviceManager, Hypervisor};
use serde::{Deserialize, Serialize};
use virtual_volume::{is_kata_virtual_volume, VirtualVolume};

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    vec::Vec,
};
use tokio::sync::RwLock;

use self::{
    block_rootfs::is_block_rootfs, erofs_rootfs::ErofsMultiLayerRootfs,
    nydus_rootfs::NYDUS_ROOTFS_TYPE,
};
use crate::rootfs::erofs_rootfs::is_erofs_multi_layer;
use crate::share_fs::{NydusShareFs, ShareFs};
use oci_spec::runtime as oci;

const ROOTFS: &str = "rootfs";
pub const HYBRID_ROOTFS_LOWER_DIR: &str = "rootfs_lower";
const TYPE_OVERLAY_FS: &str = "overlay";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SnapshotDiskPath {
    pub live_path: PathBuf,
    pub snapshot_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RootfsSnapshotArtifacts {
    pub cri_name: String,
    pub source_host_id: String,
    pub snapshot_guest_id: String,
    pub readonly_disk: SnapshotDiskPath,
    pub writable_disk: Option<SnapshotDiskPath>,
    pub files: Vec<PathBuf>,
}

#[async_trait]
pub trait Rootfs: Send + Sync {
    async fn get_guest_rootfs_path(&self) -> Result<String>;
    async fn get_rootfs_mount(&self) -> Result<Vec<oci::Mount>>;
    async fn get_storage(&self) -> Option<Vec<Storage>>;
    async fn cleanup(&self, device_manager: &RwLock<DeviceManager>) -> Result<()>;
    async fn get_device_id(&self) -> Result<Option<String>>;
    async fn snapshot_host_id(&self) -> Option<String> {
        None
    }
    async fn snapshot_artifacts(
        &self,
        _staging: &std::path::Path,
        _final_destination: &std::path::Path,
    ) -> Result<Option<RootfsSnapshotArtifacts>> {
        Ok(None)
    }
}

#[derive(Default)]
struct RootFsResourceInner {
    rootfs: Vec<Arc<dyn Rootfs>>,
}

pub struct RootFsResource {
    inner: Arc<RwLock<RootFsResourceInner>>,
}

impl Default for RootFsResource {
    fn default() -> Self {
        Self::new()
    }
}

impl RootFsResource {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RootFsResourceInner::default())),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn handler_rootfs(
        &self,
        share_fs: &Option<Arc<dyn ShareFs>>,
        nydus_share_fs: &Option<Arc<dyn NydusShareFs>>,
        device_manager: &RwLock<DeviceManager>,
        h: &dyn Hypervisor,
        sid: &str,
        cid: &str,
        root: &oci::Root,
        bundle_path: &str,
        rootfs_mounts: &[Mount],
        annotations: &HashMap<String, String>,
        cri_name: &str,
    ) -> Result<Arc<dyn Rootfs>> {
        match rootfs_mounts {
            // if rootfs_mounts is empty
            [] => {
                if let Some(share_fs) = share_fs {
                    // handle share fs rootfs
                    Ok(Arc::new(
                        share_fs_rootfs::ShareFsRootfs::new(
                            share_fs,
                            cid,
                            root.path().display().to_string().as_str(),
                            None,
                        )
                        .await
                        .context("new share fs rootfs")?,
                    ))
                } else {
                    Err(anyhow!("share fs is unavailable"))
                }
            }
            _ if is_erofs_multi_layer(rootfs_mounts) => {
                info!(
                    sl!(),
                    "handling multi-layer erofs rootfs with {} mounts",
                    rootfs_mounts.len()
                );

                let multi_layer = ErofsMultiLayerRootfs::new(
                    device_manager,
                    sid,
                    cid,
                    cri_name,
                    rootfs_mounts,
                    share_fs,
                )
                .await
                .context("new multi-layer erofs rootfs")?;

                let ret = Arc::new(multi_layer);
                let mut inner = self.inner.write().await;
                inner.rootfs.push(ret.clone());
                Ok(ret)
            }
            _ if is_single_layer_rootfs(rootfs_mounts) => {
                // Safe as single_layer_rootfs must have one layer
                let layer = &rootfs_mounts[0];
                let mut inner = self.inner.write().await;

                if is_guest_pull_volume(share_fs, layer) {
                    let mount_options = layer.options.clone();
                    let virtual_volume: Arc<dyn Rootfs> = Arc::new(
                        VirtualVolume::new(cid, annotations, mount_options.to_vec())
                            .await
                            .context("kata virtual volume failed.")?,
                    );
                    return Ok(virtual_volume);
                }

                let rootfs = if let Some((dev_id, layer)) = is_block_rootfs(layer) {
                    // handle block rootfs
                    info!(sl!(), "block device: {}", dev_id);
                    let block_rootfs: Arc<dyn Rootfs> = Arc::new(
                        block_rootfs::BlockRootfs::new(device_manager, sid, cid, dev_id, &layer)
                            .await
                            .context("new block rootfs")?,
                    );
                    Ok(block_rootfs)
                } else if let Some(share_fs) = share_fs {
                    // handle nydus rootfs (unified implementation for both inline and standalone modes)
                    let share_rootfs: Arc<dyn Rootfs> = if layer.fs_type == NYDUS_ROOTFS_TYPE {
                        Arc::new(
                            nydus_rootfs::NydusRootfs::new(
                                device_manager,
                                share_fs,
                                nydus_share_fs,
                                h,
                                sid,
                                cid,
                                layer,
                            )
                            .await
                            .context("new nydus rootfs")?,
                        )
                    }
                    // handle sharefs rootfs
                    else {
                        Arc::new(
                            share_fs_rootfs::ShareFsRootfs::new(
                                share_fs,
                                cid,
                                bundle_path,
                                Some(layer),
                            )
                            .await
                            .context("new share fs rootfs")?,
                        )
                    };
                    Ok(share_rootfs)
                } else {
                    Err(anyhow!("unsupported rootfs {:?}", &layer))
                }?;
                inner.rootfs.push(rootfs.clone());
                Ok(rootfs)
            }
            _ => Err(anyhow!(
                "unsupported rootfs mounts count {}",
                rootfs_mounts.len()
            )),
        }
    }

    pub async fn dump(&self) {
        let inner = self.inner.read().await;
        for r in &inner.rootfs {
            info!(
                sl!(),
                "rootfs {:?}: count {}",
                r.get_guest_rootfs_path().await,
                Arc::strong_count(r)
            );
        }
    }

    pub async fn snapshot_artifacts(
        &self,
        staging: &std::path::Path,
        final_destination: &std::path::Path,
        active_host_ids: &HashSet<String>,
    ) -> Result<Vec<RootfsSnapshotArtifacts>> {
        let inner = self.inner.read().await;
        let mut artifacts = Vec::new();
        let mut names = std::collections::HashSet::new();
        for rootfs in &inner.rootfs {
            if let Some(host_id) = rootfs.snapshot_host_id().await {
                if !active_host_ids.contains(&host_id) {
                    continue;
                }
            }
            if let Some(snapshot) = rootfs
                .snapshot_artifacts(staging, final_destination)
                .await?
            {
                if !names.insert(snapshot.cri_name.clone()) {
                    return Err(anyhow!(
                        "duplicate CRI container name in snapshot: {}",
                        snapshot.cri_name
                    ));
                }
                artifacts.push(snapshot);
            }
        }
        Ok(artifacts)
    }
}

fn is_single_layer_rootfs(rootfs_mounts: &[Mount]) -> bool {
    rootfs_mounts.len() == 1
}

pub fn is_guest_pull_volume(
    share_fs: &Option<Arc<dyn ShareFs>>,
    m: &kata_types::mount::Mount,
) -> bool {
    share_fs.is_none() && is_kata_virtual_volume(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    struct TestRootfs {
        host_id: Option<String>,
        snapshot: Option<RootfsSnapshotArtifacts>,
    }

    #[async_trait]
    impl Rootfs for TestRootfs {
        async fn get_guest_rootfs_path(&self) -> Result<String> {
            Ok("/rootfs".to_string())
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

        async fn snapshot_host_id(&self) -> Option<String> {
            self.host_id.clone()
        }

        async fn snapshot_artifacts(
            &self,
            _staging: &Path,
            _final_destination: &Path,
        ) -> Result<Option<RootfsSnapshotArtifacts>> {
            Ok(self.snapshot.clone())
        }
    }

    fn snapshot_artifact(name: &str, host_id: &str) -> RootfsSnapshotArtifacts {
        RootfsSnapshotArtifacts {
            cri_name: name.to_string(),
            source_host_id: host_id.to_string(),
            snapshot_guest_id: format!("guest-{host_id}"),
            readonly_disk: SnapshotDiskPath {
                live_path: PathBuf::from(format!("/live/{host_id}.img")),
                snapshot_path: PathBuf::from(format!("/snapshot/{host_id}.img")),
            },
            writable_disk: None,
            files: Vec::new(),
        }
    }

    #[tokio::test]
    async fn snapshot_artifacts_skips_inactive_host_ids() {
        let resource = RootFsResource {
            inner: Arc::new(RwLock::new(RootFsResourceInner {
                rootfs: vec![
                    Arc::new(TestRootfs {
                        host_id: Some("active".to_string()),
                        snapshot: Some(snapshot_artifact("active-cri", "active")),
                    }),
                    Arc::new(TestRootfs {
                        host_id: Some("inactive".to_string()),
                        snapshot: Some(snapshot_artifact("inactive-cri", "inactive")),
                    }),
                    Arc::new(TestRootfs {
                        host_id: None,
                        snapshot: Some(snapshot_artifact("anonymous-cri", "anonymous")),
                    }),
                ],
            })),
        };
        let active_host_ids = HashSet::from(["active".to_string()]);

        let artifacts = resource
            .snapshot_artifacts(
                Path::new("/tmp/staging"),
                Path::new("/tmp/final"),
                &active_host_ids,
            )
            .await
            .unwrap();

        let names = artifacts
            .into_iter()
            .map(|artifact| artifact.cri_name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["active-cri".to_string(), "anonymous-cri".to_string()]
        );
    }
}
