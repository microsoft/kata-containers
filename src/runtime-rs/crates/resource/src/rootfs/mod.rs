// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

mod nydus_rootfs;
mod share_fs_rootfs;
use agent::Storage;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use kata_types::mount::Mount;
mod block_rootfs;
pub mod virtual_volume;

use hypervisor::{device::device_manager::DeviceManager, Hypervisor};
use virtual_volume::{is_kata_virtual_volume, VirtualVolume};

use std::{collections::HashMap, sync::Arc, vec::Vec};
use std::path::Path;
use tokio::sync::RwLock;

use self::{block_rootfs::is_block_rootfs, nydus_rootfs::NYDUS_ROOTFS_TYPE};
use crate::share_fs::ShareFs;
use oci_spec::runtime as oci;

const ROOTFS: &str = "rootfs";
const HYBRID_ROOTFS_LOWER_DIR: &str = "rootfs_lower";
const TYPE_OVERLAY_FS: &str = "overlay";

#[async_trait]
pub trait Rootfs: Send + Sync {
    async fn get_guest_rootfs_path(&self) -> Result<String>;
    async fn get_rootfs_mount(&self) -> Result<Vec<oci::Mount>>;
    async fn get_storage(&self) -> Option<Storage>;
    async fn cleanup(&self, device_manager: &RwLock<DeviceManager>) -> Result<()>;
    async fn get_device_id(&self) -> Result<Option<String>>;
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

fn check_dir(tag: u32, dir_path: &str) {
    let p = Path::new(dir_path);
    let is_dir = p.is_dir();
    info!(sl!(), "handler_rootfs: {tag}: path = {:?}, is_dir = {is_dir}", &p);
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
        device_manager: &RwLock<DeviceManager>,
        h: &dyn Hypervisor,
        sid: &str,
        cid: &str,
        root: &oci::Root,
        bundle_path: &str,
        rootfs_mounts: &[Mount],
        annotations: &HashMap<String, String>,
    ) -> Result<Arc<dyn Rootfs>> {
        let dir1 = "/run/kata-containers/shared/sandboxes/123456789".to_string();

        let container_id = sid.to_string();
        let dir2 = dir1.clone() + "/" + &container_id;

        let dir3 = dir2.clone() + "/rw/passthrough";
        //check_dir(1, &dir3);

        let dir4 = dir3.clone() + "/" + &container_id + "/rootfs";
        //check_dir(1, &dir4);
        
        match rootfs_mounts {
            // if rootfs_mounts is empty
            [] => {
                check_dir(2, &dir3);
                check_dir(2, &dir4);

                if let Some(share_fs) = share_fs {
                    // handle share fs rootfs
                    Ok(Arc::new(
                        share_fs_rootfs::ShareFsRootfs::new(
                            share_fs,
                            cid,
                            root.path().display().to_string().as_str(),
                            None,
                            sid,
                        )
                        .await
                        .context("new share fs rootfs")?,
                    ))
                } else {
                    Err(anyhow!("share fs is unavailable"))
                }
            }
            mounts_vec if is_single_layer_rootfs(mounts_vec) => {
                //check_dir(3, &dir3);
                //check_dir(3, &dir4);

                // Safe as single_layer_rootfs must have one layer
                let layer = &mounts_vec[0];
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

                    //check_dir(4, &dir3);
                    //check_dir(4, &dir4);

                    Ok(block_rootfs)
                } else if let Some(share_fs) = share_fs {
                    // handle nydus rootfs
                    let share_rootfs: Arc<dyn Rootfs> = if layer.fs_type == NYDUS_ROOTFS_TYPE {
                        Arc::new(
                            nydus_rootfs::NydusRootfs::new(
                                device_manager,
                                share_fs,
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
                        check_dir(5, &dir3);
                        check_dir(5, &dir4);

                        Arc::new(
                            share_fs_rootfs::ShareFsRootfs::new(
                                share_fs,
                                cid,
                                bundle_path,
                                Some(layer),
                                sid,
                            )
                            .await
                            .context("new share fs rootfs")?,
                        )
                    };

                    check_dir(6, &dir3);
                    check_dir(6, &dir4);
                    
                    Ok(share_rootfs)
                } else {
                    Err(anyhow!("unsupported rootfs {:?}", &layer))
                }?;
                inner.rootfs.push(rootfs.clone());

                check_dir(7, &dir3);
                check_dir(7, &dir4);

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
