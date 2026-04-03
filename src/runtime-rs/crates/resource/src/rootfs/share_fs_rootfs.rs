// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use super::{Rootfs, ROOTFS};
use crate::share_fs::{ShareFs, ShareFsRootfsConfig};
use agent::Storage;
use anyhow::{Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use kata_sys_util::mount::{umount_timeout, Mounter};
use kata_types::mount::Mount;
use oci_spec::runtime as oci;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

pub(crate) struct ShareFsRootfs {
    guest_path: String,
    share_fs: Arc<dyn ShareFs>,
    config: ShareFsRootfsConfig,

    // log_file: tokio::fs::File,
}

async fn log_to_file(log_file: &mut tokio::fs::File, log_entry: &str) {
    let entry = format!("{log_entry}\n\n");
    let _ = log_file.write_all(entry.as_bytes()).await;
    let _ = log_file.flush().await;
}

impl ShareFsRootfs {
    pub async fn new(
        share_fs: &Arc<dyn ShareFs>,
        cid: &str,
        bundle_path: &str,
        rootfs: Option<&Mount>,
    ) -> Result<Self> {
        let mut log_file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open("/tmp/dmihai.txt")
            .await?;

        let bundle_rootfs = if let Some(rootfs) = rootfs {
            log_to_file(
                &mut log_file,
                &format!("ShareFsRootfs: rootfs = {:?}", &rootfs)
            ).await;

            let bundle_rootfs = format!("{bundle_path}/{ROOTFS}");
            log_to_file(
                &mut log_file,
                &format!("ShareFsRootfs: mounting rootfs from {:?} to {}", &rootfs, &bundle_rootfs)
            ).await;

            rootfs.mount(&bundle_rootfs).context(format!(
                "mount rootfs from {:?} to {}",
                &rootfs, &bundle_rootfs
            ))?;
            bundle_rootfs
        } else {
            log_to_file(
                &mut log_file,
                &format!("ShareFsRootfs: keeping input bundle_path = {}", &bundle_path)
            ).await;
            bundle_path.to_string()
        };

        let share_fs_mount = share_fs.get_share_fs_mount();
        let config = ShareFsRootfsConfig {
            cid: cid.to_string(),
            source: bundle_rootfs.to_string(),
            target: ROOTFS.to_string(),
            readonly: false,
            is_rafs: false,
        };
        log_to_file(
            &mut log_file,
            &format!("ShareFsRootfs: config = {:?}", &config)
        ).await;

        let mount_result = share_fs_mount
            .share_rootfs(&config, &mut log_file)
            .await
            .context("share rootfs")?;

        log_to_file(&mut log_file, 
            &format!("ShareFsRootfs: returning guest_path = {:?}, config = {:?}",
                mount_result.guest_path,
                config,
            )
        ).await;

        let r = ShareFsRootfs {
            guest_path: mount_result.guest_path,
            share_fs: Arc::clone(share_fs),
            config,
            // log_file,
        };

        Ok(r)
    }
}

#[async_trait]
impl Rootfs for ShareFsRootfs {
    async fn get_guest_rootfs_path(&self) -> Result<String> {
        Ok(self.guest_path.clone())
    }

    async fn get_rootfs_mount(&self) -> Result<Vec<oci::Mount>> {
        todo!()
    }

    async fn get_storage(&self) -> Option<Storage> {
        None
    }

    async fn get_device_id(&self) -> Result<Option<String>> {
        Ok(None)
    }

    async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
        // Umount the mount point shared to guest
        let share_fs_mount = self.share_fs.get_share_fs_mount();
        share_fs_mount
            .umount_rootfs(&self.config)
            .await
            .context("umount shared rootfs")?;

        // Umount the bundle rootfs
        umount_timeout(&self.config.source, 0).context("umount bundle rootfs")?;
        Ok(())
    }
}
