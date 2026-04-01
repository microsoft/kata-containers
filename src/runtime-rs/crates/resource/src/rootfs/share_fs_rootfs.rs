// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;
use std::path::Path;

use super::{Rootfs, ROOTFS};
use crate::share_fs::{ShareFs, ShareFsRootfsConfig};
use agent::Storage;
use anyhow::{Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::DeviceManager;
use kata_sys_util::mount::{umount_timeout, Mounter};
use kata_types::mount::Mount;
use oci_spec::runtime as oci;
use tokio::io::{
    AsyncWriteExt,
    AsyncSeekExt,
    SeekFrom
};
use tokio::sync::RwLock;

pub(crate) struct ShareFsRootfs {
    guest_path: String,
    share_fs: Arc<dyn ShareFs>,
    config: ShareFsRootfsConfig,

    // log_file: tokio::fs::File,
}

async fn log_to_file(log_file: &mut tokio::fs::File, log_entry: &str) {
    let entry = format!("{log_entry}\n\n");
    let _ = log_file.seek(SeekFrom::End(0)).await;
    let _ = log_file.write_all(entry.as_bytes()).await;
    let _ = log_file.flush().await;
}

async fn check_dir(log_file: &mut tokio::fs::File, tag: u32, dir_path: &str) {
    let p = Path::new(dir_path);
    let is_dir = p.is_dir();
    let entry = format!("ShareFsRootfs: {tag}: path = {:?}, is_dir = {is_dir}", &p);
    log_to_file(log_file, &entry).await;
}

impl ShareFsRootfs {
    pub async fn new(
        share_fs: &Arc<dyn ShareFs>,
        cid: &str,
        bundle_path: &str,
        rootfs: Option<&Mount>,
        sid: &str
    ) -> Result<Self> {
        let mut log_file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open("/tmp/dmihai.txt")
            .await?;

        let dir1 = "/run/kata-containers/shared/sandboxes/123456789".to_string();

        let container_id = sid.to_string();
        let dir2 = dir1.clone() + "/" + &container_id;
        //check_dir(&mut log_file, 1, &dir2).await;

        let dir3 = dir2.clone() + "/rw/passthrough";
        //check_dir(&mut log_file, 1, &dir3).await;

        let dir4 = dir3.clone() + "/" + &container_id + "/rootfs";
        //check_dir(&mut log_file, 1, &dir4).await;


        let bundle_rootfs = if let Some(rootfs) = rootfs {
            /*
            log_to_file(
                &mut log_file,
                &format!("ShareFsRootfs: rootfs = {:?}", &rootfs)
            ).await;
            */

            let bundle_rootfs = format!("{bundle_path}/{ROOTFS}");
            /*
            log_to_file(
                &mut log_file,
                &format!("ShareFsRootfs: mounting rootfs from {:?} to {}", &rootfs, &bundle_rootfs)
            ).await;
            */

            rootfs.mount(&bundle_rootfs).context(format!(
                "mount rootfs from {:?} to {}",
                &rootfs, &bundle_rootfs
            ))?;

            bundle_rootfs
        } else {
            /*
            log_to_file(
                &mut log_file,
                &format!("ShareFsRootfs: keeping input bundle_path = {}", &bundle_path)
            ).await;
            */
            bundle_path.to_string()
        };

        //check_dir(&mut log_file, 2, &dir3).await;
        //check_dir(&mut log_file, 2, &dir4).await;

        let share_fs_mount = share_fs.get_share_fs_mount();
        let config = ShareFsRootfsConfig {
            cid: cid.to_string(),
            source: bundle_rootfs.to_string(),
            target: ROOTFS.to_string(),
            readonly: false,
            is_rafs: false,
        };
        /*
        log_to_file(
            &mut log_file,
            &format!("ShareFsRootfs: config = {:?}", &config)
        ).await;
        */

        check_dir(&mut log_file, 3, &dir3).await;
        check_dir(&mut log_file, 3, &dir4).await;

        let mount_result = share_fs_mount
            .share_rootfs(&config, &mut log_file, &dir4)
            .await
            .context("share rootfs")?;

        check_dir(&mut log_file, 4, &dir3).await;
        check_dir(&mut log_file, 4, &dir4).await;

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
