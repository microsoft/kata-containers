// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use agent::Storage;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use kata_sys_util::mount::{bind_remount, umount_all, umount_timeout};
use kata_types::{build_path, k8s::is_watchable_mount};
use std::fs;
use std::path::Path;
use tokio::io::AsyncWriteExt;

const WATCHABLE_PATH_NAME: &str = "watchable";
const WATCHABLE_BIND_DEV_TYPE: &str = "watchable-bind";
const DEFAULT_EPHEMERAL_PATH: &str = "/run/kata-containers/sandbox/ephemeral";

use crate::share_fs::kata_guest_share_dir;

use super::{
    // get_host_rw_shared_path,
    utils::{
        self,
        do_get_host_path,
        // get_host_ro_shared_path,
        get_host_shared_path,
        mkdir_with_permissions,
    },
    ShareFsMount, ShareFsMountResult, ShareFsRootfsConfig, ShareFsVolumeConfig, PASSTHROUGH_FS_DIR,
};

use super::utils::{
        get_host_ro_shared_path_uvm,
        get_host_rw_shared_path_uvm,
};

pub fn ephemeral_path() -> String {
    build_path(DEFAULT_EPHEMERAL_PATH)
}

#[derive(Debug)]
pub struct VirtiofsShareMount {
    id: String,
    uvm_id: String,
}

impl VirtiofsShareMount {
    pub fn new(id: &str, uvm_id: &str) -> Self {
        Self {
            id: id.to_string(),
            uvm_id: uvm_id.to_string(),
        }
    }
}

async fn log_to_file(log_file: &mut tokio::fs::File, log_entry: &str) {
    let entry = format!("{log_entry}\n\n");
    let _ = log_file.write_all(entry.as_bytes()).await;
    let _ = log_file.flush().await;
}

#[async_trait]
impl ShareFsMount for VirtiofsShareMount {
    async fn share_rootfs(
        &self,
        config: &ShareFsRootfsConfig,
        log_file: &mut tokio::fs::File,
    ) -> Result<ShareFsMountResult> {
        log_to_file(
            log_file,
            &format!(
                "share_rootfs: config = {:?} , uvm_id = {}", 
                &config,
                &self.uvm_id)
        ).await;

        // TODO: select virtiofs or support nydus
        let guest_path = utils::share_to_guest(
            &config.source,
            &config.target,
            &self.id,
            &config.cid,
            config.readonly,
            false,
            config.is_rafs,
            &self.uvm_id
        )
        .context("share to guest")?;

        log_to_file(
            log_file,
            &format!("share_rootfs: success, guest_path = {:?}", &guest_path)
        ).await;

        Ok(ShareFsMountResult {
            guest_path,
            storages: vec![],
        })
    }

    async fn share_volume(&self, config: &ShareFsVolumeConfig) -> Result<ShareFsMountResult> {
        let mut log_file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(false)
            .create(true)
            .open("/tmp/dmihai.txt")
            .await?;

        log_to_file(
            &mut log_file,
            &format!(
                "share_volume: source = {:?}, target = {:?}, cid = {:?}, readonly = {:?}, is_rafs = {:?}",
                &config.source,
                &config.target,
                &config.cid,
                &config.readonly,
                &config.is_rafs
            )
        ).await;

        let mut guest_path = utils::share_to_guest(
            &config.source,
            &config.target,
            &self.id,
            &config.cid,
            config.readonly,
            true,
            config.is_rafs,
            &self.uvm_id
        )
        .context("share to guest")?;

        // watchable mounts
        if is_watchable_mount(&config.source) {
            log_to_file(
                &mut log_file,
                &format!("share_volume: source = {:?} is watchable mount", &config.source)
            ).await;

            // Create path in shared directory for creating watchable mount:
            let host_rw_path = utils::get_host_rw_shared_path_uvm(&self.id, &self.uvm_id);
            log_to_file(
                &mut log_file,
                &format!("share_volume: host_rw_path = {:?}", &host_rw_path)
            ).await;

            // "/run/kata-containers/shared/sandboxes/$sid/rw/passthrough/watchable"
            let watchable_host_path = Path::new(&host_rw_path)
                .join(PASSTHROUGH_FS_DIR)
                .join(WATCHABLE_PATH_NAME);
            log_to_file(
                &mut log_file,
                &format!("share_volume: watchable_host_path = {:?}", &watchable_host_path)
            ).await;

            mkdir_with_permissions(watchable_host_path.clone(), 0o750).context(format!(
                "unable to create watchable path {watchable_host_path:?}"
            ))?;

            // path: /run/kata-containers/shared/containers/passthrough/watchable/config-map-name
            let file_name = Path::new(&guest_path)
                .file_name()
                .context("get file name from guest path")?;
            log_to_file(
                &mut log_file,
                &format!("share_volume: file_name = {:?}", &file_name)
            ).await;

            let watchable_guest_mount = Path::new(kata_guest_share_dir().as_str())
                .join(PASSTHROUGH_FS_DIR)
                .join(WATCHABLE_PATH_NAME)
                .join(file_name)
                .into_os_string()
                .into_string()
                .map_err(|e| anyhow!("failed to get watchable guest mount path {:?}", e))?;
            log_to_file(
                &mut log_file,
                &format!("share_volume: watchable_guest_mount = {:?}", &watchable_guest_mount)
            ).await;

            let watchable_storage: Storage = Storage {
                driver: String::from(WATCHABLE_BIND_DEV_TYPE),
                driver_options: Vec::new(),
                source: guest_path,
                fs_type: String::from("bind"),
                fs_group: None,
                options: config.mount_options.clone(),
                mount_point: watchable_guest_mount.clone(),
            };
            log_to_file(
                &mut log_file,
                &format!("share_volume: guest_path / watchable_storage = {:?}", &watchable_storage)
            ).await;

            // Update the guest_path, in order to identify what will
            // change in the OCI spec.
            guest_path = watchable_guest_mount;

            let storages = vec![watchable_storage];

            return Ok(ShareFsMountResult {
                guest_path,
                storages,
            });
        }

        Ok(ShareFsMountResult {
            guest_path,
            storages: vec![],
        })
    }

    async fn upgrade_to_rw(&self, file_name: &str) -> Result<()> {
        // Remount readonly directory with readwrite permission
        let host_dest = do_get_host_path(
            file_name, 
            &self.id, 
            "", 
            true, 
            true,
            &self.uvm_id,
        );

        bind_remount(host_dest, false)
            .context("remount readonly directory with readwrite permission")?;
        // Remount readwrite directory with readwrite permission
        
        let host_dest = do_get_host_path(
            file_name, 
            &self.id, 
            "", 
            true, 
            false,
            &self.uvm_id,
        );
        
        bind_remount(host_dest, false)
            .context("remount readwrite directory with readwrite permission")?;
        Ok(())
    }

    async fn downgrade_to_ro(&self, file_name: &str) -> Result<()> {
        // Remount readwrite directory with readonly permission
        let host_dest = do_get_host_path(
            file_name, 
            &self.id, 
            "", 
            true, 
            false,
            &self.uvm_id,
        );

        bind_remount(host_dest, true)
            .context("remount readwrite directory with readonly permission")?;
        // Remount readonly directory with readonly permission
        let host_dest = do_get_host_path(
            file_name, 
            &self.id, 
            "", 
            true, 
            true,
            &self.uvm_id,
        );

        bind_remount(host_dest, true)
            .context("remount readonly directory with readonly permission")?;
        Ok(())
    }

    async fn umount_volume(&self, file_name: &str) -> Result<()> {
        let host_dest = do_get_host_path(
            file_name, 
            &self.id, 
            "", 
            true, 
            false,
            &self.uvm_id,
        );

        umount_timeout(&host_dest, 0).context("umount volume")?;
        // Umount event will be propagated to ro directory

        // Remove the directory of mointpoint
        if let Ok(md) = fs::metadata(&host_dest) {
            if md.is_file() {
                fs::remove_file(&host_dest).context("remove the volume mount point as a file")?;
            }
            if md.is_dir() {
                fs::remove_dir(&host_dest).context("remove the volume mount point as a dir")?;
            }
        }
        Ok(())
    }

    async fn umount_rootfs(&self, config: &ShareFsRootfsConfig) -> Result<()> {
        let host_dest = do_get_host_path(
            &config.target, 
            &self.id, 
            &config.cid, 
            false, 
            false,
            &self.uvm_id,
        );

        umount_timeout(&host_dest, 0).context("umount rootfs")?;

        // Remove the directory of mointpoint
        if let Ok(md) = fs::metadata(&host_dest) {
            if md.is_dir() {
                fs::remove_dir(&host_dest).context("remove the rootfs mount point as a dir")?;
            }
        }

        Ok(())
    }

    async fn cleanup(&self, sid: &str) -> Result<()> {
        // Unmount ro path
        // let host_ro_dest = get_host_ro_shared_path(sid);
        let host_ro_dest = get_host_ro_shared_path_uvm(sid, &self.uvm_id);

        umount_all(host_ro_dest.clone(), true).context("failed to umount ro path")?;
        fs::remove_dir_all(host_ro_dest).context("failed to remove ro path")?;
        // As the rootfs and volume have been umounted before calling this function, so just remove the rw dir directly

        // let host_rw_dest = get_host_rw_shared_path(sid);
        let host_rw_dest = get_host_rw_shared_path_uvm(sid, &self.uvm_id);

        fs::remove_dir_all(host_rw_dest).context("failed to remove rw path")?;
        // remove the host share directory
        let host_path = get_host_shared_path(sid);
        fs::remove_dir_all(host_path).context("failed to remove host shared path")?;
        Ok(())
    }
}
