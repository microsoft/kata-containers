use std::path::{Path, PathBuf};

use agent::Storage;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hypervisor::device::device_manager::DeviceManager;
use kata_types::{
    device::DRIVER_SMB_TYPE,
    mount::{kata_guest_sandbox_dir, DirectVolumeMountInfo},
};
use oci_spec::runtime as oci;
use tokio::sync::RwLock;

use crate::volume::Volume;

const AZURE_FILE_VOLUME_TYPE: &str = "azurefile";
const CIFS_FS_TYPE: &str = "cifs";
const SMB_FS_TYPE: &str = "smb";
const SENSITIVE_MOUNT_OPTIONS_KEY: &str = "sensitiveMountOptions";

pub(crate) struct SmbVolume {
    storage: Storage,
    mount: oci::Mount,
}

impl SmbVolume {
    pub(crate) fn new(mount: &oci::Mount, mount_info: &DirectVolumeMountInfo) -> Result<Self> {
        if mount_info.device.is_empty() {
            return Err(anyhow!("SMB volume source is empty"));
        }

        let encoded_source = URL_SAFE_NO_PAD.encode(mount_info.device.as_bytes());
        let guest_path = Path::new(&kata_guest_sandbox_dir())
            .join("storage")
            .join(encoded_source);
        let guest_path = guest_path.to_string_lossy().into_owned();

        let mut options = mount_info.options.clone();
        if let Some(sensitive_options) = mount_info.metadata.get(SENSITIVE_MOUNT_OPTIONS_KEY) {
            options.extend(
                sensitive_options
                    .split(',')
                    .filter(|option| !option.is_empty())
                    .map(str::to_owned),
            );
        }

        let storage = Storage {
            driver: DRIVER_SMB_TYPE.to_string(),
            source: mount_info.device.clone(),
            fs_type: CIFS_FS_TYPE.to_string(),
            options,
            mount_point: guest_path.clone(),
            ..Default::default()
        };

        let mut container_mount = oci::Mount::default();
        container_mount.set_destination(mount.destination().clone());
        container_mount.set_typ(Some("bind".to_string()));
        container_mount.set_source(Some(PathBuf::from(guest_path)));
        container_mount.set_options(mount.options().clone());

        Ok(Self {
            storage,
            mount: container_mount,
        })
    }
}

pub(crate) fn is_smb_volume(mount_info: &DirectVolumeMountInfo) -> bool {
    mount_info.volume_type == AZURE_FILE_VOLUME_TYPE
        && matches!(mount_info.fs_type.as_str(), CIFS_FS_TYPE | SMB_FS_TYPE)
}

#[async_trait]
impl Volume for SmbVolume {
    fn get_volume_mount(&self) -> Result<Vec<oci::Mount>> {
        Ok(vec![self.mount.clone()])
    }

    fn get_storage(&self) -> Result<Vec<Storage>> {
        Ok(vec![self.storage.clone()])
    }

    fn get_device_id(&self) -> Result<Option<String>> {
        Ok(None)
    }

    async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn creates_guest_smb_storage_and_bind_mount() {
        let mut mount = oci::Mount::default();
        mount.set_destination(PathBuf::from("/mnt/data"));
        mount.set_options(Some(vec!["rw".to_string()]));

        let mount_info = DirectVolumeMountInfo {
            volume_type: AZURE_FILE_VOLUME_TYPE.to_string(),
            device: "//account.file.core.windows.net/share".to_string(),
            fs_type: CIFS_FS_TYPE.to_string(),
            metadata: HashMap::from([(
                SENSITIVE_MOUNT_OPTIONS_KEY.to_string(),
                "username=account,password=secret".to_string(),
            )]),
            options: vec!["vers=3.0".to_string()],
        };

        let volume = SmbVolume::new(&mount, &mount_info).unwrap();
        let storage = &volume.get_storage().unwrap()[0];
        assert_eq!(storage.driver, DRIVER_SMB_TYPE);
        assert_eq!(storage.source, mount_info.device);
        assert_eq!(storage.fs_type, CIFS_FS_TYPE);
        assert_eq!(
            storage.options,
            ["vers=3.0", "username=account", "password=secret"]
        );

        let container_mount = &volume.get_volume_mount().unwrap()[0];
        assert_eq!(container_mount.typ(), &Some("bind".to_string()));
        assert_eq!(container_mount.destination(), mount.destination());
        assert_eq!(
            container_mount.source().as_ref().unwrap(),
            Path::new(&storage.mount_point)
        );
    }
}