// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use nix::libc::c_char;
use semver::Version;

use crate::{
    core::{
        device::Device,
        dm_flags::DmFlags,
        dm_ioctl as dmi, errors,
        types::{DmName, DmNameBuf, DmUuid, DmUuidBuf},
        util::str_from_c_str,
    },
    result::{DmError, DmResult},
};

/// Contains information about the device.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    version: Version,

    #[allow(dead_code)]
    data_size: u32,

    #[allow(dead_code)]
    data_start: u32,

    pub(super) target_count: u32,

    open_count: i32,
    flags: DmFlags,
    event_nr: u32,
    dev: Device,
    name: Option<DmNameBuf>,
    uuid: Option<DmUuidBuf>,
}

impl TryFrom<dmi::Struct_dm_ioctl> for DeviceInfo {
    type Error = DmError;

    fn try_from(ioctl: dmi::Struct_dm_ioctl) -> DmResult<Self> {
        let uuid = str_from_c_str(&ioctl.uuid as &[c_char]).ok_or_else(|| {
            errors::Error::InvalidArgument("Devicemapper UUID is not null terminated".to_string())
        })?;
        let uuid = if uuid.is_empty() {
            None
        } else {
            Some(DmUuidBuf::new(uuid.to_string())?)
        };
        let name = str_from_c_str(&ioctl.name as &[c_char]).ok_or_else(|| {
            errors::Error::InvalidArgument("Devicemapper name is not null terminated".to_string())
        })?;
        let name = if name.is_empty() {
            None
        } else {
            Some(DmNameBuf::new(name.to_string())?)
        };
        Ok(DeviceInfo {
            version: Version::new(
                u64::from(ioctl.version[0]),
                u64::from(ioctl.version[1]),
                u64::from(ioctl.version[2]),
            ),
            data_size: ioctl.data_size,
            data_start: ioctl.data_start,
            target_count: ioctl.target_count,
            open_count: ioctl.open_count,
            flags: DmFlags::from_bits_truncate(ioctl.flags),
            event_nr: ioctl.event_nr,
            // dm_ioctl struct reserves 64 bits for device but kernel "huge"
            // encoding is only 32 bits.
            dev: Device::from_kdev_t(ioctl.dev as u32),
            uuid,
            name,
        })
    }
}

impl DeviceInfo {
    /// Parses a DM ioctl structure.
    ///
    /// Equivalent to `DeviceInfo::try_from(hdr)`.
    pub fn new(hdr: dmi::Struct_dm_ioctl) -> DmResult<Self> {
        DeviceInfo::try_from(hdr)
    }

    /// The major, minor, and patchlevel versions of devicemapper.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The number of times the device is currently open.
    pub fn open_count(&self) -> i32 {
        self.open_count
    }

    /// The last event number for the device.
    pub fn event_nr(&self) -> u32 {
        self.event_nr
    }

    /// The device's major and minor device numbers, as a Device.
    pub fn device(&self) -> Device {
        self.dev
    }

    /// The device's name.
    pub fn name(&self) -> Option<&DmName> {
        self.name.as_ref().map(|name| name.as_ref())
    }

    /// The device's devicemapper uuid.
    pub fn uuid(&self) -> Option<&DmUuid> {
        self.uuid.as_ref().map(|uuid| uuid.as_ref())
    }

    /// The flags returned from the device.
    pub fn flags(&self) -> DmFlags {
        self.flags
    }
}
