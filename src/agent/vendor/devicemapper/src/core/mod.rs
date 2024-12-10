// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Modules that support handling of devicemapper ioctls at a low-level.

mod device;
mod deviceinfo;
mod dm;
mod dm_flags;
mod dm_ioctl;
mod dm_options;
mod dm_udev_sync;
pub mod errors;
mod sysvsem;
mod types;
mod util;

pub use self::{
    device::{devnode_to_devno, Device},
    deviceinfo::DeviceInfo,
    dm::DM,
    dm_flags::{DmFlags, DmUdevFlags},
    dm_options::DmOptions,
    types::{DevId, DmName, DmNameBuf, DmUuid, DmUuidBuf},
};
