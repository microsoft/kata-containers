// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
use crate::core::dm_flags::{DmFlags, DmUdevFlags};

/// Encapsulates options for device mapper calls
#[derive(Clone, Copy, Debug, Default)]
pub struct DmOptions {
    flags: DmFlags,
    udev_flags: DmUdevFlags,
}

impl DmOptions {
    /// Set the DmFlags value for self. Replace the previous value.
    /// Consumes self.
    pub fn set_flags(mut self, flags: DmFlags) -> DmOptions {
        self.flags = flags;
        self
    }

    /// Set the DmUdevFlags value for self. Replace the previous value.
    /// Consumes self.
    pub fn set_udev_flags(mut self, udev_flags: DmUdevFlags) -> DmOptions {
        self.udev_flags = udev_flags;
        self
    }

    /// Retrieve the flags value
    pub fn flags(&self) -> DmFlags {
        self.flags
    }

    /// Retrieve the cookie flags (used for input in upper 16 bits of event_nr header field).
    pub fn udev_flags(&self) -> DmUdevFlags {
        self.udev_flags
    }

    /// Set default udev flags for a private (internal) device.
    pub fn private() -> DmOptions {
        DmOptions::default().set_udev_flags(
            DmUdevFlags::DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG
                | DmUdevFlags::DM_UDEV_DISABLE_DISK_RULES_FLAG
                | DmUdevFlags::DM_UDEV_DISABLE_OTHER_RULES_FLAG,
        )
    }
}
