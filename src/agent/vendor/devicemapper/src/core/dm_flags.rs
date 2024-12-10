// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::core::dm_ioctl as dmi;

bitflags! {
    /// Flags used by devicemapper.
    #[derive(Default)]
    pub struct DmFlags: dmi::__u32 {
        /// In: Device should be read-only.
        /// Out: Device is read-only.
        const DM_READONLY             = dmi::DM_READONLY_FLAG;
        /// In: Device should be suspended.
        /// Out: Device is suspended.
        const DM_SUSPEND              = dmi::DM_SUSPEND_FLAG;
        /// In: Use passed-in minor number.
        const DM_PERSISTENT_DEV       = dmi::DM_PERSISTENT_DEV_FLAG;
        /// In: STATUS command returns table info instead of status.
        const DM_STATUS_TABLE         = dmi::DM_STATUS_TABLE_FLAG;
        /// Out: Active table is present.
        const DM_ACTIVE_PRESENT       = dmi::DM_ACTIVE_PRESENT_FLAG;
        /// Out: Inactive table is present.
        const DM_INACTIVE_PRESENT     = dmi::DM_INACTIVE_PRESENT_FLAG;
        /// Out: Passed-in buffer was too small.
        const DM_BUFFER_FULL          = dmi::DM_BUFFER_FULL_FLAG;
        /// Obsolete.
        const DM_SKIP_BDGET           = dmi::DM_SKIP_BDGET_FLAG;
        /// In: Avoid freezing filesystem when suspending.
        const DM_SKIP_LOCKFS          = dmi::DM_SKIP_LOCKFS_FLAG;
        /// In: Suspend without flushing queued I/Os.
        const DM_NOFLUSH              = dmi::DM_NOFLUSH_FLAG;
        /// In: Query inactive table instead of active.
        const DM_QUERY_INACTIVE_TABLE = dmi::DM_QUERY_INACTIVE_TABLE_FLAG;
        /// Out: A uevent was generated, the caller may need to wait for it.
        const DM_UEVENT_GENERATED     = dmi::DM_UEVENT_GENERATED_FLAG;
        /// In: Rename affects UUID field, not name field.
        const DM_UUID                 = dmi::DM_UUID_FLAG;
        /// In: All buffers are wiped after use. Use when handling crypto keys.
        const DM_SECURE_DATA          = dmi::DM_SECURE_DATA_FLAG;
        /// Out: A message generated output data.
        const DM_DATA_OUT             = dmi::DM_DATA_OUT_FLAG;
        /// In: Do not remove in-use devices.
        /// Out: Device scheduled to be removed when closed.
        const DM_DEFERRED_REMOVE      = dmi::DM_DEFERRED_REMOVE;
        /// Out: Device is suspended internally.
        const DM_INTERNAL_SUSPEND     = dmi::DM_INTERNAL_SUSPEND_FLAG;
    }
}

bitflags! {
    /// Flags used by devicemapper, see:
    /// https://sourceware.org/git/?p=lvm2.git;a=blob;f=libdm/libdevmapper.h#l3627
    /// for complete information about the meaning of the flags.
    #[derive(Default)]
    pub struct DmUdevFlags: u32 {
        /// Disables basic device-mapper udev rules that create symlinks in /dev/<DM_DIR>
        /// directory.
        const DM_UDEV_DISABLE_DM_RULES_FLAG = dmi::DM_UDEV_DISABLE_DM_RULES_FLAG;
        /// Disable subsystem udev rules, but allow general DM udev rules to run.
        const DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG = dmi::DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG;
        /// Disable dm udev rules which create symlinks in /dev/disk/* directory.
        const DM_UDEV_DISABLE_DISK_RULES_FLAG = dmi::DM_UDEV_DISABLE_DISK_RULES_FLAG;
        /// Disable all rules that are not general dm nor subsystem related.
        const DM_UDEV_DISABLE_OTHER_RULES_FLAG = dmi::DM_UDEV_DISABLE_OTHER_RULES_FLAG;
        /// Instruct udev rules to give lower priority to the device.
        const DM_UDEV_LOW_PRIORITY_FLAG = dmi::DM_UDEV_LOW_PRIORITY_FLAG;
        /// Disable libdevmapper's node management.
        const DM_UDEV_DISABLE_LIBRARY_FALLBACK = dmi::DM_UDEV_DISABLE_LIBRARY_FALLBACK;
        /// Automatically appended to all IOCTL calls issues by libdevmapper for generating
        /// udev uevents.
        const DM_UDEV_PRIMARY_SOURCE_FLAG = dmi::DM_UDEV_PRIMARY_SOURCE_FLAG;
    }
}
