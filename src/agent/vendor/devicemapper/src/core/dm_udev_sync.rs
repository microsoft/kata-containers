// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::{core::dm_ioctl as dmi, result::DmResult};

pub trait UdevSyncAction {
    fn begin(hdr: &mut dmi::Struct_dm_ioctl, ioctl: u8) -> DmResult<UdevSync>;
    fn end(self, flags: u32) -> DmResult<()>;
    fn cancel(self);
    fn is_active(&self) -> bool;
}

#[cfg(not(target_os = "android"))]
pub mod sync_semaphore {
    use nix::libc::{
        c_int,
        key_t,
        sembuf,
        semctl as libc_semctl,
        semget as libc_semget,
        semop as libc_semop,
        EEXIST,
        ENOMEM,
        ENOSPC,
        // These don't exist in the Linux libc crate
        // GETVAL, SETVAL, SEM_INFO,
        IPC_CREAT,
        IPC_EXCL,
        IPC_NOWAIT,
        IPC_RMID,
    };

    use nix::unistd::{access, AccessFlags};

    use rand::Rng;
    use retry::{delay::NoDelay, retry, OperationResult};
    use std::{io, path::Path};

    use crate::core::sysvsem::seminfo;

    use crate::{
        core::dm_flags::{DmFlags, DmUdevFlags},
        core::sysvsem::{semun, GETVAL, SEM_INFO, SETVAL},
        core::{dm_ioctl as dmi, errors},
        result::{DmError, DmResult},
    };

    use super::UdevSyncAction;

    // Mode for cookie semaphore creation
    const COOKIE_MODE: i32 = 0o600;

    impl DmError {
        fn udev_sync_error_from_os() -> DmError {
            DmError::Core(errors::Error::UdevSync(
                io::Error::last_os_error().to_string(),
            ))
        }
    }

    lazy_static! {
        static ref SYSV_SEM_SUPPORTED: bool = sysv_sem_supported();
    }

    /// Test whether the system is configured for SysV semaphore support.
    fn sysv_sem_supported() -> bool {
        let mut info: seminfo = Default::default();
        let arg = semun { __buf: &mut info };
        match semctl(0, 0, SEM_INFO, Some(arg)) {
            Ok(maxid) if maxid < 0 => {
                warn!(concat!(
                    "Kernel not configured for System V IPC semaphores.",
                    "Disabling udev notifications."
                ));
                false
            }
            Err(err) => {
                error!(
                    concat!(
                        "Error retrieving System V semaphore limits: {}.",
                        "Disabling udev notifications."
                    ),
                    err
                );
                false
            }
            Ok(_) => {
                if info.semmsl > 0 && info.semmni > 0 && info.semmns > 0 {
                    if info.semmsl < 1000 || info.semmni < 1000 || info.semmns < 1000 {
                        warn!(concat!(
                            "Low System V IPC semaphore limits detected: consider ",
                            "increasing values in /proc/sys/kernel/sem to avoid exhaustion."
                        ));
                    }
                    true
                } else {
                    false
                }
            }
        }
    }

    const UDEV_SOCKET_PATH: &str = "/run/udev/control";

    fn udev_running() -> bool {
        matches!(
            access(Path::new(UDEV_SOCKET_PATH), AccessFlags::F_OK),
            Ok(())
        )
    }

    /// Allocate or retrieve a SysV semaphore set identifier
    fn semget(key: i32, nsems: i32, semflg: i32) -> Result<i32, std::io::Error> {
        let semid = unsafe { libc_semget(key as key_t, nsems as c_int, semflg as c_int) };
        match semid {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(semid),
        }
    }

    fn semctl_cmd_allowed(cmd: i32) -> Result<(), std::io::Error> {
        match cmd {
            IPC_RMID | GETVAL | SETVAL | SEM_INFO => Ok(()),
            _ => Err(io::Error::from(io::ErrorKind::Unsupported)),
        }
    }

    /// SysV semaphore set control operations
    fn semctl(
        semid: i32,
        semnum: i32,
        cmd: i32,
        semun: Option<semun>,
    ) -> Result<i32, std::io::Error> {
        semctl_cmd_allowed(cmd)?;
        let semun = match semun {
            Some(semun) => semun,
            None => Default::default(),
        };
        let r = unsafe { libc_semctl(semid as c_int, semnum as c_int, cmd as c_int, semun) };
        match r {
            i if i < 0 => Err(io::Error::last_os_error()),
            _ => Ok(r),
        }
    }

    /// Attempt to generate a unique, non-zero SysV IPC key and allocate a semaphore
    /// set for notifications.
    fn generate_semaphore_cookie() -> OperationResult<(u32, i32), std::io::Error> {
        let mut base_cookie = 0u16;
        while base_cookie == 0 {
            base_cookie = rand::thread_rng().gen::<u16>();
        }
        let cookie = dmi::DM_COOKIE_MAGIC << dmi::DM_UDEV_FLAGS_SHIFT | base_cookie as u32;
        match semget(cookie as i32, 1, COOKIE_MODE | IPC_CREAT | IPC_EXCL) {
            Ok(semid) => OperationResult::Ok((cookie, semid)),
            Err(err) => match err.raw_os_error() {
                Some(ENOMEM) => OperationResult::Err(err),
                Some(ENOSPC) => OperationResult::Err(err),
                Some(EEXIST) => OperationResult::Retry(err),
                _ => OperationResult::Err(err),
            },
        }
    }

    /// Create a new, unique udev notification semaphore and return the cookie
    /// value and semid.
    ///
    /// This function will attempt to allocate a new notification semaphore and sets
    /// the initial count to the 1. This count will be decremented by udev once rule
    /// processing for the transaction is complete.
    fn notify_sem_create() -> DmResult<(u32, i32)> {
        let (cookie, semid) = match retry(NoDelay.take(4), generate_semaphore_cookie) {
            Ok((cookie, semid)) => (cookie, semid),
            Err(err) => {
                error!("Failed to generate udev notification semaphore: {}", err);
                return Err(DmError::Core(errors::Error::UdevSync(err.to_string())));
            }
        };
        let sem_arg: semun = semun { val: 1 };
        if let Err(err) = semctl(semid, 0, SETVAL, Some(sem_arg)) {
            error!("Failed to initialize udev notification semaphore: {}", err);
            if let Err(err2) = notify_sem_destroy(cookie, semid) {
                error!("Failed to clean up udev notification semaphore: {}", err2);
            }
            return Err(DmError::Core(errors::Error::UdevSync(err.to_string())));
        }
        match semctl(semid, 0, GETVAL, None) {
            Ok(1) => Ok((cookie, semid)),
            _ => {
                error!("Initalization of udev notification semaphore returned inconsistent value.");
                Err(DmError::udev_sync_error_from_os())
            }
        }
    }

    /// Destroy the notification semaphore identified by semid.
    ///
    /// Remove the SysV semaphore set identified by the SysV IPC ID semid and
    /// IPC key cookie. This removes the SysV IPC ID identified by the cookie
    /// value and should be called following completion or cancelation of a
    /// notification semaphore.
    fn notify_sem_destroy(cookie: u32, semid: i32) -> DmResult<()> {
        if let Err(err) = semctl(semid, 0, IPC_RMID, None) {
            error!(
                "Failed to remove udev synchronization semaphore {} for cookie {}",
                semid, cookie
            );
            return Err(DmError::Core(errors::Error::UdevSync(err.to_string())));
        };
        Ok(())
    }

    /// Increment the semaphore identified by SysV IPC ID semid.
    fn notify_sem_inc(cookie: u32, semid: i32) -> DmResult<()> {
        // DM protocol always uses the 0th semaphore in the set identified by semid
        let mut sb = sembuf {
            sem_num: 0,
            sem_op: 1,
            sem_flg: 0,
        };
        let r = unsafe { libc_semop(semid, &mut sb, 1) };
        match r {
            i if i < 0 => {
                error!(
                    "Failed to increment udev synchronization semaphore {} for cookie {}",
                    semid, cookie
                );
                Err(DmError::udev_sync_error_from_os())
            }
            _ => Ok(()),
        }
    }

    /// Decrement the semaphore identified by SysV IPC ID semid.
    fn notify_sem_dec(cookie: u32, semid: i32) -> DmResult<()> {
        // DM protocol always uses the 0th semaphore in the set identified by semid
        let mut sb = sembuf {
            sem_num: 0,
            sem_op: -1,
            sem_flg: IPC_NOWAIT as i16,
        };
        let r = unsafe { libc_semop(semid, &mut sb, 1) };
        match r {
            i if i < 0 => {
                error!(
                    "Failed to decrement udev synchronization semaphore {} for cookie {}",
                    semid, cookie
                );
                Err(DmError::udev_sync_error_from_os())
            }
            _ => Ok(()),
        }
    }

    /// Wait for completion of notification semaphore identified by SysV IPC ID semid.
    ///
    /// This function blocks until the value of the first semaphore in the set
    /// identified by semid reaches zero (normally as a result of the dmsetup
    /// udev_complete invoked at the end of udev rule processing).
    fn notify_sem_wait(cookie: u32, semid: i32) -> DmResult<()> {
        if let Err(err) = notify_sem_dec(cookie, semid) {
            error!(
                concat!(
                    "Failed to set initial state for notification ",
                    "semaphore identified by cookie value {}: {}"
                ),
                cookie, err
            );
            if let Err(err2) = notify_sem_destroy(cookie, semid) {
                error!("Failed to clean up udev notification semaphore: {}", err2);
            }
        }
        let mut sb = sembuf {
            sem_num: 0,
            sem_op: 0,
            sem_flg: 0,
        };
        let r = unsafe { libc_semop(semid, &mut sb, 1) };
        match r {
            i if i < 0 => {
                error!(
                    "Failed to wait on notification semaphore {} for cookie {}",
                    semid, cookie
                );
                Err(DmError::udev_sync_error_from_os())
            }
            _ => Ok(()),
        }
    }

    #[derive(Debug)]
    pub struct UdevSync {
        cookie: u32,
        semid: Option<i32>,
    }

    impl UdevSyncAction for UdevSync {
        /// Begin UdevSync notification transaction.
        ///
        /// Allocate a SysV semaphore according to the device-mapper udev cookie
        /// protocol and set the initial state of the semaphore counter.
        fn begin(hdr: &mut dmi::Struct_dm_ioctl, ioctl: u8) -> DmResult<Self> {
            if !udev_running() {
                return Err(DmError::Core(errors::Error::UdevSync(
                    "Udev daemon is not running: unable to create devices.".to_string(),
                )));
            }

            match ioctl as u32 {
                dmi::DM_DEV_REMOVE_CMD | dmi::DM_DEV_RENAME_CMD | dmi::DM_DEV_SUSPEND_CMD
                    if *SYSV_SEM_SUPPORTED && (hdr.flags & DmFlags::DM_SUSPEND.bits()) == 0 => {}
                _ => {
                    return Ok(UdevSync {
                        cookie: 0,
                        semid: None,
                    });
                }
            };

            let (base_cookie, semid) = notify_sem_create()?;

            // Encode the primary source flag and the random base cookie value into
            // the header event_nr input field.
            hdr.event_nr |= (DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits()
                << dmi::DM_UDEV_FLAGS_SHIFT)
                | (base_cookie & !dmi::DM_UDEV_FLAGS_MASK);

            debug!(
                "Created UdevSync {{ cookie: {}, semid: {} }}",
                hdr.event_nr, semid
            );

            if let Err(err) = notify_sem_inc(hdr.event_nr, semid) {
                error!(
                    "Failed to set udev notification semaphore initial state: {}",
                    err
                );
                if let Err(err2) = notify_sem_destroy(hdr.event_nr, semid) {
                    error!("Failed to clean up udev notification semaphore: {}", err2);
                }
                return Err(err);
            }
            Ok(UdevSync {
                cookie: hdr.event_nr,
                semid: Some(semid),
            })
        }

        /// End UdevSync notification transaction.
        ///
        /// Wait for notification from the udev daemon on the semaphore owned by
        /// this UdevSync instance and destroy the semaphore on success.
        fn end(self, flags: u32) -> DmResult<()> {
            if self.is_active() {
                let semid = self.semid.expect("active UdevSync must have valid semid");
                if (flags & DmFlags::DM_UEVENT_GENERATED.bits()) == 0 {
                    if let Err(err) = notify_sem_dec(self.cookie, semid) {
                        error!("Failed to clear notification semaphore state: {}", err);
                        if let Err(err2) = notify_sem_destroy(self.cookie, semid) {
                            error!("Failed to clean up notification semaphore: {}", err2);
                        }
                        return Err(err);
                    }
                }
                trace!("Waiting on {:?}", self);
                notify_sem_wait(self.cookie, semid)?;
                trace!("Destroying {:?}", self);
                if let Err(err) = notify_sem_destroy(self.cookie, semid) {
                    error!("Failed to clean up notification semaphore: {}", err);
                }
            }
            Ok(())
        }

        /// Cancel an in-progress UdevSync notification transaction.
        ///
        /// Destroy the notification semaphore owned by this UdevSync instance
        /// without waiting for completion.
        fn cancel(self) {
            if self.is_active() {
                let semid = self.semid.expect("active UdevSync must have valid semid");
                trace!("Canceling {:?}", self);
                if let Err(err) = notify_sem_destroy(self.cookie, semid) {
                    error!("Failed to clean up notification semaphore: {}", err);
                }
            }
        }

        /// Test whether this UdevSync instance has an active notification semaphore.
        fn is_active(&self) -> bool {
            self.cookie != 0 && self.semid.is_some()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::dm_flags::DmUdevFlags;

        // SysV IPC key value for testing ("DMRS" in ASCII characters)
        const IPC_TEST_KEY: i32 = 0x444d5253;

        #[test]
        fn test_semget_invalid_nsems() {
            assert!(semget(0, -1, 0).is_err());
        }

        #[test]
        fn test_semget_create_destroy() {
            assert_matches!(semget(IPC_TEST_KEY, 1, IPC_CREAT | IPC_EXCL),
                Ok(semid) => assert!(semctl(semid, 0, IPC_RMID, None).is_ok()));
        }

        #[test]
        fn test_notify_sem_create_destroy() {
            assert_matches!(notify_sem_create(),
                Ok((cookie, semid)) => assert!(notify_sem_destroy(cookie, semid).is_ok()));
        }

        #[test]
        fn test_udevsync_non_primary_source() {
            let mut hdr: dmi::Struct_dm_ioctl = devicemapper_sys::dm_ioctl {
                ..Default::default()
            };
            let sync = UdevSync::begin(&mut hdr, dmi::DM_TABLE_STATUS_CMD as u8).unwrap();
            assert_eq!(sync.cookie, 0);
            assert_eq!(sync.semid, None);
            assert_eq!(hdr.event_nr, 0);
            assert!(sync.end(DmFlags::empty().bits()).is_ok());
        }

        #[test]
        fn test_udevsync_non_primary_source_cancel() {
            let mut hdr: dmi::Struct_dm_ioctl = devicemapper_sys::dm_ioctl {
                ..Default::default()
            };
            let sync = UdevSync::begin(&mut hdr, dmi::DM_TABLE_STATUS_CMD as u8).unwrap();
            assert_eq!(sync.cookie, 0);
            assert_eq!(sync.semid, None);
            assert_eq!(hdr.event_nr, 0);
            sync.cancel();
        }

        #[test]
        fn test_udevsync_primary_source_end() {
            let mut hdr: dmi::Struct_dm_ioctl = devicemapper_sys::dm_ioctl {
                ..Default::default()
            };
            let sync = UdevSync::begin(&mut hdr, dmi::DM_DEV_REMOVE_CMD as u8).unwrap();
            assert_ne!((sync.cookie & !dmi::DM_UDEV_FLAGS_MASK), 0);
            assert!(sync.semid.unwrap() >= 0);
            assert!(notify_sem_dec(sync.cookie, sync.semid.unwrap()).is_ok());
            assert_eq!(
                (hdr.event_nr >> dmi::DM_UDEV_FLAGS_SHIFT)
                    & DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits(),
                DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits()
            );
            assert!(sync.end(DmFlags::DM_UEVENT_GENERATED.bits()).is_ok());
        }

        #[test]
        fn test_udevsync_primary_source_cancel() {
            let mut hdr: dmi::Struct_dm_ioctl = devicemapper_sys::dm_ioctl {
                ..Default::default()
            };
            let sync = UdevSync::begin(&mut hdr, dmi::DM_DEV_REMOVE_CMD as u8).unwrap();
            assert_ne!((sync.cookie & !dmi::DM_UDEV_FLAGS_MASK), 0);
            assert!(sync.semid.unwrap() >= 0);
            assert_eq!(
                (hdr.event_nr >> dmi::DM_UDEV_FLAGS_SHIFT)
                    & DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits(),
                DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits()
            );
            sync.cancel();
        }

        #[test]
        fn test_udevsync_primary_source_end_no_uevent() {
            let mut hdr: dmi::Struct_dm_ioctl = devicemapper_sys::dm_ioctl {
                ..Default::default()
            };
            let sync = UdevSync::begin(&mut hdr, dmi::DM_DEV_REMOVE_CMD as u8).unwrap();
            assert_ne!((sync.cookie & !dmi::DM_UDEV_FLAGS_MASK), 0);
            assert!(sync.semid.unwrap() >= 0);
            assert_eq!(
                (hdr.event_nr >> dmi::DM_UDEV_FLAGS_SHIFT)
                    & DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits(),
                DmUdevFlags::DM_UDEV_PRIMARY_SOURCE_FLAG.bits()
            );
            assert!(sync.end(DmFlags::empty().bits()).is_ok());
        }
    }
}
#[cfg(target_os = "android")]
pub mod sync_noop {
    use super::UdevSyncAction;
    use crate::{core::dm_ioctl as dmi, result::DmResult};

    #[derive(Debug)]
    pub struct UdevSync {
        cookie: u32,
        semid: Option<i32>,
    }

    impl UdevSyncAction for UdevSync {
        fn begin(hdr: &mut dmi::Struct_dm_ioctl, ioctl: u8) -> DmResult<Self> {
            debug!("Created noop UdevSync {{ cookie: {}, semid: {} }}", 0, -1);
            Ok(UdevSync {
                cookie: 0,
                semid: None,
            })
        }

        fn end(self, _flags: u32) -> DmResult<()> {
            trace!("Destroying noop {:?}", self);
            Ok(())
        }

        fn cancel(self) {
            trace!("Canceling noop {:?}", self);
        }

        fn is_active(&self) -> bool {
            false
        }
    }
}

#[cfg(target_os = "android")]
pub use self::sync_noop::UdevSync;
#[cfg(not(target_os = "android"))]
pub use self::sync_semaphore::UdevSync;
