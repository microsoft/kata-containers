// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    cmp,
    fs::File,
    io::{Cursor, Read, Write},
    mem::size_of,
    os::unix::io::{AsRawFd, RawFd},
    slice, str,
};

use nix::{errno, libc::ioctl as nix_ioctl};
use retry::{delay::Fixed, retry_with_index, Error as RetryError, OperationResult};
use semver::Version;

use crate::{
    core::{
        device::Device,
        deviceinfo::DeviceInfo,
        dm_flags::DmFlags,
        dm_ioctl as dmi,
        dm_options::DmOptions,
        dm_udev_sync::{UdevSync, UdevSyncAction},
        errors,
        types::{DevId, DmName, DmNameBuf, DmUuid},
        util::{
            align_to, c_struct_from_slice, mut_slice_from_c_str, slice_from_c_struct,
            str_from_byte_slice, str_from_c_str,
        },
    },
    result::{DmError, DmResult, ErrorEnum},
};

#[cfg(target_os = "linux")]
/// Control path for user space to pass IOCTL to kernel DM
const DM_CTL_PATH: &str = "/dev/mapper/control";
#[cfg(target_os = "android")]
/// Control path for user space to pass IOCTL to kernel DM
const DM_CTL_PATH: &str = "/dev/device-mapper";

/// Start with a large buffer to make BUFFER_FULL rare. Libdm does this too.
const MIN_BUF_SIZE: usize = 16 * 1024;

/// Number of device remove retry attempts
const DM_REMOVE_RETRIES: usize = 5;

/// Delay between remove attempts
const DM_REMOVE_MSLEEP_DELAY: u64 = 200;

/// Context needed for communicating with devicemapper.
pub struct DM {
    file: File,
}

impl DmOptions {
    /// Generate a header to be used for IOCTL.
    fn to_ioctl_hdr(
        self,
        id: Option<&DevId<'_>>,
        allowable_flags: DmFlags,
    ) -> DmResult<dmi::Struct_dm_ioctl> {
        let clean_flags = allowable_flags & self.flags();
        let event_nr = self.udev_flags().bits() << dmi::DM_UDEV_FLAGS_SHIFT;
        let mut hdr: dmi::Struct_dm_ioctl = devicemapper_sys::dm_ioctl {
            flags: clean_flags.bits(),
            event_nr,
            data_start: size_of::<dmi::Struct_dm_ioctl>() as u32,
            ..Default::default()
        };

        if let Some(id) = id {
            match id {
                DevId::Name(name) => DM::hdr_set_name(&mut hdr, name)?,
                DevId::Uuid(uuid) => DM::hdr_set_uuid(&mut hdr, uuid)?,
            };
        };

        Ok(hdr)
    }
}

impl DM {
    /// Create a new context for communicating with DM.
    pub fn new() -> DmResult<DM> {
        Ok(DM {
            file: File::open(DM_CTL_PATH)
                .map_err(|err| DmError::Core(errors::Error::ContextInit(err.to_string())))?,
        })
    }

    fn hdr_set_name(hdr: &mut dmi::Struct_dm_ioctl, name: &DmName) -> DmResult<()> {
        let _ = name
            .as_bytes()
            .read(mut_slice_from_c_str(&mut hdr.name))
            .map_err(|err| errors::Error::GeneralIo(err.to_string()))?;
        Ok(())
    }

    fn hdr_set_uuid(hdr: &mut dmi::Struct_dm_ioctl, uuid: &DmUuid) -> DmResult<()> {
        let _ = uuid
            .as_bytes()
            .read(mut_slice_from_c_str(&mut hdr.uuid))
            .map_err(|err| errors::Error::GeneralIo(err.to_string()))?;
        Ok(())
    }

    /// Get the file within the DM context, likely for polling purposes.
    pub fn file(&self) -> &File {
        &self.file
    }

    // Make the ioctl call specified by the given ioctl number.
    // Set the required DM version to the lowest that supports the given ioctl.
    fn do_ioctl(
        &self,
        ioctl: u8,
        hdr: &mut dmi::Struct_dm_ioctl,
        in_data: Option<&[u8]>,
    ) -> DmResult<(DeviceInfo, Vec<u8>)> {
        let op = request_code_readwrite!(dmi::DM_IOCTL, ioctl, size_of::<dmi::Struct_dm_ioctl>());
        #[cfg(target_os = "android")]
        let op = op as i32;

        let ioctl_version = dmi::ioctl_to_version(ioctl);
        hdr.version[0] = ioctl_version.0;
        hdr.version[1] = ioctl_version.1;
        hdr.version[2] = ioctl_version.2;

        // Begin udev sync transaction and set DM_UDEV_PRIMARY_SOURCE_FLAG
        // if ioctl command generates uevents.
        let sync = UdevSync::begin(hdr, ioctl)?;

        let data_size = cmp::max(
            MIN_BUF_SIZE,
            size_of::<dmi::Struct_dm_ioctl>() + in_data.map_or(0, |x| x.len()),
        );

        let mut buffer: Vec<u8> = Vec::with_capacity(data_size);
        let mut buffer_hdr;
        loop {
            hdr.data_size = buffer.capacity() as u32;

            let hdr_slc = unsafe {
                let len = hdr.data_start as usize;
                let ptr = hdr as *mut dmi::Struct_dm_ioctl as *mut u8;
                slice::from_raw_parts_mut(ptr, len)
            };

            buffer.clear();
            buffer.extend_from_slice(hdr_slc);
            if let Some(in_data) = in_data {
                buffer.extend(in_data.iter().cloned());
            }
            buffer.resize(buffer.capacity(), 0);

            buffer_hdr = unsafe { &mut *(buffer.as_mut_ptr() as *mut dmi::Struct_dm_ioctl) };

            if let Err(err) = unsafe {
                convert_ioctl_res!(nix_ioctl(self.file.as_raw_fd(), op, buffer.as_mut_ptr()))
            } {
                // Cancel udev sync and clean up semaphore
                sync.cancel();
                return Err(DmError::Core(errors::Error::Ioctl(
                    op as u8,
                    DeviceInfo::new(*hdr).ok().map(Box::new),
                    DeviceInfo::new(*buffer_hdr).ok().map(Box::new),
                    Box::new(err),
                )));
            }

            if (buffer_hdr.flags & DmFlags::DM_BUFFER_FULL.bits()) == 0 {
                break;
            }

            // If DM_BUFFER_FULL is set, DM requires more space for the
            // response.  Double the capacity of the buffer and re-try the
            // ioctl. If the size of the buffer is already as large as can be
            // possibly expressed in data_size field, return an error.
            // Never allow the size to exceed u32::MAX.
            let len = buffer.capacity();
            if len == u32::MAX as usize {
                return Err(DmError::Core(errors::Error::IoctlResultTooLarge));
            }
            buffer.resize((len as u32).saturating_mul(2) as usize, 0);
        }

        let data_end = cmp::max(buffer_hdr.data_size, buffer_hdr.data_start);

        // Synchronize with udev event processing
        sync.end(buffer_hdr.flags)?;
        Ok((
            DeviceInfo::try_from(*buffer_hdr)?,
            buffer[buffer_hdr.data_start as usize..data_end as usize].to_vec(),
        ))
    }

    /// Devicemapper version information: Major, Minor, and patchlevel versions.
    pub fn version(&self) -> DmResult<(u32, u32, u32)> {
        let mut hdr = DmOptions::default().to_ioctl_hdr(None, DmFlags::empty())?;

        let (hdr_out, _) = self.do_ioctl(dmi::DM_VERSION_CMD as u8, &mut hdr, None)?;

        Ok((
            hdr_out
                .version()
                .major
                .try_into()
                .expect("dm_ioctl struct field is u32"),
            hdr_out
                .version()
                .minor
                .try_into()
                .expect("dm_ioctl struct field is u32"),
            hdr_out
                .version()
                .patch
                .try_into()
                .expect("dm_ioctl struct field is u32"),
        ))
    }

    /// Remove all DM devices and tables. Use discouraged other than
    /// for debugging.
    ///
    /// If `DM_DEFERRED_REMOVE` is set, the request will succeed for
    /// in-use devices, and they will be removed when released.
    ///
    /// Valid flags: `DM_DEFERRED_REMOVE`
    pub fn remove_all(&self, options: DmOptions) -> DmResult<()> {
        let mut hdr = options.to_ioctl_hdr(None, DmFlags::DM_DEFERRED_REMOVE)?;

        self.do_ioctl(dmi::DM_REMOVE_ALL_CMD as u8, &mut hdr, None)?;

        Ok(())
    }

    /// Returns a list of tuples containing DM device names, a Device, which
    /// holds their major and minor device numbers, and on kernels that
    /// support it, each device's last event_nr.
    pub fn list_devices(&self) -> DmResult<Vec<(DmNameBuf, Device, Option<u32>)>> {
        let mut hdr = DmOptions::default().to_ioctl_hdr(None, DmFlags::empty())?;
        let (hdr_out, data_out) = self.do_ioctl(dmi::DM_LIST_DEVICES_CMD as u8, &mut hdr, None)?;

        let event_nr_set = hdr_out.version() >= &Version::new(4, 37, 0);

        let mut devs = Vec::new();
        if !data_out.is_empty() {
            let mut result = &data_out[..];

            loop {
                let device =
                    c_struct_from_slice::<dmi::Struct_dm_name_list>(result).ok_or_else(|| {
                        DmError::Dm(
                            ErrorEnum::Invalid,
                            "Received null pointer from kernel".to_string(),
                        )
                    })?;
                let name_offset = unsafe {
                    (device.name.as_ptr() as *const u8).offset_from(device as *const _ as *const u8)
                } as usize;

                let dm_name = str_from_byte_slice(&result[name_offset..])
                    .map(|s| s.to_owned())
                    .ok_or_else(|| {
                        DmError::Dm(
                            ErrorEnum::Invalid,
                            "Devicemapper name is not valid UTF8".to_string(),
                        )
                    })?;

                // Get each device's event number after its name, if the kernel
                // DM version supports it.
                // Should match offset calc in kernel's
                // drivers/md/dm-ioctl.c:list_devices
                let event_nr = if event_nr_set {
                    // offsetof "name" in Struct_dm_name_list.
                    let offset = align_to(name_offset + dm_name.len() + 1, size_of::<u64>());
                    let nr = u32::from_ne_bytes(
                        result[offset..offset + size_of::<u32>()]
                            .try_into()
                            .map_err(|_| {
                                DmError::Dm(
                                    ErrorEnum::Invalid,
                                    "Incorrectly sized slice for u32".to_string(),
                                )
                            })?,
                    );

                    Some(nr)
                } else {
                    None
                };

                devs.push((DmNameBuf::new(dm_name)?, device.dev.into(), event_nr));

                if device.next == 0 {
                    break;
                }

                result = &result[device.next as usize..];
            }
        }

        Ok(devs)
    }

    /// Create a DM device. It starts out in a "suspended" state.
    ///
    /// Valid flags: `DM_READONLY`, `DM_PERSISTENT_DEV`
    ///
    /// # Example
    ///
    /// ```no_run
    /// use devicemapper::{DM, DmOptions, DmName};
    ///
    /// let dm = DM::new().unwrap();
    ///
    /// // Setting a uuid is optional
    /// let name = DmName::new("example-dev").expect("is valid DM name");
    /// let dev = dm.device_create(name, None, DmOptions::default()).unwrap();
    /// ```
    pub fn device_create(
        &self,
        name: &DmName,
        uuid: Option<&DmUuid>,
        options: DmOptions,
    ) -> DmResult<DeviceInfo> {
        let mut hdr =
            options.to_ioctl_hdr(None, DmFlags::DM_READONLY | DmFlags::DM_PERSISTENT_DEV)?;

        Self::hdr_set_name(&mut hdr, name)?;
        if let Some(uuid) = uuid {
            Self::hdr_set_uuid(&mut hdr, uuid)?;
        }

        debug!("Creating device {} (uuid={:?})", name, uuid);
        self.do_ioctl(dmi::DM_DEV_CREATE_CMD as u8, &mut hdr, None)
            .map(|(hdr, _)| hdr)
    }

    fn try_device_remove(
        &self,
        id: &DevId<'_>,
        options: DmOptions,
    ) -> OperationResult<DeviceInfo, DmError> {
        let mut hdr = match options.to_ioctl_hdr(Some(id), DmFlags::DM_DEFERRED_REMOVE) {
            Ok(hdr) => hdr,
            Err(err) => {
                return OperationResult::Err(err);
            }
        };

        match self.do_ioctl(dmi::DM_DEV_REMOVE_CMD as u8, &mut hdr, None) {
            Err(err) => {
                if let DmError::Core(errors::Error::Ioctl(op, hdr_in, hdr_out, errno)) = err {
                    if *errno == errno::Errno::EBUSY {
                        OperationResult::Retry(DmError::Core(errors::Error::Ioctl(
                            op, hdr_in, hdr_out, errno,
                        )))
                    } else {
                        OperationResult::Err(DmError::Core(errors::Error::Ioctl(
                            op, hdr_in, hdr_out, errno,
                        )))
                    }
                } else {
                    OperationResult::Err(err)
                }
            }
            Ok((deviceinfo, _)) => OperationResult::Ok(deviceinfo),
        }
    }

    /// Remove a DM device and its mapping tables.
    ///
    /// If `DM_DEFERRED_REMOVE` is set, the request for an in-use
    /// devices will succeed, and it will be removed when no longer
    /// used.
    ///
    /// Valid flags: `DM_DEFERRED_REMOVE`
    pub fn device_remove(&self, id: &DevId<'_>, options: DmOptions) -> DmResult<DeviceInfo> {
        debug!("Removing device {}", id);
        match retry_with_index(
            Fixed::from_millis(DM_REMOVE_MSLEEP_DELAY).take(DM_REMOVE_RETRIES - 1),
            |i| {
                debug!("Device remove attempt {} of {}", i, DM_REMOVE_RETRIES);
                self.try_device_remove(id, options)
            },
        ) {
            Ok(deviceinfo) => Ok(deviceinfo),
            Err(err) => match err {
                RetryError::Operation { error, .. } => Err(error),
                _ => Err(DmError::Core(errors::Error::UdevSync(
                    "Error retrying ioctl".to_string(),
                ))),
            },
        }
    }

    /// Change a DM device's name OR set the device's uuid for the first time.
    ///
    /// Prerequisite: if `new == DevId::Name(new_name)`, `old_name != new_name`
    /// Prerequisite: if `new == DevId::Uuid(uuid)`, device's current uuid
    /// must be `""`.
    /// Note: Possibly surprisingly, returned `DeviceInfo`'s uuid or name field
    /// contains the previous value, not the newly set value.
    pub fn device_rename(&self, old_name: &DmName, new: &DevId<'_>) -> DmResult<DeviceInfo> {
        let (options, id_in) = match *new {
            DevId::Name(name) => (DmOptions::default(), name.as_bytes()),
            DevId::Uuid(uuid) => (
                DmOptions::default().set_flags(DmFlags::DM_UUID),
                uuid.as_bytes(),
            ),
        };

        let data_in = [id_in, &[b'\0']].concat();

        let mut hdr = options.to_ioctl_hdr(None, DmFlags::DM_UUID)?;
        Self::hdr_set_name(&mut hdr, old_name)?;

        debug!("Renaming device {} to {}", old_name, new);
        self.do_ioctl(dmi::DM_DEV_RENAME_CMD as u8, &mut hdr, Some(&data_in))
            .map(|(hdr, _)| hdr)
    }

    /// Suspend or resume a DM device, depending on if `DM_SUSPEND` flag
    /// is set or not.
    ///
    /// Resuming a DM device moves a table loaded into the "inactive"
    /// slot by [`Self::table_load`] into the "active" slot.
    ///
    /// Will block until pending I/O is completed unless DM_NOFLUSH
    /// flag is given. Will freeze filesystem unless DM_SKIP_LOCKFS
    /// flags is given. Additional I/O to a suspended device will be
    /// held until it is resumed.
    ///
    /// Valid flags: `DM_SUSPEND`, `DM_NOFLUSH`, `DM_SKIP_LOCKFS`
    ///
    /// # Example
    ///
    /// ```no_run
    /// use devicemapper::{DM, DevId, DmFlags, DmOptions, DmName};
    /// let dm = DM::new().unwrap();
    ///
    /// let name = DmName::new("example-dev").expect("is valid DM name");
    /// let id = DevId::Name(name);
    /// dm.device_suspend(&id, DmOptions::default().set_flags(DmFlags::DM_SUSPEND)).unwrap();
    /// ```
    pub fn device_suspend(&self, id: &DevId<'_>, options: DmOptions) -> DmResult<DeviceInfo> {
        let mut hdr = options.to_ioctl_hdr(
            Some(id),
            DmFlags::DM_SUSPEND | DmFlags::DM_NOFLUSH | DmFlags::DM_SKIP_LOCKFS,
        )?;

        let action = if options.flags().contains(DmFlags::DM_SUSPEND) {
            "Suspending"
        } else {
            "Resuming"
        };
        debug!("{} device {}", action, id);
        self.do_ioctl(dmi::DM_DEV_SUSPEND_CMD as u8, &mut hdr, None)
            .map(|(hdr, _)| hdr)
    }

    /// Get DeviceInfo for a device. This is also returned by other
    /// methods, but if just the DeviceInfo is desired then this just
    /// gets it.
    pub fn device_info(&self, id: &DevId<'_>) -> DmResult<DeviceInfo> {
        let mut hdr = DmOptions::default().to_ioctl_hdr(Some(id), DmFlags::empty())?;

        debug!("Retrieving info for {}", id);
        self.do_ioctl(dmi::DM_DEV_STATUS_CMD as u8, &mut hdr, None)
            .map(|(hdr, _)| hdr)
    }

    /// Wait for a device to report an event.
    ///
    /// Once an event occurs, this function behaves just like
    /// [`Self::table_status`], see that function for more details.
    ///
    /// This interface is not very friendly to monitoring multiple devices.
    /// Events are also exported via uevents, that method may be preferable.
    #[allow(clippy::type_complexity)]
    pub fn device_wait(
        &self,
        id: &DevId<'_>,
        options: DmOptions,
    ) -> DmResult<(DeviceInfo, Vec<(u64, u64, String, String)>)> {
        let mut hdr = options.to_ioctl_hdr(Some(id), DmFlags::DM_QUERY_INACTIVE_TABLE)?;

        debug!("Waiting on event for {}", id);
        let (hdr_out, data_out) = self.do_ioctl(dmi::DM_DEV_WAIT_CMD as u8, &mut hdr, None)?;

        let status = DM::parse_table_status(hdr.target_count, &data_out)?;

        Ok((hdr_out, status))
    }

    /// Load targets for a device into its inactive table slot.
    ///
    /// `targets` is an array of `(sector_start, sector_length, type, params)`.
    ///
    /// `options` Valid flags: `DM_READ_ONLY`, `DM_SECURE_DATA`
    ///
    /// # Example
    ///
    /// ```no_run
    /// use devicemapper::{DM, DevId, DmName, DmOptions};
    /// let dm = DM::new().unwrap();
    ///
    /// // Create a 16MiB device (32768 512-byte sectors) that maps to /dev/sdb1
    /// // starting 1MiB into sdb1
    /// let table = vec![(
    ///     0,
    ///     32768,
    ///     "linear".into(),
    ///     "/dev/sdb1 2048".into()
    /// )];
    ///
    /// let name = DmName::new("example-dev").expect("is valid DM name");
    /// let id = DevId::Name(name);
    /// dm.table_load(&id, &table, DmOptions::default()).unwrap();
    /// ```
    pub fn table_load(
        &self,
        id: &DevId<'_>,
        targets: &[(u64, u64, String, String)],
        options: DmOptions,
    ) -> DmResult<DeviceInfo> {
        let mut cursor = Cursor::new(Vec::new());

        // Construct targets first, since we need to know how many & size
        // before initializing the header.
        for (sector_start, length, target_type, params) in targets {
            let mut targ = dmi::Struct_dm_target_spec {
                sector_start: *sector_start,
                length: *length,
                status: 0,
                ..Default::default()
            };

            let dst = mut_slice_from_c_str(&mut targ.target_type);
            assert!(
                target_type.len() <= dst.len(),
                "TargetType max length = targ.target_type.len()"
            );
            let _ = target_type
                .as_bytes()
                .read(dst)
                .map_err(|err| errors::Error::GeneralIo(err.to_string()))?;

            // Size of the largest single member of dm_target_spec
            let align_to_size = size_of::<u64>();
            let aligned_len = align_to(params.len() + 1usize, align_to_size);
            targ.next = (size_of::<dmi::Struct_dm_target_spec>() + aligned_len) as u32;

            cursor
                .write_all(slice_from_c_struct(&targ))
                .map_err(|err| errors::Error::GeneralIo(err.to_string()))?;
            cursor
                .write_all(params.as_bytes())
                .map_err(|err| errors::Error::GeneralIo(err.to_string()))?;

            let padding = aligned_len - params.len();
            cursor
                .write_all(vec![0; padding].as_slice())
                .map_err(|err| errors::Error::GeneralIo(err.to_string()))?;
        }

        let mut hdr =
            options.to_ioctl_hdr(Some(id), DmFlags::DM_READONLY | DmFlags::DM_SECURE_DATA)?;

        // io_ioctl() will set hdr.data_size but we must set target_count
        hdr.target_count = targets.len() as u32;

        // Flatten targets into a buf
        let data_in = cursor.into_inner();

        debug!("Loading table \"{:?}\" for {}", targets, id);
        self.do_ioctl(dmi::DM_TABLE_LOAD_CMD as u8, &mut hdr, Some(&data_in))
            .map(|(hdr, _)| hdr)
    }

    /// Clear the "inactive" table for a device.
    pub fn table_clear(&self, id: &DevId<'_>) -> DmResult<DeviceInfo> {
        let mut hdr = DmOptions::default().to_ioctl_hdr(Some(id), DmFlags::empty())?;

        debug!("Clearing inactive dable for {}", id);
        self.do_ioctl(dmi::DM_TABLE_CLEAR_CMD as u8, &mut hdr, None)
            .map(|(hdr, _)| hdr)
    }

    /// Query DM for which devices are referenced by the "active"
    /// table for this device.
    ///
    /// If DM_QUERY_INACTIVE_TABLE is set, instead return for the
    /// inactive table.
    ///
    /// Valid flags: DM_QUERY_INACTIVE_TABLE
    pub fn table_deps(&self, id: &DevId<'_>, options: DmOptions) -> DmResult<Vec<Device>> {
        let mut hdr = options.to_ioctl_hdr(Some(id), DmFlags::DM_QUERY_INACTIVE_TABLE)?;

        debug!("Querying dependencies for {}", id);
        let (_, data_out) = self.do_ioctl(dmi::DM_TABLE_DEPS_CMD as u8, &mut hdr, None)?;

        if data_out.is_empty() {
            Ok(vec![])
        } else {
            let result = &data_out[..];
            let target_deps = unsafe { &*(result.as_ptr() as *const dmi::Struct_dm_target_deps) };

            let dev_slc = unsafe {
                slice::from_raw_parts(
                    result[size_of::<dmi::Struct_dm_target_deps>()..].as_ptr() as *const u64,
                    target_deps.count as usize,
                )
            };

            // Note: The DM target_deps struct reserves 64 bits for each entry
            // but only 32 bits is used by kernel "huge" dev_t encoding.
            Ok(dev_slc
                .iter()
                .map(|d| Device::from_kdev_t(*d as u32))
                .collect())
        }
    }

    /// Parse a device's table. The table value is in buf, count indicates the
    /// expected number of lines.
    /// Trims trailing white space off final entry on each line. This
    /// canonicalization makes checking identity of tables easier.
    /// Postcondition: The length of the next to last entry in any tuple is
    /// no more than 16 characters.
    fn parse_table_status(count: u32, buf: &[u8]) -> DmResult<Vec<(u64, u64, String, String)>> {
        let mut targets = Vec::new();
        if !buf.is_empty() {
            let mut next_off = 0;

            for _ in 0..count {
                let result = &buf[next_off..];
                let targ = unsafe { &*(result.as_ptr() as *const dmi::Struct_dm_target_spec) };

                let target_type = str_from_c_str(&targ.target_type)
                    .ok_or_else(|| {
                        DmError::Dm(
                            ErrorEnum::Invalid,
                            "Could not convert target type to a String".to_string(),
                        )
                    })?
                    .to_string();

                let params =
                    str_from_byte_slice(&result[size_of::<dmi::Struct_dm_target_spec>()..])
                        .ok_or_else(|| {
                            DmError::Dm(
                                ErrorEnum::Invalid,
                                "Invalid DM target parameters returned from kernel".to_string(),
                            )
                        })?
                        .to_string();

                targets.push((targ.sector_start, targ.length, target_type, params));

                next_off = targ.next as usize;
            }
        }
        Ok(targets)
    }

    /// Return the status of all targets for a device's "active"
    /// table.
    ///
    /// Returns DeviceInfo and a Vec of (sector_start, sector_length, type, params).
    ///
    /// If DM_STATUS_TABLE flag is set, returns the current table value. Otherwise
    /// returns target-specific status information.
    ///
    /// If DM_NOFLUSH is set, retrieving the target-specific status information for
    /// targets with metadata will not cause a metadata write.
    ///
    /// If DM_QUERY_INACTIVE_TABLE is set, instead return the status of the
    /// inactive table.
    ///
    /// Valid flags: DM_NOFLUSH, DM_STATUS_TABLE, DM_QUERY_INACTIVE_TABLE
    ///
    /// # Example
    ///
    /// ```no_run
    /// use devicemapper::{DM, DevId, DmFlags, DmOptions, DmName};
    /// let dm = DM::new().unwrap();
    ///
    /// let name = DmName::new("example-dev").expect("is valid DM name");
    /// let id = DevId::Name(name);
    /// let res = dm.table_status(&id,
    ///                           DmOptions::default().set_flags(DmFlags::DM_STATUS_TABLE)).unwrap();
    /// println!("{:?} {:?}", res.0.name(), res.1);
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn table_status(
        &self,
        id: &DevId<'_>,
        options: DmOptions,
    ) -> DmResult<(DeviceInfo, Vec<(u64, u64, String, String)>)> {
        let mut hdr = options.to_ioctl_hdr(
            Some(id),
            DmFlags::DM_NOFLUSH | DmFlags::DM_STATUS_TABLE | DmFlags::DM_QUERY_INACTIVE_TABLE,
        )?;

        debug!("Retrieving table status for {}", id);
        let (hdr_out, data_out) = self.do_ioctl(dmi::DM_TABLE_STATUS_CMD as u8, &mut hdr, None)?;

        let status = DM::parse_table_status(hdr_out.target_count, &data_out)?;

        Ok((hdr_out, status))
    }

    /// Returns a list of each loaded target type with its name, and
    /// version broken into major, minor, and patchlevel.
    #[cfg(devicemapper41supported)]
    pub fn list_versions(&self) -> DmResult<Vec<(String, u32, u32, u32)>> {
        let mut hdr = DmOptions::default().to_ioctl_hdr(None, DmFlags::empty())?;

        debug!("Listing loaded target versions");
        let (_, data_out) = self.do_ioctl(dmi::DM_LIST_VERSIONS_CMD as u8, &mut hdr, None)?;

        let mut targets = Vec::new();
        if !data_out.is_empty() {
            let mut result = &data_out[..];

            loop {
                let tver = unsafe { &*(result.as_ptr() as *const dmi::Struct_dm_target_versions) };

                let name =
                    str_from_byte_slice(&result[size_of::<dmi::Struct_dm_target_versions>()..])
                        .ok_or_else(|| {
                            DmError::Dm(
                                ErrorEnum::Invalid,
                                "Invalid DM target name returned from kernel".to_string(),
                            )
                        })?
                        .to_string();
                targets.push((name, tver.version[0], tver.version[1], tver.version[2]));

                if tver.next == 0 {
                    break;
                }

                result = &result[tver.next as usize..];
            }
        }

        Ok(targets)
    }

    /// Send a message to the device specified by id and the sector
    /// specified by sector. If sending to the whole device, set sector to
    /// None.
    #[cfg(devicemapper42supported)]
    pub fn target_msg(
        &self,
        id: &DevId<'_>,
        sector: Option<u64>,
        msg: &str,
    ) -> DmResult<(DeviceInfo, Option<String>)> {
        let mut hdr = DmOptions::default().to_ioctl_hdr(Some(id), DmFlags::empty())?;

        let msg_struct = dmi::Struct_dm_target_msg {
            sector: sector.unwrap_or_default(),
            ..Default::default()
        };
        let mut data_in = unsafe {
            let ptr = &msg_struct as *const dmi::Struct_dm_target_msg as *mut u8;
            slice::from_raw_parts(ptr, size_of::<dmi::Struct_dm_target_msg>()).to_vec()
        };

        data_in.extend(msg.as_bytes());
        data_in.push(b'\0');

        debug!("Sending target message \"{}\" to {}", msg, id);
        let (hdr_out, data_out) =
            self.do_ioctl(dmi::DM_TARGET_MSG_CMD as u8, &mut hdr, Some(&data_in))?;

        let output = if (hdr_out.flags().bits() & DmFlags::DM_DATA_OUT.bits()) > 0 {
            Some(
                str::from_utf8(&data_out[..data_out.len() - 1])
                    .map(|res| res.to_string())
                    .map_err(|_| {
                        DmError::Dm(
                            ErrorEnum::Invalid,
                            "Could not convert output to a String".to_string(),
                        )
                    })?,
            )
        } else {
            None
        };
        Ok((hdr_out, output))
    }

    /// If DM is being used to poll for events, once it indicates readiness it
    /// will continue to do so until we rearm it, which is what this method
    /// does.
    #[cfg(devicemapper437supported)]
    pub fn arm_poll(&self) -> DmResult<DeviceInfo> {
        let mut hdr = DmOptions::default().to_ioctl_hdr(None, DmFlags::empty())?;

        debug!("Issuing device-mapper arm poll command");
        self.do_ioctl(dmi::DM_DEV_ARM_POLL_CMD as u8, &mut hdr, None)
            .map(|(hdr, _)| hdr)
    }
}

impl AsRawFd for DM {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        core::errors::Error,
        result::DmError,
        testing::{test_name, test_uuid},
    };

    use super::*;

    #[test]
    /// Test that some version can be obtained.
    fn sudo_test_version() {
        assert_matches!(DM::new().unwrap().version(), Ok(_));
    }

    #[test]
    /// Test that versions for some targets can be obtained.
    fn sudo_test_versions() {
        assert!(!DM::new().unwrap().list_versions().unwrap().is_empty());
    }

    #[test]
    /// Verify that if no devices have been created the list of test devices
    /// is empty.
    fn sudo_test_list_devices_empty() {
        assert!(DM::new().unwrap().list_test_devices().unwrap().is_empty());
    }

    #[test]
    /// Verify that if one test device has been created, it will be the only
    /// test device listed.
    fn sudo_test_list_devices() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        dm.device_create(&name, None, DmOptions::default()).unwrap();

        let devices = dm.list_test_devices().unwrap();

        assert_eq!(devices.len(), 1);

        if dm.version().unwrap().1 >= 37 {
            assert_matches!(devices.first().expect("len is 1"), (nm, _, Some(0)) if nm == &name);
        } else {
            assert_matches!(devices.first().expect("len is 1"), (nm, _, None) if nm == &name);
        }

        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Test that device creation gives a device with the expected name.
    fn sudo_test_create() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        let result = dm.device_create(&name, None, DmOptions::default()).unwrap();

        assert_eq!(result.name(), Some(&*name));
        assert_eq!(result.uuid(), None);

        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Verify that creation with a UUID results in correct name and UUID.
    fn sudo_test_create_uuid() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        let uuid = test_uuid("example-363333333333333").expect("is valid DM uuid");
        let result = dm
            .device_create(&name, Some(&uuid), DmOptions::default())
            .unwrap();

        assert_eq!(result.name(), Some(&*name));
        assert_eq!(result.uuid(), Some(&*uuid));

        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Verify that resetting uuid fails.
    fn sudo_test_rename_uuid() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        let uuid = test_uuid("example-363333333333333").expect("is valid DM uuid");
        dm.device_create(&name, Some(&uuid), DmOptions::default())
            .unwrap();

        let new_uuid = test_uuid("example-9999999999").expect("is valid DM uuid");

        assert_matches!(
            dm.device_rename(&name, &DevId::Uuid(&new_uuid)),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::EINVAL && op == dmi::DM_DEV_RENAME_CMD as u8
        );

        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Verify that resetting uuid to same uuid fails.
    /// Since a device with that UUID already exists, the UUID can not be used.
    fn sudo_test_rename_uuid_id() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        let uuid = test_uuid("example-363333333333333").expect("is valid DM uuid");
        dm.device_create(&name, Some(&uuid), DmOptions::default())
            .unwrap();
        assert_matches!(
            dm.device_rename(&name, &DevId::Uuid(&uuid)),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::EBUSY && op == dmi::DM_DEV_RENAME_CMD as u8
        );

        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Verify that setting a new uuid succeeds.
    /// Note that the uuid is not set in the returned dev_info.
    fn sudo_test_set_uuid() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        dm.device_create(&name, None, DmOptions::default()).unwrap();

        let uuid = test_uuid("example-363333333333333").expect("is valid DM uuid");
        let result = dm.device_rename(&name, &DevId::Uuid(&uuid)).unwrap();
        assert_eq!(result.uuid(), None);
        assert_eq!(
            dm.device_info(&DevId::Name(&name)).unwrap().uuid().unwrap(),
            &*uuid
        );
        assert_matches!(dm.device_info(&DevId::Uuid(&uuid)), Ok(_));
        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Test that device rename to same name fails.
    /// Since a device with that name already exists, the name can not be used.
    fn sudo_test_rename_id() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        dm.device_create(&name, None, DmOptions::default()).unwrap();

        assert_matches!(
            dm.device_rename(&name, &DevId::Name(&name)),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::EBUSY && op == dmi::DM_DEV_RENAME_CMD as u8
        );

        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Test that device rename to different name works.
    /// Verify that the only test device in the list of devices is a device
    /// with the new name.
    fn sudo_test_rename() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        dm.device_create(&name, None, DmOptions::default()).unwrap();

        let new_name = test_name("example-dev-2").expect("is valid DM name");
        dm.device_rename(&name, &DevId::Name(&new_name)).unwrap();

        assert_matches!(
            dm.device_info(&DevId::Name(&name)),
            Err(DmError::Core(Error::Ioctl(_, _, _, err))) if *err == nix::errno::Errno::ENXIO
        );

        assert_matches!(dm.device_info(&DevId::Name(&new_name)), Ok(_));

        let devices = dm.list_test_devices().unwrap();
        assert_eq!(devices.len(), 1);

        if dm.version().unwrap().1 >= 37 {
            assert_matches!(devices.first().expect("len is 1"), (nm, _, Some(0)) if nm == &new_name);
        } else {
            assert_matches!(devices.first().expect("len is 1"), (nm, _, None) if nm == &new_name);
        }

        let third_name = test_name("example-dev-3").expect("is valid DM name");
        dm.device_create(&third_name, None, DmOptions::default())
            .unwrap();

        assert_matches!(
            dm.device_rename(&new_name, &DevId::Name(&third_name)),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::EBUSY && op == dmi::DM_DEV_RENAME_CMD as u8
        );

        dm.device_remove(&DevId::Name(&third_name), DmOptions::default())
            .unwrap();
        dm.device_remove(&DevId::Name(&new_name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Renaming a device that does not exist yields an error.
    fn sudo_test_rename_non_existant() {
        let new_name = test_name("new_name").expect("is valid DM name");
        assert_matches!(
            DM::new().unwrap().device_rename(
                &test_name("old_name").expect("is valid DM name"),
                &DevId::Name(&new_name)
            ),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::ENXIO && op == dmi::DM_DEV_RENAME_CMD as u8
        );
    }

    #[test]
    /// Removing a device that does not exist yields an error.
    fn sudo_test_remove_non_existant() {
        assert_matches!(
            DM::new().unwrap().device_remove(
                &DevId::Name(&test_name("junk").expect("is valid DM name")),
                DmOptions::default()
            ),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::ENXIO && op == dmi::DM_DEV_REMOVE_CMD as u8
        );
    }

    #[test]
    /// A newly created device has no deps.
    fn sudo_test_empty_deps() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        dm.device_create(&name, None, DmOptions::default()).unwrap();

        let deps = dm
            .table_deps(&DevId::Name(&name), DmOptions::default())
            .unwrap();
        assert!(deps.is_empty());
        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Table status on a non-existant name should return an error.
    fn sudo_test_table_status_non_existant() {
        assert_matches!(
            DM::new().unwrap().table_status(
                &DevId::Name(&test_name("junk").expect("is valid DM name")),
                DmOptions::default()
            ),
            Err(DmError::Core(Error::Ioctl(_, _, _, err))) if *err == nix::errno::Errno::ENXIO
        );
    }

    #[test]
    /// Table status on a non-existant name with TABLE_STATUS flag errors.
    fn sudo_test_table_status_non_existant_table() {
        let name = test_name("junk").expect("is valid DM name");
        assert_matches!(
            DM::new().unwrap().table_status(
                &DevId::Name(&name),
                DmOptions::default().set_flags(DmFlags::DM_STATUS_TABLE)
            ),
            Err(DmError::Core(Error::Ioctl(_, _, _, err))) if *err == nix::errno::Errno::ENXIO
        );
    }

    #[test]
    /// The table should have an entry for a newly created device.
    /// The device has no segments, so the second part of the info should
    /// be empty.
    /// The UUID of the returned info should be the device's UUID.
    fn sudo_test_table_status() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        let uuid = test_uuid("uuid").expect("is valid DM UUID");
        dm.device_create(&name, Some(&uuid), DmOptions::default())
            .unwrap();

        let (hdr_out, status) = dm
            .table_status(&DevId::Name(&name), DmOptions::default())
            .unwrap();
        assert!(status.is_empty());
        assert_eq!(hdr_out.uuid(), Some(&*uuid));
        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }

    #[test]
    /// Verify that getting the status of a non-existent device specified
    /// by name returns an error.
    fn sudo_status_no_name() {
        let name = test_name("example_dev").expect("is valid DM name");
        assert_matches!(
            DM::new().unwrap().device_info(&DevId::Name(&name)),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::ENXIO && op == dmi::DM_DEV_STATUS_CMD as u8
        );
    }

    #[test]
    /// Verify that creating a device with the same name twice fails.
    /// Verify that creating a device with the same uuid twice fails.
    fn sudo_test_double_creation() {
        let dm = DM::new().unwrap();
        let name = test_name("example-dev").expect("is valid DM name");
        let uuid = test_uuid("uuid").expect("is valid DM UUID");

        let name_alt = test_name("name-alt").expect("is valid DM name");
        let uuid_alt = test_uuid("uuid-alt").expect("is valid DM UUID");

        dm.device_create(&name, Some(&uuid), DmOptions::default())
            .unwrap();
        assert_matches!(
            dm.device_create(&name, Some(&uuid), DmOptions::default()),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::EBUSY && op == dmi::DM_DEV_CREATE_CMD as u8
        );
        assert_matches!(
            dm.device_create(&name, None, DmOptions::default()),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::EBUSY && op == dmi::DM_DEV_CREATE_CMD as u8
        );
        assert_matches!(
            dm.device_create(&name, Some(&uuid_alt), DmOptions::default()),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::EBUSY && op == dmi::DM_DEV_CREATE_CMD as u8
        );
        assert_matches!(
            dm.device_create(&name_alt, Some(&uuid), DmOptions::default()),
            Err(DmError::Core(Error::Ioctl(op, _, _, err))) if *err == nix::errno::Errno::EBUSY && op == dmi::DM_DEV_CREATE_CMD as u8
        );
        dm.device_remove(&DevId::Name(&name), DmOptions::default())
            .unwrap();
    }
}
