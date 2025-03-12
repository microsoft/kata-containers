// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// A module to contain functionality shared among the various types of
// devices.

use std::{
    fmt,
    ops::Deref,
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::{
    core::{devnode_to_devno, DevId, Device, DeviceInfo, DmFlags, DmName, DmOptions, DmUuid, DM},
    result::{DmError, DmResult, ErrorEnum},
    units::Sectors,
};

fn err_func(err_msg: &str) -> DmError {
    DmError::Dm(ErrorEnum::Invalid, err_msg.into())
}

/// Number of bytes in Struct_dm_target_spec::target_type field.
const DM_TARGET_TYPE_LEN: usize = 16;

str_id!(TargetType, TargetTypeBuf, DM_TARGET_TYPE_LEN, err_func);

/// The trait for properties of the params string of TargetType
pub trait TargetParams: Clone + fmt::Debug + fmt::Display + Eq + FromStr + PartialEq {
    /// Return the param string only
    fn param_str(&self) -> String;

    /// Return the target type
    fn target_type(&self) -> TargetTypeBuf;
}

/// One line of a device mapper table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetLine<T: TargetParams> {
    /// The start of the segment
    pub start: Sectors,
    /// The length of the segment
    pub length: Sectors,
    /// The target specific parameters
    pub params: T,
}

impl<T: TargetParams> TargetLine<T> {
    /// Make a new TargetLine struct
    pub fn new(start: Sectors, length: Sectors, params: T) -> TargetLine<T> {
        TargetLine {
            start,
            length,
            params,
        }
    }
}

/// Manages a target's table
pub trait TargetTable: Clone + fmt::Debug + fmt::Display + Eq + PartialEq + Sized {
    /// Constructs a table from a raw table returned by DM::table_status()
    fn from_raw_table(table: &[(u64, u64, String, String)]) -> DmResult<Self>;

    /// Generates a table that can be loaded by DM::table_load()
    fn to_raw_table(&self) -> Vec<(u64, u64, String, String)>;
}

/// A trait capturing some shared properties of DM devices.
pub trait DmDevice<T: TargetTable> {
    /// The device.
    fn device(&self) -> Device;

    /// The device's device node.
    fn devnode(&self) -> PathBuf;

    /// Check if tables indicate an equivalent device.
    fn equivalent_tables(left: &T, right: &T) -> DmResult<bool>;

    /// Read the devicemapper table
    fn read_kernel_table(dm: &DM, id: &DevId<'_>) -> DmResult<T> {
        let (_, table) =
            dm.table_status(id, DmOptions::default().set_flags(DmFlags::DM_STATUS_TABLE))?;
        T::from_raw_table(&table)
    }

    /// The device's name.
    fn name(&self) -> &DmName;

    /// Resume I/O on the device.
    fn resume(&mut self, dm: &DM) -> DmResult<()> {
        dm.device_suspend(&DevId::Name(self.name()), DmOptions::private())?;
        Ok(())
    }

    /// The number of sectors available for user data.
    fn size(&self) -> Sectors;

    /// Suspend I/O on the device.
    fn suspend(&mut self, dm: &DM, options: DmOptions) -> DmResult<()> {
        dm.device_suspend(
            &DevId::Name(self.name()),
            DmOptions::default()
                .set_flags(DmFlags::DM_SUSPEND | options.flags())
                .set_udev_flags(options.udev_flags()),
        )?;
        Ok(())
    }

    /// What the device thinks its table is.
    fn table(&self) -> &T;

    /// Load a table
    fn table_load(&self, dm: &DM, table: &T, options: DmOptions) -> DmResult<()> {
        dm.table_load(&DevId::Name(self.name()), &table.to_raw_table(), options)?;
        Ok(())
    }

    /// Erase the kernel's memory of this device.
    fn teardown(&mut self, dm: &DM) -> DmResult<()>;

    /// The device's UUID, if available.
    /// Note that the UUID is not any standard UUID format.
    fn uuid(&self) -> Option<&DmUuid>;
}

/// Send a message that expects no reply to target device.
pub fn message<T: TargetTable, D: DmDevice<T>>(dm: &DM, target: &D, msg: &str) -> DmResult<()> {
    dm.target_msg(&DevId::Name(target.name()), None, msg)?;
    Ok(())
}

/// Create a device, load a table, and resume it allowing the caller to specify the DmOptions for
/// resuming.
pub fn device_create<T: TargetTable>(
    dm: &DM,
    name: &DmName,
    uuid: Option<&DmUuid>,
    table: &T,
    suspend_options: DmOptions,
) -> DmResult<DeviceInfo> {
    dm.device_create(name, uuid, DmOptions::default())?;

    let id = DevId::Name(name);
    let dev_info = match dm.table_load(&id, &table.to_raw_table(), DmOptions::default()) {
        Err(e) => {
            dm.device_remove(&id, DmOptions::default())?;
            return Err(e);
        }
        Ok(dev_info) => dev_info,
    };
    dm.device_suspend(&id, suspend_options)?;

    Ok(dev_info)
}

/// Verify that kernel data matches arguments passed.
pub fn device_match<T: TargetTable, D: DmDevice<T>>(
    dm: &DM,
    dev: &D,
    uuid: Option<&DmUuid>,
) -> DmResult<()> {
    let kernel_table = D::read_kernel_table(dm, &DevId::Name(dev.name()))?;
    let device_table = dev.table();
    if !D::equivalent_tables(&kernel_table, device_table)? {
        let err_msg = format!(
            "Specified new table \"{device_table:?}\" does not match kernel table \"{kernel_table:?}\""
        );

        return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
    }

    if dev.uuid() != uuid {
        let err_msg = format!(
            "Specified uuid \"{:?}\" does not match kernel uuuid \"{:?}\"",
            uuid,
            dev.uuid()
        );

        return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
    }
    Ok(())
}

/// Check if a device of the given name exists.
pub fn device_exists(dm: &DM, name: &DmName) -> DmResult<bool> {
    dm.list_devices()
        .map(|l| l.iter().any(|(n, _, _)| &**n == name))
}

/// Parse a device from either of a path or a maj:min pair
pub fn parse_device(val: &str, desc: &str) -> DmResult<Device> {
    let device = if val.starts_with('/') {
        devnode_to_devno(Path::new(val))?
            .ok_or_else(|| {
                DmError::Dm(
                    ErrorEnum::Invalid,
                    format!("Failed to parse \"{desc}\" from input \"{val}\""),
                )
            })?
            .into()
    } else {
        val.parse::<Device>()?
    };
    Ok(device)
}

/// Parse a value or return an error.
pub fn parse_value<T>(val: &str, desc: &str) -> DmResult<T>
where
    T: FromStr,
{
    val.parse::<T>().map_err(|_| {
        DmError::Dm(
            ErrorEnum::Invalid,
            format!("Failed to parse value for \"{desc}\" from input \"{val}\""),
        )
    })
}

/// Get fields for a single status line.
/// Return an error if an insufficient number of fields are obtained.
pub fn get_status_line_fields(status_line: &str, number_required: usize) -> DmResult<Vec<&str>> {
    let status_vals = status_line.split(' ').collect::<Vec<_>>();
    let length = status_vals.len();
    if length < number_required {
        return Err(DmError::Dm(
            ErrorEnum::Invalid,
            format!(
                "Insufficient number of fields for status; requires at least {number_required}, found only {length} in status line \"{status_line}\""
            ),
        ));
    }
    Ok(status_vals)
}

/// Get unique status element from a status result.
/// Return an error if an incorrect number of lines is obtained.
pub fn get_status(status_lines: &[(u64, u64, String, String)]) -> DmResult<String> {
    let length = status_lines.len();
    if length != 1 {
        return Err(DmError::Dm(
            ErrorEnum::Invalid,
            format!(
                "Incorrect number of lines for status; expected 1, found {} in status result \"{}\"",
                length,
                status_lines.iter().map(|(s, l, t, v)| format!("{s} {l} {t} {v}")).collect::<Vec<String>>().join(", ")
            ),
        ));
    }
    Ok(status_lines
        .first()
        .expect("if length != 1, already returned")
        .3
        .to_owned())
}

/// Construct an error when parsing yields an unexpected value.
/// Indicate the location of the unexpected value, 1-indexed, its actual
/// value, and the name of the expected thing.
pub fn make_unexpected_value_error(value_index: usize, value: &str, item_name: &str) -> DmError {
    DmError::Dm(
        ErrorEnum::Invalid,
        format!(
            "Kernel returned unexpected {value_index}th value \"{value}\" for item representing {item_name} in status result"
        ),
    )
}
