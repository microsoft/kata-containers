// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{collections::hash_set::HashSet, fmt, path::PathBuf, str::FromStr};

use crate::{
    core::{DevId, Device, DeviceInfo, DmFlags, DmName, DmOptions, DmUuid, DM},
    lineardev::{LinearDev, LinearDevTargetParams},
    result::{DmError, DmResult, ErrorEnum},
    shared::{
        device_create, device_exists, device_match, get_status, get_status_line_fields,
        make_unexpected_value_error, parse_device, parse_value, DmDevice, TargetLine, TargetParams,
        TargetTable, TargetTypeBuf,
    },
    units::{DataBlocks, MetaBlocks, Sectors},
};

#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use crate::core::devnode_to_devno;

const THINPOOL_TARGET_NAME: &str = "thin-pool";

/// Struct representing params for a thin pool target
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThinPoolTargetParams {
    /// Thin pool metadata device
    pub metadata_dev: Device,
    /// Thin pool data device
    pub data_dev: Device,
    /// Block size for allocations within the thin pool
    pub data_block_size: Sectors,
    /// Amount of free space left at which to trigger the low water mark
    pub low_water_mark: DataBlocks,
    /// Feature arguments
    pub feature_args: HashSet<String>,
}

impl ThinPoolTargetParams {
    /// Create a new ThinPoolTargetParams struct
    pub fn new(
        metadata_dev: Device,
        data_dev: Device,
        data_block_size: Sectors,
        low_water_mark: DataBlocks,
        feature_args: Vec<String>,
    ) -> ThinPoolTargetParams {
        ThinPoolTargetParams {
            metadata_dev,
            data_dev,
            data_block_size,
            low_water_mark,
            feature_args: feature_args.into_iter().collect::<HashSet<_>>(),
        }
    }
}

impl fmt::Display for ThinPoolTargetParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", THINPOOL_TARGET_NAME, self.param_str())
    }
}

impl FromStr for ThinPoolTargetParams {
    type Err = DmError;

    fn from_str(s: &str) -> DmResult<ThinPoolTargetParams> {
        let vals = s.split(' ').collect::<Vec<_>>();

        if vals.len() < 5 {
            let err_msg = format!(
                "expected at least 5 values in params string \"{}\", found {}",
                s,
                vals.len()
            );
            return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
        }

        if vals[0] != THINPOOL_TARGET_NAME {
            let err_msg = format!(
                "Expected a thin-pool target entry but found target type {}",
                vals[0]
            );
            return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
        }

        let metadata_dev = parse_device(vals[1], "metadata device for thinpool target")?;
        let data_dev = parse_device(vals[2], "data device for thinpool target")?;

        let data_block_size = Sectors(parse_value(vals[3], "data block size")?);
        let low_water_mark = DataBlocks(parse_value(vals[4], "low water mark")?);

        let feature_args = if vals.len() == 5 {
            vec![]
        } else {
            vals[6..6 + parse_value::<usize>(vals[5], "number of feature args")?]
                .iter()
                .map(|x| (*x).to_string())
                .collect()
        };

        Ok(ThinPoolTargetParams::new(
            metadata_dev,
            data_dev,
            data_block_size,
            low_water_mark,
            feature_args,
        ))
    }
}

impl TargetParams for ThinPoolTargetParams {
    fn param_str(&self) -> String {
        let feature_args = if self.feature_args.is_empty() {
            "0".to_owned()
        } else {
            format!(
                "{} {}",
                self.feature_args.len(),
                self.feature_args
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };

        format!(
            "{} {} {} {} {}",
            self.metadata_dev,
            self.data_dev,
            *self.data_block_size,
            *self.low_water_mark,
            feature_args
        )
    }

    fn target_type(&self) -> TargetTypeBuf {
        TargetTypeBuf::new(THINPOOL_TARGET_NAME.into()).expect("THINPOOL_TARGET_NAME is valid")
    }
}

/// A target table for a thin pool device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThinPoolDevTargetTable {
    /// The device's table
    pub table: TargetLine<ThinPoolTargetParams>,
}

impl ThinPoolDevTargetTable {
    /// Make a new ThinPoolDevTargetTable from a suitable vec
    pub fn new(
        start: Sectors,
        length: Sectors,
        params: ThinPoolTargetParams,
    ) -> ThinPoolDevTargetTable {
        ThinPoolDevTargetTable {
            table: TargetLine::new(start, length, params),
        }
    }
}

impl fmt::Display for ThinPoolDevTargetTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let table = &self.table;
        writeln!(f, "{} {} {}", *table.start, *table.length, table.params)
    }
}

impl TargetTable for ThinPoolDevTargetTable {
    fn from_raw_table(table: &[(u64, u64, String, String)]) -> DmResult<ThinPoolDevTargetTable> {
        if table.len() != 1 {
            let err_msg = format!(
                "ThinPoolDev table should have exactly one line, has {} lines",
                table.len()
            );
            return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
        }
        let line = table.first().expect("table.len() == 1");
        Ok(ThinPoolDevTargetTable::new(
            Sectors(line.0),
            Sectors(line.1),
            format!("{} {}", line.2, line.3).parse::<ThinPoolTargetParams>()?,
        ))
    }

    fn to_raw_table(&self) -> Vec<(u64, u64, String, String)> {
        to_raw_table_unique!(self)
    }
}

/// DM construct to contain thin provisioned devices
#[derive(Debug)]
pub struct ThinPoolDev {
    dev_info: Box<DeviceInfo>,
    meta_dev: LinearDev,
    data_dev: LinearDev,
    table: ThinPoolDevTargetTable,
}

impl DmDevice<ThinPoolDevTargetTable> for ThinPoolDev {
    fn device(&self) -> Device {
        device!(self)
    }

    fn devnode(&self) -> PathBuf {
        devnode!(self)
    }

    // This method is incomplete. It is expected that it will be refined so
    // that it will return true in more cases, i.e., to be less stringent.
    // In particular, two devices are equivalent even if their low water
    // marks are different.
    fn equivalent_tables(
        left: &ThinPoolDevTargetTable,
        right: &ThinPoolDevTargetTable,
    ) -> DmResult<bool> {
        let left = &left.table;
        let right = &right.table;

        Ok(left.start == right.start
            && left.length == right.length
            && left.params.metadata_dev == right.params.metadata_dev
            && left.params.data_dev == right.params.data_dev
            && left.params.data_block_size == right.params.data_block_size)
    }

    fn name(&self) -> &DmName {
        name!(self)
    }

    fn size(&self) -> Sectors {
        self.data_dev.size()
    }

    fn table(&self) -> &ThinPoolDevTargetTable {
        table!(self)
    }

    fn teardown(&mut self, dm: &DM) -> DmResult<()> {
        dm.device_remove(&DevId::Name(self.name()), DmOptions::default())?;
        self.data_dev.teardown(dm)?;
        self.meta_dev.teardown(dm)?;
        Ok(())
    }

    fn uuid(&self) -> Option<&DmUuid> {
        uuid!(self)
    }
}

#[derive(Debug, Clone)]
/// Contains values indicating the thinpool's used vs total
/// allocations for metadata and data blocks.
pub struct ThinPoolUsage {
    /// The number of metadata blocks that are in use.
    pub used_meta: MetaBlocks,
    /// The total number of metadata blocks available to the thinpool.
    pub total_meta: MetaBlocks,
    /// The number of data blocks that are in use.
    pub used_data: DataBlocks,
    /// The total number of data blocks available to the thinpool.
    pub total_data: DataBlocks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Indicates if a working thinpool is working optimally, or is
/// experiencing a non-fatal error condition.
pub enum ThinPoolStatusSummary {
    /// The pool is working normally.
    Good,
    /// The pool has been forced to transition to read-only mode.
    ReadOnly,
    /// The pool is out of space.
    OutOfSpace,
}

/// Policy if no space on device
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThinPoolNoSpacePolicy {
    /// error the IO if no space on device
    Error,
    /// queue the IO if no space on device
    Queue,
}

/// Status of a working thin pool, i.e, one that does not have status Fail
#[derive(Debug, Clone)]
pub struct ThinPoolWorkingStatus {
    /// The transaction id.
    pub transaction_id: u64,
    /// A struct recording block usage for meta and data devices.
    pub usage: ThinPoolUsage,
    /// A single block value indicating the held metadata root
    pub held_metadata_root: Option<MetaBlocks>,
    /// discard_passdown/no_discard_passdown
    pub discard_passdown: bool,
    /// no space policy
    pub no_space_policy: ThinPoolNoSpacePolicy,
    /// A summary of some other status information.
    pub summary: ThinPoolStatusSummary,
    /// needs_check flag has been set in metadata superblock
    pub needs_check: bool,
    /// The lowater value for the metadata device in metablocks. This value
    /// is set by the kernel. Available in kernel version 4.19 and later.
    pub meta_low_water: Option<u64>,
}

impl ThinPoolWorkingStatus {
    /// Make a new ThinPoolWorkingStatus struct
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: u64,
        usage: ThinPoolUsage,
        held_metadata_root: Option<MetaBlocks>,
        discard_passdown: bool,
        no_space_policy: ThinPoolNoSpacePolicy,
        summary: ThinPoolStatusSummary,
        needs_check: bool,
        meta_low_water: Option<u64>,
    ) -> ThinPoolWorkingStatus {
        ThinPoolWorkingStatus {
            transaction_id,
            usage,
            held_metadata_root,
            discard_passdown,
            no_space_policy,
            summary,
            needs_check,
            meta_low_water,
        }
    }
}

#[derive(Debug, Clone)]
/// Top-level thinpool status that indicates if it is working or failed.
pub enum ThinPoolStatus {
    /// The thinpool has not failed utterly.
    Working(Box<ThinPoolWorkingStatus>),
    /// Devicemapper has reported that it could not obtain the status
    Error,
    /// The thinpool is in a failed condition.
    Fail,
}

impl FromStr for ThinPoolStatus {
    type Err = DmError;

    fn from_str(status_line: &str) -> DmResult<ThinPoolStatus> {
        if status_line.starts_with("Error") {
            return Ok(ThinPoolStatus::Error);
        }

        if status_line.starts_with("Fail") {
            return Ok(ThinPoolStatus::Fail);
        }

        let status_vals = get_status_line_fields(status_line, 8)?;

        let transaction_id = parse_value(status_vals[0], "transaction id")?;

        let usage = {
            let meta_vals = status_vals[1].split('/').collect::<Vec<_>>();
            let data_vals = status_vals[2].split('/').collect::<Vec<_>>();
            ThinPoolUsage {
                used_meta: MetaBlocks(parse_value(meta_vals[0], "used meta")?),
                total_meta: MetaBlocks(parse_value(meta_vals[1], "total meta")?),
                used_data: DataBlocks(parse_value(data_vals[0], "used data")?),
                total_data: DataBlocks(parse_value(data_vals[1], "total data")?),
            }
        };

        let held_metadata_root = match status_vals[3] {
            "-" => None,
            val => Some(MetaBlocks(parse_value(val, "held metadata root")?)),
        };

        let summary = match status_vals[4] {
            "rw" => ThinPoolStatusSummary::Good,
            "ro" => ThinPoolStatusSummary::ReadOnly,
            "out_of_data_space" => ThinPoolStatusSummary::OutOfSpace,
            val => {
                return Err(make_unexpected_value_error(5, val, "summary"));
            }
        };

        let discard_passdown = match status_vals[5] {
            "discard_passdown" => true,
            "no_discard_passdown" => false,
            val => {
                return Err(make_unexpected_value_error(6, val, "discard passdown"));
            }
        };

        let no_space_policy = match status_vals[6] {
            "error_if_no_space" => ThinPoolNoSpacePolicy::Error,
            "queue_if_no_space" => ThinPoolNoSpacePolicy::Queue,
            val => {
                return Err(make_unexpected_value_error(7, val, "no space policy"));
            }
        };

        let needs_check = match status_vals[7] {
            "-" => false,
            "needs_check" => true,
            val => {
                return Err(make_unexpected_value_error(8, val, "needs checK"));
            }
        };

        let meta_low_water = status_vals
            .get(8)
            .and_then(|v| parse_value(v, "meta low water").ok());

        Ok(ThinPoolStatus::Working(Box::new(
            ThinPoolWorkingStatus::new(
                transaction_id,
                usage,
                held_metadata_root,
                discard_passdown,
                no_space_policy,
                summary,
                needs_check,
                meta_low_water,
            ),
        )))
    }
}

/// Use DM to create a "thin-pool".  A "thin-pool" is shared space for
/// other thin provisioned devices to use.
///
/// See section ["Setting up a fresh pool device"](https://docs.kernel.org/admin-guide/device-mapper/thin-provisioning.html#setting-up-a-fresh-pool-device)
impl ThinPoolDev {
    /// Construct a new `ThinPoolDev` with the given data and meta devs.
    /// Returns an error if the device is already known to the kernel.
    /// Returns an error if `data_block_size` is not within required range.
    /// Precondition: the metadata device does not contain any pool metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dm: &DM,
        name: &DmName,
        uuid: Option<&DmUuid>,
        meta: LinearDev,
        data: LinearDev,
        data_block_size: Sectors,
        low_water_mark: DataBlocks,
        feature_args: Vec<String>,
    ) -> DmResult<ThinPoolDev> {
        if device_exists(dm, name)? {
            let err_msg = format!("thinpooldev {name} already exists");
            return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
        }

        let table =
            ThinPoolDev::gen_table(&meta, &data, data_block_size, low_water_mark, feature_args);
        let dev_info = device_create(dm, name, uuid, &table, DmOptions::private())?;

        Ok(ThinPoolDev {
            dev_info: Box::new(dev_info),
            meta_dev: meta,
            data_dev: data,
            table,
        })
    }

    /// Obtain the meta device that backs this thin pool device.
    pub fn meta_dev(&self) -> &LinearDev {
        &self.meta_dev
    }

    /// Obtain the data device that backs this thin pool device.
    pub fn data_dev(&self) -> &LinearDev {
        &self.data_dev
    }

    /// Obtain the data block size for this thin pool device.
    pub fn data_block_size(&self) -> Sectors {
        self.table.table.params.data_block_size
    }

    /// Set up a thin pool from the given metadata and data device.
    /// Returns an error if data_block_size is not within required range.
    /// Precondition: There is existing metadata for this thinpool device
    /// on the metadata device. If the metadata is corrupted, subsequent
    /// errors will result, so it is expected that the metadata is
    /// well-formed and consistent with the data on the data device.
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        dm: &DM,
        name: &DmName,
        uuid: Option<&DmUuid>,
        meta: LinearDev,
        data: LinearDev,
        data_block_size: Sectors,
        low_water_mark: DataBlocks,
        feature_args: Vec<String>,
    ) -> DmResult<ThinPoolDev> {
        let table =
            ThinPoolDev::gen_table(&meta, &data, data_block_size, low_water_mark, feature_args);
        let dev = if device_exists(dm, name)? {
            let dev_info = dm.device_info(&DevId::Name(name))?;
            let dev = ThinPoolDev {
                dev_info: Box::new(dev_info),
                meta_dev: meta,
                data_dev: data,
                table,
            };
            device_match(dm, &dev, uuid)?;
            dev
        } else {
            let dev_info = device_create(dm, name, uuid, &table, DmOptions::private())?;
            ThinPoolDev {
                dev_info: Box::new(dev_info),
                meta_dev: meta,
                data_dev: data,
                table,
            }
        };
        Ok(dev)
    }

    /// Generate a table to be passed to DM. The format of the table
    /// entries is:
    /// <start sec (0)> <length> "thin-pool" <thin-pool-specific string>
    /// where the thin-pool-specific string has the format:
    /// <meta maj:min> <data maj:min> <block size> <low water mark>
    /// There is exactly one entry in the table.
    fn gen_table(
        meta: &LinearDev,
        data: &LinearDev,
        data_block_size: Sectors,
        low_water_mark: DataBlocks,
        feature_args: Vec<String>,
    ) -> ThinPoolDevTargetTable {
        ThinPoolDevTargetTable::new(
            Sectors::default(),
            data.size(),
            ThinPoolTargetParams::new(
                meta.device(),
                data.device(),
                data_block_size,
                low_water_mark,
                feature_args,
            ),
        )
    }

    /// Set the low water mark.
    /// This action puts the device in a state where it is ready to be resumed.
    pub fn set_low_water_mark(&mut self, dm: &DM, low_water_mark: DataBlocks) -> DmResult<()> {
        let mut new_table = self.table.clone();
        new_table.table.params.low_water_mark = low_water_mark;

        self.suspend(dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))?;
        self.table_load(dm, &new_table, DmOptions::default())?;

        self.table = new_table;
        Ok(())
    }

    /// Get the current status of the thinpool.
    /// Returns an error if there was an error getting the status value.
    pub fn status(&self, dm: &DM, options: DmOptions) -> DmResult<ThinPoolStatus> {
        status!(self, dm, options)
    }

    /// Set the table for the existing metadata device.
    /// This action puts the device in a state where it is ready to be resumed.
    /// Warning: It is the client's responsibility to make sure the designated
    /// table is compatible with the device's existing table.
    /// If are not, this function will still succeed, but some kind of
    /// data corruption will be the inevitable result.
    pub fn set_meta_table(
        &mut self,
        dm: &DM,
        table: Vec<TargetLine<LinearDevTargetParams>>,
    ) -> DmResult<()> {
        self.suspend(dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))?;
        self.meta_dev.set_table(dm, table)?;
        self.meta_dev.resume(dm)?;

        // Reload the table even though it is unchanged.
        // See comment on CacheDev::set_cache_table for reason.
        self.table_load(dm, self.table(), DmOptions::default())?;

        Ok(())
    }

    /// Set the data device's existing table.
    /// This action puts the device in a state where it is ready to be resumed.
    /// Warning: It is the client's responsibility to make sure the designated
    /// table is compatible with the device's existing table.
    /// If not, this function will still succeed, but some kind of
    /// data corruption will be the inevitable result.
    pub fn set_data_table(
        &mut self,
        dm: &DM,
        table: Vec<TargetLine<LinearDevTargetParams>>,
    ) -> DmResult<()> {
        self.suspend(dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))?;

        self.data_dev.set_table(dm, table)?;
        self.data_dev.resume(dm)?;

        let mut table = self.table.clone();
        table.table.length = self.data_dev.size();
        self.table_load(dm, &table, DmOptions::default())?;

        self.table = table;

        Ok(())
    }

    fn set_feature_arg(&mut self, feature_arg: &str, dm: &DM) -> DmResult<()> {
        let mut table = self.table().clone();
        if !table.table.params.feature_args.contains(feature_arg) {
            table
                .table
                .params
                .feature_args
                .insert(feature_arg.to_string());

            self.suspend(dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))?;
            self.table_load(dm, &table, DmOptions::default())?;
            self.table = table;

            self.resume(dm)?;
        }

        Ok(())
    }

    fn unset_feature_arg(&mut self, feature_arg: &str, dm: &DM) -> DmResult<()> {
        let mut table = self.table().clone();
        if table.table.params.feature_args.contains(feature_arg) {
            table.table.params.feature_args.remove(feature_arg);

            self.suspend(dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))?;
            self.table_load(dm, &table, DmOptions::default())?;
            self.table = table;

            self.resume(dm)?;
        }

        Ok(())
    }

    /// Default behavior for devicemapper thin pools is to queue requests if
    /// the thin pool is out of space to allow time for the thin pool to extend.
    /// This behavior can be changed by adding the feature argument
    /// `error_if_no_space` to the devicemapper table.
    ///
    /// This method will add `error_if_no_space` from the devicemapper table
    /// if it is not present.
    pub fn error_if_no_space(&mut self, dm: &DM) -> DmResult<()> {
        self.set_feature_arg("error_if_no_space", dm)
    }

    /// Default behavior for devicemapper thin pools is to queue requests if
    /// the thin pool is out of space to allow time for the thin pool to extend.
    /// This behavior can be changed by adding the feature argument
    /// `error_if_no_space` to the devicemapper table.
    ///
    /// This method will remove `error_if_no_space` from the devicemapper table
    /// if it is present.
    pub fn queue_if_no_space(&mut self, dm: &DM) -> DmResult<()> {
        self.unset_feature_arg("error_if_no_space", dm)
    }

    /// Default behavior for devicemapper thin pools is to zero newly allocated
    /// data blocks. This behavior can be changed by adding the feature argument
    /// `skip_block_zeroing` to the devicemapper table.
    ///
    /// This method will add `skip_block_zeroing` from the devicemapper table
    /// if it is not present.
    pub fn skip_block_zeroing(&mut self, dm: &DM) -> DmResult<()> {
        self.set_feature_arg("skip_block_zeroing", dm)
    }

    /// Default behavior for devicemapper thin pools is to zero newly allocated
    /// data blocks. This behavior can be changed by adding the feature argument
    /// `skip_block_zeroing` to the devicemapper table.
    ///
    /// This method will remove `skip_block_zeroing` from the devicemapper table
    /// if it is present.
    pub fn require_block_zeroing(&mut self, dm: &DM) -> DmResult<()> {
        self.unset_feature_arg("skip_block_zeroing", dm)
    }

    /// Default behavior for devicemapper thin pools is to pass down discards.
    /// This behavior can be changed by adding the feature argument
    /// `no_discard_passdown` to the devicemapper table.
    ///
    /// This method will add `no_discard_passdown` to the devicemapper table
    /// if it is not present.
    pub fn no_discard_passdown(&mut self, dm: &DM) -> DmResult<()> {
        self.set_feature_arg("no_discard_passdown", dm)
    }

    /// Default behavior for devicemapper thin pools is to pass down discards.
    /// This behavior can be changed by adding the feature argument
    /// `no_discard_passdown` to the devicemapper table.
    ///
    /// This method will remove `no_discard_passdown` from the devicemapper
    /// table if it is present.
    pub fn discard_passdown(&mut self, dm: &DM) -> DmResult<()> {
        self.unset_feature_arg("no_discard_passdown", dm)
    }
}

#[cfg(test)]
use std::fs::OpenOptions;

#[cfg(test)]
use crate::{
    consts::IEC,
    lineardev::LinearTargetParams,
    testing::{blkdev_size, test_name},
};

/// Values are explicitly stated in the device-mapper kernel documentation.
#[cfg(test)]
const MIN_DATA_BLOCK_SIZE: Sectors = Sectors(128); // 64 KiB
#[cfg(test)]
#[allow(dead_code)]
const MAX_DATA_BLOCK_SIZE: Sectors = Sectors(2 * IEC::Mi); // 1 GiB
#[cfg(test)]
const MIN_RECOMMENDED_METADATA_SIZE: Sectors = Sectors(4 * IEC::Ki); // 2 MiB
#[cfg(test)]
#[allow(dead_code)]
// Note that this value is stated in the kernel docs to be 16 GiB, but the
// devicemapper source gives a different value for THIN_METADATA_MAX_SECTORS,
// which is the actual maximum size.
const MAX_METADATA_SIZE: MetaBlocks = MetaBlocks(255 * ((1 << 14) - 64));

#[cfg(test)]
/// Generate a minimal thinpool dev. Use all the space available not consumed
/// by the metadata device for the data device.
pub fn minimal_thinpool(dm: &DM, path: &Path) -> ThinPoolDev {
    let dev_size = blkdev_size(&OpenOptions::new().read(true).open(path).unwrap()).sectors();
    let dev = Device::from(devnode_to_devno(path).unwrap().unwrap());
    let meta_params = LinearTargetParams::new(dev, Sectors(0));
    let meta_table = vec![TargetLine::new(
        Sectors(0),
        MIN_RECOMMENDED_METADATA_SIZE,
        LinearDevTargetParams::Linear(meta_params),
    )];
    let meta = LinearDev::setup(
        dm,
        &test_name("meta").expect("valid format"),
        None,
        meta_table,
    )
    .unwrap();

    let data_params = LinearTargetParams::new(dev, MIN_RECOMMENDED_METADATA_SIZE);
    let data_table = vec![TargetLine::new(
        Sectors(0),
        dev_size - MIN_RECOMMENDED_METADATA_SIZE,
        LinearDevTargetParams::Linear(data_params),
    )];
    let data = LinearDev::setup(
        dm,
        &test_name("data").expect("valid format"),
        None,
        data_table,
    )
    .unwrap();

    ThinPoolDev::new(
        dm,
        &test_name("pool").expect("valid format"),
        None,
        meta,
        data,
        MIN_DATA_BLOCK_SIZE,
        DataBlocks(1),
        vec![
            "no_discard_passdown".to_owned(),
            "skip_block_zeroing".to_owned(),
        ],
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{
        core::{errors::Error, DmFlags},
        testing::{test_name, test_with_spec},
    };

    use super::*;

    /// Verify success when constructing a new ThinPoolDev with minimum values
    /// for data block size and metadata device. Check that the status of the
    /// device is as expected.
    fn test_minimum_values(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let mut tp = minimal_thinpool(&dm, paths[0]);
        match tp.status(&dm, DmOptions::default()).unwrap() {
            ThinPoolStatus::Working(ref status)
                if status.summary == ThinPoolStatusSummary::Good =>
            {
                assert!(!status.discard_passdown);
                assert_eq!(status.held_metadata_root, None);

                let usage = &status.usage;
                // Even an empty thinpool requires some metadata.
                assert!(usage.used_meta > MetaBlocks(0));
                assert_eq!(usage.total_meta, tp.meta_dev().size().metablocks());
                assert_eq!(usage.used_data, DataBlocks(0));
                assert_eq!(
                    usage.total_data,
                    DataBlocks(tp.data_dev().size() / tp.data_block_size())
                );
            }
            status => panic!("unexpected thinpool status: {status:?}"),
        }

        let table = ThinPoolDev::read_kernel_table(&dm, &DevId::Name(tp.name()))
            .unwrap()
            .table;
        let params = &table.params;
        assert_eq!(params.metadata_dev, tp.meta_dev().device());
        assert_eq!(params.data_dev, tp.data_dev().device());

        tp.teardown(&dm).unwrap();
    }

    #[test]
    fn loop_test_basic() {
        test_with_spec(1, test_minimum_values);
    }

    /// Verify that data block size less than minimum results in a failure.
    fn test_low_data_block_size(paths: &[&Path]) {
        assert!(!paths.is_empty());
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());

        let dm = DM::new().unwrap();

        let meta_name = test_name("meta").expect("valid format");
        let meta_params = LinearTargetParams::new(dev, Sectors(0));
        let meta_table = vec![TargetLine::new(
            Sectors(0),
            MIN_RECOMMENDED_METADATA_SIZE,
            LinearDevTargetParams::Linear(meta_params),
        )];
        let meta = LinearDev::setup(&dm, &meta_name, None, meta_table).unwrap();

        let data_name = test_name("data").expect("valid format");
        let data_params = LinearTargetParams::new(dev, MIN_RECOMMENDED_METADATA_SIZE);
        let data_table = vec![TargetLine::new(
            Sectors(0),
            512u64 * MIN_DATA_BLOCK_SIZE,
            LinearDevTargetParams::Linear(data_params),
        )];
        let data = LinearDev::setup(&dm, &data_name, None, data_table).unwrap();

        assert_matches!(
            ThinPoolDev::new(
                &dm,
                &test_name("pool").expect("valid format"),
                None,
                meta,
                data,
                MIN_DATA_BLOCK_SIZE / 2u64,
                DataBlocks(1),
                vec![
                    "no_discard_passdown".to_owned(),
                    "skip_block_zeroing".to_owned()
                ],
            ),
            Err(DmError::Core(Error::Ioctl(_, _, _, _)))
        );
        dm.device_remove(&DevId::Name(&meta_name), DmOptions::default())
            .unwrap();
        dm.device_remove(&DevId::Name(&data_name), DmOptions::default())
            .unwrap();
    }

    #[test]
    fn loop_test_low_data_block_size() {
        test_with_spec(1, test_low_data_block_size);
    }

    /// Verify that setting the data table does not fail and results in
    /// the correct size data device.
    fn test_set_data(paths: &[&Path]) {
        assert!(paths.len() > 1);

        let dm = DM::new().unwrap();
        let mut tp = minimal_thinpool(&dm, paths[0]);

        let mut data_table = tp.data_dev.table().table.clone();
        let data_size = tp.data_dev.size();

        let dev2 = Device::from(devnode_to_devno(paths[1]).unwrap().unwrap());
        let data_params = LinearTargetParams::new(dev2, Sectors(0));
        data_table.push(TargetLine::new(
            data_size,
            data_size,
            LinearDevTargetParams::Linear(data_params),
        ));
        tp.set_data_table(&dm, data_table).unwrap();
        tp.resume(&dm).unwrap();

        match tp.status(&dm, DmOptions::default()).unwrap() {
            ThinPoolStatus::Working(ref status) => {
                let usage = &status.usage;
                assert_eq!(
                    *usage.total_data * tp.table().table.params.data_block_size,
                    2u8 * data_size
                );
            }
            ThinPoolStatus::Error => panic!("devicemapper could not obtain thin pool status"),
            ThinPoolStatus::Fail => panic!("thin pool should not have failed"),
        }

        tp.teardown(&dm).unwrap();
    }

    #[test]
    fn loop_test_set_data() {
        test_with_spec(2, test_set_data);
    }

    /// Verify that setting the meta table does not fail and results in
    /// the correct size meta device.
    fn test_set_meta(paths: &[&Path]) {
        assert!(paths.len() > 1);

        let dm = DM::new().unwrap();
        let mut tp = minimal_thinpool(&dm, paths[0]);

        let mut meta_table = tp.meta_dev.table().table.clone();
        let meta_size = tp.meta_dev.size();

        let dev2 = Device::from(devnode_to_devno(paths[1]).unwrap().unwrap());
        let meta_params = LinearTargetParams::new(dev2, Sectors(0));
        meta_table.push(TargetLine::new(
            meta_size,
            meta_size,
            LinearDevTargetParams::Linear(meta_params),
        ));
        tp.set_meta_table(&dm, meta_table).unwrap();
        tp.resume(&dm).unwrap();

        match tp.status(&dm, DmOptions::default()).unwrap() {
            ThinPoolStatus::Working(ref status) => {
                let usage = &status.usage;
                assert_eq!(usage.total_meta.sectors(), 2u8 * meta_size);
            }
            ThinPoolStatus::Error => panic!("devicemapper could not obtain thin pool status"),
            ThinPoolStatus::Fail => panic!("thin pool should not have failed"),
        }

        tp.teardown(&dm).unwrap();
    }

    #[test]
    fn loop_test_set_meta() {
        test_with_spec(2, test_set_meta);
    }

    /// Just test that suspending and resuming a thinpool has no errors.
    fn test_suspend(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let mut tp = minimal_thinpool(&dm, paths[0]);
        tp.suspend(&dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))
            .unwrap();
        tp.suspend(&dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))
            .unwrap();
        tp.resume(&dm).unwrap();
        tp.resume(&dm).unwrap();
        tp.teardown(&dm).unwrap();
    }

    #[test]
    fn loop_test_suspend() {
        test_with_spec(1, test_suspend);
    }

    fn test_status_noflush(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let tp = minimal_thinpool(&dm, paths[0]);

        tp.status(&dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))
            .unwrap();
    }

    #[test]
    fn loop_test_status_noflush() {
        test_with_spec(1, test_status_noflush);
    }

    #[test]
    fn test_thinpool_target_params_zero() {
        let result = "thin-pool 42:42 42:43 16 2 0"
            .parse::<ThinPoolTargetParams>()
            .unwrap();
        assert_eq!(result.feature_args, HashSet::new());
    }

    #[test]
    fn test_thinpool_target_params_none() {
        let result = "thin-pool 42:42 42:43 16 2"
            .parse::<ThinPoolTargetParams>()
            .unwrap();
        assert_eq!(result.feature_args, HashSet::new());
    }
}
