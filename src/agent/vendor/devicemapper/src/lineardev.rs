// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{collections::HashSet, fmt, path::PathBuf, str::FromStr};

use crate::{
    core::{DevId, Device, DeviceInfo, DmFlags, DmName, DmOptions, DmUuid, DM},
    result::{DmError, DmResult, ErrorEnum},
    shared::{
        device_create, device_exists, device_match, parse_device, parse_value, DmDevice,
        TargetLine, TargetParams, TargetTable, TargetTypeBuf,
    },
    units::Sectors,
};

const FLAKEY_TARGET_NAME: &str = "flakey";
const LINEAR_TARGET_NAME: &str = "linear";

/// Struct representing params for a linear target
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearTargetParams {
    /// Device on which this segment resides.
    pub device: Device,
    /// Start offset in device on which this segment resides.
    pub start_offset: Sectors,
}

impl LinearTargetParams {
    /// Create a new LinearTargetParams struct
    pub fn new(device: Device, start_offset: Sectors) -> LinearTargetParams {
        LinearTargetParams {
            device,
            start_offset,
        }
    }
}

impl fmt::Display for LinearTargetParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", LINEAR_TARGET_NAME, self.param_str())
    }
}

impl FromStr for LinearTargetParams {
    type Err = DmError;

    fn from_str(s: &str) -> DmResult<LinearTargetParams> {
        let vals = s.split(' ').collect::<Vec<_>>();
        if vals.len() != 3 {
            let err_msg = format!(
                "expected 3 values in params string \"{}\", found {}",
                s,
                vals.len()
            );
            return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
        }

        if vals[0] != LINEAR_TARGET_NAME {
            let err_msg = format!(
                "Expected a linear target entry but found target type {}",
                vals[0]
            );
            return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
        }

        let device = parse_device(vals[1], "block device for linear target")?;
        let start = Sectors(parse_value(vals[2], "physical start offset")?);

        Ok(LinearTargetParams::new(device, start))
    }
}

impl TargetParams for LinearTargetParams {
    fn param_str(&self) -> String {
        format!("{} {}", self.device, *self.start_offset)
    }

    fn target_type(&self) -> TargetTypeBuf {
        TargetTypeBuf::new(LINEAR_TARGET_NAME.into()).expect("LINEAR_TARGET_NAME is valid")
    }
}

#[derive(Debug, Hash, Clone, Eq, PartialEq)]
pub enum Direction {
    Reads,
    Writes,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Reads => write!(f, "r"),
            Direction::Writes => write!(f, "w"),
        }
    }
}

impl FromStr for Direction {
    type Err = DmError;
    fn from_str(s: &str) -> DmResult<Direction> {
        if s == "r" {
            Ok(Direction::Reads)
        } else if s == "w" {
            Ok(Direction::Writes)
        } else {
            let err_msg = format!("Expected r or w, found {s}");
            Err(DmError::Dm(ErrorEnum::Invalid, err_msg))
        }
    }
}

/// Flakey target optional feature parameters:
/// If no feature parameters are present, during the periods of
/// unreliability, all I/O returns errors.
#[derive(Debug, Hash, Clone, Eq, PartialEq)]
pub enum FeatureArg {
    /// drop_writes:
    ///
    /// All write I/O is silently ignored.
    /// Read I/O is handled correctly.
    DropWrites,
    /// error_writes:
    ///
    /// All write I/O is failed with an error signalled.
    /// Read I/O is handled correctly.
    ErrorWrites,
    /// corrupt_bio_byte <Nth_byte> <direction> <value> <flags>:
    ///
    /// During <down interval>, replace <Nth_byte> of the data of
    /// each matching bio with <value>.
    ///
    /// <Nth_byte>: The offset of the byte to replace.
    ///             Counting starts at 1, to replace the first byte.
    /// <direction>: Either 'r' to corrupt reads or 'w' to corrupt writes.
    ///             'w' is incompatible with drop_writes.
    /// <value>:    The value (from 0-255) to write.
    /// <flags>:    Perform the replacement only if bio->bi_opf has all the
    ///             selected flags set.
    CorruptBioByte(u64, Direction, u8, u64),
}

impl fmt::Display for FeatureArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureArg::DropWrites => write!(f, "drop_writes"),
            FeatureArg::ErrorWrites => write!(f, "error_writes"),
            FeatureArg::CorruptBioByte(offset, direction, value, flags) => {
                write!(f, "corrupt_bio_byte {offset} {direction} {value} {flags}")
            }
        }
    }
}

/// Target params for flakey target
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlakeyTargetParams {
    /// The device on which this segment resides
    pub device: Device,
    /// The starting offset of this segments in the device.
    pub start_offset: Sectors,
    /// Interval during which flakey target is up, in seconds
    /// DM source type is unsigned, so restrict to u32.
    pub up_interval: u32,
    /// Interval during which flakey target is down, in seconds
    /// DM source type is unsigned, so restrict to u32.
    pub down_interval: u32,
    /// Optional feature arguments
    pub feature_args: HashSet<FeatureArg>,
}

impl FlakeyTargetParams {
    /// Create a new flakey target param struct.
    pub fn new(
        device: Device,
        start_offset: Sectors,
        up_interval: u32,
        down_interval: u32,
        feature_args: Vec<FeatureArg>,
    ) -> FlakeyTargetParams {
        FlakeyTargetParams {
            device,
            start_offset,
            up_interval,
            down_interval,
            feature_args: feature_args.into_iter().collect::<HashSet<_>>(),
        }
    }
}

impl fmt::Display for FlakeyTargetParams {
    /// Generate params to be passed to DM.  The format of the params is:
    ///
    /// ```plain
    /// <dev path> <offset> <up interval> <down interval> [<num_features> [<feature arguments>]]
    /// ```
    ///
    /// Mandatory parameters:
    ///
    /// * `<dev path>`: Full pathname to the underlying block-device, or a
    ///                "major:minor" device-number.
    /// * `<offset>`: Starting sector within the device.
    /// * `<up interval>`: Number of seconds device is available.
    /// * `<down interval>`: Number of seconds device returns errors.
    ///
    /// Optional feature parameters:
    ///  If no feature parameters are present, during the periods of
    ///  unreliability, all I/O returns errors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", FLAKEY_TARGET_NAME, self.param_str())
    }
}

impl FromStr for FlakeyTargetParams {
    type Err = DmError;

    fn from_str(s: &str) -> DmResult<FlakeyTargetParams> {
        fn parse_feature_args(vals: &[&str]) -> DmResult<Vec<FeatureArg>> {
            let mut vals_iter = vals.iter();
            let mut result: Vec<FeatureArg> = Vec::new();
            while let Some(x) = vals_iter.next() {
                match x {
                    &"drop_writes" => result.push(FeatureArg::DropWrites),
                    &"error_writes" => result.push(FeatureArg::ErrorWrites),
                    &"corrupt_bio_byte" => {
                        let offset = vals_iter
                            .next()
                            .ok_or({
                                let err_msg = "corrupt_bio_byte takes 4 parameters";
                                DmError::Dm(ErrorEnum::Invalid, err_msg.to_string())
                            })
                            .and_then(|s| parse_value::<u64>(s, "offset"))?;

                        let direction = vals_iter
                            .next()
                            .ok_or({
                                let err_msg = "corrupt_bio_byte takes 4 parameters";
                                DmError::Dm(ErrorEnum::Invalid, err_msg.to_string())
                            })
                            .and_then(|s| parse_value::<Direction>(s, "direction"))?;

                        let value = vals_iter
                            .next()
                            .ok_or({
                                let err_msg = "corrupt_bio_byte takes 4 parameters";
                                DmError::Dm(ErrorEnum::Invalid, err_msg.to_string())
                            })
                            .and_then(|s| parse_value::<u8>(s, "value"))?;

                        let flags = vals_iter
                            .next()
                            .ok_or({
                                let err_msg = "corrupt_bio_byte takes 4 parameters";
                                DmError::Dm(ErrorEnum::Invalid, err_msg.to_string())
                            })
                            .and_then(|s| parse_value::<u64>(s, "flags"))?;

                        result.push(FeatureArg::CorruptBioByte(offset, direction, value, flags));
                    }
                    x => {
                        let err_msg = format!("{x} is an unrecognized feature parameter");
                        return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
                    }
                }
            }

            Ok(result)
        }

        let vals = s.split(' ').collect::<Vec<_>>();

        if vals.len() < 5 {
            let err_msg = format!(
                "expected at least five values in params string \"{}\", found {}",
                s,
                vals.len()
            );
            return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
        }

        if vals[0] != FLAKEY_TARGET_NAME {
            let err_msg = format!(
                "Expected a flakey target entry but found target type {}",
                vals[0]
            );
            return Err(DmError::Dm(ErrorEnum::Invalid, err_msg));
        }

        let device = parse_device(vals[1], "block device for flakey target")?;
        let start_offset = Sectors(parse_value(vals[2], "physical start offset")?);

        let up_interval = parse_value(vals[3], "up interval")?;
        let down_interval = parse_value(vals[4], "down interval")?;

        let feature_args = if vals.len() == 5 {
            vec![]
        } else {
            parse_feature_args(
                &vals[6..6 + parse_value::<usize>(vals[5], "number of feature args")?],
            )?
        };

        Ok(FlakeyTargetParams::new(
            device,
            start_offset,
            up_interval,
            down_interval,
            feature_args,
        ))
    }
}

impl TargetParams for FlakeyTargetParams {
    fn param_str(&self) -> String {
        let feature_args = if self.feature_args.is_empty() {
            "0".to_owned()
        } else {
            format!(
                "{} {}",
                self.feature_args.len(),
                self.feature_args
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };

        format!(
            "{} {} {} {} {}",
            self.device, *self.start_offset, self.up_interval, self.down_interval, feature_args
        )
    }

    fn target_type(&self) -> TargetTypeBuf {
        TargetTypeBuf::new(FLAKEY_TARGET_NAME.into()).expect("FLAKEY_TARGET_NAME is valid")
    }
}

/// Target params for linear dev. These are either flakey or linear.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinearDevTargetParams {
    /// A flakey target
    Flakey(FlakeyTargetParams),
    /// A linear target
    Linear(LinearTargetParams),
}

impl fmt::Display for LinearDevTargetParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            LinearDevTargetParams::Flakey(ref flakey) => flakey.fmt(f),
            LinearDevTargetParams::Linear(ref linear) => linear.fmt(f),
        }
    }
}

impl FromStr for LinearDevTargetParams {
    type Err = DmError;

    fn from_str(s: &str) -> DmResult<LinearDevTargetParams> {
        let target_type = Some(s.split_once(' ').map_or(s, |x| x.0)).ok_or_else(|| {
            DmError::Dm(
                ErrorEnum::Invalid,
                format!("target line string \"{s}\" did not contain any values"),
            )
        })?;
        if target_type == FLAKEY_TARGET_NAME {
            Ok(LinearDevTargetParams::Flakey(
                s.parse::<FlakeyTargetParams>()?,
            ))
        } else if target_type == LINEAR_TARGET_NAME {
            Ok(LinearDevTargetParams::Linear(
                s.parse::<LinearTargetParams>()?,
            ))
        } else {
            Err(DmError::Dm(
                ErrorEnum::Invalid,
                format!("unexpected target type \"{target_type}\""),
            ))
        }
    }
}

impl TargetParams for LinearDevTargetParams {
    fn param_str(&self) -> String {
        match *self {
            LinearDevTargetParams::Flakey(ref flakey) => flakey.param_str(),
            LinearDevTargetParams::Linear(ref linear) => linear.param_str(),
        }
    }

    fn target_type(&self) -> TargetTypeBuf {
        match *self {
            LinearDevTargetParams::Flakey(ref flakey) => flakey.target_type(),
            LinearDevTargetParams::Linear(ref linear) => linear.target_type(),
        }
    }
}

/// A target table for a linear device. Such a table allows flakey targets
/// as well as linear targets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinearDevTargetTable {
    /// The device's table
    pub table: Vec<TargetLine<LinearDevTargetParams>>,
}

impl LinearDevTargetTable {
    /// Make a new LinearDevTargetTable from a suitable vec
    pub fn new(table: Vec<TargetLine<LinearDevTargetParams>>) -> LinearDevTargetTable {
        LinearDevTargetTable { table }
    }
}

impl fmt::Display for LinearDevTargetTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in &self.table {
            writeln!(f, "{} {} {}", *line.start, *line.length, line.params)?;
        }
        Ok(())
    }
}

impl TargetTable for LinearDevTargetTable {
    fn from_raw_table(table: &[(u64, u64, String, String)]) -> DmResult<LinearDevTargetTable> {
        Ok(LinearDevTargetTable {
            table: table
                .iter()
                .map(|x| -> DmResult<TargetLine<LinearDevTargetParams>> {
                    Ok(TargetLine::new(
                        Sectors(x.0),
                        Sectors(x.1),
                        format!("{} {}", x.2, x.3).parse::<LinearDevTargetParams>()?,
                    ))
                })
                .collect::<DmResult<Vec<_>>>()?,
        })
    }

    fn to_raw_table(&self) -> Vec<(u64, u64, String, String)> {
        self.table
            .iter()
            .map(|x| {
                (
                    *x.start,
                    *x.length,
                    x.params.target_type().to_string(),
                    x.params.param_str(),
                )
            })
            .collect::<Vec<_>>()
    }
}

/// A DM construct of combined Segments
#[derive(Debug)]
pub struct LinearDev {
    /// Data about the device
    dev_info: Box<DeviceInfo>,
    table: LinearDevTargetTable,
}

impl DmDevice<LinearDevTargetTable> for LinearDev {
    fn device(&self) -> Device {
        device!(self)
    }

    fn devnode(&self) -> PathBuf {
        devnode!(self)
    }

    // Since linear devices have no default or configuration parameters,
    // and the ordering of segments matters, two linear devices represent
    // the same linear device only if their tables match exactly.
    fn equivalent_tables(
        left: &LinearDevTargetTable,
        right: &LinearDevTargetTable,
    ) -> DmResult<bool> {
        Ok(left == right)
    }

    fn name(&self) -> &DmName {
        name!(self)
    }

    fn size(&self) -> Sectors {
        self.table.table.iter().map(|l| l.length).sum()
    }

    fn table(&self) -> &LinearDevTargetTable {
        table!(self)
    }

    fn teardown(&mut self, dm: &DM) -> DmResult<()> {
        dm.device_remove(&DevId::Name(self.name()), DmOptions::default())?;
        Ok(())
    }

    fn uuid(&self) -> Option<&DmUuid> {
        uuid!(self)
    }
}

/// Use DM to concatenate a list of segments together into a
/// linear block device of continuous sectors.
impl LinearDev {
    /// Construct a new block device by concatenating the given segments
    /// into linear space.
    /// If the device is already known to the kernel, just verifies that the
    /// segments argument passed exactly matches the kernel data.
    ///
    /// Warning: If the segments overlap, this method will succeed. However,
    /// the behavior of the linear device in that case should be treated as
    /// undefined.
    ///
    /// Note: A linear device is just a mapping in the kernel from locations
    /// in that device to locations on other devices which are specified by
    /// their device number. There is usually a device node so that data can
    /// be read from and written to the device. Other than that, it really
    /// has no existence. Consequently, there is no conflict in overloading
    /// this method to mean both "make a wholly new device" and "establish
    /// the existence of the requested device". Of course, a linear device
    /// is usually expected to hold data, so it is important to get the
    /// mapping just right.
    pub fn setup(
        dm: &DM,
        name: &DmName,
        uuid: Option<&DmUuid>,
        table: Vec<TargetLine<LinearDevTargetParams>>,
    ) -> DmResult<LinearDev> {
        let table = LinearDevTargetTable::new(table);
        let dev = if device_exists(dm, name)? {
            let dev_info = dm.device_info(&DevId::Name(name))?;
            let dev = LinearDev {
                dev_info: Box::new(dev_info),
                table,
            };
            device_match(dm, &dev, uuid)?;
            dev
        } else {
            let dev_info = device_create(dm, name, uuid, &table, DmOptions::private())?;
            LinearDev {
                dev_info: Box::new(dev_info),
                table,
            }
        };
        Ok(dev)
    }

    /// Set the segments for this linear device.
    /// This action puts the device in a state where it is ready to be resumed.
    /// Warning: It is the client's responsibility to make sure the designated
    /// segments are compatible with the device's existing segments.
    /// If they are not, this function will still succeed, but some kind of
    /// data corruption will be the inevitable result.
    pub fn set_table(
        &mut self,
        dm: &DM,
        table: Vec<TargetLine<LinearDevTargetParams>>,
    ) -> DmResult<()> {
        let table = LinearDevTargetTable::new(table);
        self.suspend(dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))?;
        self.table_load(dm, &table, DmOptions::default())?;
        self.table = table;
        Ok(())
    }

    /// Set the name for this LinearDev.
    pub fn set_name(&mut self, dm: &DM, name: &DmName) -> DmResult<()> {
        if self.name() == name {
            return Ok(());
        }
        dm.device_rename(self.name(), &DevId::Name(name))?;
        self.dev_info = Box::new(dm.device_info(&DevId::Name(name))?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{clone::Clone, fs::OpenOptions, path::Path};

    use crate::{
        core::{devnode_to_devno, Device},
        testing::{blkdev_size, test_name, test_with_spec},
    };

    use super::*;

    /// Verify that a new linear dev with 0 segments fails.
    fn test_empty(_paths: &[&Path]) {
        assert_matches!(
            LinearDev::setup(
                &DM::new().unwrap(),
                &test_name("new").expect("valid format"),
                None,
                vec![],
            ),
            Err(_)
        );
    }

    /// Verify that setting an empty table on an existing DM device fails.
    fn test_empty_table_set(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let name = test_name("name").expect("valid format");
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());
        let params = LinearTargetParams::new(dev, Sectors(0));
        let table = vec![TargetLine::new(
            Sectors(0),
            Sectors(1),
            LinearDevTargetParams::Linear(params),
        )];
        let mut ld = LinearDev::setup(&dm, &name, None, table).unwrap();

        assert_matches!(ld.set_table(&dm, vec![]), Err(_));
        ld.resume(&dm).unwrap();
        ld.teardown(&dm).unwrap();
    }

    /// Verify that id rename succeeds.
    fn test_rename_id(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let name = test_name("name").expect("valid format");
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());
        let params = LinearTargetParams::new(dev, Sectors(0));
        let table = vec![TargetLine::new(
            Sectors(0),
            Sectors(1),
            LinearDevTargetParams::Linear(params),
        )];
        let mut ld = LinearDev::setup(&dm, &name, None, table).unwrap();

        ld.set_name(&dm, &name).unwrap();
        assert_eq!(ld.name(), &*name);

        ld.teardown(&dm).unwrap();
    }

    /// Verify that after a rename, the device has the new name.
    fn test_rename(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let name = test_name("name").expect("valid format");
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());
        let params = LinearTargetParams::new(dev, Sectors(0));
        let table = vec![TargetLine::new(
            Sectors(0),
            Sectors(1),
            LinearDevTargetParams::Linear(params),
        )];
        let mut ld = LinearDev::setup(&dm, &name, None, table).unwrap();

        let new_name = test_name("new_name").expect("valid format");
        ld.set_name(&dm, &new_name).unwrap();
        assert_eq!(ld.name(), &*new_name);

        ld.teardown(&dm).unwrap();
    }

    /// Verify that passing the same segments two times gets two segments.
    /// Verify that the size of the devnode is the size of the sum of the
    /// ranges of the segments. Verify that the table contains entries for both
    /// segments.
    fn test_duplicate_segments(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let name = test_name("name").expect("valid format");
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());
        let params = LinearTargetParams::new(dev, Sectors(0));
        let table = vec![
            TargetLine::new(
                Sectors(0),
                Sectors(1),
                LinearDevTargetParams::Linear(params.clone()),
            ),
            TargetLine::new(
                Sectors(1),
                Sectors(1),
                LinearDevTargetParams::Linear(params),
            ),
        ];
        let range: Sectors = table.iter().map(|s| s.length).sum();
        let count = table.len();
        let mut ld = LinearDev::setup(&dm, &name, None, table).unwrap();

        let table = LinearDev::read_kernel_table(&dm, &DevId::Name(ld.name()))
            .unwrap()
            .table;
        assert_eq!(table.len(), count);
        assert_matches!(table[0].params, LinearDevTargetParams::Linear(ref device) if device.device == dev);
        assert_matches!(table[1].params, LinearDevTargetParams::Linear(ref device) if device.device == dev);

        assert_eq!(
            blkdev_size(&OpenOptions::new().read(true).open(ld.devnode()).unwrap()).sectors(),
            range
        );

        ld.teardown(&dm).unwrap();
    }

    /// Use five segments, each distinct. If parsing works correctly,
    /// default table should match extracted table.
    fn test_several_segments(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let name = test_name("name").expect("valid format");
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());
        let table = (0..5)
            .map(|n| {
                TargetLine::new(
                    Sectors(n),
                    Sectors(1),
                    LinearDevTargetParams::Linear(LinearTargetParams::new(dev, Sectors(n))),
                )
            })
            .collect::<Vec<_>>();
        let mut ld = LinearDev::setup(&dm, &name, None, table.clone()).unwrap();

        let loaded_table = LinearDev::read_kernel_table(&dm, &DevId::Name(ld.name())).unwrap();
        assert!(
            LinearDev::equivalent_tables(&LinearDevTargetTable::new(table), &loaded_table).unwrap()
        );

        ld.teardown(&dm).unwrap();
    }

    /// Verify that constructing a second dev with the same name succeeds
    /// only if it has the same list of segments.
    fn test_same_name(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let name = test_name("name").expect("valid format");
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());
        let params = LinearTargetParams::new(dev, Sectors(0));
        let table = vec![TargetLine::new(
            Sectors(0),
            Sectors(1),
            LinearDevTargetParams::Linear(params),
        )];
        let mut ld = LinearDev::setup(&dm, &name, None, table.clone()).unwrap();
        let params2 = LinearTargetParams::new(dev, Sectors(1));
        let table2 = vec![TargetLine::new(
            Sectors(0),
            Sectors(1),
            LinearDevTargetParams::Linear(params2),
        )];
        assert_matches!(LinearDev::setup(&dm, &name, None, table2), Err(_));
        assert_matches!(LinearDev::setup(&dm, &name, None, table), Ok(_));
        ld.teardown(&dm).unwrap();
    }

    /// Verify constructing a second linear dev with the same segment succeeds.
    fn test_same_segment(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let name = test_name("name").expect("valid format");
        let ersatz = test_name("ersatz").expect("valid format");
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());
        let params = LinearTargetParams::new(dev, Sectors(0));
        let table = vec![TargetLine::new(
            Sectors(0),
            Sectors(1),
            LinearDevTargetParams::Linear(params),
        )];
        let mut ld = LinearDev::setup(&dm, &name, None, table.clone()).unwrap();
        let ld2 = LinearDev::setup(&dm, &ersatz, None, table);
        assert_matches!(ld2, Ok(_));

        ld2.unwrap().teardown(&dm).unwrap();
        ld.teardown(&dm).unwrap();
    }

    /// Verify that suspending and immediately resuming doesn't fail.
    fn test_suspend(paths: &[&Path]) {
        assert!(!paths.is_empty());

        let dm = DM::new().unwrap();
        let name = test_name("name").expect("valid format");
        let dev = Device::from(devnode_to_devno(paths[0]).unwrap().unwrap());
        let params = LinearTargetParams::new(dev, Sectors(0));
        let table = vec![TargetLine::new(
            Sectors(0),
            Sectors(1),
            LinearDevTargetParams::Linear(params),
        )];
        let mut ld = LinearDev::setup(&dm, &name, None, table).unwrap();

        ld.suspend(&dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))
            .unwrap();
        ld.suspend(&dm, DmOptions::default().set_flags(DmFlags::DM_NOFLUSH))
            .unwrap();
        ld.resume(&dm).unwrap();
        ld.resume(&dm).unwrap();

        ld.teardown(&dm).unwrap();
    }

    #[test]
    fn test_flakey_target_params_zero() {
        let result = "flakey 8:32 0 16 2 0"
            .parse::<FlakeyTargetParams>()
            .unwrap();
        assert_eq!(result.feature_args, HashSet::new());
    }

    #[test]
    fn test_flakey_target_params_none() {
        let result = "flakey 8:32 0 16 2".parse::<FlakeyTargetParams>().unwrap();
        assert_eq!(result.feature_args, HashSet::new());
    }

    #[test]
    fn test_flakey_target_params_drop_writes() {
        let result = "flakey 8:32 0 16 2 1 drop_writes"
            .parse::<FlakeyTargetParams>()
            .unwrap();
        let expected = [FeatureArg::DropWrites]
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(result.feature_args, expected);
    }

    #[test]
    fn test_flakey_target_params_error_writes() {
        let result = "flakey 8:32 0 16 2 1 error_writes"
            .parse::<FlakeyTargetParams>()
            .unwrap();
        let expected = [FeatureArg::ErrorWrites]
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(result.feature_args, expected);
    }

    #[test]
    fn test_flakey_target_params_corrupt_bio_byte_reads() {
        let result = "flakey 8:32 0 16 2 5 corrupt_bio_byte 32 r 1 0"
            .parse::<FlakeyTargetParams>()
            .unwrap();
        let expected = [FeatureArg::CorruptBioByte(32, Direction::Reads, 1, 0)]
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(result.feature_args, expected);
    }

    #[test]
    fn test_flakey_target_params_corrupt_bio_byte_writes() {
        let result = "flakey 8:32 0 16 2 5 corrupt_bio_byte 224 w 0 32"
            .parse::<FlakeyTargetParams>()
            .unwrap();
        let expected = [FeatureArg::CorruptBioByte(224, Direction::Writes, 0, 32)]
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(result.feature_args, expected);
    }

    #[test]
    fn test_flakey_target_params_corrupt_bio_byte_and_drop_writes() {
        let result = "flakey 8:32 0 16 2 6 corrupt_bio_byte 32 r 1 0 drop_writes"
            .parse::<FlakeyTargetParams>()
            .unwrap();
        let expected = [
            FeatureArg::CorruptBioByte(32, Direction::Reads, 1, 0),
            FeatureArg::DropWrites,
        ]
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
        assert_eq!(result.feature_args, expected);
    }

    #[test]
    fn test_flakey_target_params_drop_writes_and_corrupt_bio_byte() {
        let result = "flakey 8:32 0 16 2 6 corrupt_bio_byte 32 r 1 0 drop_writes"
            .parse::<FlakeyTargetParams>()
            .unwrap();
        let expected = [
            FeatureArg::DropWrites,
            FeatureArg::CorruptBioByte(32, Direction::Reads, 1, 0),
        ]
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
        assert_eq!(result.feature_args, expected);
    }

    #[test]
    fn test_flakey_target_params_error_writes_and_drop_writes() {
        let result = "flakey 8:32 0 16 2 2 error_writes drop_writes"
            .parse::<FlakeyTargetParams>()
            .unwrap();
        let expected = [FeatureArg::ErrorWrites, FeatureArg::DropWrites]
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(result.feature_args, expected);
    }

    #[test]
    fn loop_test_duplicate_segments() {
        test_with_spec(1, test_duplicate_segments);
    }

    #[test]
    fn loop_test_empty() {
        test_with_spec(0, test_empty);
    }

    #[test]
    fn loop_test_empty_table_set() {
        test_with_spec(1, test_empty_table_set);
    }

    #[test]
    fn loop_test_rename() {
        test_with_spec(1, test_rename);
    }

    #[test]
    fn loop_test_rename_id() {
        test_with_spec(1, test_rename_id);
    }

    #[test]
    fn loop_test_same_name() {
        test_with_spec(1, test_same_name);
    }

    #[test]
    fn loop_test_segment() {
        test_with_spec(1, test_same_segment);
    }

    #[test]
    fn loop_test_several_segments() {
        test_with_spec(1, test_several_segments);
    }

    #[test]
    fn loop_test_suspend() {
        test_with_spec(1, test_suspend);
    }
}
