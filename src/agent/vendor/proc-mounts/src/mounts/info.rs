use partition_identity::PartitionID;
use std::{
    char,
    ffi::OsString,
    fmt::{self, Display, Formatter},
    io::{self, Error, ErrorKind},
    os::unix::ffi::OsStringExt,
    path::PathBuf,
    str::FromStr,
};

/// A mount entry which contains information regarding how and where a source
/// is mounted.
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq)]
pub struct MountInfo {
    /// The source which is mounted.
    pub source: PathBuf,
    /// Where the source is mounted.
    pub dest: PathBuf,
    /// The type of the mounted file system.
    pub fstype: String,
    /// Options specified for this file system.
    pub options: Vec<String>,
    /// Defines if the file system should be dumped.
    pub dump: i32,
    /// Defines if the file system should be checked, and in what order.
    pub pass: i32,
}

impl Display for MountInfo {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(
            fmt,
            "{} {} {} {} {} {}",
            self.source.display(),
            self.dest.display(),
            self.fstype,
            if self.options.is_empty() { "defaults".into() } else { self.options.join(",") },
            self.dump,
            self.pass
        )
    }
}

impl FromStr for MountInfo {
    type Err = io::Error;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut parts = line.split_whitespace();

        fn map_err(why: &'static str) -> io::Error { Error::new(ErrorKind::InvalidData, why) }

        let source = parts.next().ok_or_else(|| map_err("missing source"))?;
        let dest = parts.next().ok_or_else(|| map_err("missing dest"))?;
        let fstype = parts.next().ok_or_else(|| map_err("missing type"))?;
        let options = parts.next().ok_or_else(|| map_err("missing options"))?;

        let dump = parts.next().map_or(Ok(0), |value| {
            value.parse::<i32>().map_err(|_| map_err("dump value is not a number"))
        })?;

        let pass = parts.next().map_or(Ok(0), |value| {
            value.parse::<i32>().map_err(|_| map_err("pass value is not a number"))
        })?;

        let path = Self::parse_value(source)?;
        let path = path.to_str().ok_or_else(|| map_err("non-utf8 paths are unsupported"))?;

        let source = if path.starts_with("/dev/disk/by-") {
            Self::fetch_from_disk_by_path(path)?
        } else {
            PathBuf::from(path)
        };

        let path = Self::parse_value(dest)?;
        let path = path.to_str().ok_or_else(|| map_err("non-utf8 paths are unsupported"))?;

        let dest = PathBuf::from(path);

        Ok(MountInfo {
            source,
            dest,
            fstype: fstype.to_owned(),
            options: options.split(',').map(String::from).collect(),
            dump,
            pass,
        })
    }
}

impl MountInfo {
    /// Attempt to parse a `/proc/mounts`-like line.
    #[deprecated]
    pub fn parse_line(line: &str) -> io::Result<MountInfo> { line.parse::<Self>() }

    fn fetch_from_disk_by_path(path: &str) -> io::Result<PathBuf> {
        PartitionID::from_disk_by_path(path)
            .map_err(|why| Error::new(ErrorKind::InvalidData, format!("{}: {}", path, why)))?
            .get_device_path()
            .ok_or_else(|| {
                Error::new(ErrorKind::NotFound, format!("device path for {} was not found", path))
            })
    }

    fn parse_value(value: &str) -> io::Result<OsString> {
        let mut ret = Vec::new();

        let mut bytes = value.bytes();
        while let Some(b) = bytes.next() {
            match b {
                b'\\' => {
                    let mut code = 0;
                    for _i in 0..3 {
                        if let Some(b) = bytes.next() {
                            code *= 8;
                            code += u32::from_str_radix(&(b as char).to_string(), 8)
                                .map_err(|err| Error::new(ErrorKind::Other, err))?;
                        } else {
                            return Err(Error::new(ErrorKind::Other, "truncated octal code"));
                        }
                    }
                    ret.push(code as u8);
                }
                _ => {
                    ret.push(b);
                }
            }
        }

        Ok(OsString::from_vec(ret))
    }
}
