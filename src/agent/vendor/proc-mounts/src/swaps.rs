use std::{
    char,
    ffi::OsString,
    fmt::{self, Display, Formatter},
    fs::File,
    io::{self, BufRead, BufReader, Error, ErrorKind},
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    str::FromStr,
};

/// A swap entry, which defines an active swap.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SwapInfo {
    /// The path where the swap originates from.
    pub source: PathBuf,
    /// The kind of swap, such as `partition` or `file`.
    pub kind: OsString,
    /// The size of the swap partition.
    pub size: usize,
    /// Whether the swap is used or not.
    pub used: usize,
    /// The priority of a swap, which indicates the order of usage.
    pub priority: isize,
}

impl Display for SwapInfo {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(
            fmt,
            "{} {} {} {} {}",
            self.source.display(),
            self.kind.to_str().ok_or(fmt::Error)?,
            self.size,
            self.used,
            self.priority
        )
    }
}

impl FromStr for SwapInfo {
    type Err = io::Error;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut parts = line.split_whitespace();

        fn parse<F: FromStr>(string: &OsString) -> io::Result<F> {
            let string = string.to_str().ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "/proc/swaps contains non-UTF8 entry")
            })?;

            string.parse::<F>().map_err(|_| {
                Error::new(ErrorKind::InvalidData, "/proc/swaps contains invalid data")
            })
        }

        macro_rules! next_value {
            ($err:expr) => {{
                parts
                    .next()
                    .ok_or_else(|| Error::new(ErrorKind::Other, $err))
                    .and_then(|val| Self::parse_value(val))
            }};
        }

        Ok(SwapInfo {
            source:   PathBuf::from(next_value!("Missing source")?),
            kind:     next_value!("Missing kind")?,
            size:     parse::<usize>(&next_value!("Missing size")?)?,
            used:     parse::<usize>(&next_value!("Missing used")?)?,
            priority: parse::<isize>(&next_value!("Missing priority")?)?,
        })
    }
}

impl SwapInfo {
    // Attempt to parse a `/proc/swaps`-like line.
    #[deprecated]
    pub fn parse_line(line: &str) -> io::Result<SwapInfo> { line.parse::<Self>() }

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

/// A list of parsed swap entries from `/proc/swaps`.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SwapList(pub Vec<SwapInfo>);

impl SwapList {
    pub fn parse_from<'a, I: Iterator<Item = &'a str>>(lines: I) -> io::Result<SwapList> {
        lines.map(SwapInfo::from_str).collect::<io::Result<Vec<SwapInfo>>>().map(SwapList)
    }

    pub fn new() -> io::Result<SwapList> {
        Ok(SwapList(SwapIter::new()?.collect::<io::Result<Vec<SwapInfo>>>()?))
    }

    pub fn new_from_file<P: AsRef<Path>>(path: P) -> io::Result<SwapList> {
        Ok(SwapList(SwapIter::new_from_file(path)?.collect::<io::Result<Vec<SwapInfo>>>()?))
    }

    pub fn new_from_reader<R: BufRead>(reader: R) -> io::Result<SwapList> {
        Ok(SwapList(SwapIter::new_from_reader(reader)?.collect::<io::Result<Vec<SwapInfo>>>()?))
    }

    /// Returns true if the given path is a entry in the swap list.
    pub fn get_swapped(&self, path: &Path) -> bool {
        self.0.iter().any(|mount| mount.source == path)
    }
}

/// Iteratively parse the `/proc/swaps` file.
pub struct SwapIter<R: BufRead> {
    file:   R,
    buffer: String,
}

impl SwapIter<BufReader<File>> {
    pub fn new() -> io::Result<Self> { Self::new_from_file("/proc/swaps") }

    pub fn new_from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Self::new_from_reader(BufReader::new(File::open(path)?))
    }
}

impl<R: BufRead> SwapIter<R> {
    pub fn new_from_reader(mut reader: R) -> io::Result<Self> {
        let mut buffer = String::with_capacity(512);
        reader.read_line(&mut buffer)?;
        buffer.clear();

        Ok(Self { file: reader, buffer })
    }
}

impl<R: BufRead> Iterator for SwapIter<R> {
    type Item = io::Result<SwapInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        self.buffer.clear();
        match self.file.read_line(&mut self.buffer) {
            Ok(read) if read == 0 => None,
            Ok(_) => Some(SwapInfo::from_str(&self.buffer)),
            Err(why) => Some(Err(why)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, path::PathBuf};

    const SAMPLE: &str = r#"Filename				Type		Size	Used	Priority
/dev/sda5                               partition	8388600	0	-2"#;

    #[test]
    fn swaps() {
        let swaps = SwapList::parse_from(SAMPLE.lines().skip(1)).unwrap();
        assert_eq!(
            swaps,
            SwapList(vec![SwapInfo {
                source:   PathBuf::from("/dev/sda5"),
                kind:     OsString::from("partition"),
                size:     8_388_600,
                used:     0,
                priority: -2,
            }])
        );

        assert!(swaps.get_swapped(Path::new("/dev/sda5")));
        assert!(!swaps.get_swapped(Path::new("/dev/sda1")));
    }
}
