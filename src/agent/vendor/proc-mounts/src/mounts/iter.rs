use super::MountInfo;
use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
    str::FromStr,
};

/// Iteratively parse the `/proc/mounts` file.
pub struct MountIter<R> {
    file:   R,
    buffer: String,
}

impl MountIter<BufReader<File>> {
    pub fn new() -> io::Result<Self> { Self::new_from_file("/proc/mounts") }

    /// Read mounts from any mount-tab-like file.
    pub fn new_from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(Self::new_from_reader(BufReader::new(File::open(path)?)))
    }
}

impl<R: BufRead> MountIter<R> {
    /// Read mounts from any in-memory buffer.
    pub fn new_from_reader(readable: R) -> Self {
        Self { file: readable, buffer: String::with_capacity(512) }
    }

    /// Iterator-based variant of `source_mounted_at`.
    ///
    /// Returns true if the `source` is mounted at the given `dest`.
    ///
    /// Due to iterative parsing of the mount file, an error may be returned.
    pub fn source_mounted_at<D: AsRef<Path>, P: AsRef<Path>>(
        source: D,
        path: P,
    ) -> io::Result<bool> {
        let source = source.as_ref();
        let path = path.as_ref();

        let mut is_found = false;

        let mounts = MountIter::new()?;
        for mount in mounts {
            let mount = mount?;
            if mount.source == source {
                is_found = mount.dest == path;
                break;
            }
        }

        Ok(is_found)
    }
}

impl<R: BufRead> Iterator for MountIter<R> {
    type Item = io::Result<MountInfo>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.buffer.clear();
            match self.file.read_line(&mut self.buffer) {
                Ok(read) if read == 0 => return None,
                Ok(_) => {
                    let line = self.buffer.trim_start();
                    if !(line.starts_with('#') || line.is_empty()) {
                        return Some(MountInfo::from_str(line));
                    }
                }
                Err(why) => return Some(Err(why)),
            }
        }
    }
}
