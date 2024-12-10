use super::{MountInfo, MountIter};
use std::{
    io::{self, BufRead},
    os::unix::ffi::OsStrExt,
    path::Path,
    str::FromStr,
};

/// A list of parsed mount entries from `/proc/mounts`.
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq)]
pub struct MountList(pub Vec<MountInfo>);

impl MountList {
    /// Parse mounts given from an iterator of mount entry lines.
    pub fn parse_from<'a, I: Iterator<Item = &'a str>>(lines: I) -> io::Result<MountList> {
        lines.map(MountInfo::from_str).collect::<io::Result<Vec<MountInfo>>>().map(MountList)
    }

    /// Read a new list of mounts into memory from `/proc/mounts`.
    pub fn new() -> io::Result<MountList> {
        Ok(MountList(MountIter::new()?.collect::<io::Result<Vec<MountInfo>>>()?))
    }

    /// Read a new list of mounts into memory from any mount-tab-like file.
    pub fn new_from_file<P: AsRef<Path>>(path: P) -> io::Result<MountList> {
        Ok(MountList(MountIter::new_from_file(path)?.collect::<io::Result<Vec<MountInfo>>>()?))
    }

    /// Read a new list of mounts into memory from any mount-tab-like file.
    pub fn new_from_reader<R: BufRead>(reader: R) -> io::Result<MountList> {
        Ok(MountList(MountIter::new_from_reader(reader).collect::<io::Result<Vec<MountInfo>>>()?))
    }

    // Returns true if the `source` is mounted at the given `dest`.
    pub fn source_mounted_at<D: AsRef<Path>, P: AsRef<Path>>(&self, source: D, path: P) -> bool {
        self.get_mount_by_source(source)
            .map_or(false, |mount| mount.dest.as_path() == path.as_ref())
    }

    /// Find the first mount which which has the `path` destination.
    pub fn get_mount_by_dest<P: AsRef<Path>>(&self, path: P) -> Option<&MountInfo> {
        self.0.iter().find(|mount| mount.dest == path.as_ref())
    }

    /// Find the first mount hich has the source `path`.
    pub fn get_mount_by_source<P: AsRef<Path>>(&self, path: P) -> Option<&MountInfo> {
        self.0.iter().find(|mount| mount.source == path.as_ref())
    }

    /// Iterate through each source that starts with the given `path`.
    pub fn source_starts_with<'a>(
        &'a self,
        path: &'a Path,
    ) -> Box<dyn Iterator<Item = &MountInfo> + 'a> {
        self.starts_with(path.as_os_str().as_bytes(), |m| &m.source)
    }

    /// Iterate through each destination that starts with the given `path`.
    pub fn destination_starts_with<'a>(
        &'a self,
        path: &'a Path,
    ) -> Box<dyn Iterator<Item = &MountInfo> + 'a> {
        self.starts_with(path.as_os_str().as_bytes(), |m| &m.dest)
    }

    fn starts_with<'a, F: Fn(&'a MountInfo) -> &'a Path + 'a>(
        &'a self,
        path: &'a [u8],
        func: F,
    ) -> Box<dyn Iterator<Item = &MountInfo> + 'a> {
        let iterator = self.0.iter().filter(move |mount| {
            let input = func(mount).as_os_str().as_bytes();
            input.len() >= path.len() && &input[..path.len()] == path
        });

        Box::new(iterator)
    }
}
