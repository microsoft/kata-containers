// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    fs::OpenOptions,
    io::{self, Seek, SeekFrom, Write},
    os::unix::io::AsRawFd,
    panic,
    path::{Path, PathBuf},
};

use loopdev::{LoopControl, LoopDevice};
use tempfile::{self, TempDir};

use crate::{
    consts::IEC,
    testing::{logger::init_logger, test_lib::clean_up},
    units::{Bytes, Sectors, SECTOR_SIZE},
};

/// Write buf at offset length times.
fn write_sectors<P: AsRef<Path>>(
    path: P,
    offset: Sectors,
    length: Sectors,
    buf: &[u8; SECTOR_SIZE],
) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;

    f.seek(SeekFrom::Start((*offset.bytes()).try_into().unwrap()))?;
    for _ in 0..*length {
        f.write_all(buf)?;
    }

    f.sync_all()?;
    Ok(())
}

/// Zero sectors at the given offset for length sectors.
fn wipe_sectors<P: AsRef<Path>>(path: P, offset: Sectors, length: Sectors) -> io::Result<()> {
    write_sectors(path, offset, length, &[0u8; SECTOR_SIZE])
}

pub struct LoopTestDev {
    ld: LoopDevice,
}

impl LoopTestDev {
    fn new(lc: &LoopControl, path: &Path) -> LoopTestDev {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();

        let ld = lc.next_free().unwrap();
        ld.attach_file(path).unwrap();

        // Wipe one MiB at the start of the device. Devicemapper data may be
        // left on the device even after a teardown.
        wipe_sectors(
            ld.path().unwrap(),
            Sectors(0),
            Bytes(u128::from(IEC::Mi)).sectors(),
        )
        .unwrap();

        LoopTestDev { ld }
    }

    fn path(&self) -> PathBuf {
        self.ld.path().unwrap()
    }

    fn detach(&self) {
        self.ld.detach().unwrap()
    }
}

impl Drop for LoopTestDev {
    fn drop(&mut self) {
        self.detach()
    }
}

/// Setup count loop backed devices in dir.
/// Make sure each loop device is backed by a sparse 1 GiB file. The entire file will read back
/// as initialized with zero.
fn get_devices(count: u8, dir: &TempDir) -> Vec<LoopTestDev> {
    let lc = LoopControl::open().unwrap();
    let mut loop_devices = Vec::new();

    for index in 0..count {
        let path = dir.path().join(format!("store{}", &index));
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .unwrap();

        nix::unistd::ftruncate(f.as_raw_fd(), IEC::Gi as nix::libc::off_t).unwrap();
        f.sync_all().unwrap();

        let ltd = LoopTestDev::new(&lc, &path);

        loop_devices.push(ltd);
    }
    loop_devices
}

/// Set up count loopbacked devices.
/// Then, run the designated test.
/// Then, take down the loop devices.
pub fn test_with_spec<F>(count: u8, test: F)
where
    F: Fn(&[&Path]) + panic::RefUnwindSafe,
{
    init_logger();
    clean_up().unwrap();

    let tmpdir = tempfile::Builder::new()
        .prefix("devicemapper")
        .tempdir()
        .unwrap();
    let loop_devices: Vec<LoopTestDev> = get_devices(count, &tmpdir);
    let device_paths: Vec<PathBuf> = loop_devices.iter().map(|x| x.path()).collect();
    let device_paths: Vec<&Path> = device_paths.iter().map(|x| x.as_path()).collect();

    let result = panic::catch_unwind(|| test(&device_paths));
    let tear_down = clean_up();

    result.unwrap();
    tear_down.unwrap();
}
