// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::device::pcipath_to_sysfs;
use crate::linux_abi::{create_pci_root_bus_path, pcipath_from_dev_tree_path, SYSFS_DIR};

pub fn prepare_block_device_removal(pci_path: &str) -> Result<()> {
    let (root_complex, path) = pcipath_from_dev_tree_path(pci_path)?;
    let root = PathBuf::from(format!(
        "{}{}",
        SYSFS_DIR,
        create_pci_root_bus_path(root_complex)
    ));
    let relative = pcipath_to_sysfs(root.to_str().context("invalid PCI sysfs root")?, &path)?;
    let pci_device = root.join(relative.trim_start_matches('/'));
    let virtio_device = find_virtio_block_device(&pci_device)?;
    prepare_virtio_block_device(&virtio_device, Path::new("/dev"))
        .with_context(|| format!("preparing block device at PCI path {pci_path}"))
}

fn find_virtio_block_device(pci_device: &Path) -> Result<PathBuf> {
    let mut devices = Vec::new();
    for entry in fs::read_dir(pci_device).context("reading PCI device")? {
        let entry = entry?;
        if !entry.file_name().as_encoded_bytes().starts_with(b"virtio") {
            continue;
        }
        // VIRTIO_ID_BLOCK is 2. Do not unbind a different virtio device.
        if fs::read_to_string(entry.path().join("device"))?.trim() == "0x0002" {
            devices.push(entry.path());
        }
    }
    if devices.len() != 1 {
        bail!("expected one virtio block device, found {}", devices.len());
    }
    Ok(devices.remove(0))
}

fn prepare_virtio_block_device(virtio_device: &Path, dev_root: &Path) -> Result<()> {
    let driver = virtio_device.join("driver");
    let driver_path = match fs::canonicalize(&driver) {
        Ok(path) => path,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Retrying after successful unbind but failed host removal is safe.
            if !virtio_device.join("block").try_exists()? {
                return Ok(());
            }
            bail!("unbound virtio device still has block disks");
        }
        Err(e) => return Err(e).context("resolving virtio block driver"),
    };
    if driver_path.file_name() != Some(std::ffi::OsStr::new("virtio_blk")) {
        bail!("unexpected virtio block driver {}", driver_path.display());
    }

    let disks = fs::read_dir(virtio_device.join("block"))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    if disks.len() != 1 {
        bail!("expected one block disk, found {}", disks.len());
    }
    let disk = &disks[0];
    ensure_disk_has_no_holders(disk)?;

    let name = disk.file_name().context("missing block disk name")?;
    let device_path = dev_root.join(name);
    // A whole-disk exclusive claim also rejects mounted/claimed partitions.
    // Keep the claim until unbind finishes, preventing new mounts in between.
    let device = open_exclusive_disk(&device_path)?;
    device.sync_all().context("flushing block disk")?;

    let virtio_name = virtio_device
        .file_name()
        .context("missing virtio device name")?;
    fs::write(driver_path.join("unbind"), virtio_name.as_encoded_bytes())
        .context("unbinding virtio_blk while the backend is available")?;

    if driver.try_exists()? || virtio_device.join("block").try_exists()? {
        bail!("virtio block driver teardown did not complete");
    }
    drop(device);
    Ok(())
}

fn ensure_disk_has_no_holders(disk: &Path) -> Result<()> {
    ensure_no_holders(disk)?;
    for entry in
        fs::read_dir(disk).with_context(|| format!("reading block disk {}", disk.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_dir() && entry.path().join("partition").try_exists()? {
            ensure_no_holders(&entry.path())?;
        }
    }
    Ok(())
}

fn ensure_no_holders(device: &Path) -> Result<()> {
    if let Some(entry) = fs::read_dir(device.join("holders"))?.next() {
        bail!(
            "block device {} is still held by {}",
            device.display(),
            entry?.file_name().to_string_lossy()
        );
    }
    Ok(())
}

fn open_exclusive_disk(path: &Path) -> Result<File> {
    let device = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_EXCL | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("claiming unused block disk {}", path.display()))?;
    if !device.metadata()?.file_type().is_block_device() {
        return Err(anyhow!("{} is not a block device", path.display()));
    }
    Ok(device)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[test]
    fn resolves_only_virtio_block_devices() {
        let dir = tempdir().unwrap();
        assert!(find_virtio_block_device(dir.path()).is_err());
        for (name, id) in [("virtio0", "0x0001\n"), ("virtio1", "0x0002\n")] {
            fs::create_dir(dir.path().join(name)).unwrap();
            fs::write(dir.path().join(name).join("device"), id).unwrap();
        }
        assert_eq!(
            find_virtio_block_device(dir.path()).unwrap(),
            dir.path().join("virtio1")
        );
        fs::create_dir(dir.path().join("virtio2")).unwrap();
        fs::write(dir.path().join("virtio2/device"), "0x0002\n").unwrap();
        assert!(find_virtio_block_device(dir.path()).is_err());
    }

    #[test]
    fn retry_requires_disk_teardown() {
        let dir = tempdir().unwrap();
        assert!(prepare_virtio_block_device(dir.path(), dir.path()).is_ok());
        fs::create_dir(dir.path().join("block")).unwrap();
        assert!(prepare_virtio_block_device(dir.path(), dir.path()).is_err());
    }

    #[test]
    fn rejects_other_drivers() {
        let dir = tempdir().unwrap();
        let driver = dir.path().join("other_driver");
        fs::create_dir(&driver).unwrap();
        symlink(driver, dir.path().join("driver")).unwrap();
        assert!(prepare_virtio_block_device(dir.path(), dir.path())
            .unwrap_err()
            .to_string()
            .contains("unexpected virtio block driver"));
    }

    #[test]
    fn rejects_holders_and_missing_holder_information() {
        let dir = tempdir().unwrap();
        assert!(ensure_no_holders(dir.path()).is_err());
        let holders = dir.path().join("holders");
        fs::create_dir(&holders).unwrap();
        assert!(ensure_no_holders(dir.path()).is_ok());
        fs::write(holders.join("dm-0"), "").unwrap();
        assert!(ensure_no_holders(dir.path()).is_err());
    }

    #[test]
    fn scans_disk_with_sysfs_attributes_directories_and_symlinks() {
        let dir = tempdir().unwrap();
        let disk = dir.path().join("vda");
        for name in ["holders", "queue", "power", "vda1/holders"] {
            fs::create_dir_all(disk.join(name)).unwrap();
        }
        for name in ["dev", "size", "stat", "uevent"] {
            fs::write(disk.join(name), "0\n").unwrap();
        }
        fs::write(disk.join("vda1/partition"), "1\n").unwrap();
        symlink(dir.path(), disk.join("device")).unwrap();

        ensure_disk_has_no_holders(&disk).unwrap();

        fs::write(disk.join("vda1/holders/dm-0"), "").unwrap();
        let err = ensure_disk_has_no_holders(&disk).unwrap_err();
        assert!(err.to_string().contains("still held by dm-0"));
    }

    #[test]
    fn rejects_disk_and_partition_holders_before_unbinding() {
        for partition_holder in [false, true] {
            let dir = tempdir().unwrap();
            let virtio = dir.path().join("virtio0");
            let disk = virtio.join("block/vda");
            let driver = dir.path().join("virtio_blk");
            fs::create_dir_all(disk.join("holders")).unwrap();
            fs::create_dir(&driver).unwrap();
            fs::write(driver.join("unbind"), "").unwrap();
            symlink(&driver, virtio.join("driver")).unwrap();
            let held = if partition_holder {
                let partition = disk.join("vda1");
                fs::create_dir_all(partition.join("holders")).unwrap();
                fs::write(partition.join("partition"), "1\n").unwrap();
                partition
            } else {
                disk
            };
            fs::write(held.join("holders/dm-0"), "").unwrap();
            let err = prepare_virtio_block_device(&virtio, dir.path()).unwrap_err();
            assert!(err.to_string().contains("still held by dm-0"));
            assert_eq!(fs::read_to_string(driver.join("unbind")).unwrap(), "");
        }
    }

    #[test]
    fn rejects_non_block_devices() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("disk");
        fs::write(&path, "").unwrap();
        assert!(open_exclusive_disk(&path).is_err());
        assert!(open_exclusive_disk(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn rejects_invalid_pci_paths() {
        for path in ["", "../", "/sys", "xx", "00/../../"] {
            assert!(prepare_block_device_removal(path).is_err());
        }
    }
}
