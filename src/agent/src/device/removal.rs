// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: Apache-2.0

use super::pcipath_to_sysfs;
use crate::linux_abi::{create_pci_root_bus_path, pcipath_from_dev_tree_path};
use anyhow::{anyhow, ensure, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Unbind the block driver while the host still exposes the PCI device.
pub fn prepare_device_removal(pci_path: &str) -> Result<()> {
    prepare_at(Path::new("/sys"), Path::new("/dev"), pci_path)
}

fn prepare_at(sysfs: &Path, dev_root: &Path, pci_path: &str) -> Result<()> {
    let (root_complex, pci_path) = pcipath_from_dev_tree_path(pci_path)?;
    let root = sysfs.join(create_pci_root_bus_path(root_complex).trim_start_matches('/'));
    let relative = pcipath_to_sysfs(root.to_str().context("invalid PCI root path")?, &pci_path)?;
    let pci_device = root.join(relative.trim_start_matches('/'));
    let mut devices = Vec::new();
    for entry in fs::read_dir(&pci_device).context("find virtio device on PCI endpoint")? {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .to_str()
            .and_then(|name| name.strip_prefix("virtio"))
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
        {
            devices.push(entry.path());
        }
    }
    ensure!(
        devices.len() == 1,
        "expected exactly one virtio device on PCI endpoint"
    );
    let device = &devices[0];
    let kind = fs::read_to_string(device.join("device")).context("read virtio device type")?;
    ensure!(
        u32::from_str_radix(kind.trim().trim_start_matches("0x"), 16)? == 2,
        "only virtio-blk device removal is supported"
    );
    let driver_link = device.join("driver");
    let driver = match fs::canonicalize(&driver_link) {
        Ok(driver) => driver,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // A retry after a successful unbind must not reset the device again.
            ensure!(
                !device.join("block").exists(),
                "unbound device still has block children"
            );
            return Ok(());
        }
        Err(e) => return Err(e).context("resolve virtio driver"),
    };
    ensure!(
        driver == fs::canonicalize(sysfs.join("bus/virtio/drivers/virtio_blk"))?,
        "unexpected driver on virtio-blk device"
    );
    let disks = fs::read_dir(device.join("block"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(disks.len() == 1, "expected one whole block device");
    let disk = &disks[0];
    let name = disk.file_name().context("missing block device name")?;
    let node = dev_root.join(name);
    let dev = fs::read_to_string(disk.join("dev"))?;
    let (major, minor) = dev
        .trim()
        .split_once(':')
        .context("invalid block device number")?;
    let expected = nix::sys::stat::makedev(major.parse()?, minor.parse()?);
    // O_EXCL claims the whole disk and fails if it or a partition has a
    // filesystem/device-mapper holder, including mounts in other namespaces.
    // Deferred dm-verity removal can briefly retain the underlying partition.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let claim = loop {
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_EXCL)
            .open(&node)
        {
            Ok(file) => break file,
            Err(error)
                if error.raw_os_error() == Some(libc::EBUSY)
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("claim idle block device {}", node.display()))
            }
        }
    };
    validate_node(&claim, &node, expected)?;
    let name = device.file_name().context("missing virtio device name")?;
    fs::write(driver.join("unbind"), name.as_encoded_bytes())
        .context("unbind virtio-blk driver")?;
    ensure!(
        matches!(fs::symlink_metadata(&driver_link), Err(ref e) if e.kind() == ErrorKind::NotFound),
        "virtio-blk driver remains bound"
    );
    drop(claim);
    Ok(())
}

fn validate_node(file: &File, path: &Path, expected: u64) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_block_device() || metadata.rdev() != expected {
        return Err(anyhow!(
            "{} does not match the requested block device",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let device = root.path().join("devices/pci0000:00/0000:00:02.0/virtio1");
        fs::create_dir_all(&device).unwrap();
        fs::write(device.join("device"), "0x00000002\n").unwrap();
        (root, device)
    }

    #[test]
    fn already_unbound_is_idempotent() {
        let (root, _) = fixture();
        prepare_at(root.path(), root.path(), "02").unwrap();
        prepare_at(root.path(), root.path(), "02").unwrap();
    }

    #[test]
    fn rejects_wrong_device_and_invalid_paths() {
        let (root, device) = fixture();
        fs::write(device.join("device"), "0x00000001\n").unwrap();
        assert!(prepare_at(root.path(), root.path(), "02").is_err());
        assert!(prepare_at(root.path(), root.path(), "../02").is_err());
        assert!(prepare_at(root.path(), root.path(), "03").is_err());
    }

    #[test]
    fn rejects_unbound_block_children_and_other_drivers() {
        let (root, device) = fixture();
        fs::create_dir(device.join("block")).unwrap();
        assert!(prepare_at(root.path(), root.path(), "02").is_err());
        let driver = root.path().join("bus/virtio/drivers/other");
        fs::create_dir_all(&driver).unwrap();
        fs::create_dir_all(root.path().join("bus/virtio/drivers/virtio_blk")).unwrap();
        symlink(driver, device.join("driver")).unwrap();
        assert!(prepare_at(root.path(), root.path(), "02").is_err());
    }
}
