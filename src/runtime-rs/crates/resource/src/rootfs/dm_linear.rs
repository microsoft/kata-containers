// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

//Temporary GPT disk composition for OpenVMM's lack of layered VMDK support.

use anyhow::{anyhow, bail, Context, Result};
use kata_types::gpt_disk::{generate_gpt_metadata, ErofsLayer, GptDiskLayout, GptMetadataFiles};
use linux_raw_sys::loop_device::{
    loop_config, loop_info64, LOOP_CONFIGURE, LOOP_CTL_GET_FREE, LO_FLAGS_AUTOCLEAR,
    LO_FLAGS_READ_ONLY,
};
use nix::errno::Errno;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tokio::process::Command;

use super::erofs_rootfs::ensure_container_dir;

const SECTOR_SIZE: u64 = 512;
const DMSETUP_TIMEOUT: Duration = Duration::from_secs(5);

// Generate typed wrappers using the kernel's fixed loop ioctl request numbers.
// `_bad` preserves the literal request numbers from Linux's loop UAPI.
nix::ioctl_none_bad!(get_free_loop, LOOP_CTL_GET_FREE);
nix::ioctl_write_ptr_bad!(configure_loop, LOOP_CONFIGURE, loop_config);

// The generated binding lacks Default; this wrapper provides safe zero initialization.
struct LoopConfig(loop_config);

impl Default for LoopConfig {
    fn default() -> Self {
        Self(loop_config {
            fd: 0,
            block_size: 0,
            info: loop_info64 {
                lo_device: 0,
                lo_inode: 0,
                lo_rdevice: 0,
                lo_offset: 0,
                lo_sizelimit: 0,
                lo_number: 0,
                lo_encrypt_type: 0,
                lo_encrypt_key_size: 0,
                lo_flags: 0,
                lo_file_name: [0; 64],
                lo_crypt_name: [0; 64],
                lo_encrypt_key: [0; 32],
                lo_init: [0; 2],
            },
            __reserved: [0; 8],
        })
    }
}

pub(super) async fn generate_gpt_linear_with_layout(
    sid: &str,
    cid: &str,
    erofs_layers: Vec<ErofsLayer>,
) -> Result<(LinearDisk, GptDiskLayout, GptMetadataFiles)> {
    let directory = ensure_container_dir(sid, cid)?;
    let (layout, metadata) = generate_gpt_metadata(sid, cid, erofs_layers, &directory)?;
    let disk = LinearDisk::create(format!("kata-erofs-{cid}"), &layout, &metadata).await?;
    Ok((disk, layout, metadata))
}

fn attach_loop(path: &Path, sectors: u64) -> Result<(File, PathBuf)> {
    let backing = File::open(path).with_context(|| format!("open layer {}", path.display()))?;
    let metadata = backing.metadata()?;
    let size = sectors
        .checked_mul(SECTOR_SIZE)
        .context("loop backing size overflow")?;
    if !metadata.is_file() || metadata.len() != size {
        bail!(
            "dm-linear backing file size/type mismatch: {}",
            path.display()
        );
    }
    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
        .context("open loop-control (host loop support and root privileges required)")?;
    // Finding a free loop does not reserve it; another process may claim it before
    // LOOP_CONFIGURE. Retry EBUSY, bounded to 16 attempts (same as losetup --find).
    for _ in 0..16 {
        // LOOP_CTL_GET_FREE returns a device number, not a file descriptor.
        let number =
            unsafe { get_free_loop(control.as_raw_fd()) }.context("allocate host loop device")?;
        let loop_path = PathBuf::from(format!("/dev/loop{number}"));
        let device = File::open(&loop_path)?;
        let LoopConfig(mut config) = LoopConfig::default();
        config.fd = backing.as_raw_fd() as u32;
        config.block_size = SECTOR_SIZE as u32;
        config.info.lo_flags = LO_FLAGS_READ_ONLY as u32 | LO_FLAGS_AUTOCLEAR as u32;
        // The kernel copies this initialized UAPI structure during the ioctl.
        match unsafe { configure_loop(device.as_raw_fd(), &config) } {
            Ok(_) => return Ok((device, loop_path)),
            Err(Errno::EBUSY) => continue,
            Err(error) => {
                return Err(error).context("configure read-only autoclear loop device");
            }
        }
    }
    bail!("host loop allocation remained busy after 16 attempts")
}

async fn dmsetup(args: &[&str]) -> Result<()> {
    let output = tokio::time::timeout(
        DMSETUP_TIMEOUT,
        Command::new("dmsetup")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("dmsetup timed out")?
    .context("execute dmsetup (host device-mapper tools required)")?;
    if !output.status.success() {
        bail!(
            "dmsetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// The kernel removes the dm-linear device when its last opener closes. Autoclear
/// loops remain referenced by the dm table until that removal completes.
pub(super) struct LinearDisk {
    name: String,
    path: PathBuf,
    device: Mutex<Option<File>>,
    loops: Mutex<Vec<File>>,
    needs_removal: bool,
}

impl LinearDisk {
    async fn create(
        name: String,
        layout: &GptDiskLayout,
        metadata: &GptMetadataFiles,
    ) -> Result<Self> {
        let mut loops = Vec::new();
        let (device, path) = attach_loop(&metadata.head_path, metadata.head_sectors)?;
        loops.push(device);
        // Format: <disk start sector> <sector count> linear <loop device> <source sector>.
        // Map the GPT header/table at disk sector 0, starting at sector 0 of its file.
        let mut table = format!("0 {} linear {} 0\n", metadata.head_sectors, path.display());
        let mut cursor = metadata.head_sectors;
        for part in &layout.partitions {
            if part.start_lba > cursor {
                // Format: <disk start sector> <sector count> zero.
                // Fill the gap before this partition with zeroes for GPT alignment.
                table.push_str(&format!("{cursor} {} zero\n", part.start_lba - cursor));
            }
            let (device, path) = attach_loop(Path::new(&part.layer.path), part.layer.size_sectors)?;
            loops.push(device);
            // Map this partition's disk sectors to the layer file, starting at sector 0.
            table.push_str(&format!(
                "{} {} linear {} 0\n",
                part.start_lba,
                part.layer.size_sectors,
                path.display()
            ));
            cursor = part.end_lba + 1;
        }
        let path = PathBuf::from("/dev/mapper").join(&name);
        let mut disk = Self {
            name,
            path,
            device: Mutex::new(None),
            loops: Mutex::new(loops),
            needs_removal: false,
        };
        dmsetup(&["create", &disk.name, "--readonly", "--table", &table]).await?;
        // Only remove a device whose creation succeeded.
        disk.needs_removal = true;
        dmsetup(&["mknodes", &disk.name]).await?;
        let device = File::open(&disk.path).context("open dm-linear device")?;
        if !device.metadata()?.file_type().is_block_device() {
            bail!("dm-linear device path is not a block device");
        }
        // Keep our fd open while the VMM opens the path. Deferred removal also
        // handles shim crashes, once the VMM releases its final reference.
        disk.device = Mutex::new(Some(device));
        dmsetup(&["remove", "--deferred", &disk.name]).await?;
        disk.needs_removal = false;
        Ok(disk)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn release(&self) -> Result<()> {
        self.device
            .lock()
            .map_err(|_| anyhow!("disk owner lock poisoned"))?
            .take();
        self.loops
            .lock()
            .map_err(|_| anyhow!("loop owner lock poisoned"))?
            .clear();
        Ok(())
    }
}

impl Drop for LinearDisk {
    fn drop(&mut self) {
        if self.needs_removal {
            match std::process::Command::new("dmsetup")
                .args(["remove", "--deferred", &self.name])
                .output()
            {
                Ok(output) if output.status.success() => {}
                Ok(output) => error!(
                    sl!(),
                    "remove dm-linear device {}: {}",
                    self.name,
                    String::from_utf8_lossy(&output.stderr)
                ),
                Err(error) => error!(sl!(), "remove dm-linear device {}: {error}", self.name),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(path: PathBuf) -> ErofsLayer {
        ErofsLayer {
            path: path.display().to_string(),
            size_sectors: 8,
            snapshot_id: "test".to_string(),
        }
    }

    #[tokio::test]
    #[ignore = "requires root, loop and device-mapper linear/zero support"]
    async fn readonly_mapping_and_deferred_cleanup() {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        std::fs::write(&first, vec![0x11; 4096]).unwrap();
        std::fs::write(&second, vec![0x22; 4096]).unwrap();
        let (layout, metadata) = generate_gpt_metadata(
            "sandbox",
            "container",
            vec![layer(first), layer(second)],
            directory.path(),
        )
        .unwrap();
        let disk = LinearDisk::create(
            format!("kata-erofs-test-{}", uuid::Uuid::new_v4().simple()),
            &layout,
            &metadata,
        )
        .await
        .unwrap();
        let mut reader = File::open(disk.path()).unwrap();
        let dev = reader.metadata().unwrap().rdev();
        let sysfs = PathBuf::from(format!(
            "/sys/dev/block/{}:{}",
            libc::major(dev),
            libc::minor(dev)
        ));
        let mut bytes = vec![0; (layout.total_sectors * SECTOR_SIZE) as usize];
        reader.read_exact(&mut bytes).unwrap();
        let head = std::fs::read(&metadata.head_path).unwrap();
        assert_eq!(&bytes[..head.len()], head);
        let first_start = (layout.partitions[0].start_lba * SECTOR_SIZE) as usize;
        let second_start = (layout.partitions[1].start_lba * SECTOR_SIZE) as usize;
        assert_eq!(&bytes[first_start..first_start + 4096], vec![0x11; 4096]);
        assert!(bytes[first_start + 4096..second_start]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(&bytes[second_start..], vec![0x22; 4096]);
        assert_eq!(
            std::fs::read_to_string(sysfs.join("ro")).unwrap().trim(),
            "1"
        );
        disk.release().unwrap();
        assert!(
            sysfs.exists(),
            "mapping must remain while the VMM-like reader is open"
        );
        drop(reader);
        tokio::time::timeout(Duration::from_secs(2), async {
            while sysfs.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("deferred dm-linear device was not removed");
    }

    #[tokio::test]
    #[ignore = "requires root, host loop devices and losetup"]
    async fn partial_setup_releases_loop_backings() {
        let directory = tempfile::tempdir().unwrap();
        let (layout, metadata) = generate_gpt_metadata(
            "sandbox",
            "container",
            vec![layer(directory.path().join("missing"))],
            directory.path(),
        )
        .unwrap();
        let result = LinearDisk::create(
            format!("kata-erofs-test-{}", uuid::Uuid::new_v4().simple()),
            &layout,
            &metadata,
        )
        .await;
        assert!(result.is_err());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let output = Command::new("losetup")
                    .arg("--associated")
                    .arg(&metadata.head_path)
                    .args(["--noheadings", "--output", "NAME"])
                    .kill_on_drop(true)
                    .output()
                    .await
                    .unwrap();
                assert!(
                    output.status.success(),
                    "losetup failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                if output.stdout.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("partial setup retained a loop backing");
    }
}
