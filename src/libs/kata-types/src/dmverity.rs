// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//
//

use anyhow::{anyhow, Context, Result};
use devicemapper::{DevId, DmFlags, DmName, DmOptions, DmUdevFlags, DM};
use nix::sys::stat::{self, Mode, SFlag};
use slog::Logger;
use std::convert::TryFrom;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::time::sleep;

pub use crate::mount::DmVerityInfo;

/// Detect whether udevd is running in the guest.
///
/// Checks for the udevd control socket — its presence reliably indicates a
/// running udevd. The result is cached for the process lifetime since udev
/// availability does not change after boot.
pub fn has_udev() -> bool {
    static UDEV_AVAILABLE: OnceLock<bool> = OnceLock::new();
    *UDEV_AVAILABLE.get_or_init(|| Path::new("/run/udev/control").exists())
}

/// DmOptions with all udev interactions disabled, for use when udev is not running.
fn no_udev_dm_options() -> DmOptions {
    DmOptions::default().set_udev_flags(
        DmUdevFlags::DM_UDEV_DISABLE_LIBRARY_FALLBACK
            | DmUdevFlags::DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG
            | DmUdevFlags::DM_UDEV_DISABLE_DISK_RULES_FLAG
            | DmUdevFlags::DM_UDEV_DISABLE_OTHER_RULES_FLAG
            | DmUdevFlags::DM_UDEV_DISABLE_DM_RULES_FLAG,
    )
}

/// DmOptions for creating a read-only dm-verity device: udev-aware.
fn dm_opts_readonly() -> DmOptions {
    no_udev_dm_options().set_flags(DmFlags::DM_READONLY)
}

/// DmOptions for deferred device removal: udev-aware.
fn dm_opts_deferred_remove() -> DmOptions {
    no_udev_dm_options().set_flags(DmFlags::DM_DEFERRED_REMOVE)
}

/// DmOptions for creating a dm-verity device, with appropriate flags based on udev availability.
#[allow(dead_code)]
fn dm_create_options() -> DmOptions {
    if has_udev() {
        DmOptions::default().set_flags(DmFlags::DM_READONLY)
    } else {
        dm_opts_readonly()
    }
}

/// DmOptions for device suspend/resume: udev-aware.
#[allow(dead_code)]
fn dm_suspend_options() -> DmOptions {
    if has_udev() {
        DmOptions::default()
    } else {
        no_udev_dm_options()
    }
}

/// DmOptions for deferred device removal: udev-aware.
fn dm_remove_options() -> DmOptions {
    if has_udev() {
        DmOptions::default().set_flags(DmFlags::DM_DEFERRED_REMOVE)
    } else {
        dm_opts_deferred_remove()
    }
}

/// Create a block device node for a dm-verity device using mknod(2).
pub fn create_dm_dev_node(name: &str, dev: devicemapper::Device) -> Result<String> {
    let mapper_dir = Path::new("/dev/mapper");
    if !mapper_dir.exists() {
        std::fs::create_dir_all(mapper_dir)
            .with_context(|| format!("failed to create directory {}", mapper_dir.display()))?;
    }

    let dev_path = format!("/dev/mapper/{}", name);
    if Path::new(&dev_path).exists() {
        std::fs::remove_file(&dev_path)
            .with_context(|| format!("failed to remove stale device node {}", dev_path))?;
    }

    let dev_t: nix::libc::dev_t = dev.into();
    stat::mknod(
        dev_path.as_str(),
        SFlag::S_IFBLK,
        Mode::from_bits_truncate(0o600),
        dev_t,
    )
    .with_context(|| format!("failed to mknod block device {}", dev_path))?;

    Ok(dev_path)
}

/// Remove a device node created by `create_dm_dev_node`.
pub fn remove_dm_dev_node(dev_path: &str) {
    if dev_path.starts_with("/dev/mapper/") && Path::new(dev_path).exists() {
        if let Err(e) = std::fs::remove_file(dev_path) {
            slog::warn!(
                slog_scope::logger(),
                "failed to remove dm device node";
                "path" => dev_path,
                "error" => %e,
            );
        }
    }
}

/// Generate a unique dm-verity device name from source path and verity hash.
pub fn build_dmverity_device_name(source_device_path: &Path, verity_info: &DmVerityInfo) -> String {
    let source_short = source_device_path
        .file_name()
        .map(|f| f.to_string_lossy())
        .unwrap_or_default();
    let hash_prefix = &verity_info.hash[..verity_info.hash.len().min(32)];
    let mut name = format!(
        "kata-verity-{}-off{}-{}",
        source_short, verity_info.offset, hash_prefix
    );
    name.truncate(128);
    name
}

/// Result of dm-verity device setup.
type DmSetupResult = String;

/// Destroy a dm-verity device by name.
pub fn destroy_dmverity_device(verity_device_name: &str) -> Result<()> {
    let dm = devicemapper::DM::new()?;
    let name = devicemapper::DmName::new(verity_device_name)?;

    dm.device_remove(&devicemapper::DevId::Name(name), dm_remove_options())
        .context(format!("remove DmverityDevice {}", verity_device_name))?;

    Ok(())
}

/// Destroy a dm-verity device by its `/dev/mapper/` path.
pub fn destroy_partition_dmverity_device(verity_device_path: &str, logger: &Logger) -> Result<()> {
    // The verity device path is /dev/mapper/<name> (as created by create_dm_dev_node).
    // Extract the DM device name for removal. Also remove the mknod-created device node.
    let device_name = verity_device_path
        .strip_prefix("/dev/mapper/")
        .unwrap_or(verity_device_path)
        .to_string();

    destroy_dmverity_device(&device_name).context("Failed to destroy dm-verity device")?;
    info!(
        logger,
        "Destroying dm-verity device";
        "device-name" => &device_name,
    );

    // Only remove the device node manually if we created it via mknod.
    // When udev is running, it handles node lifecycle automatically.
    if !has_udev() {
        remove_dm_dev_node(verity_device_path);
    }

    Ok(())
}

/// Clean up all dm-verity devices for a multi-layer EROFS mount.
pub fn cleanup_dmverity_devices(verity_devices: &[String], logger: &Logger) {
    info!(
        logger,
        "Cleaning up {} dm-verity devices",
        verity_devices.len()
    );

    // Destroy in reverse order
    for verity_device in verity_devices.iter().rev() {
        if let Err(e) = destroy_partition_dmverity_device(verity_device, logger) {
            warn!(
                logger,
                "Failed to destroy dm-verity device";
                "device-path" => verity_device,
                "error" => format!("{:#}", e),
            );
        }
    }

    info!(logger, "dm-verity device cleanup completed");
}

/// Wait for udev to create a device-mapper node under `/dev/mapper/`.
pub async fn wait_for_dm_dev_node(name: &str) -> Result<String> {
    let dev_path = format!("/dev/mapper/{}", name);
    let path = Path::new(&dev_path);

    if path.exists() {
        return Ok(dev_path);
    }

    const MAX_WAIT_MS: u64 = 2000;
    const POLL_INTERVAL_MS: u64 = 50;

    for _attempt in 0..(MAX_WAIT_MS / POLL_INTERVAL_MS) {
        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
        if path.exists() {
            return Ok(dev_path);
        }
    }

    Err(anyhow!(
        "udev did not create dm device node {} within {} ms",
        dev_path,
        MAX_WAIT_MS
    ))
}

/// Index of the root digest in a dm-verity target table line.
///
/// The verity table is ten space-separated fields:
/// `version data_dev hash_dev data_block_size hash_block_size num_data_blocks
///  hash_start_block algorithm root_digest salt`
const VERITY_TABLE_ROOT_DIGEST_FIELD: usize = 8;

/// Number of fields in a dm-verity target table line (optional trailing feature
/// arguments may follow, so this is a minimum rather than an exact count).
const VERITY_TABLE_MIN_FIELDS: usize = 10;

/// Extract the root digest from a dm-verity target table line as reported by the kernel.
fn table_root_digest(table_params: &str) -> Result<&str> {
    let fields: Vec<&str> = table_params.split_whitespace().collect();
    if fields.len() < VERITY_TABLE_MIN_FIELDS {
        return Err(anyhow!(
            "dm-verity table has {} fields, expected at least {}: {:?}",
            fields.len(),
            VERITY_TABLE_MIN_FIELDS,
            table_params
        ));
    }
    Ok(fields[VERITY_TABLE_ROOT_DIGEST_FIELD])
}

/// RM-52: confirm the root hash the kernel is actually enforcing is the one the policy
/// approved.
///
/// The kernel faithfully enforces whatever root hash it was handed; it has no way to know
/// that hash came from the policy. This closes that gap from the other side by reading the
/// *active* table back out of the kernel and comparing the digest in force against the
/// expected value, so a mismatch introduced anywhere between the policy check and the
/// ioctl — a formatting bug, a wrong variable, a stale device — is caught rather than
/// silently enforcing the wrong content.
fn verify_table_root_digest(table_params: &str, expected_hash: &str) -> Result<()> {
    let in_force = table_root_digest(table_params)?;
    if !in_force.eq_ignore_ascii_case(expected_hash.trim()) {
        return Err(anyhow!(
            "dm-verity root hash read back from the active table does not match the \
             policy-approved hash: in force {:?}, expected {:?}. Refusing to use this device.",
            in_force,
            expected_hash
        ));
    }
    Ok(())
}

/// Create a dm-verity device using devicemapper, offloading blocking ioctls to a dedicated thread.
pub async fn create_dmverity_device(
    verity_info: &DmVerityInfo,
    source_device_path: &Path,
) -> Result<String> {
    let verity_info = verity_info.clone();
    let source_path = source_device_path.to_path_buf();

    let verity_name_string = build_dmverity_device_name(&source_path, &verity_info);
    // Owned copy for the read-back inside the closure: `verity_info` itself is still needed
    // after the closure has consumed its clone.
    let expected_root_hash = verity_info.hash.clone();
    let data_blocksize = verity_info.blocksize;

    // Offload all blocking ioctl operations to a dedicated thread.
    // Always use no-udev DmOptions inside spawn_blocking to avoid DM_UDEV_WAIT
    // blocking on udevd event processing. When udev is running, we wait for the
    // device node asynchronously after the ioctl completes (via wait_for_dm_dev_node).
    let dev_path = tokio::task::spawn_blocking(move || -> Result<DmSetupResult> {
        let dm = DM::new()?;
        let verity_name = DmName::new(&verity_name_string)?;
        let id = DevId::Name(verity_name);

        let opts = no_udev_dm_options();
        let ro_opts = dm_opts_readonly();

        // Step 0: Remove stale device if it already exists
        let remove_opts = dm_opts_deferred_remove();
        if dm.device_remove(&id, remove_opts).is_ok() {
            // Stale device removed; continue with creation.
        }

        // Step 1: Create device as read-only
        dm.device_create(verity_name, None, ro_opts)?;

        // Calculate hash start block.
        let hash_start_block: u64 = if verity_info.no_superblock {
            verity_info.offset / verity_info.hashsize
        } else {
            let superblock_blocks = 512_u64.div_ceil(verity_info.hashsize);
            (verity_info.offset / verity_info.hashsize) + superblock_blocks
        };

        let salt = verity_info.salt.as_deref().unwrap_or("-");
        let source_display = source_path.display().to_string();
        let verity_params = format!(
            "{} {} {} {} {} {} {} {} {} {}",
            verity_info.hash_type,
            source_display,
            source_display,
            verity_info.blocksize,
            verity_info.hashsize,
            verity_info.blocknum,
            hash_start_block,
            verity_info.hashtype,
            verity_info.hash,
            salt
        );

        let verity_table = vec![(
            0,
            verity_info.blocknum * verity_info.blocksize / 512,
            "verity".into(),
            verity_params.clone(),
        )];

        info!(
            slog_scope::logger(),
            "dm-verity table parameters";
            "device" => &source_display,
            "data_blocks" => verity_info.blocknum,
            "data_block_size" => verity_info.blocksize,
            "hash_block_size" => verity_info.hashsize,
            "hash_start_block" => hash_start_block,
            "hash_algorithm" => &verity_info.hashtype,
            "hash_type" => verity_info.hash_type,
            "no_superblock" => verity_info.no_superblock,
            "salt" => salt,
            "table_params" => &verity_params,
        );

        // Step 2: Load table and resume (activate)
        dm.table_load(&id, verity_table.as_slice(), ro_opts)?;
        dm.device_suspend(&id, opts)?;

        // Step 2b (RM-52): read the *active* table back and confirm the root hash the kernel
        // is enforcing is the one we were asked to enforce. See `verify_table_root_digest`.
        let (_, active) = dm
            .table_status(
                &id,
                DmOptions::default().set_flags(DmFlags::DM_STATUS_TABLE),
            )
            .context("failed to read back the active dm-verity table")?;
        let verity_target = active
            .iter()
            .find(|(_, _, target_type, _)| target_type == "verity")
            .ok_or_else(|| {
                anyhow!("no verity target in the active dm table for {verity_name_string}")
            })?;
        verify_table_root_digest(&verity_target.3, &expected_root_hash)?;

        // Step 3: Create the device node under /dev/mapper/.
        //
        // This is done unconditionally, and deliberately does not depend on whether udevd is
        // running. Device creation above always passes `no_udev_dm_options()`, which sets
        // DM_UDEV_DISABLE_DM_RULES_FLAG — udev is explicitly told *not* to manage this
        // device, so waiting for udev to create the node can only ever time out. Doing that
        // left the mapping live in the kernel with no usable node and no cleanup, so on any
        // host or guest where udevd happens to be running every dm-verity mount failed and
        // leaked a device. Since we disable the rules, we own the node.
        let device_info = dm.device_info(&id)?;
        create_dm_dev_node(&verity_name_string, device_info.device())
    })
    .await
    .context("spawn_blocking for dm-verity ioctl panicked")??;

    // RM-52: force the kernel to prove, now, that this device's hash tree actually roots at
    // the policy-approved hash.
    //
    // dm-verity verifies lazily: the table loads happily against a device whose hash tree
    // roots somewhere else entirely, and the mismatch only surfaces as an opaque EIO on the
    // first read of a data block. Reading one block here converts that into an immediate,
    // named failure at mount time. This is what "compare the device's root hash against the
    // policy" really amounts to -- the kernel hashes the block and walks the tree to the
    // supplied root, which is strictly stronger than re-deriving a root digest in userspace
    // and comparing, because it verifies the bytes actually being served.
    verify_first_block(&dev_path, data_blocksize).await?;

    Ok(dev_path)
}

/// Read the first data block through the verity device, so the kernel verifies its hash
/// chain up to the root digest before anything mounts or executes from it.
async fn verify_first_block(dev_path: &str, blocksize: u64) -> Result<()> {
    use std::io::Read;

    let path = dev_path.to_string();
    // A block size of 0 would mean a malformed table; the kernel would have rejected it, but
    // guard rather than construct a zero-length read that trivially "succeeds".
    let len = usize::try_from(blocksize).context("dm-verity block size does not fit in usize")?;
    if len == 0 {
        return Err(anyhow!(
            "dm-verity block size is 0 for {dev_path}; refusing to skip verification"
        ));
    }

    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut f = std::fs::File::open(&path)
            .with_context(|| format!("failed to open verity device {path} for verification"))?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).map_err(|e| {
            anyhow!(
                "dm-verity verification read failed on {}: {}. The device's hash tree does \
                 not match the policy-approved root hash, or the device is corrupt.",
                path,
                e
            )
        })?;
        Ok(())
    })
    .await
    .context("spawn_blocking for dm-verity verification read panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "c59e4fec79c754743340241f1a3656c1d858eb7934bfadceb770410a85b48f28";

    /// A real verity table line as the kernel reports it: the device fields come back as
    /// major:minor rather than the paths we passed in, which is exactly why the root digest
    /// is located positionally rather than by matching what we sent.
    fn table_line(hash: &str) -> String {
        format!("1 254:0 254:0 4096 4096 1986 1986 sha256 {hash} 0000000000000000000000000000000000000000000000000000000000000000")
    }

    #[test]
    fn root_digest_is_read_from_the_right_field() {
        assert_eq!(table_root_digest(&table_line(HASH)).unwrap(), HASH);
    }

    #[test]
    fn matching_root_digest_is_accepted() {
        verify_table_root_digest(&table_line(HASH), HASH).unwrap();
    }

    /// The whole point of the read-back: if the digest the kernel is enforcing is not the one
    /// the policy approved, refuse the device rather than serve content bound to some other
    /// hash.
    #[test]
    fn mismatched_root_digest_is_rejected() {
        let other = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44";
        let err = verify_table_root_digest(&table_line(other), HASH).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does not match the policy-approved hash"),
            "{}",
            msg
        );
        assert!(
            msg.contains(other),
            "error must name the hash actually in force: {}",
            msg
        );
    }

    /// A single flipped nibble must not pass.
    #[test]
    fn near_miss_root_digest_is_rejected() {
        let near = format!("0{}", &HASH[1..]);
        assert_ne!(near, HASH);
        verify_table_root_digest(&table_line(&near), HASH).unwrap_err();
    }

    /// The kernel lower-cases hex digests; a declaration that spelled the hash in upper case
    /// names the same content and must not be treated as a mismatch.
    #[test]
    fn root_digest_comparison_ignores_case_and_surrounding_space() {
        verify_table_root_digest(&table_line(HASH), &format!("  {}  ", HASH.to_uppercase()))
            .unwrap();
    }

    /// A truncated table must be an error, not an out-of-bounds index or a silent pass.
    #[test]
    fn malformed_table_is_rejected() {
        let err = verify_table_root_digest("1 254:0 254:0 4096", HASH).unwrap_err();
        assert!(format!("{err:#}").contains("expected at least"));
    }

    /// dm-verity tables may carry optional feature arguments after the salt; the digest is
    /// still at a fixed offset, so trailing fields must not disturb it.
    #[test]
    fn trailing_feature_arguments_do_not_shift_the_digest() {
        let line = format!(
            "{} 2 restart_on_corruption ignore_zero_blocks",
            table_line(HASH)
        );
        assert_eq!(table_root_digest(&line).unwrap(), HASH);
    }
}
