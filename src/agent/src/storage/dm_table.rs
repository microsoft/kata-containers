// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-5 — read a block device's *live* device-mapper target stack.
//!
//! FR-5 classifies scratch by what the kernel actually stacked rather than by what the host
//! claimed, so this module has to obtain the truth from the kernel. It originally shelled out
//! to `dmsetup table`, which does not work: `dmsetup` is a separate package from
//! `cryptsetup-bin`, and the confidential guest rootfs installs only the latter
//! (`tools/osbuilder/rootfs-builder/ubuntu/config.sh`). The NVIDIA rootfs installs `dmsetup`
//! explicitly, which is what made the omission visible. Because the verification failed
//! closed, the effect was that *encrypted* scratch was refused too — the control could never
//! succeed on the shipped image.
//!
//! Talking to `/dev/mapper/control` directly removes the dependency on a binary that is not
//! there, and on `PATH` resolution inside the guest. `DM_TABLE_STATUS` returns the live table,
//! so what is classified is what the kernel is running, not what someone intended to build.

use anyhow::{anyhow, Context, Result};
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// The device-mapper control node. Present whenever the dm driver is loaded, which it must be
/// for a dm-crypt scratch device to exist at all.
const DM_CONTROL: &str = "/dev/mapper/control";

/// `DM_IOCTL` — the ioctl type byte shared by every device-mapper command.
const DM_IOCTL_TYPE: u8 = 0xfd;

/// `DM_TABLE_STATUS_CMD`, the 13th entry (0-based 12) of the kernel's device-mapper command
/// enum in `include/uapi/linux/dm-ioctl.h`.
const DM_TABLE_STATUS_CMD: u8 = 12;

/// `sizeof(struct dm_ioctl)`. The kernel deliberately keeps this identical across 32- and
/// 64-bit builds, and it is encoded into the ioctl request number, so a mismatch here does not
/// silently misparse — it fails the ioctl outright.
const DM_IOCTL_SIZE: usize = 312;

/// `DM_VERSION_MAJOR`. The kernel rejects a request whose major version it does not implement,
/// and reports the version it does speak back in the same field.
const DM_VERSION_MAJOR: u32 = 4;

// Byte offsets within `struct dm_ioctl`.
const OFF_DATA_SIZE: usize = 12;
const OFF_DATA_START: usize = 16;
const OFF_TARGET_COUNT: usize = 20;
const OFF_NAME: usize = 48;
const DM_NAME_LEN: usize = 128;

// Byte offsets within `struct dm_target_spec`.
const TARGET_SPEC_SIZE: usize = 40;
const OFF_SPEC_NEXT: usize = 20;
const OFF_SPEC_TYPE: usize = 24;
const DM_MAX_TYPE_NAME: usize = 16;

/// Header plus every target's spec and status string. A scratch volume has a handful of
/// targets at most; 16 KiB is far more than dm-crypt over dm-integrity needs.
const BUF_LEN: usize = 16 * 1024;

// `request_code_readwrite!` encodes the direction and size the way the *target architecture*
// does, which is not uniform (powerpc and mips do not use the asm-generic layout). Hand-rolling
// the encoding would build fine and fail at runtime on those arches.
nix::ioctl_readwrite_bad!(
    dm_table_status,
    nix::request_code_readwrite!(DM_IOCTL_TYPE, DM_TABLE_STATUS_CMD, DM_IOCTL_SIZE),
    u8
);

fn read_u32(buf: &[u8], off: usize) -> Result<u32> {
    let bytes = buf
        .get(off..off + 4)
        .ok_or_else(|| anyhow!("device-mapper response truncated at offset {off}"))?;
    Ok(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Extract the target types from a `DM_TABLE_STATUS` response buffer, outermost first.
///
/// Each target is a `struct dm_target_spec` followed by a NUL-terminated status string. `next`
/// is the offset of the following spec *relative to `data_start`*, not to the current spec —
/// the kernel computes it as `outptr - outbuf` in `retrieve_status()`.
fn parse_target_types(buf: &[u8]) -> Result<Vec<String>> {
    let data_start = read_u32(buf, OFF_DATA_START)? as usize;
    let target_count = read_u32(buf, OFF_TARGET_COUNT)? as usize;

    let mut targets = Vec::with_capacity(target_count);
    let mut offset = data_start;

    for i in 0..target_count {
        let spec = buf
            .get(offset..offset + TARGET_SPEC_SIZE)
            .ok_or_else(|| anyhow!("device-mapper target {i} lies outside the response"))?;

        let name = &spec[OFF_SPEC_TYPE..OFF_SPEC_TYPE + DM_MAX_TYPE_NAME];
        let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        targets.push(String::from_utf8_lossy(&name[..end]).into_owned());

        let next = read_u32(spec, OFF_SPEC_NEXT)? as usize;
        // A zero or backwards `next` on a non-final target would loop forever.
        if i + 1 < target_count && next <= offset.saturating_sub(data_start) {
            return Err(anyhow!(
                "device-mapper response does not advance past target {i}"
            ));
        }
        offset = data_start + next;
    }

    Ok(targets)
}

/// The live device-mapper target types stacked on `dm_name`.
///
/// An error means the table could not be read, which is deliberately distinct from reading it
/// and finding no encryption: the caller must not report a broken checker as a plaintext
/// volume.
pub fn live_target_types(dm_name: &str) -> Result<Vec<String>> {
    let name = dm_name.as_bytes();
    if name.is_empty() || name.len() >= DM_NAME_LEN {
        return Err(anyhow!(
            "device-mapper name {:?} does not fit struct dm_ioctl",
            dm_name
        ));
    }

    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DM_CONTROL)
        .with_context(|| format!("open {DM_CONTROL}"))?;

    let mut buf = vec![0u8; BUF_LEN];
    buf[0..4].copy_from_slice(&DM_VERSION_MAJOR.to_ne_bytes());
    buf[OFF_DATA_SIZE..OFF_DATA_SIZE + 4].copy_from_slice(&(BUF_LEN as u32).to_ne_bytes());
    buf[OFF_DATA_START..OFF_DATA_START + 4].copy_from_slice(&(DM_IOCTL_SIZE as u32).to_ne_bytes());
    buf[OFF_NAME..OFF_NAME + name.len()].copy_from_slice(name);

    // SAFETY: `control` is an open handle to the device-mapper control node and `buf` is a
    // live allocation of `BUF_LEN` bytes whose header declares that same size in `data_size`.
    // The kernel writes only within those bytes, and `buf` outlives the call.
    unsafe { dm_table_status(control.as_raw_fd(), buf.as_mut_ptr()) }
        .with_context(|| format!("DM_TABLE_STATUS for {dm_name}"))?;

    parse_target_types(&buf)
}

fn dm_name_at(sys_block: &Path, major: u64, minor: u64) -> Result<Option<String>> {
    let path: PathBuf = sys_block.join(format!("{major}:{minor}")).join("dm/name");
    match std::fs::read_to_string(&path) {
        Ok(name) => Ok(Some(name.trim().to_string())),
        // `dm/` exists only for device-mapper devices, so its absence is not an error: it is
        // the answer. Anything else genuinely failed and must not be read as "not encrypted".
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Resolve a device number to its device-mapper name, or `None` if it is not a dm device.
pub fn dm_name_for_dev(major: u64, minor: u64) -> Result<Option<String>> {
    dm_name_at(Path::new("/sys/dev/block"), major, minor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `DM_TABLE_STATUS` response the way the kernel lays one out.
    fn response(targets: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = vec![0u8; BUF_LEN];
        buf[OFF_DATA_START..OFF_DATA_START + 4]
            .copy_from_slice(&(DM_IOCTL_SIZE as u32).to_ne_bytes());
        buf[OFF_TARGET_COUNT..OFF_TARGET_COUNT + 4]
            .copy_from_slice(&(targets.len() as u32).to_ne_bytes());

        let mut offset = DM_IOCTL_SIZE;
        for (ty, params) in targets {
            let spec = offset;
            buf[spec + OFF_SPEC_TYPE..spec + OFF_SPEC_TYPE + ty.len()]
                .copy_from_slice(ty.as_bytes());
            let params_at = spec + TARGET_SPEC_SIZE;
            buf[params_at..params_at + params.len()].copy_from_slice(params.as_bytes());
            // Advance past the NUL and round up to 8, as `align_ptr` does.
            offset = (params_at + params.len() + 1 + 7) & !7;
            let next = (offset - DM_IOCTL_SIZE) as u32;
            buf[spec + OFF_SPEC_NEXT..spec + OFF_SPEC_NEXT + 4]
                .copy_from_slice(&next.to_ne_bytes());
        }
        buf
    }

    #[test]
    fn a_single_crypt_target_is_read_back() {
        let buf = response(&[("crypt", "aes-xts-plain64 0000 0 8:16 0")]);
        assert_eq!(parse_target_types(&buf).unwrap(), vec!["crypt".to_string()]);
    }

    /// The whole point of walking `next` rather than striding by a fixed size: the status
    /// strings differ in length, so a second target is only found if the walk is correct.
    #[test]
    fn a_stacked_crypt_and_integrity_table_is_read_back() {
        let buf = response(&[
            ("crypt", "aes-xts-plain64 0 0 8:16 0 1 integrity:28:aead"),
            ("integrity", "8:16 0 J 2"),
        ]);
        assert_eq!(
            parse_target_types(&buf).unwrap(),
            vec!["crypt".to_string(), "integrity".to_string()]
        );
    }

    #[test]
    fn a_linear_table_is_read_back() {
        let buf = response(&[("linear", "8:16 0")]);
        assert_eq!(
            parse_target_types(&buf).unwrap(),
            vec!["linear".to_string()]
        );
    }

    /// A target type occupying the full 16 bytes has no NUL terminator.
    #[test]
    fn an_unterminated_target_type_does_not_overrun() {
        let mut buf = response(&[("crypt", "x")]);
        let ty = DM_IOCTL_SIZE + OFF_SPEC_TYPE;
        buf[ty..ty + DM_MAX_TYPE_NAME].copy_from_slice(b"0123456789abcdef");
        assert_eq!(
            parse_target_types(&buf).unwrap(),
            vec!["0123456789abcdef".to_string()]
        );
    }

    /// A malformed response must fail, not spin or panic. Failing is safe: the caller reports
    /// "could not verify" and refuses the mount.
    #[test]
    fn a_non_advancing_response_is_rejected_rather_than_looping() {
        let mut buf = response(&[("crypt", "a"), ("crypt", "b")]);
        buf[DM_IOCTL_SIZE + OFF_SPEC_NEXT..DM_IOCTL_SIZE + OFF_SPEC_NEXT + 4]
            .copy_from_slice(&0u32.to_ne_bytes());
        assert!(parse_target_types(&buf).is_err());
    }

    #[test]
    fn a_target_count_beyond_the_buffer_is_rejected() {
        let mut buf = response(&[("crypt", "a")]);
        buf[OFF_TARGET_COUNT..OFF_TARGET_COUNT + 4].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(parse_target_types(&buf).is_err());
    }

    #[test]
    fn a_non_device_mapper_device_reports_absence_not_failure() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(dm_name_at(dir.path(), 8, 16).unwrap(), None);
    }

    #[test]
    fn a_device_mapper_device_resolves_to_its_name() {
        let dir = tempfile::tempdir().unwrap();
        let dm = dir.path().join("254:0").join("dm");
        std::fs::create_dir_all(&dm).unwrap();
        std::fs::write(dm.join("name"), "scratch-0\n").unwrap();
        assert_eq!(
            dm_name_at(dir.path(), 254, 0).unwrap(),
            Some("scratch-0".to_string())
        );
    }

    /// Pins the request number, and with it `sizeof(struct dm_ioctl)`. If the struct layout
    /// assumed here ever drifts from the kernel's, this fails at build time rather than
    /// producing an ioctl the kernel rejects at runtime.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "s390x"))]
    fn the_request_number_matches_the_kernel_encoding() {
        let expected: u64 = (3 << 30) | ((DM_IOCTL_SIZE as u64) << 16) | (0xfd << 8) | 12;
        assert_eq!(
            nix::request_code_readwrite!(DM_IOCTL_TYPE, DM_TABLE_STATUS_CMD, DM_IOCTL_SIZE),
            expected
        );
    }

    /// Hardware proof that the ioctl path talks to a real kernel device-mapper stack.
    /// Requires root and a live dm device; run explicitly:
    ///
    /// ```text
    /// FR5_DM_NAME=<name> cargo test --features strict-policy \
    ///     live_dm_device -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn live_dm_device_reports_its_targets() {
        let name = std::env::var("FR5_DM_NAME").expect("set FR5_DM_NAME to a live dm device");
        let targets = live_target_types(&name).expect("reading the live table");
        println!("dm {} -> {:?}", name, targets);
        assert!(!targets.is_empty(), "a live device must report a target");
    }
}
