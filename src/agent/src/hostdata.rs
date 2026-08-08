// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! # In-guest binding of initdata to the launch measurement
//!
//! The host stamps the initdata digest into the confidential VM's launch configuration
//! (`HOSTDATA` on SEV-SNP, `MRCONFIGID` on TDX). Until now the guest computed the same
//! digest and discarded it, so nothing inside the guest ever checked that the initdata it
//! actually consumed was the initdata the VM was launched with. Detection was deferred to a
//! remote verifier at attestation time, which gates secret release but does not stop the
//! guest from running under host-chosen initdata in the meantime.
//!
//! This module closes that gap: it reads the local TEE report through configfs-TSM and
//! compares the reported value against the digest computed from the initdata the agent
//! parsed. On mismatch the VM is aborted. This is the equivalent of hcsshim's
//! `amdsevsnp.ValidateHostData()` check.
//!
//! On SEV-SNP, configfs-TSM (`CONFIG_TSM_REPORTS`) only exists from Linux 6.7. The guest
//! kernels this stack ships are older, so there is a second, equivalent path: the
//! `SNP_GET_REPORT` ioctl on `/dev/sev-guest`, which is how the report was fetched before
//! configfs-TSM existed and which 6.7+ kernels still support. Both are serviced by the PSP
//! via a firmware call from the guest, so neither depends on the host and the check stays
//! fail-closed either way.
//!
//! When no TEE report provider is present the guest is not a confidential VM, so there is
//! no launch measurement to bind to and nothing to verify; the check logs and returns.

use anyhow::{anyhow, bail, Context, Result};
use slog::Logger;
use std::fs;
use std::path::{Path, PathBuf};

/// configfs-TSM report directory, relative to [`fs_root`]. Present when the guest kernel
/// exposes a TEE report provider (CONFIG_TSM_REPORTS) and configfs is mounted.
const TSM_REPORT_DIR: &str = "sys/kernel/config/tsm/report";

/// Name of the report entry this module creates. Removed again once the report is read.
const TSM_REPORT_ENTRY: &str = "kata-agent-initdata";

/// configfs-TSM requires `inblob` to be exactly 64 bytes.
const TSM_INBLOB_LEN: usize = 64;

/// Root the TEE sysfs/configfs paths are resolved against. Always `/` in a shipped agent.
///
/// The `tsm-test-override` feature -- deliberately not implied by `strict-policy` and never
/// enabled in a released image -- allows redirecting it so the binding can be demonstrated
/// against a fake TEE tree on a build host. It must stay opt-in: the agent's environment is
/// host-influenced, so honouring the variable unconditionally would hand the host a way to
/// point the check at a tree it controls.
fn fs_root() -> PathBuf {
    #[cfg(feature = "tsm-test-override")]
    if let Ok(root) = std::env::var("KATA_AGENT_TSM_ROOT") {
        return PathBuf::from(root);
    }

    PathBuf::from("/")
}

/// Offset and length of `HOST_DATA` within an SEV-SNP attestation report (Table 22,
/// "SEV Secure Nested Paging Firmware ABI Specification"). The sev-guest TSM provider
/// returns the attestation report itself as `outblob`, so this offset is absolute.
const SNP_HOST_DATA_OFFSET: usize = 0xC0;
const SNP_HOST_DATA_LEN: usize = 32;

/// sysfs directory of the SEV-SNP guest driver (`DEVICE_NAME` in `sev-guest.c`), relative
/// to [`fs_root`].
const SEV_GUEST_DEV_DIR: &str = "sys/class/misc/sev-guest";

/// Character device exposed by the same driver, relative to [`fs_root`]. This is the
/// pre-configfs-TSM way to fetch an attestation report and the only one available on guest
/// kernels older than 6.7.
const SEV_GUEST_DEV: &str = "dev/sev-guest";

/// Offset of `struct snp_report` within `struct msg_report_resp`, the payload
/// `SNP_GET_REPORT` writes into `resp_data` (`u32 status`, `u32 report_size`, 24 reserved
/// bytes, then the report). Unlike configfs-TSM's `outblob`, which is the bare report, the
/// ioctl response carries this header, so [`SNP_HOST_DATA_OFFSET`] is relative to the slice
/// taken from here rather than to the buffer itself.
const SNP_REPORT_RESP_HDR_LEN: usize = 32;

/// sysfs directory of the TDX guest driver (`KBUILD_MODNAME` in `tdx-guest.c`), relative
/// to [`fs_root`].
const TDX_GUEST_DEV_DIR: &str = "sys/class/misc/tdx_guest";

/// `MRCONFIGID` as exposed by the kernel's tsm-mr measurement-register interface, relative
/// to `TDX_GUEST_DEV_DIR`. The attribute group is named "measurements", and because
/// `mrconfigid` is registered with `TSM_MR_F_NOHASH` its attribute name carries no `:hash`
/// suffix. The attribute is a binary attribute holding the raw 48-byte value.
///
/// This is deliberately preferred over parsing a TDX quote: `outblob` on TDX is produced by
/// a `GetQuote` hypercall serviced by the *host*, so it depends on host-side QGS, can stall
/// for seconds or fail outright at the host's discretion, and its layout is quote-version
/// dependent. The measurement register is read from the TDREPORT the TDX module produced,
/// entirely inside the guest.
const TDX_MRCONFIGID_ATTR: &str = "measurements/mrconfigid";
const TDX_MRCONFIGID_LEN: usize = 48;

/// The TEE report providers this module knows how to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    Snp,
    Tdx,
}

impl Provider {
    /// configfs-TSM reports the provider as e.g. "sev_guest" or "tdx_guest", sometimes with
    /// a trailing version suffix, so match on a prefix rather than the whole string.
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim().to_ascii_lowercase();
        if raw.starts_with("sev") {
            Some(Provider::Snp)
        } else if raw.starts_with("tdx") {
            Some(Provider::Tdx)
        } else {
            None
        }
    }

    /// Length the initdata digest is truncated or zero-padded to before being stamped into
    /// the launch configuration. Must match `adjust_digest()` in `kata-types`, which is what
    /// the runtime uses on the host side.
    fn measured_len(&self) -> usize {
        match self {
            Provider::Snp => SNP_HOST_DATA_LEN,
            Provider::Tdx => TDX_MRCONFIGID_LEN,
        }
    }

    fn field_name(&self) -> &'static str {
        match self {
            Provider::Snp => "HOSTDATA",
            Provider::Tdx => "MRCONFIGID",
        }
    }
}

/// RAII wrapper so the configfs report entry is removed even on an error path. Leaving
/// entries behind would make a later call fail with EEXIST.
struct ReportEntry {
    path: PathBuf,
}

impl ReportEntry {
    fn create() -> Result<Self> {
        let path = fs_root().join(TSM_REPORT_DIR).join(TSM_REPORT_ENTRY);
        // A stale entry from a previous (crashed) attempt would make create_dir fail.
        let _ = fs::remove_dir(&path);
        fs::create_dir(&path)
            .with_context(|| format!("create configfs-tsm report entry {}", path.display()))?;
        Ok(Self { path })
    }

    fn write_inblob(&self, nonce: &[u8; TSM_INBLOB_LEN]) -> Result<()> {
        fs::write(self.path.join("inblob"), nonce).context("write configfs-tsm inblob")
    }

    fn provider(&self) -> Result<String> {
        let raw =
            fs::read_to_string(self.path.join("provider")).context("read configfs-tsm provider")?;
        Ok(raw.trim().to_string())
    }

    fn outblob(&self) -> Result<Vec<u8>> {
        fs::read(self.path.join("outblob")).context("read configfs-tsm outblob")
    }
}

impl Drop for ReportEntry {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir(&self.path) {
            // Not fatal: the entry is only a scratch object, and a stale one is cleaned up
            // by the next create().
            eprintln!(
                "kata-agent: failed to remove configfs-tsm entry {}: {}",
                self.path.display(),
                e
            );
        }
    }
}

/// Extract `HOST_DATA` from an SEV-SNP attestation report.
fn extract_snp_host_data(report: &[u8]) -> Result<Vec<u8>> {
    report
        .get(SNP_HOST_DATA_OFFSET..SNP_HOST_DATA_OFFSET + SNP_HOST_DATA_LEN)
        .map(|slice| slice.to_vec())
        .ok_or_else(|| {
            anyhow!(
                "SEV-SNP report too short: need {} bytes to read HOSTDATA, got {}",
                SNP_HOST_DATA_OFFSET + SNP_HOST_DATA_LEN,
                report.len()
            )
        })
}

/// Read `MRCONFIGID` from the tsm-mr measurement register under `dev_dir`.
///
/// Fails closed when the attribute is absent: a TDX guest whose kernel predates the tsm-mr
/// interface gives us no host-independent way to read the launch configuration, and silently
/// continuing would leave the initdata unbound.
fn read_tdx_mrconfigid(dev_dir: &Path) -> Result<Vec<u8>> {
    let path = dev_dir.join(TDX_MRCONFIGID_ATTR);
    let value = fs::read(&path).with_context(|| {
        format!(
            "read {} -- the guest kernel does not expose MRCONFIGID through tsm-mr, so the \
             initdata cannot be bound to the launch measurement",
            path.display()
        )
    })?;

    if value.len() != TDX_MRCONFIGID_LEN {
        bail!(
            "{} has unexpected length {} (want {})",
            path.display(),
            value.len(),
            TDX_MRCONFIGID_LEN
        );
    }

    Ok(value)
}

/// Truncate or zero-pad the digest the same way the host does before stamping it into the
/// launch configuration. Mirrors `kata_types::initdata::adjust_digest`.
fn adjust_digest(digest: &[u8], len: usize) -> Vec<u8> {
    let mut adjusted = Vec::with_capacity(len);
    if digest.len() >= len {
        adjusted.extend_from_slice(&digest[..len]);
    } else {
        adjusted.extend_from_slice(digest);
        adjusted.resize(len, 0u8);
    }
    adjusted
}

/// Detect which TEE the guest is running under, from the presence of the guest driver's
/// sysfs directory. Returns `None` when neither is present, meaning this is not a
/// confidential VM.
fn detect_provider() -> Option<Provider> {
    let root = fs_root();
    if root.join(TDX_GUEST_DEV_DIR).is_dir() {
        Some(Provider::Tdx)
    } else if root.join(SEV_GUEST_DEV_DIR).is_dir() {
        Some(Provider::Snp)
    } else {
        None
    }
}

/// Read the launch-configuration field the initdata digest is stamped into.
///
/// Returns `Ok(None)` when the guest has no TEE provider, which means it is not a
/// confidential VM and there is no launch measurement to bind to.
fn read_measured_field(logger: &Logger) -> Result<Option<(Provider, Vec<u8>)>> {
    let Some(provider) = detect_provider() else {
        slog::info!(
            logger,
            "no TEE guest driver present; guest is not a confidential VM"
        );
        return Ok(None);
    };

    let value = match provider {
        // TDX exposes MRCONFIGID directly as a measurement register, read from the TDREPORT
        // without involving the host.
        Provider::Tdx => read_tdx_mrconfigid(&fs_root().join(TDX_GUEST_DEV_DIR))?,

        // SNP has no equivalent measurement register, but its attestation report is produced
        // by a local firmware call to the PSP, so fetching it through configfs-TSM does not
        // depend on the host either.
        Provider::Snp => {
            let report = read_snp_report(logger)?;
            extract_snp_host_data(&report)?
        }
    };

    slog::debug!(
        logger,
        "read launch measurement field";
        "field" => provider.field_name(),
        "bytes" => value.len()
    );

    Ok(Some((provider, value)))
}

/// `SNP_GET_REPORT` request body (`struct snp_report_req` in `include/uapi/linux/sev-guest.h`).
#[repr(C)]
struct SnpReportReq {
    /// Mixed into REPORT_DATA. A HOSTDATA comparison does not depend on it, and the report
    /// is read locally, so freshness is not a concern here; left zeroed.
    user_data: [u8; 64],
    /// VMPL to attest at. This stack runs the guest at VMPL0 (there is no SVSM), and the
    /// firmware rejects a request for a level more privileged than the caller's.
    vmpl: u32,
    rsvd: [u8; 28],
}

/// `SNP_GET_REPORT` response body (`struct snp_report_resp`). The kernel requires the full
/// 4000 bytes regardless of how much the firmware writes.
#[repr(C)]
struct SnpReportResp {
    data: [u8; 4000],
}

/// ioctl argument (`struct snp_guest_request_ioctl`). Not packed in the kernel header, so
/// `repr(C)` reproduces its layout, padding included.
#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    req_data: u64,
    resp_data: u64,
    /// `exitinfo2` in current kernels, `fw_err` in older ones. Same width and position, and
    /// non-zero means the firmware refused the request.
    exitinfo2: u64,
}

nix::ioctl_readwrite!(snp_get_report, b'S', 0x0, SnpGuestRequestIoctl);

/// Fetch the SEV-SNP attestation report through the `/dev/sev-guest` ioctl.
///
/// Used when the guest kernel has the sev-guest driver but not configfs-TSM. The report is
/// produced by the PSP in response to a firmware call made by the guest, exactly as in the
/// configfs path, so this is not a weaker source: the host cannot influence the result.
fn read_snp_report_ioctl(logger: &Logger, dev: &Path) -> Result<Vec<u8>> {
    use std::convert::TryInto;
    use std::os::unix::io::AsRawFd;

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev)
        .with_context(|| format!("open {}", dev.display()))?;

    let req = SnpReportReq {
        user_data: [0u8; 64],
        vmpl: 0,
        rsvd: [0u8; 28],
    };
    let mut resp = SnpReportResp { data: [0u8; 4000] };
    let mut arg = SnpGuestRequestIoctl {
        msg_version: 1,
        req_data: &req as *const SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        exitinfo2: 0,
    };

    // SAFETY: `file` is an open handle to the sev-guest device, and `arg` is a live,
    // correctly-typed value whose `req_data`/`resp_data` point at `req` and `resp`. All
    // three outlive the call, and the kernel writes only within `resp`.
    unsafe { snp_get_report(file.as_raw_fd(), &mut arg) }
        .with_context(|| format!("SNP_GET_REPORT on {}", dev.display()))?;

    // The ioctl can succeed while the firmware refuses the request, in which case the
    // response buffer is untouched and parsing it would read zeroes as a report.
    if arg.exitinfo2 != 0 {
        bail!(
            "SNP_GET_REPORT was rejected by firmware: exitinfo2 0x{:x}",
            arg.exitinfo2
        );
    }

    let status = u32::from_le_bytes(resp.data[0..4].try_into().unwrap());
    if status != 0 {
        bail!("SNP_GET_REPORT returned status {status}");
    }

    let report_size = u32::from_le_bytes(resp.data[4..8].try_into().unwrap()) as usize;
    // Bound the claimed size before slicing: the header plus a full report must fit, and the
    // report must be long enough to contain HOSTDATA.
    let end = SNP_REPORT_RESP_HDR_LEN
        .checked_add(report_size)
        .filter(|end| *end <= resp.data.len())
        .ok_or_else(|| anyhow!("SNP_GET_REPORT claimed an implausible report size {report_size}"))?;
    if report_size < SNP_HOST_DATA_OFFSET + SNP_HOST_DATA_LEN {
        bail!(
            "SNP_GET_REPORT returned {report_size} bytes, too short to contain HOSTDATA \
             (expected at least {})",
            SNP_HOST_DATA_OFFSET + SNP_HOST_DATA_LEN
        );
    }

    let report = resp.data[SNP_REPORT_RESP_HDR_LEN..end].to_vec();
    slog::debug!(
        logger,
        "read local SEV-SNP attestation report";
        "provider" => "sev-guest ioctl",
        "bytes" => report.len()
    );

    Ok(report)
}

/// Fetch the SEV-SNP attestation report, preferring configfs-TSM and falling back to the
/// `/dev/sev-guest` ioctl on kernels older than 6.7.
fn read_snp_report(logger: &Logger) -> Result<Vec<u8>> {
    let report_dir = fs_root().join(TSM_REPORT_DIR);
    if !report_dir.is_dir() {
        let dev = fs_root().join(SEV_GUEST_DEV);
        if dev.exists() {
            slog::info!(
                logger,
                "no configfs-tsm report provider; falling back to the sev-guest ioctl";
                "device" => dev.display().to_string()
            );
            return read_snp_report_ioctl(logger, &dev);
        }
        bail!(
            "neither {} nor {} is present: the guest is SEV-SNP but exposes no report \
             provider, so the initdata cannot be bound to the launch measurement",
            report_dir.display(),
            dev.display()
        );
    }

    let entry = ReportEntry::create()?;

    // The report is read locally from the guest's own TEE, so freshness is not a concern
    // here; `inblob` is required by configfs-tsm but its content is irrelevant to a
    // HOSTDATA comparison.
    entry.write_inblob(&[0u8; TSM_INBLOB_LEN])?;

    let raw_provider = entry.provider()?;
    if Provider::parse(&raw_provider) != Some(Provider::Snp) {
        bail!("expected an SEV-SNP configfs-tsm provider, got {raw_provider:?}");
    }

    let report = entry.outblob()?;
    slog::debug!(
        logger,
        "read local SEV-SNP attestation report";
        "provider" => &raw_provider,
        "bytes" => report.len()
    );

    Ok(report)
}

/// Verify that the initdata the agent parsed is the initdata this VM was launched with.
///
/// Returns `Ok(true)` when the binding was checked and holds, and `Ok(false)` when there was
/// nothing to check because the guest is not a confidential VM. Any other outcome -- a
/// mismatch, an unreadable report, an unknown provider -- is an error, and the caller is
/// expected to fail closed.
pub fn verify_initdata_binding(logger: &Logger, digest: &[u8]) -> Result<bool> {
    let logger = logger.new(slog::o!("subsystem" => "hostdata"));

    let Some((provider, measured)) = read_measured_field(&logger)? else {
        return Ok(false);
    };

    let expected = adjust_digest(digest, provider.measured_len());

    if measured != expected {
        bail!(
            "initdata does not match the launch measurement: {} is {}, initdata digest is {}",
            provider.field_name(),
            hex_encode(&measured),
            hex_encode(&expected)
        );
    }

    slog::info!(
        logger,
        "initdata is bound to the launch measurement";
        "field" => provider.field_name()
    );
    Ok(true)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_provider() {
        assert_eq!(Provider::parse("sev_guest"), Some(Provider::Snp));
        assert_eq!(Provider::parse("sev_guest\n"), Some(Provider::Snp));
        assert_eq!(Provider::parse("tdx_guest"), Some(Provider::Tdx));
        assert_eq!(Provider::parse("TDX_GUEST"), Some(Provider::Tdx));
        assert_eq!(Provider::parse("something-else"), None);
    }

    #[test]
    fn adjust_digest_truncates_and_pads() {
        // sha512 digest stamped into a 32-byte HOSTDATA field is truncated.
        let long = vec![0xAAu8; 64];
        assert_eq!(adjust_digest(&long, 32), vec![0xAAu8; 32]);

        // sha256 digest stamped into a 48-byte MRCONFIGID field is zero-padded.
        let short = vec![0xBBu8; 32];
        let padded = adjust_digest(&short, 48);
        assert_eq!(&padded[..32], &short[..]);
        assert_eq!(&padded[32..], &[0u8; 16][..]);
    }

    #[test]
    fn extract_snp_host_data_from_report() {
        let mut report = vec![0u8; 1184];
        report[SNP_HOST_DATA_OFFSET..SNP_HOST_DATA_OFFSET + SNP_HOST_DATA_LEN]
            .copy_from_slice(&[0x5Au8; SNP_HOST_DATA_LEN]);

        let extracted = extract_snp_host_data(&report).unwrap();
        assert_eq!(extracted, vec![0x5Au8; SNP_HOST_DATA_LEN]);
    }

    #[test]
    fn short_snp_report_is_rejected() {
        assert!(extract_snp_host_data(&[0u8; 8]).is_err());
    }

    // The ioctl fallback hands the kernel raw pointers into these structs, so their layout
    // is an ABI contract with `include/uapi/linux/sev-guest.h` rather than an internal
    // detail: a wrong size or offset would have the firmware write the report somewhere
    // other than where it is read back from, and the failure would be a silent mismatch
    // rather than a compile error. Neither struct is packed in the kernel header, so the
    // padding after `msg_version` is part of the contract too.
    #[test]
    fn snp_ioctl_structs_match_the_kernel_abi() {
        assert_eq!(std::mem::size_of::<super::SnpReportReq>(), 96);
        assert_eq!(std::mem::size_of::<super::SnpReportResp>(), 4000);
        assert_eq!(std::mem::size_of::<super::SnpGuestRequestIoctl>(), 32);

        let arg = super::SnpGuestRequestIoctl {
            msg_version: 1,
            req_data: 0,
            resp_data: 0,
            exitinfo2: 0,
        };
        let base = &arg as *const _ as usize;
        assert_eq!(&arg.req_data as *const _ as usize - base, 8);
        assert_eq!(&arg.resp_data as *const _ as usize - base, 16);
        assert_eq!(&arg.exitinfo2 as *const _ as usize - base, 24);
    }

    // HOSTDATA is read out of the ioctl response at a different offset than out of
    // configfs-TSM's `outblob`, because the ioctl response prefixes the report with a
    // status header. Getting this wrong reads 32 bytes of the report's signature area and
    // compares it against the initdata digest, which fails closed but for the wrong reason.
    #[test]
    fn snp_report_resp_header_precedes_the_report() {
        let mut data = [0u8; 4000];
        data[4..8].copy_from_slice(&1184u32.to_le_bytes());
        let at = super::SNP_REPORT_RESP_HDR_LEN + SNP_HOST_DATA_OFFSET;
        data[at..at + SNP_HOST_DATA_LEN].copy_from_slice(&[0xA5u8; SNP_HOST_DATA_LEN]);

        let report = &data[super::SNP_REPORT_RESP_HDR_LEN..super::SNP_REPORT_RESP_HDR_LEN + 1184];
        assert_eq!(
            extract_snp_host_data(report).unwrap(),
            vec![0xA5u8; SNP_HOST_DATA_LEN]
        );
    }

    fn fake_tdx_dev(value: Option<&[u8]>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        if let Some(value) = value {
            let attr = dir.path().join(TDX_MRCONFIGID_ATTR);
            fs::create_dir_all(attr.parent().unwrap()).unwrap();
            fs::write(attr, value).unwrap();
        }
        dir
    }

    #[test]
    fn read_tdx_mrconfigid_reads_raw_bytes() {
        let dir = fake_tdx_dev(Some(&[0x3Cu8; TDX_MRCONFIGID_LEN]));
        let value = read_tdx_mrconfigid(dir.path()).unwrap();
        assert_eq!(value, vec![0x3Cu8; TDX_MRCONFIGID_LEN]);
    }

    #[test]
    fn missing_tdx_mrconfigid_fails_closed() {
        // A TDX guest on a kernel without tsm-mr must be an error, never a silent skip.
        let dir = fake_tdx_dev(None);
        assert!(read_tdx_mrconfigid(dir.path()).is_err());
    }

    #[test]
    fn truncated_tdx_mrconfigid_is_rejected() {
        let dir = fake_tdx_dev(Some(&[0x3Cu8; 16]));
        assert!(read_tdx_mrconfigid(dir.path()).is_err());
    }

    /// Level-B end-to-end coverage: drives the whole `verify_initdata_binding()` path
    /// against a fake TEE tree, with no confidential VM and no TEE hardware.
    ///
    /// Requires the `tsm-test-override` feature, which is never enabled in a shipped image.
    #[cfg(feature = "tsm-test-override")]
    mod binding {
        use super::*;
        use std::sync::Mutex;

        /// `KATA_AGENT_TSM_ROOT` is process-global, so these cases must not overlap.
        static ENV_LOCK: Mutex<()> = Mutex::new(());

        fn null_logger() -> Logger {
            Logger::root(slog::Discard, slog::o!())
        }

        /// Build a fake TDX tree whose MRCONFIGID is `digest`, padded the way the runtime
        /// pads it before stamping it into the launch configuration.
        fn tdx_tree_for(digest: &[u8]) -> tempfile::TempDir {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join(TDX_GUEST_DEV_DIR).join("measurements");
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("mrconfigid"),
                adjust_digest(digest, TDX_MRCONFIGID_LEN),
            )
            .unwrap();
            root
        }

        fn verify_under(root: &Path, digest: &[u8]) -> Result<bool> {
            let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            std::env::set_var("KATA_AGENT_TSM_ROOT", root);
            let outcome = verify_initdata_binding(&null_logger(), digest);
            std::env::remove_var("KATA_AGENT_TSM_ROOT");
            outcome
        }

        const DIGEST: &[u8] = b"an-initdata-digest-32-bytes-long";

        #[test]
        fn matching_launch_measurement_is_accepted() {
            let root = tdx_tree_for(DIGEST);
            assert!(verify_under(root.path(), DIGEST).unwrap());
        }

        #[test]
        fn tampered_launch_measurement_is_refused() {
            // The VM was launched with one initdata; the host serves the agent another.
            let mut other = DIGEST.to_vec();
            other[0] ^= 0xFF;
            let root = tdx_tree_for(&other);

            assert!(verify_under(root.path(), DIGEST).is_err());
        }

        #[test]
        fn tdx_without_tsm_mr_is_refused() {
            // A TDX guest whose kernel predates the tsm-mr interface: there is no
            // host-independent way to read MRCONFIGID, so the agent must not continue.
            let root = tempfile::tempdir().unwrap();
            fs::create_dir_all(root.path().join(TDX_GUEST_DEV_DIR)).unwrap();

            assert!(verify_under(root.path(), DIGEST).is_err());
        }

        #[test]
        fn no_tee_provider_is_skipped_not_refused() {
            // A non-confidential development guest still boots; there is simply no launch
            // measurement to bind to.
            let root = tempfile::tempdir().unwrap();
            fs::create_dir_all(root.path().join("sys/class/misc")).unwrap();

            assert!(!verify_under(root.path(), DIGEST).unwrap());
        }
    }
}
