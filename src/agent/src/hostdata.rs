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

/// Fetch the SEV-SNP attestation report through configfs-TSM.
fn read_snp_report(logger: &Logger) -> Result<Vec<u8>> {
    let report_dir = fs_root().join(TSM_REPORT_DIR);
    if !report_dir.is_dir() {
        bail!(
            "{} is not present: the guest is SEV-SNP but exposes no configfs-tsm report \
             provider, so the initdata cannot be bound to the launch measurement",
            report_dir.display()
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
