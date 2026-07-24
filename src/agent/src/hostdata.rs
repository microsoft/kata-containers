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

/// configfs-TSM report directory. Present when the guest kernel exposes a TEE report
/// provider (CONFIG_TSM_REPORTS) and configfs is mounted.
const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";

/// Name of the report entry this module creates. Removed again once the report is read.
const TSM_REPORT_ENTRY: &str = "kata-agent-initdata";

/// configfs-TSM requires `inblob` to be exactly 64 bytes.
const TSM_INBLOB_LEN: usize = 64;

/// Offset and length of `HOST_DATA` within an SEV-SNP attestation report (Table 22,
/// "SEV Secure Nested Paging Firmware ABI Specification").
const SNP_HOST_DATA_OFFSET: usize = 0xC0;
const SNP_HOST_DATA_LEN: usize = 32;

/// Offset and length of `MRCONFIGID` within a TDX quote: a 48-byte quote header followed by
/// the TD quote body, in which `MRCONFIGID` sits at offset 184 (after TEE_TCB_SVN(16),
/// MRSEAM(48), MRSIGNERSEAM(48), SEAMATTRIBUTES(8), TDATTRIBUTES(8), XFAM(8), MRTD(48)).
const TDX_QUOTE_HEADER_LEN: usize = 48;
const TDX_BODY_MRCONFIGID_OFFSET: usize = 184;
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
        let path = Path::new(TSM_REPORT_DIR).join(TSM_REPORT_ENTRY);
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
        let raw = fs::read_to_string(self.path.join("provider"))
            .context("read configfs-tsm provider")?;
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

/// Extract the launch-configuration field the initdata digest is stamped into.
fn extract_measured_field(provider: Provider, report: &[u8]) -> Result<Vec<u8>> {
    let (offset, len) = match provider {
        Provider::Snp => (SNP_HOST_DATA_OFFSET, SNP_HOST_DATA_LEN),
        Provider::Tdx => (
            TDX_QUOTE_HEADER_LEN + TDX_BODY_MRCONFIGID_OFFSET,
            TDX_MRCONFIGID_LEN,
        ),
    };

    report
        .get(offset..offset + len)
        .map(|slice| slice.to_vec())
        .ok_or_else(|| {
            anyhow!(
                "{} report too short: need {} bytes to read {}, got {}",
                provider.field_name(),
                offset + len,
                provider.field_name(),
                report.len()
            )
        })
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

/// Fetch the local TEE report. Returns `Ok(None)` when the guest has no TEE report provider,
/// which means it is not a confidential VM and there is no launch measurement to bind to.
fn read_local_report(logger: &Logger) -> Result<Option<(Provider, Vec<u8>)>> {
    if !Path::new(TSM_REPORT_DIR).is_dir() {
        slog::info!(
            logger,
            "no configfs-tsm report provider; guest is not a confidential VM";
            "path" => TSM_REPORT_DIR
        );
        return Ok(None);
    }

    let entry = ReportEntry::create()?;

    // The report is read locally from the guest's own TEE, so freshness is not a concern
    // here; `inblob` is required by configfs-tsm but its content is irrelevant to a
    // HOSTDATA/MRCONFIGID comparison.
    entry.write_inblob(&[0u8; TSM_INBLOB_LEN])?;

    let raw_provider = entry.provider()?;
    let Some(provider) = Provider::parse(&raw_provider) else {
        bail!("unsupported TEE report provider {raw_provider:?}");
    };

    let report = entry.outblob()?;
    slog::debug!(
        logger,
        "read local TEE report";
        "provider" => &raw_provider,
        "bytes" => report.len()
    );

    Ok(Some((provider, report)))
}

/// Verify that the initdata the agent parsed is the initdata this VM was launched with.
///
/// Returns `Ok(true)` when the binding was checked and holds, and `Ok(false)` when there was
/// nothing to check because the guest is not a confidential VM. Any other outcome -- a
/// mismatch, an unreadable report, an unknown provider -- is an error, and the caller is
/// expected to fail closed.
pub fn verify_initdata_binding(logger: &Logger, digest: &[u8]) -> Result<bool> {
    let logger = logger.new(slog::o!("subsystem" => "hostdata"));

    let Some((provider, report)) = read_local_report(&logger)? else {
        return Ok(false);
    };

    let measured = extract_measured_field(provider, &report)?;
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
    fn extract_snp_host_data() {
        let mut report = vec![0u8; 1184];
        report[SNP_HOST_DATA_OFFSET..SNP_HOST_DATA_OFFSET + SNP_HOST_DATA_LEN]
            .copy_from_slice(&[0x5Au8; SNP_HOST_DATA_LEN]);

        let extracted = extract_measured_field(Provider::Snp, &report).unwrap();
        assert_eq!(extracted, vec![0x5Au8; SNP_HOST_DATA_LEN]);
    }

    #[test]
    fn extract_tdx_mrconfigid() {
        let offset = TDX_QUOTE_HEADER_LEN + TDX_BODY_MRCONFIGID_OFFSET;
        let mut quote = vec![0u8; 1024];
        quote[offset..offset + TDX_MRCONFIGID_LEN].copy_from_slice(&[0x3Cu8; TDX_MRCONFIGID_LEN]);

        let extracted = extract_measured_field(Provider::Tdx, &quote).unwrap();
        assert_eq!(extracted, vec![0x3Cu8; TDX_MRCONFIGID_LEN]);
    }

    #[test]
    fn short_report_is_rejected() {
        let report = vec![0u8; 8];
        assert!(extract_measured_field(Provider::Snp, &report).is_err());
        assert!(extract_measured_field(Provider::Tdx, &report).is_err());
    }
}
