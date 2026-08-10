// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-5 — encrypted-scratch invariant.
//!
//! Writable scratch (block-backed `emptyDir` and similar ephemeral volumes) may hold
//! secrets a workload writes at runtime. A host must not be able to obtain that data by
//! presenting an unencrypted backing device, nor by *claiming* encryption in the storage
//! driver options while the effective mount is plaintext.
//!
//! The enforcer therefore classifies scratch by its **effective** device-mapper target
//! (what the kernel actually stacked), not by the host-supplied driver options, and
//! applies a policy invariant that scratch must be encrypted (optionally with integrity).
//! A plaintext effective mount is refused even when the host asked for encryption.

use std::fmt;

/// Effective protection of a scratch volume, derived from its device-mapper target stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScratchClass {
    /// No encryption target present in the effective stack.
    Plaintext,
    /// Encrypted (dm-crypt) but no integrity target.
    Encrypted,
    /// Encrypted with integrity protection (dm-crypt + dm-integrity, e.g. LUKS2 authenticated).
    EncryptedWithIntegrity,
}

impl fmt::Display for ScratchClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScratchClass::Plaintext => "plaintext",
            ScratchClass::Encrypted => "encrypted",
            ScratchClass::EncryptedWithIntegrity => "encrypted-with-integrity",
        })
    }
}

/// The invariant a policy imposes on scratch volumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScratchRequirement {
    /// No requirement (non-strict / opt-out).
    AnyAllowed,
    /// Must be at least encrypted.
    RequireEncrypted,
    /// Must be encrypted with integrity protection.
    RequireEncryptedWithIntegrity,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScratchError {
    /// The effective mount does not meet the required protection level.
    InsufficientProtection {
        required: ScratchRequirement,
        effective: ScratchClass,
    },
}

impl fmt::Display for ScratchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScratchError::InsufficientProtection {
                required,
                effective,
            } => write!(
                f,
                "scratch protection insufficient: effective mode is {effective}, policy requires {required:?}"
            ),
        }
    }
}

impl std::error::Error for ScratchError {}

/// Classify scratch from the *effective* device-mapper target types stacked on its backing
/// device (as reported by the kernel, e.g. the target-type column of `dmsetup table`).
///
/// The presence of a `crypt` target means encryption is actually in force; an additional
/// `integrity` target (or an integrity-tagged crypt target) means integrity is in force.
/// Anything else (`linear`, empty, ...) is plaintext regardless of what the host claimed.
pub fn classify_scratch(effective_dm_targets: &[&str]) -> ScratchClass {
    let has_crypt = effective_dm_targets.contains(&"crypt");
    let has_integrity = effective_dm_targets.contains(&"integrity");
    match (has_crypt, has_integrity) {
        (true, true) => ScratchClass::EncryptedWithIntegrity,
        (true, false) => ScratchClass::Encrypted,
        _ => ScratchClass::Plaintext,
    }
}

/// Enforce the scratch protection invariant against the effective classification.
pub fn enforce_scratch(
    effective: ScratchClass,
    required: ScratchRequirement,
) -> Result<(), ScratchError> {
    let ok = match required {
        ScratchRequirement::AnyAllowed => true,
        ScratchRequirement::RequireEncrypted => {
            matches!(
                effective,
                ScratchClass::Encrypted | ScratchClass::EncryptedWithIntegrity
            )
        }
        ScratchRequirement::RequireEncryptedWithIntegrity => {
            effective == ScratchClass::EncryptedWithIntegrity
        }
    };
    if ok {
        Ok(())
    } else {
        Err(ScratchError::InsufficientProtection {
            required,
            effective,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_by_target_stack() {
        assert_eq!(classify_scratch(&["crypt"]), ScratchClass::Encrypted);
        assert_eq!(
            classify_scratch(&["crypt", "integrity"]),
            ScratchClass::EncryptedWithIntegrity
        );
        assert_eq!(classify_scratch(&["linear"]), ScratchClass::Plaintext);
        assert_eq!(classify_scratch(&[]), ScratchClass::Plaintext);
    }

    /// TC5.1: scratch without encryption is denied when the policy requires encryption.
    #[test]
    fn plaintext_scratch_is_denied() {
        assert_eq!(
            enforce_scratch(
                ScratchClass::Plaintext,
                ScratchRequirement::RequireEncrypted
            )
            .unwrap_err(),
            ScratchError::InsufficientProtection {
                required: ScratchRequirement::RequireEncrypted,
                effective: ScratchClass::Plaintext,
            }
        );
    }

    /// TC5.2: a host that claims encryption but whose *effective* mount is plaintext is
    /// denied — enforcement is on the effective dm stack, not host driver options.
    #[test]
    fn host_claimed_encryption_but_effective_plaintext_is_denied() {
        // Host driver_options said "encryption_key=ephemeral", but the kernel's live table
        // shows no crypt target (e.g. a linear passthrough). classify_scratch ignores the claim.
        let effective = classify_scratch(&["linear"]);
        assert_eq!(effective, ScratchClass::Plaintext);
        assert!(enforce_scratch(effective, ScratchRequirement::RequireEncrypted).is_err());
    }

    /// TC5.3: scratch is classified correctly across the three levels, and the integrity
    /// requirement rejects encryption-without-integrity.
    #[test]
    fn classification_levels_and_integrity_requirement() {
        assert!(enforce_scratch(
            ScratchClass::Encrypted,
            ScratchRequirement::RequireEncrypted
        )
        .is_ok());
        assert!(enforce_scratch(
            ScratchClass::EncryptedWithIntegrity,
            ScratchRequirement::RequireEncryptedWithIntegrity
        )
        .is_ok());
        // Encrypted but no integrity fails the integrity requirement.
        assert!(enforce_scratch(
            ScratchClass::Encrypted,
            ScratchRequirement::RequireEncryptedWithIntegrity
        )
        .is_err());
        // AnyAllowed permits plaintext (non-strict).
        assert!(enforce_scratch(ScratchClass::Plaintext, ScratchRequirement::AnyAllowed).is_ok());
    }
}
