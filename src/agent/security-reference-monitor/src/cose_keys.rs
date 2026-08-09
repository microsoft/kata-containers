// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! BL-2 — multi-algorithm public-key verification for fragment signatures.
//!
//! A single verifier used by both the did:x509 certificate path (leaf COSE signature +
//! chain-link certificate signatures) and the transparency trust list (receipt / signed
//! tree-head signatures). Supported algorithms (pure-Rust RustCrypto, no Go):
//!
//! | COSE alg | id  | key         | hash    |
//! |----------|-----|-------------|---------|
//! | EdDSA    | -8  | Ed25519     | (n/a)   |
//! | ES256    | -7  | EC P-256    | SHA-256 |
//! | ES384    | -35 | EC P-384    | SHA-384 |
//! | PS256    | -37 | RSA (PSS)   | SHA-256 |
//! | RS256    |-257 | RSA (PKCS1) | SHA-256 |
//!
//! For X.509 chain links the certificate `signatureAlgorithm` OID selects the scheme:
//! ecdsa-with-SHA256/384, sha256/384-WithRSAEncryption (PKCS#1 v1.5). RSA-PSS in certificates
//! is uncommon and intentionally not accepted for chain links (fail-closed).
//!
//! ## RSA modulus size
//!
//! The elliptic-curve algorithms have exactly one key size each, fixed by the curve, so
//! there is nothing to bound. RSA does not, so the accepted range is stated explicitly:
//! [`MIN_RSA_MODULUS_BITS`]..=[`MAX_RSA_MODULUS_BITS`].
//!
//! The upper bound already existed but arrived by accident rather than by decision. The
//! `rsa` crate applies its own `RsaPublicKey::MAX_SIZE` (4096) inside `RsaPublicKey::new`,
//! which every DER decoding path funnels through, so an oversized modulus was never
//! accepted. Restating it here is a no-op today and a tripwire if that internal default
//! ever moves; the constant below is what this code depends on, not what the dependency
//! happens to do.
//!
//! The lower bound did *not* exist, and its absence was a real divergence from the
//! reference stack. The C-ACI/hcsshim implementation is Go, and since Go 1.24 `crypto/rsa`
//! refuses keys below 1024 bits for *every* operation including `Verify`, so that stack has
//! a 1024-bit floor it never had to write down. The `rsa` crate has no equivalent: its
//! `check_public` rejects a degenerate exponent (`e < 2`, even `e`, `e >= n`) and an even
//! modulus, but accepts a 512-bit — or 64-bit — modulus without complaint. A certificate
//! carrying a weak key, whether through CA misissuance or a legacy anchor, would have had
//! its signatures verified on their own terms; 512-bit RSA is factorable on commodity
//! hardware, so verifying under such a key is not meaningfully verification at all.
//! Matching Go's floor closes that gap and keeps the two stacks agreeing on which keys
//! are strong enough to be worth checking.

use const_oid::ObjectIdentifier;
use ed25519_dalek::Verifier as _;
use std::convert::TryFrom;

/// Signature verification failed.
///
/// Deliberately carries no detail: the caller must not be able to distinguish *why* a
/// signature was rejected (bad encoding, wrong algorithm, bad signature), since that
/// distinction is an oracle for an attacker probing the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigError;

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("signature verification failed")
    }
}

impl std::error::Error for SigError {}

/// COSE signature algorithms we accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlg {
    EdDsa,
    Es256,
    Es384,
    Ps256,
    Rs256,
}

impl CoseAlg {
    /// Map a COSE algorithm integer (RFC 9053 / IANA COSE registry) to a supported scheme.
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            -8 => Some(CoseAlg::EdDsa),
            -7 => Some(CoseAlg::Es256),
            -35 => Some(CoseAlg::Es384),
            -37 => Some(CoseAlg::Ps256),
            -257 => Some(CoseAlg::Rs256),
            _ => None,
        }
    }
}

// Certificate signatureAlgorithm OIDs.
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
// SubjectPublicKeyInfo algorithm OID for RSA.
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Smallest RSA modulus accepted for signature verification, in bits.
///
/// Matches the floor Go's `crypto/rsa` has enforced since Go 1.24, which is what the
/// C-ACI/hcsshim stack verifies under. See the module documentation for why this is stated
/// here rather than inherited from the `rsa` crate, which imposes no minimum.
pub const MIN_RSA_MODULUS_BITS: usize = 1024;

/// Largest RSA modulus accepted for signature verification, in bits.
///
/// Equal to `rsa::RsaPublicKey::MAX_SIZE`, restated so the bound this code relies on is
/// visible and tested here rather than being a side effect of a dependency's default.
pub const MAX_RSA_MODULUS_BITS: usize = 4096;

/// A parsed public key of one of the supported algorithms.
#[derive(Clone)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

impl PublicKey {
    /// Parse a public key from a raw 32-byte Ed25519 key.
    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Option<Self> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .ok()
            .map(PublicKey::Ed25519)
    }

    /// Parse a public key from a DER-encoded SubjectPublicKeyInfo (as found in a certificate
    /// or a configured ledger key). Tries EC P-256, EC P-384, then RSA.
    pub fn from_spki_der(der: &[u8]) -> Option<Self> {
        use spki::DecodePublicKey;
        if let Ok(k) = p256::ecdsa::VerifyingKey::from_public_key_der(der) {
            return Some(PublicKey::P256(k));
        }
        if let Ok(k) = p384::ecdsa::VerifyingKey::from_public_key_der(der) {
            return Some(PublicKey::P384(k));
        }
        // RSA: pull the PKCS#1 RSAPublicKey out of the SPKI and parse it.
        if let Ok(spki) = spki::SubjectPublicKeyInfoRef::try_from(der) {
            if spki.algorithm.oid == RSA_ENCRYPTION {
                if let Some(pk_der) = spki.subject_public_key.as_bytes() {
                    use rsa::pkcs1::DecodeRsaPublicKey;
                    if let Ok(k) = rsa::RsaPublicKey::from_pkcs1_der(pk_der) {
                        return Self::rsa_within_bounds(k);
                    }
                }
            }
        }
        None
    }

    /// Wrap an RSA key only if its modulus is within [`MIN_RSA_MODULUS_BITS`]..=
    /// [`MAX_RSA_MODULUS_BITS`].
    ///
    /// This is the single construction site for [`PublicKey::Rsa`], so a key that is out of
    /// range is never represented — there is no later point at which the check could be
    /// forgotten, and no way to hold an `RsaPublicKey` this module would refuse to use.
    fn rsa_within_bounds(k: rsa::RsaPublicKey) -> Option<Self> {
        use rsa::traits::PublicKeyParts as _;
        let bits = k.n().bits();
        if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&bits) {
            return None;
        }
        Some(PublicKey::Rsa(k))
    }

    /// Verify a COSE detached signature (`sig`) over `tbs` under `alg`. `sig` is in the COSE
    /// wire form: fixed-width `r||s` for ECDSA, raw modulus-width bytes for RSA, 64 bytes for
    /// EdDSA. Returns `Ok(())` iff the signature is valid and `alg` matches this key type.
    pub fn verify_cose(&self, alg: CoseAlg, tbs: &[u8], sig: &[u8]) -> Result<(), SigError> {
        match (self, alg) {
            (PublicKey::Ed25519(k), CoseAlg::EdDsa) => {
                let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| SigError)?;
                k.verify(tbs, &s).map_err(|_| SigError)
            }
            (PublicKey::P256(k), CoseAlg::Es256) => {
                let s = p256::ecdsa::Signature::from_slice(sig).map_err(|_| SigError)?;
                k.verify(tbs, &s).map_err(|_| SigError)
            }
            (PublicKey::P384(k), CoseAlg::Es384) => {
                let s = p384::ecdsa::Signature::from_slice(sig).map_err(|_| SigError)?;
                k.verify(tbs, &s).map_err(|_| SigError)
            }
            (PublicKey::Rsa(k), CoseAlg::Ps256) => {
                let vk = rsa::pss::VerifyingKey::<sha2::Sha256>::new(k.clone());
                let s = rsa::pss::Signature::try_from(sig).map_err(|_| SigError)?;
                vk.verify(tbs, &s).map_err(|_| SigError)
            }
            (PublicKey::Rsa(k), CoseAlg::Rs256) => {
                let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(k.clone());
                let s = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| SigError)?;
                vk.verify(tbs, &s).map_err(|_| SigError)
            }
            // Algorithm does not match the key type ⇒ reject (no cross-alg confusion).
            _ => Err(SigError),
        }
    }

    /// Verify an X.509 certificate signature: `sig_der` is the certificate's `signatureValue`
    /// (DER ECDSA-Sig-Value for ECDSA, raw for RSA) and `sig_alg_oid` its `signatureAlgorithm`.
    /// This key is the *issuer* key. Returns `Ok(())` iff valid and the scheme is supported and
    /// consistent with this key type.
    pub fn verify_cert_sig(
        &self,
        sig_alg_oid: &ObjectIdentifier,
        tbs: &[u8],
        sig_der: &[u8],
    ) -> Result<(), SigError> {
        match (self, *sig_alg_oid) {
            (PublicKey::P256(k), oid) if oid == ECDSA_WITH_SHA256 => {
                let s = p256::ecdsa::DerSignature::try_from(sig_der).map_err(|_| SigError)?;
                k.verify(tbs, &s).map_err(|_| SigError)
            }
            (PublicKey::P384(k), oid) if oid == ECDSA_WITH_SHA384 => {
                let s = p384::ecdsa::DerSignature::try_from(sig_der).map_err(|_| SigError)?;
                k.verify(tbs, &s).map_err(|_| SigError)
            }
            (PublicKey::Rsa(k), oid) if oid == SHA256_WITH_RSA => {
                let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(k.clone());
                let s = rsa::pkcs1v15::Signature::try_from(sig_der).map_err(|_| SigError)?;
                vk.verify(tbs, &s).map_err(|_| SigError)
            }
            (PublicKey::Rsa(k), oid) if oid == SHA384_WITH_RSA => {
                let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(k.clone());
                let s = rsa::pkcs1v15::Signature::try_from(sig_der).map_err(|_| SigError)?;
                vk.verify(tbs, &s).map_err(|_| SigError)
            }
            _ => Err(SigError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a DER length.
    fn der_len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else {
            let b = n.to_be_bytes();
            let b = &b[b.iter().position(|&x| x != 0).unwrap()..];
            let mut out = vec![0x80 | b.len() as u8];
            out.extend_from_slice(b);
            out
        }
    }

    /// Encode a DER tag-length-value.
    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// Encode a big-endian magnitude as a DER INTEGER (prefixing 0x00 when the high bit is
    /// set, so it is not read as negative).
    fn der_uint(mag: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        if mag[0] & 0x80 != 0 {
            v.push(0x00);
        }
        v.extend_from_slice(mag);
        der_tlv(0x02, &v)
    }

    /// Build a DER SubjectPublicKeyInfo for an RSA key whose modulus is exactly `bits` bits
    /// (`bits` must be a multiple of 8) with `e = 65537`.
    ///
    /// The modulus is synthetic — `2^(bits-1) + 1` — rather than a generated key, because
    /// what is under test is the size gate, which runs before any use of the key. This keeps
    /// the test exact about bit length (a generated key is only approximately the requested
    /// size) and free of a keygen dependency. The value still satisfies every structural
    /// check the `rsa` crate makes: the modulus is odd, and `2 <= e < n`.
    fn rsa_spki_der(bits: usize) -> Vec<u8> {
        assert!(bits % 8 == 0 && bits >= 16);
        let mut n = vec![0u8; bits / 8];
        n[0] = 0x80;
        *n.last_mut().unwrap() = 0x01;

        let pkcs1 = der_tlv(0x30, &[der_uint(&n), der_uint(&[0x01, 0x00, 0x01])].concat());
        // BIT STRING with zero unused bits, wrapping the PKCS#1 RSAPublicKey.
        let bitstr = der_tlv(0x03, &[&[0x00u8][..], &pkcs1].concat());
        // AlgorithmIdentifier { rsaEncryption, NULL }.
        let alg = hex_literal_rsa_alg_id();
        der_tlv(0x30, &[alg.as_slice(), bitstr.as_slice()].concat())
    }

    /// `SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }`.
    fn hex_literal_rsa_alg_id() -> Vec<u8> {
        let oid = der_tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
        let null = der_tlv(0x05, &[]);
        der_tlv(0x30, &[oid, null].concat())
    }

    #[test]
    fn rsa_modulus_size_is_bounded() {
        // Sanity: the encoder produces what the size gate is meant to be reading, so a
        // failure below is the gate's verdict and not a malformed test vector.
        assert!(
            matches!(
                PublicKey::from_spki_der(&rsa_spki_der(2048)),
                Some(PublicKey::Rsa(_))
            ),
            "a 2048-bit key must be accepted"
        );

        // Exactly at each bound: accepted.
        for bits in [MIN_RSA_MODULUS_BITS, MAX_RSA_MODULUS_BITS] {
            assert!(
                PublicKey::from_spki_der(&rsa_spki_der(bits)).is_some(),
                "{bits}-bit modulus is on the boundary and must be accepted"
            );
        }

        // One step outside each bound: refused.
        for bits in [MIN_RSA_MODULUS_BITS - 8, MAX_RSA_MODULUS_BITS + 8] {
            assert!(
                PublicKey::from_spki_der(&rsa_spki_der(bits)).is_none(),
                "{bits}-bit modulus is outside the accepted range and must be refused"
            );
        }

        // The size that motivated the floor. 512-bit RSA is factorable on commodity
        // hardware, so verifying under it is not verification; Go's crypto/rsa — which the
        // C-ACI/hcsshim stack verifies with — refuses it, and so must this.
        assert!(
            PublicKey::from_spki_der(&rsa_spki_der(512)).is_none(),
            "512-bit RSA must be refused, matching Go's crypto/rsa floor"
        );
        // Degenerate sizes are refused by the same gate rather than reaching any modexp.
        assert!(PublicKey::from_spki_der(&rsa_spki_der(64)).is_none());
    }

    #[test]
    fn cose_alg_mapping() {
        assert_eq!(CoseAlg::from_i64(-8), Some(CoseAlg::EdDsa));
        assert_eq!(CoseAlg::from_i64(-7), Some(CoseAlg::Es256));
        assert_eq!(CoseAlg::from_i64(-35), Some(CoseAlg::Es384));
        assert_eq!(CoseAlg::from_i64(-37), Some(CoseAlg::Ps256));
        assert_eq!(CoseAlg::from_i64(-257), Some(CoseAlg::Rs256));
        assert_eq!(CoseAlg::from_i64(-999), None);
    }

    #[test]
    fn ed25519_roundtrip_and_alg_mismatch() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = PublicKey::from_ed25519_bytes(&sk.verifying_key().to_bytes()).unwrap();
        let msg = b"hello";
        let sig = sk.sign(msg).to_bytes().to_vec();
        assert!(pk.verify_cose(CoseAlg::EdDsa, msg, &sig).is_ok());
        // Wrong algorithm for an Ed25519 key is rejected (no cross-alg confusion).
        assert!(pk.verify_cose(CoseAlg::Es256, msg, &sig).is_err());
        // Tampered message rejected.
        assert!(pk.verify_cose(CoseAlg::EdDsa, b"hell0", &sig).is_err());
    }
}
