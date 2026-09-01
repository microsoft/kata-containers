// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-1d — `did:x509` issuer identity for policy fragments.
//!
//! Instead of pinning a single issuer public key, an issuer may be proven by an **X.509
//! certificate chain** carried in the COSE_Sign1 `x5chain` header (COSE header label 33).
//! Trust is anchored on a **CA certificate fingerprint plus a `did:x509` policy** (required
//! subject CN / EKU / SAN over the leaf), *not* on a leaf key — so leaf **rotation** under
//! the same CA and policy is accepted with no configuration change, and **revocation** is a
//! measured fingerprint list.
//!
//! Verification is fully self-contained (no network, no Go dependency): X.509 parsing via
//! `x509-cert`, chain-link and leaf signatures via `p256` (ECDSA P-256 / SHA-256), which is
//! the common code-signing algorithm. The design mirrors runhcs/OpenGCS
//! (`didx509resolver.Resolve` over the `x5chain`) while keeping the raw-Ed25519 issuer path
//! untouched — the two identity models coexist and there is no downgrade path.

use crate::cose_keys::{CoseAlg, PublicKey};
use crate::FragmentError;
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_SUBJECT_ALT_NAME,
};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use x509_cert::Certificate;

/// COSE header parameter label for `x5chain` (RFC 9360).
const COSE_HEADER_X5CHAIN: i64 = 33;

/// Upper bound on the number of certificates in a presented `x5chain`.
///
/// The chain arrives from the untrusted host and every certificate in it is fingerprinted
/// and DER-parsed *before* any anchor has matched, so without a bound a host can choose how
/// much work the guest does on a request it will ultimately refuse. 100 is hcsshim's
/// number (`internal/tools/securitypolicy/cosesign1/check.go`), and it is far above any
/// legitimate chain: real ones are leaf plus one or two intermediates plus a root.
const MAX_X5CHAIN_CERTS: usize = 100;
/// id-at-commonName (2.5.4.3).
const AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

/// A `did:x509` trust policy over the leaf certificate. All non-empty constraints must hold.
#[derive(Debug, Clone, Default)]
pub struct DidX509Policy {
    /// Required leaf subject Common Name (exact match), if set.
    pub require_subject_cn: Option<String>,
    /// Required Extended Key Usage OIDs on the leaf (all must be present), as dotted strings.
    pub require_eku: Vec<String>,
    /// Required Subject Alternative Name DNS entries on the leaf (all must be present).
    pub require_san_dns: Vec<String>,
}

/// A trust anchor authorizing a `did:x509` issuer: a trusted CA (by SHA-256 fingerprint of
/// its DER) plus the policy the leaf must satisfy. `did` is the issuer id fragments must
/// declare and equals the canonical `did:x509` derived from this anchor.
#[derive(Debug, Clone)]
pub struct DidX509Anchor {
    pub did: String,
    pub ca_fingerprint: [u8; 32],
    pub policy: DidX509Policy,
}

fn fingerprint(der_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(der_bytes);
    h.finalize().into()
}

/// SHA-256 fingerprint of a DER-encoded certificate (the value a `did:x509` anchor and the
/// revocation list are keyed on).
pub fn sha256_fingerprint(der_bytes: &[u8]) -> [u8; 32] {
    fingerprint(der_bytes)
}

/// Compute the SHA-256 fingerprint of the first `CERTIFICATE` block in a PEM string, for
/// configuring a CA anchor from a PEM cert instead of a raw fingerprint. Pure-Rust base64
/// decode (no network, no extra crate beyond `base64ct`).
pub fn ca_fingerprint_from_pem(pem: &str) -> Result<[u8; 32], FragmentError> {
    use base64ct::{Base64, Encoding};
    let mut b64 = String::new();
    let mut in_block = false;
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN CERTIFICATE-----") {
            in_block = true;
            continue;
        }
        if t.starts_with("-----END CERTIFICATE-----") {
            break;
        }
        if in_block {
            b64.push_str(t);
        }
    }
    if b64.is_empty() {
        return Err(FragmentError::InvalidCertChain);
    }
    let der = Base64::decode_vec(&b64).map_err(|_| FragmentError::InvalidCertChain)?;
    Ok(fingerprint(&der))
}

/// Build the canonical `did:x509` identifier naming a CA by fingerprint, with no leaf
/// predicates. Callers append predicates (e.g. `::subject:CN:signer`) for the constraints
/// their anchor policy enforces.
pub fn did_x509_for(ca_fingerprint: &[u8; 32]) -> String {
    use base64ct::{Base64UrlUnpadded, Encoding};
    format!(
        "did:x509:0:sha256:{}",
        Base64UrlUnpadded::encode_string(ca_fingerprint)
    )
}

/// The trust-relevant content of a canonical `did:x509` identifier: the CA fingerprint it
/// names and the leaf constraints it declares.
#[derive(Debug, Clone)]
pub struct DidX509Parts {
    /// SHA-256 fingerprint of the CA certificate the DID is anchored on.
    pub ca_fingerprint: [u8; 32],
    /// Declared policy predicates, as `(name, arguments)` — e.g. `("subject", ["CN", "signer"])`.
    pub predicates: Vec<(String, Vec<String>)>,
}

/// Percent-decode a `did:x509` policy argument. The method percent-encodes `:` and `%` so
/// that arguments can be split on `:` unambiguously.
///
/// Decoding accumulates *bytes* and validates the result as UTF-8 at the end. Decoding each
/// byte straight into a `char` would reinterpret it as a Unicode scalar, so a percent-encoded
/// or literal non-ASCII value (`%C3%A9` or `é`) would decode to mojibake (`Ã©`) and no longer
/// compare equal to the certificate field it names — rejecting an anchor whose DID and
/// certificate actually agree.
fn percent_decode(s: &str) -> Result<String, FragmentError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or(FragmentError::MalformedAnchorDid)?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| FragmentError::MalformedAnchorDid)?;
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| FragmentError::MalformedAnchorDid)
}

/// Parse a canonical `did:x509` identifier:
/// `did:x509:0:sha256:<base64url(CA SHA-256)>(::<policy>:<arg>(:<arg>)*)*`
///
/// This is what makes the identifier *self-describing*: the CA the identity is rooted in is
/// carried inside the identity string itself rather than alongside it, so an anchor's DID and
/// its trust root cannot drift apart. Only version `0` and `sha256` are accepted; anything
/// else is refused rather than ignored, so an unrecognized future form fails closed.
pub fn parse_did_x509(did: &str) -> Result<DidX509Parts, FragmentError> {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let rest = did
        .strip_prefix("did:x509:")
        .ok_or(FragmentError::MalformedAnchorDid)?;
    let mut sections = rest.split("::");
    let head = sections.next().ok_or(FragmentError::MalformedAnchorDid)?;

    let mut hp = head.split(':');
    let version = hp.next().ok_or(FragmentError::MalformedAnchorDid)?;
    let alg = hp.next().ok_or(FragmentError::MalformedAnchorDid)?;
    let fp_b64 = hp.next().ok_or(FragmentError::MalformedAnchorDid)?;
    if hp.next().is_some() || version != "0" || alg != "sha256" {
        return Err(FragmentError::MalformedAnchorDid);
    }
    let mut ca_fingerprint = [0u8; 32];
    Base64UrlUnpadded::decode(fp_b64, &mut ca_fingerprint)
        .map_err(|_| FragmentError::MalformedAnchorDid)?;

    let mut predicates = Vec::new();
    for section in sections {
        let mut parts = section.split(':');
        let name = parts.next().ok_or(FragmentError::MalformedAnchorDid)?;
        if name.is_empty() {
            return Err(FragmentError::MalformedAnchorDid);
        }
        let args = parts
            .map(percent_decode)
            .collect::<Result<Vec<_>, FragmentError>>()?;
        if args.is_empty() {
            return Err(FragmentError::MalformedAnchorDid);
        }
        predicates.push((name.to_string(), args));
    }
    Ok(DidX509Parts {
        ca_fingerprint,
        predicates,
    })
}

impl DidX509Anchor {
    /// Check that this anchor is internally consistent: that its `did` is a canonical
    /// `did:x509`, that the CA fingerprint named *inside* the DID is the one the anchor
    /// actually anchors on, and that every constraint the DID advertises is a constraint the
    /// leaf policy really enforces.
    ///
    /// Without this the DID is only a label. Both it and `ca_fingerprint` come from measured
    /// configuration, so a mismatch is a misconfiguration rather than an attack — but a
    /// mismatched anchor would enforce one identity while reporting a different one as the
    /// accepted issuer, which is exactly the confusion the identifier exists to prevent.
    /// Refusing the anchor keeps the DID a complete description of what was checked.
    pub fn validate(&self) -> Result<(), FragmentError> {
        let parts = parse_did_x509(&self.did)?;
        if parts.ca_fingerprint != self.ca_fingerprint {
            return Err(FragmentError::AnchorDidMismatch);
        }
        for (name, args) in &parts.predicates {
            let enforced = match (name.as_str(), args.as_slice()) {
                // Only the subject key we can actually enforce is accepted; a DID asserting
                // some other RDN would otherwise read as a constraint that nothing checks.
                ("subject", [key, value]) if key == "CN" => {
                    self.policy.require_subject_cn.as_deref() == Some(value.as_str())
                }
                ("eku", [oid]) => self.policy.require_eku.iter().any(|e| e == oid),
                ("san", [kind, value]) if kind == "dns" => {
                    self.policy.require_san_dns.iter().any(|d| d == value)
                }
                _ => return Err(FragmentError::UnsupportedAnchorDidPolicy),
            };
            if !enforced {
                return Err(FragmentError::AnchorDidMismatch);
            }
        }
        Ok(())
    }
}

/// Extract the ordered DER certificates (leaf first) from a COSE_Sign1 `x5chain` header
/// (checked in both the protected and unprotected buckets). A single certificate may be a
/// bare byte string; a chain is an array of byte strings.
fn extract_x5chain(sign1: &coset::CoseSign1) -> Result<Vec<Vec<u8>>, FragmentError> {
    use coset::cbor::value::Value;
    let find = |rest: &[(coset::Label, Value)]| -> Option<Value> {
        rest.iter().find_map(|(l, v)| match l {
            coset::Label::Int(i) if *i == COSE_HEADER_X5CHAIN => Some(v.clone()),
            _ => None,
        })
    };
    let val = find(&sign1.protected.header.rest)
        .or_else(|| find(&sign1.unprotected.rest))
        .ok_or(FragmentError::InvalidCertChain)?;
    let certs = match val {
        Value::Bytes(b) => vec![b],
        Value::Array(arr) => {
            // Checked against the array length before draining it, so an oversized chain is
            // refused without allocating for it.
            if arr.len() > MAX_X5CHAIN_CERTS {
                return Err(FragmentError::CertChainTooLong {
                    len: arr.len(),
                    max: MAX_X5CHAIN_CERTS,
                });
            }
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                match v {
                    Value::Bytes(b) => out.push(b),
                    _ => return Err(FragmentError::InvalidCertChain),
                }
            }
            out
        }
        _ => return Err(FragmentError::InvalidCertChain),
    };
    if certs.is_empty() {
        return Err(FragmentError::InvalidCertChain);
    }
    Ok(certs)
}

/// Whether a COSE_Sign1 envelope carries an `x5chain` header (used to route to the
/// `did:x509` verification path without attempting a full verification first).
///
/// This asks only whether the header is *present*, deliberately not whether its contents are
/// well-formed. Routing on validity would let a host steer an envelope away from the X.509
/// path by malforming the chain it presents — an oversized or corrupt chain would fall
/// through to the raw-key path rather than being refused. Presence is the honest question;
/// anything wrong with the chain is then reported by `verify_x509_cose`.
pub fn cose_has_x5chain(cose_sign1: &[u8]) -> bool {
    use coset::CborSerializable;
    match coset::CoseSign1::from_slice(cose_sign1) {
        Ok(sign1) => {
            let has = |rest: &[(coset::Label, coset::cbor::value::Value)]| {
                rest.iter()
                    .any(|(l, _)| matches!(l, coset::Label::Int(i) if *i == COSE_HEADER_X5CHAIN))
            };
            has(&sign1.protected.header.rest) || has(&sign1.unprotected.rest)
        }
        Err(_) => false,
    }
}

/// Public key of a certificate (multi-algorithm: EC P-256/P-384 or RSA), parsed from its
/// SubjectPublicKeyInfo.
fn cert_key(cert: &Certificate) -> Result<PublicKey, FragmentError> {
    let der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| FragmentError::InvalidCertChain)?;
    PublicKey::from_spki_der(&der).ok_or(FragmentError::InvalidCertChain)
}

/// Whether a certificate asserts `basicConstraints: cA=TRUE` — required of every issuer
/// (intermediate/CA) in the chain so that a non-CA leaf cannot mint sub-certificates.
fn is_ca(cert: &Certificate) -> bool {
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == ID_CE_BASIC_CONSTRAINTS {
                if let Ok(bc) =
                    x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes())
                {
                    return bc.ca;
                }
                return false;
            }
        }
    }
    false
}

/// Verify that `subject` was signed by `issuer`, dispatching on the certificate's
/// `signatureAlgorithm` (ECDSA P-256/384 or RSA PKCS#1 v1.5 with SHA-256/384).
fn verify_link(subject: &Certificate, issuer: &Certificate) -> Result<(), FragmentError> {
    // The issuer must be a CA (basicConstraints cA=TRUE), else a plain leaf could act as an
    // intermediate and mint sub-certificates (privilege escalation).
    if !is_ca(issuer) {
        return Err(FragmentError::InvalidCertChain);
    }
    let issuer_key = cert_key(issuer)?;
    let tbs = subject
        .tbs_certificate
        .to_der()
        .map_err(|_| FragmentError::InvalidCertChain)?;
    let sig_der = subject
        .signature
        .as_bytes()
        .ok_or(FragmentError::InvalidCertChain)?;
    issuer_key
        .verify_cert_sig(&subject.signature_algorithm.oid, &tbs, sig_der)
        .map_err(|_| FragmentError::InvalidCertChain)
}

/// Reject a certificate whose validity window does not include the current time.
fn check_validity(cert: &Certificate) -> Result<(), FragmentError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| FragmentError::CertExpired)?;
    let nb = cert.tbs_certificate.validity.not_before.to_unix_duration();
    let na = cert.tbs_certificate.validity.not_after.to_unix_duration();
    if now < nb || now > na {
        return Err(FragmentError::CertExpired);
    }
    Ok(())
}

/// The leaf's subject Common Name, if present.
fn subject_cn(leaf: &Certificate) -> Option<String> {
    for rdn in leaf.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == AT_COMMON_NAME {
                if let Ok(s) = atv.value.decode_as::<der::asn1::Utf8StringRef>() {
                    return Some(s.as_str().to_string());
                }
                if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef>() {
                    return Some(s.as_str().to_string());
                }
            }
        }
    }
    None
}

/// The dotted EKU OIDs asserted by the leaf.
fn leaf_ekus(leaf: &Certificate) -> HashSet<String> {
    let mut out = HashSet::new();
    if let Some(exts) = &leaf.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == ID_CE_EXT_KEY_USAGE {
                if let Ok(eku) =
                    x509_cert::ext::pkix::ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
                {
                    for oid in eku.0.iter() {
                        out.insert(oid.to_string());
                    }
                }
            }
        }
    }
    out
}

/// The leaf's DNS SubjectAltName entries.
fn leaf_san_dns(leaf: &Certificate) -> HashSet<String> {
    let mut out = HashSet::new();
    if let Some(exts) = &leaf.tbs_certificate.extensions {
        for ext in exts.iter() {
            if ext.extn_id == ID_CE_SUBJECT_ALT_NAME {
                if let Ok(san) =
                    x509_cert::ext::pkix::SubjectAltName::from_der(ext.extn_value.as_bytes())
                {
                    for gn in san.0.iter() {
                        if let x509_cert::ext::pkix::name::GeneralName::DnsName(dns) = gn {
                            out.insert(dns.as_str().to_string());
                        }
                    }
                }
            }
        }
    }
    out
}

fn policy_matches(policy: &DidX509Policy, leaf: &Certificate) -> bool {
    if let Some(cn) = &policy.require_subject_cn {
        if subject_cn(leaf).as_deref() != Some(cn.as_str()) {
            return false;
        }
    }
    if !policy.require_eku.is_empty() {
        let have = leaf_ekus(leaf);
        if !policy.require_eku.iter().all(|e| have.contains(e)) {
            return false;
        }
    }
    if !policy.require_san_dns.is_empty() {
        let have = leaf_san_dns(leaf);
        if !policy.require_san_dns.iter().all(|s| have.contains(s)) {
            return false;
        }
    }
    true
}

/// Verify a COSE_Sign1 fragment envelope that carries an `x5chain`, against the configured
/// `did:x509` anchors and revocation list. On success returns the matched anchor's `did`
/// (which the caller requires to equal the issuer the envelope declares).
///
/// Steps (all fail-closed): parse the chain → for each anchor, locate its trusted CA in the
/// chain by fingerprint → path-validate leaf→…→CA (signatures + validity) → check none of the
/// chain certs is revoked → check the `did:x509` policy over the leaf → verify the COSE_Sign1
/// signature with the leaf key.
///
/// There is no separate payload-equality check any more, and none is needed. It existed
/// because the fragment's fields were supplied by the caller next to the envelope, so
/// something had to tie the two together; now they are parsed *out of* the envelope, and the
/// COSE signature already covers the protected header and payload they come from.
pub fn verify_x509_cose(
    anchors: &HashMap<String, DidX509Anchor>,
    revoked: &HashSet<[u8; 32]>,
    cose_sign1: &[u8],
) -> Result<String, FragmentError> {
    use coset::CborSerializable;

    if anchors.is_empty() {
        return Err(FragmentError::UntrustedCa);
    }
    let sign1 =
        coset::CoseSign1::from_slice(cose_sign1).map_err(|_| FragmentError::InvalidCertChain)?;

    let chain_der = extract_x5chain(&sign1)?;
    let mut fps = Vec::with_capacity(chain_der.len());
    let mut certs = Vec::with_capacity(chain_der.len());
    for der in &chain_der {
        fps.push(fingerprint(der));
        certs.push(Certificate::from_der(der).map_err(|_| FragmentError::InvalidCertChain)?);
    }

    // Revocation is independent of which anchor matches: any revoked cert in the chain fails.
    if fps.iter().any(|fp| revoked.contains(fp)) {
        return Err(FragmentError::RevokedCertificate);
    }

    // Find an anchor whose trusted CA fingerprint appears in the chain.
    for anchor in anchors.values() {
        let Some(ca_idx) = fps.iter().position(|fp| *fp == anchor.ca_fingerprint) else {
            continue;
        };

        // Path-validate leaf(0) → … → CA(ca_idx): each cert signed by the next, all in date.
        for i in 0..=ca_idx {
            check_validity(&certs[i])?;
            if i < ca_idx {
                verify_link(&certs[i], &certs[i + 1])?;
            }
        }

        // did:x509 policy over the leaf.
        if !policy_matches(&anchor.policy, &certs[0]) {
            return Err(FragmentError::DidX509Mismatch);
        }

        // Verify the COSE_Sign1 signature with the leaf key, dispatching on the envelope's
        // declared algorithm (ES256/ES384/PS256/RS256/EdDSA).
        use coset::iana::EnumI64;
        let alg = match &sign1.protected.header.alg {
            Some(coset::RegisteredLabelWithPrivate::Assigned(a)) => {
                CoseAlg::from_i64(a.to_i64()).ok_or(FragmentError::InvalidSignature)?
            }
            _ => return Err(FragmentError::InvalidSignature),
        };
        let leaf_key = cert_key(&certs[0])?;
        sign1
            .verify_signature(b"", |sig, tbs| leaf_key.verify_cose(alg, tbs, sig))
            .map_err(|_| FragmentError::InvalidSignature)?;

        return Ok(anchor.did.clone());
    }

    // No configured anchor's CA appeared in the presented chain.
    Err(FragmentError::UntrustedCa)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PolicyFragment;
    use coset::cbor::value::Value;
    use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, Signature as EcSignature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use rand_core::OsRng;
    use std::convert::TryFrom;
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::{Time, Validity};

    const EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";

    fn spki_of(sk: &SigningKey) -> SubjectPublicKeyInfoOwned {
        let der = sk.verifying_key().to_public_key_der().unwrap();
        SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).unwrap()
    }

    fn mint_ca(cn: &str, sk: &SigningKey) -> Vec<u8> {
        let subject = Name::from_str(&format!("CN={cn}")).unwrap();
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            validity,
            subject,
            spki_of(sk),
            sk,
        )
        .unwrap();
        builder.build::<DerSignature>().unwrap().to_der().unwrap()
    }

    /// Mint a leaf signed by the CA key, with a code-signing EKU. `validity` lets tests mint
    /// an expired leaf.
    fn mint_leaf(
        cn: &str,
        leaf_sk: &SigningKey,
        ca_cn: &str,
        ca_sk: &SigningKey,
        validity: Validity,
    ) -> Vec<u8> {
        let issuer = Name::from_str(&format!("CN={ca_cn}")).unwrap();
        let subject = Name::from_str(&format!("CN={cn}")).unwrap();
        let mut builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(2u32),
            validity,
            subject,
            spki_of(leaf_sk),
            ca_sk,
        )
        .unwrap();
        let eku = ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(EKU_CODE_SIGNING)]);
        builder.add_extension(&eku).unwrap();
        builder.build::<DerSignature>().unwrap().to_der().unwrap()
    }

    /// Mint an intermediate CA (basicConstraints cA=TRUE) signed by the root CA key.
    fn mint_intermediate(
        cn: &str,
        int_sk: &SigningKey,
        root_cn: &str,
        root_sk: &SigningKey,
    ) -> Vec<u8> {
        let issuer = Name::from_str(&format!("CN={root_cn}")).unwrap();
        let subject = Name::from_str(&format!("CN={cn}")).unwrap();
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        let builder = CertificateBuilder::new(
            Profile::SubCA {
                issuer,
                path_len_constraint: None,
            },
            SerialNumber::from(3u32),
            validity,
            subject,
            spki_of(int_sk),
            root_sk,
        )
        .unwrap();
        builder.build::<DerSignature>().unwrap().to_der().unwrap()
    }

    fn cose_with_chain(statement: &[u8], leaf_sk: &SigningKey, chain: &[Vec<u8>]) -> Vec<u8> {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let mut unprotected = coset::Header::default();
        unprotected.rest.push((
            coset::Label::Int(COSE_HEADER_X5CHAIN),
            Value::Array(chain.iter().map(|c| Value::Bytes(c.clone())).collect()),
        ));
        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(statement.to_vec())
            .create_signature(b"", |tbs| {
                let sig: EcSignature = leaf_sk.sign(tbs);
                sig.to_bytes().to_vec()
            })
            .build()
            .to_vec()
            .unwrap()
    }

    fn anchor_for(ca_der: &[u8], did: &str) -> DidX509Anchor {
        DidX509Anchor {
            did: did.to_string(),
            ca_fingerprint: fingerprint(ca_der),
            policy: DidX509Policy {
                require_eku: vec![EKU_CODE_SIGNING.to_string()],
                ..Default::default()
            },
        }
    }

    /// Any payload will do here. `verify_x509_cose` authenticates the *envelope* — chain,
    /// policy, revocation, signature — and no longer inspects what is inside it, so these
    /// tests no longer need to build a fragment at all.
    fn payload() -> Vec<u8> {
        b"package agent_policy.fragments.test\n".to_vec()
    }

    /// TC-F1.9: a leaf under a trusted CA, satisfying the did:x509 policy, verifies; the
    /// derived did equals the anchor did.
    #[test]
    fn tc_f1_9_valid_chain_accepted() {
        let ca_sk = SigningKey::random(&mut OsRng);
        let leaf_sk = SigningKey::random(&mut OsRng);
        let ca = mint_ca("test-ca", &ca_sk);
        let leaf = mint_leaf(
            "issuerX",
            &leaf_sk,
            "test-ca",
            &ca_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        let anchor = anchor_for(&ca, "did:x509:test:issuerX");

        let cose = cose_with_chain(&payload(), &leaf_sk, &[leaf, ca]);
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);
        let did = verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap();
        assert_eq!(did, "did:x509:test:issuerX");
    }

    /// TC-F1.10: an untrusted CA (fingerprint not configured) is rejected.
    #[test]
    fn tc_f1_10_untrusted_ca_rejected() {
        let ca_sk = SigningKey::random(&mut OsRng);
        let other_sk = SigningKey::random(&mut OsRng);
        let leaf_sk = SigningKey::random(&mut OsRng);
        let ca = mint_ca("test-ca", &ca_sk);
        let other_ca = mint_ca("other-ca", &other_sk);
        let leaf = mint_leaf(
            "issuerX",
            &leaf_sk,
            "test-ca",
            &ca_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        // Anchor trusts a different CA than the one in the chain.
        let anchor = anchor_for(&other_ca, "did:x509:test:issuerX");

        let cose = cose_with_chain(&payload(), &leaf_sk, &[leaf, ca]);
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap_err(),
            FragmentError::UntrustedCa
        );
    }

    /// TC-F1.10b: a broken leaf signature (wrong signing key over the COSE) is rejected.
    #[test]
    fn tc_f1_10b_broken_signature_rejected() {
        let ca_sk = SigningKey::random(&mut OsRng);
        let leaf_sk = SigningKey::random(&mut OsRng);
        let attacker_sk = SigningKey::random(&mut OsRng);
        let ca = mint_ca("test-ca", &ca_sk);
        let leaf = mint_leaf(
            "issuerX",
            &leaf_sk,
            "test-ca",
            &ca_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        let anchor = anchor_for(&ca, "did:x509:test:issuerX");

        // COSE signed by an attacker key, not the leaf's key.
        let cose = cose_with_chain(&payload(), &attacker_sk, &[leaf, ca]);
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap_err(),
            FragmentError::InvalidSignature
        );
    }

    /// TC-F1.10c: an expired leaf is rejected.
    #[test]
    fn tc_f1_10c_expired_leaf_rejected() {
        let ca_sk = SigningKey::random(&mut OsRng);
        let leaf_sk = SigningKey::random(&mut OsRng);
        let ca = mint_ca("test-ca", &ca_sk);
        // Validity window entirely in the past.
        let past = Validity {
            not_before: Time::try_from(std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000))
                .unwrap(),
            not_after: Time::try_from(std::time::UNIX_EPOCH + Duration::from_secs(1_000_100_000))
                .unwrap(),
        };
        let leaf = mint_leaf("issuerX", &leaf_sk, "test-ca", &ca_sk, past);
        let anchor = anchor_for(&ca, "did:x509:test:issuerX");

        let cose = cose_with_chain(&payload(), &leaf_sk, &[leaf, ca]);
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap_err(),
            FragmentError::CertExpired
        );
    }

    /// TC-F1.11: a revoked leaf (fingerprint on the measured list) is rejected even with a
    /// valid chain and signature.
    #[test]
    fn tc_f1_11_revoked_leaf_rejected() {
        let ca_sk = SigningKey::random(&mut OsRng);
        let leaf_sk = SigningKey::random(&mut OsRng);
        let ca = mint_ca("test-ca", &ca_sk);
        let leaf = mint_leaf(
            "issuerX",
            &leaf_sk,
            "test-ca",
            &ca_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        let anchor = anchor_for(&ca, "did:x509:test:issuerX");

        let cose = cose_with_chain(&payload(), &leaf_sk, &[leaf.clone(), ca]);
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);
        let mut revoked = HashSet::new();
        revoked.insert(fingerprint(&leaf));
        assert_eq!(
            verify_x509_cose(&anchors, &revoked, &cose).unwrap_err(),
            FragmentError::RevokedCertificate
        );
    }

    /// TC-F1.12: a rotated leaf (new key + cert, same CA and policy) verifies with no
    /// anchor/config change — trust is anchored on the CA + policy, not the leaf key.
    #[test]
    fn tc_f1_12_rotated_leaf_accepted() {
        let ca_sk = SigningKey::random(&mut OsRng);
        let ca = mint_ca("test-ca", &ca_sk);
        let anchor = anchor_for(&ca, "did:x509:test:issuerX");
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);

        // First leaf.
        let leaf1_sk = SigningKey::random(&mut OsRng);
        let leaf1 = mint_leaf(
            "issuerX",
            &leaf1_sk,
            "test-ca",
            &ca_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        let cose1 = cose_with_chain(&payload(), &leaf1_sk, &[leaf1, ca.clone()]);
        assert!(verify_x509_cose(&anchors, &HashSet::new(), &cose1).is_ok());

        // Rotated leaf: brand-new key, same CA + policy, no config change.
        let leaf2_sk = SigningKey::random(&mut OsRng);
        let leaf2 = mint_leaf(
            "issuerX",
            &leaf2_sk,
            "test-ca",
            &ca_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        let cose2 = cose_with_chain(&payload(), &leaf2_sk, &[leaf2, ca]);
        assert!(verify_x509_cose(&anchors, &HashSet::new(), &cose2).is_ok());
    }

    /// TC-F1.12d: the did:x509 policy is enforced — a leaf missing the required EKU is
    /// rejected as a did:x509 mismatch even though the chain is otherwise valid.
    #[test]
    fn tc_f1_12d_policy_mismatch_rejected() {
        let ca_sk = SigningKey::random(&mut OsRng);
        let leaf_sk = SigningKey::random(&mut OsRng);
        let ca = mint_ca("test-ca", &ca_sk);
        let leaf = mint_leaf(
            "issuerX",
            &leaf_sk,
            "test-ca",
            &ca_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        // Anchor requires an EKU the leaf does not carry (server-auth instead of code-signing).
        let anchor = DidX509Anchor {
            did: "did:x509:test:issuerX".to_string(),
            ca_fingerprint: fingerprint(&ca),
            policy: DidX509Policy {
                require_eku: vec!["1.3.6.1.5.5.7.3.1".to_string()],
                ..Default::default()
            },
        };
        let cose = cose_with_chain(&payload(), &leaf_sk, &[leaf, ca]);
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap_err(),
            FragmentError::DidX509Mismatch
        );
    }

    /// TC-F1.13: a 3-cert chain (leaf ← intermediate CA ← root CA), anchored on the root
    /// fingerprint, path-validates through the intermediate and is accepted.
    #[test]
    fn tc_f1_13_intermediate_ca_chain_accepted() {
        let root_sk = SigningKey::random(&mut OsRng);
        let int_sk = SigningKey::random(&mut OsRng);
        let leaf_sk = SigningKey::random(&mut OsRng);
        let root = mint_ca("root-ca", &root_sk);
        let intermediate = mint_intermediate("int-ca", &int_sk, "root-ca", &root_sk);
        let leaf = mint_leaf(
            "issuerX",
            &leaf_sk,
            "int-ca",
            &int_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        // Trust anchored on the ROOT fingerprint; the intermediate is validated in between.
        let anchor = anchor_for(&root, "did:x509:test:issuerX");
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);

        let cose = cose_with_chain(&payload(), &leaf_sk, &[leaf, intermediate, root]);
        let did = verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap();
        assert_eq!(did, "did:x509:test:issuerX");
    }

    /// TC-F1.13b: a chain whose "intermediate" is a non-CA leaf (basicConstraints cA=FALSE)
    /// is rejected — a plain leaf cannot act as an issuer and mint sub-certificates.
    #[test]
    fn tc_f1_13b_non_ca_intermediate_rejected() {
        let root_sk = SigningKey::random(&mut OsRng);
        let mid_sk = SigningKey::random(&mut OsRng); // a LEAF (cA=FALSE), misused as an issuer
        let subleaf_sk = SigningKey::random(&mut OsRng);
        let root = mint_ca("root-ca", &root_sk);
        let mid_leaf = mint_leaf(
            "mid",
            &mid_sk,
            "root-ca",
            &root_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        let subleaf = mint_leaf(
            "issuerX",
            &subleaf_sk,
            "mid",
            &mid_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        let anchor = anchor_for(&root, "did:x509:test:issuerX");
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);

        let cose = cose_with_chain(&payload(), &subleaf_sk, &[subleaf, mid_leaf, root]);
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap_err(),
            FragmentError::InvalidCertChain
        );
    }
    // ---- F-163: the presented chain is length-bounded (hcsshim parity) ----

    /// Build `[leaf, root, root, ...]` padded to exactly `total` certificates. Padding with
    /// copies of the root is deliberate: it costs no extra key generation, and because the
    /// anchor is located by *first* fingerprint match the padding sits past `ca_idx`, so it
    /// is fingerprinted and parsed but never path-validated — which is precisely the work an
    /// attacker would be buying with a long chain.
    fn padded_chain(total: usize) -> (Vec<Vec<u8>>, SigningKey, Vec<u8>) {
        let root_sk = SigningKey::random(&mut OsRng);
        let leaf_sk = SigningKey::random(&mut OsRng);
        let root = mint_ca("root-ca", &root_sk);
        let leaf = mint_leaf(
            "issuerX",
            &leaf_sk,
            "root-ca",
            &root_sk,
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
        );
        let mut chain = vec![leaf, root.clone()];
        while chain.len() < total {
            chain.push(root.clone());
        }
        (chain, leaf_sk, root)
    }

    /// A chain at exactly the limit still verifies. Without this the rejection test below
    /// would also pass with the bound set absurdly low, or applied with the wrong comparison.
    #[test]
    fn a_chain_at_the_length_limit_is_still_accepted() {
        let (chain, leaf_sk, root) = padded_chain(MAX_X5CHAIN_CERTS);
        assert_eq!(chain.len(), MAX_X5CHAIN_CERTS);
        let anchor = anchor_for(&root, "did:x509:test:issuerX");
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);

        let cose = cose_with_chain(&payload(), &leaf_sk, &chain);
        let did = verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap();
        assert_eq!(did, "did:x509:test:issuerX");
    }

    /// One certificate past the limit is refused, and refused *as* an over-length chain
    /// rather than as a generic malformed one, so the reason reaches the operator.
    #[test]
    fn a_chain_past_the_length_limit_is_refused() {
        let (chain, leaf_sk, root) = padded_chain(MAX_X5CHAIN_CERTS + 1);
        let anchor = anchor_for(&root, "did:x509:test:issuerX");
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);

        let cose = cose_with_chain(&payload(), &leaf_sk, &chain);
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap_err(),
            FragmentError::CertChainTooLong {
                len: MAX_X5CHAIN_CERTS + 1,
                max: MAX_X5CHAIN_CERTS,
            }
        );
    }

    /// The length bound must not become a routing lever. `verify_envelope_with` picks the
    /// X.509 path on `cose_has_x5chain`, so if that predicate answered "no" for an
    /// over-length chain the envelope would fall through to the raw-key path and the new
    /// error would never be raised — turning a refusal into a detour.
    #[test]
    fn an_over_length_chain_is_still_routed_to_the_x509_path() {
        let (chain, leaf_sk, _root) = padded_chain(MAX_X5CHAIN_CERTS + 1);
        let cose = cose_with_chain(&payload(), &leaf_sk, &chain);
        assert!(
            cose_has_x5chain(&cose),
            "an over-length chain must still be recognised as carrying one"
        );
    }

    use p384::ecdsa::{DerSignature as P384DerSig, Signature as P384Sig, SigningKey as P384Sk};
    use rsa::pkcs1v15::{Signature as RsaPkcsSig, SigningKey as RsaPkcsSk};
    use rsa::signature::SignatureEncoding as _RsaSigEnc;
    use rsa::RsaPrivateKey;
    use sha2::Sha256 as _Sha256;

    fn spki_p384(sk: &P384Sk) -> SubjectPublicKeyInfoOwned {
        let der = sk.verifying_key().to_public_key_der().unwrap();
        SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).unwrap()
    }

    fn mint_ca_p384(cn: &str, sk: &P384Sk) -> Vec<u8> {
        let subject = Name::from_str(&format!("CN={cn}")).unwrap();
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            validity,
            subject,
            spki_p384(sk),
            sk,
        )
        .unwrap()
        .build::<P384DerSig>()
        .unwrap()
        .to_der()
        .unwrap()
    }

    fn mint_leaf_p384(cn: &str, leaf_sk: &P384Sk, ca_cn: &str, ca_sk: &P384Sk) -> Vec<u8> {
        let issuer = Name::from_str(&format!("CN={ca_cn}")).unwrap();
        let subject = Name::from_str(&format!("CN={cn}")).unwrap();
        let mut b = CertificateBuilder::new(
            Profile::Leaf {
                issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(2u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            subject,
            spki_p384(leaf_sk),
            ca_sk,
        )
        .unwrap();
        b.add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
            EKU_CODE_SIGNING,
        )]))
        .unwrap();
        b.build::<P384DerSig>().unwrap().to_der().unwrap()
    }

    fn cose_es384(statement: &[u8], leaf_sk: &P384Sk, chain: &[Vec<u8>]) -> Vec<u8> {
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .build();
        let mut unprotected = coset::Header::default();
        unprotected.rest.push((
            coset::Label::Int(COSE_HEADER_X5CHAIN),
            Value::Array(chain.iter().map(|c| Value::Bytes(c.clone())).collect()),
        ));
        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(statement.to_vec())
            .create_signature(b"", |tbs| {
                let s: P384Sig = leaf_sk.sign(tbs);
                s.to_bytes().to_vec()
            })
            .build()
            .to_vec()
            .unwrap()
    }

    fn spki_rsa(sk: &RsaPrivateKey) -> SubjectPublicKeyInfoOwned {
        let der = sk.to_public_key().to_public_key_der().unwrap();
        SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).unwrap()
    }

    fn mint_ca_rsa(cn: &str, sk: &RsaPrivateKey) -> Vec<u8> {
        let signer = RsaPkcsSk::<_Sha256>::new(sk.clone());
        let subject = Name::from_str(&format!("CN={cn}")).unwrap();
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
        CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            validity,
            subject,
            spki_rsa(sk),
            &signer,
        )
        .unwrap()
        .build::<RsaPkcsSig>()
        .unwrap()
        .to_der()
        .unwrap()
    }

    fn mint_leaf_rsa(
        cn: &str,
        leaf_sk: &RsaPrivateKey,
        ca_cn: &str,
        ca_sk: &RsaPrivateKey,
    ) -> Vec<u8> {
        let signer = RsaPkcsSk::<_Sha256>::new(ca_sk.clone());
        let issuer = Name::from_str(&format!("CN={ca_cn}")).unwrap();
        let subject = Name::from_str(&format!("CN={cn}")).unwrap();
        let mut b = CertificateBuilder::new(
            Profile::Leaf {
                issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(2u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            subject,
            spki_rsa(leaf_sk),
            &signer,
        )
        .unwrap();
        b.add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
            EKU_CODE_SIGNING,
        )]))
        .unwrap();
        b.build::<RsaPkcsSig>().unwrap().to_der().unwrap()
    }

    fn cose_rs256(statement: &[u8], leaf_sk: &RsaPrivateKey, chain: &[Vec<u8>]) -> Vec<u8> {
        let signer = RsaPkcsSk::<_Sha256>::new(leaf_sk.clone());
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::RS256)
            .build();
        let mut unprotected = coset::Header::default();
        unprotected.rest.push((
            coset::Label::Int(COSE_HEADER_X5CHAIN),
            Value::Array(chain.iter().map(|c| Value::Bytes(c.clone())).collect()),
        ));
        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(statement.to_vec())
            .create_signature(b"", |tbs| {
                let s: RsaPkcsSig = signer.sign(tbs);
                s.to_vec()
            })
            .build()
            .to_vec()
            .unwrap()
    }

    /// TC-F1.14: an ES384 (EC P-384) leaf under a P-384 CA verifies end-to-end.
    #[test]
    fn tc_f1_14_es384_chain_accepted() {
        let ca_sk = P384Sk::random(&mut OsRng);
        let leaf_sk = P384Sk::random(&mut OsRng);
        let ca = mint_ca_p384("es384-ca", &ca_sk);
        let leaf = mint_leaf_p384("issuerX", &leaf_sk, "es384-ca", &ca_sk);
        let anchor = anchor_for(&ca, "did:x509:test:issuerX");
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);
        let cose = cose_es384(&payload(), &leaf_sk, &[leaf, ca]);
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap(),
            "did:x509:test:issuerX"
        );
    }

    /// TC-F1.15: an RSA (RS256, PKCS#1 v1.5 / SHA-256) leaf under an RSA CA verifies
    /// end-to-end (chain-link RSA signature + RS256 COSE leaf signature).
    #[test]
    fn tc_f1_15_rsa_rs256_chain_accepted() {
        let ca_sk = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let leaf_sk = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let ca = mint_ca_rsa("rsa-ca", &ca_sk);
        let leaf = mint_leaf_rsa("issuerX", &leaf_sk, "rsa-ca", &ca_sk);
        let anchor = anchor_for(&ca, "did:x509:test:issuerX");
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);
        let cose = cose_rs256(&payload(), &leaf_sk, &[leaf, ca]);
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).unwrap(),
            "did:x509:test:issuerX"
        );
    }

    /// TC-F1.15b: an RS256 envelope whose payload has been altered after signing is rejected
    /// (the RSA path is not a rubber stamp).
    ///
    /// The payload is the policy module itself now, so this is the case that matters most on
    /// this path: swapping in a different Rego module under a genuine issuer's signature.
    /// There is no separate "presented statement" left to disagree with the payload, so the
    /// only way to reach a mismatch is to tamper with the signed bytes directly.
    #[test]
    fn tc_f1_15b_rsa_tampered_payload_rejected() {
        use coset::CborSerializable;

        let ca_sk = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let leaf_sk = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let ca = mint_ca_rsa("rsa-ca", &ca_sk);
        let leaf = mint_leaf_rsa("issuerX", &leaf_sk, "rsa-ca", &ca_sk);
        let anchor = anchor_for(&ca, "did:x509:test:issuerX");
        let mut anchors = HashMap::new();
        anchors.insert(anchor.did.clone(), anchor);

        let cose = cose_rs256(&payload(), &leaf_sk, &[leaf, ca]);
        assert!(
            verify_x509_cose(&anchors, &HashSet::new(), &cose).is_ok(),
            "fixture must verify before it is tampered with"
        );

        let mut tampered = coset::CoseSign1::from_slice(&cose).unwrap();
        tampered.payload = Some(b"package agent_policy.fragments.evil\nallow := true\n".to_vec());
        assert_eq!(
            verify_x509_cose(&anchors, &HashSet::new(), &tampered.to_vec().unwrap()).unwrap_err(),
            FragmentError::InvalidSignature
        );
    }

    /// A canonical `did:x509` round-trips: the fingerprint it names is the one it was built
    /// from, and declared predicates parse into (name, args).
    #[test]
    fn tc_f1_10e_canonical_did_parses() {
        let fp = [7u8; 32];
        let did = format!("{}::subject:CN:signer::eku:{}", did_x509_for(&fp), EKU_CODE_SIGNING);
        let parts = parse_did_x509(&did).unwrap();
        assert_eq!(parts.ca_fingerprint, fp);
        assert_eq!(
            parts.predicates,
            vec![
                ("subject".to_string(), vec!["CN".to_string(), "signer".to_string()]),
                ("eku".to_string(), vec![EKU_CODE_SIGNING.to_string()]),
            ]
        );
        // Percent-encoded arguments decode, so a value containing ':' survives the split.
        let did = format!("{}::subject:CN:a%3Ab", did_x509_for(&fp));
        assert_eq!(parse_did_x509(&did).unwrap().predicates[0].1[1], "a:b");
    }

    /// A non-ASCII CN survives decoding, percent-encoded or literal. Decoding byte-by-byte
    /// into `char` would yield mojibake ("Ã©"), so an anchor naming a CA whose CN is not
    /// ASCII would be refused even though its DID and its leaf policy agree.
    #[test]
    fn tc_f1_10e_non_ascii_arguments_decode_as_utf8() {
        let fp = [7u8; 32];
        for encoded in ["caf%C3%A9", "café"] {
            let did = format!("{}::subject:CN:{encoded}", did_x509_for(&fp));
            assert_eq!(
                parse_did_x509(&did).unwrap().predicates[0].1[1],
                "café",
                "decoding {encoded}"
            );
        }
        // A percent escape that is not valid UTF-8 is refused rather than replaced, so a
        // decoded argument is always exactly the bytes the DID named.
        let bad = format!("{}::subject:CN:%FF", did_x509_for(&fp));
        assert_eq!(
            parse_did_x509(&bad).unwrap_err(),
            FragmentError::MalformedAnchorDid
        );
    }

    /// TC-F1.10e: an anchor whose DID names a *different* CA than the one it anchors on is
    /// refused, so a DID can never advertise a trust root that was not the one enforced.
    #[test]
    fn tc_f1_10e_anchor_did_must_name_its_own_ca() {
        let good = DidX509Anchor {
            did: did_x509_for(&[1u8; 32]),
            ca_fingerprint: [1u8; 32],
            policy: DidX509Policy::default(),
        };
        assert!(good.validate().is_ok());

        let mismatched = DidX509Anchor {
            did: did_x509_for(&[2u8; 32]),
            ca_fingerprint: [1u8; 32],
            ..good.clone()
        };
        assert_eq!(
            mismatched.validate().unwrap_err(),
            FragmentError::AnchorDidMismatch
        );

        // A DID that is not canonical carries no CA to compare against at all.
        let opaque = DidX509Anchor {
            did: "did:x509:test:issuerX".to_string(),
            ..good.clone()
        };
        assert_eq!(
            opaque.validate().unwrap_err(),
            FragmentError::MalformedAnchorDid
        );
    }

    /// TC-F1.10e: a DID may not advertise a leaf constraint the policy does not enforce, and
    /// may not name a predicate this implementation cannot check. Both would let the accepted
    /// issuer string read as a stronger promise than what was actually verified.
    #[test]
    fn tc_f1_10e_anchor_did_predicates_must_be_enforced() {
        let fp = [3u8; 32];
        let base = DidX509Anchor {
            did: did_x509_for(&fp),
            ca_fingerprint: fp,
            policy: DidX509Policy::default(),
        };

        let claims_cn = DidX509Anchor {
            did: format!("{}::subject:CN:signer", did_x509_for(&fp)),
            ..base.clone()
        };
        assert_eq!(
            claims_cn.validate().unwrap_err(),
            FragmentError::AnchorDidMismatch
        );

        // ... and is accepted once the policy actually requires that CN.
        let enforced = DidX509Anchor {
            policy: DidX509Policy {
                require_subject_cn: Some("signer".to_string()),
                ..Default::default()
            },
            ..claims_cn.clone()
        };
        assert!(enforced.validate().is_ok());

        // A different CN is not "close enough".
        let wrong_cn = DidX509Anchor {
            policy: DidX509Policy {
                require_subject_cn: Some("someone-else".to_string()),
                ..Default::default()
            },
            ..claims_cn
        };
        assert_eq!(
            wrong_cn.validate().unwrap_err(),
            FragmentError::AnchorDidMismatch
        );

        // Predicates we cannot enforce are refused rather than silently ignored.
        for did in [
            format!("{}::fulcio-issuer:github.com%2Flogin", did_x509_for(&fp)),
            format!("{}::subject:O:contoso", did_x509_for(&fp)),
            format!("{}::san:email:signer%40contoso.com", did_x509_for(&fp)),
        ] {
            let a = DidX509Anchor { did, ..base.clone() };
            assert_eq!(
                a.validate().unwrap_err(),
                FragmentError::UnsupportedAnchorDidPolicy
            );
        }

        // A policy stricter than the DID advertises is fine: enforcing more than promised is
        // not a confusion, only enforcing less would be.
        let stricter = DidX509Anchor {
            policy: DidX509Policy {
                require_eku: vec![EKU_CODE_SIGNING.to_string()],
                ..Default::default()
            },
            ..base
        };
        assert!(stricter.validate().is_ok());
    }

    /// TC-F1.10e: the trust store is the only way an anchor reaches production, and it
    /// refuses an inconsistent one — the check cannot be skipped by configuration.
    #[test]
    fn tc_f1_10e_store_refuses_inconsistent_anchor() {
        let mut store = crate::FragmentStore::new(false);
        assert_eq!(
            store
                .authorize_did_x509(DidX509Anchor {
                    did: did_x509_for(&[9u8; 32]),
                    ca_fingerprint: [8u8; 32],
                    policy: DidX509Policy::default(),
                })
                .unwrap_err(),
            FragmentError::AnchorDidMismatch
        );
        assert!(!store.has_did_x509_anchors());

        assert!(store
            .authorize_did_x509(DidX509Anchor {
                did: did_x509_for(&[8u8; 32]),
                ca_fingerprint: [8u8; 32],
                policy: DidX509Policy::default(),
            })
            .is_ok());
        assert!(store.has_did_x509_anchors());
    }
}
