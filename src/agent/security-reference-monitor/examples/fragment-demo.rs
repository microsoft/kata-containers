// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-1 signed-policy-fragments capability demo.
//!
//! A single, self-contained, offline proof of every fragment feature, runnable by any
//! developer with no cluster, no openssl, and no network:
//!
//! ```text
//! cargo run --example fragment-demo -p kata-security-reference-monitor \
//!     --target aarch64-unknown-linux-musl
//! ```
//!
//! It exercises the real `FragmentStore` verification path and asserts on every outcome, so
//! it doubles as an executable specification and a regression guard. Sections:
//!
//!   1. Core   (FR-1a/b/e/g): signed, authorized, add-only, monotonic, composed fragments.
//!   2. FR-1f: transparency Trust List — multiple ledgers, allowed_ledgers scoping,
//!             policy-driven required_receipts, and ledger key rotation.
//!   3. FR-1d: did:x509 issuer identity — certificate-chain trust, revocation, and leaf
//!             rotation under the same CA + policy (no config change).
//!   4. FR-1j: append-only application ordering — a rolling, signed log head that rejects
//!             reordering/omission/insertion and yields a customer-auditable record of the
//!             exact sequence in which fragments were applied.

use ed25519_dalek::{Signer, SigningKey};
use kata_security_reference_monitor::did_x509::{DidX509Anchor, DidX509Policy};
use kata_security_reference_monitor::{FragmentError, FragmentStore, PolicyFragment};

// ---- x509 minting (in-process P-256 PKI; needs only the dev-deps the tests already use) --
use const_oid::ObjectIdentifier;
use coset::cbor::value::Value;
use coset::{iana, CborSerializable};
use p256::ecdsa::{DerSignature, Signature as EcSignature, SigningKey as EcSigningKey};
use p256::pkcs8::EncodePublicKey;
use rand_core::OsRng;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

const EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";

fn ed_key(seed: u8) -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

// The fragment *is* its COSE_Sign1 envelope, so the demo signs into one and hands the store
// nothing else -- the same thing the guest does with what arrives over the RPC. Receipts are
// countersignatures over the same signed bytes and legitimately travel outside the envelope,
// so they are re-attached after parsing.
fn tbs_of(f: &PolicyFragment) -> Vec<u8> {
    f.to_unsigned_cose(coset::iana::Algorithm::EdDSA).tbs_data(b"")
}

fn env(sk: &SigningKey, f: &PolicyFragment) -> Vec<u8> {
    use coset::CborSerializable;
    let mut s = f.to_unsigned_cose(coset::iana::Algorithm::EdDSA);
    s.signature = sk.sign(&s.tbs_data(b"")).to_bytes().to_vec();
    s.to_vec().expect("serialize COSE_Sign1")
}

fn verify_frag(
    store: &FragmentStore,
    sk: &SigningKey,
    f: &PolicyFragment,
) -> Result<kata_security_reference_monitor::fragments::VerifiedFragment, FragmentError> {
    store.verify_envelope_with(&env(sk, f), |g| {
        g.receipt = f.receipt.clone();
        g.receipt_ledger = f.receipt_ledger.clone();
        g.receipt_proof = f.receipt_proof.clone();
        g.extra_receipts = f.extra_receipts.clone();
    })
}

fn load_frag(
    store: &mut FragmentStore,
    sk: &SigningKey,
    f: &PolicyFragment,
) -> Result<(), FragmentError> {
    let v = verify_frag(store, sk, f)?;
    store.commit(&v);
    Ok(())
}

fn ok(label: &str) {
    println!("  \x1b[32mPASS\x1b[0m {label}");
}

fn hexs(b: &[u8]) -> String {
    b.iter()
        .take(8)
        .map(|x| format!("{:02x}", x))
        .collect::<String>()
        + "…"
}

// ---------------------------------------------------------------------------------------
fn section1_core() {
    println!("\n== 1. Core: signed, authorized, add-only, monotonic (FR-1a/b/e/g) ==");
    let (sk, pk) = ed_key(1);
    let mut store = FragmentStore::new(false);
    store.authorize_issuer("issuerA", &pk).unwrap();

    // Unauthorized issuer -> rejected (fail-closed).
    let rogue = PolicyFragment {
        issuer: "attacker".into(),
        svn: 1,
        ..Default::default()
    };
    assert!(matches!(
        verify_frag(&store, &sk, &rogue),
        Err(FragmentError::UnauthorizedIssuer(_))
    ));
    ok("unknown issuer rejected");

    // A properly signed fragment from an authorized issuer is accepted.
    let f = PolicyFragment {
        issuer: "issuerA".into(),
        svn: 1,
        includes: vec!["exec".into()],
        ..Default::default()
    };
    assert!(load_frag(&mut store, &sk, &f).is_ok());
    ok("authorized + signed fragment accepted");

    // Tampering after signing invalidates the signature. The scope lives in the *protected*
    // header, which is inside the COSE Sig_structure, so swapping it in a signed envelope
    // breaks the signature rather than going unnoticed.
    let mut widened = f.clone();
    widened.includes = vec!["exec".into(), "mount".into()];
    let mut tampered = coset::CoseSign1::from_slice(&env(&sk, &f)).unwrap();
    tampered.protected = coset::CoseSign1::from_slice(&env(&sk, &widened))
        .unwrap()
        .protected;
    assert!(matches!(
        store.verify_envelope(&tampered.to_vec().unwrap()),
        Err(FragmentError::InvalidSignature)
    ));
    ok("tampered fragment rejected (scope bound into signature)");

    // Monotonic SVN: replaying the same SVN is rejected.
    let replay = PolicyFragment {
        issuer: "issuerA".into(),
        svn: 1,
        ..Default::default()
    };
    assert!(matches!(
        verify_frag(&store, &sk, &replay),
        Err(FragmentError::RolledBackSvn { .. })
    ));
    ok("rolled-back SVN rejected (anti-replay)");
}

// ---------------------------------------------------------------------------------------
/// Attach a transparency receipt: a ledger countersignature over the *same* signed bytes
/// the issuer signs. `tbs_data` does not depend on the issuer's signature, so a ledger can
/// compute this without the issuer key -- which is why the receipt can be produced
/// independently and still bind to exactly this fragment.
fn signed_with_receipt(f: &mut PolicyFragment, ledger: &str, ledger_sk: &SigningKey) {
    let rsig = ledger_sk.sign(&tbs_of(f));
    f.receipt = Some(
        rsig.to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect(),
    );
    f.receipt_ledger = Some(ledger.to_string());
}

fn section2_trust_list() {
    println!("\n== 2. FR-1f: transparency Trust List (ledgers, scoping, required, rotation) ==");
    let (issuer_sk, issuer_pk) = ed_key(1);
    let (led_a_sk, led_a_pk) = ed_key(20);
    let (led_a2_sk, led_a2_pk) = ed_key(22); // rotated key for ledgerA
    let (led_b_sk, led_b_pk) = ed_key(21);
    let mut store = FragmentStore::new(false);
    store.authorize_issuer("issuerA", &issuer_pk).unwrap();
    store.declare_feed("issuerA", "prod", 0);
    store
        .load_transparency_trust_list(&[
            ("ledgerA".into(), vec![led_a_pk, led_a2_pk]),
            ("ledgerB".into(), vec![led_b_pk]),
        ])
        .unwrap();
    // prod may only be backed by ledgerA, and REQUIRES a receipt from it.
    store.set_allowed_ledgers("issuerA", "prod", &["ledgerA".to_string()]);
    store.require_receipt_for("issuerA", "prod", &["ledgerA".to_string()]);

    // Valid receipt from the allowed ledger -> accepted.
    let mut f = PolicyFragment {
        issuer: "issuerA".into(),
        feed: "prod".into(),
        svn: 1,
        ..Default::default()
    };
    signed_with_receipt(&mut f, "ledgerA", &led_a_sk);
    assert!(verify_frag(&store, &issuer_sk, &f).is_ok());
    ok("receipt from allowed ledger accepted");

    // Receipt from a non-allowed ledger -> rejected.
    let mut g = PolicyFragment {
        issuer: "issuerA".into(),
        feed: "prod".into(),
        svn: 1,
        ..Default::default()
    };
    signed_with_receipt(&mut g, "ledgerB", &led_b_sk);
    assert!(matches!(
        verify_frag(&store, &issuer_sk, &g),
        Err(FragmentError::LedgerNotAllowed { .. })
    ));
    ok("receipt from disallowed ledger rejected (allowed_ledgers)");

    // No receipt where one is required -> rejected.
    let h = PolicyFragment {
        issuer: "issuerA".into(),
        feed: "prod".into(),
        svn: 1,
        ..Default::default()
    };
    assert!(matches!(
        verify_frag(&store, &issuer_sk, &h),
        Err(FragmentError::MissingReceipt)
    ));
    ok("missing required receipt rejected (required_receipts)");

    // Rotation: a receipt signed by ledgerA's NEW key still verifies.
    let mut r = PolicyFragment {
        issuer: "issuerA".into(),
        feed: "prod".into(),
        svn: 2,
        ..Default::default()
    };
    signed_with_receipt(&mut r, "ledgerA", &led_a2_sk);
    assert!(verify_frag(&store, &issuer_sk, &r).is_ok());
    ok("receipt signed by rotated ledger key accepted (rotation)");
}

// ---------------------------------------------------------------------------------------
fn ec_spki(sk: &EcSigningKey) -> SubjectPublicKeyInfoOwned {
    let der = sk.verifying_key().to_public_key_der().unwrap();
    SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).unwrap()
}

fn mint_ca(cn: &str, sk: &EcSigningKey) -> Vec<u8> {
    let subject = Name::from_str(&format!("CN={cn}")).unwrap();
    let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
    CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        subject,
        ec_spki(sk),
        sk,
    )
    .unwrap()
    .build::<DerSignature>()
    .unwrap()
    .to_der()
    .unwrap()
}

fn mint_leaf(cn: &str, leaf_sk: &EcSigningKey, ca_cn: &str, ca_sk: &EcSigningKey) -> Vec<u8> {
    let issuer = Name::from_str(&format!("CN={ca_cn}")).unwrap();
    let subject = Name::from_str(&format!("CN={cn}")).unwrap();
    let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();
    let mut b = CertificateBuilder::new(
        Profile::Leaf {
            issuer,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(2u32),
        validity,
        subject,
        ec_spki(leaf_sk),
        ca_sk,
    )
    .unwrap();
    b.add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
        EKU_CODE_SIGNING,
    )]))
    .unwrap();
    b.build::<DerSignature>().unwrap().to_der().unwrap()
}

/// Sign a fragment into a did:x509 envelope: the same protected header and payload the
/// Ed25519 path produces, signed by an EC P-256 leaf, with the chain in the *unprotected*
/// x5chain header (COSE label 33) where RFC 9360 and hcsshim's `sign1util` put it.
///
/// The chain is not the identity — the leaf key having produced this signature is, and that
/// is what gets checked against the measured `did:x509` anchor.
fn cose_x509(f: &PolicyFragment, leaf_sk: &EcSigningKey, chain: &[Vec<u8>]) -> Vec<u8> {
    let mut s = f.to_unsigned_cose(iana::Algorithm::ES256);
    s.unprotected.rest.push((
        coset::Label::Int(33),
        Value::Array(chain.iter().map(|c| Value::Bytes(c.clone())).collect()),
    ));
    let sig: EcSignature = leaf_sk.sign(&s.tbs_data(b""));
    s.signature = sig.to_bytes().to_vec();
    s.to_vec().unwrap()
}

fn section3_did_x509() {
    println!("\n== 3. FR-1d: did:x509 issuer identity (chain trust, revocation, rotation) ==");
    let ca_sk = EcSigningKey::random(&mut OsRng);
    let ca = mint_ca("demo-ca", &ca_sk);
    let ca_fp = kata_security_reference_monitor::did_x509::sha256_fingerprint(&ca);
    let did_owned = kata_security_reference_monitor::did_x509::did_x509_for(&ca_fp);
    let did = did_owned.as_str();

    let mut store = FragmentStore::new(false);
    store
        .authorize_did_x509(DidX509Anchor {
            did: did.to_string(),
            ca_fingerprint: ca_fp,
            policy: DidX509Policy {
                require_eku: vec![EKU_CODE_SIGNING.into()],
                ..Default::default()
            },
        })
        .expect("anchor is self-consistent");

    // Valid chain to the trusted CA, leaf satisfies the policy -> accepted.
    let leaf1_sk = EcSigningKey::random(&mut OsRng);
    let leaf1 = mint_leaf("issuerX", &leaf1_sk, "demo-ca", &ca_sk);
    let f = PolicyFragment {
        issuer: did.into(),
        svn: 1,
        ..Default::default()
    };
    let cose = cose_x509(&f, &leaf1_sk, &[leaf1.clone(), ca.clone()]);
    assert!(store.verify_envelope(&cose).is_ok());
    ok("valid did:x509 chain accepted (identity = CA + policy, not a pinned key)");

    // Untrusted CA -> rejected.
    let other_ca_sk = EcSigningKey::random(&mut OsRng);
    let other_ca = mint_ca("evil-ca", &other_ca_sk);
    let evil_leaf_sk = EcSigningKey::random(&mut OsRng);
    let evil_leaf = mint_leaf("issuerX", &evil_leaf_sk, "evil-ca", &other_ca_sk);
    let cose_evil = cose_x509(&f, &evil_leaf_sk, &[evil_leaf, other_ca]);
    assert!(matches!(
        store.verify_envelope(&cose_evil),
        Err(FragmentError::UntrustedCa)
    ));
    ok("chain to an untrusted CA rejected");

    // Rotation: a brand-new leaf under the SAME CA + policy is accepted with no config change.
    let leaf2_sk = EcSigningKey::random(&mut OsRng);
    let leaf2 = mint_leaf("issuerX", &leaf2_sk, "demo-ca", &ca_sk);
    let f2 = PolicyFragment {
        issuer: did.into(),
        svn: 2,
        ..Default::default()
    };
    let cose2 = cose_x509(&f2, &leaf2_sk, &[leaf2, ca.clone()]);
    assert!(store.verify_envelope(&cose2).is_ok());
    ok("rotated leaf (new key, same CA) accepted with no config change");

    // Revocation: revoke leaf1's fingerprint; even a valid chain is now rejected.
    store
        .set_revoked_certs([kata_security_reference_monitor::did_x509::sha256_fingerprint(&leaf1)]);
    let f3 = PolicyFragment {
        issuer: did.into(),
        svn: 3,
        ..Default::default()
    };
    let cose3 = cose_x509(&f3, &leaf1_sk, &[leaf1, ca]);
    assert!(matches!(
        store.verify_envelope(&cose3),
        Err(FragmentError::RevokedCertificate)
    ));
    ok("revoked leaf rejected (measured revocation list)");
}

// ---------------------------------------------------------------------------------------
fn ordered_frag(issuer: &str, svn: u64, prev_head: &[u8]) -> PolicyFragment {
    let f = PolicyFragment {
        issuer: issuer.into(),
        svn,
        prev_log_head: Some(prev_head.to_vec()),
        ..Default::default()
    };
    f
}

fn section4_ordering() {
    println!("\n== 4. FR-1j: append-only application ordering (signed rolling log head) ==");
    let (sk, pk) = ed_key(1);
    let mut store = FragmentStore::new(false);
    store.authorize_issuer("issuerA", &pk).unwrap();
    store.set_log_genesis(b"kata-fragment-log/v1");

    let h0 = store.log_head().to_vec();
    println!("  genesis head = {}", hexs(&h0));

    // Apply A then B in order.
    let a = ordered_frag("issuerA", 1, &h0);
    load_frag(&mut store, &sk, &a).unwrap();
    let h1 = store.log_head().to_vec();
    let b = ordered_frag("issuerA", 2, &h1);
    load_frag(&mut store, &sk, &b).unwrap();
    let h2 = store.log_head().to_vec();
    ok(&format!(
        "in-order A→B accepted; head advanced {} → {} → {}",
        hexs(&h0),
        hexs(&h1),
        hexs(&h2)
    ));

    // A fragment asserting the stale genesis head (a reorder/insertion) is rejected.
    let stale = ordered_frag("issuerA", 3, &h0);
    assert!(matches!(
        load_frag(&mut store, &sk, &stale),
        Err(FragmentError::LogHeadMismatch { .. })
    ));
    assert_eq!(store.log_head(), h2.as_slice());
    ok("out-of-order fragment rejected (LogHeadMismatch); head unchanged");

    // Persist + restart: the head survives and the next in-order fragment still applies.
    let snap = store.export_svn_state();
    let mut restarted = FragmentStore::new(false);
    restarted.authorize_issuer("issuerA", &pk).unwrap();
    restarted.set_log_genesis(b"kata-fragment-log/v1");
    restarted.import_svn_state(&snap);
    assert_eq!(restarted.log_head(), h2.as_slice());
    let c = ordered_frag("issuerA", 3, &h2);
    assert!(load_frag(&mut restarted, &sk, &c).is_ok());
    ok("log head persisted across restart (raise-only); next in-order fragment applied");

    // The exportable, customer-auditable ordered record.
    println!("  --- exportable ordered application log (non-repudiable) ---");
    for line in store.export_fragment_log().lines() {
        println!("    {line}");
    }
}

fn main() {
    println!("=======================================================================");
    println!(" Kata CoCo — FR-1 signed policy fragments — capability demo");
    println!(" (offline, self-contained; asserts every outcome)");
    println!("=======================================================================");
    section1_core();
    section2_trust_list();
    section3_did_x509();
    section4_ordering();
    section5_transparency_log();
    println!("\n\x1b[32mAll FR-1 fragment capabilities verified.\x1b[0m");
}

// ---------------------------------------------------------------------------------------
// FR-1f Stage 2: transparency-log inclusion + consistency proofs (SCITT/CT). We play the
// role of the external append-only ledger in-process using the RFC 6962 tree, and prove the
// agent (a) accepts a fragment recorded in the log, (b) rejects a forged inclusion, and
// (c) rejects a rewound (shrinking) log — the append-only ORDERING guarantee.
use kata_security_reference_monitor::fragments::{encode_transparency_proof, sth_signing_bytes};
use kata_security_reference_monitor::merkle::MerkleTree;

fn ttl_proof(
    tree: &MerkleTree,
    sk: &SigningKey,
    ledger: &str,
    index: usize,
    cons_from: Option<usize>,
) -> String {
    let size = tree.size();
    let root = tree.root();
    let sig = sk.sign(&sth_signing_bytes(ledger, size, &root)).to_bytes();
    let incl = tree.inclusion_proof(index);
    let cons = cons_from
        .map(|m| tree.consistency_proof(m))
        .unwrap_or_default();
    encode_transparency_proof(size, &root, &sig, index as u64, &incl, &cons)
}

fn ttl_frag(svn: u64, ledger: &str) -> PolicyFragment {
    let f = PolicyFragment {
        issuer: "issuerA".into(),
        svn,
        receipt_ledger: Some(ledger.into()),
        ..Default::default()
    };
    f
}

fn section5_transparency_log() {
    println!("\n== 5. FR-1f Stage 2: transparency-log inclusion + consistency (SCITT/CT) ==");
    let (issuer_sk, issuer_pk) = ed_key(1);
    let (led_sk, led_pk) = ed_key(30);
    let mut store = FragmentStore::new(false);
    store.authorize_issuer("issuerA", &issuer_pk).unwrap();
    store
        .load_transparency_trust_list(&[("acl".into(), vec![led_pk])])
        .unwrap();

    // Ledger records fragment A as leaf 0; the agent accepts its inclusion proof.
    let fa = ttl_frag(1, "acl");
    let mut ledger = MerkleTree::new();
    ledger.push(tbs_of(&fa));
    let mut a = fa.clone();
    a.receipt_proof = Some(ttl_proof(&ledger, &led_sk, "acl", 0, None));
    assert!(load_frag(&mut store, &issuer_sk, &a).is_ok());
    ok(&format!(
        "inclusion proof accepted (log size {})",
        ledger.size()
    ));

    // Ledger grows: fragment B at leaf 1, with a consistency proof from size 1 → accepted.
    let fb = ttl_frag(2, "acl");
    ledger.push(tbs_of(&fb));
    let mut b = fb.clone();
    b.receipt_proof = Some(ttl_proof(&ledger, &led_sk, "acl", 1, Some(1)));
    assert!(load_frag(&mut store, &issuer_sk, &b).is_ok());
    ok(&format!(
        "append-only growth accepted with consistency proof (size {})",
        ledger.size()
    ));

    // Forged inclusion: claim a statement never recorded in the log → rejected.
    let forged = ttl_frag(3, "acl");
    let mut fbad = forged.clone();
    // Reuse B's proof (wrong statement for that leaf) → inclusion recompute fails.
    fbad.receipt_proof = Some(ttl_proof(&ledger, &led_sk, "acl", 1, Some(1)));
    assert!(matches!(
        verify_frag(&store, &issuer_sk, &fbad),
        Err(FragmentError::InvalidInclusionProof)
    ));
    ok("forged inclusion (statement not in log) rejected");

    // Rewound log: present an older, smaller signed tree head after the head advanced → rejected.
    let fc = ttl_frag(3, "acl");
    let mut small = MerkleTree::new();
    small.push(tbs_of(&fc));
    let mut c = fc.clone();
    c.receipt_proof = Some(ttl_proof(&small, &led_sk, "acl", 0, None));
    assert!(matches!(
        verify_frag(&store, &issuer_sk, &c),
        Err(FragmentError::LogRolledBack { .. })
    ));
    ok("rewound (shrinking) transparency log rejected — append-only ordering enforced");
}
