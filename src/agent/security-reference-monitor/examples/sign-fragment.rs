// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-1 offline fragment signer / key generator (developer tooling).
//!
//! Builds the envelope through [`PolicyFragment::to_unsigned_cose`], so the format is by
//! construction the one the guest verifies. Not a production signing tool — for tests,
//! demos, and local development of the signed-policy-fragment feature.
//!
//! Usage:
//!   # generate an Ed25519 keypair (hex); put the public key in fragment-issuers.toml
//!   cargo run --example sign-fragment -- gen-key
//!
//!   # sign a fragment; prints the COSE_Sign1 envelope (hex)
//!   cargo run --example sign-fragment -- sign \
//!       --issuer issuerA --feed reg/frag:1 --svn 1 --receipt r1 \
//!       --includes exec \
//!       --module /path/to/fragment.rego \
//!       --key <privkey-hex>
//!
//! The output is a single `cose_sign1_hex=` value, and that is the whole fragment: the
//! payload is the Rego module and issuer/feed/SVN live in the protected header, which is
//! the wire format C-ACI/hcsshim uses. There is no detached signature and no separate
//! statement to pass alongside it — feed the hex to `kata-agent-ctl`'s `LoadPolicyFragment`
//! command and nothing else.
//!
//! CBOR is not readable as text, so `sign` also prints `envelope_diag=` — the emitted bytes
//! decoded into CBOR diagnostic notation (RFC 8949 §8) — and `--emit-statement-diag <path>`
//! writes the same rendering to a file. `--emit-statement` writes the COSE `Sig_structure`,
//! which is what a transparency ledger records as a Merkle leaf and what receipts
//! countersign; those bytes must stay byte-exact.
//!
//! `--x509-key`/`--x509-chain` additionally emit a `did:x509` envelope (`cose_sign1_x509_hex=`),
//! signed by an EC P-256 leaf with the chain in the `x5chain` header. Its protected header
//! carries ES256, so its `Sig_structure` differs from the Ed25519 one: use
//! `--emit-x509-statement` for that envelope's ledger leaf, never `--emit-statement`.

use ed25519_dalek::{Signer, SigningKey};
use kata_security_reference_monitor::PolicyFragment;
use std::collections::HashMap;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Render a CBOR value in diagnostic notation (RFC 8949 §8).
///
/// A COSE_Sign1 is binary, so `cose_sign1_hex` alone does not tell a developer *what* was
/// signed. Everything a fragment envelope can hold is covered explicitly; anything else falls
/// through to `Debug` rather than being silently dropped, so an unexpected shape is visible
/// instead of invisible.
fn cbor_diag(v: &ciborium::value::Value) -> String {
    use ciborium::value::Value;
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Integer(i) => i128::from(*i).to_string(),
        // Quoted and escaped, so a value containing a quote, a newline or a control
        // character is unambiguous on screen -- the ambiguity class v3 signed over.
        Value::Text(s) => format!("{:?}", s),
        Value::Bytes(b) => format!("h'{}'", hex_encode(b)),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(cbor_diag).collect::<Vec<_>>().join(", ")
        ),
        Value::Map(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(k, val)| format!("{}: {}", cbor_diag(k), cbor_diag(val)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => format!("{:?}", other),
    }
}

/// Render a byte string that is *itself* meaningful: the protected header is embedded CBOR
/// and the payload is a Rego module, and printing either as raw hex hides exactly the thing
/// a reviewer needs to see.
///
/// Falls back to hex when the bytes are not what they should be, because that case is itself
/// worth seeing rather than papering over.
fn nested_diag(b: &[u8]) -> String {
    if let Ok(v) = ciborium::from_reader::<ciborium::value::Value, _>(b) {
        if matches!(v, ciborium::value::Value::Map(_)) {
            return format!("<< {} >>", cbor_diag(&v));
        }
    }
    match std::str::from_utf8(b) {
        Ok(s) => format!("{:?}", s),
        Err(_) => format!("h'{}'", hex_encode(b)),
    }
}

/// Decode an emitted COSE_Sign1 and render it for human inspection.
///
/// Decodes the *emitted bytes themselves* rather than re-printing the fields they were built
/// from, so an encoding bug shows up here instead of being masked by a pretty-printer that
/// agrees with the input by construction. The protected header and the payload are decoded
/// one level further, since both are meaningful and neither is readable as hex.
fn statement_diag(bytes: &[u8]) -> String {
    use ciborium::value::Value;
    let v: Value = match ciborium::from_reader(bytes) {
        Ok(v) => v,
        Err(e) => return format!("<undecodable: {}; hex={}>", e, hex_encode(bytes)),
    };
    // COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr/null, signature: bstr].
    if let Value::Array(items) = &v {
        if items.len() == 4 {
            let part = |i: usize| match &items[i] {
                Value::Bytes(b) => nested_diag(b),
                other => cbor_diag(other),
            };
            return format!(
                "[protected: {}, unprotected: {}, payload: {}, signature: {}]",
                part(0),
                cbor_diag(&items[1]),
                part(2),
                match &items[3] {
                    Value::Bytes(b) => format!("h'{}'", hex_encode(b)),
                    other => cbor_diag(other),
                }
            );
        }
    }
    cbor_diag(&v)
}

/// Decode the first `CERTIFICATE` block of a PEM string into DER (for the x5chain header).
fn pem_cert_to_der(pem: &str) -> Result<Vec<u8>, String> {
    use base64ct::{Base64, Encoding};
    let mut b64 = String::new();
    let mut in_block = false;
    for line in pem.lines() {
        let t = line.trim();
        if t == "-----BEGIN CERTIFICATE-----" {
            in_block = true;
            continue;
        }
        if t == "-----END CERTIFICATE-----" {
            break;
        }
        if in_block {
            b64.push_str(t);
        }
    }
    if b64.is_empty() {
        return Err("no CERTIFICATE block in pem".into());
    }
    Base64::decode_vec(&b64).map_err(|e| e.to_string())
}

/// Parse `--flag value` pairs from args. A `--flag` with no following value (end of args
/// or immediately followed by another `--flag`) is recorded as a boolean (value "true").
fn parse_flags(args: &[String]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(flag) = args[i].strip_prefix("--") {
            let next_is_value = i + 1 < args.len() && !args[i + 1].starts_with("--");
            if next_is_value {
                m.insert(flag.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                m.insert(flag.to_string(), "true".to_string());
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    m
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        eprintln!("usage: sign-fragment <gen-key|sign> [--flags]");
        std::process::exit(2);
    }

    match argv[1].as_str() {
        "gen-key" => {
            // 32 random bytes from the OS as the Ed25519 secret scalar seed.
            use std::io::Read;
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .expect("open /dev/urandom")
                .read_exact(&mut seed)
                .expect("read 32 random bytes");
            let sk = SigningKey::from_bytes(&seed);
            let pk = sk.verifying_key().to_bytes();
            println!("private_key_hex={}", hex_encode(&seed));
            println!("public_key_hex={}", hex_encode(&pk));
        }
        "sign" => {
            let f = parse_flags(&argv[2..]);
            let issuer = f.get("issuer").cloned().unwrap_or_default();
            let svn: u64 = f.get("svn").and_then(|s| s.parse().ok()).unwrap_or(0);
            let receipt = f.get("receipt").cloned();
            let includes: Vec<String> = f
                .get("includes")
                .map(|s| {
                    s.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let module = f.get("module").map(|p| {
                String::from_utf8(std::fs::read(p).expect("read module file")).expect("module utf8")
            });
            let key_hex = match f.get("key") {
                Some(k) => k.clone(),
                None => {
                    eprintln!("--key <privkey-hex> is required");
                    std::process::exit(2);
                }
            };
            let seed_vec = hex_decode(&key_hex).expect("decode key hex");
            if seed_vec.len() != 32 {
                eprintln!("key must be 32 bytes ({} hex chars)", 64);
                std::process::exit(2);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_vec);
            let sk = SigningKey::from_bytes(&seed);

            let fragment = PolicyFragment {
                issuer,
                feed: f.get("feed").cloned().unwrap_or_default(),
                svn,
                policy_module: module,
                includes,
                requires: f
                    .get("requires")
                    .map(|s| {
                        s.split(',')
                            .map(|x| x.trim().to_string())
                            .filter(|x| !x.is_empty())
                            .collect()
                    })
                    .unwrap_or_default(),
                receipt,
                receipt_ledger: f.get("ledger").cloned(),
                receipt_proof: f.get("proof").cloned(),
                // FR-1f: further countersignatures, for a conjunctive
                // `required_receipt_from`. Comma-separated `<ledger>:<receipt>` pairs;
                // the ledger name is what the requirement list matches on.
                extra_receipts: f
                    .get("extra-receipts")
                    .map(|s| {
                        s.split(',')
                            .map(|x| x.trim())
                            .filter(|x| !x.is_empty())
                            .map(|x| match x.split_once(':') {
                                Some((ledger, receipt)) => {
                                    (ledger.to_string(), receipt.to_string())
                                }
                                None => {
                                    eprintln!(
                                        "--extra-receipts entries must be <ledger>:<receipt>, got {x:?}"
                                    );
                                    std::process::exit(2);
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                // FR-1j: the append-only log head this fragment is applied on top of.
                prev_log_head: f
                    .get("prev-head")
                    .map(|h| hex_decode(h).expect("decode prev-head hex")),
                // `tbs` is an output of parsing an envelope, never an input to building one.
                ..Default::default()
            };

            // The fragment *is* the envelope now: there is no detached signature and no
            // separate statement to carry alongside it. The unsigned COSE_Sign1 comes from
            // the library, so this tool cannot drift from what the guest verifies.
            use coset::{iana, CborSerializable};
            let mut sign1 = fragment.to_unsigned_cose(iana::Algorithm::EdDSA);
            let tbs = sign1.tbs_data(b"");
            sign1.signature = sk.sign(&tbs).to_bytes().to_vec();
            let cose_bytes = sign1.to_vec().expect("serialize COSE_Sign1");
            println!("cose_sign1_hex={}", hex_encode(&cose_bytes));

            // The envelope is binary CBOR, so print what was actually signed in diagnostic
            // notation. Decoded from the emitted bytes, not rebuilt from the fields.
            println!("envelope_diag={}", statement_diag(&cose_bytes));

            // FR-1j: print the next log head = sha256(prev_head || sha256(signed bytes)), so
            // a client can chain the following fragment onto this one.
            if let Some(prev_hex) = f.get("prev-head") {
                use sha2::{Digest, Sha256};
                let prev = hex_decode(prev_hex).expect("decode prev-head hex");
                let stmt_hash = Sha256::digest(&tbs);
                let mut h = Sha256::new();
                h.update(&prev);
                h.update(stmt_hash);
                println!("next_log_head={}", hex_encode(&h.finalize()));
            }

            // FR-1f Stage 2: optionally write the bytes a transparency ledger records as a
            // Merkle leaf -- the COSE `Sig_structure`, not the whole envelope. It has to be
            // the signed bytes rather than the serialized envelope, or an intermediary could
            // add an unprotected header and give one signed fragment two ledger identities.
            if let Some(path) = f.get("emit-statement") {
                std::fs::write(path, &tbs).expect("write statement file");
            }

            // Readable companion to --emit-statement, for diffing and review. Never fed back
            // into signing or verification.
            if let Some(path) = f.get("emit-statement-diag") {
                std::fs::write(path, statement_diag(&cose_bytes))
                    .expect("write statement diag file");
            }

            // FR-1f: optionally also emit a transparency receipt = a signature over the same
            // signed bytes by a transparency ledger key (--receipt-key <hex>). Tag the
            // originating ledger with --ledger <id> so the trust list can scope/verify it.
            if let Some(rk_hex) = f.get("receipt-key") {
                let rk_vec = hex_decode(rk_hex).expect("decode receipt key hex");
                if rk_vec.len() == 32 {
                    let mut rk = [0u8; 32];
                    rk.copy_from_slice(&rk_vec);
                    let ask = SigningKey::from_bytes(&rk);
                    let rsig = ask.sign(&tbs);
                    println!("receipt_hex={}", hex_encode(&rsig.to_bytes()));
                    if let Some(ledger) = f.get("ledger") {
                        println!("receipt_ledger={}", ledger);
                    }
                }
            }

            // FR-1d: optionally emit a did:x509 envelope instead: same protected header and
            // payload, signed by an EC P-256 leaf key (ES256), with the leaf->CA chain in the
            // x5chain header (COSE label 33). --x509-key <leaf-priv-pem>
            // --x509-chain <leaf.pem,intermediate.pem,...,ca.pem> (leaf first).
            if let (Some(key_pem), Some(chain_paths)) = (f.get("x509-key"), f.get("x509-chain")) {
                use coset::cbor::value::Value;
                use p256::ecdsa::{signature::Signer, Signature, SigningKey};
                use p256::pkcs8::DecodePrivateKey;

                let key_text = std::fs::read_to_string(key_pem).expect("read x509 key pem");
                let leaf_sk = SigningKey::from_pkcs8_pem(&key_text)
                    .expect("parse EC P-256 leaf private key (PKCS#8 PEM)");

                let mut chain: Vec<Value> = Vec::new();
                for path in chain_paths
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    let pem = std::fs::read_to_string(path).expect("read cert pem");
                    let der = pem_cert_to_der(&pem).expect("decode CERTIFICATE pem");
                    chain.push(Value::Bytes(der));
                }

                let mut sign1 = fragment.to_unsigned_cose(iana::Algorithm::ES256);
                // x5chain goes in the *unprotected* header, which is where hcsshim's
                // `sign1util` puts it and where COSE X509 (RFC 9360) allows it. The chain is
                // not the identity: the leaf key having produced this signature is, and that
                // is checked against the measured `did:x509` anchor.
                sign1
                    .unprotected
                    .rest
                    .push((coset::Label::Int(33), Value::Array(chain)));
                let tbs = sign1.tbs_data(b"");
                let sig: Signature = leaf_sk.sign(&tbs);
                sign1.signature = sig.to_bytes().to_vec();
                let x509_bytes = sign1.to_vec().unwrap();
                println!("cose_sign1_x509_hex={}", hex_encode(&x509_bytes));

                // The x509 envelope's protected header carries ES256, so its `Sig_structure`
                // is *not* the one `--emit-statement` wrote for the Ed25519 envelope above.
                // A ledger leaf minted from the wrong one validates as a signature and still
                // binds the wrong bytes, so these are separate flags rather than an
                // overwrite: whichever envelope is delivered, its own statement is named.
                if let Some(path) = f.get("emit-x509-statement") {
                    std::fs::write(path, &tbs).expect("write x509 statement file");
                }
                if let Some(path) = f.get("emit-x509-statement-diag") {
                    std::fs::write(path, statement_diag(&x509_bytes))
                        .expect("write x509 statement diag file");
                }
            }
        }
        // FR-1d dev/verification tool: verify a did:x509 COSE fragment offline against a CA
        // fingerprint + policy, exactly as the agent would. Proves openssl-minted PKI interop.
        //   verify-x509 --issuer <did> --cose <hex> --ca-fp <sha256-hex> \
        //       [--subject-cn <cn>] [--eku <oid>] [--revoked <sha256-hex,...>]
        // The flags must describe the same anchor the DID does: a DID naming a subject CN
        // requires --subject-cn to match, exactly as a measured anchor would.
        "verify-x509" => {
            use kata_security_reference_monitor::did_x509::{DidX509Anchor, DidX509Policy};
            use kata_security_reference_monitor::FragmentStore;
            let f = parse_flags(&argv[2..]);
            // `--issuer` names the anchor to trust, not the fragment: the issuer the
            // envelope claims is read out of the envelope and must match what the chain
            // proves. There is nothing left for the caller to describe.
            let issuer = f.get("issuer").cloned().unwrap_or_default();
            let cose =
                hex_decode(f.get("cose").expect("--cose required")).expect("decode cose hex");
            let ca_fp_vec =
                hex_decode(f.get("ca-fp").expect("--ca-fp required")).expect("decode ca-fp");
            let mut ca_fp = [0u8; 32];
            ca_fp.copy_from_slice(&ca_fp_vec);

            let mut store = FragmentStore::new(false);
            store.set_require_x509(true);
            store
                .authorize_did_x509(DidX509Anchor {
                    did: issuer.clone(),
                    ca_fingerprint: ca_fp,
                    policy: DidX509Policy {
                        require_subject_cn: f.get("subject-cn").cloned(),
                        require_eku: f
                            .get("eku")
                            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                            .unwrap_or_default(),
                        ..Default::default()
                    },
                })
                .unwrap_or_else(|e| {
                    panic!(
                        "--issuer/--ca-fp/--subject-cn describe an inconsistent anchor: {}",
                        e
                    )
                });
            if let Some(rev) = f.get("revoked") {
                let fps: Vec<[u8; 32]> = rev
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|h| {
                        let v = hex_decode(h).expect("decode revoked fp");
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&v);
                        a
                    })
                    .collect();
                store.set_revoked_certs(fps);
            }
            match store.verify_envelope(&cose) {
                Ok(v) => println!("verify=OK issuer={} svn={}", v.issuer, v.svn),
                Err(e) => {
                    println!("verify=ERR {e}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            std::process::exit(2);
        }
    }
}
