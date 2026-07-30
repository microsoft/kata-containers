// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! Mock transparency ledger for FR-1f Stage 2 demos/harnesses.
//!
//! Plays the role of an append-only transparency log (SCITT / Certificate-Transparency): it
//! builds an RFC 6962 Merkle tree over a list of recorded fragment *statements*, signs the
//! resulting tree head with a ledger Ed25519 key, and emits a `kata-ttl-proof/v1` proof for
//! a target leaf (inclusion proof + optional consistency proof from a previous size). The
//! proof format is produced by the SRM crate itself, so it is byte-identical to what the
//! agent verifies.
//!
//! ```text
//! # append leaves f0,f1 (raw statement files), prove leaf 1 at size 2, consistency from 1:
//! mock-ledger prove --key <ledger-priv-hex> --ledger acl \
//!     --leaves f0.stmt,f1.stmt --target 1 --cons-from 1
//! # -> prints the ttl-proof text on stdout
//! ```

use ed25519_dalek::{Signer, SigningKey};
use kata_security_reference_monitor::fragments::{encode_transparency_proof, sth_signing_bytes};
use kata_security_reference_monitor::merkle::MerkleTree;
use std::collections::HashMap;

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// BL-6 / LV-3: emit a SCITT CCF-profile `kata-ccf-proof/v1` receipt for a fragment statement.
// Builds a real ccf-inclusion-proof (CBOR {1:[tx_hash,evidence,data_hash], 2:[[left,hash]]}),
// recomputes the Merkle root with the same plain-SHA-256 CCF construction the guest verifier
// uses (crate::ccf), and signs that root with the ledger Ed25519 key. `--tamper` flips the
// leaf data_hash so the recomputed root no longer binds the statement (rejection demo).
fn prove_ccf(f: &HashMap<String, String>) {
    use ciborium::value::Value;
    use sha2::{Digest, Sha256};

    let key = hex_decode(f.get("key").expect("--key required"));
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key[..32]);
    let sk = SigningKey::from_bytes(&seed);

    let leaf_path = f.get("leaf").expect("--leaf <statement-file> required");
    let statement = std::fs::read(leaf_path).expect("read leaf statement file");
    let mut data_hash: [u8; 32] = Sha256::digest(&statement).into();
    if f.contains_key("tamper") {
        data_hash[0] ^= 0xff; // bind a different statement -> verifier must reject
    }

    let tx = [7u8; 32];
    let evidence = "ccf-evidence";
    let leaf =
        kata_security_reference_monitor::ccf::ccf_leaf_hash(&tx, evidence.as_bytes(), &data_hash);
    let sib = [0x11u8; 32];
    // Single right sibling (left=false): root = SHA-256(leaf || sib).
    let mut h = Sha256::new();
    h.update(leaf);
    h.update(sib);
    let root: [u8; 32] = h.finalize().into();

    let proof = Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Array(vec![
                Value::Bytes(tx.to_vec()),
                Value::Text(evidence.to_string()),
                Value::Bytes(data_hash.to_vec()),
            ]),
        ),
        (
            Value::Integer(2.into()),
            Value::Array(vec![Value::Array(vec![
                Value::Bool(false),
                Value::Bytes(sib.to_vec()),
            ])]),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::into_writer(&proof, &mut cbor).expect("encode ccf proof");
    let sig = sk.sign(&root).to_bytes();
    print!(
        "kata-ccf-proof/v1\nproof={}\nsig={}\n",
        hex_encode(&cbor),
        hex_encode(&sig)
    );
}

fn parse_flags(args: &[String]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(flag) = args[i].strip_prefix("--") {
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                m.insert(flag.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                m.insert(flag.to_string(), "true".to_string());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    m
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("");
    if sub != "prove" && sub != "prove-ccf" {
        eprintln!("usage: mock-ledger prove --key <hex> --ledger <id> --leaves <f0,f1,...> --target <idx> [--cons-from <m>]");
        eprintln!("       mock-ledger prove-ccf --key <hex> --leaf <statement-file> [--tamper]");
        std::process::exit(2);
    }
    let f = parse_flags(&argv[2..]);
    if sub == "prove-ccf" {
        prove_ccf(&f);
        return;
    }
    let key = hex_decode(f.get("key").expect("--key required"));
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key[..32]);
    let sk = SigningKey::from_bytes(&seed);
    let ledger = f
        .get("ledger")
        .cloned()
        .unwrap_or_else(|| "acl".to_string());
    let target: usize = f.get("target").and_then(|s| s.parse().ok()).unwrap_or(0);
    let cons_from: Option<usize> = f.get("cons-from").and_then(|s| s.parse().ok());

    let mut tree = MerkleTree::new();
    for path in f
        .get("leaves")
        .expect("--leaves required")
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        tree.push(std::fs::read(path).expect("read leaf statement file"));
    }

    let size = tree.size();
    let root = tree.root();
    let sig = sk.sign(&sth_signing_bytes(&ledger, size, &root)).to_bytes();
    let incl = tree.inclusion_proof(target);
    let cons = cons_from
        .map(|m| tree.consistency_proof(m))
        .unwrap_or_default();
    print!(
        "{}",
        encode_transparency_proof(size, &root, &sig, target as u64, &incl, &cons)
    );
}
