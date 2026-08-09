// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! BL-6 — SCITT / CCF-profile transparency-log inclusion proofs.
//!
//! FR-1f Stage 2 already verifies our native RFC 6962 `kata-ttl-proof/v1` (self-chained,
//! mock-ledger). This module adds interoperability with a **real external transparency
//! ledger** — the SCITT CCF profile used by Azure Confidential Ledger and CCF-based SCITT
//! services (draft-ietf-scitt-receipts-ccf-profile), the same profile the reference
//! confidential runtime consumes. It recomputes the Merkle root from a CCF `ccf-inclusion-proof`
//! and returns the leaf `data-hash`, so the caller can (a) require `data-hash == SHA-256(signed
//! statement)` and (b) verify the ledger's signature over the recomputed root.
//!
//! CCF construction (note: **not** RFC 6962 — no `0x00`/`0x01` domain-separation prefixes):
//! ```text
//! leaf_hash = SHA-256( internal_transaction_hash(32) || SHA-256(internal_evidence) || data_hash(32) )
//! for each path element [left: bool, sibling: 32]:
//!     h = left ? SHA-256(sibling || h) : SHA-256(h || sibling)
//! root = h
//! ```
//!
//! `ccf-inclusion-proof = { 1 => [tx_hash, evidence, data_hash], 2 => [ [left, hash], ... ] }`
//! (CBOR). Pure-Rust (`ciborium` + `sha2`); no network, no Go.

use ciborium::value::Value;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// CCF leaf hash: `SHA-256(internal_tx_hash || SHA-256(internal_evidence) || data_hash)`.
pub fn ccf_leaf_hash(
    internal_tx_hash: &[u8; 32],
    internal_evidence: &[u8],
    data_hash: &[u8; 32],
) -> [u8; 32] {
    let ev = sha256(&[internal_evidence]);
    sha256(&[internal_tx_hash, &ev, data_hash])
}

/// Upper bound on the number of elements in a CCF inclusion-proof path.
///
/// The tree is binary, so an `n`-element path attests a ledger of up to `2^n` entries; 64 is
/// already far past any real CCF deployment (production proofs run to roughly 40). The bound
/// exists because the fold in [`ccf_root_and_data_hash`] runs on host-supplied, *unsigned*
/// input — `receipt_proof` is attached alongside the envelope, not inside it, so a genuinely
/// signed fragment can still carry an attacker-chosen proof — and each element costs a
/// SHA-256 before any signature has been checked.
///
/// This is the same reasoning that bounds `internal_evidence` twenty lines below, the native
/// RFC 6962 path in `merkle.rs` (`// proof too long`), and the `did:x509` chain
/// (`MAX_X5CHAIN_CERTS`, added under F-164 after hcsshim's `cosesign1/check.go` 1..100
/// bound). Without it this loop was the one unbounded attacker-controlled input in the crate.
pub const MAX_CCF_PATH_ELEMENTS: usize = 64;

/// Why a CCF inclusion proof was rejected.
///
/// [`Malformed`](CcfError::Malformed) is the catch-all for anything structurally wrong.
/// The other two are separated out because they are the cases an operator can act on: a
/// proof that is well-formed but deeper than we accept points at a misconfigured or
/// implausibly large ledger, and a data-hash mismatch points at a receipt for a *different*
/// statement — neither is the same diagnosis as "this is not a CCF proof".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcfError {
    /// Not a well-formed `ccf-inclusion-proof`.
    Malformed,
    /// The inclusion path has more than [`MAX_CCF_PATH_ELEMENTS`] elements.
    PathTooLong { len: usize, max: usize },
    /// The proof is well-formed but its leaf `data-hash` is not the expected statement hash.
    DataHashMismatch,
}

fn as_bytes32(v: &Value) -> Option<[u8; 32]> {
    let b = v.as_bytes()?;
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Some(out)
}

/// Recompute the Merkle root and extract the leaf `data-hash` from a CBOR-encoded
/// `ccf-inclusion-proof`. Returns `(root, data_hash)`, or a [`CcfError`] describing why the
/// proof was refused.
pub fn ccf_root_and_data_hash(proof_cbor: &[u8]) -> Result<([u8; 32], [u8; 32]), CcfError> {
    let bad = || CcfError::Malformed;
    let proof: Value = ciborium::from_reader(proof_cbor).map_err(|_| bad())?;
    let map = proof.as_map().ok_or_else(bad)?;
    // Keyed by integer: 1 => leaf, 2 => path.
    let mut leaf: Option<&Value> = None;
    let mut path: Option<&Value> = None;
    for (k, val) in map {
        match k.as_integer().and_then(|i| i64::try_from(i).ok()) {
            Some(1) => leaf = Some(val),
            Some(2) => path = Some(val),
            _ => {}
        }
    }
    // ccf-leaf = [ internal_tx_hash: bstr(32), internal_evidence: tstr(1..1024), data_hash: bstr(32) ]
    let leaf_arr = leaf.ok_or_else(bad)?.as_array().ok_or_else(bad)?;
    if leaf_arr.len() != 3 {
        return Err(bad());
    }
    let internal_tx_hash = as_bytes32(&leaf_arr[0]).ok_or_else(bad)?;
    let internal_evidence = leaf_arr[1].as_text().ok_or_else(bad)?;
    if internal_evidence.is_empty() || internal_evidence.len() > 1024 {
        return Err(bad());
    }
    let data_hash = as_bytes32(&leaf_arr[2]).ok_or_else(bad)?;

    let mut h = ccf_leaf_hash(&internal_tx_hash, internal_evidence.as_bytes(), &data_hash);

    // ccf-proof-element = [ left: bool, hash: bstr(32) ]; path must be non-empty.
    let path_arr = path.ok_or_else(bad)?.as_array().ok_or_else(bad)?;
    if path_arr.is_empty() {
        return Err(bad());
    }
    // Checked *before* the fold: the whole point is to not do the work.
    if path_arr.len() > MAX_CCF_PATH_ELEMENTS {
        return Err(CcfError::PathTooLong {
            len: path_arr.len(),
            max: MAX_CCF_PATH_ELEMENTS,
        });
    }
    for el in path_arr {
        let el = el.as_array().ok_or_else(bad)?;
        if el.len() != 2 {
            return Err(bad());
        }
        let left = match &el[0] {
            Value::Bool(b) => *b,
            _ => return Err(bad()),
        };
        let sib = as_bytes32(&el[1]).ok_or_else(bad)?;
        h = if left {
            sha256(&[&sib, &h])
        } else {
            sha256(&[&h, &sib])
        };
    }
    Ok((h, data_hash))
}

/// Verify a CCF inclusion proof binds `expected_data_hash` and return the Merkle root the
/// ledger's receipt must be signed over. The caller passes `SHA-256(signed statement)` as
/// `expected_data_hash` and then checks the ledger signature over the returned root.
pub fn verify_ccf_inclusion(
    proof_cbor: &[u8],
    expected_data_hash: &[u8; 32],
) -> Result<[u8; 32], CcfError> {
    let (root, data_hash) = ccf_root_and_data_hash(proof_cbor)?;
    if &data_hash == expected_data_hash {
        Ok(root)
    } else {
        Err(CcfError::DataHashMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a CBOR ccf-inclusion-proof for `data_hash` with a single sibling on the right
    // (left=false): root = SHA-256(leaf || sib).
    fn make_proof(
        data_hash: &[u8; 32],
        sib: &[u8; 32],
        left: bool,
        evidence: &str,
    ) -> (Vec<u8>, [u8; 32]) {
        let tx = [7u8; 32];
        let leaf = ccf_leaf_hash(&tx, evidence.as_bytes(), data_hash);
        let root = if left {
            sha256(&[sib, &leaf])
        } else {
            sha256(&[&leaf, sib])
        };
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
                    Value::Bool(left),
                    Value::Bytes(sib.to_vec()),
                ])]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&proof, &mut buf).unwrap();
        (buf, root)
    }

    #[test]
    fn ccf_inclusion_recomputes_root_and_binds_data_hash() {
        let data_hash = [0xabu8; 32];
        let sib = [0x11u8; 32];
        let (proof, root) = make_proof(&data_hash, &sib, false, "ccf-evidence");
        // Correct data-hash → returns the same root the producer computed.
        assert_eq!(verify_ccf_inclusion(&proof, &data_hash), Ok(root));
        // Wrong expected data-hash → rejected (the proof does not bind our statement).
        assert_eq!(
            verify_ccf_inclusion(&proof, &[0u8; 32]),
            Err(CcfError::DataHashMismatch)
        );
    }

    #[test]
    fn ccf_left_sibling_folds_correctly() {
        let data_hash = [0x5au8; 32];
        let sib = [0x22u8; 32];
        let (proof, root) = make_proof(&data_hash, &sib, true, "e");
        assert_eq!(verify_ccf_inclusion(&proof, &data_hash), Ok(root));
    }

    /// F-168: build a proof with `n` path elements, all right-siblings.
    fn proof_with_path_len(n: usize) -> Vec<u8> {
        let path: Vec<Value> = (0..n)
            .map(|i| Value::Array(vec![Value::Bool(false), Value::Bytes(vec![i as u8; 32])]))
            .collect();
        let v = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Array(vec![
                    Value::Bytes(vec![7u8; 32]),
                    Value::Text("e".into()),
                    Value::Bytes(vec![0xabu8; 32]),
                ]),
            ),
            (Value::Integer(2.into()), Value::Array(path)),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&v, &mut buf).unwrap();
        buf
    }

    #[test]
    fn ccf_path_length_is_bounded() {
        // F-168: the fold runs on host-supplied, unsigned input before any signature is
        // checked, so its length is capped the way `merkle.rs` and `did_x509.rs` cap theirs.

        // At the bound: accepted (the cap is not accidentally off-by-one).
        assert!(ccf_root_and_data_hash(&proof_with_path_len(MAX_CCF_PATH_ELEMENTS)).is_ok());

        // One over: refused, and refused *distinguishably* — an operator can tell an
        // implausibly deep ledger from a garbage proof.
        assert_eq!(
            ccf_root_and_data_hash(&proof_with_path_len(MAX_CCF_PATH_ELEMENTS + 1)),
            Err(CcfError::PathTooLong {
                len: MAX_CCF_PATH_ELEMENTS + 1,
                max: MAX_CCF_PATH_ELEMENTS,
            })
        );

        // Far over: same answer, and it costs no hashing to say so.
        assert!(matches!(
            ccf_root_and_data_hash(&proof_with_path_len(100_000)),
            Err(CcfError::PathTooLong { .. })
        ));
    }

    #[test]
    fn ccf_malformed_proof_rejected() {
        // Not CBOR.
        assert_eq!(ccf_root_and_data_hash(b"not-cbor"), Err(CcfError::Malformed));
        // Empty path is rejected.
        let bad = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Array(vec![
                    Value::Bytes(vec![0u8; 32]),
                    Value::Text("e".into()),
                    Value::Bytes(vec![0u8; 32]),
                ]),
            ),
            (Value::Integer(2.into()), Value::Array(vec![])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&bad, &mut buf).unwrap();
        assert_eq!(ccf_root_and_data_hash(&buf), Err(CcfError::Malformed));
    }
}
