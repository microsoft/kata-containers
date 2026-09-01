#!/usr/bin/env python3
#
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: Apache-2.0
#
# Decode a `kata-ccf-proof/v1` transparency receipt and recompute what the guest
# recomputes from it, so a demo can show the check instead of describing it.
#
# The receipt is the one part of a fragment delivery that is *not* covered by the
# issuer's signature: it travels alongside the envelope, so a host can substitute
# or drop it at will. That is exactly why the guest never reads a claim out of it.
# It recomputes the ledger's Merkle root from the inclusion path, requires the
# leaf's data-hash to be SHA-256 of the statement the issuer signed, and only then
# checks the ledger's signature over that root.
#
# This tool reproduces the first two steps byte for byte from
# src/agent/security-reference-monitor/src/ccf.rs:
#
#     leaf = SHA-256(tx_hash || SHA-256(evidence) || data_hash)
#     fold: h = SHA-256(sib || h) if left else SHA-256(h || sib)
#
# It does not verify the ledger's Ed25519 signature over the root -- there is no
# Ed25519 in the Python standard library, and a demo should not need a pip install
# to explain itself. The signature is what the guest checks; the point here is to
# show the bytes it is checked over, and that they bind this statement.
#
# Usage:
#   receipt-inspect.py <proof-file> [--statement <file>] [--json]
#
#   --statement   the signed bytes the receipt should cover (sign-fragment
#                 --emit-statement); reports whether the leaf binds them
#   --json        machine-readable output

import hashlib
import importlib.util
import json
import pathlib
import sys

# Reuse the CBOR reader from the fragment inspector rather than carrying a second
# copy. The filename is not importable as a module name, hence the explicit load.
_spec = importlib.util.spec_from_file_location(
    "cose_inspect", pathlib.Path(__file__).resolve().with_name("cose-inspect.py")
)
_cose = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cose)

# Mirrors ccf.rs MAX_CCF_PATH_ELEMENTS: the fold runs on host-supplied, unsigned
# input before any signature has been checked, so its length is bounded.
MAX_CCF_PATH_ELEMENTS = 64


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def parse_proof_text(text):
    """Parse the `kata-ccf-proof/v1` wire form: a version line, then key=value."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines or lines[0] != "kata-ccf-proof/v1":
        raise SystemExit("not a kata-ccf-proof/v1 receipt (first line: %r)" % (lines[:1],))
    fields = {}
    for ln in lines[1:]:
        if "=" in ln:
            k, v = ln.split("=", 1)
            fields[k.strip()] = v.strip()
    for required in ("proof", "sig"):
        if required not in fields:
            raise SystemExit("receipt has no %s= field" % required)
    return fields


def decode(proof_cbor):
    """Recompute (leaf, root, data_hash, path) exactly as ccf_root_and_data_hash does."""
    proof = _cose.Reader(proof_cbor).value()
    if not isinstance(proof, dict) or 1 not in proof or 2 not in proof:
        raise SystemExit("malformed ccf-inclusion-proof: want a map with keys 1 and 2")

    leaf_arr = proof[1]
    if not isinstance(leaf_arr, list) or len(leaf_arr) != 3:
        raise SystemExit("malformed ccf-leaf: want [tx_hash, evidence, data_hash]")
    tx_hash, evidence, data_hash = leaf_arr
    # ccf.rs bounds internal_evidence by its length in *bytes*. Python's len() on a str
    # counts characters, so measuring it here would accept a non-ASCII evidence up to
    # four times the size the guest accepts -- and this tool exists to reproduce the
    # guest's arithmetic exactly, not approximately.
    if not isinstance(evidence, str) or not 1 <= len(evidence.encode()) <= 1024:
        raise SystemExit("malformed internal_evidence")
    if not isinstance(tx_hash, bytes) or not isinstance(data_hash, bytes):
        raise SystemExit("tx_hash and data_hash must be CBOR byte strings")
    if len(tx_hash) != 32 or len(data_hash) != 32:
        raise SystemExit("tx_hash and data_hash must be 32 bytes")

    leaf = sha256(tx_hash, sha256(evidence.encode()), data_hash)

    path = proof[2]
    if not isinstance(path, list) or not path:
        raise SystemExit("ccf inclusion path must be a non-empty array")
    if len(path) > MAX_CCF_PATH_ELEMENTS:
        raise SystemExit("inclusion path too long: %d > %d" % (len(path), MAX_CCF_PATH_ELEMENTS))

    h = leaf
    for el in path:
        if not isinstance(el, list) or len(el) != 2:
            raise SystemExit("malformed ccf-proof-element")
        left, sib = el
        if len(sib) != 32:
            raise SystemExit("sibling hash must be 32 bytes")
        h = sha256(sib, h) if left else sha256(h, sib)

    return {
        "tx_hash": tx_hash,
        "evidence": evidence,
        "data_hash": data_hash,
        "leaf": leaf,
        "root": h,
        "path": path,
    }


def main():
    argv = sys.argv[1:]
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    statement_path = None
    if "--statement" in argv:
        i = argv.index("--statement")
        if i + 1 >= len(argv):
            raise SystemExit("--statement needs a file")
        statement_path = argv[i + 1]
        args = [a for a in args if a != statement_path]
    if len(args) != 1:
        print("usage: receipt-inspect.py <proof-file> [--statement <file>] [--json]",
              file=sys.stderr)
        return 2

    fields = parse_proof_text(open(args[0], "r", encoding="utf-8").read())
    d = decode(bytes.fromhex(fields["proof"]))
    sig = bytes.fromhex(fields["sig"])

    binds = None
    if statement_path:
        with open(statement_path, "rb") as f:
            stmt_hash = hashlib.sha256(f.read()).digest()
        binds = stmt_hash == d["data_hash"]

    if "--json" in flags:
        print(json.dumps({
            "data_hash": d["data_hash"].hex(),
            "leaf": d["leaf"].hex(),
            "root": d["root"].hex(),
            "path_len": len(d["path"]),
            "sig_bytes": len(sig),
            "binds_statement": binds,
        }, indent=2))
        return 0

    print("kata-ccf-proof/v1")
    print("  ledger leaf (what the ledger recorded):")
    print("    tx hash        %s" % d["tx_hash"].hex()[:32] + "...")
    print("    evidence       %s" % d["evidence"])
    print("    data hash      %s" % d["data_hash"].hex())
    print("  recomputed here, the same way the guest does it (ccf.rs):")
    print("    leaf hash      %s" % d["leaf"].hex())
    print("    path elements  %d (bound: %d)" % (len(d["path"]), MAX_CCF_PATH_ELEMENTS))
    print("    merkle root    %s" % d["root"].hex())
    print("    ledger sig     %d bytes, over that root — verified in the guest" % len(sig))
    if binds is not None:
        print("  does this receipt cover the statement the issuer signed?")
        print("    sha256(statement) %s" % hashlib.sha256(
            open(statement_path, "rb").read()).hexdigest())
        print("    leaf data hash    %s" % d["data_hash"].hex())
        print("    -> %s" % ("MATCH — the receipt is for these exact signed bytes"
                             if binds else
                             "MISMATCH — this receipt is for a different statement"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
