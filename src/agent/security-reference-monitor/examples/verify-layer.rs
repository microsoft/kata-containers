// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-4C dev tool — exercise the verified read-only-layer (dm-verity) authorization gate
//! offline, using the *same* [`VerifiedLayerStore`] the agent calls in
//! `storage::multi_layer_erofs::create_partition_dmverity_device` before creating a
//! dm-verity device.
//!
//! Feed it a real dm-verity root hash (e.g. from `veritysetup format`) plus the measured
//! allowlist, and it prints the authorization decision and exits non-zero on rejection —
//! so a live harness can prove "the SRM authorizes only the measured root digest".
//!
//! Usage:
//!   verify-layer --algorithm sha256 --root-hash <hex> [--authorize <hex> ...] [--require true|false]
//!
//! Exit code: 0 = authorized (Ok), 1 = rejected (fail-closed), 2 = bad args.

use kata_security_reference_monitor::VerifiedLayerStore;
use std::collections::HashMap;

fn parse_flags(args: &[String]) -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(key) = args[i].strip_prefix("--") {
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                m.entry(key.to_string())
                    .or_default()
                    .push(args[i + 1].clone());
                i += 2;
            } else {
                m.entry(key.to_string())
                    .or_default()
                    .push("true".to_string());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    m
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let f = parse_flags(&argv);

    let algorithm = f
        .get("algorithm")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_else(|| "sha256".to_string());
    let root_hash = match f.get("root-hash").and_then(|v| v.first()) {
        Some(h) => h.clone(),
        None => {
            eprintln!("--root-hash <hex> is required");
            std::process::exit(2);
        }
    };
    // require defaults to true (fail-closed), matching the strict-build posture.
    let require = f
        .get("require")
        .and_then(|v| v.first())
        .map(|s| s != "false")
        .unwrap_or(true);

    let mut store = VerifiedLayerStore::new(require);
    if let Some(authorized) = f.get("authorize") {
        for h in authorized {
            store.authorize_layer(&algorithm, h);
        }
    }

    match store.verify(&algorithm, &root_hash) {
        Ok(()) => {
            println!(
                "AUTHORIZED  algorithm={algorithm} root_hash={root_hash} (approved={})",
                store.len()
            );
            std::process::exit(0);
        }
        Err(e) => {
            println!("REJECTED    algorithm={algorithm} root_hash={root_hash} :: {e}");
            std::process::exit(1);
        }
    }
}
