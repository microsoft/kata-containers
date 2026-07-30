// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-4D dev tool — exercise the verified guest-pull image authorization gate offline, using
//! the *same* [`VerifiedImageStore`] the agent calls in
//! `storage::image_pull_handler` before asking the Confidential Data Hub to pull an image.
//!
//! Feed it an image reference plus the measured allowlist of manifest digests; it prints the
//! decision and exits non-zero on rejection — so a live harness can prove the SRM only pulls
//! images pinned to a measured/approved manifest digest.
//!
//! Usage:
//!   verify-image --image-ref <name@alg:hex> [--authorize <alg:hex> ...] [--require true|false]
//!
//! Exit code: 0 = authorized (Ok), 1 = rejected (fail-closed), 2 = bad args.

use kata_security_reference_monitor::VerifiedImageStore;
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

    let image_ref = match f.get("image-ref").and_then(|v| v.first()) {
        Some(r) => r.clone(),
        None => {
            eprintln!("--image-ref <name@alg:hex> is required");
            std::process::exit(2);
        }
    };
    let require = f
        .get("require")
        .and_then(|v| v.first())
        .map(|s| s != "false")
        .unwrap_or(true);

    let mut store = VerifiedImageStore::new(require);
    if let Some(authorized) = f.get("authorize") {
        for d in authorized {
            store.authorize_image(d);
        }
    }

    match store.verify(&image_ref) {
        Ok(()) => {
            println!(
                "AUTHORIZED  image_ref={image_ref} (approved={})",
                store.len()
            );
            std::process::exit(0);
        }
        Err(e) => {
            println!("REJECTED    image_ref={image_ref} :: {e}");
            std::process::exit(1);
        }
    }
}
