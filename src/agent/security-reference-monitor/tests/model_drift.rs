// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

//! FR-15 — keep the TLA+ model and the implementation from drifting apart.
//!
//! `formal/SRM.tla` is a snapshot of a belief about `lib.rs` and `rpc.rs`. A model
//! that is not re-checked against the code it describes decays into documentation
//! that reads like a proof, and this one has already drifted once: the agent grew a
//! sixth `quarantine()` call site (the FR-9 occurrence-registry divergence in
//! `rpc.rs`) while the model still enumerated five causes, and nothing said so.
//!
//! These tests are deliberately *lints*, not proofs. They cannot tell whether the
//! model is faithful — only whether the two artefacts still agree on the facts that
//! are cheap to check mechanically:
//!
//!  1. every production `quarantine()` call site maps to a member of `Causes`, and
//!     every member of `Causes` is claimed by a call site;
//!  2. every property the module defines is actually listed in `SRM.cfg`, since a
//!     property TLC is never told to check is silently not checked.
//!
//! Both failure modes are invisible in a green TLC run, which is exactly why they
//! need a test rather than a review.
//!
//! Note on formatting: this crate is edition 2018, where a lone string literal is
//! *not* treated as a format string, so every message below passes its values as
//! explicit `format!` arguments. An implicit capture (`{cause:?}`) would print the
//! placeholder verbatim and lose the very name the failure exists to report — the
//! same defect FR-15's F-201 records against `fault_injection.rs`.

use std::fs;
use std::path::{Path, PathBuf};

/// Repository-relative paths, resolved from this crate's manifest directory.
fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read(rel: &str) -> String {
    let path = repo_path(rel);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e))
}

/// Drop everything from the unit-test module onwards.
///
/// Test code quarantines the monitor freely to set up fixtures, and those call
/// sites are not part of the protocol the model describes.
///
/// The marker is `#[cfg(test)]` on the test *module*, not merely the first
/// `#[cfg(test)]`: `rpc.rs` carries several test-only items (helpers, mock shims)
/// long before its test module, and truncating at the first of those hides most of
/// the production file — which it did, silently reporting 2 call sites instead of 6
/// on the first run of this lint. Intervening attributes are skipped, because
/// `rpc.rs` writes `#[cfg(test)] #[allow(dead_code)] mod tests` — requiring
/// `mod tests` to follow immediately missed the module entirely and swept two test
/// call sites into the production count.
fn production_only(src: &str) -> &str {
    let mut from = 0;
    while let Some(rel) = src[from..].find("#[cfg(test)]") {
        let at = from + rel;
        from = at + "#[cfg(test)]".len();

        let mut rest = src[from..].trim_start();
        while rest.starts_with("#[") {
            match rest.find(']') {
                Some(end) => rest = rest[end + 1..].trim_start(),
                None => break,
            }
        }
        if rest.starts_with("mod tests") {
            return &src[..at];
        }
    }
    src
}

/// Locate call sites of the *method* `quarantine(`, excluding `abort_or_quarantine(`
/// and `commit_or_quarantine(` (which contain it as a substring), the `fn
/// quarantine(` definition itself, and mentions inside comments.
///
/// Returns `(line number, trimmed line)` so a failure can name what it found: a
/// bare count tells a developer that the lint fired but not which call site is new.
fn quarantine_call_sites(src: &str) -> Vec<(usize, String)> {
    let mut sites = Vec::new();
    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("*") {
            continue;
        }
        let bytes = line.as_bytes();
        let mut from = 0;
        while let Some(rel) = line[from..].find("quarantine(") {
            let at = from + rel;
            from = at + "quarantine(".len();

            // Part of a longer identifier (`abort_or_quarantine`).
            if at > 0 && {
                let p = bytes[at - 1];
                p == b'_' || p.is_ascii_alphanumeric()
            } {
                continue;
            }
            // The definition, not a call.
            if line[..at].contains("fn ") {
                continue;
            }
            // A mention in prose, e.g. `quarantine()` in a doc comment.
            if line[from..].starts_with(')') {
                continue;
            }
            sites.push((idx + 1, trimmed.to_string()));
            break;
        }
    }
    sites
}

/// The `Causes` set as the model declares it, minus the `"none"` sentinel.
fn model_causes(tla: &str) -> Vec<String> {
    let start = tla
        .find("Causes ==")
        .expect("SRM.tla no longer defines `Causes`");
    let open = tla[start..].find('{').expect("`Causes` has no set literal") + start;
    let close = tla[open..].find('}').expect("`Causes` set is unterminated") + open;
    tla[open + 1..close]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty() && s != "none")
        .collect()
}

/// Each cause in the model, paired with a distinctive fragment of the reason
/// literal at the call site that produces it.
///
/// This table is the part a human must maintain, and it is the point: adding a
/// `quarantine()` call site without deciding which modelled cause it is now fails
/// the build instead of silently widening the implementation past the model.
const CAUSE_CALL_SITES: &[(&str, &str, &str)] = &[
    (
        "abandoned-after-execute",
        "src/lib.rs",
        "was abandoned after execution",
    ),
    (
        "occurrence-diverged",
        "../src/rpc.rs",
        "occurrence registry diverged",
    ),
    (
        "no-snapshot",
        "../src/rpc.rs",
        "no policy snapshot available after",
    ),
    (
        "rollback-failed",
        "../src/rpc.rs",
        "policy state rollback failed after",
    ),
    (
        "abort-failed",
        "../src/rpc.rs",
        "failed with unprovable state",
    ),
    (
        "commit-failed",
        "../src/rpc.rs",
        "commit failed after a successful",
    ),
];

#[test]
fn quarantine_causes_match_the_formal_model() {
    let tla = read("formal/SRM.tla");
    let declared = model_causes(&tla);

    for cause in &declared {
        let site = CAUSE_CALL_SITES.iter().find(|(c, _, _)| c == cause);
        let (_, file, marker) = site.unwrap_or_else(|| {
            panic!(
                "SRM.tla declares the quarantine cause {:?}, but tests/model_drift.rs \
                 does not say which call site produces it. Add it to CAUSE_CALL_SITES.",
                cause
            )
        });
        let src = read(file);
        assert!(
            production_only(&src).contains(marker),
            "SRM.tla declares the quarantine cause {:?}, which should come from {} \
             containing {:?} — but it does not. Either the reason string changed, or \
             the cause no longer exists and must be removed from the model.",
            cause,
            file,
            marker
        );
    }

    for (cause, _, _) in CAUSE_CALL_SITES {
        assert!(
            declared.iter().any(|d| d == cause),
            "tests/model_drift.rs claims a call site for the quarantine cause {:?}, \
             but SRM.tla's `Causes` does not declare it.",
            cause
        );
    }
}

#[test]
fn every_quarantine_call_site_is_modelled() {
    let mut found: Vec<String> = Vec::new();
    for file in ["src/lib.rs", "../src/rpc.rs"] {
        let src = read(file);
        for (line, text) in quarantine_call_sites(production_only(&src)) {
            found.push(format!("  {}:{}  {}", file, line, text));
        }
    }

    assert_eq!(
        found.len(),
        CAUSE_CALL_SITES.len(),
        "the agent has {} production quarantine() call sites but the model accounts for \
         {}. A new call site is a new way for the monitor to fail closed; it needs a \
         cause in SRM.tla's `Causes`, an action that raises it, and a row in \
         CAUSE_CALL_SITES. (This is exactly the drift that left the model claiming five \
         causes while the agent had six.)\nfound:\n{}",
        found.len(),
        CAUSE_CALL_SITES.len(),
        found.join("\n")
    );
}

/// Operators defined in `SRM.tla` that are not properties and so are legitimately
/// absent from `SRM.cfg`.
const NOT_CHECKED_PROPERTIES: &[&str] = &["Committed"];

/// Top-level operator definitions at or after the `(* Invariants *)` divider, plus
/// `TypeOK`, which is defined earlier with the state declarations.
fn defined_properties(tla: &str) -> Vec<String> {
    let start = tla
        .find("(* Invariants *)")
        .expect("SRM.tla no longer has an `(* Invariants *)` divider; this lint keys off it");

    let mut names = vec!["TypeOK".to_string()];
    for line in tla[start..].lines() {
        // A top-level definition starts in column 0 as `Name ==`.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((name, _)) = line.split_once("==") else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() || name.contains(' ') || !name.starts_with(char::is_alphabetic) {
            continue;
        }
        names.push(name.to_string());
    }
    names.retain(|n| !NOT_CHECKED_PROPERTIES.contains(&n.as_str()));
    names
}

#[test]
fn every_defined_property_is_checked_by_the_config() {
    let tla = read("formal/SRM.tla");
    let cfg = read("formal/SRM.cfg");

    // Only the INVARIANTS / PROPERTIES sections count. A name that appears solely
    // in a comment is not something TLC checks.
    let listed: Vec<&str> = cfg
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with("\\*"))
        .collect();

    for name in defined_properties(&tla) {
        assert!(
            listed.iter().any(|l| *l == name),
            "SRM.tla defines {:?} but SRM.cfg does not list it, so TLC never checks it. \
             A property that is defined and not listed is indistinguishable from one that \
             holds. Add it to INVARIANTS or PROPERTIES, or add it to NOT_CHECKED_PROPERTIES \
             with a reason.",
            name
        );
    }
}
