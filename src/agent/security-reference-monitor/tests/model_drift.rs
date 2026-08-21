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
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e))
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

/// A production `quarantine()` call, together with the reason expression it passes.
struct CallSite {
    line: usize,
    text: String,
    /// The reason as written at the call: the argument list itself, or -- when the
    /// argument is merely a binding -- that binding's initializer.
    reason: String,
}

/// The source between `open` (which must index a `(`) and its matching `)`.
///
/// String literals are tracked so that parentheses *inside* a reason string cannot
/// unbalance the scan.
fn balanced(src: &str, open: usize) -> Option<&str> {
    let bytes = src.as_bytes();
    let (mut depth, mut in_str, mut escaped) = (0usize, false, false);
    for i in open..bytes.len() {
        let c = bytes[i];
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open + 1..i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// `s` truncated at the first `;` outside any bracket or string.
fn until_semicolon(s: &str) -> &str {
    let (mut depth, mut in_str, mut escaped) = (0i32, false, false);
    for (i, c) in s.bytes().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_str = false;
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth <= 0 => return &s[..i],
            _ => {}
        }
    }
    s
}

/// The reason expression belonging to a `quarantine()` call at `call_at`.
///
/// Most call sites build the reason in place (`quarantine(format!("..."))`), so the
/// argument list already contains it. One does not: the FR-9 occurrence-divergence
/// site binds `let reason = format!(...)` so it can both log and return the same
/// text, and calls `quarantine(reason.clone())`. Following that one hop is what
/// lets the lint insist the reason belongs to *this* call rather than merely
/// occurring somewhere in the file.
fn resolve_reason(src: &str, call_at: usize, args: &str) -> String {
    if args.contains('"') {
        return args.to_string();
    }
    let ident: String = args
        .trim()
        .trim_start_matches('&')
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() {
        return args.to_string();
    }
    let head = &src[..call_at];
    match head.rfind(&format!("let {} =", ident)) {
        Some(at) => until_semicolon(&head[at..]).to_string(),
        None => args.to_string(),
    }
}

/// Locate call sites of the *method* `quarantine(`, excluding `abort_or_quarantine(`
/// and `commit_or_quarantine(` (which contain it as a substring), the `fn
/// quarantine(` definition itself, and mentions inside comments.
///
/// Each site carries its line number and text so a failure can name what it found:
/// a bare count tells a developer that the lint fired but not which call site is new.
fn quarantine_call_sites(src: &str) -> Vec<CallSite> {
    let bytes = src.as_bytes();
    let mut sites = Vec::new();
    let mut from = 0;
    while let Some(rel) = src[from..].find("quarantine(") {
        let at = from + rel;
        from = at + "quarantine(".len();
        let open = from - 1;

        // Part of a longer identifier (`abort_or_quarantine`).
        if at > 0 {
            let p = bytes[at - 1];
            if p == b'_' || p.is_ascii_alphanumeric() {
                continue;
            }
        }
        let line_start = src[..at].rfind('\n').map_or(0, |i| i + 1);
        let line_end = src[at..].find('\n').map_or(src.len(), |i| at + i);
        let trimmed = src[line_start..line_end].trim();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        // The definition, not a call.
        if src[line_start..at].contains("fn ") {
            continue;
        }
        // A mention in prose, e.g. `quarantine()` in a doc comment.
        if src[from..].starts_with(')') {
            continue;
        }

        let args = balanced(src, open).unwrap_or("");
        sites.push(CallSite {
            line: src[..at].matches('\n').count() + 1,
            text: trimmed.to_string(),
            reason: resolve_reason(src, at, args),
        });
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
        let sites = quarantine_call_sites(production_only(&src));
        let matched: Vec<&CallSite> = sites.iter().filter(|s| s.reason.contains(marker)).collect();

        assert_eq!(
            matched.len(),
            1,
            "SRM.tla declares the quarantine cause {:?}, which should be raised by \
             exactly one quarantine() call in {} whose reason contains {:?} — but {} \
             such calls were found. Searching the reason *at the call* rather than \
             the whole file is deliberate: leaving the text in a nearby log line \
             while the call itself says something else is drift, not a match.\n\
             call sites in {}:\n{}",
            cause,
            file,
            marker,
            matched.len(),
            file,
            sites
                .iter()
                .map(|s| format!("  {}:{}  {}", file, s.line, s.text))
                .collect::<Vec<_>>()
                .join("\n")
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
    let mut unclaimed: Vec<String> = Vec::new();

    for file in ["src/lib.rs", "../src/rpc.rs"] {
        let src = read(file);
        for site in quarantine_call_sites(production_only(&src)) {
            let where_ = format!("  {}:{}  {}", file, site.line, site.text);
            let claims = CAUSE_CALL_SITES
                .iter()
                .filter(|(_, f, marker)| *f == file && site.reason.contains(marker))
                .count();
            if claims != 1 {
                unclaimed.push(format!("{}   [{} rows claim it]", where_, claims));
            }
            found.push(where_);
        }
    }

    // Counting alone would let a new call site hide behind a deleted one. Each
    // site must be claimed by exactly one row, and (via the companion test) each
    // row must claim exactly one site -- together a bijection between the code's
    // ways of failing closed and the model's `Causes`.
    assert!(
        unclaimed.is_empty(),
        "these production quarantine() call sites are not matched by exactly one row \
         of CAUSE_CALL_SITES:\n{}\n\nA new call site is a new way for the monitor to \
         fail closed; it needs a cause in SRM.tla's `Causes`, an action that raises \
         it, and a row here. (This is exactly the drift that left the model claiming \
         five causes while the agent had six.)",
        unclaimed.join("\n")
    );

    assert_eq!(
        found.len(),
        CAUSE_CALL_SITES.len(),
        "the agent has {} production quarantine() call sites but the model accounts for \
         {}.\nfound:\n{}",
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
