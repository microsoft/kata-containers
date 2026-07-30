// Copyright (c) 2025 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! FR-16 coverage gate.
//!
//! The Kata agent policy (rules.rego) authorizes a CreateContainerRequest by
//! matching individual fields of the OCI Process/User the host forwards; any
//! field the policy does not reference is silently accepted. This test fails the
//! build when a new security-relevant field appears in the agent's on-wire OCI
//! Process/User messages (src/libs/protocols/protos/oci.proto) without being
//! consciously classified as either enforced by the policy or deliberately left
//! unenforced (with a rationale below). It forces every future OCI field to be
//! reviewed for policy coverage instead of being ignored by default.

use std::collections::BTreeSet;

const OCI_PROTO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../libs/protocols/protos/oci.proto"
);

/// Extract the field names of a top-level `message <name> { ... }` block.
fn message_fields(proto: &str, message: &str) -> BTreeSet<String> {
    let header = format!("message {message} {{");
    let start = proto
        .find(&header)
        .unwrap_or_else(|| panic!("message {message} not found in {OCI_PROTO}"));
    let body = &proto[start + header.len()..];
    let end = body.find("\n}").expect("message end not found");
    let body = &body[..end];

    let mut fields = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        // A field line looks like: "<modifiers> <type> <Name> = <tag>;".
        // The field name is the identifier immediately before '='.
        if let Some((lhs, _)) = line.split_once('=') {
            if let Some(name) = lhs.split_whitespace().last() {
                fields.insert(name.to_string());
            }
        }
    }
    fields
}

#[test]
fn oci_process_user_fields_are_classified() {
    let proto = std::fs::read_to_string(OCI_PROTO)
        .unwrap_or_else(|e| panic!("cannot read {OCI_PROTO}: {e}"));

    // Fields the policy exact-matches (or requires-absent) against the input, in
    // rules.rego allow_process / allow_process_common / allow_process_fields_fr16
    // / allow_user and the reject-if-present block.
    let enforced: BTreeSet<&str> = [
        // Process
        "Terminal",
        "User",
        "Args",
        "Env",
        "Cwd",
        "Capabilities",
        "NoNewPrivileges",
        "Rlimits",
        "ApparmorProfile",
        "SelinuxLabel", // reject-if-present: policy requires it to be empty
        // User
        "UID",
        "GID",
        "AdditionalGids",
    ]
    .into_iter()
    .collect();

    // Fields present on the wire but deliberately not exact-matched, each with a
    // documented rationale. Adding a field here is a conscious security review
    // decision, not a silent omission.
    let reviewed_unenforced: BTreeSet<&str> = [
        // ConsoleSize: terminal window dimensions; cosmetic, not a sandbox boundary.
        "ConsoleSize",
        // OOMScoreAdj: computed by kubelet from the pod QoS class and node memory,
        // so it is environment-derived and not predictable at policy-generation
        // time; it only influences OOM-kill ordering, not sandbox integrity.
        "OOMScoreAdj",
        // Username: purely informational; process identity is enforced via UID/GID.
        "Username",
    ]
    .into_iter()
    .collect();

    let mut all_fields = message_fields(&proto, "Process");
    all_fields.extend(message_fields(&proto, "User"));

    let unclassified: Vec<&String> = all_fields
        .iter()
        .filter(|f| !enforced.contains(f.as_str()) && !reviewed_unenforced.contains(f.as_str()))
        .collect();

    assert!(
        unclassified.is_empty(),
        "New OCI Process/User field(s) {:?} are neither enforced by the agent policy \
         (rules.rego) nor classified as reviewed-unenforced in this test. Classify each: \
         add policy enforcement and list it in `enforced`, or document why it is safe to \
         leave unconstrained and list it in `reviewed_unenforced`.",
        unclassified
    );
}

#[test]
fn provably_irrelevant_fields_are_absent_from_the_wire() {
    // The corresponding OCI struct fields cannot be transmitted to the agent via
    // CreateContainerRequest, so a host cannot use them to weaken the sandbox and
    // the policy does not need to model them. This test locks in that assumption:
    // if any of these fields is ever added to the agent's oci.proto, it must be
    // re-evaluated for policy coverage.
    let proto = std::fs::read_to_string(OCI_PROTO)
        .unwrap_or_else(|e| panic!("cannot read {OCI_PROTO}: {e}"));

    let user_fields = message_fields(&proto, "User");
    assert!(
        !user_fields.iter().any(|f| f.eq_ignore_ascii_case("umask")),
        "oci.proto User now carries a `umask` field; it can reach the agent and must be \
         covered by the policy (see rules.rego allow_user)."
    );

    let linux_fields = message_fields(&proto, "Linux");
    assert!(
        !linux_fields
            .iter()
            .any(|f| f.eq_ignore_ascii_case("personality")),
        "oci.proto Linux now carries a `personality` field; it can reach the agent and must \
         be covered by the policy (see rules.rego allow_linux)."
    );
}
