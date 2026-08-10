// Copyright (c) 2025 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! FR-16 coverage gate.
//!
//! The Kata agent policy (rules.rego) authorizes a CreateContainerRequest by
//! matching *individually named* fields of the OCI spec the host forwards. Rego
//! has no "compare everything" operator, so any field the policy does not name is
//! silently accepted. These tests fail the build when a new security-relevant
//! field appears in the agent's on-wire OCI messages
//! (src/libs/protocols/protos/oci.proto) without being consciously classified as
//! either constrained by the policy or deliberately left unconstrained (with a
//! rationale recorded below). They force every future OCI field to be reviewed
//! for policy coverage instead of being ignored by default.
//!
//! The threat being managed is drift, not a specific bypass: `oci.proto` is a
//! vendored copy of the OCI runtime-spec types and it already lags upstream
//! (`Scheduler`, `IOPriority` and `ExecCPUAffinity` exist in the spec but not
//! here), so a future re-sync is exactly the event these gates exist for.

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

/// Assert that every field of `message` is classified.
///
/// `constrained` means the policy either exact-matches the field against the
/// policy container or requires it to be absent/empty. `reviewed_unconstrained`
/// means it is deliberately left alone; every entry there carries a written
/// rationale at its definition site.
fn assert_all_fields_classified(
    proto: &str,
    message: &str,
    constrained: &[&str],
    reviewed_unconstrained: &[&str],
) {
    let constrained: BTreeSet<&str> = constrained.iter().copied().collect();
    let reviewed: BTreeSet<&str> = reviewed_unconstrained.iter().copied().collect();

    let overlap: Vec<&&str> = constrained.intersection(&reviewed).collect();
    assert!(
        overlap.is_empty(),
        "field(s) {overlap:?} of message {message} appear in both the constrained and the \
         reviewed-unconstrained list; a field is one or the other"
    );

    let fields = message_fields(proto, message);
    for name in constrained.iter().chain(reviewed.iter()) {
        assert!(
            fields.contains(*name),
            "message {message} has no field `{name}`, but this test classifies one. The \
             proto was probably renamed or the field removed: re-check whether the policy \
             rule that referenced it is now dead."
        );
    }

    let unclassified: Vec<&String> = fields
        .iter()
        .filter(|f| !constrained.contains(f.as_str()) && !reviewed.contains(f.as_str()))
        .collect();

    assert!(
        unclassified.is_empty(),
        "New field(s) {unclassified:?} on OCI message {message} are neither constrained by \
         the agent policy (rules.rego) nor classified as reviewed-unconstrained in this \
         test. Classify each: add policy enforcement and list it as constrained, or \
         document why it is safe to leave unconstrained and list it as reviewed."
    );
}

#[test]
fn oci_process_user_fields_are_classified() {
    let proto = std::fs::read_to_string(OCI_PROTO)
        .unwrap_or_else(|e| panic!("cannot read {OCI_PROTO}: {e}"));

    // Constrained in rules.rego by allow_process / allow_process_common /
    // allow_process_fields_fr16 / allow_user and the allow_create_container_input
    // reject-if-present block.
    let process_constrained = [
        "Terminal",
        "User",
        "Args",
        "Env",
        "Cwd",
        "Capabilities",
        "NoNewPrivileges",
        "Rlimits",
        // ApparmorProfile is exact-matched when the policy models an expected
        // value. Note this is defence-in-depth only: the kata-agent contains no
        // apparmor code at all, so the field is inert in the guest today. It is
        // constrained so that adding apparmor support to the agent cannot
        // silently introduce a host-controlled input.
        "ApparmorProfile",
        // Reject-if-present: the policy requires it to be empty.
        "SelinuxLabel",
    ];

    let process_reviewed = [
        // ConsoleSize: terminal window dimensions; cosmetic, not a sandbox boundary.
        "ConsoleSize",
        // OOMScoreAdj: computed by kubelet from the pod QoS class and node memory,
        // so it is environment-derived and not predictable at policy-generation
        // time. It only influences OOM-kill ordering, i.e. availability, which is
        // outside the confidential-computing threat model -- a host that wants the
        // workload dead can simply stop scheduling the sandbox.
        "OOMScoreAdj",
    ];

    let user_constrained = [
        "UID",
        "GID",
        "AdditionalGids",
        // Reject-if-present (rules.rego, allow_create_container_input). Note this
        // is a *create* constraint only; allow_exec_process_input does not
        // require it, which is safe because rustjail resolves process identity
        // from UID/GID and never from Username.
        "Username",
    ];

    assert_all_fields_classified(&proto, "Process", &process_constrained, &process_reviewed);
    assert_all_fields_classified(&proto, "User", &user_constrained, &[]);
}

#[test]
fn oci_spec_and_linux_fields_are_classified() {
    let proto = std::fs::read_to_string(OCI_PROTO)
        .unwrap_or_else(|e| panic!("cannot read {OCI_PROTO}: {e}"));

    // The same silent-acceptance property that motivates the Process/User gate
    // applies verbatim to the rest of the spec. These messages are guarded mostly
    // by the hand-maintained reject-if-present list in
    // rules.rego::allow_create_container_input, which is exactly the kind of list
    // that rots without a gate.

    let spec_constrained = [
        "Version",     // exact match (CreateContainerRequest)
        "Process",     // allow_process; own fields gated by the test above
        "Root",        // Root.Path via allow_by_bundle_or_sandbox_id, Root.Readonly exact
        "Mounts",      // allow_mount, bijective: every input mount must match a policy mount
        "Hooks",       // reject-if-present: must be null
        "Annotations", // allow_anno
        "Linux",       // allow_linux; own fields gated below
        "Solaris",     // reject-if-present: must be null
        "Windows",     // reject-if-present: must be null
    ];
    let spec_reviewed = [
        // Hostname: sets the sandbox UTS hostname. Not a boundary, and pinning it
        // would constrain nothing that is not already open: the policy's
        // `$(host-name)` env substitution (rules.rego, allow_var variant 5)
        // deliberately accepts *any* value for the variable derived from it, so a
        // host that wants a different hostname is already free to have one.
        // hcsshim does not model this field either.
        "Hostname",
    ];
    assert_all_fields_classified(&proto, "Spec", &spec_constrained, &spec_reviewed);

    let linux_constrained = [
        "UIDMappings",       // reject-if-present: must be empty
        "GIDMappings",       // reject-if-present: must be empty
        "MountLabel",        // reject-if-present: must be empty
        "RootfsPropagation", // reject-if-present: must be empty
        "IntelRdt",          // reject-if-present: must be null
        "Seccomp",           // reject-if-present: must be null (see note below)
        "Sysctl",            // allow_linux_sysctl
        "Namespaces",        // allow_linux
        "Devices",           // allow_linux_devices
        "MaskedPaths",       // allow_masked_paths
        "ReadonlyPaths",     // allow_readonly_paths
        "Resources",         // partially; own fields gated below
    ];
    let linux_reviewed = [
        // CgroupsPath: cgroup placement is resource allocation, which is a host
        // prerogative in this threat model, and a malicious value can only
        // misplace the container's own cgroup -- an availability effect. hcsshim
        // explicitly does not verify it either; see the parity table in
        // src/agent/src/plan_binding.rs.
        "CgroupsPath",
    ];
    assert_all_fields_classified(&proto, "Linux", &linux_constrained, &linux_reviewed);

    let resources_constrained = [
        "Devices", // reject-if-present: the cgroup device ACL must be empty
        "BlockIO", // reject-if-present: must be null
        "Network", // reject-if-present: must be null
        "Pids",    // reject-if-present: must be null
    ];
    let resources_reviewed = [
        // Memory / CPU / HugepageLimits are cgroup limits: pure resource
        // allocation. Constraining them buys nothing, because a host that wants
        // to starve the workload can simply decline to schedule the sandbox.
        // Availability is outside the confidential-computing threat model.
        "Memory",
        "CPU",
        "HugepageLimits",
    ];
    assert_all_fields_classified(
        &proto,
        "LinuxResources",
        &resources_constrained,
        &resources_reviewed,
    );

    assert_all_fields_classified(&proto, "Root", &["Path", "Readonly"], &[]);
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

    // Umask is the one OCI Process field the C-ACI / hcsshim enforcer constrains
    // that this policy does not (hcsshim compares `user.umask` exactly). The
    // parity argument is not "we checked and it is fine" but "it is structurally
    // unreachable" -- so this assertion is what makes that argument hold.
    let user_fields = message_fields(&proto, "User");
    assert!(
        !user_fields.iter().any(|f| f.eq_ignore_ascii_case("umask")),
        "oci.proto User now carries a `umask` field; it can reach the agent and must be \
         covered by the policy (see rules.rego allow_user). hcsshim enforces this field, \
         so leaving it unconstrained would be a parity regression."
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
