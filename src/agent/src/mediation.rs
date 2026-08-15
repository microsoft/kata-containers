// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! FR-7 — complete mediation manifest.
//!
//! Total mediation requires that *every* agent RPC that a (possibly hostile) caller can
//! invoke passes through the policy enforcement point before it can act, with no
//! always-allowed escape hatch. This module is the machine-checkable record of that
//! property:
//!
//!  - [`MEDIATION_MANIFEST`] classifies every method of the agent ttRPC service by the
//!    enforcement point it must pass through.
//!  - A `const` block below **fails the build** if the proto service and this manifest
//!    drift apart — a new RPC added without a mediation classification, a stale entry for
//!    a method the service no longer exposes, or a wrong request type.
//!  - The tests below re-check the same invariants with readable diagnostics, and —
//!    under `--features agent-policy` — they **call every handler under a deny-all
//!    policy** and require each one to refuse.
//!
//! In strict builds the default policy is closed-door (every request denied unless the
//! activated policy allows it), so a mediated RPC with no matching allow rule is denied.
//! The enforcement classes here document *how* each RPC is mediated, not *whether* a
//! particular policy happens to allow it.
//!
//! ## Why the proof is behavioural
//!
//! An earlier version of this module proved mediation by `include_str!`ing `rpc.rs` and
//! asserting the substring `is_allowed` appeared inside each handler's source span. That
//! is **cfg-blind, order-blind and dead-code-blind**: a gate inside a compiled-out branch,
//! or placed after an early `return`, or sitting in a comment, all satisfied it. It also
//! certified `CopyFile` as policy-gated while strict builds deny it without consulting the
//! policy at all — the manifest disagreed with the binary and the test could not tell.
//!
//! The sweep in [`tests`] replaces that with the property itself: install a policy that
//! denies everything, invoke each RPC, and require a refusal. A handler that acts before
//! authorizing fails, wherever the gate is written and whatever the `cfg` soup around it.
//! Because the sweep runs the *compiled* build, the manifest is `cfg`-aware too: RPCs whose
//! handler is not compiled in are declared [`EnforcementClass::CompiledOut`] rather than
//! silently claimed as gated.
//!
//! ## What is checked when
//!
//! The two halves of the proof have different reach, and it is worth being precise about
//! which is which:
//!
//! | Check | Fails at | Reach |
//! | --- | --- | --- |
//! | Manifest covers the service, exactly, with the right request types | **`cargo build`** | every build, every `cfg`, including consumers who never run tests |
//! | Every handler refuses under a deny-all policy | `cargo test --features agent-policy` | only where the suite is run *with the policy engine enabled* |
//!
//! The coverage half is a `const` assertion against [`PROTO_RPCS`], generated from
//! `agent.proto` by `build.rs`. It is evaluated per build configuration, so the
//! `cfg`-conditional rows are checked in the configuration they describe.
//!
//! The behavioural half cannot be lifted to build time — it has to run code. Note that it
//! is gated behind `--features agent-policy`, so a default-feature test run does **not**
//! exercise it; CI must opt in explicitly for the FR-7 claim to be continuously verified.
//!
//! Run it with:
//!
//! ```text
//! cargo test --features agent-policy  mediation
//! cargo test --features strict-policy mediation
//! ```

/// The enforcement point an RPC must pass through before it can take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementClass {
    /// Mutates container/sandbox lifecycle state; gated by policy *and* by the FR-9
    /// occurrence state machine.
    LifecycleGated,
    /// Mutates guest/sandbox state; gated by the policy enforcement point (`is_allowed`).
    PolicyGated,
    /// Read-only / observational; still gated by the policy enforcement point.
    PolicyGatedQuery,
    /// Gated *before* any effect, but a denial redacts rather than refuses: the caller
    /// gets a success with the payload removed. Used by the stdout/stderr readers, where
    /// the host-visible contract is an empty response rather than an error.
    PolicyGatedRedacted,
    /// The one-shot policy-activation endpoint; self-gated by the `SetPolicyRequest`
    /// rule in the currently active policy.
    PolicyActivation,
    /// Refused unconditionally in this build configuration, without consulting the policy
    /// at all. Strictly stronger than policy gating — there is no rule that can admit it.
    DeniedUnconditionally,
    /// The handler is not compiled into this build, so the method is not registered on the
    /// ttRPC service and cannot be invoked at all. Strongest of the classes: the surface
    /// does not exist. Declared per build configuration, never assumed.
    CompiledOut,
}

impl EnforcementClass {
    /// Whether an RPC in this class must be *refused* when the active policy denies
    /// everything. `CompiledOut` is excluded because there is no handler to call, and
    /// `PolicyGatedRedacted` returns an empty success by design — the sweep checks that
    /// separately, including that the denial short-circuits before any effect.
    fn must_refuse_under_deny_all(self) -> bool {
        !matches!(
            self,
            EnforcementClass::CompiledOut | EnforcementClass::PolicyGatedRedacted
        )
    }
}

/// Every method of the agent ttRPC service, the handler that implements it, the request
/// type the policy engine sees as its entry point, and the enforcement point it must pass
/// through. This table is exhaustive: the proto-sync test fails if any service method is
/// missing, unknown, or paired with the wrong request type.
///
/// The request type matters as much as the method name: the policy entry point is the
/// protobuf **message** name (`is_allowed` uses `req.descriptor_dyn().name()`), not the RPC
/// name. Seven of them differ, and `ReadStdout`/`ReadStderr` share one — so the policy
/// cannot tell those two apart. Recording it here makes that visible instead of implied.
///
/// Rows whose handler is `cfg`-gated appear once per configuration, so the manifest
/// describes the build that is actually running.
///
/// Kept hand-aligned one entry per line: this is a reference table that is read far more
/// often than it is edited, and rustfmt would expand each row to a five-line tuple.
#[rustfmt::skip]
pub const MEDIATION_MANIFEST: &[(&str, &str, &str, EnforcementClass)] = &[
    // Container lifecycle (policy + occurrence state machine).
    ("CreateContainer", "create_container", "CreateContainerRequest", EnforcementClass::LifecycleGated),
    ("StartContainer", "start_container", "StartContainerRequest", EnforcementClass::LifecycleGated),
    ("RemoveContainer", "remove_container", "RemoveContainerRequest", EnforcementClass::LifecycleGated),
    ("ExecProcess", "exec_process", "ExecProcessRequest", EnforcementClass::LifecycleGated),
    ("SignalProcess", "signal_process", "SignalProcessRequest", EnforcementClass::LifecycleGated),
    // State-mutating operations (policy gated).
    ("WaitProcess", "wait_process", "WaitProcessRequest", EnforcementClass::PolicyGated),
    ("UpdateContainer", "update_container", "UpdateContainerRequest", EnforcementClass::PolicyGated),
    ("UpdateEphemeralMounts", "update_ephemeral_mounts", "UpdateEphemeralMountsRequest", EnforcementClass::PolicyGated),
    ("PauseContainer", "pause_container", "PauseContainerRequest", EnforcementClass::PolicyGated),
    ("ResumeContainer", "resume_container", "ResumeContainerRequest", EnforcementClass::PolicyGated),
    ("RemoveStaleVirtiofsShareMounts", "remove_stale_virtiofs_share_mounts", "RemoveStaleVirtiofsShareMountsRequest", EnforcementClass::PolicyGated),
    ("WriteStdin", "write_stdin", "WriteStreamRequest", EnforcementClass::PolicyGated),
    ("CloseStdin", "close_stdin", "CloseStdinRequest", EnforcementClass::PolicyGated),
    ("TtyWinResize", "tty_win_resize", "TtyWinResizeRequest", EnforcementClass::PolicyGated),
    ("UpdateInterface", "update_interface", "UpdateInterfaceRequest", EnforcementClass::PolicyGated),
    ("UpdateRoutes", "update_routes", "UpdateRoutesRequest", EnforcementClass::PolicyGated),
    ("AddARPNeighbors", "add_arp_neighbors", "AddARPNeighborsRequest", EnforcementClass::PolicyGated),
    ("SetIPTables", "set_ip_tables", "SetIPTablesRequest", EnforcementClass::PolicyGated),
    ("MemAgentMemcgSet", "mem_agent_memcg_set", "MemAgentMemcgConfig", EnforcementClass::PolicyGated),
    ("MemAgentCompactSet", "mem_agent_compact_set", "MemAgentCompactConfig", EnforcementClass::PolicyGated),
    ("CreateSandbox", "create_sandbox", "CreateSandboxRequest", EnforcementClass::PolicyGated),
    ("DestroySandbox", "destroy_sandbox", "DestroySandboxRequest", EnforcementClass::PolicyGated),
    ("OnlineCPUMem", "online_cpu_mem", "OnlineCPUMemRequest", EnforcementClass::PolicyGated),
    ("ReseedRandomDev", "reseed_random_dev", "ReseedRandomDevRequest", EnforcementClass::PolicyGated),
    ("MemHotplugByProbe", "mem_hotplug_by_probe", "MemHotplugByProbeRequest", EnforcementClass::PolicyGated),
    ("SetGuestDateTime", "set_guest_date_time", "SetGuestDateTimeRequest", EnforcementClass::PolicyGated),
    ("AddSwap", "add_swap", "AddSwapRequest", EnforcementClass::PolicyGated),
    ("AddSwapPath", "add_swap_path", "AddSwapPathRequest", EnforcementClass::PolicyGated),
    ("ResizeVolume", "resize_volume", "ResizeVolumeRequest", EnforcementClass::PolicyGated),
    // Typed host->guest content channel that replaces the destination-path-carrying CopyFile
    // for the paths the runtime still needs. The guest, not the host, chooses the destination
    // file name, and every host-supplied path component is validated before use. The two that
    // carry file content are evaluated against a pre-processed input that hides the payload
    // and decodes the S_IFMT bits, so `rules.rego` can refuse a symlink where a regular file
    // is expected (RM-114).
    ("CopySingleFile", "copy_single_file", "CopySingleFileRequest", EnforcementClass::PolicyGated),
    ("InitVolume", "init_volume", "InitVolumeRequest", EnforcementClass::PolicyGated),
    ("PutVolumeFileRevision", "put_volume_file_revision", "PutVolumeFileRevisionRequest", EnforcementClass::PolicyGated),
    ("CommitVolumeRevision", "commit_volume_revision", "CommitVolumeRevisionRequest", EnforcementClass::PolicyGated),
    // FR-10: strict builds refuse the generic CopyFile outright — the content is not
    // policy-measured and the host chooses the destination path. The typed content channel
    // above carries the traffic the runtime still needs. Declared as it behaves, not as it
    // would behave if the deny were absent.
    #[cfg(feature = "strict-policy")]
    ("CopyFile", "copy_file", "CopyFileRequest", EnforcementClass::DeniedUnconditionally),
    #[cfg(not(feature = "strict-policy"))]
    ("CopyFile", "copy_file", "CopyFileRequest", EnforcementClass::PolicyGated),
    // Read-only / observational (still policy gated).
    ("StatsContainer", "stats_container", "StatsContainerRequest", EnforcementClass::PolicyGatedQuery),
    // FR-7: strict builds refuse the diagnostic dump outright, without a policy round trip.
    #[cfg(feature = "strict-policy")]
    ("GetDiagnosticData", "get_diagnostic_data", "GetDiagnosticDataRequest", EnforcementClass::DeniedUnconditionally),
    #[cfg(not(feature = "strict-policy"))]
    ("GetDiagnosticData", "get_diagnostic_data", "GetDiagnosticDataRequest", EnforcementClass::PolicyGatedQuery),
    ("ReadStdout", "read_stdout", "ReadStreamRequest", EnforcementClass::PolicyGatedRedacted),
    ("ReadStderr", "read_stderr", "ReadStreamRequest", EnforcementClass::PolicyGatedRedacted),
    ("ListInterfaces", "list_interfaces", "ListInterfacesRequest", EnforcementClass::PolicyGatedQuery),
    ("ListRoutes", "list_routes", "ListRoutesRequest", EnforcementClass::PolicyGatedQuery),
    ("GetIPTables", "get_ip_tables", "GetIPTablesRequest", EnforcementClass::PolicyGatedQuery),
    ("GetMetrics", "get_metrics", "GetMetricsRequest", EnforcementClass::PolicyGatedQuery),
    ("GetGuestDetails", "get_guest_details", "GuestDetailsRequest", EnforcementClass::PolicyGatedQuery),
    ("GetOOMEvent", "get_oom_event", "GetOOMEventRequest", EnforcementClass::PolicyGatedQuery),
    ("GetVolumeStats", "get_volume_stats", "VolumeStatsRequest", EnforcementClass::PolicyGatedQuery),
    // Policy activation. FR-12: strict builds compile the SetPolicy handler out entirely —
    // policy arrives through measured initdata and there is no host-facing mutation channel.
    #[cfg(all(feature = "agent-policy", not(feature = "strict-policy")))]
    ("SetPolicy", "set_policy", "SetPolicyRequest", EnforcementClass::PolicyActivation),
    #[cfg(not(all(feature = "agent-policy", not(feature = "strict-policy"))))]
    ("SetPolicy", "set_policy", "SetPolicyRequest", EnforcementClass::CompiledOut),
    // FR-1a: fragment delivery exists only in strict builds.
    #[cfg(feature = "strict-policy")]
    ("LoadPolicyFragment", "load_policy_fragment", "LoadPolicyFragmentRequest", EnforcementClass::PolicyGated),
    #[cfg(not(feature = "strict-policy"))]
    ("LoadPolicyFragment", "load_policy_fragment", "LoadPolicyFragmentRequest", EnforcementClass::CompiledOut),
];

// Every `rpc` the agent service declares, generated from `agent.proto` by `build.rs` as
// `(method, request message)` in `PROTO_RPCS`.
//
// Generated rather than hand-written so that the service definition, not a copy of it, is
// what `MEDIATION_MANIFEST` is checked against.
include!(concat!(env!("OUT_DIR"), "/proto_rpcs.rs"));

/// `str` equality usable in `const` evaluation.
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether the manifest classifies `method`, and — if it does — whether it records the
/// same request type the proto declares.
const fn manifest_covers(method: &str, request: &str) -> bool {
    let mut i = 0;
    while i < MEDIATION_MANIFEST.len() {
        let (m, _, req, _) = MEDIATION_MANIFEST[i];
        if str_eq(m, method) {
            return str_eq(req, request);
        }
        i += 1;
    }
    false
}

/// Whether the service still declares `method`.
const fn proto_declares(method: &str) -> bool {
    let mut i = 0;
    while i < PROTO_RPCS.len() {
        let (m, _) = PROTO_RPCS[i];
        if str_eq(m, method) {
            return true;
        }
        i += 1;
    }
    false
}

/// FR-7 coverage gate — **a compile error, not a test failure**.
///
/// Total mediation is only a property of the shipped binary if it is impossible to build a
/// binary without it. Expressing the check as a `const` assertion rather than a `#[test]`
/// closes the gap where an RPC is added, the crate compiles, and nobody runs the suite
/// before the artefact is consumed.
///
/// Three invariants, evaluated in whatever configuration is being built:
///
///  1. every RPC the service exposes is classified in the manifest — no unmediated surface;
///  2. the manifest declares no method the service no longer exposes — no stale rows
///     inflating the coverage count;
///  3. the request types agree — the policy entry point is the request *message* name, so
///     a manifest row naming the wrong one would silently exempt that endpoint from the
///     deny-all sweep and let it pass vacuously.
///
/// `const` panics take a literal message, so the diagnostics here are deliberately terse.
/// [`tests::every_service_rpc_is_classified`] and
/// [`tests::manifest_request_types_match_the_proto`] re-check the same invariants and name
/// the offending RPCs; run them to find out *which* method drifted.
const _: () = {
    assert!(
        !PROTO_RPCS.is_empty(),
        "no rpc parsed from agent.proto; the FR-7 mediation gate would pass vacuously"
    );

    let mut i = 0;
    while i < PROTO_RPCS.len() {
        let (method, request) = PROTO_RPCS[i];
        assert!(
            manifest_covers(method, request),
            "FR-7: an agent RPC is unclassified, or is classified with the wrong request \
             type, in MEDIATION_MANIFEST. Run `cargo test -p kata-agent mediation` to see \
             which one."
        );
        i += 1;
    }

    let mut j = 0;
    while j < MEDIATION_MANIFEST.len() {
        let (method, _, _, _) = MEDIATION_MANIFEST[j];
        assert!(
            proto_declares(method),
            "FR-7: MEDIATION_MANIFEST classifies a method the agent service no longer \
             exposes. Run `cargo test -p kata-agent mediation` to see which one."
        );
        j += 1;
    }
};

/// Return the enforcement class declared for a service method, if any.
pub fn enforcement_class(rpc_method: &str) -> Option<EnforcementClass> {
    MEDIATION_MANIFEST
        .iter()
        .find(|(m, _, _, _)| *m == rpc_method)
        .map(|(_, _, _, c)| *c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const AGENT_PROTO: &str = include_str!("../../libs/protocols/protos/agent.proto");

    /// Extract `(method, request type)` for every `rpc <Name>(<Request>)` declared by the
    /// agent proto service.
    fn proto_rpcs() -> Vec<(String, String)> {
        AGENT_PROTO
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("rpc ")?;
                let open = rest.find('(')?;
                let close = rest[open..].find(')')? + open;
                let name = rest[..open].trim().to_string();
                // Request types may be package-qualified; the policy sees the bare
                // message name, which is what the manifest records.
                let req = rest[open + 1..close]
                    .trim()
                    .rsplit('.')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                (!name.is_empty() && !req.is_empty()).then_some((name, req))
            })
            .collect()
    }

    /// TC3.9: complete-mediation coverage. Every RPC exposed by the service must be
    /// classified in the manifest, and the manifest must not classify a method the
    /// service does not expose.
    ///
    /// The same invariant is enforced at build time by the `const` gate above, which is
    /// what actually makes it unbypassable. This test exists for its diagnostics: the
    /// `const` assertion can only carry a literal message, whereas this one names the
    /// offending RPCs.
    #[test]
    fn every_service_rpc_is_classified() {
        let rpcs = proto_rpcs();
        assert!(!rpcs.is_empty(), "failed to parse any rpc from agent.proto");
        let proto: HashSet<String> = rpcs.iter().map(|(m, _)| m.clone()).collect();

        let manifest: HashSet<String> = MEDIATION_MANIFEST
            .iter()
            .map(|(m, _, _, _)| m.to_string())
            .collect();

        let unclassified: Vec<_> = proto.difference(&manifest).collect();
        assert!(
            unclassified.is_empty(),
            "agent RPC(s) exposed but not covered by the mediation manifest (FR-7 gap): {:?}",
            unclassified
        );

        let stale: Vec<_> = manifest.difference(&proto).collect();
        assert!(
            stale.is_empty(),
            "mediation manifest classifies method(s) the service no longer exposes: {:?}",
            stale
        );
    }

    /// The policy entry point is the request *message* name, not the RPC name. If the
    /// manifest records the wrong one, the deny-all policy the conformance sweep builds
    /// would miss that endpoint and the sweep would pass vacuously.
    ///
    /// Also enforced at build time by the `const` gate above; kept here to name the
    /// mismatched RPC and show both types.
    #[test]
    fn manifest_request_types_match_the_proto() {
        for (method, req) in proto_rpcs() {
            let declared = MEDIATION_MANIFEST
                .iter()
                .find(|(m, _, _, _)| *m == method)
                .map(|(_, _, r, _)| *r)
                .unwrap_or_else(|| panic!("RPC `{}` missing from the manifest", method));
            assert_eq!(
                declared, req,
                "RPC `{method}` takes `{req}` but the manifest declares `{declared}`; the \
                 policy entry point is the message name, so this would silently exempt it"
            );
        }
    }

    /// No agent RPC may be left unmediated. Encoded as: every manifest entry belongs to a
    /// mediated class (there is no `Unmediated` variant), and the manifest is non-empty.
    #[test]
    fn no_always_allowed_escape_hatch() {
        assert!(!MEDIATION_MANIFEST.is_empty());
        for (rpc, _, _, class) in MEDIATION_MANIFEST {
            // All defined classes are enforcement points; this match must stay exhaustive
            // so adding a future non-mediated class forces a deliberate decision here.
            match class {
                EnforcementClass::LifecycleGated
                | EnforcementClass::PolicyGated
                | EnforcementClass::PolicyGatedQuery
                | EnforcementClass::PolicyGatedRedacted
                | EnforcementClass::PolicyActivation
                | EnforcementClass::DeniedUnconditionally
                | EnforcementClass::CompiledOut => {}
            }
            assert!(enforcement_class(rpc).is_some());
        }
    }

    /// The behavioural proof of complete mediation: with a policy that denies everything,
    /// every RPC the build exposes must be refused.
    ///
    /// This is the property FR-7 actually claims. A handler that acts before authorizing
    /// fails here regardless of where its gate is written, whether the gate sits in a
    /// compiled-out branch, or whether it is reachable at all — none of which the previous
    /// source-text scan could detect (F-43).
    ///
    /// Requires the policy engine, so it is compiled only with `--features agent-policy`
    /// (which `strict-policy` implies).
    #[cfg(feature = "agent-policy")]
    #[tokio::test]
    async fn every_exposed_rpc_is_refused_under_a_deny_all_policy() {
        use protocols::agent as ag;
        use protocols::agent_ttrpc_async::AgentService as AgentServiceTrait;
        use std::sync::Arc;
        use tokio::sync::Mutex;
        use ttrpc::r#async::TtrpcContext;

        // A policy that defines every entry point as false. It must be explicit rather
        // than empty: an undefined rule makes the engine return no result, which surfaces
        // as an INTERNAL error rather than a policy denial, and would let a handler that
        // never consults the policy pass for the wrong reason.
        let mut deny_all = String::from("package agent_policy\n");
        let mut seen = HashSet::new();
        for (_, req) in proto_rpcs() {
            if seen.insert(req.clone()) {
                deny_all.push_str(&format!("default {req} := false\n"));
            }
        }
        deny_all.push_str("default AllowRequestsFailingPolicy := false\n");

        // Via the shared helper, not `set_policy` directly: `AGENT_POLICY` is
        // process-global, so this sweep and any other policy-driven test must not
        // install policies concurrently. Held until the sweep finishes.
        let _policy_guard = crate::policy::test_support::install_policy(&deny_all).await;

        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let sandbox = crate::sandbox::Sandbox::new(&logger).expect("sandbox");
        let svc = crate::rpc::AgentService::new_for_test(Arc::new(Mutex::new(sandbox)));
        let ctx = TtrpcContext {
            // Not a real connection: the sweep calls the handlers directly rather than
            // over a socket, and no handler reads the descriptor. -1 is the conventional
            // "no fd" sentinel and fails loudly if anything ever does read it.
            fd: -1,
            mh: ttrpc::proto::MessageHeader::default(),
            metadata: std::collections::HashMap::new(),
            timeout_nano: 0,
        };

        // Assert a refusal, and that it is the *authorization* refusing rather than the
        // handler failing for an unrelated reason. `DeniedUnconditionally` handlers refuse
        // without a policy round trip, so they are held only to PERMISSION_DENIED.
        fn check<T>(rpc: &str, class: EnforcementClass, result: ttrpc::Result<T>) {
            let err = match result {
                Ok(_) => panic!(
                    "RPC `{}` ({:?}) SUCCEEDED under a deny-all policy — total-mediation \
                     gap: it acts without reaching its enforcement point",
                    rpc, class
                ),
                Err(e) => e,
            };
            let ttrpc::Error::RpcStatus(status) = &err else {
                panic!(
                    "RPC `{}` ({:?}) failed with a non-status error: {:?}",
                    rpc, class, err
                );
            };
            assert_eq!(
                status.code(),
                ttrpc::Code::PERMISSION_DENIED,
                "RPC `{rpc}` ({class:?}) was refused with {:?} (`{}`) rather than \
                 PERMISSION_DENIED; a non-authorization failure means the sweep did not \
                 actually exercise its enforcement point",
                status.code(),
                status.message()
            );
            if class != EnforcementClass::DeniedUnconditionally {
                // The policy engine's denial text comes from `DecisionObject::explain()`,
                // which always names the endpoint and the phrase "blocked by policy" in
                // both its attributable and its no-reason-rule branches. That phrase is
                // the canonical operator-facing marker -- attributability is added to it,
                // never substituted for it -- so matching on it is what keeps a mere
                // validation error from passing for enforcement (F-153). Handlers that
                // refuse without consulting the policy word their errors differently (e.g.
                // "guest diagnostics are disabled in strict mode"), so this still
                // discriminates the policy engine from the handler.
                assert!(
                    status.message().contains("blocked by policy"),
                    "RPC `{rpc}` ({class:?}) was denied by something other than the policy \
                     engine: `{}`",
                    status.message()
                );
            }
        }

        // One arm per RPC. Exhaustive by construction: the coverage assertion below fails
        // if an arm is missing, and `every_service_rpc_is_classified` fails if the proto
        // grows a method the manifest does not know about.
        // Entries whose handler is not compiled into this build have no call site by
        // definition; seed them so the coverage assertion below still means something.
        let mut swept: HashSet<&str> = MEDIATION_MANIFEST
            .iter()
            .filter(|(_, _, _, c)| *c == EnforcementClass::CompiledOut)
            .map(|(rpc, _, _, _)| *rpc)
            .collect();
        macro_rules! sweep {
            ($rpc:literal, $call:expr) => {{
                let class = enforcement_class($rpc).expect(concat!($rpc, " in manifest"));
                if class.must_refuse_under_deny_all() {
                    check($rpc, class, $call.await);
                }
                swept.insert($rpc);
            }};
        }

        sweep!(
            "CreateContainer",
            svc.create_container(&ctx, ag::CreateContainerRequest::default())
        );
        sweep!(
            "StartContainer",
            svc.start_container(&ctx, ag::StartContainerRequest::default())
        );
        sweep!(
            "RemoveContainer",
            svc.remove_container(&ctx, ag::RemoveContainerRequest::default())
        );
        sweep!(
            "ExecProcess",
            svc.exec_process(&ctx, ag::ExecProcessRequest::default())
        );
        sweep!(
            "SignalProcess",
            svc.signal_process(&ctx, ag::SignalProcessRequest::default())
        );
        sweep!(
            "WaitProcess",
            svc.wait_process(&ctx, ag::WaitProcessRequest::default())
        );
        sweep!(
            "UpdateContainer",
            svc.update_container(&ctx, ag::UpdateContainerRequest::default())
        );
        sweep!(
            "UpdateEphemeralMounts",
            svc.update_ephemeral_mounts(&ctx, ag::UpdateEphemeralMountsRequest::default())
        );
        sweep!(
            "PauseContainer",
            svc.pause_container(&ctx, ag::PauseContainerRequest::default())
        );
        sweep!(
            "ResumeContainer",
            svc.resume_container(&ctx, ag::ResumeContainerRequest::default())
        );
        sweep!(
            "RemoveStaleVirtiofsShareMounts",
            svc.remove_stale_virtiofs_share_mounts(
                &ctx,
                ag::RemoveStaleVirtiofsShareMountsRequest::default()
            )
        );
        sweep!(
            "WriteStdin",
            svc.write_stdin(&ctx, ag::WriteStreamRequest::default())
        );
        sweep!(
            "CloseStdin",
            svc.close_stdin(&ctx, ag::CloseStdinRequest::default())
        );
        sweep!(
            "TtyWinResize",
            svc.tty_win_resize(&ctx, ag::TtyWinResizeRequest::default())
        );
        sweep!(
            "UpdateInterface",
            svc.update_interface(&ctx, ag::UpdateInterfaceRequest::default())
        );
        sweep!(
            "UpdateRoutes",
            svc.update_routes(&ctx, ag::UpdateRoutesRequest::default())
        );
        sweep!(
            "AddARPNeighbors",
            svc.add_arp_neighbors(&ctx, ag::AddARPNeighborsRequest::default())
        );
        sweep!(
            "SetIPTables",
            svc.set_ip_tables(&ctx, ag::SetIPTablesRequest::default())
        );
        sweep!(
            "MemAgentMemcgSet",
            svc.mem_agent_memcg_set(&ctx, ag::MemAgentMemcgConfig::default())
        );
        sweep!(
            "MemAgentCompactSet",
            svc.mem_agent_compact_set(&ctx, ag::MemAgentCompactConfig::default())
        );
        sweep!(
            "CreateSandbox",
            svc.create_sandbox(&ctx, ag::CreateSandboxRequest::default())
        );
        sweep!(
            "DestroySandbox",
            svc.destroy_sandbox(&ctx, ag::DestroySandboxRequest::default())
        );
        sweep!(
            "OnlineCPUMem",
            svc.online_cpu_mem(&ctx, ag::OnlineCPUMemRequest::default())
        );
        sweep!(
            "ReseedRandomDev",
            svc.reseed_random_dev(&ctx, ag::ReseedRandomDevRequest::default())
        );
        sweep!(
            "MemHotplugByProbe",
            svc.mem_hotplug_by_probe(&ctx, ag::MemHotplugByProbeRequest::default())
        );
        sweep!(
            "SetGuestDateTime",
            svc.set_guest_date_time(&ctx, ag::SetGuestDateTimeRequest::default())
        );
        sweep!(
            "CopyFile",
            svc.copy_file(&ctx, ag::CopyFileRequest::default())
        );
        sweep!("AddSwap", svc.add_swap(&ctx, ag::AddSwapRequest::default()));
        sweep!(
            "AddSwapPath",
            svc.add_swap_path(&ctx, ag::AddSwapPathRequest::default())
        );
        sweep!(
            "ResizeVolume",
            svc.resize_volume(&ctx, ag::ResizeVolumeRequest::default())
        );
        sweep!(
            "CopySingleFile",
            svc.copy_single_file(&ctx, ag::CopySingleFileRequest::default())
        );
        sweep!(
            "InitVolume",
            svc.init_volume(&ctx, ag::InitVolumeRequest::default())
        );
        sweep!(
            "PutVolumeFileRevision",
            svc.put_volume_file_revision(&ctx, ag::PutVolumeFileRevisionRequest::default())
        );
        sweep!(
            "CommitVolumeRevision",
            svc.commit_volume_revision(&ctx, ag::CommitVolumeRevisionRequest::default())
        );
        sweep!(
            "StatsContainer",
            svc.stats_container(&ctx, ag::StatsContainerRequest::default())
        );
        sweep!(
            "GetDiagnosticData",
            svc.get_diagnostic_data(&ctx, ag::GetDiagnosticDataRequest::default())
        );

        // ReadStdout/ReadStderr are `PolicyGatedRedacted`: a denial returns an empty
        // success, so "no error" is not evidence of mediation on its own. The request
        // names a container that does not exist, so a handler that read before authorizing
        // would fail with InvalidContainerId — as it did before this was fixed. An empty
        // Ok is therefore proof that the denial short-circuited ahead of any effect, which
        // matters because reading a pipe consumes its bytes.
        for (rpc, stdout) in [("ReadStdout", true), ("ReadStderr", false)] {
            let resp = if stdout {
                svc.read_stdout(&ctx, ag::ReadStreamRequest::default())
                    .await
            } else {
                svc.read_stderr(&ctx, ag::ReadStreamRequest::default())
                    .await
            };
            let resp = resp.unwrap_or_else(|e| {
                panic!(
                    "RPC `{}` (PolicyGatedRedacted) returned {:?} under a deny-all policy; \
                     it must return an empty success without touching the stream, and this \
                     error shows it reached the container before authorizing",
                    rpc, e
                )
            });
            assert!(
                resp.data.is_empty(),
                "RPC `{rpc}` returned {} bytes under a deny-all policy",
                resp.data.len()
            );
            swept.insert(rpc);
        }

        sweep!(
            "ListInterfaces",
            svc.list_interfaces(&ctx, ag::ListInterfacesRequest::default())
        );
        sweep!(
            "ListRoutes",
            svc.list_routes(&ctx, ag::ListRoutesRequest::default())
        );
        sweep!(
            "GetIPTables",
            svc.get_ip_tables(&ctx, ag::GetIPTablesRequest::default())
        );
        sweep!(
            "GetMetrics",
            svc.get_metrics(&ctx, ag::GetMetricsRequest::default())
        );
        sweep!(
            "GetGuestDetails",
            svc.get_guest_details(&ctx, ag::GuestDetailsRequest::default())
        );
        sweep!(
            "GetOOMEvent",
            svc.get_oom_event(&ctx, ag::GetOOMEventRequest::default())
        );
        sweep!(
            "GetVolumeStats",
            svc.get_volume_stats(&ctx, ag::VolumeStatsRequest::default())
        );
        #[cfg(not(feature = "strict-policy"))]
        sweep!(
            "SetPolicy",
            svc.set_policy(&ctx, ag::SetPolicyRequest::default())
        );
        #[cfg(feature = "strict-policy")]
        sweep!(
            "LoadPolicyFragment",
            svc.load_policy_fragment(&ctx, ag::LoadPolicyFragmentRequest::default())
        );

        // Every manifest entry must have been visited. Without this, an RPC could be
        // dropped from the sweep and the test would still pass — the same "absence of a
        // check reads as success" failure mode the source scan had.
        let missed: Vec<&str> = MEDIATION_MANIFEST
            .iter()
            .map(|(rpc, _, _, _)| *rpc)
            .filter(|rpc| !swept.contains(rpc))
            .collect();
        assert!(
            missed.is_empty(),
            "manifest entries not exercised by the conformance sweep: {:?}",
            missed
        );
    }
}
