// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Returns a sorted list of optional features enabled at agent build time.
//
// This list is diagnostics: it is surfaced in `--version`, in the startup announce
// message, and in the `GetGuestDetails` response so an operator can see how the agent
// was built. It is guest self-report over ttRPC, so it is not evidence of anything to a
// relying party - and in a strict build `GetGuestDetails` is itself policy-gated, so the
// closed-door baseline denies it until an authorized policy is activated. A verifier
// establishes which agent it is talking to from the launch measurement (a strict build is
// a distinct UVM image), and which policy is in force from HOSTDATA/MRCONFIGID via
// init-data. Do not treat any entry below as a pre-flight security signal.
pub fn get_build_features() -> Vec<String> {
    let features: Vec<&str> = vec![
        #[cfg(feature = "agent-policy")]
        "agent-policy",
        #[cfg(feature = "seccomp")]
        "seccomp",
        // Report the strict confidential-runtime policy behaviour (closed-door baseline,
        // one-shot policy activation) for diagnostics. See the note above: the
        // authoritative signal is the launch measurement, not this entry.
        #[cfg(feature = "strict-policy")]
        "strict-policy",
        // FR-10: strict builds refuse the generic host->guest CopyFile RPC (no
        // execution-integrity guarantee for host-delivered files). Reported for
        // diagnostics; the behaviour is enforced by the build, not by this entry.
        #[cfg(feature = "strict-policy")]
        "no-generic-copyfile",
        // FR-7: strict builds disable the interactive debug console and guest diagnostics
        // (un-mediated guest access / data-exfiltration surfaces). Reported for
        // diagnostics; the behaviour is enforced by the build, not by this entry.
        #[cfg(feature = "strict-policy")]
        "no-debug-console",
        #[cfg(feature = "strict-policy")]
        "no-guest-diagnostics",
    ];

    let mut sorted: Vec<String> = features.into_iter().map(String::from).collect();

    sorted.sort();

    sorted
}
