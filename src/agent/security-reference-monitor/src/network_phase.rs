// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-14 — network phase binding.
//!
//! Network configuration (interfaces, routes, iptables, ARP) is legitimate only while the
//! sandbox is being set up. Once the workload is running, the network surface must be
//! frozen: a host that can add a route, rewrite iptables, or spoof ARP *after* the
//! workload starts can exfiltrate or redirect traffic. The enforcer therefore binds
//! network-mutating operations to a phase state machine and refuses them once the workload
//! is running or the network is explicitly locked.
//!
//! Routes and interface addresses are additionally constrained by the policy layer
//! (`UpdateRoutesRequest.allowed_dest_regex` / `allowed_gateway_regex` and
//! `UpdateInterfaceRequest.allowed_ip_regex` in the generated Rego), which is where the
//! declared allowlist lives. This module owns the phase, not the payload.

use std::fmt;

/// Lifecycle phase of the sandbox network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkPhase {
    /// Guest booting; no sandbox yet.
    #[default]
    Boot,
    /// Sandbox being set up; network configuration is permitted here.
    SandboxSetup,
    /// A workload container has started; network is frozen.
    WorkloadRunning,
    /// Network explicitly locked (terminal); frozen.
    Locked,
}

impl fmt::Display for NetworkPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NetworkPhase::Boot => "boot",
            NetworkPhase::SandboxSetup => "sandbox-setup",
            NetworkPhase::WorkloadRunning => "workload-running",
            NetworkPhase::Locked => "locked",
        })
    }
}

/// A network-mutating operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetOp {
    ConfigureInterface,
    ConfigureRoutes,
    ConfigureIptables,
    ConfigureArp,
}

impl fmt::Display for NetOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NetOp::ConfigureInterface => "configure-interface",
            NetOp::ConfigureRoutes => "configure-routes",
            NetOp::ConfigureIptables => "configure-iptables",
            NetOp::ConfigureArp => "configure-arp",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NetPhaseError {
    /// The operation is not allowed in the current phase (post-start network mutation).
    FrozenPhase { op: NetOp, phase: NetworkPhase },
}

impl fmt::Display for NetPhaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetPhaseError::FrozenPhase { op, phase } => write!(
                f,
                "network operation {op} is not permitted while network phase is {phase}"
            ),
        }
    }
}

impl std::error::Error for NetPhaseError {}

/// Network phase state machine.
#[derive(Debug, Default)]
pub struct NetworkPhaseMachine {
    phase: NetworkPhase,
}

impl NetworkPhaseMachine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn phase(&self) -> NetworkPhase {
        self.phase
    }

    /// Enter sandbox-setup (on sandbox creation). Idempotent from Boot.
    pub fn to_sandbox_setup(&mut self) {
        if self.phase == NetworkPhase::Boot {
            self.phase = NetworkPhase::SandboxSetup;
        }
    }

    /// A workload container has started; freeze the network. Only advances forward.
    pub fn to_workload_running(&mut self) {
        if matches!(self.phase, NetworkPhase::Boot | NetworkPhase::SandboxSetup) {
            self.phase = NetworkPhase::WorkloadRunning;
        }
    }

    /// Explicitly lock the network (terminal).
    pub fn lock(&mut self) {
        self.phase = NetworkPhase::Locked;
    }

    /// Network mutation is permitted only during boot/sandbox setup.
    pub fn mutation_permitted(&self) -> bool {
        matches!(self.phase, NetworkPhase::Boot | NetworkPhase::SandboxSetup)
    }

    /// Authorize a network-mutating operation against the current phase.
    pub fn authorize(&self, op: NetOp) -> Result<(), NetPhaseError> {
        if self.mutation_permitted() {
            Ok(())
        } else {
            Err(NetPhaseError::FrozenPhase {
                op,
                phase: self.phase,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC5.5: modifying routes/iptables after the workload starts is denied by phase.
    #[test]
    fn network_mutation_after_workload_start_is_denied() {
        let mut m = NetworkPhaseMachine::new();
        m.to_sandbox_setup();
        // During setup, mutation is allowed.
        assert!(m.authorize(NetOp::ConfigureRoutes).is_ok());
        assert!(m.authorize(NetOp::ConfigureIptables).is_ok());

        // Workload starts -> frozen.
        m.to_workload_running();
        assert!(matches!(
            m.authorize(NetOp::ConfigureRoutes).unwrap_err(),
            NetPhaseError::FrozenPhase { .. }
        ));
        assert!(matches!(
            m.authorize(NetOp::ConfigureIptables).unwrap_err(),
            NetPhaseError::FrozenPhase { .. }
        ));
        assert!(matches!(
            m.authorize(NetOp::ConfigureArp).unwrap_err(),
            NetPhaseError::FrozenPhase { .. }
        ));
    }

    #[test]
    fn phase_only_advances_forward() {
        let mut m = NetworkPhaseMachine::new();
        m.to_workload_running();
        assert_eq!(m.phase(), NetworkPhase::WorkloadRunning);
        // Cannot go back to sandbox-setup.
        m.to_sandbox_setup();
        assert_eq!(m.phase(), NetworkPhase::WorkloadRunning);
        m.lock();
        assert_eq!(m.phase(), NetworkPhase::Locked);
    }

    /// TC5.6: the route destination allowlist lives in the policy layer, not here — this
    /// machine gates the phase for every network-mutating operation uniformly, including
    /// route programming, whatever the payload says.
    #[test]
    fn route_programming_is_gated_by_phase_only() {
        let mut m = NetworkPhaseMachine::new();
        assert_eq!(m.phase(), NetworkPhase::Boot);
        m.to_sandbox_setup();
        assert!(m.authorize(NetOp::ConfigureRoutes).is_ok());
        m.to_workload_running();
        assert!(matches!(
            m.authorize(NetOp::ConfigureRoutes).unwrap_err(),
            NetPhaseError::FrozenPhase {
                op: NetOp::ConfigureRoutes,
                phase: NetworkPhase::WorkloadRunning
            }
        ));
    }
}
