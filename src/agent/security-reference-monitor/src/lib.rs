// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! Security Reference Monitor (SRM) — universal two-phase transaction manager.
//!
//! Every security-relevant, state-mutating agent operation is modelled as a
//! transaction so that policy state and runtime state commit together or are
//! reconciled/rolled back. A partial failure can never leave the enforcer believing
//! a container/mount/identity exists (or vice-versa); if a safe state cannot be
//! proven the sandbox is quarantined.
//!
//! Lifecycle: `prepare` (reserve + record the authorized plan) → `execute` (bind the
//! plan being executed, verified byte-for-byte against what was authorized) →
//! `commit` (validate observed runtime result, advance state) OR `abort` (roll back).
//!
//! Guarantees provided here:
//! - **Authorized == executed:** `execute` rejects any plan whose digest differs from
//!   the one authorized at `prepare` (supports FR-3's canonical-object property).
//! - **Anti-replay / idempotency:** a stale `expected_state_version` is rejected, and a
//!   retried operation id returns the committed result instead of duplicating effects —
//!   but only for as long as the transaction is retained. Callers that `retire` a
//!   transaction on commit trade lifetime replay protection for correctness on
//!   *repeatable* operations, where returning a cached success would report work the
//!   agent never performed. In-flight duplicates are still refused by `prepare`.
//! - **No eager commit:** state only advances on `commit`, never at authorization time.
//! - **No abandonment:** a handler future can be dropped at any await point — the ttrpc
//!   server drops it on a host-supplied timeout — which would otherwise leave a
//!   transaction in flight forever and, since `prepare` refuses in-flight ids, wedge that
//!   operation permanently. Holding a [`TxnGuard`] turns abandonment into an abort (if
//!   nothing was executed) or a quarantine (if the outcome is unknowable).
//! - **Quarantine:** on an unprovable state the monitor refuses every new operation
//!   *except teardown* (see [`ReferenceMonitor::prepare_teardown`]). Teardown is exempt
//!   because it can only remove capability: with `prepare` refused, no container, process
//!   or mount can be created while quarantined, so permitting stop/remove moves the
//!   sandbox monotonically towards less state. Refusing it instead strands the workload
//!   running with only sandbox-level destroy — which is not SRM-gated and is strictly
//!   more destructive — as the escape hatch. hcsshim draws the same line: its
//!   `setUVMInconsistent` marker is scoped to device operations, not to teardown.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

pub mod ccf;
pub mod cdi;
pub mod cose_keys;
pub mod did_x509;
pub mod fragments;
pub mod handle_binding;
pub mod merkle;
pub mod network_phase;
pub mod occurrence;
pub mod resource_graph;
pub mod scratch;
pub mod verified_images;
pub mod verified_layers;
pub use cdi::{authorize_cdi, CdiDeviceRequest, CdiError, MeasuredCdiSpec, VerifiedCdiDevice};
pub use did_x509::{DidX509Anchor, DidX509Policy};
pub use fragments::{FragmentError, FragmentStore, PolicyFragment};
pub use handle_binding::{CheckedHandle, HandleError};
pub use network_phase::{NetOp, NetPhaseError, NetworkPhase, NetworkPhaseMachine};
pub use occurrence::{Lifecycle, Occurrence, OccurrenceError, OccurrenceRegistry};
pub use resource_graph::{
    verify_ordered_bijection, PresentedResource, ResourceDeclaration, ResourceGraphError,
    ResourceKind, VerifiedResourceHandle,
};
pub use scratch::{
    classify_scratch, dm_target_types, enforce_scratch, ScratchClass, ScratchError,
    ScratchRequirement,
};
pub use verified_images::{ImageError, VerifiedImageStore};
pub use verified_layers::{LayerError, VerifiedLayerStore};

/// Host-independent identifier for a single mutating operation (idempotency key).
pub type OperationId = String;

/// Lifecycle state of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnState {
    /// Authorized and reserved; no irreversible mutation performed yet.
    Prepared,
    /// The authorized plan has been handed to execution.
    Executed,
    /// Runtime result validated; state advanced.
    Committed,
    /// Rolled back; the reserved state was released.
    ///
    /// Spec-level state only. The implementation *drops* the transaction on abort
    /// (see [`ReferenceMonitor::abort`]) so the map cannot grow without bound. This is
    /// why `formal/SRM.tla` models abort as a return to its `none` state rather than
    /// carrying a distinct `aborted` state: the two are indistinguishable to every
    /// subsequent operation, since re-preparing after an abort is legitimate.
    Aborted,
}

/// A single tracked operation.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub op_id: OperationId,
    /// State version the caller expected when preparing (anti-replay).
    pub expected_state_version: u64,
    /// Digest of the authorized, canonicalized operation plan.
    pub plan_digest: String,
    /// FR-3: digest of the object actually resolved for execution (e.g. the OCI spec
    /// after all in-guest transformers). Bound to the authorized plan so the
    /// authorized→executed relationship is explicit and auditable.
    pub executed_digest: Option<String>,
    pub state: TxnState,
    /// Committed result, retained for idempotent replay.
    pub result: Option<String>,
    /// RM-8: this transaction tears capability down (stop/remove) rather than building it
    /// up, so it is exempt from the quarantine gate. Set only via
    /// [`ReferenceMonitor::prepare_teardown`].
    pub teardown: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SrmError {
    /// The monitor is quarantined and refuses every new operation except teardown.
    Quarantined(String),
    /// Expected state version did not match the current version (stale/replayed).
    StaleStateVersion { expected: u64, current: u64 },
    /// The plan presented at execution differs from the authorized plan.
    PlanMismatch {
        authorized: String,
        presented: String,
    },
    /// No such prepared transaction.
    UnknownOperation(OperationId),
    /// The transaction is not in a state that permits this action.
    InvalidState { op: OperationId, state: TxnState },
    /// The executed-object digest is already bound and a *different* one was presented.
    /// The binding is write-once: rebinding it would rewrite the record of which object
    /// was actually executed under an authorization that has already been granted.
    ExecutedDigestAlreadyBound {
        op: OperationId,
        bound: String,
        presented: String,
    },
}

impl fmt::Display for SrmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrmError::Quarantined(r) => write!(f, "SRM quarantined: {r}"),
            SrmError::StaleStateVersion { expected, current } => {
                write!(
                    f,
                    "stale state version: expected {expected}, current {current}"
                )
            }
            SrmError::PlanMismatch {
                authorized,
                presented,
            } => {
                write!(
                    f,
                    "plan mismatch: authorized {authorized}, presented {presented}"
                )
            }
            SrmError::UnknownOperation(id) => write!(f, "unknown operation: {id}"),
            SrmError::InvalidState { op, state } => {
                write!(
                    f,
                    "operation {op} in invalid state {state:?} for this action"
                )
            }
            SrmError::ExecutedDigestAlreadyBound {
                op,
                bound,
                presented,
            } => {
                write!(
                    f,
                    "operation {op} already bound executed digest {bound}, presented {presented}"
                )
            }
        }
    }
}

impl std::error::Error for SrmError {}

/// Result of a `prepare` call.
#[derive(Debug, PartialEq, Eq)]
pub enum Prepared {
    /// A fresh transaction was reserved.
    New,
    /// The operation was already committed; the retained result is returned
    /// (idempotent replay — the caller must NOT execute again).
    AlreadyCommitted(String),
}

/// The universal two-phase transaction manager.
#[derive(Debug, Default)]
pub struct ReferenceMonitor {
    state_version: u64,
    txns: HashMap<OperationId, Transaction>,
    quarantined: Option<String>,
    /// Operation ids whose caller disappeared without resolving the transaction.
    ///
    /// Shared with every live [`TxnGuard`] so a guard's `Drop` — which is synchronous and
    /// cannot take the monitor's async lock — can still report the abandonment. Drained by
    /// [`ReferenceMonitor::reclaim_orphans`].
    orphans: Arc<Mutex<Vec<OperationId>>>,
}

/// Resolves an abandoned transaction if its caller never commits or aborts it.
///
/// A transaction is only safe because every path out of the handler that opened it either
/// commits or aborts it. That assumption does not hold: an async handler future can be
/// *dropped* at any await point, running no further code. The ttrpc server does exactly
/// this — it wraps each handler in `tokio::time::timeout` whenever the client sets
/// `timeout_nano`, a field supplied by the untrusted host — so the host can abandon any
/// transaction it likes, at a moment of its choosing.
///
/// Since `prepare` refuses an in-flight transaction rather than clobbering it, an
/// abandoned transaction would otherwise wedge its operation id for the lifetime of the
/// VM. For `remove_container` that is an unkillable container on demand, which is the
/// exact failure the transaction was introduced to prevent.
///
/// Holding this guard for the transaction's lifetime closes that hole: dropping it without
/// [`TxnGuard::disarm`] queues the operation id for reclamation, and the next `prepare` or
/// `execute` resolves it.
#[derive(Debug)]
pub struct TxnGuard {
    op_id: OperationId,
    orphans: Arc<Mutex<Vec<OperationId>>>,
    armed: bool,
}

impl TxnGuard {
    /// The transaction reached a terminal state under its owner's control; drop quietly.
    pub fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for TxnGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // A poisoned lock still holds a usable queue: another thread panicked while
        // pushing, which must not stop this abandonment from being recorded.
        let mut orphans = self.orphans.lock().unwrap_or_else(|e| e.into_inner());
        orphans.push(self.op_id.clone());
    }
}

impl ReferenceMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state_version(&self) -> u64 {
        self.state_version
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantined.is_some()
    }

    /// Take ownership of `op_id`'s lifetime, so that abandoning it cannot wedge the id.
    ///
    /// Call immediately after a successful `prepare` and [`TxnGuard::disarm`] once the
    /// transaction has been committed or aborted. See [`TxnGuard`] for why this is needed.
    pub fn guard(&self, op_id: impl Into<OperationId>) -> TxnGuard {
        TxnGuard {
            op_id: op_id.into(),
            orphans: Arc::clone(&self.orphans),
            armed: true,
        }
    }

    /// Resolve transactions whose owning handler disappeared without committing or
    /// aborting them.
    ///
    /// The state at the moment of abandonment decides what is provable:
    /// - `Prepared` — the plan was authorized and reserved, but never handed to
    ///   execution, so nothing happened. Aborting releases the id for a legitimate retry.
    /// - `Executed` — the plan *was* handed to execution and the outcome was never
    ///   observed. Whether the effect landed is unknowable, which is precisely the
    ///   divergence this monitor exists to prevent, so the sandbox is quarantined.
    ///
    /// Anything else is already terminal and needs nothing.
    fn reclaim_orphans(&mut self) {
        let orphaned = {
            let mut orphans = self.orphans.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *orphans)
        };
        for op_id in orphaned {
            match self.txns.get(&op_id).map(|t| t.state.clone()) {
                Some(TxnState::Prepared) => {
                    let _ = self.abort(&op_id);
                }
                Some(TxnState::Executed) => self.quarantine(format!(
                    "operation {op_id} was abandoned after execution; whether it took \
                     effect is unknown"
                )),
                _ => {}
            }
        }
    }

    /// Move the monitor into the quarantined state. Fail-open for availability is
    /// prohibited: once quarantined, `prepare` and `execute` refuse every operation that
    /// could create or alter capability, so no *new* SRM-tracked transaction can build
    /// capability — no container, process or mount is admitted into existence.
    ///
    /// RM-8: teardown prepared via [`Self::prepare_teardown`] is exempt, so the sandbox can
    /// still be stopped and removed gracefully. That is a de-escalation rather than a
    /// fail-open: with `prepare` still refused for everything else, admitting teardown only
    /// moves the sandbox towards less state, whereas refusing it strands the workload
    /// running and leaves sandbox-level destroy — strictly more destructive and not gated
    /// here — as the only escape.
    ///
    /// Caveat: the claim is scoped to SRM-tracked transitions. `StartContainer` now takes a
    /// non-teardown transaction, so a container created and committed *before* the
    /// quarantine can no longer be started after it; what remains outside the claim is any
    /// state transition the agent performs without minting a transaction at all. The
    /// exemption's rationale must not be read as asserting the quarantined sandbox is
    /// globally frozen.
    pub fn quarantine(&mut self, reason: impl Into<String>) {
        if self.quarantined.is_none() {
            self.quarantined = Some(reason.into());
        }
    }

    /// Phase 1: reserve state for an authorized plan. Rejects when quarantined or when
    /// the caller's expected state version is stale. Idempotent for a committed op id.
    pub fn prepare(
        &mut self,
        op_id: impl Into<OperationId>,
        expected_state_version: u64,
        plan_digest: impl Into<String>,
    ) -> Result<Prepared, SrmError> {
        self.prepare_inner(op_id, expected_state_version, plan_digest, false)
    }

    /// RM-8: like [`Self::prepare`], but for an operation that only tears capability down
    /// (stop/remove). Exempt from the quarantine gate so a degraded sandbox can still be
    /// shut down gracefully; see the module docs for why this is not a fail-open.
    pub fn prepare_teardown(
        &mut self,
        op_id: impl Into<OperationId>,
        expected_state_version: u64,
        plan_digest: impl Into<String>,
    ) -> Result<Prepared, SrmError> {
        self.prepare_inner(op_id, expected_state_version, plan_digest, true)
    }

    fn prepare_inner(
        &mut self,
        op_id: impl Into<OperationId>,
        expected_state_version: u64,
        plan_digest: impl Into<String>,
        teardown: bool,
    ) -> Result<Prepared, SrmError> {
        self.reclaim_orphans();
        if !teardown {
            if let Some(r) = &self.quarantined {
                return Err(SrmError::Quarantined(r.clone()));
            }
        }
        let op_id = op_id.into();

        // Idempotent replay: a committed op returns its retained result.
        //
        // An in-flight transaction is refused rather than overwritten. Without this, a
        // duplicate request for an operation still in progress replaces the live
        // transaction, and the loser's commit or abort then fails against a state machine
        // that no longer describes it. `formal/SRM.tla` already specifies this: `Prepare(o)`
        // requires `state[o] = "none"`, and abort returns an operation to that state.
        // Re-preparing after an abort is legitimate -- the reserved state was released.
        if let Some(txn) = self.txns.get(&op_id) {
            match txn.state {
                TxnState::Committed => {
                    return Ok(Prepared::AlreadyCommitted(
                        txn.result.clone().unwrap_or_default(),
                    ))
                }
                // RM-8: a teardown retried against an already-quarantined monitor
                // supersedes the stranded attempt instead of being refused. The dominant
                // way a host induces a quarantine is abandoning a call after `execute`
                // (see `reclaim_orphans`), which deliberately leaves the transaction
                // parked in `Executed`. Without this the very op id the host needs --
                // `remove/<cid>` or the SIGKILL id -- is wedged forever and the only
                // escape is the sandbox-level destroy RM-8 exists to avoid. Superseding
                // concedes nothing: the anti-clobber invariant protects the provability of
                // a state the monitor has *already* declared unprovable, and the exemption
                // is still confined to teardown-on-teardown while quarantined.
                TxnState::Prepared | TxnState::Executed
                    if teardown && txn.teardown && self.quarantined.is_some() => {}
                TxnState::Prepared | TxnState::Executed => {
                    return Err(SrmError::InvalidState {
                        op: op_id,
                        state: txn.state.clone(),
                    })
                }
                TxnState::Aborted => {}
            }
        }

        if expected_state_version != self.state_version {
            return Err(SrmError::StaleStateVersion {
                expected: expected_state_version,
                current: self.state_version,
            });
        }

        self.txns.insert(
            op_id.clone(),
            Transaction {
                op_id,
                expected_state_version,
                plan_digest: plan_digest.into(),
                executed_digest: None,
                state: TxnState::Prepared,
                result: None,
                teardown,
            },
        );
        Ok(Prepared::New)
    }

    /// FR-3: record the digest of the object actually resolved for execution, binding it
    /// to the authorized transaction. Returns the pair (authorized_plan_digest,
    /// executed_digest) so the caller can audit/log the canonical-object relationship.
    ///
    /// F-40: this is an audit record, and an audit record the host can rewrite after the
    /// fact is worthless as evidence, so it is gated like the entry points that *grant*
    /// capability rather than trusted to be called correctly:
    ///
    /// - **A quarantined monitor refuses it, unconditionally.** Unlike [`Self::execute`],
    ///   there is no teardown exemption: teardown exists to let a quarantined sandbox shed
    ///   capability, and nothing about writing an audit digest sheds capability. No
    ///   teardown path calls this today, and refusing one could not strand it even if it
    ///   did, because no transition of the monitor reads `executed_digest`.
    /// - **Only an in-flight transaction accepts it.** The digest describes the object
    ///   being handed to execution, so `Prepared` (bound before `execute`) and `Executed`
    ///   (bound while the runtime op is in progress, which is what `create_container`
    ///   does) are the only states where that is meaningful. Binding it to a `Committed`
    ///   transaction would retroactively change what a completed, authorized operation
    ///   claims to have executed.
    /// - **The binding is write-once.** Re-presenting the same digest is idempotent, so a
    ///   retried resolution path is harmless; presenting a *different* one is refused.
    ///
    /// `commit`, `abort` and `retire` remain deliberately ungated: they only *resolve* a
    /// transaction the monitor already authorized, and refusing them would strand it.
    ///
    /// Nothing currently reads `executed_digest` to make a decision — the real FR-3 check
    /// is `enforce_plan_binding` in the agent — but that is an argument for gating it now,
    /// not later: any future check that starts trusting the field must not inherit a hole.
    pub fn attach_executed(
        &mut self,
        op_id: &str,
        executed_digest: impl Into<String>,
    ) -> Result<(String, String), SrmError> {
        if let Some(r) = &self.quarantined {
            return Err(SrmError::Quarantined(r.clone()));
        }
        let txn = self
            .txns
            .get_mut(op_id)
            .ok_or_else(|| SrmError::UnknownOperation(op_id.to_string()))?;
        if !matches!(txn.state, TxnState::Prepared | TxnState::Executed) {
            return Err(SrmError::InvalidState {
                op: op_id.to_string(),
                state: txn.state.clone(),
            });
        }
        let executed = executed_digest.into();
        match &txn.executed_digest {
            Some(bound) if bound != &executed => {
                return Err(SrmError::ExecutedDigestAlreadyBound {
                    op: op_id.to_string(),
                    bound: bound.clone(),
                    presented: executed,
                })
            }
            _ => {}
        }
        txn.executed_digest = Some(executed.clone());
        Ok((txn.plan_digest.clone(), executed))
    }

    /// Phase 2a: bind the plan actually being executed. The presented plan digest MUST
    /// equal the authorized one, enforcing authorized == executed.
    pub fn execute(&mut self, op_id: &str, presented_plan_digest: &str) -> Result<(), SrmError> {
        self.reclaim_orphans();
        // RM-8: resolve the transaction before the quarantine gate so a teardown prepared
        // by `prepare_teardown` can still complete. An unknown op id is not a teardown, so
        // it still hits the gate first and reports the quarantine rather than a lookup miss.
        let teardown = self.txns.get(op_id).is_some_and(|t| t.teardown);
        if !teardown {
            if let Some(r) = &self.quarantined {
                return Err(SrmError::Quarantined(r.clone()));
            }
        }
        let txn = self
            .txns
            .get_mut(op_id)
            .ok_or_else(|| SrmError::UnknownOperation(op_id.to_string()))?;
        if txn.state != TxnState::Prepared {
            return Err(SrmError::InvalidState {
                op: op_id.to_string(),
                state: txn.state.clone(),
            });
        }
        if txn.plan_digest != presented_plan_digest {
            return Err(SrmError::PlanMismatch {
                authorized: txn.plan_digest.clone(),
                presented: presented_plan_digest.to_string(),
            });
        }
        txn.state = TxnState::Executed;
        Ok(())
    }

    /// Phase 2b: the runtime op succeeded; advance state and retain the result.
    pub fn commit(
        &mut self,
        op_id: &str,
        observed_result: impl Into<String>,
    ) -> Result<(), SrmError> {
        let txn = self
            .txns
            .get_mut(op_id)
            .ok_or_else(|| SrmError::UnknownOperation(op_id.to_string()))?;
        if txn.state != TxnState::Executed {
            return Err(SrmError::InvalidState {
                op: op_id.to_string(),
                state: txn.state.clone(),
            });
        }
        txn.state = TxnState::Committed;
        txn.result = Some(observed_result.into());
        self.state_version += 1;
        Ok(())
    }

    /// Roll back a prepared/executed transaction. The reserved state is released and
    /// the state version is NOT advanced (the operation had no committed effect).
    ///
    /// The entry is *removed* rather than parked in [`TxnState::Aborted`]. An aborted id
    /// carries no replay-protection value — `prepare` already treats it as re-preparable —
    /// so retaining it only grows the map. A host that can drive aborts on demand (loop
    /// `SignalProcess`/`ExecProcess` with a fresh random `exec_id`, each authorized but
    /// failing at process lookup) would otherwise add one permanent entry per attempt and
    /// exhaust guest memory.
    pub fn abort(&mut self, op_id: &str) -> Result<(), SrmError> {
        let txn = self
            .txns
            .get(op_id)
            .ok_or_else(|| SrmError::UnknownOperation(op_id.to_string()))?;
        match txn.state {
            TxnState::Prepared | TxnState::Executed => {
                self.txns.remove(op_id);
                Ok(())
            }
            _ => Err(SrmError::InvalidState {
                op: op_id.to_string(),
                state: txn.state.clone(),
            }),
        }
    }

    /// Retire a committed transaction so its operation id may be used again.
    ///
    /// `prepare` treats a committed operation id as an idempotent replay and returns the
    /// retained result without executing anything. That is correct while the object the id
    /// names still exists, but a container id is reusable: once the container is removed,
    /// the occurrence layer expects a later create for the same id to mint a fresh
    /// generation. Without retiring the create transaction that later create would be
    /// answered from the replay cache and silently do nothing.
    ///
    /// The same applies, for a different reason, to ids that name a *repeatable event*
    /// rather than an object — a signal delivery, or an exec whose id the runtime permits
    /// to be reused. There the cached result is not merely stale, it is false: replying
    /// with the retained success reports work the agent never performed. Retiring on
    /// commit narrows replay protection for those operations to in-flight duplicates,
    /// which `prepare` still refuses.
    ///
    /// Only a committed transaction may be retired; an in-flight one must be committed or
    /// aborted first.
    pub fn retire(&mut self, op_id: &str) -> Result<(), SrmError> {
        match self.txns.get(op_id) {
            Some(txn) if txn.state == TxnState::Committed => {
                self.txns.remove(op_id);
                Ok(())
            }
            Some(txn) => Err(SrmError::InvalidState {
                op: op_id.to_string(),
                state: txn.state.clone(),
            }),
            None => Err(SrmError::UnknownOperation(op_id.to_string())),
        }
    }

    pub fn transaction(&self, op_id: &str) -> Option<&Transaction> {
        self.txns.get(op_id)
    }

    /// Number of transactions currently tracked.
    ///
    /// Only committed (awaiting retirement) and in-flight transactions are retained;
    /// aborted ones are dropped. Exposed so tests can assert that host-drivable failure
    /// paths do not grow the map without bound.
    pub fn transaction_count(&self) -> usize {
        self.txns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_commits_and_advances_version() {
        let mut m = ReferenceMonitor::new();
        assert_eq!(m.state_version(), 0);
        assert_eq!(m.prepare("op1", 0, "digestA").unwrap(), Prepared::New);
        m.execute("op1", "digestA").unwrap();
        m.commit("op1", "container-created").unwrap();
        assert_eq!(m.state_version(), 1);
        assert_eq!(m.transaction("op1").unwrap().state, TxnState::Committed);
    }

    #[test]
    fn execute_rejects_plan_mismatch() {
        // authorized == executed: a plan different from the authorized one is refused.
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "digestA").unwrap();
        let err = m.execute("op1", "digestB").unwrap_err();
        assert_eq!(
            err,
            SrmError::PlanMismatch {
                authorized: "digestA".into(),
                presented: "digestB".into()
            }
        );
    }

    #[test]
    fn idempotent_replay_returns_result_without_reexecuting() {
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "d").unwrap();
        m.execute("op1", "d").unwrap();
        m.commit("op1", "result-1").unwrap();
        let v = m.state_version();
        // Re-preparing the same committed op returns the retained result, no new effect.
        assert_eq!(
            m.prepare("op1", 99, "d").unwrap(),
            Prepared::AlreadyCommitted("result-1".into())
        );
        assert_eq!(m.state_version(), v, "replay must not advance state");
    }

    #[test]
    fn stale_state_version_is_rejected() {
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "d").unwrap();
        m.execute("op1", "d").unwrap();
        m.commit("op1", "r").unwrap(); // version -> 1
        let err = m.prepare("op2", 0, "d").unwrap_err();
        assert_eq!(
            err,
            SrmError::StaleStateVersion {
                expected: 0,
                current: 1
            }
        );
    }

    #[test]
    fn abort_rolls_back_without_advancing_version() {
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "d").unwrap();
        m.execute("op1", "d").unwrap();
        m.abort("op1").unwrap();
        assert_eq!(m.state_version(), 0, "aborted op must not advance state");
        assert!(
            m.transaction("op1").is_none(),
            "aborted transaction must be dropped, not retained"
        );
        // The id is free again, exactly as if it had never been prepared.
        assert!(matches!(m.prepare("op1", 0, "d"), Ok(Prepared::New)));
    }

    #[test]
    fn aborted_transactions_do_not_accumulate() {
        // A host that can drive aborts on demand must not be able to grow the
        // transaction map without bound (guest-agent memory exhaustion).
        let mut m = ReferenceMonitor::new();
        for i in 0..1_000 {
            let op = format!("op{i}");
            m.prepare(&op, 0, "d").unwrap();
            m.abort(&op).unwrap();
        }
        assert_eq!(
            m.transaction_count(),
            0,
            "aborted transactions must not be retained"
        );
        assert_eq!(m.state_version(), 0);
    }

    #[test]
    fn quarantine_blocks_new_operations() {
        let mut m = ReferenceMonitor::new();
        m.quarantine("ambiguous failure between execute and commit");
        assert!(m.is_quarantined());
        assert!(matches!(
            m.prepare("op1", 0, "d"),
            Err(SrmError::Quarantined(_))
        ));
    }

    /// RM-8: a quarantined monitor must still let the sandbox be torn down. Refusing
    /// teardown strands the workload running with only sandbox-level destroy — which is
    /// not SRM-gated and is strictly more destructive — as the escape hatch.
    #[test]
    fn quarantine_exempts_teardown_end_to_end() {
        let mut m = ReferenceMonitor::new();
        m.quarantine("policy state rollback failed after remove_container");

        // Build-up is still refused ...
        assert!(matches!(
            m.prepare("create/ctr1", 0, "d"),
            Err(SrmError::Quarantined(_))
        ));

        // ... but a teardown runs the full prepare → execute → commit path.
        assert_eq!(
            m.prepare_teardown("remove/ctr1", 0, "d").unwrap(),
            Prepared::New
        );
        m.execute("remove/ctr1", "d").unwrap();
        m.commit("remove/ctr1", "container-removed").unwrap();
        assert_eq!(
            m.state_version(),
            1,
            "a committed teardown must still advance state"
        );
        assert!(
            m.is_quarantined(),
            "completing a teardown must not clear the quarantine"
        );
    }

    /// RM-8 regression: the dominant way a host induces a quarantine is abandoning a call
    /// after `execute`, and `reclaim_orphans` deliberately parks that transaction in
    /// `Executed`. If the retry were refused with `InvalidState`, the exact op id needed to
    /// tear the sandbox down would be wedged forever and the exemption would not fix the
    /// case that motivates it.
    #[test]
    fn an_abandoned_teardown_can_be_retried_after_the_quarantine_it_caused() {
        let mut m = ReferenceMonitor::new();

        let guard = m.guard("remove/4:ctr1");
        m.prepare_teardown("remove/4:ctr1", 0, "d1").unwrap();
        m.execute("remove/4:ctr1", "d1").unwrap();
        drop(guard); // host abandoned the call mid-flight

        m.reclaim_orphans();
        assert!(
            m.is_quarantined(),
            "abandoning after execute must quarantine"
        );
        assert_eq!(
            m.transaction("remove/4:ctr1").map(|t| t.state.clone()),
            Some(TxnState::Executed),
            "the abandoned teardown is parked, not released"
        );

        assert_eq!(
            m.prepare_teardown("remove/4:ctr1", m.state_version(), "d1")
                .unwrap(),
            Prepared::New,
            "the retry must supersede the stranded teardown"
        );
        m.execute("remove/4:ctr1", "d1").unwrap();
        m.commit("remove/4:ctr1", "container-removed").unwrap();
    }

    /// Superseding is confined to teardown-on-teardown while quarantined. Outside those
    /// conditions the anti-clobber invariant still refuses to overwrite a live transaction.
    #[test]
    fn superseding_is_confined_to_quarantined_teardown() {
        // Not quarantined: even a teardown may not clobber a live teardown.
        let mut m = ReferenceMonitor::new();
        m.prepare_teardown("remove/ctr1", 0, "d").unwrap();
        assert!(
            matches!(
                m.prepare_teardown("remove/ctr1", 0, "d"),
                Err(SrmError::InvalidState { .. })
            ),
            "a healthy monitor must still refuse a duplicate in-flight teardown"
        );

        // Quarantined, but the in-flight transaction is a build-up: still refused, so a
        // teardown op id cannot be used to displace something that creates capability.
        let mut m = ReferenceMonitor::new();
        m.prepare("create/ctr1", 0, "d").unwrap();
        m.quarantine("unprovable state");
        assert!(
            matches!(
                m.prepare_teardown("create/ctr1", m.state_version(), "d"),
                Err(SrmError::InvalidState { .. })
            ),
            "teardown must not supersede an in-flight build-up transaction"
        );
    }
    #[test]
    fn teardown_exemption_does_not_leak_to_other_transactions() {
        let mut m = ReferenceMonitor::new();
        m.prepare("create/ctr1", 0, "d1").unwrap();
        m.prepare_teardown("remove/ctr1", 0, "d2").unwrap();
        m.quarantine("unprovable state");

        assert!(
            matches!(
                m.execute("create/ctr1", "d1"),
                Err(SrmError::Quarantined(_))
            ),
            "a build-up transaction prepared before the quarantine must not execute after it"
        );
        m.execute("remove/ctr1", "d2")
            .expect("teardown must still execute");
    }

    /// An unknown op id must report the quarantine, not a lookup miss: the caller is not
    /// holding a teardown transaction, so the gate applies.
    #[test]
    fn execute_of_an_unknown_op_reports_the_quarantine() {
        let mut m = ReferenceMonitor::new();
        m.quarantine("unprovable state");
        assert!(matches!(
            m.execute("never-prepared", "d"),
            Err(SrmError::Quarantined(_))
        ));
    }

    /// Teardown is exempt from the quarantine gate, not from every other invariant.
    #[test]
    fn teardown_still_enforces_plan_binding_and_anti_replay() {
        let mut m = ReferenceMonitor::new();
        m.quarantine("unprovable state");

        assert!(
            matches!(
                m.prepare_teardown("remove/ctr1", 99, "d"),
                Err(SrmError::StaleStateVersion { .. })
            ),
            "teardown must still reject a stale expected state version"
        );

        m.prepare_teardown("remove/ctr1", 0, "authorized").unwrap();
        assert!(
            matches!(
                m.execute("remove/ctr1", "tampered"),
                Err(SrmError::PlanMismatch { .. })
            ),
            "teardown must still bind the executed plan to the authorized one"
        );
    }

    #[test]
    fn cannot_commit_without_execute() {
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "d").unwrap();
        assert!(matches!(
            m.commit("op1", "r"),
            Err(SrmError::InvalidState { .. })
        ));
    }

    #[test]
    fn a_failed_commit_leaves_the_monitor_disagreeing_with_reality() {
        // This is the hazard the commit-failure quarantine responds to. A commit can only
        // fail when the transaction is missing or not in `Executed`; the caller reaches
        // that code path *after* the runtime operation has already succeeded. The monitor
        // is then silently wrong about a real effect, so callers must not ignore the
        // error.
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "d").unwrap();
        let version_before = m.state_version();

        // Executed was never reached (or another caller already resolved the txn).
        assert!(matches!(
            m.commit("op1", "container-created"),
            Err(SrmError::InvalidState { .. })
        ));

        // The operation happened, but nothing about the monitor records it: the state
        // version has not advanced and the transaction never reaches Committed.
        assert_eq!(m.state_version(), version_before);
        assert_eq!(m.transaction("op1").unwrap().state, TxnState::Prepared);
        assert!(m.transaction("op1").unwrap().result.is_none());

        // An unknown id fails the same way, which is what an id collision looks like.
        assert!(matches!(
            m.commit("never-prepared", "r"),
            Err(SrmError::UnknownOperation(_))
        ));
    }

    #[test]
    fn prepare_refuses_an_in_flight_transaction_instead_of_clobbering_it() {
        // F-13: a duplicate request for an operation that is still in flight used to
        // overwrite the live transaction, after which the original's commit or abort
        // acted on a state machine that no longer described it. `formal/SRM.tla` requires
        // `state[o] \in {"none", "aborted"}` to prepare; this is that requirement.
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "d1").unwrap();

        // Prepared: the duplicate is refused, and the original is untouched.
        assert!(matches!(
            m.prepare("op1", m.state_version(), "d2"),
            Err(SrmError::InvalidState {
                state: TxnState::Prepared,
                ..
            })
        ));
        assert_eq!(m.transaction("op1").unwrap().plan_digest, "d1");

        // Executed: still in flight, still refused.
        m.execute("op1", "d1").unwrap();
        assert!(matches!(
            m.prepare("op1", m.state_version(), "d2"),
            Err(SrmError::InvalidState {
                state: TxnState::Executed,
                ..
            })
        ));

        // The original can still complete normally.
        m.commit("op1", "done").unwrap();
    }

    #[test]
    fn prepare_allows_a_retry_after_an_abort() {
        // The counterpart to the check above: an aborted transaction released its
        // reserved state, so re-preparing the same operation id is legitimate.
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "d1").unwrap();
        m.abort("op1").unwrap();

        assert_eq!(
            m.prepare("op1", m.state_version(), "d2").unwrap(),
            Prepared::New
        );
        assert_eq!(m.transaction("op1").unwrap().plan_digest, "d2");
    }

    #[test]
    fn concurrent_duplicates_cannot_both_reserve_the_same_operation() {
        // The checks above drive `prepare` sequentially, but the defect they cover is a
        // race. The agent holds the monitor behind a mutex and releases it between
        // phases -- `SRM.lock()` is taken and dropped around prepare, execute and commit
        // separately -- so a duplicate request can arrive while the first operation is
        // still running. This reproduces that shape: two threads contend for the same
        // operation id, each locking only for the duration of a phase.
        //
        // Exactly one must win. The loser must be refused rather than silently taking
        // the winner's transaction over, which is what made this a correctness bug and
        // not just a tidiness one.
        use std::sync::{Arc, Barrier, Mutex};

        let m = Arc::new(Mutex::new(ReferenceMonitor::new()));
        let start = Arc::new(Barrier::new(2));

        let handles: Vec<_> = vec!["d-a", "d-b"]
            .into_iter()
            .map(|digest| {
                let m = Arc::clone(&m);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    let mut guard = m.lock().unwrap();
                    let version = guard.state_version();
                    let outcome = guard.prepare("ctr1", version, digest);
                    drop(guard);
                    (digest, outcome)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let winners: Vec<_> = results
            .iter()
            .filter(|(_, r)| matches!(r, Ok(Prepared::New)))
            .collect();
        assert_eq!(winners.len(), 1, "exactly one prepare may reserve the id");

        let losers: Vec<_> = results
            .iter()
            .filter(|(_, r)| !matches!(r, Ok(Prepared::New)))
            .collect();
        assert_eq!(losers.len(), 1);
        assert!(
            matches!(
                losers[0].1,
                Err(SrmError::InvalidState {
                    state: TxnState::Prepared,
                    ..
                })
            ),
            "the losing duplicate must be refused, got {:?}",
            losers[0].1
        );

        // The surviving transaction is the winner's, untouched by the loser.
        let guard = m.lock().unwrap();
        assert_eq!(
            guard.transaction("ctr1").unwrap().plan_digest,
            *winners[0].0
        );
    }

    #[test]
    fn retiring_on_commit_gives_up_replay_protection_after_the_fact() {
        // Pins the trade-off documented for FR-6 so it cannot change silently.
        //
        // Signal and exec retire their transaction on commit, because their operation
        // ids name repeatable events rather than unique objects -- a second SIGHUP is a
        // legitimate request, not a replay, and answering it from the retained result
        // means the signal is never delivered.
        //
        // The cost is that replay protection for those two paths is scoped to duplicates
        // that arrive while the first is still in flight (refused by `prepare`, see
        // above). A retry issued after the original committed is indistinguishable from
        // a fresh request and will execute again. Closing that window needs an
        // idempotency key pinned by the initiator, which is outside FR-6's scope.
        let mut m = ReferenceMonitor::new();
        let op = "signal:ctr1::15";

        m.prepare(op, 0, "d1").unwrap();
        m.execute(op, "d1").unwrap();
        m.commit(op, "signal-delivered").unwrap();
        m.retire(op).unwrap();

        // Not deduplicated: the monitor has no memory of the first delivery, so an
        // after-the-fact retry is admitted as a new operation and the signal is sent
        // twice. This is the accepted behaviour, not a defect.
        assert_eq!(
            m.prepare(op, m.state_version(), "d1").unwrap(),
            Prepared::New,
            "a post-commit repeat is admitted; replay protection is in-flight only"
        );
    }

    #[test]
    fn retire_frees_a_committed_op_id_for_reuse() {
        // F-17/F-19: a container id is reusable once the container is removed. Without
        // retiring the create transaction, the next create for the same id is answered
        // from the replay cache and the container is never created.
        let mut m = ReferenceMonitor::new();
        m.prepare("ctr1", 0, "d1").unwrap();
        m.execute("ctr1", "d1").unwrap();
        m.commit("ctr1", "container-created").unwrap();

        // Before retiring, a fresh create for the same id is swallowed as a replay.
        assert!(matches!(
            m.prepare("ctr1", m.state_version(), "d2"),
            Ok(Prepared::AlreadyCommitted(_))
        ));

        m.retire("ctr1").unwrap();
        assert!(m.transaction("ctr1").is_none());

        // After retiring it is a genuinely new transaction again.
        assert_eq!(
            m.prepare("ctr1", m.state_version(), "d2").unwrap(),
            Prepared::New
        );
    }

    #[test]
    fn retire_refuses_in_flight_and_unknown_transactions() {
        let mut m = ReferenceMonitor::new();
        assert!(matches!(
            m.retire("nope"),
            Err(SrmError::UnknownOperation(_))
        ));

        m.prepare("op1", 0, "d").unwrap();
        assert!(matches!(
            m.retire("op1"),
            Err(SrmError::InvalidState { .. })
        ));
        m.execute("op1", "d").unwrap();
        assert!(matches!(
            m.retire("op1"),
            Err(SrmError::InvalidState { .. })
        ));
    }

    #[test]
    fn attach_executed_binds_authorized_to_executed() {
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "authorized-digest").unwrap();
        let (authorized, executed) = m.attach_executed("op1", "executed-digest").unwrap();
        assert_eq!(authorized, "authorized-digest");
        assert_eq!(executed, "executed-digest");
        assert_eq!(
            m.transaction("op1").unwrap().executed_digest.as_deref(),
            Some("executed-digest")
        );
    }

    /// F-40: the executed-object record is evidence, so a quarantined monitor must refuse
    /// to write it. Before this gate `attach_executed` was the one entry point with no
    /// state check, no quarantine gate and no write-once protection at all.
    ///
    /// There is deliberately no teardown exemption here, unlike [`ReferenceMonitor::execute`]:
    /// the RM-8 carve-out exists so a quarantined sandbox can still shed capability, and
    /// writing an audit digest sheds none. (`commit`/`abort`/`retire` stay ungated for the
    /// opposite reason — they resolve transactions the monitor already authorized.)
    #[test]
    fn attach_executed_is_refused_while_quarantined() {
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "authorized").unwrap();
        m.quarantine("unprovable");
        assert!(matches!(
            m.attach_executed("op1", "executed"),
            Err(SrmError::Quarantined(_))
        ));
        assert_eq!(m.transaction("op1").unwrap().executed_digest, None);
    }

    /// The quarantine gate is unconditional: a teardown transaction gets no carve-out,
    /// because nothing reads `executed_digest` and so refusing it strands nothing.
    #[test]
    fn attach_executed_refuses_a_teardown_too_while_quarantined() {
        let mut m = ReferenceMonitor::new();
        m.prepare_teardown("op1", 0, "authorized").unwrap();
        m.quarantine("unprovable");
        assert!(matches!(
            m.attach_executed("op1", "executed"),
            Err(SrmError::Quarantined(_))
        ));
        m.execute("op1", "authorized")
            .expect("RM-8: teardown must still execute while quarantined");
    }

    /// F-40: binding an executed object to an already-committed transaction would
    /// retroactively rewrite what a completed, authorized operation claims to have run.
    #[test]
    fn attach_executed_is_refused_once_committed() {
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "d").unwrap();
        m.execute("op1", "d").unwrap();
        m.attach_executed("op1", "executed").unwrap();
        m.commit("op1", "ok").unwrap();
        assert!(matches!(
            m.attach_executed("op1", "rewritten"),
            Err(SrmError::InvalidState { .. })
        ));
        assert_eq!(
            m.transaction("op1").unwrap().executed_digest.as_deref(),
            Some("executed"),
            "the original record must survive the refused rebind"
        );
    }

    /// F-40: write-once. A retried resolution presenting the same digest is harmless and
    /// stays idempotent; a *different* digest is a second claim about the same authorized
    /// operation and is refused rather than silently overwriting the first.
    #[test]
    fn attach_executed_is_write_once() {
        let mut m = ReferenceMonitor::new();
        m.prepare("op1", 0, "authorized").unwrap();
        m.attach_executed("op1", "executed").unwrap();
        m.attach_executed("op1", "executed")
            .expect("rebinding the same digest is idempotent");
        assert_eq!(
            m.attach_executed("op1", "other"),
            Err(SrmError::ExecutedDigestAlreadyBound {
                op: "op1".into(),
                bound: "executed".into(),
                presented: "other".into(),
            })
        );
        assert_eq!(
            m.transaction("op1").unwrap().executed_digest.as_deref(),
            Some("executed")
        );
    }

    #[test]
    fn unknown_operation_errors() {
        let mut m = ReferenceMonitor::new();
        assert_eq!(
            m.execute("nope", "d").unwrap_err(),
            SrmError::UnknownOperation("nope".into())
        );
    }

    /// An owner that disappears between `prepare` and `execute` performed no side effect,
    /// so the id must become usable again. Without reclamation the refusal added to
    /// `prepare` would wedge it permanently: the host can cause exactly this by setting
    /// the ttrpc `timeout_nano` field, so a wedged `remove` id is an unkillable container.
    #[test]
    fn an_abandoned_prepared_transaction_is_released_for_retry() {
        let mut m = ReferenceMonitor::new();
        let guard = m.guard("remove/4:ctr1");
        m.prepare("remove/4:ctr1", 0, "d1").unwrap();

        drop(guard);

        // The retry succeeds and the monitor is still usable: nothing had happened yet.
        assert_eq!(
            m.prepare("remove/4:ctr1", m.state_version(), "d1").unwrap(),
            Prepared::New
        );
        assert!(!m.is_quarantined());
    }

    /// Abandoned *after* execution the outcome is unknowable, so the honest answer is
    /// quarantine rather than silently releasing the id and letting a retry build on
    /// state nobody observed.
    #[test]
    fn an_abandoned_executed_transaction_quarantines() {
        let mut m = ReferenceMonitor::new();
        let guard = m.guard("remove/4:ctr1");
        m.prepare("remove/4:ctr1", 0, "d1").unwrap();
        m.execute("remove/4:ctr1", "d1").unwrap();

        drop(guard);

        assert!(matches!(
            m.prepare("other", m.state_version(), "d2"),
            Err(SrmError::Quarantined(_))
        ));
        assert!(m.is_quarantined());
    }

    /// The normal path must not be disturbed: a transaction its owner resolved is not
    /// abandoned, however the guard is dropped afterwards.
    #[test]
    fn a_disarmed_guard_does_not_report_abandonment() {
        let mut m = ReferenceMonitor::new();
        let guard = m.guard("op1");
        m.prepare("op1", 0, "d1").unwrap();
        m.execute("op1", "d1").unwrap();
        m.commit("op1", "done").unwrap();
        guard.disarm();

        assert!(matches!(
            m.prepare("op1", m.state_version(), "d1"),
            Ok(Prepared::AlreadyCommitted(_))
        ));
        assert!(!m.is_quarantined());
    }

    /// Reclamation runs on `execute` too, so an abandonment is noticed as early as
    /// possible rather than waiting for the next `prepare`.
    #[test]
    fn execute_also_reclaims_abandoned_transactions() {
        let mut m = ReferenceMonitor::new();
        let live = m.guard("op-live");
        m.prepare("op-live", 0, "d1").unwrap();

        let abandoned = m.guard("op-gone");
        m.prepare("op-gone", m.state_version(), "d2").unwrap();
        m.execute("op-gone", "d2").unwrap();
        drop(abandoned);

        assert!(matches!(
            m.execute("op-live", "d1"),
            Err(SrmError::Quarantined(_))
        ));
        live.disarm();
    }
}
