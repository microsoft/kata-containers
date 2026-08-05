// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-9 — container *occurrence* tracking.
//!
//! The host-supplied `container_id` is an untrusted alias: the host chooses it and
//! can reuse, forge or replay it. The trusted enforcer therefore mints its own
//! *occurrence handle* for every container it creates and drives that occurrence
//! through an explicit lifecycle state machine.
//!
//! The RPCs gated on occurrence state are exactly the five the mediation manifest
//! classes `LifecycleGated`: `CreateContainer`, `StartContainer`, `ExecProcess`,
//! `SignalProcess` and `RemoveContainer`. `PauseContainer` and `ResumeContainer` are
//! **not** gated here — they are policy-gated only, and resolve the alias through the
//! sandbox's own container map. So a host cannot start a container that was never
//! created, start one twice, exec into one that is not running, signal one that was
//! never started, operate on a removed occurrence, or reuse a container id.
//!
//! Exec and signal are gated differently on purpose. `ExecProcess` requires `Running`,
//! because it introduces new execution. `SignalProcess` requires only that the
//! occurrence has been *started* (`Running` or `Stopped`): a signal to a container whose
//! init has already exited reaches nothing new, and the host must be able to send one —
//! the shim signals an exited container while stopping the pod, so refusing it would
//! leave the container unkillable.
//!
//! `Stopped` is reached from the agent's own SIGCHLD reaper when a container's init
//! process exits, not from a host RPC, so the state follows the container rather than
//! the host's say-so. A host that never calls `WaitProcess` or `RemoveContainer` cannot
//! hold the occurrence in `Running` after its init has gone.
//!
//! What is *not* armed today (implemented and unit-tested, no caller in the agent):
//!  - **Cardinality** (optional, per declaration): `create` is called with `None` for
//!    both the declaration index and the bound, so a declaration meant to admit N
//!    containers is not held to N (Attack #15). The parity implementation (hcsshim)
//!    enforces no cardinality either.
//!  - **Generation** (per-alias replay guard): `assert_generation` has no caller. No
//!    agent RPC carries an occurrence handle or generation across a call — the host
//!    presents only the alias and every gate resolves it to the *live* occurrence —
//!    so a stale generation is not expressible over the wire. Arming it requires such
//!    an RPC to exist first. With id reuse now refused outright the guard has nothing
//!    left to catch in-sandbox: an alias can no longer be recreated, so no second
//!    generation of it can exist.
//!
//! Both are retained as forward-looking capabilities, not delivered guarantees.

use std::collections::HashMap;
use std::fmt;

/// Lifecycle state of a container occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// Created (bundle/rootfs prepared) but the init process has not been started.
    Created,
    /// The init process has been started and is running.
    Running,
    /// The init process has exited / been stopped but the occurrence is not yet removed.
    Stopped,
    /// The occurrence has been torn down; its alias may not be operated on again.
    Removed,
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Lifecycle::Created => "created",
            Lifecycle::Running => "running",
            Lifecycle::Stopped => "stopped",
            Lifecycle::Removed => "removed",
        };
        f.write_str(s)
    }
}

/// A single tracked container occurrence.
#[derive(Debug, Clone)]
pub struct Occurrence {
    /// Enforcer-minted, host-independent handle for this occurrence.
    pub handle: String,
    /// The host-chosen alias (container_id) currently bound to this occurrence.
    pub alias: String,
    /// Monotonic generation for this alias (bumped every time the alias is (re)created).
    pub generation: u64,
    /// Current lifecycle state.
    pub state: Lifecycle,
    /// Policy declaration index this occurrence was admitted against (FR-4A binding /
    /// cardinality accounting). `None` if declarations are not indexed.
    pub declaration_index: Option<usize>,
    /// FR-11: fully-qualified CDI devices (with their measured spec digest) bound to this
    /// occurrence after trusted resolution.
    pub devices: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OccurrenceError {
    /// No occurrence is bound to this alias (e.g. start/exec before create).
    UnknownAlias(String),
    /// The alias exists but the requested transition is illegal from its current state.
    IllegalTransition {
        alias: String,
        from: Lifecycle,
        action: &'static str,
    },
    /// An occurrence already exists for this alias and has not been removed.
    AliasInUse(String),
    /// The alias named an occurrence that has already been removed. A container id is
    /// consumed for the sandbox's lifetime and may never name a second occurrence.
    AliasRetired(String),
    /// Admitting this occurrence would exceed the declaration's allowed cardinality.
    CardinalityExceeded {
        declaration_index: usize,
        allowed: usize,
    },
    /// The operation referenced a stale generation of the alias (replay of a prior
    /// occurrence after the alias was recreated).
    StaleGeneration {
        alias: String,
        presented: u64,
        current: u64,
    },
}

impl fmt::Display for OccurrenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OccurrenceError::UnknownAlias(a) => write!(f, "no occurrence for alias {a}"),
            OccurrenceError::IllegalTransition {
                alias,
                from,
                action,
            } => write!(
                f,
                "illegal lifecycle transition: {action} on alias {alias} while {from}"
            ),
            OccurrenceError::AliasInUse(a) => {
                write!(f, "alias {a} is already bound to a live occurrence")
            }
            OccurrenceError::AliasRetired(a) => write!(
                f,
                "alias {a} named an occurrence that has been removed; a container id is \
                 consumed for the sandbox's lifetime and cannot be reused"
            ),
            OccurrenceError::CardinalityExceeded {
                declaration_index,
                allowed,
            } => write!(
                f,
                "declaration {declaration_index} admits at most {allowed} occurrence(s)"
            ),
            OccurrenceError::StaleGeneration {
                alias,
                presented,
                current,
            } => write!(
                f,
                "stale generation for alias {alias}: presented {presented}, current {current}"
            ),
        }
    }
}

impl std::error::Error for OccurrenceError {}

/// Registry of container occurrences and their lifecycle states.
#[derive(Debug, Default)]
pub struct OccurrenceRegistry {
    /// Live and stopped occurrences, keyed by host alias.
    by_alias: HashMap<String, Occurrence>,
    /// Last generation seen for every alias ever created (retained after removal so a
    /// replayed alias cannot re-use an old generation number).
    generations: HashMap<String, u64>,
    /// Count of live (non-removed) occurrences admitted per declaration index.
    declaration_counts: HashMap<usize, usize>,
    /// Monotonic counter used to mint unique occurrence handles.
    next_handle: u64,
}

impl OccurrenceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn mint_handle(&mut self) -> String {
        self.next_handle += 1;
        format!("occ-{}", self.next_handle)
    }

    /// Create (register) a new occurrence for `alias`.
    ///
    /// * Rejects a duplicate alias that is still bound to a live occurrence.
    /// * Rejects an alias that has *ever* named an occurrence in this sandbox, even one
    ///   since removed: the id is consumed for the sandbox's lifetime (RM-20). This is the
    ///   parity behaviour — hcsshim's `create_container` requires `not container_started`
    ///   and never clears that mark, not even on `shutdown_container` — and it is what
    ///   makes "the host-supplied id is an untrusted alias" harmless: an id names at most
    ///   one occurrence, so no stale reference to it can ever be revived.
    /// * If `declaration_index` and `max_cardinality` are supplied, rejects the create
    ///   when admitting it would exceed the declaration's allowed count.
    ///
    /// Returns the minted occurrence handle.
    pub fn create(
        &mut self,
        alias: impl Into<String>,
        declaration_index: Option<usize>,
        max_cardinality: Option<usize>,
    ) -> Result<String, OccurrenceError> {
        let alias = alias.into();

        if let Some(existing) = self.by_alias.get(&alias) {
            if existing.state == Lifecycle::Removed {
                return Err(OccurrenceError::AliasRetired(alias));
            }
            return Err(OccurrenceError::AliasInUse(alias));
        }

        if let (Some(idx), Some(max)) = (declaration_index, max_cardinality) {
            let live = *self.declaration_counts.get(&idx).unwrap_or(&0);
            if live >= max {
                return Err(OccurrenceError::CardinalityExceeded {
                    declaration_index: idx,
                    allowed: max,
                });
            }
        }

        let generation = self.generations.get(&alias).map_or(0, |g| g + 1);
        self.generations.insert(alias.clone(), generation);

        let handle = self.mint_handle();
        if let Some(idx) = declaration_index {
            *self.declaration_counts.entry(idx).or_insert(0) += 1;
        }

        self.by_alias.insert(
            alias.clone(),
            Occurrence {
                handle: handle.clone(),
                alias,
                generation,
                state: Lifecycle::Created,
                declaration_index,
                devices: Vec::new(),
            },
        );
        Ok(handle)
    }

    /// FR-11: bind a trusted-resolved CDI device (fully-qualified name + measured spec
    /// digest) to a live occurrence. Rejects binding to an unknown/removed occurrence.
    pub fn bind_device(
        &mut self,
        alias: &str,
        device: impl Into<String>,
        spec_digest: impl Into<String>,
    ) -> Result<(), OccurrenceError> {
        match self.by_alias.get_mut(alias) {
            Some(o) if o.state != Lifecycle::Removed => {
                o.devices.push((device.into(), spec_digest.into()));
                Ok(())
            }
            _ => Err(OccurrenceError::UnknownAlias(alias.to_string())),
        }
    }

    /// Devices bound to a live occurrence.
    pub fn devices(&self, alias: &str) -> Option<&[(String, String)]> {
        self.get_live(alias).ok().map(|o| o.devices.as_slice())
    }

    fn get_live(&self, alias: &str) -> Result<&Occurrence, OccurrenceError> {
        match self.by_alias.get(alias) {
            Some(o) if o.state != Lifecycle::Removed => Ok(o),
            _ => Err(OccurrenceError::UnknownAlias(alias.to_string())),
        }
    }

    /// Current lifecycle state for an alias, if it has a live occurrence.
    pub fn state(&self, alias: &str) -> Option<Lifecycle> {
        self.get_live(alias).ok().map(|o| o.state)
    }

    /// Current generation for an alias, if it has a live occurrence.
    pub fn generation(&self, alias: &str) -> Option<u64> {
        self.get_live(alias).ok().map(|o| o.generation)
    }

    /// Occurrence handle bound to an alias, if it has a live occurrence.
    pub fn handle(&self, alias: &str) -> Option<&str> {
        self.get_live(alias).ok().map(|o| o.handle.as_str())
    }

    /// Assert that `alias` refers to the given generation (replay guard). Callers that
    /// carry an occurrence generation across an operation use this to reject a replayed
    /// or recreated alias.
    pub fn assert_generation(&self, alias: &str, generation: u64) -> Result<(), OccurrenceError> {
        let o = self.get_live(alias)?;
        if o.generation != generation {
            return Err(OccurrenceError::StaleGeneration {
                alias: alias.to_string(),
                presented: generation,
                current: o.generation,
            });
        }
        Ok(())
    }

    fn transition(
        &mut self,
        alias: &str,
        action: &'static str,
        allowed_from: &[Lifecycle],
        to: Lifecycle,
    ) -> Result<(), OccurrenceError> {
        let o = match self.by_alias.get_mut(alias) {
            Some(o) if o.state != Lifecycle::Removed => o,
            _ => return Err(OccurrenceError::UnknownAlias(alias.to_string())),
        };
        if !allowed_from.contains(&o.state) {
            return Err(OccurrenceError::IllegalTransition {
                alias: alias.to_string(),
                from: o.state,
                action,
            });
        }
        let decl = o.declaration_index;
        o.state = to;
        if to == Lifecycle::Removed {
            if let Some(idx) = decl {
                if let Some(c) = self.declaration_counts.get_mut(&idx) {
                    *c = c.saturating_sub(1);
                }
            }
        }
        Ok(())
    }

    /// Start: `Created` → `Running`. Rejects start-before-create and double-start.
    pub fn start(&mut self, alias: &str) -> Result<(), OccurrenceError> {
        self.transition(alias, "start", &[Lifecycle::Created], Lifecycle::Running)
    }

    /// Undo a start the runtime then refused: `Running` → `Created`.
    ///
    /// This exists so the trusted state can be made to match reality when the enforcer
    /// has already recorded a start that did not actually happen, leaving the occurrence
    /// retryable. It is **not** a host-drivable transition: no RPC maps to it, it is only
    /// reachable from the agent's own start-failure path, and it does not touch the
    /// generation counter, so it cannot be used to rewind the replay guard.
    pub fn unstart(&mut self, alias: &str) -> Result<(), OccurrenceError> {
        self.transition(alias, "unstart", &[Lifecycle::Running], Lifecycle::Created)
    }

    /// Require that an alias refers to a running occurrence (exec gating).
    ///
    /// This is the strict form: `Created` (never started), `Stopped` (init has exited) and
    /// unknown/removed are all refused. Use it for operations that would introduce new
    /// execution into the container.
    pub fn require_running(
        &self,
        alias: &str,
        action: &'static str,
    ) -> Result<(), OccurrenceError> {
        let o = self.get_live(alias)?;
        if o.state != Lifecycle::Running {
            return Err(OccurrenceError::IllegalTransition {
                alias: alias.to_string(),
                from: o.state,
                action,
            });
        }
        Ok(())
    }

    /// Require that an alias refers to a started, not-yet-removed occurrence (signal
    /// gating): `Running` or `Stopped`.
    ///
    /// Signalling is deliberately weaker than exec. A signal delivered after the init
    /// process has exited reaches nothing it could not already reach, and the host has to
    /// be able to send one: the shim signals a container whose init has already exited as
    /// part of stopping the pod, so refusing it would leave the container unkillable and
    /// the pod wedged in `Terminating`. What stays refused is what matters — signalling an
    /// occurrence that was never started, one that was never created, or one that has been
    /// removed.
    pub fn require_started(
        &self,
        alias: &str,
        action: &'static str,
    ) -> Result<(), OccurrenceError> {
        let o = self.get_live(alias)?;
        if o.state != Lifecycle::Running && o.state != Lifecycle::Stopped {
            return Err(OccurrenceError::IllegalTransition {
                alias: alias.to_string(),
                from: o.state,
                action,
            });
        }
        Ok(())
    }

    /// Stop: `Running` → `Stopped` (idempotent if already stopped).
    ///
    /// Driven by the agent's own SIGCHLD reaper when a container's init process exits, so
    /// the recorded state follows the container rather than the host's say-so.
    pub fn stop(&mut self, alias: &str) -> Result<(), OccurrenceError> {
        self.transition(
            alias,
            "stop",
            &[Lifecycle::Running, Lifecycle::Stopped],
            Lifecycle::Stopped,
        )
    }

    /// Remove: any live state → `Removed`. Frees the declaration's cardinality slot.
    pub fn remove(&mut self, alias: &str) -> Result<(), OccurrenceError> {
        self.transition(
            alias,
            "remove",
            &[Lifecycle::Created, Lifecycle::Running, Lifecycle::Stopped],
            Lifecycle::Removed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_start_exec_stop_remove_happy_path() {
        let mut r = OccurrenceRegistry::new();
        let h = r.create("c1", None, None).unwrap();
        assert!(h.starts_with("occ-"));
        assert_eq!(r.state("c1"), Some(Lifecycle::Created));
        r.start("c1").unwrap();
        assert_eq!(r.state("c1"), Some(Lifecycle::Running));
        r.require_running("c1", "exec").unwrap();
        r.stop("c1").unwrap();
        assert_eq!(r.state("c1"), Some(Lifecycle::Stopped));
        r.remove("c1").unwrap();
        assert_eq!(r.state("c1"), None);
    }

    #[test]
    fn start_before_create_is_denied() {
        let mut r = OccurrenceRegistry::new();
        assert_eq!(
            r.start("ghost").unwrap_err(),
            OccurrenceError::UnknownAlias("ghost".into())
        );
    }

    #[test]
    fn unstart_returns_a_failed_start_to_created_and_allows_retry() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        r.start("c1").unwrap();
        assert_eq!(r.state("c1"), Some(Lifecycle::Running));

        // the runtime refused the start: undo it
        r.unstart("c1").unwrap();
        assert_eq!(r.state("c1"), Some(Lifecycle::Created));

        // a legitimate retry now succeeds -- this is the regression `remove()` caused,
        // which left the occurrence terminally `Removed` and the container unstartable.
        r.start("c1").unwrap();
        assert_eq!(r.state("c1"), Some(Lifecycle::Running));
    }

    #[test]
    fn unstart_is_denied_unless_running() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        // Created, never started
        assert!(matches!(
            r.unstart("c1").unwrap_err(),
            OccurrenceError::IllegalTransition {
                from: Lifecycle::Created,
                action: "unstart",
                ..
            }
        ));

        // and it cannot resurrect a removed occurrence
        r.remove("c1").unwrap();
        assert_eq!(
            r.unstart("c1").unwrap_err(),
            OccurrenceError::UnknownAlias("c1".into())
        );
    }

    #[test]
    fn unstart_keeps_the_declaration_cardinality_slot_held() {
        let mut r = OccurrenceRegistry::new();
        // declaration 0 admits exactly one occurrence
        r.create("c1", Some(0), Some(1)).unwrap();
        r.start("c1").unwrap();
        r.unstart("c1").unwrap();

        // c1 is still alive as `Created`, so it must still hold the only slot --
        // unlike `remove()`, which would have freed it.
        assert_eq!(
            r.create("c2", Some(0), Some(1)).unwrap_err(),
            OccurrenceError::CardinalityExceeded {
                declaration_index: 0,
                allowed: 1,
            }
        );
    }

    #[test]
    fn exec_on_unknown_id_is_denied() {
        let r = OccurrenceRegistry::new();
        assert_eq!(
            r.require_running("ghost", "exec").unwrap_err(),
            OccurrenceError::UnknownAlias("ghost".into())
        );
    }

    #[test]
    fn exec_before_running_is_denied() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        // still Created, not Running
        assert!(matches!(
            r.require_running("c1", "exec").unwrap_err(),
            OccurrenceError::IllegalTransition { .. }
        ));
    }

    #[test]
    fn double_start_is_denied() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        r.start("c1").unwrap();
        assert!(matches!(
            r.start("c1").unwrap_err(),
            OccurrenceError::IllegalTransition { .. }
        ));
    }

    #[test]
    fn duplicate_live_alias_is_denied() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        assert_eq!(
            r.create("c1", None, None).unwrap_err(),
            OccurrenceError::AliasInUse("c1".into())
        );
    }

    #[test]
    fn removed_alias_cannot_be_recreated() {
        // RM-20: a container id is consumed for the sandbox's lifetime, matching the
        // baseline (hcsshim's `container_started` mark is never cleared). Without this an
        // id could name a second occurrence and a stale reference to it could be revived.
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        r.remove("c1").unwrap();
        assert_eq!(
            r.create("c1", None, None).unwrap_err(),
            OccurrenceError::AliasRetired("c1".into())
        );
        // The retirement is permanent, not a one-shot refusal.
        assert_eq!(
            r.create("c1", None, None).unwrap_err(),
            OccurrenceError::AliasRetired("c1".into())
        );
        assert_eq!(r.state("c1"), None);
    }

    #[test]
    fn stale_generation_is_rejected() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        assert_eq!(
            r.assert_generation("c1", 1).unwrap_err(),
            OccurrenceError::StaleGeneration {
                alias: "c1".into(),
                presented: 1,
                current: 0,
            }
        );
        r.assert_generation("c1", 0).unwrap();
    }

    #[test]
    fn exec_is_denied_after_the_init_process_exits() {
        // RM-19: the reaper stops the occurrence when init exits, and an exec into a
        // container that is no longer running must not be admitted.
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        r.start("c1").unwrap();
        r.stop("c1").unwrap();
        assert_eq!(
            r.require_running("c1", "exec").unwrap_err(),
            OccurrenceError::IllegalTransition {
                alias: "c1".into(),
                from: Lifecycle::Stopped,
                action: "exec",
            }
        );
    }

    #[test]
    fn signal_is_allowed_after_the_init_process_exits_but_not_before_start() {
        // Deliberately weaker than exec: the shim signals an exited container while
        // stopping the pod, and refusing that leaves the pod wedged in Terminating.
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        assert_eq!(
            r.require_started("c1", "signal").unwrap_err(),
            OccurrenceError::IllegalTransition {
                alias: "c1".into(),
                from: Lifecycle::Created,
                action: "signal",
            }
        );
        r.start("c1").unwrap();
        r.require_started("c1", "signal").unwrap();
        r.stop("c1").unwrap();
        r.require_started("c1", "signal").unwrap();
        r.remove("c1").unwrap();
        assert_eq!(
            r.require_started("c1", "signal").unwrap_err(),
            OccurrenceError::UnknownAlias("c1".into())
        );
        assert_eq!(
            r.require_started("ghost", "signal").unwrap_err(),
            OccurrenceError::UnknownAlias("ghost".into())
        );
    }

    #[test]
    fn stop_is_idempotent_and_denied_before_start() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        assert_eq!(
            r.stop("c1").unwrap_err(),
            OccurrenceError::IllegalTransition {
                alias: "c1".into(),
                from: Lifecycle::Created,
                action: "stop",
            }
        );
        r.start("c1").unwrap();
        r.stop("c1").unwrap();
        r.stop("c1").unwrap();
        assert_eq!(r.state("c1"), Some(Lifecycle::Stopped));
    }

    #[test]
    fn a_stopped_occurrence_cannot_be_started_again() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        r.start("c1").unwrap();
        r.stop("c1").unwrap();
        assert_eq!(
            r.start("c1").unwrap_err(),
            OccurrenceError::IllegalTransition {
                alias: "c1".into(),
                from: Lifecycle::Stopped,
                action: "start",
            }
        );
    }

    #[test]
    fn cardinality_denies_second_occurrence_for_one_declaration() {
        let mut r = OccurrenceRegistry::new();
        // declaration 0 admits exactly one occurrence
        r.create("c1", Some(0), Some(1)).unwrap();
        assert_eq!(
            r.create("c2", Some(0), Some(1)).unwrap_err(),
            OccurrenceError::CardinalityExceeded {
                declaration_index: 0,
                allowed: 1,
            }
        );
        // removing the first frees the slot
        r.remove("c1").unwrap();
        r.create("c2", Some(0), Some(1)).unwrap();
    }

    #[test]
    fn bind_device_records_verified_cdi_devices() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        r.bind_device("c1", "nvidia.com/gpu=0", "sha256:TRUSTED")
            .unwrap();
        assert_eq!(
            r.devices("c1"),
            Some([("nvidia.com/gpu=0".to_string(), "sha256:TRUSTED".to_string())].as_slice())
        );
        // cannot bind to a removed occurrence
        r.remove("c1").unwrap();
        assert!(r.bind_device("c1", "x=1", "d").is_err());
    }

    #[test]
    fn operating_on_removed_alias_is_denied() {
        let mut r = OccurrenceRegistry::new();
        r.create("c1", None, None).unwrap();
        r.remove("c1").unwrap();
        assert_eq!(
            r.start("c1").unwrap_err(),
            OccurrenceError::UnknownAlias("c1".into())
        );
    }
}
