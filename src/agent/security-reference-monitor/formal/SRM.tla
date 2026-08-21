\* Copyright (c) 2026 Microsoft Corporation
\*
\* SPDX-License-Identifier: Apache-2.0
-------------------------------- MODULE SRM --------------------------------
(***************************************************************************)
(* FR-15 — formal model of the Security Reference Monitor (SRM) lifecycle. *)
(*                                                                         *)
(* This models the two-phase transaction lifecycle implemented in          *)
(* security-reference-monitor/src/lib.rs: every security-relevant,         *)
(* state-mutating operation is prepared, executed, then either committed   *)
(* or aborted, with a global quarantine that fails closed.                 *)
(*                                                                         *)
(* The model is deliberately operation-generic: `Ops` stands for whatever  *)
(* the agent keys a transaction on -- `create/<cid>`, `start/<cid>`,       *)
(* `exec/<cid>/<eid>`, `signal/<cid>/<eid>/<sig>`, `remove/<cid>`. Nothing *)
(* below is specific to a lifecycle edge, so bringing a new handler into   *)
(* the protocol adds no proof obligation; only a handler that departs from *)
(* it does -- which is exactly how `StartContainer` once mutated sandbox   *)
(* state while taking no transaction at all, leaving                       *)
(* QuarantineAdmitsOnlyTeardown true of this model and false of the agent. *)
(*                                                                         *)
(* ------------------------------------------------------------------     *)
(* WHAT THIS MODULE DOES *NOT* MODEL                                       *)
(*                                                                         *)
(* Stated up front, because the previous revision of this file asserted a  *)
(* property it did not have.                                               *)
(*                                                                         *)
(* 1. The FR-3 authorized->executed OCI binding. `presented` below is the  *)
(*    digest handed to `execute()`, which the monitor requires to EQUAL    *)
(*    the authorization. That is an internal consistency check on the      *)
(*    monitor's own API, and on every current call site the caller passes  *)
(*    the same binding it passed to `prepare`, so no caller can fail it    *)
(*    today; it is a barrier against a future caller, not a live gate.     *)
(*                                                                         *)
(*    The real FR-3 relationship -- between the plan policy authorized and *)
(*    the OCI spec that in-guest transformers actually resolved -- is NOT  *)
(*    equality. Those digests routinely differ because the resolution      *)
(*    chain legitimately rewrites parts of the spec. It is enforced by     *)
(*    `enforce_plan_binding` in rpc.rs as a BOUNDED-DIVERGENCE check over  *)
(*    the fields policy actually decided on, which is outside this module. *)
(*                                                                         *)
(* 2. `attach_executed` (lib.rs), which records the resolved digest for    *)
(*    audit. It is gated (F-40): refused outright while quarantined, with  *)
(*    no RM-8 teardown exemption, accepted only from PREPARED/EXECUTED,    *)
(*    and write-once. Those guards constrain a field no transition here    *)
(*    reads, and add no reachable state, so unit tests cover them instead. *)
(*                                                                         *)
(* 3. Idempotent replay: preparing a COMMITTED op returns the retained     *)
(*    result without re-executing. It changes no state, so it is a         *)
(*    stuttering step.                                                     *)
(*                                                                         *)
(* 4. Stale `expected_state_version` rejection. The check is               *)
(*    `expected = version`, so a caller that reads the version and         *)
(*    prepares against it is exactly the enabled case below; a stale       *)
(*    prepare is simply not enabled.                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Ops,        \* a finite set of operation identifiers
    Digests,    \* a finite set of plan digests
    MaxCommits  \* bound on committed operations, to keep the model finite

(* Sentinel for "no digest recorded". Must not be an element of Digests. *)
NoDigest == "nodigest"

ASSUME NoDigest \notin Digests

(***************************************************************************)
(* An operation's lifecycle state.                                         *)
(*                                                                         *)
(* There is deliberately no "aborted" state. `abort` REMOVES the entry     *)
(* rather than parking it (lib.rs), because an aborted id carries no       *)
(* replay-protection value -- `prepare` already treats it as               *)
(* re-preparable -- while retaining it lets a host that can drive aborts   *)
(* on demand grow the map without bound. An earlier revision of this model *)
(* had an "aborted" state and asserted it was terminal, which contradicted *)
(* its own `Prepare` guard.                                                *)
(***************************************************************************)
States == {"none", "prepared", "executed", "committed"}

(***************************************************************************)
(* Why the monitor is quarantined. There is no unconditional quarantine    *)
(* action: every quarantine below corresponds to a specific call site.     *)
(*                                                                         *)
(*   commit-failed            commit_or_quarantine  (rpc.rs)               *)
(*   abandoned-after-execute  reclaim_orphans       (lib.rs)               *)
(*   rollback-failed          rollback_policy_state (rpc.rs)               *)
(*   no-snapshot              rollback_policy_state (rpc.rs)               *)
(*   abort-failed             abort_or_quarantine   (rpc.rs)               *)
(*   occurrence-diverged      do_create_container   (rpc.rs, strict-policy)*)
(*                                                                         *)
(* This list is checked against the implementation by                      *)
(* `quarantine_causes_match_the_formal_model` in                           *)
(* `tests/model_drift.rs`: every production `quarantine()` call site must  *)
(* map to a member of `Causes` and vice versa. The sixth cause was added   *)
(* by the agent without being added here, which is the drift that test now *)
(* prevents.                                                               *)
(***************************************************************************)
Causes == {"none", "commit-failed", "abandoned-after-execute",
           "rollback-failed", "no-snapshot", "abort-failed",
           "occurrence-diverged"}

VARIABLES
    state,        \* state[o]     : the lifecycle state of operation o
    authorized,   \* authorized[o]: the plan digest o was authorized for
    presented,    \* presented[o] : the digest handed to execute() -- see note 1
    teardown,     \* teardown[o]  : o was prepared via prepare_teardown (RM-8)
    version,      \* the monotonic committed-state version
    commits,      \* ghost: how many commits have EVER occurred
    quarantined,  \* whether the monitor is quarantined
    qcause,       \* why it is quarantined
    divergent     \* ghost: an effect landed that the monitor never recorded

vars == <<state, authorized, presented, teardown,
          version, commits, quarantined, qcause, divergent>>

DigestOrNone == Digests \cup {NoDigest}

TypeOK ==
    /\ state \in [Ops -> States]
    /\ authorized \in [Ops -> DigestOrNone]
    /\ presented \in [Ops -> DigestOrNone]
    /\ teardown \in [Ops -> BOOLEAN]
    /\ version \in Nat
    /\ commits \in Nat
    /\ quarantined \in BOOLEAN
    /\ qcause \in Causes
    /\ divergent \in BOOLEAN

Init ==
    /\ state = [o \in Ops |-> "none"]
    /\ authorized = [o \in Ops |-> NoDigest]
    /\ presented = [o \in Ops |-> NoDigest]
    /\ teardown = [o \in Ops |-> FALSE]
    /\ version = 0
    /\ commits = 0
    /\ quarantined = FALSE
    /\ qcause = "none"
    /\ divergent = FALSE

(* Clear every per-operation field, so a released id is indistinguishable
   from one that was never used. This mirrors `txns.remove(op_id)`. *)
Release(o) ==
    /\ state' = [state EXCEPT ![o] = "none"]
    /\ authorized' = [authorized EXCEPT ![o] = NoDigest]
    /\ presented' = [presented EXCEPT ![o] = NoDigest]
    /\ teardown' = [teardown EXCEPT ![o] = FALSE]

(* `quarantine()` is first-write-wins on the reason and does NOT refuse to
   fire when already quarantined (lib.rs). Modelling it as enabled only on
   a healthy monitor would make this model STRONGER than the code and hide
   every second-fault interleaving. *)
Poison(cause) ==
    /\ quarantined' = TRUE
    /\ qcause' = IF quarantined THEN qcause ELSE cause
    /\ divergent' = TRUE

----------------------------------------------------------------------------
(* Actions *)

(***************************************************************************)
(* Phase 1: reserve state for an authorized plan.                          *)
(*                                                                         *)
(* `td` distinguishes `prepare_teardown` from `prepare`. RM-8: a teardown  *)
(* is exempt from the quarantine gate so a degraded sandbox can still be   *)
(* shut down gracefully. That is a de-escalation, not a fail-open: with    *)
(* `prepare` still refused for everything else, no new transaction can     *)
(* build capability, so admitting teardown only moves the sandbox towards  *)
(* less state.                                                             *)
(*                                                                         *)
(* Second disjunct -- the RM-8 SUPERSEDING RULE. The dominant way a host   *)
(* induces a quarantine is abandoning a call after `execute` (it controls  *)
(* ttrpc's `timeout_nano`), which parks the transaction in "executed".     *)
(* Without superseding, the very op id needed to tear down is wedged       *)
(* forever and the only escape is the sandbox-level destroy RM-8 exists to *)
(* avoid. Superseding concedes nothing: the anti-clobber invariant it      *)
(* relaxes protects the provability of a state the monitor has ALREADY     *)
(* declared unprovable, and it is confined to teardown-on-teardown while   *)
(* quarantined -- see the SupersedingIsConfined property.                  *)
(***************************************************************************)
Prepare(o, d, td) ==
    /\ td \/ ~quarantined
    /\ \/ state[o] = "none"
       \/ /\ state[o] \in {"prepared", "executed"}
          /\ td
          /\ teardown[o]
          /\ quarantined
    /\ state' = [state EXCEPT ![o] = "prepared"]
    /\ authorized' = [authorized EXCEPT ![o] = d]
    /\ presented' = [presented EXCEPT ![o] = NoDigest]
    /\ teardown' = [teardown EXCEPT ![o] = td]
    /\ UNCHANGED <<version, commits, quarantined, qcause, divergent>>

(***************************************************************************)
(* Phase 2a: hand the plan to execution. The presented digest MUST equal   *)
(* the authorized one (see note 1 in the header for exactly how much this  *)
(* does and does not establish).                                           *)
(*                                                                         *)
(* The quarantine gate is applied AFTER resolving the transaction, so a    *)
(* teardown prepared before or during the quarantine can still complete.   *)
(* An unknown op id is not a teardown, so it still reports the quarantine  *)
(* rather than a lookup miss.                                              *)
(*                                                                         *)
(* A refusal (`SrmError::PlanMismatch`, or a failed gate) is deliberately  *)
(* NOT an action. `execute` mutates nothing on any error path: the entry   *)
(* stays "prepared" and the id stays reserved. Releasing it is the         *)
(* caller's separate decision, taken in `abort_or_quarantine`, and that is *)
(* what `Abort` models. An earlier revision had an `ExecuteRefused` action *)
(* that released the id in the same step; it was transition-equivalent to  *)
(* `Abort` and hid the window in which a mismatched transaction is still   *)
(* live and re-executable through the monitor's public API.                *)
(***************************************************************************)
Execute(o, d) ==
    /\ teardown[o] \/ ~quarantined
    /\ state[o] = "prepared"
    /\ d = authorized[o]
    /\ state' = [state EXCEPT ![o] = "executed"]
    /\ presented' = [presented EXCEPT ![o] = d]
    /\ UNCHANGED <<authorized, teardown, version, commits,
                   quarantined, qcause, divergent>>

(***************************************************************************)
(* Phase 2b: the runtime operation succeeded. Enabled ONLY from            *)
(* "executed", so a committed op was necessarily executed, and by the      *)
(* Execute guard it was executed with the digest it was authorized for.    *)
(* Advances the version by exactly one.                                    *)
(***************************************************************************)
Commit(o) ==
    /\ state[o] = "executed"
    /\ commits < MaxCommits
    /\ state' = [state EXCEPT ![o] = "committed"]
    /\ version' = version + 1
    /\ commits' = commits + 1
    /\ UNCHANGED <<authorized, presented, teardown, quarantined, qcause, divergent>>

(***************************************************************************)
(* The commit itself fails. The runtime operation ALREADY HAPPENED, so the *)
(* agent's `commit_or_quarantine` returns success to the shim -- reporting *)
(* failure for an effect that landed would invite a replay that performs   *)
(* it twice -- and quarantines instead.                                    *)
(*                                                                         *)
(* This is why RM-7 maps `Quarantined` to ttrpc DATA_LOSS: the shim's      *)
(* FIRST sight of a degraded guest is its NEXT gated call, and it must be  *)
(* able to tell "this guest is degraded" from "this request was invalid".  *)
(*                                                                         *)
(* Guarded on NOT "executed", which is the exact complement of `Commit`.   *)
(* `ReferenceMonitor::commit` is total once the entry is in `Executed`:    *)
(* it can only return `UnknownOperation` (the entry is gone -- modelled as *)
(* "none") or `InvalidState` (`execute` never ran, or another caller       *)
(* already resolved it -- "prepared" or "committed"). Guarding this on     *)
(* "executed" instead, as an earlier revision did, modelled a fault the    *)
(* code cannot produce while never exercising the ones it can.             *)
(***************************************************************************)
CommitFails(o) ==
    /\ state[o] # "executed"
    /\ Poison("commit-failed")
    /\ UNCHANGED <<state, authorized, presented, teardown, version, commits>>

(* Roll back a reserved/executed op. The version is NOT advanced: the
   operation had no committed effect. *)
Abort(o) ==
    /\ state[o] \in {"prepared", "executed"}
    /\ Release(o)
    /\ UNCHANGED <<version, commits, quarantined, qcause, divergent>>

(* `abort_or_quarantine`: the rollback of an in-flight transaction itself
   failed, so what the monitor was tracking is no longer provable.

   `ReferenceMonitor::abort` is infallible from "prepared" and "executed" --
   it removes the entry and returns Ok -- so, as with CommitFails, the
   reachable fault is the complement: an unknown id ("none") or an entry
   that is already resolved ("committed"). Nothing is released, because
   there is nothing the monitor can soundly release. *)
AbortFailed(o) ==
    /\ state[o] \in {"none", "committed"}
    /\ Poison("abort-failed")
    /\ UNCHANGED <<state, authorized, presented, teardown, version, commits>>

(***************************************************************************)
(* Retire a committed transaction so its operation id may be used again.   *)
(*                                                                         *)
(* Absent from the first revision of this model, which treated "committed" *)
(* as terminal and asserted `version = Cardinality(Committed)`. That       *)
(* invariant is FALSE against the implementation: retiring frees the id    *)
(* but must not rewind the version, or a monitor could be talked into      *)
(* forgetting effects that really happened. The ghost `commits` counter    *)
(* pins the corrected claim.                                               *)
(*                                                                         *)
(* Retirement is required for two distinct reasons: an id naming a         *)
(* REUSABLE OBJECT (a container id, once removed) would otherwise answer a *)
(* later create from the replay cache and silently do nothing; and an id   *)
(* naming a REPEATABLE EVENT (a signal delivery, a start, an exec whose id *)
(* the runtime permits to be reused) would answer with a retained success  *)
(* for work the agent never performed.                                     *)
(***************************************************************************)
Retire(o) ==
    /\ state[o] = "committed"
    /\ Release(o)
    /\ UNCHANGED <<version, commits, quarantined, qcause, divergent>>

(***************************************************************************)
(* Abandonment (`reclaim_orphans`). The host controls `timeout_nano`, so   *)
(* it can drop any in-flight call. What is provable depends on the state   *)
(* at the moment of abandonment.                                           *)
(***************************************************************************)

(* Prepared: the plan was authorized and reserved but never handed to
   execution, so nothing happened. Releasing the id is safe. *)
AbandonPrepared(o) ==
    /\ state[o] = "prepared"
    /\ Release(o)
    /\ UNCHANGED <<version, commits, quarantined, qcause, divergent>>

(* Executed: the plan WAS handed to execution and the outcome was never
   observed. Whether the effect landed is unknowable -- precisely the
   divergence this monitor exists to prevent -- so quarantine. The
   transaction is deliberately left parked in "executed", which is what
   makes the superseding rule in Prepare necessary. *)
AbandonExecuted(o) ==
    /\ state[o] = "executed"
    /\ Poison("abandoned-after-execute")
    /\ UNCHANGED <<state, authorized, presented, teardown, version, commits>>

(* The agent failed to restore policy state after a failed operation, so
   the enforcer's view of what is permitted no longer matches what was
   authorized. Two distinct call sites in `rollback_policy_state`: the
   revert failed, or there was no snapshot to revert to. Neither is
   internal to the transaction lifecycle, so neither is scoped to an op. *)
RollbackFailed ==
    /\ Poison("rollback-failed")
    /\ UNCHANGED <<state, authorized, presented, teardown, version, commits>>

SnapshotMissing ==
    /\ Poison("no-snapshot")
    /\ UNCHANGED <<state, authorized, presented, teardown, version, commits>>

(* FR-9: under `strict-policy`, `do_create_container` records the container's
   occurrence after the transaction has committed. If the occurrence registry
   refuses the record, the monitor's transaction log and the registry disagree
   about which containers exist, and neither can be believed. Like the two
   rollback faults this is not scoped to an operation id -- the divergence is
   between two whole-sandbox registries, not within one transaction -- so it
   takes no argument. *)
OccurrenceDiverged ==
    /\ Poison("occurrence-diverged")
    /\ UNCHANGED <<state, authorized, presented, teardown, version, commits>>

Next ==
    \/ \E o \in Ops, d \in Digests, td \in BOOLEAN : Prepare(o, d, td)
    \/ \E o \in Ops, d \in Digests : Execute(o, d)
    \/ \E o \in Ops : Commit(o)
    \/ \E o \in Ops : CommitFails(o)
    \/ \E o \in Ops : Abort(o)
    \/ \E o \in Ops : AbortFailed(o)
    \/ \E o \in Ops : Retire(o)
    \/ \E o \in Ops : AbandonPrepared(o)
    \/ \E o \in Ops : AbandonExecuted(o)
    \/ RollbackFailed
    \/ SnapshotMissing
    \/ OccurrenceDiverged

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
(* Invariants *)

Committed == {o \in Ops : state[o] = "committed"}

(* Safety: the version counts every commit that has ever occurred. Retiring
   a transaction frees its id without rewinding the version, so the version
   is an upper bound on the currently-committed set rather than equal to it.
   The second conjunct is the load-bearing one; the first holds by
   construction of the `commits` ghost and is here to catch an edit that
   advances one without the other. *)
VersionCountsAllCommits ==
    /\ version = commits
    /\ version >= Cardinality(Committed)

(* A committed operation was executed with exactly the digest it was
   authorized for. This is the monitor's internal execute() check; see note
   1 in the header for why it is NOT the FR-3 OCI binding. Structurally
   guaranteed -- Commit is enabled only from "executed", and Execute only
   when the presented digest matches -- but stated so that a future
   relaxation of either guard is caught. *)
CommittedIsPlanBound ==
    \A o \in Ops :
        state[o] = "committed" =>
            /\ presented[o] = authorized[o]
            /\ presented[o] \in Digests

(* Every quarantine has a cause, and a cause implies a quarantine. There is
   no unconditional fail-closed action: the model can only quarantine
   through one of the six call sites enumerated in `Causes`. *)
QuarantineHasCause == quarantined <=> (qcause # "none")

(* A monitor whose recorded version no longer matches reality is always
   quarantined -- what makes it safe for the agent to return success on a
   failed commit.

   Honest scope: `divergent` is only ever raised by `Poison`, which raises
   `quarantined` in the same step, so this is a structural check that no
   divergence-introducing action forgets to fail closed. It guards future
   edits to the model; it is not an independent theorem about the code. *)
DivergenceImpliesQuarantine == divergent => quarantined

(* An in-flight transaction always has an authorization to be bound to. *)
InFlightIsAuthorized ==
    \A o \in Ops :
        state[o] \in {"prepared", "executed"} => authorized[o] \in Digests

----------------------------------------------------------------------------
(* Action and temporal properties *)

(* Quarantine is sticky: once set it never clears. Stated as an ACTION
   property rather than []( quarantined => []quarantined ) so that TLC
   checks it during state exploration and NAMES it on violation; the
   temporal form is only reached in the liveness phase, which never runs if
   an invariant fires first, and TLC reports it anonymously as "Temporal
   properties were violated". The two are equivalent: no single step may
   clear the flag, so by induction no behaviour may. *)
QuarantineSticky == [][quarantined => quarantined']_vars

(* Fail closed, part 1: once quarantined, no operation is newly admitted
   unless it is a teardown. This is the RM-8 soundness claim, and the reason
   F-39 mattered -- `StartContainer` used to build capability without
   appearing in this protocol at all, so the claim held over the model while
   being false of the agent. *)
QuarantineAdmitsOnlyTeardown ==
    [][ \A o \in Ops :
            (quarantined /\ state[o] = "none" /\ state'[o] = "prepared")
                => teardown'[o] ]_vars

(* Fail closed, part 2: the gate on `execute` is separate from the gate on
   `prepare`, and is the one that stops a non-teardown transaction prepared
   BEFORE the quarantine from proceeding after it. Without this property the
   model checks only half of what `quarantine()` claims. *)
QuarantineGatesExecute ==
    [][ \A o \in Ops :
            (quarantined /\ state[o] = "prepared" /\ state'[o] = "executed")
                => teardown[o] ]_vars

(* The superseding rule never touches a non-teardown transaction, and never
   fires on a healthy monitor. The antecedent references the `Prepare`
   ACTION rather than a before/after state predicate: a predicate of the
   form state[o] # "none" /\ state'[o] = "prepared" also holds of an op
   that merely STAYED prepared while a different op took a step.

   Known blind spot: the `_vars` subscript exempts steps that change
   nothing, so re-preparing an entry that is already "prepared" with the
   SAME digest and the SAME `td` is a stuttering step and is not checked.
   That case changes no modelled state at all -- state, authorized,
   presented (already NoDigest for a prepared entry) and teardown are all
   identical -- so it is unobservable here by construction rather than
   overlooked. Every supersede that changes anything, including one that
   reuses the digest but flips `td` or acts on an "executed" entry, is
   checked. Closing it would need a ghost step counter in `vars`, which
   would make the state space unbounded for no additional coverage.

   Without this confinement, superseding would be a general clobber of
   in-flight transactions -- exactly the defect the anti-clobber check in
   `prepare` exists to prevent. *)
SupersedingIsConfined ==
    [][ \A o \in Ops, d \in Digests, td \in BOOLEAN :
            (Prepare(o, d, td) /\ state[o] # "none")
                => (quarantined /\ teardown[o] /\ td) ]_vars

(* The version never rewinds -- in particular, retirement does not
   decrement it. *)
VersionMonotone == [][version' >= version]_vars

=============================================================================
