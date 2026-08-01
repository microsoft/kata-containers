# SRM formal model (FR-15)

`SRM.tla` is a TLA+ model of the Security Reference Monitor's two-phase transaction
lifecycle implemented in `../src/lib.rs` (`prepare` → `execute` → `commit`/`abort`/`retire`,
with a fail-closed `quarantine`).

The model is deliberately **operation-generic**: `Ops` stands for whatever the agent keys a
transaction on — `create/<cid>`, `start/<cid>`, `exec/<cid>/<eid>`,
`signal/<cid>/<eid>/<sig>`, `remove/<cid>`. Nothing in the module is specific to a lifecycle
edge, so bringing a new handler into the protocol adds no proof obligation. Only a handler
that departs from the protocol does — which is exactly how `StartContainer` once mutated
sandbox state while taking no transaction at all: `QuarantineAdmitsOnlyTeardown` held over
the model while being false of the agent.

## What the model does *not* cover

A formal model is only as useful as its stated scope; the header of `SRM.tla` carries the
authoritative list. In summary, the module covers the *monitor's* lifecycle and says nothing
about:

- **The FR-3 authorized→executed OCI binding.** That check lives in
  `enforce_plan_binding` (`src/agent/src/rpc.rs`) and is a *bounded-divergence* comparison,
  not an equality: the resolution chain legitimately rewrites parts of the spec between
  authorization and execution. `CommittedIsPlanBound` models only the monitor's own
  digest-equality gate in `execute()`.
- **`attach_executed`.** It records an audit digest and performs no digest *comparison*, so
  it has no bearing on any lifecycle property the model checks. It is nonetheless gated
  (F-40): refused outright on a quarantined monitor (no RM-8 teardown exemption — writing
  an audit record sheds no capability), accepted only from `Prepared`/`Executed`, and
  write-once. Those guards are enforced by unit tests in `lib.rs` rather than by this
  model, because they constrain a field no transition of the monitor reads.
- **Idempotent replay** and **stale-version rejection**, both of which are properties of the
  RPC layer above the monitor.
- **Error paths as transitions.** `execute`, `commit` and `abort` mutate nothing when they
  return `Err`, so a refusal is modelled as the absence of an enabled action, not as an
  action of its own. Releasing the reserved id afterwards is the caller's separate decision
  (`abort_or_quarantine`), which `Abort` models. `CommitFails` and `AbortFailed` are guarded
  on the states in which those calls can actually fail — the *complement* of the states from
  which they succeed.

## Checked properties

`SRM.cfg` lists the invariants individually rather than conjoining them into one operator,
so that TLC names the invariant that actually fired. `mutation-test.py` depends on this to
assert that each mutant is caught by the property it targets.

Invariants:

- **`TypeOK`** — the state variables stay in their declared domains.
- **`VersionCountsAllCommits`** — the state version equals the number of commits that have
  *ever* occurred, and is an upper bound on the currently-committed set. Retiring a
  transaction frees its operation id without rewinding the version. The load-bearing half is
  `version >= Cardinality(Committed)`; the equality additionally pins the counter to the
  commit history.
- **`CommittedIsPlanBound`** — a committed operation was executed with exactly the plan
  digest it was authorized for. `Commit` is enabled only from `executed`, and `Execute` only
  when the presented digest matches. This is the monitor's gate, not the FR-3 OCI binding
  (see scope note above).
- **`QuarantineHasCause`** — quarantine and cause imply each other. There is no
  unconditional fail-closed action; the model can only quarantine through one of the six
  causes that exist in the implementation.
- **`DivergenceImpliesQuarantine`** — a monitor whose recorded version no longer matches
  reality is always quarantined. This is what makes it safe for the agent to return success
  on a failed commit: the effect already landed, so reporting failure would invite a replay
  that performs it twice, and the divergence is never silent. Because the implementation
  sets both flags atomically under the same lock, `Poison` does too — so this invariant is a
  *structural lint* that guards future edits to the model rather than an independent
  theorem.
- **`InFlightIsAuthorized`** — an in-flight transaction always has an authorization to bind.

Action and temporal properties:

- **`QuarantineSticky`** — once quarantined the monitor never clears. Stated as an action
  property (`[][quarantined => quarantined']_vars`) rather than the equivalent
  `[](quarantined => []quarantined)`, so TLC checks it during state exploration and names it
  on violation instead of reporting an anonymous "Temporal properties were violated".
- **`QuarantineAdmitsOnlyTeardown`** — after quarantine no operation is newly admitted
  unless it is a teardown. Admitting teardown is a de-escalation, not a fail-open: with
  `prepare` still refused for everything else, no new transaction can build capability.
- **`QuarantineGatesExecute`** — the other half of the same gate: an operation prepared
  *before* the quarantine cannot proceed to execute afterwards unless it is a teardown.
  Without this, `QuarantineAdmitsOnlyTeardown` constrains only the `none → prepared` edge
  and the execute-side guard is unchecked.
- **`SupersedingIsConfined`** — the rule that lets a teardown supersede an in-flight
  transaction never touches a non-teardown and never fires on a healthy monitor. The
  anti-clobber invariant it relaxes protects the provability of a state the monitor has
  already declared unprovable. The antecedent references the `Prepare` *action* rather than
  a before/after state predicate, which would also hold of an operation that merely stayed
  prepared while a different one took a step. One case is out of reach: re-preparing an
  already-`prepared` entry with the same digest *and* the same teardown flag changes no
  modelled state, so it is a stuttering step that `[][...]_vars` exempts. Every supersede
  that changes anything is checked.
- **`VersionMonotone`** — the version never rewinds.

## Run

```bash
./run-tlc.sh          # fetches tla2tools.jar if needed, runs TLC
./mutation-test.py    # proves the properties above are not vacuous
```

Deadlock checking is disabled because the model legitimately terminates (every operation
reaches a terminal state or the monitor quarantines), so a "deadlock" is an expected end
state rather than a defect.

`mutation-test.py` breaks one implementation-faithful guard at a time and requires TLC to
report a violation *of the property that mutation targets*. A surviving mutant — or one
caught only by an unrelated property — means the targeted property is vacuous, which is the
failure mode an earlier revision of this model actually had, where `TerminalExclusive`
asserted only that a variable did not hold two values at once.
