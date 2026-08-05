# Confidential-runtime execution-integrity hardening (PARMA compliance)

In order to support **PARMA compliance**, we identified a set of hardening features that
close concrete execution-integrity gaps in the Kata confidential-containers runtime, and
this development branch (`coco-parity`) addresses them.

PARMA reasons about a guest whose *authorized* plan equals its *executed* plan under a
closed-door policy that mediates every host-reachable operation. Reaching that bar
requires more than a policy check on the incoming request: the agent must default to
deny, treat host-supplied identifiers as untrusted aliases, bind every operation that
mutates enforcer state to a transactional state machine, verify that the object actually
executed matches the object that was authorized, and freeze or refuse surfaces that would
otherwise let the host mutate a running workload. The features below implement those
properties as a
"strict" build of the guest agent (`STRICT_POLICY=yes`), deployed via the `kata-parma`
runtime profile.

This document maps each feature to the requirement it satisfies, the commits that
implement it, the security guarantee it introduces, and how it was validated.

---

## How to read this document

- **Branch:** `coco-parity` (fork), based on kata `main` @ `4984d7944`.
- **Strict build:** all hardening is compiled under the `strict-policy` feature; a normal
  (non-strict) build is behaviourally unchanged, so the branch is safe to carry as a
  superset.
- **Trusted-state authority:** most guarantees are enforced by an agent-internal
  **Security Reference Monitor (SRM)** crate (`src/agent/security-reference-monitor/`),
  which owns the transactional lifecycle, occurrence registry, resource graph, CDI trust,
  policy-fragment verifier, scratch classifier, verified-layer + verified-image allowlists, TOCTOU handle
  binding, and network-phase machine. Keeping this logic in one crate makes it
  unit-testable and, for the lifecycle, formally model-checkable.
- **Companion docs:** `docs/cc/build-deploy-test-demo.md` (developer runbook — build, test,
  deploy, and demo, with verified commands), `docs/cc/fr1-fragments.md` (the full FR-1
  fragments reference), `docs/cc/fr1-fragment-e2e.md` (a reproducible end-to-end walk-through),
  and `docs/cc/backlog.md` (the remaining/open execution-integrity work items). This file is
  the guide-level overview across all features; the FR-1 fragments detail is large enough to
  live in its own document.
- **No new host↔guest protocol** except FR-1 (`LoadPolicyFragment`), which is additive and
  backward-compatible.
- **Validation vocabulary:** *unit* = crate unit/integration tests; *matrix* = the live
  `policy-matrix.sh` on strict `kata-parma` pods (expected 5/5); *live attack* = a
  `kata-agent-ctl` ttRPC client impersonating the shim against a running guest.

---

## Feature → requirement → commit map

| Requirement | Feature | Key commits |
|---|---|---|
| FR-2 | Closed-door default policy (fail closed) | `0a538d111` |
| FR-12 | One-shot policy activation + strict capability advertisement | `85b3ce3f7`, `ad01dd311`, `8424e7e08` |
| FR-6 | Two-phase transaction manager (SRM substrate) | `b10ffc663`, `b88ff8e51`, `e4d6c8c97`, `dfac4bd7a`, this PR |
| FR-3 | Canonical object: authorized == executed | `61ee0ca0d`, `5a736c4a8`, `798301421` |
| FR-9 | Container occurrence + lifecycle state machine | `96a0d641c`, `2434d3ef2` |
| FR-7 | Complete-mediation manifest + CI coverage | `d68c96708` |
| FR-4A | Ordered bijective resource graph | `6f8f42eea` |
| FR-11 | Trusted device/CDI resolution + occurrence binding | `9669a913b`, `0f3aa0f2f` |
| FR-10 | Disable generic CopyFile in strict | `0b41cf8a4` |
| FR-1 | Signed, add-only policy fragments — see **`docs/cc/fr1-fragments.md`** for the full sub-requirement (FR-1a…1j + Stage 2) breakdown | `11285337c`, `4ccd43f8a`, `dd2630053`, `294353a2a`, `bf602cb18`, `ff8a4d5b9`, `c6b52c2ba`, `69228f3b5`, `c0ea3cb25`, `f7ed23319`, `93e1ff6e5`, `db24d40f5`, `9cddd7f75`, `8efdaa65e`, `a63b9d5b3`, `d01fabe13`, `d6cdba49e`, `62fb8d45a`, `392d890a8`, `adaa7558b` |
| FR-1d / FR-1f | Multi-algorithm signature breadth (ES256/ES384 + RSA PS256/RS256 + EdDSA) for did:x509 leaves/chains and transparency receipts/tree-heads (PR #3) | `0ac3af0c2`, `10a0ec277` |
| FR-1c | genpolicy-native fragment declaration & composition (`fragments[]`, `fragment_containers`/`all_policy_containers`) (PR #6) | `e3e203876` |
| FR-1f (Stage 2) | External SCITT / CCF-profile transparency inclusion-proof receipts (`kata-ccf-proof/v1`) (PR #5) | `763a54cf5` |
| FR-1 (delivery) | Boot-time OCI pull → SRM-verify → inject of declared fragments (fail-closed) + the `genpolicy-fragmentgen` OCI packaging/push + settings-emission tool (PRs #7, #8) | `09c7421ae`, `391bbacaf` |
| FR-7 (breadth) | Fine-grained per-container endpoint gating on authorized container state (PRs #2, #4) | `2a6c1c3ae`, `c806264bf`, `109317082`, `54a652dd0` |
| FR-16 | Complete OCI Process field coverage in genpolicy (workingDir/apparmor/rlimits exact-match + on-wire field-coverage CI gate) | this PR |
| FR-5 | Encrypted scratch by effective mode | `44d6f9d04`, `b1603c3a6` |
| FR-4B | Mount bound to the checked handle (TOCTOU) | `44d6f9d04`, `dbea0d59b` |
| FR-4C | Verified read-only layers (dm-verity root-digest authorization) | `26d408bd7` |
| FR-4D | Verified guest-pull images (image manifest-digest authorization) (PR #9) | `3f21b647a`, `655671b39` |
| FR-14 | Network phase binding | `44d6f9d04`, `8cf9c5785` |
| FR-7 (rest) | Debug console + diagnostics disabled in strict | `8cf9c5785` |
| FR-15 | Formal model + fault injection + equivalence-claim proof | `21ac6e048`, `e76bc8d81` |
| FR-8 | Structured, no-leak decision objects | `a59f5e74f` |
| — | Local dev-env build plumbing | `c486222c1` |

---

## Stage 1 — Strict profile foundation

### FR-2 — Closed-door default policy
- **Gap:** a guest with no (or a not-yet-delivered) policy would fail open, allowing host
  requests before an authorized policy is active.
- **Fix:** the strict build ships a closed-door default policy. The "ignore requests failing
  policy" escape hatch is compiled out of strict builds.
- **Guarantee:** no host-reachable operation is permitted before an authorized policy is
  activated; unknown/undefined requests are denied, not allowed.
- **Commit:** `0a538d111`.
- **Validated:** matrix — a pod booted with no policy is closed-door (sandbox denied).

#### FR-2 hardening follow-up — closing the residual bypasses

Review against the C-ACI/hcsshim bar found three ways the closed-door default could still be
bypassed, plus a missing binding. All four are addressed on `fr2-strict-policy-hardening`.

- **Baseline is now unconditional.** Previously, if a policy file was present on the guest
  filesystem it was loaded *instead of* the closed-door baseline. That file is selected by
  host-controlled input (`KATA_AGENT_POLICY_FILE`, `agent.config_file=`) and is consumed at
  `initialize_policy()`, *before* initdata is read — so there is nothing to verify it
  against. The strict build now installs the baseline unconditionally and logs an
  `ignored-policy-file` warning if one was configured. The measured rootfs guarantees the
  *content* integrity of such a file, but not the integrity of *which* file is chosen.
- **The baseline is now fully closed.** The `default SetPolicyRequest := true` carve-out is
  removed. Initdata policy delivery calls `AgentPolicy::set_policy()` directly and never
  passed through that gate, so the carve-out only ever widened the host-reachable surface.
- **`SetPolicy` RPC compiled out of strict builds.** Policy is delivered through initdata;
  the ttRPC `SetPolicy` endpoint is no longer needed and is `#[cfg]`-ed out, so ttRPC returns
  "unimplemented" (the same pattern already used for the fragment RPCs).
- **Initdata is now bound to the launch measurement in-guest.** The agent recomputes the
  initdata digest and compares it against the launch configuration field the host stamped it
  into, immediately after `initialize_initdata()` and before any consumer. Without this, a
  host could serve initdata that does not match what the VM was launched with.
  - **SEV-SNP:** `HOST_DATA` at offset `0xC0` of the attestation report, fetched via
    configfs-TSM. The report is produced by a local PSP call, not by the host.
  - **TDX:** `MRCONFIGID` read from the kernel's tsm-mr measurement register at
    `/sys/class/misc/tdx_guest/measurements/mrconfigid`. Deliberately *not* parsed out of a
    TDX quote: `outblob` on TDX is produced by a `GetQuote` hypercall serviced by the host,
    so it depends on host-side QGS, can stall or fail at the host's discretion, and its
    layout is quote-version dependent. The measurement register comes from the TDREPORT the
    TDX module produced and is served entirely inside the guest.
  - **Failure policy:** mismatch, unreadable report, or (on TDX) a kernel without the tsm-mr
    interface aborts the VM. A guest with no TEE provider at all logs a warning and continues,
    so non-confidential development flows still boot.
- **Permissive rego excluded from the strict rootfs.** `rootfs.sh` no longer installs the
  default policy file when `STRICT_POLICY=yes`, so `allow-all.rego` is not present in the
  image to be selected in the first place.

### FR-12 — One-shot policy activation + capability advertisement
- **Gap:** if the host can replace the active policy at runtime, it can weaken enforcement
  after attestation; a verifier also needs to distinguish a strict guest from a permissive
  one.
- **Fix:** once an authorized policy is active, `SetPolicy` is refused (changing policy
  requires a new verifier-authorized epoch). The guest advertises `strict-policy` in its
  build features.
- **Guarantee:** the base policy is immutable within an epoch — `set_policy` is one-shot. The
  only sanctioned runtime extension is a signed, namespace-confined policy fragment (FR-1),
  which is additive and cannot redefine or shadow a base `agent_policy` rule. A verifier can
  distinguish a strict
  guest from a permissive one **from the attestation report**: a strict build is a distinct
  UVM image (different agent binary; `rootfs.sh` also skips installing the default policy
  under `STRICT_POLICY=yes`), so it has a distinct launch `MEASUREMENT`, and the policy
  itself is bound to `HOSTDATA`/`MRCONFIGID` via init-data (see FR-2). The `strict-policy`
  entry in `AgentDetails.extra_features` is **diagnostics only** — it is self-reported over
  ttRPC, and in a strict build `GetGuestDetails` is itself policy-gated, so it is denied by
  the closed-door baseline until a policy is activated. Do not treat it as a pre-flight
  security signal; use the launch measurement.
- **Commits:** `85b3ce3f7` (one-shot), `ad01dd311` (advertisement), `8424e7e08` (build).
- **Validated:** matrix + capability advertisement observed live. Unit coverage for the
  one-shot guard itself: first activation succeeds, a second is refused, a refused call
  leaves the active policy untouched (the guard returns before the engine is rebuilt), an
  additive policy fragment still applies after activation while `set_policy` stays refused,
  and default builds remain replaceable.
- **Follow-up:**
  - With the `SetPolicy` RPC compiled out of strict builds (see FR-2 above), the one-shot
    guard no longer has a host-reachable caller in strict mode; it now only guards the
    internal init-data activation, and is retained as defence in depth for any future
    caller. The immutability guarantee is unchanged and strictly stronger.
  - The measurement-based detection above is only actionable if the release pipeline
    **publishes the strict UVM launch digest** as a golden value for verifiers to compare
    against. That publication step is not part of this branch.

---

## Stage 2 — Canonical object + transaction core

### FR-6 — Two-phase transaction manager (Security Reference Monitor)
- **Gap:** policy state and runtime state could diverge on partial failure, leaving the
  enforcer believing a container/mount/identity exists (or not) when the opposite is true.
- **Fix:** a universal `ReferenceMonitor` models a mutating operation as
  `prepare → execute → commit`/`abort`, with idempotent replay, refusal of duplicates that
  are still in flight, a monotonic state version that rejects a `prepare` raced against a
  concurrent state change, and a fail-closed `quarantine`. (The state version is an
  internal consistency check, not host anti-replay — see **Limits** below.)
  `CreateContainer`, `ExecProcess`, `SignalProcess`, and `RemoveContainer` run as SRM
  transactions. Policy state is bracketed
  around authorization and the request's **own delta** is reverted on abort, rather than a
  whole-document snapshot being restored: ttrpc dispatches each request on its own task and
  the policy lock is released while the runtime operation runs, so restoring a snapshot
  would silently discard state committed by a concurrent request. A failed revert, or a
  missing bracket, quarantines the monitor rather than continuing on unprovable state.
  Every transaction is covered by a `TxnGuard` taken **under the same lock acquisition as
  `prepare`**, so a request cancelled at any suspension point — including one cancelled
  before it reaches its first `.await` — leaves a reclaimable record rather than a
  transaction wedged in `Prepared` forever; orphans are drained at the head of the next
  `prepare`/`execute`. Every early return between `prepare` and the runtime call reverts
  the policy delta, so a refused or duplicate operation cannot leave a phantom container
  in the enforcer's state. On a successful removal the container's transactions are
  **retired**, so a later create for the same id is a new operation rather than an
  idempotent replay of the create just undone. `prepare` refuses a duplicate for an
  operation that is still in flight rather than overwriting the live transaction. Aborted
  transactions are dropped from the map rather than parked in a terminal state, so a host
  that can drive aborts on demand cannot grow guest agent memory without bound. Every
  `commit` and `abort` result is acted on: a failure at either point means the monitor
  cannot account for an operation that already ran, so it quarantines rather than
  continuing on state it cannot vouch for. Operation ids are built by a length-prefixed
  encoder rather than by joining host-supplied names with a separator, so no two
  operations can resolve to the same id.
- **Guarantee:** policy and runtime state commit together or are reconciled/rolled back;
  an unprovable state quarantines the monitor (never fails open).
- **Scope — which RPCs are transactions, and why:** only two policy rules mutate persisted
  policy state (`pstate`): `CreateContainerRequest` (adds the container) and
  `RemoveContainerRequest` (deletes it). Both are covered, so the state that authorization
  actually mutates can always be rolled back. `ExecProcess` and `SignalProcess` are covered
  as well, though under the reference policy they emit no state ops. The remaining mutating
  RPCs in the complete-mediation manifest (FR-7) are policy-gated but **not** transactional;
  extending coverage to them is tracked in `docs/cc/backlog.md`. The bar this is measured
  against is enforcer-state coverage, not RPC-count coverage: the equivalent hcsshim
  mechanism wraps only its storage and device paths and does not bracket container
  lifecycle at all, so a transaction on an RPC that mutates no enforcer state would add
  bookkeeping without adding a rollback guarantee.
- **Limits:** the plan digest passed to `execute` is the same value computed for `prepare`
  at each call site, and the `expected_state_version` is read from the monitor and handed
  straight back, so `PlanMismatch` and `StaleStateVersion` are properties of the crate
  rather than of the integration. Meaningful anti-replay would require the version to be
  pinned by the initiator, which is outside FR-6's agent-internal scope. Quarantine blocks
  further SRM-gated operations; it does not halt the guest, but because `SignalProcess` and
  `RemoveContainer` are among those operations it does block graceful container teardown
  (see RM-7/RM-8 in `docs/cc/backlog.md`). Replay protection is also not
  uniform across the four transactions: the retained-result cache is only sound when the
  operation id names a unique object, which holds for a container id but not for a signal
  (`(container, exec, signal)` names a repeatable event) or for an exec id (reusable once
  the exec is deleted). Those two therefore retire on commit, which scopes their replay
  protection to duplicates arriving while the first is still in flight; a retry issued
  after the original committed will execute again.
- **Commits:** `b10ffc663` (crate), `b88ff8e51` (create), `e4d6c8c97` (exec/signal),
  `dfac4bd7a` (policy-state rollback), this PR (removal + rollback failure handling).
- **Validated:** unit (transaction manager tests, including transaction retirement,
  refusal of in-flight duplicates under thread contention, the orphan reaper, bounded
  growth under repeated aborts, and what a failed commit leaves behind) + fault-injection
  and randomized-sequence invariant tests + `rpc`-level integration tests covering
  operation-id injectivity and the commit/retire helpers + policy tests covering removal
  rollback via delta revert, including that a concurrent request's state change survives
  another request's rollback + matrix no-regression.

### FR-3 — Canonical object (authorized == executed)
- **Gap:** the agent mutates the authorized request before executing it (effective signal
  resolution, PCI-address rewriting of the exec environment, and a chain of in-guest OCI
  transformers at create time), so the executed object was not the object policy saw.
- **Fix, at all three mutation sites:**
  - **Effective signal:** the delivered signal is resolved (e.g. `SIGTERM`→`SIGKILL` for an
    init process with no handler) *before* authorization, so policy authorizes the signal
    actually delivered (`61ee0ca0d`).
  - **Exec environment:** `update_env_pci` is applied before authorization so the policy
    evaluates the environment actually given to the process (`798301421`).
  - **Create spec:** the authorized OCI spec is digested before any transformer runs, and
    the fully-resolved spec is digested and bound to the create transaction; divergence is
    recorded for audit (`5a736c4a8`).
- **Guarantee:** the object that executes is explicitly and auditably tied to the object
  that was authorized.
- **Commits:** `61ee0ca0d`, `798301421`, `5a736c4a8`.
- **Validated:** unit + matrix no-regression.

---

## Stage 3 — Resource graph + occurrence + total mediation

### FR-9 — Container occurrence + lifecycle state machine
- **Gap:** the host-supplied `container_id` is an untrusted alias — it can be forged,
  reused, or replayed to drive illegal lifecycle transitions.
- **Fix:** the enforcer mints its own occurrence handle per container and drives it through
  `created → running → stopped → removed`. Lifecycle RPCs are gated on occurrence state.
- **Guarantee:** start-before-create, exec/signal on an unknown occurrence, **exec** on a
  not-running occurrence, operations on a removed occurrence, and **reuse of a container id
  that has already been removed** are all rejected — by the occurrence machine, not by
  policy. Signal is deliberately *not* closed on a stopped occurrence: the shim signals
  containers it has already reaped while tearing a pod down, and refusing those leaves every
  pod on the node stuck `Terminating`.
- **Limits:** the registry additionally carries a monotonic per-alias **generation** and an
  optional per-declaration **cardinality** bound. Both are implemented and unit-tested, and
  neither is currently *armed*: `create` is called with `(None, None)` for the declaration
  index and bound, and `assert_generation` has no caller. They are forward-looking
  capabilities, not delivered guarantees. Arming them requires an operation that carries an
  occurrence handle across a call — no agent RPC does today, since the host presents only
  the `container_id` alias and every gate resolves it to the *live* occurrence. The parity
  implementation (hcsshim) enforces no cardinality either. The generation counter is in any
  case now moot for in-sandbox replay, since an alias cannot be reused at all (RM-20).
- **Commits:** `96a0d641c` (registry), `2434d3ef2` (wiring).
- **Validated:** unit + **live attack**, now automated as e2e stage
  `docs/cc/e2e/08-lifecycle-gates.sh`: a second `StartContainer` on a live container is
  refused with `IllegalTransition` under the *reference* policy; `StartContainer`,
  `SignalProcess` and `ExecProcess` on a never-created id are refused with `UnknownAlias`
  under a lifecycle-permissive policy — i.e. with the policy layer removed, so the refusal
  can only come from the occurrence machine; and, on a container whose init has exited while
  its pod sandbox is still alive, `ExecProcess` is refused with `IllegalTransition` while
  `SignalProcess` is still admitted.

### FR-7 — Complete-mediation manifest
- **Gap:** without a machine-checked inventory, a newly added RPC could ship unmediated.
- **Fix:** a manifest classifies every agent ttRPC method by its enforcement point; build
  tests fail if the proto and manifest drift, if the manifest lists a removed method, or if
  a mediated handler does not reach its enforcement point.
- **Guarantee:** every host-reachable RPC is provably mediated; there is no always-allow
  escape hatch (the strict default is closed-door).
- **Commit:** `d68c96708`.
- **Validated:** three build-time CI tests.

### FR-4A — Ordered bijective resource graph
- **Gap:** verifying only that *some* declared resource matches each presented one, with
  equal counts, lets image layers be reordered or a duplicate satisfy one declaration
  twice — producing a different root filesystem than authorized.
- **Fix:** a typed verifier enforces an order-relevant 1:1 mapping between declared and
  presented resources and equality of each resource's integrity digest (dm-verity root
  hash), returning typed handles bound to the declaration index.
- **Guarantee:** reorder, duplicate, undeclared/extra, cardinality mismatch, and
  stale-digest substitution are all rejected.
- **Commit:** `6f8f42eea`.
- **Validated:** unit tests (reorder / duplicate / stale-verity / undeclared / cardinality).
- **Follow-up:** moving this bijection into the live rego/genpolicy storage check needs a
  dm-verity/guest-pull-backed image to validate.

---

## Stage 4 — Conditional capabilities

### FR-11 — Trusted device / CDI resolution
- **Gap:** CDI resolution applies `containerEdits` (env/devices/mounts/hooks) from spec
  files in the guest *after* authorization, from a possibly host-influenced source — the
  device instance of the canonical-object gap.
- **Fix:** every CDI spec that provides a requested device must be **measured** (its content
  digest present in an authorized set); resolution is closed-door by default (host-arbitrary
  CDI refused), and each authorized device is bound to the container occurrence.
- **Guarantee:** a host cannot smuggle privilege via an unmeasured CDI annotation or spec;
  resolved device handles are tied to the occurrence.
- **Commits:** `9669a913b` (authorization logic), `0f3aa0f2f` (agent wiring + binding).
- **Validated:** unit + device-module tests; matrix no-regression.
- **Deferred (HW):** real GPU CC-attestation evidence for the device.

### FR-10 — Disable generic CopyFile in strict
- **Gap:** a generic host→guest `CopyFile` lands host-chosen bytes at a host-chosen path
  with no content-addressing or execution-integrity guarantee.
- **Fix:** strict builds refuse `CopyFile` outright (independent of the active policy) and
  advertise `no-generic-copyfile`.
- **Guarantee:** the host cannot plant files the policy never authorized.
- **Commit:** `0b41cf8a4`.
- **Validated:** **live attack** — `CopyFile` under an allow-all policy returns
  `PERMISSION_DENIED`; matrix no-regression (pod creation does not require CopyFile).

### FR-1 — Signed, add-only policy fragments
> **Full detail:** `docs/cc/fr1-fragments.md` (sub-requirement map FR-1a…1j + Stage 2, code
> locations, error variants, config format, tooling, tests). End-to-end walk-through:
> `docs/cc/fr1-fragment-e2e.md`. The summary below is the guide-level overview.
- **Gap:** the base policy is one-shot/immutable within an epoch (FR-12), but some
  deployments need to *extend* what a workload may do at runtime without a new attestation.
  Doing so is unsafe unless every extension is authenticated, monotonic, scope-limited, and
  incapable of relaxing a base invariant.
- **Fix:** a fragment carries a **signed Rego module** (the statement binds issuer, feed,
  SVN, grants, includes, requires, and module). It is verified and, on success, **merged
  into the live policy engine** so it changes authorization at enforcement time — via an
  additive, namespace-scoped `add_policy` that never touches the one-shot `set_policy` lock.
  Verification is a chain of fail-closed gates:
  - **authorized issuer** (Ed25519), signature over the statement;
  - **feed scoping** — the base declares accepted `(issuer, feed)` pairs; an undeclared feed
    is rejected;
  - **strictly-monotonic per-`(issuer, feed)` SVN**, with a declarative floor from measured
    state, persisted across restart (import can only raise the floor, never lower it);
  - **transparency Trust List** — receipts are validated at runtime against a measured
    trust list of ledgers (each with rotatable keys); per-`(issuer, feed)` `allowed_ledgers`
    scoping and policy-driven `required_receipts` decide which ledger(s) a receipt must come
    from (a single legacy anchor maps to a default ledger for back-compat). Receipts may be a
    detached ledger signature or a **transparency-log inclusion + consistency proof** (RFC
    6962 Merkle): the fragment must be provably recorded in an append-only log whose signed
    tree head only ever grows (a rewound/forked log is rejected; the head is persisted
    raise-only across restart);
  - **issuer identity** — either a pinned Ed25519 key **or** a `did:x509` certificate chain
    in the COSE `x5chain` header: path-validated to a measured CA fingerprint, leaf must
    satisfy a `did:x509` policy (subject CN / EKU / DNS SAN), revoked fingerprints rejected;
    trust anchored on **CA + policy** so leaf rotation (and leaf algorithm) needs no config
    change; `require_x509` disables the raw-key path (no downgrade). Multi-algorithm
    (ES256/ES384/RS256/PS256) leaf + chain; pure-Rust X.509/ECDSA/RSA, no Go dependency;
  - **add-only / includes scoping** — a module may only contribute in its declared
    `agent_policy.fragments[.<include>]` namespace and can never redefine a base rule;
  - **composition** — a fragment may `require` other fragments, which must already be loaded
    (cycles/unbounded depth are impossible by construction).
  - **append-only application ordering** (opt-in) — a rolling, signed log head binds each
    fragment to its predecessor (bound into the signed statement), so reordering, omission,
    or insertion is rejected fail-closed; the head is persisted raise-only across restart and
    the ordered log is exportable as a non-repudiable, customer-auditable record of the exact
    applied sequence.
  The `LoadPolicyFragment` RPC is doubly mediated (policy `is_allowed` + fragment
  verification) and fail-closed (no authorized issuers ⇒ every fragment rejected). Verify →
  apply → commit is atomic. Both a native detached-Ed25519 signature and a **COSE_Sign1
  (CBOR) envelope** are accepted (COSE via the pure-Rust `coset` crate; no Go dependency).
  Issuers, feeds, SVN floors, the transparency trust list, the did:x509 CA anchors, and the
  ordering genesis are all configured from measured state.
- **Guarantee:** only signed, non-rolled-back, scope-limited policy extensions from an
  attested-trusted issuer (pinned key or did:x509 chain) can change what the workload may do
  — in a verifiable order, auditably; unsigned, wrong-issuer, untrusted-CA, revoked,
  rolled-back, undeclared-feed, over-broad, invalid/disallowed-receipt, out-of-order, or
  unsatisfied-requirement fragments are all rejected.
- **Commits:** `11285337c`,`4ccd43f8a` (verifier + RPC); `bf602cb18`,`dd2630053`,`294353a2a`
  (Iteration 1: apply-to-live-engine, attested trust root, structured payload);
  `ff8a4d5b9`,`c6b52c2ba`,`69228f3b5` (Iteration 2: feed scoping, cryptographic receipts,
  chaining); `c0ea3cb25`,`f7ed23319`,`93e1ff6e5` (Iteration 3: SVN persistence, COSE_Sign1);
  `db24d40f5` (Iteration 4: transparency trust list), `9cddd7f75` (did:x509 identity),
  `8efdaa65e` (append-only ordering), `a63b9d5b3` (capability demo), Stage 2
  transparency-log inclusion + consistency proofs (RFC 6962 Merkle);
  `392d890a8`,`adaa7558b` (signer example, agent-ctl command, demo policy, guide).
- **Validated:** 86 fragment-related SRM unit tests (of 109 in the SRM crate)
  (issuer/signature/SVN/feed/receipt/trust-list/rotation/
  did:x509-chain/revocation/includes/chaining/persistence/COSE/ordering/Merkle-inclusion/
  consistency); an offline, self-contained capability demo (`examples/fragment-demo` —
  asserts all of the above with no cluster/openssl); **live E2E** — a base-denied exec
  becomes allowed only after a valid signed fragment is loaded over vsock
  (`fr1-fragment-attack.sh`), again via a COSE_Sign1 envelope (`fr1-cose-attack.sh`), via a
  did:x509 chain (`fr1-x509-attack.sh`); an out-of-order fragment is rejected
  (`fr1-ordering-attack.sh`); and a fragment without a transparency-log inclusion+consistency
  proof, or one presenting a rewound log, is rejected (`fr1-ttl-attack.sh`). Reproducible dev
  guide: `docs/cc/fr1-fragment-e2e.md`.
- **Follow-up (optional):** binding the issuer config + SVN/ordering/tree-head state into the
  initdata measured section proper.

---

## Stage 5 — Production hardening

### FR-5 — Encrypted scratch by effective mode
- **Gap:** trusting the host's storage driver options to decide whether scratch is
  encrypted lets a host claim encryption while presenting a plaintext backing device.
- **Fix:** the enforcer classifies scratch by its **effective** device-mapper target stack
  (`dmsetup table`) — `crypt`/`integrity` — not the host's claim, and refuses a scratch
  mount whose effective stack is plaintext.
- **Guarantee:** writable scratch is provably encrypted; host-claims-encrypted-but-plaintext
  is denied.
- **Commits:** `44d6f9d04` (classifier), `b1603c3a6` (wiring).
- **Validated:** unit tests (classification / plaintext-denied / effective-not-claimed).
- **Follow-up:** live block-`emptyDir` validation needs a dm-crypt emptyDir pod.

### FR-4B — Mount bound to the checked handle (TOCTOU)
- **Gap:** a mount destination validated at check time can be swapped (symlink/rename)
  before the mount syscall uses it.
- **Fix:** capture the destination's identity (dev/ino) right after validation and
  re-verify it immediately before `baremount`; a swap is detected and the mount refused.
- **Guarantee:** a mount binds to the object that was checked, not a re-resolved name.
- **Commits:** `44d6f9d04` (handle-binding), `dbea0d59b` (wiring).
- **Validated:** unit tests including a real filesystem swap; matrix no-regression.

### FR-4C — Verified read-only layers (dm-verity root-digest authorization)
- **Gap:** the agent builds dm-verity targets for read-only rootfs (EROFS) layers, so the
  kernel enforces that a layer's contents hash to a given root digest — but nothing checked
  that the root digest the (untrusted) host supplied is one the tenant approved. Without that
  check, a host can serve its *own* layer together with the matching, self-computed root hash:
  dm-verity passes and an attacker-controlled layer is mounted read-only.
- **Fix:** a **measured allowlist** of authorized `(algorithm, root_hash)` pairs
  (`/etc/kata/verified-layers.toml`, seeded at boot from measured state like the fragment
  trust root) plus a **fail-closed authorization gate** that runs *before* the dm-verity
  device is created (`multi_layer_erofs.rs` → `VerifiedLayerStore::verify`). Fail-closed:
  when verification is required but no layer is authorized, every layer is rejected; a
  presented digest not in the allowlist is `UnauthorizedLayer`. Comparison is normalized
  (trim + lower-case) and the algorithm is part of the key.
- **Guarantee:** a read-only layer is mounted only if its contents match a root digest the
  tenant measured/approved — the kernel proves *content ↔ digest*, this gate proves *digest ∈
  approved set*, so the host cannot substitute a different (self-consistent) layer.
- **Commits:** `26d408bd7` (store + gate + measured-config seed).
- **Validated:** 6 unit tests (`verified_layers` — authorized/unauthorized, empty-allowlist
  fail-closed, algorithm-bound, normalized compare, multi-layer); agent builds clean in both
  strict (musl) and strict+`devicemapper` (gnu) feature sets.
- **Follow-up:** live validation needs a `devicemapper` agent build + a GPT/EROFS verity
  image; optional defense-in-depth is a dm-table read-back of the effective root hash.

### FR-4D — Verified guest-pull images (image manifest-digest authorization)
- **Gap:** in the confidential guest-pull path the agent asks the Confidential Data Hub (CDH)
  to pull and unpack a container image referenced by the (untrusted) host. The registry/CDH
  verify that the pulled content matches the referenced digest, but nothing in the guest
  checked that the *reference* resolves to a digest the tenant approved — so a host could
  point the workload at a different (self-consistent) image, or use a mutable tag.
- **Fix:** a **measured allowlist** of authorized image manifest digests
  (`/etc/kata/verified-images.toml`, seeded at boot like the other measured trust roots) plus
  a **fail-closed authorization gate** that runs *before* the pull
  (`image_pull_handler.rs` → `VerifiedImageStore::verify`). Fail-closed: when verification is
  required, the reference must be pinned by digest (`name@alg:hex`, else `UnpinnedImage`), the
  allowlist must be non-empty (else `NoApprovedImages`), and the digest must be present (else
  `UnauthorizedImage`). Digests are normalized (`algorithm:hex`, lower-cased).
- **Guarantee:** a guest-pull image is fetched only if it is pinned to a manifest digest the
  tenant measured/approved — the registry/CDH prove *content ↔ digest* (pull-by-digest), this
  gate proves *digest ∈ approved set*, so the host cannot substitute a different image or a
  mutable tag.
- **Commits:** `3f21b647a`, `655671b39` (store + gate + measured-config seed; PR #9).
- **Validated:** 6 unit tests (`verified_images` — authorized/unauthorized, unpinned rejected,
  empty-allowlist fail-closed, normalized/algorithm-bound, multi-image); agent builds strict
  clean; SRM crate 109 tests.
- **Follow-up:** live validation needs a guest-pull-enabled (CDH) agent + pod.

### FR-14 — Network phase binding
- **Gap:** a host that can add a route, rewrite iptables, or spoof ARP *after* the workload
  starts can exfiltrate or redirect traffic.
- **Fix:** a phase machine (`Boot → SandboxSetup → WorkloadRunning → Locked`) permits
  network-mutating RPCs only during sandbox setup and freezes them once the workload runs;
  a route allowlist further constrains programmed destinations.
- **Guarantee:** post-start network mutation is refused.
- **Commits:** `44d6f9d04` (phase machine), `8cf9c5785` (wiring).
- **Validated:** unit tests + **live attack** — `UpdateRoutes` on a running pod is denied
  (`FrozenPhase`); matrix no-regression (network config during sandbox setup is unaffected).

### FR-7 (remainder) — Strict runtime surface
- **Gap:** the interactive debug console and guest diagnostics are un-mediated
  guest-access / data-exfiltration surfaces.
- **Fix:** strict builds never launch the debug console (regardless of host config) and
  refuse `GetDiagnosticData`; the guest advertises `no-debug-console` and
  `no-guest-diagnostics`.
- **Guarantee:** no un-mediated shell or diagnostic dump in a strict guest.
- **Commit:** `8cf9c5785`.
- **Validated:** **live** — features advertised; `GetDiagnosticData` denied in strict.

---

## Stage 6 — Formal proof + auditability

### FR-15 — Formal model, fault injection, and the equivalence-claim proof
- **Goal:** prove that no reachable state of the monitor is permissive or phantom — the
  equivalence claim underpinning PARMA-style reasoning.
- **Fix:**
  - a **TLA+ model** (`src/agent/security-reference-monitor/formal/SRM.tla`) of the
    two-phase lifecycle + quarantine, model-checked by TLC over all reachable states:
    version equals committed count (no phantom/missed commit), `Commit` is enabled only from
    `executed` (authorized == executed), committed/aborted are terminal & exclusive, and
    quarantine is sticky;
  - **fault-injection + fuzz** tests
    (`src/agent/security-reference-monitor/tests/fault_injection.rs`): a fault injected at
    every phase and reconciled as the agent does never leaves an operation committed or
    advances the version; a deterministic 200-seed fuzz checks the invariants after every
    step;
  - an **aggregate negative-test runner** that runs the policy matrix and the FR-9/FR-10/
    FR-14 live attacks (plus the unit/fault tests and the model check) as one gate.
- **Guarantee:** the lifecycle safety properties hold under all interleavings and injected
  faults; the negative-test matrix is the reproducible equivalence-claim proof.
- **Commits:** `21ac6e048` (fault/fuzz), `e76bc8d81` (TLA+ model).
- **Validated:** TLC — *no error* over 250 states; fault/fuzz tests pass; aggregate runner
  green.

### FR-8 — Structured, rule-attributable decision objects
- **Gap:** denials must be auditable without leaking workload data.
- **Fix:** on denial the policy emits a `DecisionObject` recording the endpoint, the
  decision, the denied Rego rule (query path), and the **names** of the request's top-level
  fields — never their values.
- **Guarantee:** denials are rule-attributable and carry no environment values, sealed
  secrets, or policy text.
- **Commit:** `a59f5e74f`.
- **Validated:** unit tests for attribution and the no-secret-leakage guarantee.

---

## Scope relative to the upstream baseline

This branch targets the **upstream** Kata base it forks from. Some deployments already
harden a subset of these areas through build configuration or product-layer mechanisms; to
keep the guarantees explicit and portable, the features below are classified by how they
relate to the upstream baseline. All remain valid on an unmodified upstream base; on a
pre-hardened deployment a few are parity or additional defense-in-depth.

- **Baseline-independent invariants (novel relative to the upstream default):**
  - **FR-2** — the upstream rootfs default policy is fail-open (`allow-all.rego`). A
    deny-all-except-`SetPolicy` policy file exists in-tree but is not the default. This
    branch compiles the **closed-door default into the strict agent binary** so it does not
    depend on build-time policy-file selection, and it **compiles out** the
    `AllowRequestsFailingPolicy` escape hatch entirely. This is a stronger, build-independent
    form of the closed-door posture.

- **Defense-in-depth (the base capability may already exist; these add assurance):**
  - **FR-5 (effective-mode scratch verification)** — encrypted ephemeral storage already
    exists when requested via storage driver options; this branch additionally verifies the
    **effective** device-mapper stack (so a plaintext effective mount is refused even when
    encryption was requested) and enforces a mandatory-encryption invariant.
  - **FR-3 (create-spec canonical binding)** — because policy evaluation, the in-guest
    transformers, and execution all run inside a **single trusted agent process** sourcing
    trusted guest state, byte-identity between the authorized and executed OCI object is not
    required for the security property. This branch therefore **only records/audits** the
    authorized→executed digest relationship (it does not reorder transformers or enforce
    byte-identity). The **effective-signal** and **exec-environment** pre-authorization
    resolution (also under FR-3) are independent integrity improvements and are enforced.
  - **FR-4B (mount TOCTOU handle binding)** — a defensive re-verification of the mount
    destination's identity; closes a check-to-use window rather than a demonstrated exploit.

- **Confirmed structural gaps closed here (independent of any product-layer hardening):**
  FR-4A (ordered/bijective resource graph), FR-9 (occurrence/cardinality), FR-1 (signed
  policy fragments), FR-6 (transactional rollback of authorization state), FR-7 (total-mediation
  manifest + gating the always-allowed lifecycle RPCs), FR-11 (trusted CDI/device
  resolution), FR-14 (network phase binding + route allowlist), FR-10 (CopyFile content),
  and FR-8/FR-15 (auditability + the model-checked equivalence proof). These are not
  addressed by image-integrity or default-posture hardening alone.

---

## Post-baseline hardening — fragment distribution, transparency interop & endpoint breadth

The items below were merged **after** the initial feature baseline, as reviewable pull
requests (fork PRs #2–#9). They extend the FR-1 fragment surface (signature breadth,
external transparency interop, and the full declare→publish→pull→verify→inject lifecycle),
close the guest-pull image gap (FR-4D, above), and broaden per-endpoint enforcement. Each is
build- and unit-test-validated; items whose *live* validation needs a node / registry /
external ledger are flagged and tracked in `docs/cc/backlog.md`.

### Multi-algorithm signature breadth (FR-1d / FR-1f) — PR #3
- **What:** a shared multi-algorithm verifier (`security-reference-monitor/src/cose_keys.rs`)
  covering **Ed25519 (EdDSA), ECDSA P-256 (ES256) / P-384 (ES384), and RSA (PS256 / RS256)**,
  wired into did:x509 leaf + chain verification (`did_x509.rs`) and the transparency
  receipt / signed-tree-head path (`fragments.rs`). Algorithm selection is dispatched on the
  COSE `alg` / certificate OID — no downgrade.
- **Why:** parity with (and beyond) the reference confidential runtime, which verifies the
  RSA/ES256/ES384/EdDSA set; the baseline did Ed25519 + ES256 only.
- **Commits:** `0ac3af0c2`, `10a0ec277`.

### External SCITT / CCF transparency receipts (FR-1f Stage 2) — PR #5
- **What:** verification of **SCITT CCF-profile inclusion proofs**
  (draft-ietf-scitt-receipts-ccf-profile) from a real external ledger, in addition to the
  native RFC 6962 `kata-ttl-proof/v1`. New module
  `security-reference-monitor/src/ccf.rs` decodes the CBOR `ccf-inclusion-proof`, recomputes
  the Merkle root using plain SHA-256 concatenation (CCF has **no** RFC 6962 `0x00`/`0x01`
  domain-separation prefixes), and returns the leaf `data-hash`. A new `kata-ccf-proof/v1`
  receipt variant in the fragment gate requires `data-hash == SHA-256(statement)` and
  verifies the ledger's COSE signature over the recomputed root against a trust-list key
  (multi-alg, per PR #3).
- **Guarantee:** a fragment can be required to be anchored in an external transparency ledger
  (e.g. Azure Confidential Ledger / a CCF-based SCITT service); cross-fragment append-only
  ordering remains governed by FR-1j `prev_log_head`.
- **Commits:** `763a54cf5`. *(Live SCITT/CCF endpoint e2e is deployment-time — no guest egress
  in the test bed.)*

### genpolicy-native fragment declaration & composition (FR-1c) — PR #6
- **What:** the measured base policy can **declare** trusted fragments and **compose**
  fragment-contributed containers at policy-generation time: a `fragments[]` settings block
  plus `fragment_containers` / `all_policy_containers` composition in genpolicy's `rules.rego`
  / `policy.rs`. Inert (no behavioural change) when no fragments are declared.
- **Why:** fragments become operable/attested from the measured base policy, not only pushed
  at runtime.
- **Commits:** `e3e203876`.

### Boot-time OCI pull → SRM-verify → inject (FR-1 delivery) — PR #7
- **What:** at boot, for every fragment the measured base policy declares
  (`data.agent_policy.policy_fragments[]`, read via `AgentPolicy::fragment_specs()`), the guest
  pulls the COSE_Sign1(rego) OCI artifact (layer `application/cose-x509+rego`, artifactType
  `application/x-ms-ccepolicy-frag`), reconstructs the fragment from the signed payload
  (`PolicyFragment::from_cose_payload` / `from_cose_envelope`), and runs it through the **same**
  SRM `FragmentStore` verify→apply→commit path as the runtime `LoadPolicyFragment` push
  (`agent/src/policy_fragments.rs`). FR-1d (did:x509) / FR-1f (receipts) / FR-1i (rollback
  floor) / FR-1j (ordering) therefore all apply to OCI-delivered fragments too; both delivery
  paths share one monotonic ordering chain. did:x509 routing has no permissive fallback.
- **Fail-closed:** wired into `start_sandbox()` after the initdata base policy is set and the
  fragment trust root is seeded, before the ttRPC server serves any request; any
  fetch/verify/inject failure **aborts the VM** (strict builds only). Adds `oci-client` under
  the `agent-policy` feature.
- **Commits:** `09c7421ae`. *(Live dev-registry wire tests are deployment-time.)*

### OCI packaging/push + settings emission — `genpolicy-fragmentgen` — PR #8
- **What:** a new workspace tool (`src/tools/genpolicy-fragmentgen`) that packages an
  already-signed COSE fragment envelope as an OCI artifact (matching the guest fetcher's
  artifactType / layer / empty-config media types), optionally pushes it (`--push`), and emits
  the base-policy `data.agent_policy.policy_fragments[]` declaration entry. Issuer/feed/SVN are
  derived from the envelope via the guest's own `PolicyFragment::from_cose_envelope`, so the
  emitted entry matches exactly what the guest verifies — the tool reuses the existing signer
  and adds **no** duplicate crypto/format code.
- **Commits:** `391bbacaf`. *(Live registry push is deployment-time; verified offline
  end-to-end: sign → package → matching settings entry.)*

### Fine-grained per-container endpoint gating (FR-7 breadth) — PRs #2, #4
- **What:** every per-container agent endpoint is gated on **authorized container state**
  (fail-closed for unknown/removed `container_id`): `SignalProcessRequest` (plus an
  `allowed_signals` allowlist), `StartContainerRequest`, `WaitProcessRequest`,
  `StatsContainerRequest`, `TtyWinResizeRequest`, and `RemoveContainerRequest` (removal is now
  idempotent — a second remove is denied). The remaining unconditional endpoints
  (`DestroySandboxRequest`, `GetOOMEventRequest`, `GuestDetailsRequest`, `OnlineCPUMemRequest`,
  `RemoveStaleVirtiofsShareMountsRequest`) are an audited host-driven sandbox-lifecycle /
  read-only infrastructure set with a documented reviewed-allow rationale in `rules.rego`
  (no attacker-constrainable payload); the diagnostics surface the reference runtime gates is
  hard-disabled in the strict build.
- **Commits:** `2a6c1c3ae`, `c806264bf`, `109317082`, `54a652dd0`.

### Measured-initdata trust roots (FR-1i / FR-4C / FR-4D provenance) — PR #10
- **What:** the SRM trust roots — the policy-fragment issuer config (`fragment-issuers.toml`),
  the verified read-only-layer dm-verity allowlist (`verified-layers.toml`), and the verified
  guest-pull image-digest allowlist (`verified-images.toml`) — can now be carried in the
  **measured initdata section** as well-known keys, instead of relying only on files in the
  measured rootfs. Each is resolved with provenance precedence: the attestation-bound initdata
  section first, else the measured-rootfs file (a shared `resolve_measured_config` helper logs
  the chosen source). Seeding runs after initdata is parsed and before the ttRPC server / the
  boot fragment pull; fail-closed semantics are unchanged (absent config ⇒ no authorized
  issuer/layer/image).
- **Guarantee:** the fragment/layer/image trust roots are bound to the **initdata digest**,
  which is part of the TEE-attested launch measurement — so a host cannot alter the trust root
  without changing the attestation. The runtime-advancing FR-1i SVN high-water / FR-1j ordering
  state stays on sealed encrypted-scratch (mutable + monotonic by construction); only the
  immutable initial trust config is bound into the measured section.
- **Delivered by:** PR #10 (branch `bl5-initdata-measured`).

### Complete OCI Process field coverage in genpolicy (FR-16) — this PR
- **What:** the generated policy matches an incoming `CreateContainerRequest` field-by-field,
  so any OCI `Process` field the policy does not reference was previously accepted with any
  value. This closes that gap for the security-relevant fields the host forwards from the
  CRI/kubelet:
  - **`workingDir` (Cwd):** genpolicy previously derived `Cwd` only from the container image's
    `WorkingDir` and ignored the Kubernetes `container.workingDir` override — both a coverage
    gap (the host could set any `Cwd` for images without a `WorkingDir`) and a latent
    false-deny (a pod that legitimately set `workingDir` was rejected). genpolicy now models
    `container.workingDir` and the policy exact-matches it.
  - **apparmor profile:** the pod-pinned `securityContext.appArmorProfile` is modeled
    (`Localhost` → the profile name, `Unconfined` → empty) and exact-matched, at both pod and
    container scope (container overrides pod). When the pod pins no profile the value is left
    unconstrained, because the profile emitted for the `RuntimeDefault` case depends on whether
    apparmor is enabled on the host, which is not derivable from the pod spec; operators who
    run a fixed runtime-default profile can pin it cluster-wide via the
    `common.default_apparmor_profile` genpolicy setting.
  - **rlimits:** modeled and exact-matched (as a set) against the policy value (default: none),
    with a `common.default_rlimits` setting for environments that inject default rlimits.
- **Coverage CI gate:** a build-time test enumerates the agent's on-wire OCI `Process`/`User`
  fields (from `src/libs/protocols/protos/oci.proto`) and fails when a new field is neither
  enforced by `rules.rego` nor explicitly classified as reviewed-unenforced with a rationale,
  so future OCI fields cannot silently escape mediation. A companion test locks in that the
  agent `oci.proto` `User` carries no `umask` and `Linux` carries no `personality` field.
- **Guarantee:** a compromised host cannot silently weaken a container's working directory,
  mandatory-access-control (apparmor) profile, or resource limits when it forwards a
  `CreateContainerRequest` — each is exact-matched against the value the policy generator
  derived from the authorized pod spec; and the coverage gate prevents new OCI `Process`/`User`
  fields from being added without a policy-coverage decision.
- **Deliberately not enforced:** `OOMScoreAdj` is on the wire but kubelet computes it from the
  pod QoS class and node memory, so it is environment-derived and not predictable at
  policy-generation time; it only affects OOM-kill ordering and is not a sandbox-integrity
  boundary. `umask` (OCI `User`) and `personality` (OCI `Linux`) are not part of the agent's
  `oci.proto`, so they cannot reach the guest via `CreateContainerRequest` and need no policy
  coverage (the coverage gate enforces this assumption).
- **Validation:** genpolicy unit + integration tests, including a `createcontainer/fr16`
  GOOD/BAD matrix (matching request accepted; host-overridden `workingDir`, swapped/disabled
  apparmor profile, and injected rlimit each rejected) and the `oci_field_coverage` gate.

---

## Deferred / out of scope


- **FR-13 (snapshot/restore/migration sealing) — not applicable.** Snapshot, restore, and
  live-migration are not possible for GPU-passthrough (VFIO) confidential workloads at the
  hypervisor/device layer, so there is no state to securely restore. The strict guest should
  advertise these as unsupported and deny them; the anti-replay defenses that would back
  secure migration (monotonic SRM state version, occurrence generation) already exist and
  are model-checked. The sealing machinery itself is not built.
- **Hardware-gated items** requiring a real TEE (SNP/TDX) or real GPU attestation:
  verifier-bound claims and secret-release gating (part of FR-12), and real GPU
  CC-attestation evidence for FR-11. These cannot be exercised on a software-only bed.
- **FR-10 content-addressed artifact API** (`BeginArtifactInstall/…`) — an optional
  alternative to the "disable CopyFile" default that this branch ships; build it only if
  trusted host-delivered artifacts become a requirement.

---

## Validation at a glance

- **Unit / integration:** the SRM crate carries the transaction manager, occurrence
  registry, resource graph, CDI trust, fragment verifier, scratch classifier, handle
  binding, verified-layer allowlist, network-phase machine, and lifecycle
  fault-injection/fuzz tests, all green (109 SRM unit tests + 4 fault-injection).
- **Formal:** TLC model-checks the lifecycle safety properties with no error.
- **Live matrix:** the strict `kata-parma` profile passes the policy-enforcement matrix
  with no regression, and the FR-9/FR-10/FR-14 live ttRPC attacks are denied.
- **Mediation CI:** build-time tests keep the complete-mediation manifest in sync with the
  agent protocol.
