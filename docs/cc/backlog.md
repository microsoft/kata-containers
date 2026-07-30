# Execution-integrity backlog — remaining work

Everything in the feature baseline and the post-baseline hardening set is **merged** to
`coco-parity` and documented in `docs/cc/parma-hardening-features.md` (the single source of
truth for shipped features). This file tracks only what is **not yet complete**: open work
items and the merged features whose *live* end-to-end validation is deployment-time.

_For the full list of shipped items and their commits/PRs, see
`docs/cc/parma-hardening-features.md`._

## Open work items

FR-16 (complete OCI Process field coverage in genpolicy — `workingDir`/apparmor/rlimits
exact-match plus an on-wire OCI field-coverage CI gate) is **delivered in this PR**; see
`parma-hardening-features.md` §"Complete OCI Process field coverage in genpolicy (FR-16)".
All earlier execution-integrity work items (BL-1…BL-9) are merged to `coco-parity`.
BL-5 (bind measured state into initdata) landed in PR #10 (branch `bl5-initdata-measured`) — see
`parma-hardening-features.md` §"Measured-initdata trust roots". Besides FR-16, what remains is **live
validation** of already-merged features (below).

### Documentation completeness (DOC-1…DOC-3)

`parma-hardening-features.md` documents each feature as **Gap → Fix → Guarantee → Commits →
Validated**, which explains what each feature does but not the reasoning the set as a whole
rests on. Three additions would make the document self-justifying to a reader outside the
team, and would make over-claims harder to introduce.

| ID | Item | Why |
|---|---|---|
| DOC-1 | **Threat model section.** State the adversary (untrusted host and shim), the trust boundary, the assumptions inherited from the hardware TEE, and what is explicitly *not* defended (host-controlled scheduling and resource starvation, denial of service, side channels). | Every feature is currently justified against an unstated model, so "is this a gap?" has no written arbiter. This is the first thing an external reviewer needs. |
| DOC-2 | **Parity anchors.** For each feature, name the equivalent mechanism in the runhcs/OpenGCS confidential stack and state whether this branch matches it or deliberately differs, with the reason. | The design is a parity effort, but the comparison appears nowhere in the docs and only once in the code (`policy.rs` citing `WithMetadataRollback`). Recording it turns "we chose differently" into a reviewable decision instead of an apparent omission. |
| DOC-3 | **A `Limits` bullet per feature**, stating what the guarantee does *not* cover. | A **Guarantee** with no matching **Limits** is how a requirement's text drifts ahead of its implementation. FR-6 now carries one; the rest do not. |

### Reference-monitor correctness (RM-1…RM-5)

Open items in the FR-6 transaction machinery. RM-1 and RM-2 are the halves deliberately
left out of the transaction-lifecycle fix; RM-3…RM-5 are pre-existing.

| ID | Item | Why |
|---|---|---|
| RM-1 | **Serialize concurrent operations on the same id.** `prepare` now *refuses* a duplicate while one is in flight, but the SRM lock is still released before the runtime operation runs, so the refusal is a clean failure rather than serialization. runhcs takes a per-container `TryLock` for the duration. | Two concurrent requests for the same container id are host-triggerable. Failing cleanly is correct but returns an error for what may be a legitimate retry; holding the lock would let the second wait. |
| RM-2 | **Initiator-pinned idempotency key.** Replay protection for `SignalProcess` and `ExecProcess` is scoped to in-flight duplicates only, because their operation ids name repeatable events rather than unique objects, so their transactions retire on commit. A key chosen by the initiator (an attempt or sequence number) would make a post-commit retry distinguishable from a new operation. | This is the residual window in FR-6's anti-replay story. Needs a shim↔agent API change, which FR-6 scoped out. |
| RM-3 | **Route `commit` failures into quarantine.** ✅ Delivered — all four call sites now act on the result, as does the fourth `abort` site (`signal_process`) which had been discarding its own. | The abort path quarantined on unprovable state; the commit path did not. Asymmetric, and the commit path is the one that runs on success. |
| RM-6 | **Test the SRM integration, not just the crate.** The four `rpc.rs` call sites have no test coverage at all — every reference-monitor test is crate-level, and the rpc test module never touches `SRM`. | The crate is well tested and the defects keep being found in the wiring: F-19 (removal never wrapped), F-23 (replay cache misapplied), RM-3 (results discarded). Crate-level tests cannot see any of those. |
| RM-4 | **Injective operation ids.** Ids are built by concatenating host-controlled strings with unescaped separators: `{cid}`, `{cid}:{exec_id}`, `{cid}:{exec_id}:sig:{signal}`, `remove:{cid}`. A container named `remove:foo`, or an `exec_id` containing `:sig:`, collides with a different operation. Fix is a length-prefixed id builder applied at all four sites. | Every collision consequence is a state-machine confusion in the component whose job is proving authorized == executed. |
| RM-5 | **Bind the executed digest in the formal model.** `formal/SRM.tla` specifies `Prepare`/`Execute`/`Commit`/`Abort` but has no commit-failure action, does not bind `executed_digest` on `Execute`, and models `Quarantine` as unguarded. | The model is what caught the `prepare` clobber (`Prepare(o)` requires `state[o] \in {"none","aborted"}`). Extending it is cheaper than finding the next divergence by inspection. |

### Testing and CI

| ID | Item | Why |
|---|---|---|
| CI-1 | **Exercise the feature matrix in CI.** `cargo check`/`test` for `--features strict-policy` and `--features agent-policy` separately. | `rpc::tests::test_get_oom_event_no_deadlock` fails on `coco-parity` under `--features strict-policy` (the strict baseline policy defines no `GetOOMEventRequest` rule, so `eval_query` returns no results and the test unwraps). It fails *closed*, so it is not a security gap — but it went unnoticed, which means the strict configuration is not built or tested anywhere. That is the configuration the hardening work exists to protect. |
| CI-2 | **`cargo fmt --check` gate, crate-scoped.** Limit to `kata-agent`, `kata-security-reference-monitor`, `kata-agent-policy`, `genpolicy-fragmentgen`. | Upstream kata is not fmt-clean under this repo's pinned toolchain (files under `rustjail/` and `runtime-rs/`), so a repo-wide gate cannot pass. Scoping it to the crates this work owns makes it enforceable today. |
| CI-3 | **Run the TLA+ model in CI** (`formal/run-tlc.sh`). | The model already encodes properties the implementation had drifted from. It is only useful if it runs. |

### Feature coverage

| ID | Item | Why |
|---|---|---|
| BL-10 | **Extend SRM transaction coverage** beyond `CreateContainer`, `ExecProcess`, `SignalProcess`, and `RemoveContainer` to the remaining mutating RPCs in the complete-mediation manifest (`UpdateContainer`, `PauseContainer`/`ResumeContainer`, `StartContainer`, sandbox lifecycle, `SetIPTables`, `AddSwap`, …). | FR-6's intent is every mutating operation. The four covered today include both rules that mutate persisted policy state, so the rollback property is complete; the rest are policy-gated but not transactional. |

## Merged, but live end-to-end validation is deployment-time

These features are implemented, unit-tested, and build-clean on `coco-parity`; the remaining
validation needs a running node, an OCI registry, or a live external ledger — none of which
exist inside the confidential-guest test bed. They are **not** code gaps.

This work is now an **active workstream** (LV-1…LV-5) to produce a security-guarantees
**showcase** — each guarantee demonstrated with a GOOD (accepted) and BAD (rejected/aborted)
case. Items are sized so parallel agents can pick them up independently; dependencies are
noted. Legend: 🟢 host-feasible now · 🟠 needs a deployed strict agent / guest.

| ID | Live validation | Feasibility | Depends on | Status |
|---|---|---|---|---|
| LV-0 | **Strict-agent test bed** — build the strict-policy agent + a runnable way to exercise the real SRM against live external artifacts (component-level live harnesses linking `kata-security-reference-monitor`, plus, for LV-2, a deployed guest). | 🟢 build now / 🟠 guest deploy | — | ✅ done — strict rootfs (STRICT_POLICY=yes) redeployed to `/opt/kata` on `.6`; `fr1-fragment-attack.sh` 4/4 |
| LV-1 | **FR-4C dm-verity verified layers** — build a real EROFS/ext4 + dm-verity hash tree (`veritysetup`/`losetup`), authorize the root digest via `verified-layers.toml`, show an approved digest accepted and a tampered/other digest rejected against a real dm-verity device. | 🟢 | LV-0 | ✅ done — `fr4c-verity-demo.sh` 5/5 (real `veritysetup` hash; SRM gate accept/reject; kernel dm-verity catches a corrupted block). Tool: `examples/verify-layer`. |
| LV-2 | **FR-4D verified guest-pull images** — an allowlisted manifest digest pulls; an unlisted digest / mutable tag is denied. | 🟠 | LV-0 | ✅ done — `fr4d-guestpull-demo.sh` 4/4 against a real registry manifest digest (allowlisted ok; unlisted/unpinned/empty rejected). Tool: `examples/verify-image`. In-guest CDH snapshotter is deployment-time. |
| LV-3 | **FR-1f Stage-2 SCITT/CCF receipts** — feed a real `kata-ccf-proof/v1` receipt to the agent verifier: GOOD accepted, tampered rejected. | 🟢/🟠 | LV-0 | ✅ done — `fr1-ccf-attack.sh` 3/3 live on a real `kata-parma` pod (valid CCF accepted; tampered/missing rejected). Tool: `mock-ledger prove-ccf`. A real Azure Confidential Ledger emits the same format. |
| LV-4 | **BL-8/BL-9 boot OCI fragment pull + push** — fail-closed boot-pull (declared-but-unfetchable fragment → VM aborts) + `genpolicy-fragmentgen` push/consume round-trip against a real registry. | 🟢 | LV-0 | ✅ done — `bl8-bootpull-demo.sh` 2/2 (real pods), `bl9-oci-push-demo.sh` 4/4 (real `registry:2`). In-guest GOOD-path fetch (egress+TLS) is deployment-time; GOOD-inject covered by the ttRPC-push harness. |
| LV-5 | **Security-guarantees showcase** — a single scripted demo + doc presenting each guarantee (GOOD-accepted / BAD-rejected), suitable to present. | 🟢 | LV-1…LV-4 | ✅ done — `showcase.sh` runs all proofs: **6/6 suites, 22/22 checks PASS** on node `.6`. See the private `GB200_poc` `coco/showcase.md` + `coco/harness/`. |

**Test-bed host:** GB200 node `.6` (`gb200-bm-wxjifb`), `aarch64`, Ubuntu 6.8 kernel —
docker 28.3.2, `veritysetup`/`losetup`/`cryptsetup` present, passwordless `sudo`, and
admin kubectl via `kubectl-admin`. LV-1 and LV-4 are runnable on this host today; LV-2 needs
the strict agent deployed into a Kata guest; LV-3 needs a reachable CCF/SCITT endpoint.

## Deferred / out of scope

See `docs/cc/parma-hardening-features.md` §"Deferred / out of scope" for FR-13
(snapshot/restore/migration sealing — not applicable to GPU-passthrough CC), the
hardware-gated TEE/GPU-attestation items, and the optional FR-10 content-addressed
artifact API.
