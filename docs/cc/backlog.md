# Execution-integrity backlog — remaining work

Everything in the feature baseline and the post-baseline hardening set is **merged** to
`coco-parity` and documented in `docs/cc/parma-hardening-features.md` (the single source of
truth for shipped features). This file tracks only what is **not yet complete**: open work
items and the merged features whose *live* end-to-end validation is deployment-time.

_For the full list of shipped items and their commits/PRs, see
`docs/cc/parma-hardening-features.md`._

## Open work items

**FR-16 — Complete OCI field-model coverage in genpolicy** _(P1, open)_

_Guarantee._ The policy models and enforces every security-relevant field of the container
OCI runtime spec and process, so a host cannot silently alter an unmodeled field to change
process behavior.

_Gap (in `genpolicy` today)._ `KataUser` (`src/tools/genpolicy/src/policy.rs`) models only
UID / GID / AdditionalGids / Username — **`process.user.umask` is not modeled**. `Cwd` is
populated **only** from the image config `WorkingDir` (`src/tools/genpolicy/src/registry.rs`),
so a Kubernetes pod-spec **`workingDir` override is never read into the policy**.
`KataProcess` / `KataLinux` do not model **`personality`** (e.g. forcing `LINUX32`),
**`rlimits`**, or **`apparmorProfile`**. A host can set any of these to a value the policy
neither pins nor rejects.

_Acceptance criteria._
1. Extend the `genpolicy` struct model + `rules.rego` to represent and match
   `process.user.umask`, `process.rlimits`, `personality`, and `apparmorProfile`; in strict
   mode, reject any input container whose spec sets a security-relevant field the policy does
   not model.
2. Read the Kubernetes container `workingDir` override into the policy `Cwd` (not only the
   image `WorkingDir`) and match it exactly.
3. Add a `genpolicy` field-completeness CI gate that fails when a new security-relevant OCI
   field is present in the agent `oci` spec but has no corresponding policy input (prevents
   silent model drift).
4. Negative tests: a non-default `umask` / `personality=LINUX32` / an extra `rlimit` / an
   `apparmorProfile` not in policy → **DENIED**; a `workingDir` not equal to the policy value
   → **DENIED**.

_Suggested location._ `src/tools/genpolicy/src/policy.rs` (`KataUser` / `KataProcess` /
`KataLinux` field additions), `src/tools/genpolicy/src/registry.rs` (`workingDir` override),
`src/tools/genpolicy/rules.rego` (`allow_user` / `allow_linux` matching), plus an agent
`oci`-spec cross-check. This is the same subtree as the fine-grained endpoint gating (PRs #2, #4).

---

All other planned execution-integrity work items (BL-1…BL-9) are merged to `coco-parity`.
BL-5 (bind measured state into initdata) landed in PR #10 (branch `bl5-initdata-measured`) — see
`parma-hardening-features.md` §"Measured-initdata trust roots". Besides FR-16, what remains is **live
validation** of already-merged features (below).

## Merged, but live end-to-end validation is deployment-time

These features are implemented, unit-tested, and build-clean on `coco-parity`; the remaining
validation needs a running node, an OCI registry, or a live external ledger — none of which
exist inside the confidential-guest test bed. They are **not** code gaps.

This work is now an **active workstream** (LV-1…LV-5) to produce a security-guarantees
**showcase** — each guarantee demonstrated with a GOOD (accepted) and BAD (rejected/aborted)
case. Items are sized so parallel agents can pick them up independently; dependencies are
noted. Legend: 🟢 host-feasible now · 🟠 needs a deployed strict agent / guest.

| ID | Live validation | Feasibility | Depends on |
|---|---|---|---|
| LV-0 | **Strict-agent test bed** — build the strict-policy agent + a runnable way to exercise the real SRM against live external artifacts (component-level live harnesses linking `kata-security-reference-monitor`, plus, for LV-2, a deployed guest). | 🟢 build now / 🟠 guest deploy | — |
| LV-1 | **FR-4C dm-verity verified layers** — build a real EROFS/ext4 + dm-verity hash tree (`veritysetup`/`losetup`), authorize the root digest via `verified-layers.toml`, show an approved digest accepted and a tampered/other digest rejected against a real dm-verity device. | 🟢 | LV-0 |
| LV-2 | **FR-4D CDH guest-pull verified images** — an allowlisted manifest digest pulls; an unlisted digest / mutable tag is denied, in a running Kata pod with a guest-pull (CDH) strict agent. | 🟠 | LV-0 |
| LV-3 | **FR-1f Stage-2 SCITT/CCF receipts** — a CCF-profile ledger (local CCF or Azure Confidential Ledger) emits a real `ccf-inclusion-proof` + COSE receipt; feed a `kata-ccf-proof/v1` receipt to the agent verifier: GOOD accepted, tampered rejected. | 🟢/🟠 | LV-0 |
| LV-4 | **BL-8/BL-9 boot OCI fragment pull + push** — local OCI registry (`registry:2`); sign with `sign-fragment`, package/push with `genpolicy-fragmentgen` (GOOD/badsvn/wrongiss/tampered), then boot-pull fetch + SRM-verify: GOOD injects, the rest are rejected. | 🟢 | LV-0 |
| LV-5 | **Security-guarantees showcase** — a single scripted demo + doc presenting each guarantee (GOOD-accepted / BAD-rejected), suitable to present. | 🟢 | LV-1…LV-4 |

**Test-bed host:** GB200 node `.6` (`gb200-bm-wxjifb`), `aarch64`, Ubuntu 6.8 kernel —
docker 28.3.2, `veritysetup`/`losetup`/`cryptsetup` present, passwordless `sudo`, and
admin kubectl via `kubectl-admin`. LV-1 and LV-4 are runnable on this host today; LV-2 needs
the strict agent deployed into a Kata guest; LV-3 needs a reachable CCF/SCITT endpoint.

## Deferred / out of scope

See `docs/cc/parma-hardening-features.md` §"Deferred / out of scope" for FR-13
(snapshot/restore/migration sealing — not applicable to GPU-passthrough CC), the
hardware-gated TEE/GPU-attestation items, and the optional FR-10 content-addressed
artifact API.
