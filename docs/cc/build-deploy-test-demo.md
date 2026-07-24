# Build → Deploy → Test → Demo (developer runbook)

A self-contained guide to build, test, deploy, and demonstrate the execution-integrity
hardening on this branch (`coco-parity`) — for **new** features (FR-1 fragments incl. did:x509,
transparency receipts/SCITT-CCF, append-only ordering; FR-4C/4D verified layers/images;
BL-8/9 boot-time OCI fragment pull/push; measured-initdata trust roots) and **existing** ones.

Companion docs: `docs/cc/parma-hardening-features.md` (feature → commit map, the source of
truth), `docs/cc/fr1-fragments.md` (FR-1 reference), `docs/cc/backlog.md` (status).

## What you can do without a cluster vs. with one

| Level | Needs | Proves |
|---|---|---|
| **A. Unit tests** | a build host (Docker or a Rust musl toolchain) | every FR/BL gate, hermetically |
| **B. Offline demos** | same as A | the real gate code accepting good / rejecting bad input, no VM/cluster |
| **C. Deploy** | a Kata-capable node (+ containerd/k8s) | a strict confidential guest running the built agent |
| **D. Live pod demos** | C + a way to drive the guest (kubectl + a ttRPC client) | the guarantees enforced end-to-end inside a real guest |

Levels **A and B run anywhere** and already exercise both new and existing features. C and D
need a Kata deployment and are environment-specific (an operator's ops repo typically wraps
them; the generic recipe is in §D).

---

## 0. Prerequisites

- **Docker** (the Kata build system runs builds in pinned builder images) *or* a local Rust
  toolchain with the `aarch64-unknown-linux-musl` target (`rustup target add
  aarch64-unknown-linux-musl`). Examples below use the aarch64 musl target; substitute your
  arch triple as needed.
- For **C/D**: a node with Kata Containers installed (containerd runtime handler + a Kata
  RuntimeClass), `kubectl`, and root on the node.
- Behind a corporate proxy? Add `-e http_proxy=… -e https_proxy=…` to the `docker run`
  commands and `CARGO_NET_RETRY=20` (crates.io fetches can be slow); retry transient
  `spurious network error` failures.

Set once for the examples below:

```bash
KATA_SRC=$(git rev-parse --show-toplevel)          # this repo
TGT=aarch64-unknown-linux-musl
# A pinned Kata builder image (has the Rust musl toolchain). Any recent
# quay.io/kata-containers/builders:agent-*-aarch64 tag works; `make` (§C) auto-selects one.
BUILDER=quay.io/kata-containers/builders:agent-3840e64e3-0a538d111-1.95-aarch64
runc() { docker run --rm -v "$KATA_SRC:$KATA_SRC" -w "$KATA_SRC" "$BUILDER" bash -c "$*"; }
```

---

## 1. Build & Test (anywhere — no cluster) — VERIFIED

### 1a. Run the unit tests (covers every feature)

```bash
runc "cargo test -p kata-security-reference-monitor -p kata-agent-policy --target $TGT"
```

Expected (current branch): **109 `kata-security-reference-monitor` tests + 7
`kata-agent-policy` tests, all `ok`**. The SRM crate holds every gate (fragments, did:x509,
transparency/CCF, Merkle, ordering, verified layers, verified images, occurrence, resource
graph, network phase, transaction manager) so this is the fastest full-feature check.

### 1b. Compile the strict agent (the confidential build)

All strict hardening is behind the `strict-policy` cargo feature; a normal build is
behaviourally unchanged.

```bash
runc "cargo build -p kata-agent --no-default-features --features strict-policy --target $TGT"
```

### 1c. Build the in-tree demo/dev tools

```bash
runc "cargo build --release --target $TGT -p kata-security-reference-monitor \
  --example sign-fragment --example verify-layer --example verify-image \
  --example mock-ledger --example fragment-demo"
runc "cargo build --release --target $TGT -p genpolicy-fragmentgen"
```

Binaries land under `target/$TGT/release/` (`examples/…` for the SRM examples).

---

## 2. Offline demos (anywhere — no cluster) — VERIFIED

These run the **real gate code** against real inputs, with no VM/cluster. They are the fastest
way for a dev to see each guarantee accept a GOOD input and reject a BAD one.

### 2a. FR-1 fragments end-to-end, self-contained

```bash
target/$TGT/release/examples/fragment-demo
```

One binary exercises: signed fragments, transparency **trust list + key rotation**, **did:x509**
chain/revocation/rotation, **FR-1j append-only ordering** (in-order accept, out-of-order
reject, exportable non-repudiable log), and **FR-1f Stage 2** transparency-log inclusion +
consistency (forged/rewound rejected). Ends with `All FR-1 fragment capabilities verified.`

### 2b. FR-4C verified read-only layers (real dm-verity)

Needs `veritysetup`/`losetup` + root (Linux host):

```bash
dd if=/dev/urandom of=/tmp/layer.data bs=1M count=8 status=none
ROOT=$(sudo veritysetup format /tmp/layer.data /tmp/layer.hash | awk '/Root hash:/{print $3}')
VL=target/$TGT/release/examples/verify-layer
$VL --algorithm sha256 --require true --authorize "$ROOT" --root-hash "$ROOT"   # AUTHORIZED (exit 0)
$VL --algorithm sha256 --require true --authorize "$ROOT" --root-hash "$(echo $ROOT | sed s/^../00/)"  # REJECTED (exit 1)
$VL --algorithm sha256 --require true --root-hash "$ROOT"                        # REJECTED: empty allowlist (fail-closed)
```

`verify-layer` calls the exact `VerifiedLayerStore::verify` the agent uses before creating a
dm-verity device.

### 2c. FR-4D verified guest-pull images

`verify-image` calls the exact `VerifiedImageStore::verify`. Use a **full 64-hex** digest
(short/tag-only refs are rejected as unpinned):

```bash
VI=target/$TGT/release/examples/verify-image
D=sha256:$(printf 'a%.0s' {1..64})
$VI --require true --authorize "$D" --image-ref "reg/img@$D"     # AUTHORIZED
$VI --require true --authorize "$D" --image-ref "reg/img@sha256:$(printf 'b%.0s' {1..64})"  # REJECTED (unlisted)
$VI --require true --image-ref "reg/img:1"                       # REJECTED (unpinned/tag-only)
```

### 2d. Sign + package/publish a fragment (BL-9)

```bash
S=target/$TGT/release/examples/sign-fragment
G=target/$TGT/release/genpolicy-fragmentgen
KEY=$($S gen-key | awk -F= '/private_key_hex/{print $2}')
printf 'package agent_policy.fragments\nsvn := 3\nexec_allowed := true\n' > /tmp/frag.rego
$S sign --issuer did:x509:0:sha256:AAA::CN:signer --feed localhost:5000/frag/infra:1 --svn 3 \
   --includes exec --module /tmp/frag.rego --key "$KEY" --cose | awk -F= '/cose_sign1_hex/{print $2}' > /tmp/frag.cose.hex
$G --cose /tmp/frag.cose.hex                       # emit the base-policy policy_fragments[] entry (offline)
# with a registry:  $G --cose /tmp/frag.cose.hex --push localhost:5000/frag/infra:1 --plain-http
```

### 2e. Produce an external SCITT / CCF-profile receipt (BL-6)

```bash
L=target/$TGT/release/examples/mock-ledger
LKEY=$($S gen-key | awk -F= '/private_key_hex/{print $2}')
$S sign --issuer issuerA --svn 1 --includes exec --module /tmp/frag.rego --key "$KEY" --emit-statement /tmp/a.stmt >/dev/null
$L prove-ccf --key "$LKEY" --leaf /tmp/a.stmt              # emits a kata-ccf-proof/v1 receipt
$L prove-ccf --key "$LKEY" --leaf /tmp/a.stmt --tamper     # a receipt the guest MUST reject
```

`mock-ledger` stands in for a real transparency ledger (Azure Confidential Ledger / a CCF or
RFC 6962 log). It defines the exact receipt wire format the guest verifies.

---

## 3. Deploy the strict runtime (needs a Kata node)

The confidential behaviour lives in the guest **agent**, compiled with `STRICT_POLICY=yes`
(default is `no`). Build the deployable Kata artifacts with the kata-deploy make targets (they
run in the pinned builder image automatically):

```bash
cd tools/packaging/kata-deploy/local-build
STRICT_POLICY=yes AGENT_POLICY=yes make agent-tarball rootfs-image-tarball genpolicy-tarball
# → build/kata-static-{agent,rootfs-image,genpolicy}.tar.zst
```

Verify the strict agent is in the artifact (the guest rootfs embeds it):

```bash
tar --zstd -xOf build/kata-static-rootfs-image.tar.zst 2>/dev/null | strings \
  | grep -m1 "boot fragment pull failed, aborting VM"   # BL-8 string present ⇒ strict build
```

Install onto the node and register a strict RuntimeClass (**environment-specific** — adapt
paths/handler to your Kata install):

```bash
for c in agent rootfs-image genpolicy; do sudo tar --zstd -xf build/kata-static-$c.tar.zst -C /; done
# Register a RuntimeClass (e.g. `kata-parma`) whose containerd handler points at your strict
# Kata config, then deploy pods with runtimeClassName: <that class>.
```

> Some environments need extra config (direct-kernel-boot firmware, enabling the `policy`
> annotation). Those are deployment-specific; an operator ops repo typically scripts the
> install + RuntimeClass + config in one wrapper.

---

## 4. Live pod demos (needs §3) — the guarantees enforced inside a real guest

Two knobs make a strict guest testable:

1. **Measured trust roots** — the guest reads `/etc/kata/fragment-issuers.toml`,
   `/etc/kata/verified-layers.toml`, `/etc/kata/verified-images.toml` from measured state (or,
   per BL-5, from the initdata measured section). Provide the authorized issuer/ledger keys and
   allowlists there.
2. **Fragment delivery** — either **runtime push** (`kata-agent-ctl` `LoadPolicyFragment` over
   the guest's vsock) or **boot-time OCI pull** (BL-8; the base policy declares
   `policy_fragments[]`).

Generic recipe (adapt injection to your image/deploy mechanism):

```bash
# a) put the measured config + (optionally) the freshly built agent into the guest rootfs image
# b) deploy a pod with runtimeClassName: <strict class> and a base policy annotation
# c) drive it:
kata-agent-ctl connect --server-address vsock://<GUEST_CID>:1024 \
  -c "LoadPolicyFragment issuer=issuerA svn=1 includes=exec module=/path/frag.rego sig=<hex> \
      receipt_ledger=acl proof=</path/receipt-file>"
```

GOOD/BAD cases to demonstrate (all shown live in the operator harnesses):
- **FR-1**: signed fragment flips a denied exec to allowed; a wrong-key fragment is rejected.
- **FR-1f / BL-6**: a fragment with a valid `kata-ccf-proof/v1` receipt is accepted; tampered
  or missing (when required) is rejected.
- **BL-8**: a pod whose measured base policy **requires an unfetchable fragment** fails to boot
  — the agent aborts the VM in `start_sandbox()` (pod stuck `ContainerCreating`,
  `timed out connecting to vsock`); a control pod without the declaration boots.

> A turnkey set of these live proofs (rootfs injection + pod deploy + a scoreboard
> `showcase.sh`) is maintained in the operator's environment repo; this section is the generic
> equivalent so anyone with a strict Kata deployment can reproduce them.

---

## 5. Feature → how to exercise it

| Feature | Unit test (`§1a`) | Offline demo (`§2`) | Live (`§4`) |
|---|---|---|---|
| FR-1 signed fragments | ✅ `fragments::` | `fragment-demo` | LoadPolicyFragment |
| FR-1d did:x509 identity | ✅ `did_x509::` | `fragment-demo` | did:x509 fragment |
| FR-1f transparency receipts (Stage 1/2) | ✅ `fragments::`, `merkle::` | `fragment-demo` | `mock-ledger prove` + push |
| FR-1f / **BL-6** SCITT/CCF receipts | ✅ `ccf::` | `mock-ledger prove-ccf` | CCF `receipt_proof` |
| FR-1j append-only ordering | ✅ `fragments::` | `fragment-demo` | ordered fragments |
| **BL-2** multi-alg signatures | ✅ `cose_keys::` | — | — |
| **FR-4C** verified dm-verity layers | ✅ `verified_layers::` | `verify-layer` + real `veritysetup` | verity mount |
| **FR-4D** verified guest-pull images | ✅ `verified_images::` | `verify-image` | CDH guest-pull |
| **BL-8** boot-time OCI fragment pull | ✅ policy `fragment_specs` | — | fail-closed boot |
| **BL-9** OCI packaging/push | — | `genpolicy-fragmentgen` | push + boot-pull |
| **BL-5** measured-initdata trust roots | ✅ `initdata::` | — | initdata keys |

---

## 6. Gotchas (learned the hard way)

- **`STRICT_POLICY` defaults to `no`.** You must pass `STRICT_POLICY=yes AGENT_POLICY=yes` to
  the make targets, or the deployed agent won't contain the strict gates.
- **Strict boot policy source.** A strict agent loads the compiled-in closed-door baseline when
  `policy_file` is empty; the runtime `policy` annotation arrives *after* boot via
  `SetPolicyRequest`. So **BL-8 boot-pull only sees `policy_fragments[]` from the boot policy** —
  point the agent at a measured base policy (`KATA_AGENT_POLICY_FILE`) or deliver it via
  initdata.
- **Plain-HTTP registries.** The boot-pull fetcher allows plain HTTP only for
  `localhost`/loopback; any other registry must be HTTPS with a guest-trusted CA.
- **`verify-image` digests** must be well-formed `alg:hex` (sha256=64, sha384=96, sha512=128
  hex chars); anything else is treated as unpinned and rejected.
- **Transient crates.io fetch timeouts** in the builder image — set `CARGO_NET_RETRY=20` and
  retry.
