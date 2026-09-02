# End-to-end reproduction on an Azure VM

Scripted reproduction of the confidential-containers end-to-end path used to
validate the hardened (`STRICT_POLICY`) guest stack, including the signed
policy-fragment flow.

Everything here is idempotent and resumable. Each stage records a marker under
`~/.coco-e2e`; a re-run skips completed stages. `E2E_FORCE=1` re-runs anyway.

Stages 01–08 have been run start to finish from an empty resource group. That
exercise is worth repeating after any substantial change: standing a second node
up beside a working one turned up seven defects in this suite, every one of them
hidden by state the original node had accumulated by hand.

## What each stage proves

| Stage | Proves |
| --- | --- |
| `01-provision-vm.sh` | An Azure VM on a confidential-capable host SKU exists and is reachable. The node itself is a plain VM, not a confidential one — see "the node is not a confidential VM" below. Run from your workstation. |
| `02-bootstrap-node.sh` | Toolchain, container engine, kubectl, Go, Rust and the repo checkout are present on the node. |
| `03-deploy-cluster.sh` | A kubeadm cluster with `kata-deploy` and the CoCo KBS is up and the runtime classes are registered. |
| `04-build-guest-stack.sh` | The hardened agent is built **and installed** into `/opt/kata`, the deployed guest image is byte-for-byte the one just built, the runtime is re-pinned to that image's dm-verity root hashes, and the runtime-rs shim is rebuilt and installed so host-side changes are under test too — asserted by the commit the shim reports. |
| `05-smoke-test.sh` | The pod that boots is provably the locally built guest (verity pin), and an undeclared `exec` is denied. Mediation is live. |
| `06-policy-fragment-e2e.sh` | FR-1 signed policy fragments: every verification invariant holds, and the OCI delivery artifact matches the contract the guest fetcher depends on. |
| `07-fragment-bootpull.sh` | BL-8 live delivery: the host fetches a declared fragment and pushes it in, the guest verifies and injects it on a running cluster, and a declaration left unsatisfied blocks container creation. |

`test-path-guard.sh` is not a stage. It is a six-case unit test of
`tarball_confined()` in `lib.sh` — the predicate stage 04 consults before
extracting a build artifact as root into `/`. It needs no VM and no cluster, only
`tar` and `zstd`, so run it anywhere the suite is edited:

```bash
bash docs/cc/e2e/test-path-guard.sh    # expects 6/6
```

The guard is deliberately defined once and shared: a test carrying its own
transcription of the predicate can keep passing after the real guard has been
weakened, and that divergence is invisible exactly when it matters. Two of the
six cases exist because the obvious implementations get them wrong — a tarball
whose members are listed by a `tar` that *failed* looks identical to a clean one,
and the rootfs tarball legitimately contains a symlink, so symlinks must be
judged by target rather than rejected by type.

## Quick start

```bash
# from your workstation
./01-provision-vm.sh                  # provisions, and adds the ssh alias
./sync.sh                             # copies the suite to the node

# on the node
ssh coco-e2e
export E2E_NIGHTLY_SHA=<sha>          # see "CI nightly artifact" below
cd ~/coco-e2e && ./run-all.sh
```

`sync.sh` can also drive stages remotely, forwarding the knobs that change what a
run means (`E2E_FAST`, `E2E_SKIP_BUILD`, `E2E_FORCE`, `E2E_BRANCH`, …):

```bash
E2E_FAST=1 ./sync.sh 04 05
```

Always use `sync.sh` rather than a bare `scp`: a Windows checkout carries no
executable bit and `scp` preserves that, so hand-copied scripts arrive
non-executable. `sync.sh` `chmod +x`s them on arrival.

Stage 02 adds you to the `docker` group. Group membership only applies to a new
login session, so if stage 02 warns about it, reconnect (`exit`, then `ssh
coco-e2e`) before running stage 04. Stage 04 re-execs itself under `sg docker`
when it can, so a single-session run usually still works.

`run-all.sh` skips stage 01 automatically when the Azure CLI is absent (i.e. on
the node). Force the decision with `E2E_SKIP_PROVISION=1` or `=0`.

Individual stages:

```bash
./run-all.sh 04 05 06
E2E_FORCE=1 ./run-all.sh 06
```

## Clean-room run from nothing

Follow this top to bottom for a fresh node. Steps 1–4 run on your workstation,
5 onwards on the node. The Quick start above is the terse version, for a node
that is already bootstrapped.

Two orderings here are not obvious and each costs a run if you get them wrong:
the CI-nightly artifact has to be staged **after** step 5 — stage 02 is what
creates the checkout it goes into — and **before** step 7; and the docker group
needs a fresh login in between.

**1. Workstation prerequisites.**

```bash
az login && az account set -s <subscription>
az --version && jq --version        # stage 01 checks both and fails fast
ls ~/.ssh/id_rsa.pub                # E2E_SSH_KEY — stage 01 uploads this
```

`jq` is not part of git-bash; install it separately. Note that `bash` on a
Windows PATH is often WSL, which keeps its own `~/.ssh/config` and so will not
resolve the `coco-e2e` alias — run the workstation-side scripts from git-bash.

**2. Check region and quota.** They are independent, and each alone is a false
green. See [Region and quota](#region-and-quota).

**3. Provision the node** (`01`). Defaults target `E2E_VM=coco-e2e-1` /
`E2E_SSH_HOST=coco-e2e`; override both together for a second, parallel node.

```bash
./01-provision-vm.sh                # or: E2E_VM=coco-e2e-2 E2E_SSH_HOST=coco-e2e-2 ./01-provision-vm.sh
```

Stage 01 appends an ssh alias when none exists and warns rather than rewriting
one that does. If you are reusing the name of a VM you deleted, delete the stale
alias first or you will connect to a dead address.

**4. Copy the suite.**

```bash
./sync.sh
```

Always `sync.sh`, never a bare `scp` — a Windows checkout carries no executable
bit and `scp` preserves that. `sync.sh` `chmod +x`s the scripts on arrival.

**5. Bootstrap the node** (`02`), then reconnect.

```bash
ssh coco-e2e
cd ~/coco-e2e && ./run-all.sh 02
exit && ssh coco-e2e                # docker group only applies to a new session
```

This is the step that clones the repo to `~/kata-containers` (`E2E_REPO_DIR`) at
`E2E_BRANCH`, so nothing before it can write into that tree.

**6. Stage the CI-nightly artifact.** Stage 03 needs
`kata-tools-static.tar.zst` in `$E2E_REPO_DIR/kata-tools-artifacts/`. The
*overall* nightly run is usually red — that is fine, only the build/publish jobs
matter.

The nightly belongs to **upstream `kata-containers/kata-containers`**, not to
this fork — `ci-nightly.yaml` does not exist here, so `gh` returns a 404 unless
you pass `-R`. That also means everything the tarball carries is upstream's,
including the genpolicy inputs; stage 03 restages `rules.rego` and
`genpolicy-settings.json` from your branch afterwards so the run exercises our
policy rather than upstream's.

`gh` is **not** among the packages stage 02 installs, so the simplest path is to
download on your workstation, where `gh` is already authenticated, and copy it
over:

```bash
# workstation
gh run list -R kata-containers/kata-containers --workflow ci-nightly.yaml -L 5 \
  --json databaseId,headSha,conclusion
gh run download <id> -R kata-containers/kata-containers \
  -n kata-tools-static-tarball-amd64-<sha>-nightly
ssh coco-e2e 'mkdir -p ~/kata-containers/kata-tools-artifacts'
scp kata-tools-static.tar.zst coco-e2e:~/kata-containers/kata-tools-artifacts/
```

Then, on the node, for every shell that runs stage 03:

```bash
export E2E_NIGHTLY_SHA=<sha>        # the same sha as the artifact
```

**7. Deploy the cluster** (`03`). Destructive: it redeploys `kata-deploy` over
whatever is on the node.

```bash
./run-all.sh 03
```

**8. Build and install the guest stack** (`04`). A clean build is **40–60
minutes**; that is normal, not a hang. Do not poll for it with `pgrep -f`.
Stage 04 refuses to run on a dirty tree, and fails unless the deployed image
hashes equal to the copy inside the tarball it just built.

```bash
./run-all.sh 04
```

**9. Prove it** (`05`, `06`, `07`).

```bash
./run-all.sh 05 06 07
```

Stage 05 passes only if the booted pod is provably the guest you just built (a
verity pin) and an undeclared `exec` is denied. Stage 06 asserts every
policy-fragment verification invariant and the OCI delivery contract. Stage 07
takes it onto the cluster: it declares a fragment in the base policy and lets the
guest do the fetching. A green `05`, `06` and `07` on a run that did **not** set
`E2E_FAST` is the end state.

Stage 07 always runs its control and its fail-closed negative. Its *good path*
needs a feed the guest can reach over TLS and pull anonymously — see
[Live fragment delivery (stage 07)](#live-fragment-delivery-stage-07).

**10. Clean up** — see [Cleanup](#cleanup). Deallocate the VM; leave the shared
VNET alone if other VMs in the resource group use it.

## Configuration

All settings live at the top of `lib.sh` and are environment-overridable.

| Variable | Default | Notes |
| --- | --- | --- |
| `E2E_PLATFORM` | `qemu-coco-dev` | Which hypervisor stack to validate. `clh-snp` and `openvmm-snp` select real SEV-SNP guests over MSHV — see "Platforms" below. |
| `E2E_RG` / `E2E_VM` | `coco-e2e-rg` / `coco-e2e-1` | Azure resource group and VM name. The suite creates the RG if it is absent, so leaving these at their defaults provisions a fresh, self-owned environment rather than reusing anyone else's. |
| `E2E_SSH_HOST` | `coco-e2e` | ssh alias the workstation-side helpers use. Override with `E2E_VM` for a parallel environment. |
| `E2E_FAST` | `0` | Dev-loop mode. Reduces assurance — see below. |
| `E2E_SKIP_BUILD` | `0` | Install the tarballs already in `build/` without rebuilding. |
| `E2E_REGION` | `eastus` | See the region trap below. |
| `E2E_VM_SIZE` | `Standard_DC16as_cc_v5` (`aks`: `Standard_DC8as_cc_v6`) | Confidential-capable **host** SKU (nested virt). The node itself is a normal VM. |
| `E2E_VM_SECURITY_TYPE` | `Standard` | See "The node is not a confidential VM" below. |
| `E2E_BRANCH` | `manifold-cc` | Branch under test. Defaults with `E2E_REPO_URL` to where this branch lives. |
| `E2E_REPO_URL` | `https://github.com/microsoft/kata-containers.git` | Fork the node clones. Override together with `E2E_BRANCH`. |
| `E2E_REPO_DIR` | `~/kata-containers` | Checkout on the node. |
| `E2E_STRICT_POLICY` | `yes` | Pulls in the security reference monitor. Set to `no` for a non-strict A/B leg — stage 04 asserts in whichever direction you ask for, so a non-strict build is verified too rather than silently accepted. Note that an operator `env.sh` must not `export` this unconditionally, or it will clobber a per-run override. |
| `E2E_NIGHTLY_SHA` | *(required for stage 03)* | CI-nightly commit sha. |
| `E2E_HANDLER_CONFIG` | *(auto)* | `aks` only. The `configuration.toml` the RuntimeClass's containerd handler resolves to. Stage 00c normally reads this from `ConfigPath`; set it when a handler declares none, because a handler whose config cannot be located cannot be tied to a payload and the stage refuses to guess. |
| `E2E_REGISTRY` | `localhost:5000` | Registry for the policy fragment. Loopback starts a throwaway `registry:2`. Overridden when `E2E_ACR` resolves. |
| `E2E_ACR` | *(empty)* | `auto` provisions/adopts an ACR so stage 07 exercises a real TLS pull; a name adopts that registry; empty stays on loopback, which now also works. |
| `E2E_ACR_RG` / `_SKU` | `$E2E_RG` / `Standard` | Where and how `ensure_acr` creates the registry. Anonymous pull needs Standard or better; Basic rejects it. |
| `E2E_ACR_LOGIN_SERVER` / `_USERNAME` / `_PASSWORD` | *(empty)* | Pre-provisioned registry. Set these and nothing shells out to `az` — use when the node has no Azure credentials. |
| `E2E_SKIP_PROVISION` | `auto` | `auto` skips stage 01 when `az` is missing; `1` always skips, `0` always runs. |
| `E2E_NS` | `coco-e2e` | Namespace for the stage-05 pod. |
| `E2E_GO_VERSION` | `1.25.0` | Go toolchain installed by stage 02. |
| `E2E_OPENVMM_VP_COUNT` | `2` | Fixed VP count embedded in the OpenVMM IGVM and requested by runtime-rs. |
| `E2E_OPENVMM_KERNEL_SRC` | `~/src/openvmm-aci-kernel` | Validated ACI kernel source on the E2E node. |
| `E2E_OPENVMM_KERNEL_SRC_LOCAL` | *(empty)* | Workstation checkout archived and copied by `sync.sh` for `openvmm-snp`. |
| `E2E_OPENVMM_REPO` / `_REV` | `nbojanic/openvmm` / `645ac42f...` | Pinned OpenVMM source carrying VM-service SNP IGVM support. |
| `E2E_STATE_DIR` | `~/.coco-e2e` | Stage markers and stage-06 artifacts. |
| `E2E_FRAGMENT_ISSUER` / `_FEED` / `_SVN` / `_MIN_SVN` / `_TAG` | `did:example:e2e-issuer` / `$E2E_REGISTRY/coco-e2e/fragment` / `2` / `1` / `e2e` | Stage-06 fragment identity and rollback floor. |
| `E2E_FRAGMENT_WORK` | `$E2E_STATE_DIR/fragments` | Holds the issuer private key; created mode 700. |
| `E2E_FRAGMENT_UNREACHABLE_FEED` | `localhost:5000/coco-e2e/absent:e2e` | Stage-07 fail-closed fixture. Loopback is deliberate: it is unfetchable from inside the guest no matter what the node's egress looks like. |
| `E2E_FRAGMENT_NEG_WAIT` | `150` | Seconds stage 07 waits before concluding a pod will never reach Running. |

### CI nightly artifact

Stage 03 needs `kata-tools-static.tar.zst` in `$E2E_REPO_DIR/kata-tools-artifacts/`,
and `E2E_NIGHTLY_SHA` set to the matching commit sha. The procedure — including
why it has to happen between stages 02 and 03, and why `gh` runs on the
workstation rather than the node — is
[step 6 of the clean-room run](#clean-room-run-from-nothing). It is written down
once, there.

## Parallel environments

Stage 03 is destructive — it redeploys `kata-deploy` over whatever is on the
node. To keep a known-good cluster as a fallback, stand a second node up beside
it instead of re-running 03 on the first:

```bash
E2E_VM=coco-e2e-2 E2E_SSH_HOST=coco-e2e-2 ./01-provision-vm.sh
E2E_VM=coco-e2e-2 E2E_SSH_HOST=coco-e2e-2 ./sync.sh
```

Stage 01 appends an ssh alias for `$E2E_SSH_HOST` when none exists, and warns
rather than rewriting one that does (an existing entry may be hand-tuned, and a
redeployed VM changes IP). Nothing else is shared: `E2E_STATE_DIR` lives on each
node, and `E2E_REGISTRY=localhost:5000` is loopback-only.

Deallocate both when finished — see [Cleanup](#cleanup).

## Dev loop

A full stage 04 is a 40–60 minute clean build, which is far too slow to iterate
against. `E2E_FAST=1` cuts it down:

| Change | What it does | Why it is sound |
| --- | --- | --- |
| Keeps `src/agent/target` | Incremental cargo build | The stale-artifact trap is about *tarballs*, not the target dir; the tarballs are still deleted. |
| Reuses `rootfs-image-coco-extension` | Skips a second image build | The extension image contains no `kata-agent` — it packages the prebuilt CoCo guest components and pause bundle. It is rebuilt whenever the `tools/` tree hash changes. |
| **Skips the differential SetPolicy test** | Avoids two more agent builds | **This one weakens the run.** |

That last row matters: the `strings`-based check only asserts the SRM is present
and the bypass symbol is not. The `SetPolicy` handler is *compiled out*, so its
absence can only be shown against a non-strict control binary — which is what
`src/agent/tests/test-setpolicy-absent.sh` does. `E2E_FAST` prints a loud warning
where it skips it.

**Do not report a result from an `E2E_FAST` run.** Use it while iterating, then
re-run stage 04 clean (`E2E_FORCE=1 ./run-all.sh 04 05`) before believing
anything.

`E2E_SKIP_BUILD=1` goes further and only installs the tarballs already sitting in
`build/`, for iterating on stages 05/06 against a guest stack you just built. It
fails loudly if those tarballs are absent.

## Traps these scripts already handle

Each of these cost real debugging time; the scripts encode the fix, but knowing
about them helps when something drifts.

- **A stale tarball silently ships the wrong agent.** `kata-deploy-binaries.sh`
  guards each packaging step with `[[ ! -f ${final_tarball_path} ]]`. If the
  tarball exists it recompiles the agent, discards the result, and repackages the
  old one. `USE_CACHE=no` does *not* bypass this. Stage 04 deletes the tarballs
  first, and proves the hardening with a differential symbol test
  (`src/agent/tests/test-setpolicy-absent.sh`) rather than a string match — a
  hardened binary contains no rejection string because the handler is compiled
  out entirely.
- **Building is not installing.** The build only populates `build/*.tar.zst`;
  until those are extracted into `/` the cluster keeps booting the CI-nightly
  guest. Stage 04 installs them and fails unless the deployed image hashes equal
  to the copy inside the tarball it just built (so a byte-identical rebuild is a
  pass, and a change made by anything else is a failure).
- **The host-side genpolicy inputs come from upstream, not from your branch.**
  `kata-tools-static.tar.zst` and the `kata-deploy` image are both built from
  upstream `main`, and genpolicy reads `rules.rego` at *runtime* — so a pod
  policy would be generated from upstream's rules even though the repo has ours.
  Stage 03 restages `rules.rego` and `genpolicy-settings.json` from
  `$E2E_REPO_DIR` after `deploy-kata` (which also writes `/opt/kata` and would
  otherwise clobber them), and then asserts the installed `rules.rego` is
  byte-identical to the repo copy.
- **Upstream CI steps prompt when a human runs them.** `gha-run.sh` is written
  for GitHub Actions, where stdin is never a TTY. Over an interactive ssh session
  it is, so `install-bats` — which calls `add-apt-repository` without `-y`
  (`gha-run-k8s-common.sh:175,177`) — parks on *"Press [ENTER] to continue"* and
  waits forever, immediately before stage 04's 40–60 minute build. Stage 03's
  `gha` wrapper closes stdin so the prompts take their default.
- **The agent builds from a git checkout inside a container**, so uncommitted
  working-tree changes are invisible. Stage 04 refuses to run on a dirty tree.
- **`DOCKER_TAG` needs an `-amd64` suffix.** The manifest-list tag is only
  published when the multi-arch merge job runs, and recent nightlies fail before
  it. Without the suffix `kata-deploy` `ImagePullBackOff`s and the install times
  out.
- **`genpolicy-settings.json` must describe the node it generates for.** Three of
  its values are compared for exact equality inside the guest, and a mismatch
  denies every pod with no hint that the settings are at fault: `oci_version`
  (containerd 2.2.x/2.3.x emit `1.3.0`), `root_path` (runtime-rs hands the agent
  a passthrough path, not the virtio-fs one), and `image_layer_verification`
  (`none` declares no layers, so the erofs snapshotter's storages are all
  refused). This branch's defaults now carry the values this stack needs. For a
  node that differs — an older containerd, say — use genpolicy's drop-in
  mechanism rather than editing the file: point `-j` at a *directory* holding
  `genpolicy-settings.json` plus a `genpolicy-settings.d/` of RFC 6902 patches
  (`src/tools/genpolicy/drop-in-examples/`). The suite does exactly that for the
  values that are genuinely per-platform: `pause_container_image`, and on
  `qemu-coco-dev` the guest-pull settings described in the next bullet.
- **`qemu-coco-dev` runs guest pull, which the branch's defaults refuse.** Stage
  03 deploys that cluster with `PULL_TYPE=guest-pull` and the nydus snapshotter,
  so a rootfs arrives as an `image_guest_pull` storage. Every body of
  `allow_image_guest_pull_source` is gated on `allow_guest_pull_images`, which
  ships `false` — the pause sentinel included — so the branch's defaults deny
  every container in the pod, the sandbox first; and `host-erofs-dm-verity`
  declares layers that cluster never presents. `ensure_genpolicy_defaults` stages
  `10-guest-pull-drop-in.json` beside the settings to undo both, as a per-platform
  opt-in. It stays out of the defaults deliberately: a guest-pull storage carries
  no policy declaration, so it is exempt from the declared-vs-presented storage
  count and a host can mount undeclared content at the container root without
  failing a verity check. `clh-snp`, `aks` and `openvmm-snp` pull on the host and
  keep the verity-bound default.

  The drop-in is staged only when the cluster really is on guest pull, and stage
  03 records the pull type it deployed with (`${E2E_STATE_DIR}/pull-type`) for
  that decision. Two reasons. Deciding from a recorded fact rather than from the
  platform name means overriding `PULL_TYPE` before stage 03 cannot leave the
  policy settings describing a cluster that no longer exists. And
  `$E2E_STATE_DIR` is per-node, not per-platform, so the drop-in directory is
  emptied before staging — otherwise running `qemu-coco-dev` and then a
  host-pull platform on the same node would carry `allow_guest_pull_images=true`
  onto a platform whose whole point is to refuse it.
- **`guest-pull` requires an explicit pod-level `securityContext`** — genpolicy
  refuses images whose user/group would come from the image layers.
- **The policy annotation is `cc_init_data`,** not the legacy
  `io.katacontainers.config.agent.policy`. Any "did genpolicy run?" check must
  look for the former.
- **`install_libseccomp.sh` must be staged by hand.** The agent Dockerfile
  `COPY`s it, but it only reaches that path via Makefile-only targets that
  `kata-deploy-binaries.sh` skips.
- **Changing the agent feature set needs a clean build** — flipping
  `STRICT_POLICY` does not invalidate the cargo cache.
- **Do not wait on a build with `pgrep -f`** — it matches the ssh command line
  carrying the pattern and never exits. Poll for a marker in the log instead.
- **`kubectl exec` into a genpolicy'd pod is denied by design**, and
  `kubectl logs` is empty for these pods. Plan in-guest observation accordingly.
- **The extension image is assembled, not compiled.** It unpacks the CoCo guest
  components and the pause bundle into a rootfs, so both must already exist as
  tarballs. Nothing builds them implicitly; stage 04 builds them from the cache
  (they contain no `kata-agent`, so the stale-tarball trap above does not apply
  and the published artefact is the correct input).
- **Components are built into `build/` but consumed out of the local-build build
  directory.** `build_component` stages every tarball it produces into both, so
  a later component never has to be taught about an earlier one.
- **`kata-containers.img` is a symlink, in the tarball and once installed.**
  `tar -xO` on a symlink member emits no bytes, so hashing it digests the empty
  string. Any comparison against tarball contents must unpack and hash through
  the link — and note that an `[ -n "$hash" ]` guard cannot catch this, because
  hashing empty input still produces a hash.
- **The extension tarball ships its ancestor directories (`./`, `./opt/`) as
  entries.** A path allow-list over archive members has to permit them, or it
  rejects a perfectly well-formed archive.
- **`helm dependency build` (stage 03) writes untracked files** into the
  kata-deploy chart — a `Chart.lock` and vendored dependency charts. Stage 04's
  dirty-tree check excludes them, or every clean-room run fails on its
  predecessor's output.

### Region and quota

Availability and quota are independent, and each one alone is a false green —
check both. For AKS-based runs (not covered by these scripts) use `westus`:
`eastus` is restricted for that subscription, and the `_cc_v6` SKUs have zero
quota by default.

Restriction *type* matters as much as the reason code. A `Location` restriction
means the SKU cannot be deployed in the region at all; a `Zone` restriction only
blocks *zonal* deployments. `Standard_DC16as_cc_v5` in `eastus` reports
`NotAvailableForSubscription` on all three zones yet deploys regionally without
complaint, so stage 01 fails only on `Location` and warns on `Zone`.

```bash
az vm list-skus --size Standard_DC16as_cc_v5 \
  --query "[].{Loc:locationInfo[0].location, T:restrictions[0].type, R:restrictions[0].reasonCode}" -o table
az vm list-usage --location westus --query "[?contains(localName,'DCACCV5')]" -o table
```

### Platforms

`E2E_PLATFORM` selects the stack under test. Everything that differs between them
is derived in one `case` block at the top of `lib.sh`, so the stages themselves
stay declarative.

| | `qemu-coco-dev` (default) | `clh-snp` | `aks` | `openvmm-snp` |
| --- | --- | --- | --- | --- |
| Hypervisor | QEMU + KVM | Cloud Hypervisor + MSHV | Cloud Hypervisor + MSHV | OpenVMM + MSHV |
| Guest | ordinary VM, **not attested** | real SEV-SNP CVM | real SEV-SNP CVM | real SEV-SNP CVM |
| Node OS | Ubuntu 24.04 | Azure Linux 3 | Azure Linux 3 (AKS node image) | Azure Linux 3 |
| Default SKU | `Standard_DC16as_cc_v5` | `Standard_DC16as_cc_v5` | `Standard_DC8as_cc_v6` | `Standard_DC32as_cc_v6` |
| Installed by | kata-deploy (Helm) | `make all-confpods` from `tools/osbuilder/node-builder/azure-linux` | **already baked into the node image** | `tools/osbuilder/openvmm-igvm` |
| Prefix | `/opt/kata` | `/opt/confidential-containers` | `/opt/confidential-containers` | `~/kata-openvmm` |
| RuntimeClass | `kata-qemu-coco-dev-runtime-rs` | `kata-cc` | discovered on the cluster | `kata-cc` |
| genpolicy | ships in the kata-deploy image | **none** — built from the branch | **none** — built from the branch | built from the branch |
| Verity pin | patched into `configuration-*.toml` | baked into the IGVM kernel cmdline | baked into the IGVM kernel cmdline | baked into the IGVM cmdline |

The platforms answer different questions. `qemu-coco-dev` is fast and exercises the
policy logic, the agent and the guest-pull path, which is most of what changes
day to day. It cannot say anything about attestation, the SNP boot path, or
anything MSHV-specific — for example the pathrs kernel-version panic is invisible
under QEMU because it needs a version string containing an MSHV suffix.
The SNP-backed platforms cover those gaps. `openvmm-snp` uses the VM-service
OpenVMM backend and supports a fixed, selectable multi-VP IGVM topology.

**`clh-snp` prerequisites the suite handles for you:** the MSHV host kernel and
the `Dom0` grub entry (stage 02 — this needs one reboot, and the stage says so),
containerd 2.3.x, cloud-hypervisor built with `--features sev_snp`, and the
6.1.58 UVM kernel rebuilt from the distro SRPM with `CONFIG_EROFS_FS` enabled
(stage 04). The packaged UVM kernel is not usable: 6.6.137.mshv1 triple-faults
during IGVM boot, and the packaged 6.1.58 has EROFS off.

Note that `AGENT_POLICY_FILE=allow-all.rego`, which the node-builder README
passes, is deliberately **not** used here — it would make stages 05–08 vacuous.
The default for a release build is `allow-set-policy.rego`, which is what these
tests need.

### `aks` — validating a prebuilt node image

`E2E_PLATFORM=aks` does not build anything. It points the suite at a cluster
whose nodes already run an image someone else produced, and asks whether that
image was assembled correctly. Stage `00-adopt-node.sh` replaces stages 01–04:
it discovers the node, finds the payload, checks the RuntimeClass wiring,
inspects the shipped guest agent, and records a baseline — then marks 01–04 done
so stage 05 onwards run unchanged.

```bash
export KUBECONFIG=~/.kube/aks.config
export E2E_PLATFORM=aks
export E2E_STATE_DIR=$HOME/.coco-e2e-aks   # keep it away from a build run's state
export E2E_REPO_DIR=$HOME/kata-containers  # genpolicy is built from here
./00-adopt-node.sh && ./05-smoke-test.sh
```

A node pool carrying an image built elsewhere is created with the BYOI custom
headers. The SKU must be a confidential-container one (`_cc_`); the v6
generation comes in 8- and 32-vCPU shapes only — there is no `DC16as_cc_v6` —
and is offered in regions where no v5 CC SKU is, `belgiumcentral` among them.
`az vm list-skus -l "$LOCATION"` before you create the pool: an absent SKU
surfaces as a quota error rather than as "not offered here".

```bash
az aks create -g "$RG" -n "$CLUSTER" -l "$LOCATION" \
  --node-count 1 --node-vm-size Standard_DC8as_cc_v6 \
  --os-sku AzureLinux --workload-runtime KataVmIsolation \
  --node-os-upgrade-channel None --generate-ssh-keys \
  --aks-custom-headers \
"AKSHTTPCustomFeatures=Microsoft.ContainerService/UseCustomizedOSImage,\
OSImageSubscriptionID=<sub>,OSImageResourceGroup=<rg>,OSImageGallery=<gallery>,\
OSImageName=AzureLinuxV3gen2,OSImageVersion=<version>,OSSKU=AzureLinux,\
OSDistro=CustomizedImageKata"
```

Note that `--workload-runtime KataVmIsolation` provisions its own RuntimeClass,
and on the images seen so far that class points at the node's *legacy* kata
handler rather than the confidential one — which is the second failure below.
Expect to create your own RuntimeClass over the right handler.

Stage 00 exists because a wrong image still looks healthy. Three failures it is
built to catch, all of which produce a *running pod* and no error anywhere:

- **The agent is not the strict one.** An agent built without the security
  reference monitor, or without `--features devicemapper`, boots fine. 00e
  loop-mounts `kata-containers.img` on the node and greps the agent binary
  rather than trusting the image label. Note that a shipped agent is stripped,
  so the SRM shows up only as the panic-location paths
  (`src/agent/security-reference-monitor/...`), not as symbol names.
- **The RuntimeClass runs the wrong stack.** A node can carry two complete kata
  installs — a legacy one under `/usr/share` and the confidential one under
  `/opt/confidential-containers` — each with its own containerd handler,
  `ConfigPath`, guest image and `enable_annotations` list. If the RuntimeClass
  resolves to the legacy handler, `cc_init_data` is not in its allowlist, so the
  generated policy is dropped **silently**: the pod comes up and `exec` is
  allowed. 00c ties the handler's `ConfigPath` back to the payload prefix and
  checks the allowlist, and prints the handler table so you can see which
  handler you should have used.
- **The layers do not arrive the way the policy describes them.** This suite
  generates policy for the host-EROFS + dm-verity path, where layers are built
  and hashed on the node and attached to the guest as verified block devices.
  A handler on the `nydus` snapshotter pulls inside the guest instead, where no
  host-side root hash exists; and an EROFS differ with `enable_dmverity = false`
  or unpinned `mkfs_options` produces layers whose digests genpolicy cannot
  predict. All three end the same way — every container refused, with the error
  pointing at storages rather than at the configuration — so 00d reads the
  node's containerd config and asserts the transport before anything is built.

Two AKS-specific traps worth knowing. A RuntimeClass carries
`scheduling.nodeSelector`, which the API server copies onto every pod using it;
if the node lacks those labels the pod is rejected by kubelet with an opaque
`Predicate NodeAffinity failed`, so 00a checks this for the class it is about to
use — whether that class was discovered or supplied through `E2E_RUNTIMECLASS`.
And on AKS those labels are system-managed —
`aks-node-validating-webhook` refuses to let you add them by hand, so if the
provisioned RuntimeClass is unusable the way forward is a new RuntimeClass with no
nodeSelector over the correct handler.

Every AKS pod is pinned to the adopted node with `nodeName`, through the shared
`pod_pin` helper in `lib.sh` rather than per-stage, because the assertions are
about one node's image and a multi-node pool would otherwise let the scheduler
measure something this run made no claim about. For the same reason `run-all.sh`
narrows its stage list by platform *before* matching arguments: `./run-all.sh 04`
on AKS is refused rather than silently installing a second guest stack over the
one under test.

Building genpolicy needs `mkfs.erofs` >= 1.8 for `--mkfs-time`. Ubuntu 24.04
ships 1.7.1, which fails with `unrecognized option '--mkfs-time'` partway
through layer derivation; build erofs-utils from source into `/usr/local`.

**`openvmm-snp` kernel source:** the validated ACI kernel source is not
automatically cloned by the suite. Point `E2E_OPENVMM_KERNEL_SRC_LOCAL` at a
workstation checkout when syncing:

```bash
E2E_PLATFORM=openvmm-snp \
E2E_OPENVMM_KERNEL_SRC_LOCAL="$HOME/src/openvmm-aci-kernel" \
  ./sync.sh
```

`sync.sh` sends a `git archive`, not the checkout metadata or credentials, and
extracts it at the node’s default `E2E_OPENVMM_KERNEL_SRC`.

#### Current `openvmm-snp` limitations

- **EROFS VMDK is flattened before attachment.** Kata represents GPT-partitioned,
  dm-verity-protected EROFS layers as a flat VMDK descriptor. OpenVMM has no
  native flat-VMDK/composite-disk backend, so the OpenVMM runtime path uses
  `qemu-img` to create an equivalent raw GPT disk beside the descriptor before
  attaching it. The raw artifact is regenerated atomically if VM startup is
  retried. The guest still mounts the EROFS partitions through dm-verity, but
  this temporary compatibility path copies layer data and costs additional
  startup time and host disk space.
- **The IGVM topology remains fixed.** `E2E_OPENVMM_VP_COUNT` is embedded in the
  generated IGVM and must match runtime-rs `default_vcpus`; Kubernetes CPU
  requests cannot resize an already measured OpenVMM SNP topology.
- **The guest command line carries a layout-specific workaround.**
  `memmap=4K$0x416b000` avoids the currently observed
  `HvMessageTypeUnacceptedGpa` failure. It is not a stable ABI or production
  solution.
- **The ACI kernel source is private.** Fresh nodes need an authenticated clone
  or `E2E_OPENVMM_KERNEL_SRC_LOCAL` during `sync.sh`.

Stages 01–08 have been validated with this platform on
`Standard_DC32as_cc_v6`, including measured initdata, EROFS dm-verity, signed
policy-fragment delivery, and lifecycle gates.

### The node is not a confidential VM

This applies to the default `qemu-coco-dev` platform. Tempting as the SKU name
is, the node is provisioned with
`--security-type Standard`. This suite exercises the `qemu-coco-dev` runtime
class, which is the **non-attested dev path**: the guest is an ordinary VM, so
what the node needs is a confidential-*capable* host SKU for nested
virtualisation (the `_cc_` in `DC16as_cc_v5`), not a confidential VM of its own.
Asking for `ConfidentialVM` also fails outright against the plain Ubuntu
`server` image this suite is built around ("Use of ConfidentialVM setting is not
supported for the provided image") — a `:cvm:` image sku is required for that.
`E2E_VM_SECURITY_TYPE=ConfidentialVM` is available if you pair it with one.

Both SNP platforms also use `Standard`, for a different reason: the node is the
*hypervisor root partition* (MSHV Dom0) that launches SNP guests, so it must not
itself be a CVM. Confidentiality on that path comes from the guest's IGVM
measurement, not from the node.

### Running stage 01 from Windows

`01-provision-vm.sh` and `sync.sh` are the only workstation-side scripts. Under
git-bash/cygwin, `whoami` returns `DOMAIN+user`, which Azure rejects as an admin
name; `lib.sh` strips the domain and normalises the case. `jq` is required and
is not part of git-bash — install it separately.


## Policy fragments (stage 06)

The fragment feature has two boundaries and the stage covers both:

**Verification** — `fragment-demo` drives the real `FragmentStore`, the same one
used by the runtime `LoadPolicyFragment` push
path. It asserts every positive and negative outcome internally (unsigned,
unauthorized issuer, SVN rollback, revoked certificate, reordered log head,
missing or foreign receipt), so a non-zero exit is a genuine regression.

**Delivery** — the stage signs a fragment, packages it as an OCI artifact and
pushes it, then reads the manifest back and asserts the contract the guest
fetcher depends on:

| Field | Value | Asserted |
| --- | --- | --- |
| `artifactType` | `application/x-ms-ccepolicy-frag` | yes |
| COSE layer `mediaType` | `application/cose-x509+rego` | yes |
| config `mediaType` | `application/vnd.oci.empty.v1+json` | no — contract only |

Against a remote registry the read-back is done *anonymously* over HTTPS, using
the same token dance the guest's OCI client performs. That is deliberate: it
doubles as a preflight that anonymous pull really is enabled, which is what the
guest depends on. The stage also asserts the negative case: `--plain-http`
against a non-loopback registry must fail with the specific downgrade guard
message, not merely a non-zero exit.

It then prints the `policy_fragments[]` settings entry for the base policy and
the `fragment-issuers.toml` trust root to deliver through measured initdata. Both
are needed for live delivery; stage 07 consumes them directly.

The trust root is measured, so it must arrive through initdata (preferred) or the
measured rootfs — never from the host. The initdata half of that only holds once
FR-2 has bound the initdata to the launch measurement: since RM-88/F-166 an
unbound initdata section is ignored in favour of the rootfs file, and in a strict
build a guest with no TEE report provider aborts rather than booting on unverified
initdata. Fragment failures abort the VM by design.

## Live fragment delivery (stage 07)

Stage 06 stops at the delivery boundary: it proves the artifact is correct and
that `FragmentStore` accepts and rejects the right things. It never asks the
guest to do anything. Stage 07 closes that gap on the cluster from 03/04.

**Who fetches.** The host does. The guest has no interfaces at the point
fragments must be loaded — they arrive only through the `update_interface` /
`update_routes` ttRPC handlers, which cannot run before the agent serves — so an
in-guest pull can never succeed. The shim pulls each artifact named by the
`io.katacontainers.config.agent.policy_fragments` pod annotation and pushes the
COSE envelope over `LoadPolicyFragment`. This is how hcsshim does it too.

**Why an untrusted fetcher is fine.** The annotation says only *what to offer*.
Every trust anchor — authorized issuers, accepted feeds, per-feed SVN floors —
comes from the **measured** policy, and the guest verifies the COSE envelope
against it. A host that substitutes, downgrades or reorders a fragment gets a
visible failure, never a silent bypass. The host is a courier, not an authority.

**Withholding, and the `required` flag.** The one attack a courier keeps is
saying nothing. That is already fail-safe by default: an undelivered fragment
contributes no rules, so a container only it would have permitted fails to match
the composed policy and is refused on its own merits. Withholding can only reduce
what runs. This is C-ACI/hcsshim behaviour, where injection is lazy and nothing
obliges the host to send anything.

It is *not* fail-safe when the fragment carries something whose absence is
permissive — a deny rule, an audit obligation, a constraint the base policy
assumes was composed in. A declaration can therefore set `"required": true`,
which makes the guest refuse `CreateContainer` until that fragment is delivered
and verified. This is stricter than C-ACI, which has no equivalent. The flag is
per declaration, so a policy can demand a mandatory baseline while leaving
optional add-ons optional. It governs only whether *absence* is an error:
a delivered fragment is verified identically either way.

**The oracle.** The `required` gate makes pod phase sound in *both* directions —
Running with a non-empty required declaration means the fragment was delivered,
verified **and** injected, and there is nothing to read out of the guest to
confirm it.

**Why the control is load-bearing.** A pod that fails to start is weak evidence
on its own; almost any unrelated breakage produces the same symptom. So 07 first
boots an otherwise identical pod with an empty declaration. If *that* does not
reach Running the stage aborts rather than reporting a pass, because no
fail-closed result below it would mean anything.

| Case | Declaration | Expected | Runs |
| --- | --- | --- | --- |
| `07a` | `policy_fragments := []` | Running | always — control |
| `07b` | a `required` feed that is declared but never offered for delivery | never Running | always |
| `07c` | the real feed from 06, `required`, offered via the annotation | Running | always |
| `07d` | the real feed, `required`, `minimum_svn` raised above the fragment''s | never Running | always |
| `07e` | same as `07b` but `"required": false` | Running | always |

`07b` and `07e` differ by exactly one field, so a difference in outcome can be
attributed to nothing else. Asserting both is the only way to show the flag is
actually read: `07b` alone is satisfied by a gate that is simply always shut, and
`07e` alone by one that is never armed.

**How the declaration gets in.** genpolicy has no `policy_fragments` support, so
the stage appends the entry to a *copy* of `rules.rego` and passes it with `-p`.
The staged `/opt/kata/share/defaults/kata-containers/rules.rego` is never
touched — stage 03 asserts its hash and stage 05 depends on it. The trust root
goes in through `--initdata-path=`, which is where the guest expects a measured
`fragment-issuers.toml` to arrive.

**An ACR is optional.** Because the *host* fetches, the throwaway loopback
registry works for 07c/07d — the node is the one that has to reach it. This was
not always true: when the guest fetched, a loopback feed was unreachable by
construction, so the good path could not run at all without a publicly trusted,
anonymously pullable HTTPS registry. Use an ACR when you want the pull to
traverse real TLS and real auth:

```bash
E2E_ACR=auto E2E_FORCE=1 ./run-all.sh 06 07   # 06 must be re-run: 07 consumes its artifacts
```

`ensure_acr` creates or adopts a registry whose name is derived from the
subscription and resource group, so repeated runs reuse the same one rather than
littering the subscription. It *asserts* `anonymousPullEnabled` and repairs it if
missing — an adopted registry can have it off, and it can be turned off later.
Push uses a short-lived token from `az acr login --expose-token`, passed to
`genpolicy-fragmentgen` through `FRAGMENTGEN_USERNAME` / `FRAGMENTGEN_PASSWORD`
rather than argv, since `/proc/<pid>/cmdline` is world-readable.

The feed is baked into the COSE payload at signing time and the guest checks the
delivered envelope against *that*, so the registry is decided before 06c signs.
Mirroring the artifact into a registry afterwards would not change what the guest
will accept. (The feed is a trust identity and carries no tag; the tagged OCI
reference the host actually pulls is written separately to `fragment-ref.txt`.)

If the node has no Azure credentials, provision from the workstation and hand the
values over instead — nothing then shells out to `az`. The e2e node is this case:

```bash
az acr create -n <acr> -g <rg> --sku Standard
az acr update -n <acr> -g <rg> --anonymous-pull-enabled true

E2E_ACR_LOGIN_SERVER=<acr>.azurecr.io \
E2E_ACR_USERNAME=00000000-0000-0000-0000-000000000000 \
E2E_ACR_PASSWORD=$(az acr login -n <acr> --expose-token --query accessToken -o tsv) \
E2E_FORCE=1 ./run-all.sh 06 07
```

The token is short-lived (hours), so mint it right before the run. Without a
reachable registry the stage still runs 07a and 07b and says plainly which cases
it skipped. A missing registry costs coverage, not correctness.

### Re-running 07 on its own

Stage 07 consumes what 06 produced — `fragment-entry.json`, `fragment-issuers.toml`
and `fragment-ref.txt` under `~/.coco-e2e/fragments/` — and the COSE envelope
commits to its feed, so these cannot be regenerated independently without drifting
from what was published. 07 alone is fine:

```bash
E2E_FORCE=1 ./run-all.sh 07
```

`E2E_FORCE=1` is required, not optional: completed stages are marked done in
`~/.coco-e2e` and a bare re-run silently skips them.

Re-run **06 first** in three cases:

- the fragment fixture or issuer key changed
- the node rebooted — before the registry gained `--restart unless-stopped` and a
  named volume this emptied it, leaving `fragment-ref.txt` pointing at nothing
- the artefacts above are missing

Stage 07 now resolves the manifest before creating any pod, so a stale fixture
fails in seconds with a clear message instead of costing a five-minute pod
timeout that reads like a delivery failure. Note the probe is loopback-only: a
real ACR speaks HTTPS and wants a token, so a bare `GET` would prove nothing.

If you probe a registry by hand, send the `Accept` header — without it an OCI
registry returns `404` for a manifest that is perfectly present:

```bash
curl -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  http://localhost:5000/v2/coco-e2e/fragment/manifests/e2e
```

Re-run **04 first** after any change to the agent, the SRM, or the fragment
declaration handling — 07 exercises the installed guest, and stage 04 is what
rebuilds it.

## Cleanup

```bash
az vm deallocate -g "$E2E_RG" -n "$E2E_VM"
az acr delete -g <rg> -n <acr> --yes   # a Standard registry bills per day
docker rm -f coco-e2e-registry
rm -rf ~/.coco-e2e          # clears the stage markers
```
