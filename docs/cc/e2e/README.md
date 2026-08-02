# End-to-end reproduction on an Azure VM

Scripted reproduction of the confidential-containers end-to-end path used to
validate the hardened (`STRICT_POLICY`) guest stack, including the signed
policy-fragment flow.

Everything here is idempotent and resumable. Each stage records a marker under
`~/.coco-e2e`; a re-run skips completed stages. `E2E_FORCE=1` re-runs anyway.

Stages 01–06 have been run start to finish from an empty resource group. That
exercise is worth repeating after any substantial change: standing a second node
up beside a working one turned up seven defects in this suite, every one of them
hidden by state the original node had accumulated by hand.

## What each stage proves

| Stage | Proves |
| --- | --- |
| `01-provision-vm.sh` | An Azure VM on a confidential-capable host SKU exists and is reachable. The node itself is a plain VM, not a confidential one — see "the node is not a confidential VM" below. Run from your workstation. |
| `02-bootstrap-node.sh` | Toolchain, container engine, kubectl, Go, Rust and the repo checkout are present on the node. |
| `03-deploy-cluster.sh` | A kubeadm cluster with `kata-deploy` and the CoCo KBS is up and the runtime classes are registered. |
| `04-build-guest-stack.sh` | The hardened agent is built **and installed** into `/opt/kata`, the deployed guest image is byte-for-byte the one just built, and the runtime is re-pinned to that image's dm-verity root hashes. |
| `05-smoke-test.sh` | The pod that boots is provably the locally built guest (verity pin), and an undeclared `exec` is denied. Mediation is live. |
| `06-policy-fragment-e2e.sh` | FR-1 signed policy fragments: every verification invariant holds, and the OCI delivery artifact matches the contract the guest fetcher depends on. |

## Quick start

```bash
# from your workstation
./01-provision-vm.sh                  # provisions, and adds the ssh alias
./sync.sh                             # copies the suite to the node

# on the node
ssh coco-dev
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
coco-dev`) before running stage 04. Stage 04 re-execs itself under `sg docker`
when it can, so a single-session run usually still works.

`run-all.sh` skips stage 01 automatically when the Azure CLI is absent (i.e. on
the node). Force the decision with `E2E_SKIP_PROVISION=1` or `=0`.

Individual stages:

```bash
./run-all.sh 04 05 06
E2E_FORCE=1 ./run-all.sh 06
```

## Configuration

All settings live at the top of `lib.sh` and are environment-overridable.

| Variable | Default | Notes |
| --- | --- | --- |
| `E2E_RG` / `E2E_VM` | `jiria-coco-cvm-rg` / `coco-dev-1` | Azure resource group and VM name. |
| `E2E_SSH_HOST` | `coco-dev` | ssh alias the workstation-side helpers use. Override with `E2E_VM` for a parallel environment. |
| `E2E_FAST` | `0` | Dev-loop mode. Reduces assurance — see below. |
| `E2E_SKIP_BUILD` | `0` | Install the tarballs already in `build/` without rebuilding. |
| `E2E_REGION` | `eastus` | See the region trap below. |
| `E2E_VM_SIZE` | `Standard_DC16as_cc_v5` | Confidential-capable **host** SKU (nested virt). The node itself is a normal VM. |
| `E2E_VM_SECURITY_TYPE` | `Standard` | See "The node is not a confidential VM" below. |
| `E2E_BRANCH` | `agent-unstart-failed-start` | Branch under test. |
| `E2E_REPO_DIR` | `~/kata-containers` | Checkout on the node. |
| `E2E_STRICT_POLICY` | `yes` | Pulls in the security reference monitor. |
| `E2E_NIGHTLY_SHA` | *(required for stage 03)* | CI-nightly commit sha. |
| `E2E_REGISTRY` | `localhost:5000` | Registry for the policy fragment. Loopback starts a throwaway `registry:2`. |
| `E2E_SKIP_PROVISION` | `auto` | `auto` skips stage 01 when `az` is missing; `1` always skips, `0` always runs. |
| `E2E_NS` | `coco-e2e` | Namespace for the stage-05 pod. |
| `E2E_GO_VERSION` | `1.25.0` | Go toolchain installed by stage 02. |
| `E2E_STATE_DIR` | `~/.coco-e2e` | Stage markers and stage-06 artifacts. |
| `E2E_FRAGMENT_ISSUER` / `_FEED` / `_SVN` / `_MIN_SVN` / `_TAG` | `did:example:e2e-issuer` / `$E2E_REGISTRY/coco-e2e/fragment` / `2` / `1` / `e2e` | Stage-06 fragment identity and rollback floor. |
| `E2E_FRAGMENT_WORK` | `$E2E_STATE_DIR/fragments` | Holds the issuer private key; created mode 700. |

### CI nightly artifact

Stage 03 needs `kata-tools-static.tar.zst` in `$E2E_REPO_DIR/kata-tools-artifacts/`.
The *overall* nightly run is usually red — that is fine, only the build/publish
jobs matter.

```bash
gh run list --workflow ci-nightly.yaml -L 5 --json databaseId,headSha,conclusion
gh run download <id> -n kata-tools-static-tarball-amd64-<sha>-nightly
mkdir -p ~/kata-containers/kata-tools-artifacts
mv kata-tools-static.tar.zst ~/kata-containers/kata-tools-artifacts/
export E2E_NIGHTLY_SHA=<sha>
```

## Parallel environments

Stage 03 is destructive — it redeploys `kata-deploy` over whatever is on the
node. To keep a known-good cluster as a fallback, stand a second node up beside
it instead of re-running 03 on the first:

```bash
E2E_VM=coco-dev-2 E2E_SSH_HOST=coco-dev-2 ./01-provision-vm.sh
E2E_VM=coco-dev-2 E2E_SSH_HOST=coco-dev-2 ./sync.sh
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
- **The agent builds from a git checkout inside a container**, so uncommitted
  working-tree changes are invisible. Stage 04 refuses to run on a dirty tree.
- **`DOCKER_TAG` needs an `-amd64` suffix.** The manifest-list tag is only
  published when the multi-arch merge job runs, and recent nightlies fail before
  it. Without the suffix `kata-deploy` `ImagePullBackOff`s and the install times
  out.
- **`oci_version` in `genpolicy-settings.json` is stale (1.1.0)** while
  containerd emits 1.3.0, which denies every pod at `CreateContainerRequest`.
  Stage 03 patches it.
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

### The node is not a confidential VM

Tempting as the SKU name is, the node is provisioned with
`--security-type Standard`. This suite exercises the `qemu-coco-dev` runtime
class, which is the **non-attested dev path**: the guest is an ordinary VM, so
what the node needs is a confidential-*capable* host SKU for nested
virtualisation (the `_cc_` in `DC16as_cc_v5`), not a confidential VM of its own.
Asking for `ConfidentialVM` also fails outright against the plain Ubuntu
`server` image this suite is built around ("Use of ConfidentialVM setting is not
supported for the provided image") — a `:cvm:` image sku is required for that.
`E2E_VM_SECURITY_TYPE=ConfidentialVM` is available if you pair it with one.

### Running stage 01 from Windows

`01-provision-vm.sh` and `sync.sh` are the only workstation-side scripts. Under
git-bash/cygwin, `whoami` returns `DOMAIN+user`, which Azure rejects as an admin
name; `lib.sh` strips the domain and normalises the case. `jq` is required and
is not part of git-bash — install it separately.


## Policy fragments (stage 06)

The fragment feature has two boundaries and the stage covers both:

**Verification** — `fragment-demo` drives the real `FragmentStore`, the same one
used by both the guest boot-pull path and the runtime `LoadPolicyFragment` push
path. It asserts every positive and negative outcome internally (unsigned,
unauthorized issuer, SVN rollback, revoked certificate, reordered log head,
missing or foreign receipt), so a non-zero exit is a genuine regression.

**Delivery** — the stage signs a fragment, packages it as an OCI artifact and
pushes it. For a loopback registry it then reads the manifest back and asserts
the contract the guest fetcher depends on:

| Field | Value | Asserted |
| --- | --- | --- |
| `artifactType` | `application/x-ms-ccepolicy-frag` | yes |
| COSE layer `mediaType` | `application/cose-x509+rego` | yes |
| config `mediaType` | `application/vnd.oci.empty.v1+json` | no — contract only |

Against a remote registry the read-back is skipped (no credentials are assumed);
verify by hand with `oras manifest fetch`. The stage also asserts the negative
case: `--plain-http` against a non-loopback registry must fail with the specific
downgrade guard message, not merely a non-zero exit.

It then prints the `policy_fragments[]` settings entry for the base policy and
the `fragment-issuers.toml` trust root to deliver through measured initdata. Both
are needed for a live boot-pull; the stage prints the exact wiring.

The trust root is measured, so it must arrive through initdata (preferred) or the
measured rootfs — never from the host. Fragment failures abort the VM by design.

## Cleanup

```bash
az vm deallocate -g jiria-coco-cvm-rg -n coco-dev-1
docker rm -f coco-e2e-registry
rm -rf ~/.coco-e2e          # clears the stage markers
```
