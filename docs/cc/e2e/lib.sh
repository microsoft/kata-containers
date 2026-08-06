#!/usr/bin/env bash
# Shared helpers and configuration for the CoCo end-to-end reproduction scripts.
# Source this from every step script:  . "$(dirname "$0")/lib.sh"

set -uo pipefail

# ----------------------------------------------------------------- configuration
# Everything here can be overridden from the environment.

: "${E2E_RG:=jiria-coco-cvm-rg}"
: "${E2E_VM:=coco-dev-1}"
# ssh alias the workstation-side helpers use to reach the node. Override together
# with E2E_VM to drive a second, parallel environment from the same checkout.
: "${E2E_SSH_HOST:=coco-dev}"
: "${E2E_REGION:=eastus}"

# ------------------------------------------------------------------- platform
# Which hypervisor/accelerator stack the suite validates against.
#
#   qemu-coco-dev  QEMU + KVM, guest is a *non-attested* dev VM. Installed by
#                  upstream kata-deploy (Helm) under /opt/kata. This is the
#                  historical default and every stage was written for it.
#   clh-snp        Cloud Hypervisor + MSHV with real SEV-SNP, built from source
#                  on Azure Linux 3 by tools/osbuilder/node-builder/azure-linux
#                  and installed under /opt/confidential-containers. kata-deploy
#                  is not involved at all on this path.
#
# The split matters because the two differ in more than a hypervisor name: the
# install prefix, the shim binary, the containerd handler and the RuntimeClass
# are all different, and only the QEMU path ships a genpolicy binary. Anything
# platform-dependent is derived here so the stages stay declarative.
: "${E2E_PLATFORM:=qemu-coco-dev}"
case "$E2E_PLATFORM" in
  qemu-coco-dev)
    # Standard_DC16as_cc_v5 is a SEV-SNP CC SKU. See README for the region/quota
    # trap: availability and quota are independent, and each alone is a false green.
    : "${E2E_VM_SIZE:=Standard_DC16as_cc_v5}"
    : "${E2E_VM_IMAGE:=Canonical:ubuntu-24_04-lts:server:latest}"
    # Standard, not ConfidentialVM — see the comment in 01-provision-vm.sh. The
    # guest here is an ordinary VM, so what the node needs is a confidential-capable
    # *host* for nested virt, not a confidential VM of its own.
    : "${E2E_VM_SECURITY_TYPE:=Standard}"
    : "${E2E_OS_DISK_GB:=256}"
    : "${E2E_PKG:=apt}"
    : "${E2E_RUNTIMECLASS:=kata-qemu-coco-dev-runtime-rs}"
    : "${E2E_KATA_PREFIX:=/opt/kata}"
    # The QEMU guest boots a plain rootfs image.
    : "${E2E_GUEST_IMAGE_NAME:=kata-containers.img}"
    ;;
  clh-snp)
    # The guest is a real SEV-SNP CVM here, so unlike the QEMU path the *node*
    # must itself be a CC SKU running as an MSHV Dom0 — nested virt is not enough.
    # DC16 rather than DC4: this platform compiles cloud-hypervisor, the UVM
    # kernel and the full Rust runtime natively on the node, so cores are the
    # dominant cost of stage 04. DC4as_cc_v5 is also NotAvailableForSubscription
    # in eastus, whereas DC16 is the size the AzL3/MSHV repro was validated on.
    : "${E2E_VM_SIZE:=Standard_DC16as_cc_v5}"
    : "${E2E_VM_IMAGE:=MicrosoftCBLMariner:azure-linux-3:azure-linux-3-gen2:latest}"
    : "${E2E_VM_SECURITY_TYPE:=Standard}"
    # 60 GB is what the node-builder README asks for; the guest-stack build needs
    # considerably more than that, so keep the suite's larger disk.
    : "${E2E_OS_DISK_GB:=256}"
    : "${E2E_PKG:=dnf}"
    # Handler name comes from the shim binary the confpods flow installs,
    # containerd-shim-kata-cc-v2 -> io.containerd.kata-cc.v2 -> "kata-cc".
    : "${E2E_RUNTIMECLASS:=kata-cc}"
    : "${E2E_KATA_PREFIX:=/opt/confidential-containers}"
    # Both platforms install a rootfs image under the same name. What differs is
    # what boots it: on SNP the kernel and the launch measurement live in a
    # separate IGVM file, and the rootfs' dm-verity root hash is baked into the
    # kernel command line *inside* that IGVM (uvm_build.sh passes
    # DM_VERITY_FORMAT=kernelinit). So the verity pin is not visible in
    # configuration.toml the way it is on the QEMU path, and the IGVM is the
    # artefact that has to be attested instead.
    : "${E2E_GUEST_IMAGE_NAME:=kata-containers.img}"
    : "${E2E_GUEST_IGVM_NAME:=kata-containers-igvm.img}"
    ;;
  *)
    echo "unsupported E2E_PLATFORM=$E2E_PLATFORM (expected qemu-coco-dev or clh-snp)" >&2
    exit 1
    ;;
esac

# Where the *installed* kata payload lives. Only ever used for things the
# platform actually installs — notably not genpolicy, which the confpods flow
# does not ship at all (see genpolicy_defaults below).
E2E_KATA_DEFAULTS="$E2E_KATA_PREFIX/share/defaults/kata-containers"
E2E_GUEST_IMAGE="$E2E_KATA_PREFIX/share/kata-containers/$E2E_GUEST_IMAGE_NAME"
E2E_GUEST_IGVM="$E2E_KATA_PREFIX/share/kata-containers/${E2E_GUEST_IGVM_NAME:-}"

# Component versions for the clh-snp build. Pinned rather than floating: the
# node-builder README is explicit that AzL's packaged kernel-uvm 6.6.137.mshv1
# triple-faults during IGVM boot, so the UVM kernel is a specific older one that
# has to be rebuilt with EROFS support.
: "${E2E_CLH_REPO:=https://github.com/microsoft/cloud-hypervisor.git}"
: "${E2E_CLH_TAG:=msft/v51.1.101}"
: "${E2E_UVM_KERNEL_VERSION:=6.1.58.mshv8}"
# whoami returns DOMAIN\user on a Windows workstation, and cygwin/git-bash render
# that as DOMAIN+user. Azure rejects both separators and upper case in an admin
# name, so normalise here rather than failing deep inside az vm create.
: "${E2E_ADMIN:=$(whoami | sed 's|.*[\\/+]||' | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')}"
: "${E2E_SSH_KEY:=$HOME/.ssh/id_rsa.pub}"

# Repo under test.
: "${E2E_REPO_URL:=https://github.com/abhishek179/kata-containers-coco.git}"
: "${E2E_BRANCH:=agent-unstart-failed-start}"
: "${E2E_REPO_DIR:=$HOME/kata-containers}"

# Guest-stack build flags. STRICT_POLICY=yes is what pulls in the security reference
# monitor; without it none of the hardening is in the binary.
: "${E2E_AGENT_POLICY:=yes}"
: "${E2E_STRICT_POLICY:=yes}"
: "${E2E_INIT_DATA:=yes}"

# Dev-loop controls. The defaults are the slow, paranoid path: a clean rebuild of
# everything. E2E_FAST=1 trades that for iteration speed and is only safe for the
# cases documented in the README.
: "${E2E_FAST:=0}"
: "${E2E_SKIP_BUILD:=0}"

# Local dev registry used by the policy-fragment step.
: "${E2E_REGISTRY:=localhost:5000}"

# Guest-reachable registry for the live boot-pull (stage 07). The guest resolves
# the fragment feed itself and allows plain HTTP only for its own loopback
# (policy_fragments.rs:236), so a real fetch needs HTTPS with a publicly trusted
# certificate and anonymous pull. E2E_ACR=auto provisions an ACR that satisfies
# both; set it to a registry name to reuse one, or to "" to stay on the loopback
# registry and skip 07c/07d.
: "${E2E_ACR:=}"
: "${E2E_ACR_RG:=$E2E_RG}"
: "${E2E_ACR_SKU:=Standard}"

E2E_STATE_DIR="${E2E_STATE_DIR:-$HOME/.coco-e2e}"
mkdir -p "$E2E_STATE_DIR"

# ---------------------------------------------------------------------- logging
_c_red=$'\033[31m'; _c_grn=$'\033[32m'; _c_yel=$'\033[33m'
_c_blu=$'\033[34m'; _c_off=$'\033[0m'

log()   { printf '%s[e2e]%s %s\n'  "$_c_blu" "$_c_off" "$*"; }
ok()    { printf '%s[ ok]%s %s\n'  "$_c_grn" "$_c_off" "$*"; }
warn()  { printf '%s[warn]%s %s\n' "$_c_yel" "$_c_off" "$*"; }
die()   { printf '%s[FAIL]%s %s\n' "$_c_red" "$_c_off" "$*" >&2; exit 1; }

step()  { printf '\n%s========== %s ==========%s\n' "$_c_blu" "$*" "$_c_off"; }

# Mark a step complete so re-running the suite skips it.
mark_done()   { touch "$E2E_STATE_DIR/$1.done"; }
is_done()     { [ -f "$E2E_STATE_DIR/$1.done" ]; }
skip_if_done() {
  if is_done "$1" && [ "${E2E_FORCE:-0}" != "1" ]; then
    ok "$1 already complete (rm $E2E_STATE_DIR/$1.done or set E2E_FORCE=1 to redo)"
    exit 0
  fi
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

# ------------------------------------------------------------------ path guard
# True when every member of a tarball is confined to ./opt/kata/. On failure the
# reason is printed on stdout and the return is non-zero; nothing is printed on
# success. It lives here, rather than inline in the one call site, so that
# test-path-guard.sh exercises the same copy the install path runs — a guard and
# a test that each carry their own transcription of the predicate can drift apart
# silently, and the drift is invisible precisely when the guard has been weakened.
#
# The caller extracts as root into /, so every path in the archive is trusted.
# Today these tarballs only contain ./opt/kata/..., but a packaging change that
# widened them would overwrite arbitrary root-owned files.
tarball_confined() {
  local t="$1" listing escaping stray
  # List and filter in separate steps. Folding them into one pipeline with
  # `|| true` would let a tar failure (corrupt archive, missing zstd) produce an
  # empty stream that reads exactly like a clean archive — the guard would then
  # pass by failing, which is the bug class this function exists to avoid.
  listing=$(tar --zstd -tf "$t" 2>/dev/null) || { echo "cannot list $t"; return 1; }
  [ -n "$listing" ] || { echo "$t lists no members"; return 1; }
  if grep -q '\.\.' <<<"$listing"; then
    echo "$t contains .. in a member path"; return 1
  fi
  # Prefix matching alone would accept a symlink member under ./opt/kata/ that
  # points outside it, and any subsequent member written through that link. The
  # rootfs tarball legitimately carries one symlink (kata-containers.img ->
  # kata-ubuntu-noble.image), so reject by target, not by member type: a relative
  # target that stays inside the payload is fine, absolute or ..-escaping is not.
  escaping=$(tar --zstd -tvf "$t" 2>/dev/null | grep ' -> ' | awk -F' -> ' '$2 ~ /^\/|\.\./' || true)
  if [ -n "$escaping" ]; then
    echo "$t contains symlinks pointing outside the payload:
$escaping"; return 1
  fi
  # Some tarballs carry the ancestor directories as their own entries (./, ./opt,
  # ./opt/kata). Those are the path to the payload, not a widening of it, and
  # extracting them changes nothing, so allow exactly those three and no more.
  stray=$(grep -v '^\./opt/kata/' <<<"$listing" \
    | grep -vx '\./' | grep -vx '\./opt/' | grep -vx '\./opt/kata/' || true)
  if [ -n "$stray" ]; then
    echo "$t contains paths outside ./opt/kata/:
$stray"; return 1
  fi
  return 0
}

# ------------------------------------------------------- guest-provenance guard
# Fail unless the guest currently deployed is the one stage 04 built and installed.
#
# Every cluster-level assertion in stages 05+ is a statement about the hardened
# agent. Run against the CI-nightly guest instead, they all still "pass" — the pod
# boots, and the negatives fail for the wrong reason (no strict-policy build means
# no mediation and no boot-pull at all). That is a false green in the direction
# that matters, so the check is a hard gate rather than a warning.
#
# It lives here so 05 and 07 share one copy: two transcriptions of the same
# predicate drift apart silently, and the drift is invisible exactly when one of
# them has been weakened.
assert_local_guest_installed() {
  local rec="$E2E_STATE_DIR/guest-image-sha256"
  local img="$E2E_GUEST_IMAGE"
  [ -f "$rec" ] || die "no record of a locally built guest image — run 04-build-guest-stack.sh first"
  [ -f "$img" ] || die "missing $img"
  [ "$(sha256sum "$img" | cut -d' ' -f1)" = "$(cat "$rec")" ] \
    || die "$img is not the image stage 04 installed — re-run stage 04 (E2E_FORCE=1)"

  # The runtime pins the guest to a dm-verity root hash. If the configured hash is
  # the one from our build, then a pod that reaches Running can only have booted
  # our image: any other rootfs fails verity and never starts. Stage 04 patches
  # every config it finds, so read back exactly what it recorded instead of
  # guessing which config the runtime class resolves to.
  #
  # On clh-snp that hash is not in any config file to read back: uvm_build.sh
  # bakes it into the guest kernel command line inside the IGVM. The IGVM is
  # therefore the artefact that carries the pin, and asserting it is the one we
  # built is the same claim by a different route — a tampered rootfs fails verity
  # against a hash the IGVM measurement covers.
  if [ "$E2E_PLATFORM" = "clh-snp" ]; then
    local igvm_rec="$E2E_STATE_DIR/guest-igvm-sha256"
    [ -s "$igvm_rec" ] || die "no recorded IGVM digest — re-run stage 04"
    [ -f "$E2E_GUEST_IGVM" ] || die "missing $E2E_GUEST_IGVM"
    [ "$(sha256sum "$E2E_GUEST_IGVM" | cut -d' ' -f1)" = "$(cat "$igvm_rec")" ] \
      || die "$E2E_GUEST_IGVM is not the IGVM stage 04 installed — re-run stage 04 (E2E_FORCE=1)"
    ok "guest pinned by IGVM measurement to the locally built image"
    ok "testing guest built from $(cat "$E2E_STATE_DIR/guest-image-commit" 2>/dev/null || echo unknown)"
    return 0
  fi

  local params_rec="$E2E_STATE_DIR/guest-verity-params"
  local cfg_rec="$E2E_STATE_DIR/guest-config-paths"
  [ -s "$params_rec" ] || die "no recorded dm-verity parameters — re-run stage 04"
  [ -s "$cfg_rec" ]    || die "no recorded runtime config paths — re-run stage 04"
  local cfgs=()
  mapfile -t cfgs < "$cfg_rec"
  [ "${#cfgs[@]}" -gt 0 ] || die "no runtime config paths recorded by stage 04"
  local cfg
  for cfg in "${cfgs[@]}"; do
    [ -f "$cfg" ] || die "runtime config recorded by stage 04 is gone: $cfg"
    grep -qF "$(cat "$params_rec")" "$cfg" \
      || die "dm-verity hash in $cfg does not match the installed image — re-run stage 04"
  done
  ok "guest pinned by dm-verity to the locally built image (${#cfgs[@]} config(s))"
  ok "testing guest built from $(cat "$E2E_STATE_DIR/guest-image-commit" 2>/dev/null || echo unknown)"
}

# Wait until a shell predicate succeeds.  wait_for <timeout-s> <desc> <cmd...>
# Fatal on timeout. Use wait_for_soft when the caller needs to print diagnostics
# before giving up — `if ! wait_for ...` never runs its else branch, because the
# timeout exits the script from inside the callee.
wait_for() { wait_for_soft "$@" || die "timed out after ${1}s waiting for: $2"; }

# Same, but returns 1 on timeout instead of exiting.
wait_for_soft() {
  local timeout="$1" desc="$2"; shift 2
  local deadline=$(( $(date +%s) + timeout ))
  log "waiting up to ${timeout}s for: $desc"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if "$@" >/dev/null 2>&1; then ok "$desc"; return 0; fi
    sleep 5
  done
  return 1
}

# True only when at least one node exists and every node reports Ready. A
# `grep -qv NotReady` is not equivalent: it succeeds as soon as any single line
# is not NotReady, so a half-broken cluster reads as healthy.
all_nodes_ready() {
  local out
  out=$(kubectl get nodes --no-headers 2>/dev/null) || return 1
  [ -n "$out" ] || return 1
  ! awk '{print $2}' <<<"$out" | grep -qvx Ready
}

# Load the cluster/runtime environment. Sourced before every gha-run.sh invocation.
load_coco_env() {
  local f="${1:-$HOME/coco-env.sh}"
  [ -f "$f" ] || die "missing $f — run 03-deploy-cluster.sh first (it writes this file)"
  # shellcheck disable=SC1090
  . "$f"
  export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
}

# Make cargo/go/kubectl reachable in non-interactive ssh sessions, which do not
# source ~/.bashrc or ~/.cargo/env.
load_toolchain() {
  export PATH="$PATH:$HOME/.cargo/bin:/usr/local/go/bin:$HOME/gopath/bin"
  export GOROOT="${GOROOT:-/usr/local/go}"
  export GOPATH="${GOPATH:-$HOME/gopath}"
}

# Build genpolicy from the branch and export GENPOLICY pointing at it.
#
# The binary installed under /opt/kata comes from the upstream CI nightly and is
# not rebuilt by any stage, so it lags the branch by however long the nightly is
# old. genpolicy re-serialises its settings through a typed struct, so the two
# desync in both directions:
#
#   - a binary that PREDATES a settings key drops it silently (CI-9: the nightly
#     predated SignalProcessRequest.allowed_signals, so generated policies denied
#     SIGKILL and every pod started was left unkillable);
#   - a binary that POSTDATES the branch rejects the settings outright
#     ("Merged settings are invalid: missing field ..."), which reads like a
#     porting defect but is only a vintage mismatch.
#
# A tool is only interchangeable with its source when it is built from it. Do not
# reintroduce a feature probe here: a probe for one flag says nothing about the
# settings schema, and the nightly has passed such probes while still being stale.
#
# Only the binary is branch-built. The settings and rules under /opt/kata are
# installed from the branch by stage 03 (with the deliberate oci_version patch it
# applies to match the installed runtime), so callers should keep using those.
#
# src/version.rs is generated from src/version.rs.in by genpolicy's Makefile and
# is gitignored, so a bare `cargo build` fails with E0583 on a fresh checkout.
# Reproduce just that one substitution rather than invoking `make`, whose build
# target also cross-compiles to $TRIPLE and runs `cargo test --no-run`.
ensure_branch_genpolicy() {
  local gp_src="$E2E_REPO_DIR/src/tools/genpolicy" gp_commit

  [ -f "$gp_src/src/version.rs.in" ] || die "missing $gp_src/src/version.rs.in"
  gp_commit=$(git -C "$E2E_REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
  [ -n "$(git -C "$E2E_REPO_DIR" status --porcelain --untracked-files=no 2>/dev/null)" ] \
    && gp_commit="$gp_commit-dirty"
  sed -e "s|@COMMIT_INFO@|$gp_commit|g" "$gp_src/src/version.rs.in" > "$gp_src/src/version.rs" \
    || die "could not generate $gp_src/src/version.rs"

  # genpolicy is a member of the root workspace (see the repo-root Cargo.toml),
  # so the artifact lands in the workspace target dir, not under src/tools.
  log "building genpolicy from ${E2E_BRANCH:-the branch} ($gp_commit)"
  ( cd "$E2E_REPO_DIR" && cargo build --release -p genpolicy ) \
    || die "could not build genpolicy from the branch"

  GENPOLICY="$E2E_REPO_DIR/target/release/genpolicy"
  [ -x "$GENPOLICY" ] || die "genpolicy built but $GENPOLICY is missing"
  export GENPOLICY
  ok "using genpolicy from the branch: $GENPOLICY"
}

# Export GP_RULES / GP_SETTINGS — the rules.rego and genpolicy-settings.json that
# genpolicy should be driven with on this platform.
#
# These are deliberately NOT derived from $E2E_KATA_DEFAULTS unconditionally,
# because the two platforms disagree about whether that directory has genpolicy
# inputs in it at all:
#
#   qemu-coco-dev  kata-deploy lays down upstream's copies and stage 03 then
#                  overwrites them with the branch's, plus the oci_version patch
#                  that matches the installed containerd. Use those — re-deriving
#                  them here would drop the patch and deny every pod at
#                  CreateContainerRequest.
#   clh-snp        the confpods flow installs no genpolicy, no rules.rego and no
#                  settings whatsoever (grep the node-builder scripts: genpolicy
#                  is never mentioned). There is nothing to consume, so stage the
#                  branch copies into a suite-owned directory and apply the same
#                  oci_version patch stage 03 applies on the other platform.
ensure_genpolicy_defaults() {
  case "$E2E_PLATFORM" in
    qemu-coco-dev)
      GP_RULES="$E2E_KATA_DEFAULTS/rules.rego"
      GP_SETTINGS="$E2E_KATA_DEFAULTS/genpolicy-settings.json"
      [ -f "$GP_RULES" ]    || die "missing $GP_RULES — run stage 03 first"
      [ -f "$GP_SETTINGS" ] || die "missing $GP_SETTINGS — run stage 03 first"
      ;;
    clh-snp)
      local src="$E2E_REPO_DIR/src/tools/genpolicy" dst="$E2E_STATE_DIR/genpolicy"
      mkdir -p "$dst"
      for f in rules.rego genpolicy-settings.json; do
        [ -f "$src/$f" ] || die "missing $src/$f — genpolicy inputs are not where the suite expects them"
        install -m 0644 "$src/$f" "$dst/$f" || die "could not stage $f into $dst"
      done
      GP_RULES="$dst/rules.rego"
      GP_SETTINGS="$dst/genpolicy-settings.json"
      # containerd 2.3.x emits OCI spec 1.3.0 while the branch's settings still
      # say 1.1.0, which denies *every* pod at CreateContainerRequest.
      if grep -q '"oci_version": "1.1.0"' "$GP_SETTINGS" 2>/dev/null; then
        log "patching oci_version 1.1.0 -> 1.3.0 in $GP_SETTINGS"
        sed -i 's/"oci_version": "1.1.0"/"oci_version": "1.3.0"/' "$GP_SETTINGS"
      fi
      ;;
  esac
  export GP_RULES GP_SETTINGS
  ok "genpolicy inputs: $GP_RULES"
}

# Provision (or adopt) the guest-reachable registry the live boot-pull needs, and
# export ACR_LOGIN_SERVER / ACR_USERNAME / ACR_PASSWORD.
#
# Returns non-zero — without dying — when it cannot get there, so callers can
# fall back to the loopback registry. A missing registry costs coverage, not
# correctness: the stages that need it skip themselves and say so.
#
# Two ways in:
#   1. Pre-provisioned. Export E2E_ACR_LOGIN_SERVER (+ optionally
#      E2E_ACR_USERNAME/E2E_ACR_PASSWORD) and nothing here shells out to az.
#      Use this when the node has no Azure credentials — provision from the
#      workstation and hand the values over.
#   2. E2E_ACR set. Creates or adopts that registry with `az` wherever this runs.
ensure_acr() {
  if [ -n "${E2E_ACR_LOGIN_SERVER:-}" ]; then
    ACR_LOGIN_SERVER="$E2E_ACR_LOGIN_SERVER"
    ACR_USERNAME="${E2E_ACR_USERNAME:-}"
    ACR_PASSWORD="${E2E_ACR_PASSWORD:-}"
    export ACR_LOGIN_SERVER ACR_USERNAME ACR_PASSWORD
    ok "using pre-provisioned registry $ACR_LOGIN_SERVER"
    return 0
  fi

  [ -n "${E2E_ACR:-}" ] || return 1

  command -v az >/dev/null 2>&1 || {
    warn "az is not installed here — cannot provision a registry"
    warn "provision one elsewhere and re-run with E2E_ACR_LOGIN_SERVER/_USERNAME/_PASSWORD set"
    return 1
  }
  az account show >/dev/null 2>&1 || {
    warn "az is not logged in here — run 'az login' or set E2E_ACR_LOGIN_SERVER/_USERNAME/_PASSWORD"
    return 1
  }

  local name="$E2E_ACR"
  if [ "$name" = auto ]; then
    # Derive a stable, globally-unique-ish name from the subscription and
    # resource group so repeated runs adopt the same registry instead of
    # littering the subscription. ACR names are 5-50 lowercase alphanumerics.
    local sub seed
    sub=$(az account show --query id -o tsv) || return 1
    seed=$(printf '%s/%s' "$sub" "$E2E_ACR_RG" | sha256sum | cut -c1-12)
    name="cocoe2e$seed"
  fi

  if az acr show -n "$name" -g "$E2E_ACR_RG" >/dev/null 2>&1; then
    log "adopting existing registry $name"
  else
    log "creating registry $name in $E2E_ACR_RG ($E2E_ACR_SKU, $E2E_REGION)"
    # Anonymous pull is deliberately not set here: older az does not accept
    # --anonymous-pull-enabled on `acr create`. The assertion below turns it on
    # either way, and has to run anyway for adopted registries.
    az acr create -n "$name" -g "$E2E_ACR_RG" --sku "$E2E_ACR_SKU" \
        --location "$E2E_REGION" -o none || {
      warn "could not create registry $name"
      return 1
    }
  fi

  # Assert rather than assume: the guest pulls the fragment anonymously, and
  # anonymous pull can be off on an adopted registry or turned off later. It also
  # requires Standard or better — Basic rejects it outright.
  local anon
  anon=$(az acr show -n "$name" -g "$E2E_ACR_RG" \
           --query anonymousPullEnabled -o tsv 2>/dev/null) || anon=""
  if [ "$anon" != true ]; then
    log "enabling anonymous pull on $name (was: ${anon:-unset})"
    az acr update -n "$name" -g "$E2E_ACR_RG" --anonymous-pull-enabled true -o none || {
      warn "could not enable anonymous pull on $name — the guest could not fetch the fragment"
      return 1
    }
  fi

  ACR_LOGIN_SERVER=$(az acr show -n "$name" -g "$E2E_ACR_RG" --query loginServer -o tsv) || return 1
  # A refresh token beats admin credentials: it is short-lived and does not
  # require the registry's admin user to be enabled at all.
  ACR_PASSWORD=$(az acr login -n "$name" --expose-token --query accessToken -o tsv 2>/dev/null) || {
    warn "could not mint a push token for $name"
    return 1
  }
  ACR_USERNAME=00000000-0000-0000-0000-000000000000
  export ACR_LOGIN_SERVER ACR_USERNAME ACR_PASSWORD
  ok "registry ready: $ACR_LOGIN_SERVER (anonymous pull on)"
}

# Platform-specific helpers, sourced last so they can use everything above. Only
# the selected platform's module is loaded: the clh-snp one assumes Azure Linux
# and would be nothing but a loaded footgun on the QEMU path.
if [ "$E2E_PLATFORM" = "clh-snp" ]; then
  # shellcheck source=platform-clh-snp.sh
  . "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/platform-clh-snp.sh"
fi
