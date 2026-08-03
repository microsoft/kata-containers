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
# Standard_DC16as_cc_v5 is a SEV-SNP CC SKU. See README for the region/quota trap:
# availability and quota are independent, and each alone is a false green.
: "${E2E_VM_SIZE:=Standard_DC16as_cc_v5}"
: "${E2E_VM_IMAGE:=Canonical:ubuntu-24_04-lts:server:latest}"
# Standard, not ConfidentialVM — see the comment in 01-provision-vm.sh. Set to
# ConfidentialVM only with an image whose sku supports it (e.g. ...:cvm:latest).
: "${E2E_VM_SECURITY_TYPE:=Standard}"
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
  local img=/opt/kata/share/kata-containers/kata-containers.img
  [ -f "$rec" ] || die "no record of a locally built guest image — run 04-build-guest-stack.sh first"
  [ -f "$img" ] || die "missing $img"
  [ "$(sha256sum "$img" | cut -d' ' -f1)" = "$(cat "$rec")" ] \
    || die "$img is not the image stage 04 installed — re-run stage 04 (E2E_FORCE=1)"

  # The runtime pins the guest to a dm-verity root hash. If the configured hash is
  # the one from our build, then a pod that reaches Running can only have booted
  # our image: any other rootfs fails verity and never starts. Stage 04 patches
  # every config it finds, so read back exactly what it recorded instead of
  # guessing which config the runtime class resolves to.
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
