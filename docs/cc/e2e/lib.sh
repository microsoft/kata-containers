#!/usr/bin/env bash
# Shared helpers and configuration for the CoCo end-to-end reproduction scripts.
# Source this from every step script:  . "$(dirname "$0")/lib.sh"

set -uo pipefail

# ----------------------------------------------------------------- configuration
# Everything here can be overridden from the environment.

: "${E2E_RG:=jiria-coco-cvm-rg}"
: "${E2E_VM:=coco-dev-1}"
: "${E2E_REGION:=eastus}"
# Standard_DC16as_cc_v5 is a SEV-SNP CC SKU. See README for the region/quota trap:
# availability and quota are independent, and each alone is a false green.
: "${E2E_VM_SIZE:=Standard_DC16as_cc_v5}"
: "${E2E_VM_IMAGE:=Canonical:ubuntu-24_04-lts:server:latest}"
: "${E2E_ADMIN:=$(whoami)}"
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

# Local dev registry used by the policy-fragment step.
: "${E2E_REGISTRY:=localhost:5000}"

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

# Wait until a shell predicate succeeds.  wait_for <timeout-s> <desc> <cmd...>
wait_for() {
  local timeout="$1" desc="$2"; shift 2
  local deadline=$(( $(date +%s) + timeout ))
  log "waiting up to ${timeout}s for: $desc"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if "$@" >/dev/null 2>&1; then ok "$desc"; return 0; fi
    sleep 5
  done
  die "timed out after ${timeout}s waiting for: $desc"
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
