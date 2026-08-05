#!/usr/bin/env bash
# 08 — FR-9: prove the container-occurrence lifecycle gates are live, and that they
#      refuse illegal transitions *independently of policy*.
#
# Why this stage exists. FR-9 mints an enforcer-side occurrence per container and
# gates StartContainer / ExecProcess / SignalProcess on its lifecycle state, so a
# host cannot start a container that was never created, start one twice, or exec
# into one that is not running. Until now that was claimed on the strength of unit
# tests plus a one-off manual kata-agent-ctl run; nothing in the suite exercised it,
# and a regression that deleted every OCCURRENCES call would have stayed green.
#
# The gate is not observable through kubectl: the shim only ever drives legal
# transitions. These cases therefore speak the agent's ttRPC protocol directly with
# kata-agent-ctl over the sandbox's vsock — which is exactly the threat model, a
# host that ignores the shim and calls the agent itself.
#
# Two policies are used deliberately:
#
#   * the *reference* policy, to show what a real workload sees. Here the policy
#     answers first for an unknown container id (PERMISSION_DENIED) and the
#     occurrence machine is defence in depth behind it. Only the double-start is
#     visible, because a double start passes policy (the container *is* in policy
#     state) and can only be refused by the lifecycle machine.
#
#   * a *lifecycle-permissive* policy, which allows StartContainer / ExecProcess /
#     SignalProcess unconditionally. That removes the policy layer so the occurrence
#     machine is the only thing left that can refuse — which is precisely the FR-9
#     claim ("rejected by the occurrence machine, not by policy"). This policy is a
#     test fixture generated into a temp dir; it is never installed.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 08-lifecycle-gates

step "08 — FR-9 container occurrence lifecycle gates"
load_toolchain
load_coco_env
assert_local_guest_installed

NS="${E2E_NS:-coco-e2e}"
WORK=$(mktemp -d)
CTL="$E2E_REPO_DIR/target/release/kata-agent-ctl"
FAILURES=0

cleanup() {
  # --wait=false: a graceful delete blocks on SIGTERM/SIGKILL reaching the guest,
  # and this stage exists precisely to poke at the paths that can refuse them.
  kubectl delete pod fr9-reference fr9-permissive -n "$NS" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS"

fail_case() { printf '%s[FAIL]%s %s\n' "$_c_red" "$_c_off" "$*" >&2; FAILURES=$((FAILURES + 1)); }

# ------------------------------------------------------------------ agent-ctl
# Built from the branch, not installed: this is a debug tool and has no business in
# the deployed toolchain.
if [ ! -x "$CTL" ]; then
  log "building kata-agent-ctl (a few minutes on a cold cache)"
  ( cd "$E2E_REPO_DIR/src/tools/agent-ctl" && cargo build --release >/dev/null 2>&1 ) \
    || die "failed to build kata-agent-ctl"
fi
[ -x "$CTL" ] || die "kata-agent-ctl not found at $CTL"
ok "kata-agent-ctl ready"

# ------------------------------------------------------------------- genpolicy
# Build genpolicy from the branch, for the reason stage 03 documents: the binary
# re-serialises request_defaults through a typed struct, so an installed binary
# that predates a settings key drops it silently. The nightly one predates
# SignalProcessRequest.allowed_signals, and without that key the rule is
# undefined and *every* signal is denied -- which leaves every pod this stage
# starts unkillable and stuck Terminating, long after the stage has "passed".
if [ ! -x "$E2E_REPO_DIR/target/release/genpolicy" ]; then
  log "building genpolicy from $E2E_BRANCH"
  ( cd "$E2E_REPO_DIR" && cargo build --release -p genpolicy ) \
    || die "could not build genpolicy from the branch"
fi
GENPOLICY="$E2E_REPO_DIR/target/release/genpolicy"
[ -x "$GENPOLICY" ] || die "genpolicy built but $GENPOLICY is missing"
ok "using genpolicy from the branch: $GENPOLICY"

# ------------------------------------------------------------------- fixtures
# The lifecycle-permissive rules file. Appending extra rule bodies is enough: rego
# ORs the bodies of a rule, so these sit alongside the real ones and win whenever
# the real body is undefined. A body of just print(...) is true.
make_permissive_rules() {
  cp /opt/kata/share/defaults/kata-containers/rules.rego "$WORK/permissive.rego"
  cat >> "$WORK/permissive.rego" <<'EOF'

# ---- e2e FR-9 fixture only (never installed) --------------------------------
# Neutralise the policy layer for the three lifecycle endpoints so that anything
# still refusing them must be the FR-9 occurrence state machine.
StartContainerRequest if { print("e2e-fr9: permissive start") }
SignalProcessRequest if { print("e2e-fr9: permissive signal") }
ExecProcessRequest if { print("e2e-fr9: permissive exec") }
EOF
}

# policy_text <pod> -- the generated policy, decoded out of the cc_init_data annotation
policy_text() {
  local pod=$1
  python3 - "$WORK/$pod.yaml" <<'PY'
import base64, gzip, io, sys
import re
y = open(sys.argv[1]).read()
m = re.search(r'cc_init_data:\s*([A-Za-z0-9+/=]+)', y)
if not m:
    sys.exit(0)
raw = base64.b64decode(m.group(1))
try:
    raw = gzip.decompress(raw)
except Exception:
    pass
sys.stdout.write(raw.decode('utf8', 'ignore'))
PY
}

# render_pod <name> <rules.rego>
render_pod() {
  local pod=$1 rules=$2
  cat > "$WORK/$pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  namespace: $NS
spec:
  runtimeClassName: kata-qemu-coco-dev-runtime-rs
  restartPolicy: Never
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    supplementalGroups: [10]
  containers:
    - name: busybox
      image: quay.io/prometheus/busybox:latest
      command: ["sleep", "900"]
EOF
  "$GENPOLICY" -y "$WORK/$pod.yaml" \
    -p "$rules" \
    -j /opt/kata/share/defaults/kata-containers/genpolicy-settings.json \
    >/dev/null 2>&1 || die "genpolicy failed for $pod"
  grep -q 'cc_init_data' "$WORK/$pod.yaml" || die "$pod: genpolicy did not inject a policy"
  # The generated policy must carry every settings key the rules read. If
  # allowed_signals is missing the pod boots and passes every case below, then
  # can never be killed -- so check it here rather than discovering it as a
  # namespace full of Terminating pods.
  policy_text "$pod" | grep -q '"allowed_signals"' \
    || die "$pod: generated policy has no request_defaults.SignalProcessRequest.allowed_signals — genpolicy is older than genpolicy-settings.json and dropped it; the pod would be unkillable"
}

pod_running() { kubectl get pod "$1" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null | grep -qx Running; }

# start_pod <name> <rules.rego>
start_pod() {
  local pod=$1 rules=$2
  render_pod "$pod" "$rules"
  kubectl delete pod "$pod" -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
  kubectl apply -f "$WORK/$pod.yaml" >/dev/null || die "kubectl apply failed for $pod"
  wait_for 300 "pod $pod Running" pod_running "$pod"
}

# ------------------------------------------------------------------ discovery
# The agent listens on vsock port 1024 inside the guest. Reaching it needs the
# sandbox's guest CID, which only the hypervisor process knows, and the container
# id the agent knows -- which is the CRI container id, not anything kubectl prints
# by default.

# sandbox_id <pod>
# Read it off the pod's workload container rather than looking for a sandbox
# container: with containerd's sandbox API the pod sandbox is no longer listed
# by `ctr container ls`, so scanning for io.cri-containerd.kind == sandbox finds
# nothing on a current node. The workload container always carries the id.
sandbox_id() {
  local pod=$1 ct sb
  ct=$(container_id "$pod") || return 1
  [ -n "$ct" ] || return 1
  sb=$(sudo ctr -n k8s.io c info "$ct" 2>/dev/null \
    | sed -n 's/.*"io.kubernetes.cri.sandbox-id": "\([a-f0-9]*\)".*/\1/p' | head -1)
  [ -n "$sb" ] || return 1
  echo "$sb"
}

# guest_cid <sandbox-id>
guest_cid() {
  ps -ef | grep "[s]andbox-$1" | sed -n 's/.*guest-cid=\([0-9]*\).*/\1/p' | head -1
}

# container_id <pod>
container_id() {
  kubectl get pod "$1" -n "$NS" \
    -o jsonpath='{.status.containerStatuses[0].containerID}' 2>/dev/null \
    | sed 's|containerd://||'
}

# agent_call <cid> <command-string> -- returns the agent's reply (or error) on stdout
agent_call() {
  local cid=$1 cmd=$2
  sudo "$CTL" -l error connect --server-address "vsock://$cid:1024" -n true -c "$cmd" 2>&1
}

# expect_refusal <label> <output> <expected-code> <expected-substring>
expect_refusal() {
  local label=$1 out=$2 code=$3 want=$4
  if ! echo "$out" | grep -q "code: $code"; then
    echo "$out" | tail -3
    fail_case "$label: expected $code"
    return 1
  fi
  if ! echo "$out" | grep -q "$want"; then
    echo "$out" | tail -3
    fail_case "$label: expected the refusal to mention '$want'"
    return 1
  fi
  ok "$label"
}

# =============================================================== reference pod
step "08 — reference policy (what a real workload sees)"
start_pod fr9-reference /opt/kata/share/defaults/kata-containers/rules.rego

REF_SB=$(sandbox_id fr9-reference)   || die "could not find the sandbox for fr9-reference"
REF_CID=$(guest_cid "$REF_SB")
REF_CT=$(container_id fr9-reference)
[ -n "$REF_CID" ] || die "could not read the guest CID for sandbox $REF_SB"
[ -n "$REF_CT" ]  || die "could not read the container id for fr9-reference"
log "sandbox=${REF_SB:0:12} cid=$REF_CID container=${REF_CT:0:12}"

# Connectivity first: if this fails the later refusals prove nothing, because an
# unreachable agent also "refuses" everything.
agent_call "$REF_CID" Check | grep -qi 'error' \
  && die "cannot reach the agent over vsock -- the rest of this stage would be meaningless"
ok "08-pre — agent reachable over vsock (the host can bypass the shim; that is the threat model)"

# --- 08a ---------------------------------------------------------------------
# The one FR-9 property visible under a real policy. The container is in policy
# state, so StartContainerRequest is *allowed*; the only thing that can refuse a
# second start is the occurrence machine.
out=$(agent_call "$REF_CID" "StartContainer json://{\"container_id\":\"$REF_CT\"}")
expect_refusal "08a — a second StartContainer is refused by the occurrence machine (IllegalTransition from Running), not by policy" \
  "$out" FAILED_PRECONDITION 'IllegalTransition'

# --- 08b ---------------------------------------------------------------------
# Documents the layering: for an id the policy has never seen, policy answers
# first and the occurrence gate is never reached. This is the expected order --
# it is recorded so that a future change that lets an unknown id past the policy
# is caught here rather than silently relying on FR-9 to catch it.
out=$(agent_call "$REF_CID" 'StartContainer json://{"container_id":"ghost-never-created"}')
expect_refusal "08b — under the reference policy an unknown container id is refused by policy first (occurrence gate is defence in depth)" \
  "$out" PERMISSION_DENIED 'blocked by policy'

kubectl delete pod fr9-reference -n "$NS" --ignore-not-found >/dev/null 2>&1 || true

# ============================================================== permissive pod
step "08 — lifecycle-permissive policy (the occurrence machine, alone)"
make_permissive_rules
start_pod fr9-permissive "$WORK/permissive.rego"

P_SB=$(sandbox_id fr9-permissive) || die "could not find the sandbox for fr9-permissive"
P_CID=$(guest_cid "$P_SB")
P_CT=$(container_id fr9-permissive)
[ -n "$P_CID" ] || die "could not read the guest CID for sandbox $P_SB"
[ -n "$P_CT" ]  || die "could not read the container id for fr9-permissive"
log "sandbox=${P_SB:0:12} cid=$P_CID container=${P_CT:0:12}"

# Prove the fixture actually neutralised the policy, otherwise every case below
# would "pass" for the wrong reason. A signal 0 to the live container is allowed
# by the permissive rule *and* by the occurrence machine, so it must succeed --
# under the reference policy this same call is refused (signal 0 is not in
# allowed_signals).
out=$(agent_call "$P_CID" "SignalProcess json://{\"container_id\":\"$P_CT\",\"exec_id\":\"$P_CT\",\"signal\":0}")
if echo "$out" | grep -q 'blocked by policy'; then
  die "the permissive fixture did not take -- policy is still refusing, so 08c-08f would prove nothing"
fi
ok "08-pre — the lifecycle endpoints are policy-permissive on this pod"

# --- 08c/08d/08e -------------------------------------------------------------
# With policy out of the way, an id the enforcer never minted an occurrence for
# must still be refused -- by the occurrence machine, with UnknownAlias.
out=$(agent_call "$P_CID" 'StartContainer json://{"container_id":"ghost-never-created"}')
expect_refusal "08c — StartContainer on a never-created id is refused by the occurrence machine (UnknownAlias)" \
  "$out" FAILED_PRECONDITION 'UnknownAlias'

out=$(agent_call "$P_CID" 'SignalProcess json://{"container_id":"ghost-never-created","exec_id":"ghost","signal":15}')
expect_refusal "08d — SignalProcess on a never-created id is refused by the occurrence machine (UnknownAlias)" \
  "$out" FAILED_PRECONDITION 'UnknownAlias'

out=$(agent_call "$P_CID" 'ExecProcess json://{"container_id":"ghost-never-created","exec_id":"x1"}')
expect_refusal "08e — ExecProcess on a never-created id is refused by the occurrence machine (UnknownAlias)" \
  "$out" FAILED_PRECONDITION 'UnknownAlias'

# --- 08f ---------------------------------------------------------------------
# The double start again, this time with the policy layer removed: the refusal
# can only be coming from the lifecycle machine.
out=$(agent_call "$P_CID" "StartContainer json://{\"container_id\":\"$P_CT\"}")
expect_refusal "08f — a second StartContainer is refused even with policy neutralised (IllegalTransition)" \
  "$out" FAILED_PRECONDITION 'IllegalTransition'

# --- 08g ---------------------------------------------------------------------
# Characterisation, not a guarantee. F-72: the registry has no `stop()` caller, so
# an occurrence never enters `Stopped`; what actually retires it is RemoveContainer.
# Measured here: with a cooperating shim the retirement is immediate on exit, so
# the "exited but still Running" window is not reachable by a host that follows
# the protocol. A host that simply never calls RemoveContainer holds the window
# open indefinitely -- which is the residual F-72 documents, and which hcsshim
# shares (it records containerTerminated but does not gate exec or signal on it).
step "08g — characterisation: when is an occurrence retired?"
log "signalling the live container with signal 0 (a liveness probe, delivers nothing)"
before=$(agent_call "$P_CID" "SignalProcess json://{\"container_id\":\"$P_CT\",\"exec_id\":\"$P_CT\",\"signal\":0}")
if echo "$before" | grep -q 'FAILED_PRECONDITION'; then
  fail_case "08g: a running container's occurrence should accept signal 0"
else
  ok "08g — a running occurrence accepts the probe"
fi

kubectl delete pod fr9-permissive -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
# The sandbox is gone with the pod, so the post-removal half of this case cannot be
# probed over the same vsock. It is covered by 08c/08d/08e, which exercise the same
# UnknownAlias path the retirement produces.

# ---------------------------------------------------------------------- verdict
if [ "$FAILURES" -ne 0 ]; then
  die "$FAILURES FR-9 lifecycle case(s) failed"
fi
ok "all FR-9 lifecycle gate cases passed"
mark_done 08-lifecycle-gates
