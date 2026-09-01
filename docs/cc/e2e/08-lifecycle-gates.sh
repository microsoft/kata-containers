#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
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
CTL="${E2E_REPO_DIR}/target/release/kata-agent-ctl"
FAILURES=0

cleanup() {
  # --wait=false: a graceful delete blocks on SIGTERM/SIGKILL reaching the guest,
  # and this stage exists precisely to poke at the paths that can refuse them.
  kubectl delete pod fr9-reference fr9-permissive -n "${NS}" \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

ensure_ns "${NS}"

fail_case() { printf '%s[FAIL]%s %s\n' "${_c_red}" "${_c_off}" "$*" >&2; FAILURES=$((FAILURES + 1)); }

# ------------------------------------------------------------------ agent-ctl
# Built from the branch, not installed: this is a debug tool and has no business in
# the deployed toolchain.
if [[ ! -x "${CTL}" ]]; then
  log "building kata-agent-ctl (a few minutes on a cold cache)"
  ( cd "${E2E_REPO_DIR}/src/tools/agent-ctl" && cargo build --release >/dev/null 2>&1 ) \
    || die "failed to build kata-agent-ctl"
fi
[[ -x "${CTL}" ]] || die "kata-agent-ctl not found at ${CTL}"
ok "kata-agent-ctl ready"

# ------------------------------------------------------------------- genpolicy
# Build genpolicy from the branch, for the reason ensure_branch_genpolicy()
# documents: the binary re-serialises request_defaults through a typed struct, so
# an installed binary that predates a settings key drops it silently. The nightly
# one predates SignalProcessRequest.allowed_signals, and without that key the rule
# is undefined and *every* signal is denied -- which leaves every pod this stage
# starts unkillable and stuck Terminating, long after the stage has "passed".
ensure_branch_genpolicy

# genpolicy also needs a settings file. Only ensure_genpolicy_defaults() knows
# which one is right for this platform -- and, on clh-snp, is the thing that
# stages it out of the branch and builds the drop-in directory at all. This
# stage overrides GP_RULES with REF_RULES below on purpose, but GP_SETTINGS
# must come from here or it is simply never set.
ensure_genpolicy_defaults

# The rules come from the branch too, and for the same reason: /opt/kata carries
# whatever the last kata-deploy or stage 03 run installed, which is not
# necessarily this commit. Testing a branch gate against a stale rules.rego
# passes or fails for reasons that have nothing to do with the branch.
REF_RULES="${E2E_REPO_DIR}/src/tools/genpolicy/rules.rego"
[[ -r "${REF_RULES}" ]] || die "cannot read the branch rules.rego at ${REF_RULES}"
ok "using rules.rego from the branch: ${REF_RULES}"

# ------------------------------------------------------------------- fixtures
# The lifecycle-permissive rules file. Appending extra rule bodies is enough: rego
# ORs the bodies of a rule, so these sit alongside the real ones and win whenever
# the real body is undefined. A body of just print(...) is true.
make_permissive_rules() {
  cp "${REF_RULES}" "${WORK}/permissive.rego"
  cat >> "${WORK}/permissive.rego" <<'EOF'

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
  python3 - "${WORK}/${pod}.yaml" <<'PY'
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
# POD_WITH_EXITER=1 adds a second container that runs to completion immediately.
# The pod stays Running on the first container, so its sandbox -- and the exited
# container's occurrence -- remain reachable over vsock, which is what makes the
# post-exit gates (08h/08i) observable at all.
render_pod() {
  local pod=$1 rules=$2
  cat > "${WORK}/${pod}.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
  namespace: ${NS}
spec:
  runtimeClassName: ${E2E_RUNTIMECLASS}
$(pod_pin)
  restartPolicy: Never
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    supplementalGroups: [10]
  containers:
    - name: busybox
      image: ${E2E_BUSYBOX_IMAGE}
      command: ["sleep", "900"]
EOF
  if [[ "${POD_WITH_EXITER:-0}" = 1 ]]; then
    cat >> "${WORK}/${pod}.yaml" <<EOF
    - name: exiter
      image: ${E2E_BUSYBOX_IMAGE}
      command: ["true"]
EOF
  fi
  "${GENPOLICY}" -y "${WORK}/${pod}.yaml" \
    -p "${rules}" \
    -j "${GP_SETTINGS}" \
    >/dev/null 2>&1 || die "genpolicy failed for ${pod}"
  grep -q 'cc_init_data' "${WORK}/${pod}.yaml" || die "${pod}: genpolicy did not inject a policy"
  # The generated policy must carry every settings key the rules read. If
  # allowed_signals is missing the pod boots and passes every case below, then
  # can never be killed -- so check it here rather than discovering it as a
  # namespace full of Terminating pods.
  #
  # Matched via a here-string rather than a pipe on purpose: `grep -q` exits at
  # the first match, which SIGPIPEs the still-writing python producer, and under
  # `set -o pipefail` that turns a successful match into a failed pipeline. The
  # policy only has to be large enough for the producer not to have finished
  # yet, so the bug is a size-dependent race that appears the moment the policy
  # grows. A here-string has no producer process, so it cannot happen.
  grep -q '"allowed_signals"' <<<"$(policy_text "${pod}")" \
    || die "${pod}: generated policy has no request_defaults.SignalProcessRequest.allowed_signals — genpolicy is older than genpolicy-settings.json and dropped it; the pod would be unkillable"
}

pod_running() { kubectl get pod "$1" -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null | grep -qx Running; }

# start_pod <name> <rules.rego>
start_pod() {
  local pod=$1 rules=$2
  render_pod "${pod}" "${rules}"
  kubectl delete pod "${pod}" -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl apply -f "${WORK}/${pod}.yaml" >/dev/null || die "kubectl apply failed for ${pod}"
  wait_for 300 "pod ${pod} Running" pod_running "${pod}"
}

# ------------------------------------------------------------------ discovery
# The agent listens on vsock port 1024 inside the guest. Reaching it needs an
# address only the hypervisor side knows, and the container id the agent knows --
# which is the CRI container id, not anything kubectl prints by default.
#
# The address is not the same shape on both platforms. QEMU gives the guest a
# real AF_VSOCK context id, so the host dials vsock://<cid>:1024. Cloud
# Hypervisor uses hybrid vsock instead: there is no host-visible CID, and the
# guest is reached through a unix socket that the shim creates per sandbox.
# agent_addr() therefore returns a whole server address rather than a CID, so
# the call sites below stay identical on both.

# sandbox_id <pod>
# Read it off the pod's workload container rather than looking for a sandbox
# container: with containerd's sandbox API the pod sandbox is no longer listed
# by `ctr container ls`, so scanning for io.cri-containerd.kind == sandbox finds
# nothing on a current node. The workload container always carries the id.
sandbox_id() {
  local pod=$1 ct sb
  ct=$(container_id "${pod}") || return 1
  [[ -n "${ct}" ]] || return 1
  sb=$(sudo ctr -n k8s.io c info "${ct}" 2>/dev/null \
    | sed -n 's/.*"io.kubernetes.cri.sandbox-id": "\([a-f0-9]*\)".*/\1/p' | head -1)
  [[ -n "${sb}" ]] || return 1
  echo "${sb}"
}

# agent_addr <sandbox-id> -- the server address to reach that sandbox's agent
agent_addr() {
  local sb=$1 sock
  if [[ "${E2E_PLATFORM}" = "clh-snp" ]]; then
    # The shim names this per sandbox under /run/kata. Wait for it: the pod can
    # report Running a moment before the socket is observable to us.
    sock="/run/kata/${sb}/ch-vm.sock"
    for _ in $(seq 1 20); do
      sudo test -S "${sock}" && { echo "unix://${sock}"; return 0; }
      sleep 1
    done
    return 1
  fi
  if [[ "${E2E_PLATFORM}" = "openvmm-snp" ]]; then
    sock="/run/kata/${sb}/vsock.sock"
    for _ in $(seq 1 20); do
      sudo test -S "${sock}" && { echo "unix://${sock}"; return 0; }
      sleep 1
    done
    return 1
  fi
  local cid
  # shellcheck disable=SC2009  # pgrep cannot be substituted here: we need the full
  # argv to sed guest-cid out of, and the [s] bracket idiom already prevents the
  # grep process from matching itself.
  cid=$(ps -ef | grep "[s]andbox-${sb}" | sed -n 's/.*guest-cid=\([0-9]*\).*/\1/p' | head -1)
  [[ -n "${cid}" ]] || return 1
  echo "vsock://${cid}:1024"
}

# container_id <pod> [container-name]
container_id() {
  local pod=$1 name=${2:-}
  if [[ -n "${name}" ]]; then
    kubectl get pod "${pod}" -n "${NS}" \
      -o jsonpath="{.status.containerStatuses[?(@.name=='${name}')].containerID}" 2>/dev/null \
      | sed 's|containerd://||'
  else
    kubectl get pod "${pod}" -n "${NS}" \
      -o jsonpath='{.status.containerStatuses[0].containerID}' 2>/dev/null \
      | sed 's|containerd://||'
  fi
}

# container_terminated <pod> <container-name>
container_terminated() {
  kubectl get pod "$1" -n "${NS}" \
    -o jsonpath="{.status.containerStatuses[?(@.name=='$2')].state.terminated.exitCode}" \
    2>/dev/null | grep -qx 0
}

# agent_call <address> <command-string> -- returns the agent's reply (or error) on stdout
# A unix:// address is a hybrid vsock socket, not a plain domain socket, and
# agent-ctl only treats it as one when told to.
agent_hvsock_flag() {
  case "$1" in unix://*) printf '%s' "--hybrid-vsock true" ;; *) printf '%s' "" ;; esac
}

agent_call() {
  local addr=$1 cmd=$2
  # shellcheck disable=SC2046  # the flag is deliberately word-split (it is empty on qemu)
  sudo "${CTL}" -l error connect --server-address "${addr}" $(agent_hvsock_flag "${addr}") -n true -c "${cmd}" 2>&1
}

# Same, but at info level, so a *successful* reply is visible ("response
# received"). Refusals are proved by their ttrpc status and need only -l error;
# successes have no output at that level at all.
agent_call_verbose() {
  local addr=$1 cmd=$2
  # shellcheck disable=SC2046
  sudo "${CTL}" -l info connect --server-address "${addr}" $(agent_hvsock_flag "${addr}") -n true -c "${cmd}" 2>&1
}

# expect_refusal <label> <output> <expected-code> <expected-substring>
expect_refusal() {
  local label=$1 out=$2 code=$3 want=$4
  if ! echo "${out}" | grep -q "code: ${code}"; then
    echo "${out}" | tail -3
    fail_case "${label}: expected ${code}"
    return 1
  fi
  if ! echo "${out}" | grep -q "${want}"; then
    echo "${out}" | tail -3
    fail_case "${label}: expected the refusal to mention '${want}'"
    return 1
  fi
  ok "${label}"
}

# =============================================================== reference pod
step "08 — reference policy (what a real workload sees)"
start_pod fr9-reference "${REF_RULES}"

REF_SB=$(sandbox_id fr9-reference)   || die "could not find the sandbox for fr9-reference"
REF_AGENT=$(agent_addr "${REF_SB}")
REF_CT=$(container_id fr9-reference)
[[ -n "${REF_AGENT}" ]] || die "could not work out the agent address for sandbox ${REF_SB}"
[[ -n "${REF_CT}" ]]  || die "could not read the container id for fr9-reference"
log "sandbox=${REF_SB:0:12} agent=${REF_AGENT} container=${REF_CT:0:12}"

# Connectivity first: if this fails the later refusals prove nothing, because an
# unreachable agent also "refuses" everything.
agent_call "${REF_AGENT}" Check | grep -qi 'error' \
  && die "cannot reach the agent over vsock -- the rest of this stage would be meaningless"
ok "08-pre — agent reachable over vsock (the host can bypass the shim; that is the threat model)"

# --- 08a ---------------------------------------------------------------------
# The one FR-9 property visible under a real policy. The container is in policy
# state, so StartContainerRequest is *allowed*; the only thing that can refuse a
# second start is the occurrence machine.
out=$(agent_call "${REF_AGENT}" "StartContainer json://{\"container_id\":\"${REF_CT}\"}")
expect_refusal "08a — a second StartContainer is refused by the occurrence machine (IllegalTransition from Running), not by policy" \
  "${out}" FAILED_PRECONDITION 'IllegalTransition'

# --- 08b ---------------------------------------------------------------------
# Documents the layering: for an id the policy has never seen, policy answers
# first and the occurrence gate is never reached. This is the expected order --
# it is recorded so that a future change that lets an unknown id past the policy
# is caught here rather than silently relying on FR-9 to catch it.
out=$(agent_call "${REF_AGENT}" 'StartContainer json://{"container_id":"ghost-never-created"}')
expect_refusal "08b — under the reference policy an unknown container id is refused by policy first (occurrence gate is defence in depth)" \
  "${out}" PERMISSION_DENIED 'blocked by policy'

# --- 08k / 08l ---------------------------------------------------------------
# F-77: SIGSTOP and SIGCONT are no longer in the shipped allow-list. Nothing in the
# CRI lifecycle sends them -- pausing a container uses the cgroup freezer, not
# signals -- while admitting them lets a malicious host freeze any workload process
# indefinitely and single-step it for timing observation. 19 and 18 were inherited
# from upstream's list; these two cases keep them out.
out=$(agent_call "${REF_AGENT}" "SignalProcess json://{\"container_id\":\"${REF_CT}\",\"exec_id\":\"\",\"signal\":19}")
expect_refusal "08k — SIGSTOP(19) is refused by policy (F-77: the host cannot freeze a workload)" \
  "${out}" PERMISSION_DENIED 'blocked by policy'

out=$(agent_call "${REF_AGENT}" "SignalProcess json://{\"container_id\":\"${REF_CT}\",\"exec_id\":\"\",\"signal\":18}")
expect_refusal "08l — SIGCONT(18) is refused by policy (F-77)" \
  "${out}" PERMISSION_DENIED 'blocked by policy'

# --- 08m / 08n ---------------------------------------------------------------
# F-76: the signal allow-list is per container, not per sandbox -- hcsshim's
# securityPolicyContainer.Signals parity. The pause container's set is narrowed to
# {SIGKILL, SIGTERM} by pause_container_allowed_signals, so a signal that is
# perfectly legal for the workload container must still be refused for the pause
# container of the *same* sandbox. Under a sandbox-global list both would be
# admitted, which is exactly the gap this pair is here to catch: a regression that
# reverts to the global list still passes 08k/08l but fails 08n.
#
# The pause container is addressed by the sandbox id: containerd creates a pod's
# sandbox container with the sandbox id as its container id.
out=$(agent_call "${REF_AGENT}" "SignalProcess json://{\"container_id\":\"${REF_CT}\",\"exec_id\":\"\",\"signal\":28}")
if echo "${out}" | grep -q 'blocked by policy'; then
  echo "${out}" | tail -3
  fail_case "08m — SIGWINCH(28) should be allowed for the workload container"
else
  ok "08m — SIGWINCH(28) is allowed for the workload container (positive control for 08n)"
fi

out=$(agent_call "${REF_AGENT}" "SignalProcess json://{\"container_id\":\"${REF_SB}\",\"exec_id\":\"\",\"signal\":28}")
expect_refusal "08n — the same SIGWINCH(28) is refused for the pause container of the same sandbox (F-76: per-container signal sets)" \
  "${out}" PERMISSION_DENIED 'blocked by policy'

# --- 08o / 08p ---------------------------------------------------------------
# RM-26: removing a container id the policy never admitted must succeed, exactly
# once.
#
# Refusing it is what left pods stuck in Terminating: when a CreateContainer is
# denied, the shim's cleanup still issues RemoveContainer for the same id, that
# was denied too, and the composition had no exit -- every individual decision
# correct, the pod unkillable. An operator experiences a correctly enforced
# denial as a hung workload, which is exactly the pressure that gets policies
# loosened, so this is asserted rather than left to the unit test.
#
# 08b directly above is the control that keeps this honest: it uses the *same*
# ghost id and shows StartContainer for it is still refused. The no-op is scoped
# to removal -- where there is nothing to act on -- not to unknown ids generally.
# A successful reply is proved positively rather than by the absence of an error,
# because kata-agent-ctl's RemoveContainer subcommand unmounts the container's
# rootfs *on the client side* after the RPC returns -- and for an id that never
# existed there is nothing to unmount, so the tool exits ENOENT even though the
# agent answered Ok. That client-side noise is reached only after a successful
# reply, but grepping for "error" would score it as a failure.
out=$(agent_call_verbose "${REF_AGENT}" 'RemoveContainer json://{"container_id":"ghost-never-created"}')
if echo "${out}" | grep -q 'response received'; then
  ok "08o — RemoveContainer for a never-created id succeeds as a no-op (RM-26)"
else
  echo "${out}"
  fail_case "08o — RemoveContainer for a never-created id must succeed as a no-op (RM-26), or a denied create leaves the pod stuck Terminating"
fi

# The no-op still burns the id, so removal stays single-shot however it was
# admitted (RM-20). A second attempt now carries a tombstone and must be refused
# -- that is what stops 08o from becoming a general "remove any id" hole.
out=$(agent_call "${REF_AGENT}" 'RemoveContainer json://{"container_id":"ghost-never-created"}')
expect_refusal "08p — the second RemoveContainer for the same id is refused: the no-op tombstoned it (RM-20 preserved)" \
  "${out}" PERMISSION_DENIED 'blocked by policy'

kubectl delete pod fr9-reference -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true

# ============================================================== permissive pod
step "08 — lifecycle-permissive policy (the occurrence machine, alone)"
make_permissive_rules
POD_WITH_EXITER=1 start_pod fr9-permissive "${WORK}/permissive.rego"

P_SB=$(sandbox_id fr9-permissive) || die "could not find the sandbox for fr9-permissive"
P_AGENT=$(agent_addr "${P_SB}")
P_CT=$(container_id fr9-permissive)
[[ -n "${P_AGENT}" ]] || die "could not work out the agent address for sandbox ${P_SB}"
[[ -n "${P_CT}" ]]  || die "could not read the container id for fr9-permissive"
log "sandbox=${P_SB:0:12} agent=${P_AGENT} container=${P_CT:0:12}"

# Prove the fixture actually neutralised the policy, otherwise every case below
# would "pass" for the wrong reason. A signal 0 to the live container is allowed
# by the permissive rule *and* by the occurrence machine, so it must succeed --
# under the reference policy this same call is refused (signal 0 is not in
# allowed_signals).
out=$(agent_call "${P_AGENT}" "SignalProcess json://{\"container_id\":\"${P_CT}\",\"exec_id\":\"${P_CT}\",\"signal\":0}")
if echo "${out}" | grep -q 'blocked by policy'; then
  die "the permissive fixture did not take -- policy is still refusing, so 08c-08f would prove nothing"
fi
ok "08-pre — the lifecycle endpoints are policy-permissive on this pod"

# --- 08c/08d/08e -------------------------------------------------------------
# With policy out of the way, an id the enforcer never minted an occurrence for
# must still be refused -- by the occurrence machine, with UnknownAlias.
out=$(agent_call "${P_AGENT}" 'StartContainer json://{"container_id":"ghost-never-created"}')
expect_refusal "08c — StartContainer on a never-created id is refused by the occurrence machine (UnknownAlias)" \
  "${out}" FAILED_PRECONDITION 'UnknownAlias'

out=$(agent_call "${P_AGENT}" 'SignalProcess json://{"container_id":"ghost-never-created","exec_id":"ghost","signal":15}')
expect_refusal "08d — SignalProcess on a never-created id is refused by the occurrence machine (UnknownAlias)" \
  "${out}" FAILED_PRECONDITION 'UnknownAlias'

out=$(agent_call "${P_AGENT}" 'ExecProcess json://{"container_id":"ghost-never-created","exec_id":"x1"}')
expect_refusal "08e — ExecProcess on a never-created id is refused by the occurrence machine (UnknownAlias)" \
  "${out}" FAILED_PRECONDITION 'UnknownAlias'

# --- 08f ---------------------------------------------------------------------
# The double start again, this time with the policy layer removed: the refusal
# can only be coming from the lifecycle machine.
out=$(agent_call "${P_AGENT}" "StartContainer json://{\"container_id\":\"${P_CT}\"}")
expect_refusal "08f — a second StartContainer is refused even with policy neutralised (IllegalTransition)" \
  "${out}" FAILED_PRECONDITION 'IllegalTransition'

# --- 08g/08h/08i -------------------------------------------------------------
# RM-19: the occurrence follows the container, not the host's bookkeeping. The
# agent's own SIGCHLD reaper moves an occurrence to `stopped` when the container's
# init exits, so a host that never calls WaitProcess or RemoveContainer cannot
# hold a dead container's occurrence open and exec into it. This is the property
# hcsshim gets from the same place (its exit callback), and the one F-72 recorded
# as missing here.
#
# The split matters and is asserted below: exec after exit must be refused, but
# signal after exit must still be allowed. The shim signals containers it has
# already reaped while tearing a pod down -- gating signal on `running` makes
# every pod on the node unkillable, which is exactly the F-75 outage this stage
# now guards against.
step "08g — post-exit gates (RM-19)"
wait_for 120 "the exiter container to run to completion" container_terminated fr9-permissive exiter
X_CT=$(container_id fr9-permissive exiter)
[[ -n "${X_CT}" ]] || die "could not read the container id for the exited container"
log "exited container=${X_CT:0:12}"

# The reaper runs in the guest, asynchronously from kubelet's view of the pod.
# Give it a moment rather than racing it.
sleep 3

out=$(agent_call "${P_AGENT}" "ExecProcess json://{\"container_id\":\"${X_CT}\",\"exec_id\":\"post-exit\"}")
if echo "${out}" | grep -q 'code: FAILED_PRECONDITION' \
   && echo "${out}" | grep -qE 'IllegalTransition|UnknownAlias'; then
  # Which of the two appears says *who* retired the occurrence, and both are the
  # occurrence machine: IllegalTransition means the reaper stopped it and the
  # host has not removed the container yet; UnknownAlias means the shim had
  # already called RemoveContainer. A cooperating shim usually gets there first,
  # which is exactly why the reaper matters -- an uncooperative one never does,
  # and before RM-19 that left the occurrence `running` and the exec admitted.
  if echo "${out}" | grep -q 'IllegalTransition'; then
    ok "08g — ExecProcess into a container whose init has exited is refused (IllegalTransition: the reaper stopped the occurrence)"
  else
    ok "08g — ExecProcess into a container whose init has exited is refused (UnknownAlias: the shim removed it before the probe)"
  fi
else
  echo "${out}" | tail -3
  fail_case "08g: exec into a container whose init has exited must be refused by the occurrence machine"
fi

# --- 08h ---------------------------------------------------------------------
# The regression test for the split gate, and for F-75. Signals must keep flowing
# to a container the shim has already reaped, or kubelet can never complete a
# kill: the pod hangs in Terminating forever and its sandbox leaks. That is not a
# subtle failure -- it took the whole node out on the first run of this stage --
# so it is asserted as an end-to-end property rather than as an agent probe:
# a graceful delete must actually finish.
step "08h — a pod with an exited container still deletes gracefully (F-75, split signal gate)"
t0=$(date +%s)
if kubectl delete pod fr9-permissive -n "${NS}" --wait=true --timeout=90s >/dev/null 2>&1; then
  ok "08h — graceful delete completed in $(( $(date +%s) - t0 ))s (signals still reach reaped containers)"
else
  kubectl get pod fr9-permissive -n "${NS}" -o wide 2>/dev/null || true
  fail_case "08h: the pod did not delete within 90s -- signals are being refused, which is the F-75 outage"
fi

# --- 08i ---------------------------------------------------------------------
# RM-20 at the policy layer. The enforcer's one-way latch is covered by the
# occurrence unit tests (a removed alias cannot be recreated); what is checked
# here is that the *generated policy* carries the matching tombstone, so a host
# that reuses a container id is refused before the enforcer is even consulted.
step "08i — container ids are not reusable (RM-20)"
if grep -q 'retired:' <<<"$(policy_text fr9-permissive)"; then
  ok "08i — the generated policy tombstones removed container ids (create for a reused id is refused at the policy layer)"
else
  fail_case "08i: the generated policy has no retired-id tombstone -- a removed container id could name a second container"
fi

kubectl delete pod fr9-permissive -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true
# The sandbox is gone with the pod, so the post-removal half of this case cannot be
# probed over the same vsock. It is covered by 08c/08d/08e, which exercise the same
# UnknownAlias path the retirement produces.

# ---------------------------------------------------------------------- verdict
if [[ "${FAILURES}" -ne 0 ]]; then
  die "${FAILURES} FR-9 lifecycle case(s) failed"
fi
ok "all FR-9 lifecycle gate cases passed"
mark_done 08-lifecycle-gates
