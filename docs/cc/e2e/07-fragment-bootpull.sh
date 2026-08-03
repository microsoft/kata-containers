#!/usr/bin/env bash
# 07 — live boot-pull of a declared policy fragment (BL-8), on the cluster.
#
# Stage 06 stops at the delivery boundary: it signs a fragment, publishes it, and
# prints the wiring. Nothing there boots a VM, so nothing there proves the guest
# actually consumes a declaration. This stage closes that gap.
#
# The whole stage rests on one property of the agent (src/agent/src/main.rs, the
# BL-8 block): a declared fragment that cannot be fetched, verified, or injected
# is fatal — the agent aborts the VM before the ttRPC server serves any request.
# That makes pod phase a sound oracle in *both* directions:
#
#   declaration absent            -> Running   (control: the wiring is inert)
#   declaration unfetchable       -> never Running (fail-closed)
#   declaration good + reachable  -> Running   => fetched AND verified AND injected
#
# The last inference is only valid because of the second: if any step had failed,
# the VM would be gone. So "Running with a non-empty policy_fragments[]" is proof
# of a completed boot-pull, without needing to read anything out of the guest.
#
# The control is not optional decoration. Without it, a pod that fails to start
# for an unrelated reason (a bad rules.rego patch, a broken node) would read as a
# passing fail-closed test. 07a must go green using the identical mechanism, or
# 07b proves nothing.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 07-fragment-bootpull

step "07 — boot-pull of declared policy fragments (BL-8)"
load_toolchain
load_coco_env
need jq
need kubectl

# Same preflight as the smoke test: without the locally built guest this stage
# would exercise the CI nightly agent, which has no strict-policy build and
# therefore no boot-pull at all — and would report a green control plus a green
# "fail-closed" (the pod fails for a different reason entirely).
assert_local_guest_installed

NS="${E2E_NS:-coco-e2e}"
DEFAULTS=/opt/kata/share/defaults/kata-containers
SETTINGS="$DEFAULTS/genpolicy-settings.json"
RULES_SRC="$DEFAULTS/rules.rego"
[ -f "$SETTINGS" ]  || die "missing $SETTINGS — run 03-deploy-cluster.sh first"
[ -f "$RULES_SRC" ] || die "missing $RULES_SRC — run 03-deploy-cluster.sh first"

# Artifacts from stage 06. The COSE envelope commits to its feed, so the entry and
# the trust root must be the ones 06 actually produced — regenerating them here
# would silently drift from what was published.
FRAG="${E2E_FRAGMENT_WORK:-$E2E_STATE_DIR/fragments}"
ENTRY="$FRAG/fragment-entry.json"
ISSUERS="$FRAG/fragment-issuers.toml"
[ -s "$ENTRY" ]   || die "missing $ENTRY — run 06-policy-fragment-e2e.sh first"
[ -s "$ISSUERS" ] || die "missing $ISSUERS — run 06-policy-fragment-e2e.sh first"

ISSUER=$(jq -r .issuer      "$ENTRY") || die "could not read issuer from $ENTRY"
FEED=$(jq -r .feed          "$ENTRY") || die "could not read feed from $ENTRY"
SVN=$(jq -r .minimum_svn    "$ENTRY") || die "could not read minimum_svn from $ENTRY"
[ -n "$ISSUER" ] && [ -n "$FEED" ] && [ -n "$SVN" ] || die "incomplete entry in $ENTRY"

# Is the published feed reachable from inside the guest? The guest resolves the
# feed itself, so a loopback registry on the *host* is not the same address: the
# guest's localhost is its own, and nothing is listening there. That makes a
# loopback feed a perfect fail-closed fixture and a useless good-path one.
FEED_REG="${FEED%%/*}"
case "$FEED_REG" in
  localhost*|127.0.0.1*|\[::1\]*) GUEST_REACHABLE=0 ;;
  *)                              GUEST_REACHABLE=1 ;;
esac

# Always-unreachable declaration for the fail-closed case. A loopback address is
# guaranteed to refuse the connection inside the guest regardless of node egress,
# so this negative cannot go green for an environmental reason.
UNREACHABLE_FEED="${E2E_FRAGMENT_UNREACHABLE_FEED:-localhost:5000/coco-e2e/absent:e2e}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------- genpolicy
# The declaration is delivered by patching the base policy, and the trust root by
# initdata, so this stage needs a genpolicy that accepts --initdata_path. The
# installed binary comes from the upstream CI nightly (see CI-9), which may
# predate that flag; fall back to the branch copy rather than failing, and always
# log which one ran — the provenance of the tool is part of the result.
GENPOLICY=/opt/kata/bin/genpolicy
if ! "$GENPOLICY" --help 2>&1 | grep -q -- '--initdata_path'; then
  warn "$GENPOLICY does not accept --initdata_path — building genpolicy from $E2E_BRANCH"
  # genpolicy is a member of the root workspace (see the repo-root Cargo.toml),
  # so the artifact lands in the workspace target dir, not under src/tools.
  ( cd "$E2E_REPO_DIR" && cargo build --release -p genpolicy ) \
    || die "could not build genpolicy from the branch"
  GENPOLICY="$E2E_REPO_DIR/target/release/genpolicy"
  [ -x "$GENPOLICY" ] || die "genpolicy built but $GENPOLICY is missing"
  "$GENPOLICY" --help 2>&1 | grep -q -- '--initdata_path' \
    || die "branch genpolicy still lacks --initdata_path — cannot deliver the trust root"
fi
log "using genpolicy: $GENPOLICY"

# -------------------------------------------------------------------- fixtures
# The trust root travels as a measured initdata key, which is the provenance the
# agent prefers (BL-5). A TOML literal block is used so the hex key and the DID
# pass through unescaped and the value is byte-identical to the file 06 wrote.
render_initdata() {
  printf 'version = "0.1.0"\nalgorithm = "sha256"\n\n[data]\n"fragment-issuers.toml" = %s\n%s\n%s\n' \
    "'''" "$(cat "$ISSUERS")" "'''"
}
render_initdata > "$WORK/initdata.toml"

# genpolicy concatenates the rules file verbatim into the generated policy, and
# `policy_fragments` is undefined upstream, so appending the declaration to a copy
# of the staged rules is the whole wiring. Append rather than edit in place: the
# staged copy is what stage 03 asserted, and mutating it would poison stage 05.
render_rules() {
  local out="$1" decl="$2"
  cat "$RULES_SRC" > "$out" || die "could not copy $RULES_SRC"
  printf '\n# BL-8 (e2e stage 07): boot-time fragment declarations.\npolicy_fragments := %s\n' \
    "$decl" >> "$out"
}

render_pod() {
  # Mirrors 05-smoke-test.sh: with PULL_TYPE=guest-pull genpolicy refuses images
  # whose user/group would come from the layers, so the securityContext must be
  # explicit at pod level.
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
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
      command: ["sleep", "600"]
EOF
}

# Generate a policy over the given rules + initdata and apply the pod.
apply_case() {
  local pod="$1" rules="$2" yaml="$WORK/$pod.yaml"
  render_pod "$pod" > "$yaml"
  "$GENPOLICY" -y "$yaml" -p "$rules" -j "$SETTINGS" \
    --initdata_path="$WORK/initdata.toml" >/dev/null \
    || die "genpolicy failed for $pod"
  # This build delivers the policy through initdata, not the legacy agent.policy
  # annotation, so a "did the policy land?" check must look for cc_init_data.
  grep -q 'cc_init_data' "$yaml" || die "no cc_init_data annotation for $pod"
  kubectl delete pod "$pod" -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
  kubectl apply -f "$yaml" >/dev/null || die "kubectl apply failed for $pod"
}

pod_phase() { kubectl get pod "$1" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null; }

# Fail as soon as the pod reports Running, rather than only sampling at the end:
# a sandbox that comes up and is then torn down would otherwise slip through.
expect_never_running() {
  local pod="$1" secs="$2" deadline
  deadline=$(( $(date +%s) + secs ))
  log "watching $pod for ${secs}s — it must never reach Running"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(pod_phase "$pod")" = "Running" ] && return 1
    sleep 5
  done
  return 0
}

diagnose() {
  local pod="$1"
  warn "diagnostics for $pod:"
  kubectl describe pod "$pod" -n "$NS" 2>&1 | tail -25 | sed 's/^/    /'
  # Guest agent logs reach the host journal only when the runtime has debug
  # enabled, so treat this as informational and never as the assertion.
  sudo journalctl -t kata --since '-10m' 2>/dev/null | grep -i 'FR-1\|fragment' \
    | tail -15 | sed 's/^/    /' || true
}

cleanup_pod() { kubectl delete pod "$1" -n "$NS" --ignore-not-found >/dev/null 2>&1 || true; }

kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS" >/dev/null

# ============================================================ 07a — the control
step "07a — control: an empty declaration must still boot"
render_rules "$WORK/rules-none.rego" '[]'
apply_case e2e-frag-none "$WORK/rules-none.rego"
if ! wait_for_soft 300 "pod e2e-frag-none Running" \
     bash -c "kubectl get pod e2e-frag-none -n $NS -o jsonpath='{.status.phase}' | grep -qx Running"; then
  diagnose e2e-frag-none
  die "the control pod did not boot — the patched base policy is broken, so no fail-closed result below would mean anything"
fi
ok "control booted — patching policy_fragments is inert when the list is empty"
cleanup_pod e2e-frag-none

# ====================================================== 07b — fail-closed (BL-8)
step "07b — a declared but unfetchable fragment must abort the VM"
render_rules "$WORK/rules-bad.rego" \
  "[{\"issuer\": \"$ISSUER\", \"feed\": \"$UNREACHABLE_FEED\", \"minimum_svn\": 1}]"
apply_case e2e-frag-unfetchable "$WORK/rules-bad.rego"
if expect_never_running e2e-frag-unfetchable "${E2E_FRAGMENT_NEG_WAIT:-180}"; then
  ok "pod never reached Running — boot-pull failed closed (expected)"
  kubectl describe pod e2e-frag-unfetchable -n "$NS" 2>/dev/null \
    | grep -i 'sandbox\|failed' | tail -5 | sed 's/^/    /' || true
else
  diagnose e2e-frag-unfetchable
  cleanup_pod e2e-frag-unfetchable
  die "pod is Running despite declaring an unfetchable fragment — boot-pull is not wired, or it is not fail-closed"
fi
cleanup_pod e2e-frag-unfetchable

# ================================================== 07c/07d — the reachable feed
if [ "$GUEST_REACHABLE" != "1" ]; then
  warn "feed $FEED is a loopback registry — the guest cannot reach it, so the good path is skipped"
  warn "to exercise 07c/07d, re-run 06 with E2E_REGISTRY set to a TLS registry the guest"
  warn "can reach and pull anonymously (e.g. an ACR with anonymous pull enabled), then re-run 07"
else
  step "07c — good path: a reachable, valid fragment must boot"
  render_rules "$WORK/rules-good.rego" \
    "[{\"issuer\": \"$ISSUER\", \"feed\": \"$FEED\", \"minimum_svn\": $SVN}]"
  apply_case e2e-frag-good "$WORK/rules-good.rego"
  if ! wait_for_soft 300 "pod e2e-frag-good Running" \
       bash -c "kubectl get pod e2e-frag-good -n $NS -o jsonpath='{.status.phase}' | grep -qx Running"; then
    diagnose e2e-frag-good
    cleanup_pod e2e-frag-good
    die "the declared fragment did not boot — fetch, verification, or injection failed"
  fi
  # Sound only because 07b established that any failure is fatal: had the fetch,
  # the signature check, the SVN floor, or the injection failed, this VM would
  # have aborted instead of reaching Running.
  ok "pod booted with a declared fragment => it was fetched, SRM-verified and injected"
  sudo journalctl -t kata --since '-10m' 2>/dev/null | grep -i 'FR-1' | tail -5 \
    | sed 's/^/    /' || true
  cleanup_pod e2e-frag-good

  step "07d — negative: an SVN floor above the published fragment must abort"
  # Same reachable artifact, so the fetch succeeds and the rejection can only come
  # from verification. This is what separates a working trust gate from a working
  # network path — 07b alone cannot tell them apart.
  render_rules "$WORK/rules-rollback.rego" \
    "[{\"issuer\": \"$ISSUER\", \"feed\": \"$FEED\", \"minimum_svn\": $((SVN + 1))}]"
  apply_case e2e-frag-rollback "$WORK/rules-rollback.rego"
  if expect_never_running e2e-frag-rollback "${E2E_FRAGMENT_NEG_WAIT:-180}"; then
    ok "pod never reached Running — the SVN rollback floor held (expected)"
  else
    diagnose e2e-frag-rollback
    cleanup_pod e2e-frag-rollback
    die "pod is Running with minimum_svn above the fragment's SVN — the rollback floor is not enforced"
  fi
  cleanup_pod e2e-frag-rollback
fi

ok "boot-pull e2e passed"
mark_done 07-fragment-bootpull
