#!/usr/bin/env bash
# Hand-runnable demo of the C-ACI sidecar shape: a measured base policy that pins
# one workload by layer root hash, and a separately signed fragment that admits a
# second container by *its* layer root hashes.
#
#   1. a container starts under a policy that contains it
#   2. a sidecar the policy has never seen is refused, and the pod keeps running
#   3. the sidecar's container entry is signed into a fragment and published
#   4. the same sidecar starts, because the delivered fragment now authorizes it
#
# Steps 2 and 4 differ in exactly one thing: whether the pod declares and receives
# the fragment. Nothing about the sidecar itself changes.
#
# This is the interactive twin of stage 07 cases 07l/07m. It is not part of
# run-all.sh, writes no .done marker, and can be re-run at will.
#
# Prerequisites (all produced by the normal stages):
#   * a cluster with the branch guest stack   — 03-deploy-cluster.sh, 04-build-guest-stack.sh
#   * an issuer key and issuer allow-list      — 06-policy-fragment-e2e.sh
#   * a reachable registry (loopback is fine)  — 06-policy-fragment-e2e.sh
#
# Env:
#   DEMO_PAUSE=1   wait for Enter between steps (default: run straight through)
#   E2E_NS         namespace (default coco-e2e)
set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NS="${E2E_NS:-coco-e2e}"
POD=demo-frag-sidecar
DEFAULTS=/opt/kata/share/defaults/kata-containers
SETTINGS="$DEFAULTS/genpolicy-settings.json"
RULES_SRC="$DEFAULTS/rules.rego"
FRAG="$HOME/.coco-e2e/fragments"
ENTRY="$FRAG/fragment-entry.json"
E2E_REPO_DIR="${E2E_REPO_DIR:-$HOME/kata-containers}"

# The sidecar is identified in the generated policy by its command, not its name:
# the container entry records the process argv, and two containers of the same
# image are otherwise indistinguishable.
MARK="sleep-601-demo-sidecar"

pause() {
  [ "${DEMO_PAUSE:-0}" = "1" ] || return 0
  printf '\n    press Enter to continue '
  read -r _
}

need kubectl; need jq; need python3
[ -s "$ENTRY" ] || die "no fragment fixture at $ENTRY — run 06-policy-fragment-e2e.sh first"
[ -s "$FRAG/key.txt" ] || die "no issuer key at $FRAG/key.txt — run 06-policy-fragment-e2e.sh first"
[ -r "$RULES_SRC" ] || die "no staged rules.rego at $RULES_SRC — run 03-deploy-cluster.sh first"

ISSUER=$(jq -r .issuer "$ENTRY")
FEED=$(jq -r .feed "$ENTRY")
SVN=$(jq -r .minimum_svn "$ENTRY")
PRIV=$(grep '^private_key_hex=' "$FRAG/key.txt" | cut -d= -f2)
SIDECAR_FEED="${FEED}-sidecar-demo"
SIDECAR_REF="$SIDECAR_FEED:demo"
PLAIN_HTTP=""
case "${FEED%%/*}" in localhost*|127.0.0.1*) PLAIN_HTTP="--plain-http" ;; esac

load_toolchain 2>/dev/null || true
log "building genpolicy from the branch (the installed one is upstream's)"
( cd "$E2E_REPO_DIR" && cargo build --release -p genpolicy ) >/dev/null \
  || die "could not build genpolicy"
GENPOLICY="$E2E_REPO_DIR/target/release/genpolicy"

SIGN()    { ( cd "$E2E_REPO_DIR" && cargo run -q --example sign-fragment \
              -p kata-security-reference-monitor -- "$@" ); }
FRAGGEN() { ( cd "$E2E_REPO_DIR" && cargo run -q -p genpolicy-fragmentgen -- "$@" ); }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS" >/dev/null

# The issuer allow-list is measured configuration: it travels in initdata, not in
# the policy, so the guest knows which issuers exist before any policy runs.
printf 'version = "0.1.0"\nalgorithm = "sha256"\n\n[data]\n"fragment-issuers.toml" = %s\n%s\n%s\n' \
  "'''" "$(cat "$FRAG/fragment-issuers.toml")" "'''" > "$WORK/initdata.toml"

# Two rule files: one declaring no fragment, one declaring this fragment. The
# declaration is part of the measured policy — a fragment cannot be trusted by a
# policy that never named it, which is why steps 2 and 4 need different policies.
cp "$RULES_SRC" "$WORK/rules-none.rego"
printf '\npolicy_fragments := []\n' >> "$WORK/rules-none.rego"
cp "$RULES_SRC" "$WORK/rules-sidecar.rego"
printf '\npolicy_fragments := [{"issuer": "%s", "feed": "%s", "minimum_svn": %s}]\n' \
  "$ISSUER" "$SIDECAR_FEED" "$SVN" >> "$WORK/rules-sidecar.rego"

# $1 = delivery annotation, empty for none.
render_pod() {
  local anno=""
  [ -n "${1:-}" ] && anno="
  annotations:
    io.katacontainers.config.agent.policy_fragments: \"$1\""
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: $NS$anno
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

append_sidecar() {
  cat >> "$1" <<EOF
    - name: sidecar
      image: quay.io/prometheus/busybox:latest
      command: ["sh", "-c", "echo $MARK; sleep 600"]
EOF
}

ready_of() {
  kubectl get pod "$POD" -n "$NS" \
    -o jsonpath="{.status.containerStatuses[?(@.name=='$1')].ready}" 2>/dev/null
}

wipe_pod() {
  kubectl delete pod "$POD" -n "$NS" --ignore-not-found --now >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    kubectl get pod "$POD" -n "$NS" >/dev/null 2>&1 || return 0
    sleep 2
  done
  kubectl delete pod "$POD" -n "$NS" --force --grace-period=0 >/dev/null 2>&1 || true
  sleep 3
}

# ---------------------------------------------------------------------------
step "1 — a container the measured policy contains"
log "generating a policy from a one-container pod, then running that pod"
wipe_pod
render_pod "" > "$WORK/step1.yaml"
"$GENPOLICY" -y "$WORK/step1.yaml" -p "$WORK/rules-none.rego" -j "$SETTINGS" \
  --initdata-path="$WORK/initdata.toml" >/dev/null || die "genpolicy failed"
kubectl apply -f "$WORK/step1.yaml" >/dev/null
wait_for 300 "pod $POD Running" "kubectl get pod $POD -n $NS -o jsonpath='{.status.phase}' | grep -q Running"
ok "busybox is running, authorized by an entry in the measured policy"
kubectl get pod "$POD" -n "$NS"
pause

# ---------------------------------------------------------------------------
step "2 — a sidecar the policy has never seen"
log "same policy, plus a container appended to the yaml *after* generation"
log "the policy therefore has no entry for it, and no fragment is declared"
wipe_pod
render_pod "" > "$WORK/step2.yaml"
"$GENPOLICY" -y "$WORK/step2.yaml" -p "$WORK/rules-none.rego" -j "$SETTINGS" \
  --initdata-path="$WORK/initdata.toml" >/dev/null || die "genpolicy failed"
append_sidecar "$WORK/step2.yaml"
kubectl apply -f "$WORK/step2.yaml" >/dev/null
wait_for 300 "busybox ready" "[ \"\$(kubectl get pod $POD -n $NS -o jsonpath='{.status.containerStatuses[?(@.name==\"busybox\")].ready}')\" = true ]"
sleep 20
sc=$(ready_of sidecar)
[ "$sc" = "true" ] && die "the sidecar started without a fragment — the policy is not being enforced"
ok "busybox ready, sidecar refused (ready=${sc:-<none>})"
log "the guest's reason, from the pod events:"
kubectl get events -n "$NS" --field-selector involvedObject.name="$POD" \
  -o jsonpath='{range .items[*]}{.message}{"\n"}{end}' 2>/dev/null \
  | grep -o 'blocked by policy[^\\]*' | head -1 | cut -c1-200 || true
log "note the pod is not dead: the sandbox and the authorized container keep running."
log "that is the C-ACI behaviour — the policy denies the request, it does not kill the pod."
pause

# ---------------------------------------------------------------------------
step "3 — sign and publish a fragment that authorizes exactly that sidecar"
# The entry is lifted from a policy generated for the pod the sidecar will really
# run in — annotation included, because the runtime stamps pod annotations onto
# every container's OCI spec and the entry has to match the request byte for byte.
log "generating a two-container reference policy to lift the sidecar's real entry from"
render_pod "$SIDECAR_REF" > "$WORK/ref.yaml"
append_sidecar "$WORK/ref.yaml"
"$GENPOLICY" -y "$WORK/ref.yaml" -p "$WORK/rules-none.rego" -j "$SETTINGS" \
  --initdata-path="$WORK/initdata.toml" >/dev/null || die "genpolicy failed"

python3 - "$WORK/ref.yaml" "$MARK" > "$WORK/entry.json" <<'PY'
import base64, gzip, json, re, sys
blob = re.search(r'cc_init_data:\s*"?([A-Za-z0-9+/=]+)"?', open(sys.argv[1]).read())
policy = gzip.decompress(base64.b64decode(blob.group(1))).decode("utf-8", "replace")
i = policy.find("policy_data := {")
data, _ = json.JSONDecoder().raw_decode(policy, policy.index("{", i))
hits = [c for c in data["containers"] if sys.argv[2] in json.dumps(c)]
assert len(hits) == 1, f"expected one sidecar entry, found {len(hits)}"
print(json.dumps(hits[0], indent=2))
PY
[ -s "$WORK/entry.json" ] || die "could not lift the sidecar entry"
grep -q 'root_hash\|verity' "$WORK/entry.json" \
  && ok "the entry pins the image by dm-verity root hash, not by name" \
  || warn "the entry carries no root hash — guest-pull may be off"

# The package is the fragment's own feed, quoted: a feed is an OCI reference and
# not a bare Rego identifier. The agent accepts that form only for the feed the
# SRM verified from the COSE envelope, so no publisher can write another's key.
{
  printf 'package agent_policy.fragments["%s"]\n\n' "$SIDECAR_FEED"
  printf 'issuer := "%s"\n' "$ISSUER"
  printf 'svn := %s\n' "$SVN"
  printf 'containers := [%s]\n' "$(cat "$WORK/entry.json")"
} > "$WORK/sidecar.rego"
log "the fragment declares:"
head -4 "$WORK/sidecar.rego" | sed 's/^/      /'

SIGN sign --issuer "$ISSUER" --feed "$SIDECAR_FEED" --svn "$SVN" \
     --module "$WORK/sidecar.rego" --key "$PRIV" --cose > "$WORK/sign.txt" \
  || { tail -20 "$WORK/sign.txt"; die "signing failed"; }
grep '^cose_sign1_hex=' "$WORK/sign.txt" | cut -d= -f2 > "$WORK/cose.hex"
FRAGGEN --cose "$WORK/cose.hex" --push "$SIDECAR_REF" $PLAIN_HTTP > "$WORK/push.txt" \
  || { tail -20 "$WORK/push.txt"; die "publishing failed"; }
ok "published $SIDECAR_REF, COSE_Sign1-signed by $ISSUER at svn $SVN"
pause

# ---------------------------------------------------------------------------
step "4 — the same sidecar, now authorized by the delivered fragment"
log "identical workload; the pod now declares the fragment and the host delivers it"
wipe_pod
render_pod "$SIDECAR_REF" > "$WORK/step4.yaml"
"$GENPOLICY" -y "$WORK/step4.yaml" -p "$WORK/rules-sidecar.rego" -j "$SETTINGS" \
  --initdata-path="$WORK/initdata.toml" >/dev/null || die "genpolicy failed"
append_sidecar "$WORK/step4.yaml"
kubectl apply -f "$WORK/step4.yaml" >/dev/null
wait_for 300 "sidecar ready" "[ \"\$(kubectl get pod $POD -n $NS -o jsonpath='{.status.containerStatuses[?(@.name==\"sidecar\")].ready}')\" = true ]"
[ "$(ready_of busybox)" = "true" ] || die "busybox is not ready"
ok "both containers running — the fragment authorized a container the measured policy never contained"
kubectl get pod "$POD" -n "$NS"
kubectl logs "$POD" -n "$NS" -c sidecar 2>/dev/null | head -1 || true

step "what just happened"
cat <<'EOF'
  step 2 and step 4 run the same image, the same command, the same pod.
  The difference is a signed, versioned artifact fetched from a registry by the
  host and verified inside the guest before it can authorize anything:

    * the issuer is on an allow-list measured into initdata, not into the policy
    * the fragment is COSE_Sign1-signed and its feed must match the declaration
    * its SVN must be at or above the floor the policy declares
    * it may only write under its own signed feed's namespace
    * the container it admits is pinned by dm-verity root hash, not by image name

  Withhold the fragment (step 2) and the container simply never runs.
EOF
log "clean up with: kubectl delete pod $POD -n $NS"
