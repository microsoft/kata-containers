#!/usr/bin/env bash
# 05 — smoke test: boot a genpolicy-protected pod on the hardened stack, then
#      assert the strict-policy negative behaviours.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 05-smoke-test

step "05 — smoke test"
load_toolchain
load_coco_env

NS="${E2E_NS:-coco-e2e}"
POD=e2e-busybox
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------- preflight: what are we testing?
# Without this the stage happily exercises the CI nightly guest image and reports
# PASS, which would prove nothing about the hardening.
assert_local_guest_installed

kubectl get ns "$NS" >/dev/null 2>&1 || kubectl create ns "$NS"

# With PULL_TYPE=guest-pull genpolicy refuses images whose user/group would come
# from the image layers, so the securityContext must be explicit at pod level.
cat > "$WORK/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD
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

log "generating policy (edits the YAML in place)"
/opt/kata/bin/genpolicy -y "$WORK/pod.yaml" \
  -p /opt/kata/share/defaults/kata-containers/rules.rego \
  -j /opt/kata/share/defaults/kata-containers/genpolicy-settings.json \
  || die "genpolicy failed"

# This build delivers the policy through initdata, not the legacy agent.policy
# annotation — a "did genpolicy run?" check must look for cc_init_data.
grep -q 'cc_init_data' "$WORK/pod.yaml" \
  || die "no cc_init_data annotation — genpolicy did not inject the policy"
ok "policy injected via cc_init_data"

kubectl delete pod "$POD" -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$WORK/pod.yaml" >/dev/null || die "kubectl apply failed"

wait_for 300 "pod $POD Running" \
  bash -c "kubectl get pod $POD -n $NS -o jsonpath='{.status.phase}' | grep -qx Running"
ok "pod is Running on the hardened stack"

# ------------------------------------------------------- negative assertions
# exec is not in the generated policy, so the agent must refuse it. A denial here
# is the proof that mediation is live; a success would mean the policy is not
# being enforced.
step "05a — exec must be denied by policy"
if out=$(kubectl exec -n "$NS" "$POD" -- /bin/true 2>&1); then
  die "kubectl exec SUCCEEDED — policy is not being enforced"
fi
if echo "$out" | grep -qi "blocked by policy\|ExecProcessRequest"; then
  ok "exec denied by policy (expected)"
else
  echo "$out" | tail -5
  die "exec failed, but not with a policy denial — cannot conclude mediation is live"
fi

kubectl delete pod "$POD" -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
ok "smoke test passed"
mark_done 05-smoke-test
