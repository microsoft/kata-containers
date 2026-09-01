#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
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

# genpolicy must come from the branch, not from the installed payload: on the
# QEMU path the installed binary is whatever the CI nightly shipped, and its
# settings schema drifts from the branch in both directions; on clh-snp the
# node-builder installs no genpolicy at all. See ensure_branch_genpolicy() and
# ensure_genpolicy_defaults() in lib.sh, which also resolve the rules/settings
# inputs for the platform in use.
ensure_branch_genpolicy
ensure_genpolicy_defaults

ensure_ns "${NS}"

# Where the image is pulled in the guest, genpolicy refuses images whose
# user/group would come from the layers, so the securityContext must be explicit
# at pod level. Harmless on the host-EROFS platforms, so it is set unconditionally
# rather than branched on.
cat > "${WORK}/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
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
      command: ["sleep", "600"]
EOF

log "generating policy (edits the YAML in place)"
"${GENPOLICY}" -y "${WORK}/pod.yaml" \
  -p "${GP_RULES}" \
  -j "${GP_SETTINGS}" \
  || die "genpolicy failed"

# This build delivers the policy through initdata, not the legacy agent.policy
# annotation — a "did genpolicy run?" check must look for cc_init_data.
grep -q 'cc_init_data' "${WORK}/pod.yaml" \
  || die "no cc_init_data annotation — genpolicy did not inject the policy"
ok "policy injected via cc_init_data"

kubectl delete pod "${POD}" -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "${WORK}/pod.yaml" >/dev/null || die "kubectl apply failed"

wait_for 300 "pod ${POD} Running" \
  bash -c "kubectl get pod ${POD} -n ${NS} -o jsonpath='{.status.phase}' | grep -qx Running"
ok "pod is Running on the hardened stack"

# ------------------------------------------------------- negative assertions
# exec is not in the generated policy, so the agent must refuse it. A denial here
# is the proof that mediation is live; a success would mean the policy is not
# being enforced.
step "05a — exec must be denied by policy"
if out=$(kubectl exec -n "${NS}" "${POD}" -- /bin/true 2>&1); then
  die "kubectl exec SUCCEEDED — policy is not being enforced"
fi
if echo "${out}" | grep -qi "blocked by policy\|ExecProcessRequest"; then
  ok "exec denied by policy (expected)"
else
  echo "${out}" | tail -5
  die "exec failed, but not with a policy denial — cannot conclude mediation is live"
fi

kubectl delete pod "${POD}" -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true
ok "smoke test passed"
mark_done 05-smoke-test
