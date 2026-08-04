#!/usr/bin/env bash
# 03 — deploy the kubeadm cluster, kata-deploy and the CoCo KBS (Path A).
#
# Writes ~/coco-env.sh, which every later step sources.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 03-deploy-cluster

step "03 — deploy cluster"
load_toolchain
cd "$E2E_REPO_DIR" || die "no repo at $E2E_REPO_DIR — run 02 first"

# ---------------------------------------------------------------- environment
# DOCKER_TAG must carry the -amd64 suffix: ci-nightly publishes the manifest-list
# tag only when the multi-arch merge job runs, and recent nightlies fail before
# it. Without the suffix kata-deploy ImagePullBackOffs 42 times and times out.
#
# When a cluster is already running, the sha it was deployed with is on the
# daemonset image, so recover it rather than making the caller hunt for a value
# that only has to match what is already installed. Restaging genpolicy inputs is
# the common reason to re-run this stage and it should not require archaeology.
if [ -z "${E2E_NIGHTLY_SHA:-}" ]; then
  E2E_NIGHTLY_SHA=$(kubectl -n kube-system get daemonset kata-deploy \
    -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null \
    | sed -n 's/.*kata-deploy-ci:\([0-9a-f]\{40\}\)-nightly.*/\1/p')
  [ -n "$E2E_NIGHTLY_SHA" ] \
    && log "recovered E2E_NIGHTLY_SHA=$E2E_NIGHTLY_SHA from the running kata-deploy"
fi
: "${E2E_NIGHTLY_SHA:?set E2E_NIGHTLY_SHA to the CI-nightly commit sha (see README)}"

ENV_FILE="$HOME/coco-env.sh"
cat > "$ENV_FILE" <<EOF
export KATA_HYPERVISOR="qemu-coco-dev-runtime-rs"
export KBS="true" KBS_INGRESS="nodeport" PULL_TYPE="guest-pull"
export SNAPSHOTTER="nydus" KATA_HOST_OS="ubuntu" K8S_TEST_HOST_TYPE="all"
export CONTAINER_ENGINE_VERSION="latest" CONTAINER_ENGINE="containerd"
export USE_EXPERIMENTAL_SETUP_SNAPSHOTTER="true" AUTO_GENERATE_POLICY="yes"
export DOCKER_REGISTRY="ghcr.io" DOCKER_REPO="kata-containers/kata-deploy-ci"
export DOCKER_TAG="${E2E_NIGHTLY_SHA}-nightly-amd64"
export GH_PR_NUMBER="nightly" KUBERNETES="vanilla"
EOF
ok "wrote $ENV_FILE"
load_coco_env "$ENV_FILE"

ART_DIR="$E2E_REPO_DIR/kata-tools-artifacts"
[ -f "$ART_DIR/kata-tools-static.tar.zst" ] \
  || die "missing $ART_DIR/kata-tools-static.tar.zst — download it first (see README, 'Clean-room run from nothing', step 6)"

gha() {
  log "gha-run.sh $1"
  # stdin is closed deliberately. gha-run.sh is written for GitHub Actions, where
  # stdin is never a TTY, so a few upstream steps prompt only when a human runs
  # them -- install-bats calls add-apt-repository without -y
  # (gha-run-k8s-common.sh:175,177) and parks on "Press [ENTER] to continue".
  # That would stall the stage indefinitely, right before the 40-60 minute build
  # in stage 04. Every sudo here already runs unattended, so nothing else wants
  # stdin; closing it makes the prompts take their default and proceed.
  ( cd "$E2E_REPO_DIR" && bash tests/integration/kubernetes/gha-run.sh "$@" ) </dev/null \
    || die "gha-run.sh $1 failed"
}

gha install-kata-tools kata-tools-artifacts

# Bringing the cluster up is not idempotent, and this stage is the only documented
# way to restage the genpolicy inputs below -- so every rules.rego edit used to
# demand a full redeploy, which then failed. `deploy-k8s` runs
# `kubectl taint ... node-role.kubernetes.io/control-plane-` unconditionally and
# exits non-zero when the taint is already gone, i.e. on every second run. The
# stage would then burn 5 x 180s retrying something that could not succeed, and
# fail with a healthy cluster sitting right there.
#
# So bring the cluster up only when there is not already one. Restaging is the
# common case by far and must stay cheap. E2E_REDEPLOY=1 forces the full path.
cluster_is_up() {
  kubectl get nodes >/dev/null 2>&1 \
    && kubectl -n kube-system get daemonset kata-deploy >/dev/null 2>&1
}

if [ "${E2E_REDEPLOY:-0}" != "1" ] && cluster_is_up; then
  log "cluster and kata-deploy are already up — skipping bring-up (E2E_REDEPLOY=1 forces it)"
  log "restaging genpolicy inputs only"
else
  gha deploy-k8s
  gha install-bats

  # A half-installed daemonset does not self-heal, so clear it before (re)deploying.
  kubectl -n kube-system delete daemonset kata-deploy --ignore-not-found >/dev/null 2>&1 || true
  helm uninstall kata-deploy -n kube-system >/dev/null 2>&1 || true
  gha deploy-kata

  gha deploy-coco-kbs
  gha install-kbs-client
fi

# The kata-tools tarball and the kata-deploy image both come from the *upstream*
# CI-nightly, so every genpolicy input on disk is upstream's — including
# rules.rego, which genpolicy reads at runtime rather than compiling in. Without
# this, stage 05 generates its pod policy from upstream rules and nothing in the
# suite exercises ours (e.g. the FR-4A storage bijection).
#
# Staging the inputs is necessary but NOT sufficient. genpolicy re-serializes
# request_defaults through a typed struct, so the *binary* also has to know each
# key the settings declare or it drops it silently. The nightly binary predates
# SignalProcessRequest.allowed_signals and dropped it, which denied SIGKILL and
# left started pods unstoppable. Stage 07 therefore builds genpolicy from the
# branch and asserts no request_defaults key was lost; stage 05 still runs the
# installed one, so treat a 05-only failure around a new settings key as this.
#
# This has to happen after deploy-kata: that step also writes
# /opt/kata from the kata-deploy image and would clobber an earlier copy, which
# is the same reason the oci_version patch below sits here.
DEFAULTS=/opt/kata/share/defaults/kata-containers
for f in rules.rego genpolicy-settings.json; do
  src="$E2E_REPO_DIR/src/tools/genpolicy/$f"
  [ -f "$src" ] || die "missing $src — genpolicy inputs are not where 03 expects them"
  sudo install -D --mode 0644 "$src" "$DEFAULTS/$f" \
    || die "could not stage $f into $DEFAULTS"
done
ok "staged genpolicy inputs from $E2E_BRANCH"

# containerd 2.3.3 emits OCI spec 1.3.0 while the shipped settings still say
# 1.1.0, which denies *every* pod at CreateContainerRequest. Fix once here.
SETTINGS="$DEFAULTS/genpolicy-settings.json"
if grep -q '"oci_version": "1.1.0"' "$SETTINGS" 2>/dev/null; then
  log "patching oci_version 1.1.0 -> 1.3.0 in $SETTINGS"
  sudo sed -i 's/"oci_version": "1.1.0"/"oci_version": "1.3.0"/' "$SETTINGS"
fi

# The staging above is only worth anything if it survived to disk. rules.rego is
# untouched by the patch, so it must still be byte-identical to the repo copy;
# anything else means something rewrote /opt/kata after we did.
if [ "$(sudo sha256sum "$DEFAULTS/rules.rego" | cut -d' ' -f1)" \
   != "$(sha256sum "$E2E_REPO_DIR/src/tools/genpolicy/rules.rego" | cut -d' ' -f1)" ]; then
  die "installed rules.rego is not the branch copy — policy would be generated from upstream rules"
fi
ok "genpolicy rules.rego matches $E2E_BRANCH"

wait_for 300 "all nodes Ready" all_nodes_ready

ok "cluster deployed"
kubectl get runtimeclass
mark_done 03-deploy-cluster
