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
  || die "missing $ART_DIR/kata-tools-static.tar.zst — download it first (see README step 3)"

gha() {
  log "gha-run.sh $1"
  ( cd "$E2E_REPO_DIR" && bash tests/integration/kubernetes/gha-run.sh "$@" ) \
    || die "gha-run.sh $1 failed"
}

gha install-kata-tools kata-tools-artifacts
gha deploy-k8s
gha install-bats

# A half-installed daemonset does not self-heal, so clear it before (re)deploying.
kubectl -n kube-system delete daemonset kata-deploy --ignore-not-found >/dev/null 2>&1 || true
helm uninstall kata-deploy -n kube-system >/dev/null 2>&1 || true
gha deploy-kata

gha deploy-coco-kbs
gha install-kbs-client

# containerd 2.3.3 emits OCI spec 1.3.0 while the shipped settings still say
# 1.1.0, which denies *every* pod at CreateContainerRequest. Fix once here.
SETTINGS=/opt/kata/share/defaults/kata-containers/genpolicy-settings.json
if grep -q '"oci_version": "1.1.0"' "$SETTINGS" 2>/dev/null; then
  log "patching oci_version 1.1.0 -> 1.3.0 in $SETTINGS"
  sudo sed -i 's/"oci_version": "1.1.0"/"oci_version": "1.3.0"/' "$SETTINGS"
fi

wait_for 300 "all nodes Ready" all_nodes_ready

ok "cluster deployed"
kubectl get runtimeclass
mark_done 03-deploy-cluster
