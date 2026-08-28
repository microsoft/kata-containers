#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
# 02 — bootstrap the node: toolchain, container engine, kubectl, Go, repo checkout.
# Run this ON the VM.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 02-bootstrap-node

step "02 — bootstrap node"
log "platform: ${E2E_PLATFORM}"

if [[ "${E2E_PLATFORM}" = "clh-snp" ]]; then
  # Azure Linux 3: dnf, no docker, and the host side of the CC stack. The guest
  # stack is built natively by the node-builder in stage 04 rather than in a
  # container, so nothing here needs a container engine.
  clh_bootstrap_node
elif [[ "${E2E_PLATFORM}" = "openvmm-snp" ]]; then
  openvmm_bootstrap_node
else
  log "installing base packages"
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    cmake curl git jq unzip wget build-essential pkg-config libssl-dev \
    protobuf-compiler \
    socat conntrack ebtables ethtool docker.io docker-buildx default-jre \
    || die "apt install failed"

  # yq from snap: the apt package is a different, incompatible tool. On the
  # clh-snp path ci/install_yq.sh below provides it instead — AzL3 has no snap.
  command -v yq >/dev/null 2>&1 || sudo snap install yq || die "yq install failed"

  log "configuring docker access"
  sudo usermod -aG docker "${USER}" || die "usermod failed"
  # The docker.io package already ships /var/run/docker.sock as root:docker 0660, so
  # there is nothing to fix here — and widening it to a+rw would be a root-equivalent
  # grant to every local account. The membership added above does not apply to THIS
  # session, so verify under `sg` and tell the operator to reconnect if needed.
  if ! docker info >/dev/null 2>&1 && ! sg docker -c 'docker info' >/dev/null 2>&1; then
    die "docker is not usable by ${USER} even under the docker group — check 'systemctl status docker'"
  fi
  if ! docker info >/dev/null 2>&1; then
    warn "docker group membership added but not active in this session"
    warn "log out and back in (or reconnect ssh) before running 04-build-guest-stack.sh"
  fi
  _boot_hint=" — log out and back in for the docker group to apply"
fi

# genpolicy's containerd-client / k8s-cri build scripts shell out to protoc; without
# it the crate fails to build and the failure looks unrelated. Both platforms
# install it above, so this is a shared post-condition rather than a step.
need protoc

if ! command -v kubectl >/dev/null 2>&1; then
  log "installing kubectl"
  ver=$(curl -fsSL https://dl.k8s.io/release/stable.txt) || die "could not resolve kubectl version"
  curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/${ver}/bin/linux/amd64/kubectl" \
    || die "kubectl download failed"
  sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl || die "kubectl install failed"
fi
kubectl version --client >/dev/null 2>&1 || die "kubectl is not usable after install"

GO_VER="${E2E_GO_VERSION:-1.25.0}"
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VER}"; then
  log "installing Go ${GO_VER}"
  curl -fsSLo /tmp/go.tgz "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" \
    || die "Go download failed"
  sudo rm -rf /usr/local/go || die "could not remove the previous Go install"
  sudo tar -C /usr/local -xzf /tmp/go.tgz || die "Go install failed"
fi
/usr/local/go/bin/go version >/dev/null 2>&1 || die "Go is not usable after install"

if ! "${HOME}/.cargo/bin/cargo" --version >/dev/null 2>&1; then
  log "installing Rust"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path \
    || die "rustup install failed"
fi
"${HOME}/.cargo/bin/cargo" --version >/dev/null 2>&1 || die "cargo is not usable after install"

load_toolchain

# Non-interactive ssh sessions do not source ~/.bashrc, so scripts call
# load_toolchain(); this block is purely for interactive convenience.
if ! grep -q 'E2E toolchain' "${HOME}/.bashrc" 2>/dev/null; then
  cat >> "${HOME}/.bashrc" <<'EOF'

# --- E2E toolchain ---
export GOROOT=/usr/local/go
export GOPATH=$HOME/gopath
export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.cargo/bin:$PATH
EOF
fi

if [[ ! -d "${E2E_REPO_DIR}/.git" ]]; then
  log "cloning ${E2E_REPO_URL}"
  git clone "${E2E_REPO_URL}" "${E2E_REPO_DIR}" || die "clone failed"
fi
log "checking out ${E2E_BRANCH}"
git -C "${E2E_REPO_DIR}" fetch --all --prune -q || die "fetch failed"
git -C "${E2E_REPO_DIR}" checkout -q "${E2E_BRANCH}" || die "checkout ${E2E_BRANCH} failed"
git -C "${E2E_REPO_DIR}" pull -q --ff-only || warn "could not fast-forward ${E2E_BRANCH}"
ok "repo at $(git -C "${E2E_REPO_DIR}" rev-parse --short HEAD)"

cd "${E2E_REPO_DIR}" || die "cannot enter ${E2E_REPO_DIR}"
if [[ -x ci/install_oras.sh ]]; then
  sudo ci/install_oras.sh || true
fi
# INSTALL_IN_GOPATH defaults to true, and under sudo that resolves against
# root's HOME, so yq lands in /root/go/bin — invisible to every later stage and
# to gha-run.sh, which aborts with "yq command is not in your $PATH". Force the
# system location instead. sudo scrubs the environment, hence `sudo env`.
if [[ -x ci/install_yq.sh ]]; then
  sudo env INSTALL_IN_GOPATH=false ci/install_yq.sh || true
fi
command -v yq >/dev/null || die "yq is still not on PATH after ci/install_yq.sh"

ok "node bootstrapped${_boot_hint:-}"
mark_done 02-bootstrap-node
