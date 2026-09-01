#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
# sync.sh — push this suite to the node and (optionally) run stages there.
#
# Run from the workstation. The scripts are copied rather than git-pulled on the
# node so an in-progress local edit can be tested without committing it — the
# suite itself is not what stage 04's clean-tree gate is about.
#
#   ./sync.sh                       # copy only
#   ./sync.sh 04 05                 # copy, then run those stages on the node
#   E2E_SSH_HOST=coco-e2e-2 ./sync.sh 02
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/lib.sh"

need ssh
need scp

ssh "${E2E_SSH_HOST}" 'mkdir -p ~/coco-e2e' || die "cannot reach ${E2E_SSH_HOST} over ssh"
# env*.sh is workstation-side site config, not part of the suite: it names a
# resource group, a VM and a platform. Shipping it puts a file on the node that
# describes a *different* environment, which is worth nothing there and is an
# easy way to run the wrong thing by hand later. The knobs that matter are
# forwarded explicitly below.
# A glob plus an explicit filter, not `ls | grep`: filenames here are known-simple,
# but the array form is what keeps scp's argv correct if that ever stops being true.
sync_files=()
for f in "${HERE}"/*.sh; do
  [[ "$(basename "${f}")" == env*.sh ]] && continue
  sync_files+=("${f}")
done
scp "${sync_files[@]}" "${HERE}"/README.md "${E2E_SSH_HOST}:~/coco-e2e/" || die "scp failed"
# Windows checkouts carry no executable bit, and scp preserves that, so the
# scripts arrive non-executable and every invocation fails with Permission denied.
ssh "${E2E_SSH_HOST}" 'chmod +x ~/coco-e2e/*.sh' || die "chmod failed"
ok "suite synced to ${E2E_SSH_HOST}:~/coco-e2e"

if [[ "${E2E_PLATFORM}" = "openvmm-snp" &&
      -n "${E2E_OPENVMM_KERNEL_SRC_LOCAL}" ]]; then
  [[ -d "${E2E_OPENVMM_KERNEL_SRC_LOCAL}/.git" ]] \
    || die "E2E_OPENVMM_KERNEL_SRC_LOCAL is not a git checkout: ${E2E_OPENVMM_KERNEL_SRC_LOCAL}"
  kernel_archive=$(mktemp)
  trap 'rm -f -- "${kernel_archive}"' EXIT
  log "archiving ACI kernel source from ${E2E_OPENVMM_KERNEL_SRC_LOCAL}"
  git -C "${E2E_OPENVMM_KERNEL_SRC_LOCAL}" archive --format=tar.gz \
    --output="${kernel_archive}" HEAD || die "kernel source archive failed"
  scp "${kernel_archive}" "${E2E_SSH_HOST}:~/aci-openvmm-kernel.tar.gz" \
    || die "kernel source transfer failed"
  ssh "${E2E_SSH_HOST}" \
    'mkdir -p ~/src/openvmm-aci-kernel &&
     tar -xzf ~/aci-openvmm-kernel.tar.gz -C ~/src/openvmm-aci-kernel' \
    || die "kernel source extraction failed"
  ok "ACI kernel source synced"
fi

[[ "$#" -gt 0 ]] || exit 0

# Forward the knobs that change what the run means, so a remote run is not
# silently different from what was asked for locally.
env_prefix=""
for v in E2E_FAST E2E_SKIP_BUILD E2E_FORCE E2E_NIGHTLY_SHA E2E_BRANCH \
         E2E_STRICT_POLICY E2E_AGENT_POLICY E2E_REGISTRY E2E_NS \
         E2E_PLATFORM E2E_REPO_URL E2E_INIT_DATA \
         E2E_CLH_TAG E2E_UVM_KERNEL_VERSION E2E_OPENVMM_REPO \
         E2E_OPENVMM_REV E2E_OPENVMM_DIR E2E_OPENVMM_KERNEL_SRC \
         E2E_OPENVMM_VP_COUNT; do
  if [[ -n "${!v:-}" ]]; then
    env_prefix+="${v}=$(printf '%q' "${!v}") "
  fi
done

# E2E_STATE_DIR is an absolute path under the *local* $HOME, which does not
# exist on the node — forwarding it verbatim makes every mark_done fail. Keep
# the environment's identity (the directory name) and let the remote shell
# resolve $HOME itself.
if [[ -n "${E2E_STATE_DIR:-}" ]]; then
  env_prefix+="E2E_STATE_DIR=\$HOME/$(basename "${E2E_STATE_DIR}") "
fi

log "running on ${E2E_SSH_HOST}: $*"
# -t so ^C reaches the remote side rather than orphaning a multi-hour build.
ssh -t "${E2E_SSH_HOST}" "cd ~/coco-e2e && ${env_prefix}./run-all.sh $*"
