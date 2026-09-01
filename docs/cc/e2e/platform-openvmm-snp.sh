#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2154

# Reuse the Azure Linux, MSHV Dom0, and kubeadm helpers. OpenVMM supplies its
# own build and containerd configuration below.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/platform-clh-snp.sh"

OPENVMM_HOST_PKGS=(
  bc binutils bison clang cmake containerd cpio cri-tools curl
  device-mapper-devel elfutils-libelf-devel erofs-utils file flex gcc gcc-c++
  git glibc-devel gzip jq kernel-headers libseccomp-devel llvm-devel make
  openssl-devel parted perl pkg-config protobuf protobuf-devel python3-pip
  qemu-img tar veritysetup
)

openvmm_configure_containerd() {
  local cfg=/etc/containerd/config.toml
  : "${E2E_OPENVMM_RUNTIME_CONFIG:?OpenVMM runtime config path is not set}"

  [[ -f "${cfg}" ]] && sudo cp -n "${cfg}" "${cfg}.pre-e2e"
  sudo tee "${cfg}" >/dev/null <<EOF
version = 3

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
    SystemdCgroup = true

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata-cc]
  runtime_type = "io.containerd.kata-cc.v2"
  snapshotter = "erofs"
  pod_annotations = ["io.katacontainers.*"]
  container_annotations = ["io.katacontainers.*"]
  privileged_without_host_devices = true
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata-cc.options]
    ConfigPath = "${E2E_OPENVMM_RUNTIME_CONFIG}"

[plugins.'io.containerd.snapshotter.v1.erofs']
  default_size = "0"

[plugins.'io.containerd.differ.v1.erofs']
  enable_dmverity = true
  mkfs_options = ["-T0", "--mkfs-time", "--sort=none"]
  enable_tar_index = false

[plugins.'io.containerd.service.v1.diff-service']
  default = ["erofs", "walking"]
EOF

  sudo systemctl restart containerd || die "containerd failed to restart for OpenVMM"
  wait_for 60 "containerd CRI ready" \
    sudo crictl info
}

openvmm_bootstrap_node() {
  need_azl3
  log "installing OpenVMM SNP host and build packages"
  sudo dnf -y install "${OPENVMM_HOST_PKGS[@]}" \
    || die "OpenVMM host dependency installation failed"
  sudo dnf -y install kernel-mshv kernel-mshv-devel mshv mshv-bootloader-lx edk2-hvloader \
    || die "MSHV host package installation failed"

  install_containerd
  enable_dom0
  assert_snp_host
  E2E_OPENVMM_RUNTIME_CONFIG="${E2E_KATA_DEFAULTS}/runtime-rs/configuration.toml"
  export E2E_OPENVMM_RUNTIME_CONFIG
  openvmm_configure_containerd
  ok "node bootstrapped for openvmm-snp"
}

openvmm_prepare_sources() {
  if [[ ! -d "${E2E_OPENVMM_DIR}/.git" ]]; then
    log "cloning OpenVMM"
    git clone --no-checkout "${E2E_OPENVMM_REPO}" "${E2E_OPENVMM_DIR}" \
      || die "OpenVMM clone failed"
  fi
  (
    set -e
    cd "${E2E_OPENVMM_DIR}"
    git fetch origin "${E2E_OPENVMM_REV}" --quiet
    git checkout --detach --quiet "${E2E_OPENVMM_REV}"
    [[ "$(git rev-parse HEAD)" = "${E2E_OPENVMM_REV}" ]]
    PROTOC="$(command -v protoc)" cargo xflowey restore-packages --no-compat-igvm
  ) || die "OpenVMM source preparation failed"

  [[ -f "${E2E_OPENVMM_KERNEL_SRC}/Makefile" &&
     -x "${E2E_OPENVMM_KERNEL_SRC}/scripts/config" ]] || die \
    "ACI kernel source is incomplete at ${E2E_OPENVMM_KERNEL_SRC}.
Provide the validated ACI kernel source or set E2E_OPENVMM_KERNEL_SRC."
}

openvmm_build_and_deploy() {
  openvmm_prepare_sources

  E2E_OPENVMM_OUT="${E2E_KATA_PREFIX}/share/kata-containers"
  E2E_OPENVMM_RUNTIME_CONFIG="${E2E_KATA_DEFAULTS}/runtime-rs/configuration.toml"
  export E2E_OPENVMM_OUT E2E_OPENVMM_RUNTIME_CONFIG
  mkdir -p "${E2E_OPENVMM_OUT}" "$(dirname "${E2E_OPENVMM_RUNTIME_CONFIG}")"

  local tooling="${E2E_REPO_DIR}/tools/osbuilder/openvmm-igvm"
  local policy="${E2E_REPO_DIR}/src/kata-opa/allow-set-policy.rego"
  [[ -d "${tooling}" ]] || die "OpenVMM osbuilder tooling is missing"
  [[ -f "${policy}" ]] || die "SetPolicy bootstrap policy is missing: ${policy}"

  log "building strict-policy OpenVMM guest image"
  make -C "${tooling}" guest-image \
    OUT_DIR="${E2E_OPENVMM_OUT}" \
    AGENT_POLICY="${E2E_AGENT_POLICY}" \
    AGENT_POLICY_FILE="${policy}" \
    STRICT_POLICY="${E2E_STRICT_POLICY}" \
    || die "OpenVMM guest image build failed"

  log "building and installing OpenVMM runtime"
  CONFIGURE_CONTAINERD=no \
  DISABLE_NEW_NETNS=no \
  NETWORK_MODEL=tcfilter \
  REBUILD_IGVM=yes \
  OPENVMM_DIR="${E2E_OPENVMM_DIR}" \
  KERNEL_SRC="${E2E_OPENVMM_KERNEL_SRC}" \
  KATA_IMAGE="${E2E_OPENVMM_OUT}/kata-containers.img" \
  ROOT_HASH_FILE="${E2E_OPENVMM_OUT}/root_hash_.txt" \
  OUT_DIR="${E2E_OPENVMM_OUT}" \
  RUNTIME_CONFIG="${E2E_OPENVMM_RUNTIME_CONFIG}" \
  VP_COUNT="${E2E_OPENVMM_VP_COUNT}" \
    "${tooling}/e2e-setup.sh" \
    || die "OpenVMM runtime setup failed"

  openvmm_configure_containerd
  register_runtimeclass

  E2E_GUEST_IMAGE="${E2E_OPENVMM_OUT}/${E2E_GUEST_IMAGE_NAME}"
  E2E_GUEST_IGVM="${E2E_OPENVMM_OUT}/${E2E_GUEST_IGVM_NAME}"
  export E2E_GUEST_IMAGE E2E_GUEST_IGVM

  [[ -f "${E2E_GUEST_IMAGE}" ]] || die "OpenVMM guest image was not built"
  [[ -f "${E2E_GUEST_IGVM}" ]] || die "OpenVMM IGVM was not built"
  local base_vcpus workload_vcpus
  base_vcpus=$(sed -n 's/^default_vcpus = //p' "${E2E_OPENVMM_RUNTIME_CONFIG}")
  workload_vcpus=$(sed -n 's/^static_sandbox_default_workload_vcpus = //p' \
    "${E2E_OPENVMM_RUNTIME_CONFIG}")
  [[ $((base_vcpus + workload_vcpus)) -eq "${E2E_OPENVMM_VP_COUNT}" ]] \
    || die "effective runtime VP count does not match the requested IGVM topology"
  ok "OpenVMM SNP runtime installed"
}
