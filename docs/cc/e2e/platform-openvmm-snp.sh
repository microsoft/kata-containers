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

openvmm_assert_snp_host() {
  clh_assert_snp_host
}

openvmm_configure_containerd() {
  local cfg=/etc/containerd/config.toml
  : "${E2E_OPENVMM_RUNTIME_CONFIG:?OpenVMM runtime config path is not set}"

  sudo tee "${cfg}" >/dev/null <<EOF
version = 3

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
    SystemdCgroup = true

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata-openvmm]
  runtime_type = "io.containerd.kata-openvmm.v2"
  snapshotter = "erofs"
  pod_annotations = ["io.katacontainers.*"]
  container_annotations = ["io.katacontainers.*"]
  privileged_without_host_devices = true
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata-openvmm.options]
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
  clh_need_azl3
  log "installing OpenVMM SNP host and build packages"
  sudo dnf -y install "${OPENVMM_HOST_PKGS[@]}" \
    || die "OpenVMM host dependency installation failed"
  sudo dnf -y install kernel-mshv kernel-mshv-devel mshv mshv-bootloader-lx edk2-hvloader \
    || die "MSHV host package installation failed"

  clh_install_containerd
  clh_enable_dom0
  openvmm_assert_snp_host
  E2E_OPENVMM_RUNTIME_CONFIG="${E2E_KATA_DEFAULTS}/runtime-rs/configuration.toml"
  export E2E_OPENVMM_RUNTIME_CONFIG
  openvmm_configure_containerd
  ok "node bootstrapped for openvmm-snp"
}

openvmm_deploy_k8s() {
  clh_deploy_k8s
}

openvmm_register_runtimeclass() {
  clh_register_runtimeclass
}

openvmm_prepare_sources() {
  if [[ ! -d "${E2E_OPENVMM_DIR}/.git" ]]; then
    log "cloning OpenVMM ${E2E_OPENVMM_BRANCH}"
    git clone --single-branch --branch "${E2E_OPENVMM_BRANCH}" \
      "${E2E_OPENVMM_REPO}" "${E2E_OPENVMM_DIR}" \
      || die "OpenVMM clone failed"
  fi
  (
    cd "${E2E_OPENVMM_DIR}"
    git fetch origin "${E2E_OPENVMM_BRANCH}" --quiet
    git checkout --quiet "${E2E_OPENVMM_BRANCH}"
    git pull --ff-only --quiet
    PROTOC="$(command -v protoc)" cargo xflowey restore-packages --no-compat-igvm
  ) || die "OpenVMM source preparation failed"

  [[ -f "${E2E_OPENVMM_KERNEL_SRC}/Makefile" ]] || die \
    "ACI kernel source is missing at ${E2E_OPENVMM_KERNEL_SRC}.
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
  openvmm_register_runtimeclass

  E2E_GUEST_IMAGE="${E2E_OPENVMM_OUT}/${E2E_GUEST_IMAGE_NAME}"
  E2E_GUEST_IGVM="${E2E_OPENVMM_OUT}/${E2E_GUEST_IGVM_NAME}"
  export E2E_GUEST_IMAGE E2E_GUEST_IGVM

  [[ -f "${E2E_GUEST_IMAGE}" ]] || die "OpenVMM guest image was not built"
  [[ -f "${E2E_GUEST_IGVM}" ]] || die "OpenVMM IGVM was not built"
  grep -q "^default_vcpus = ${E2E_OPENVMM_VP_COUNT}$" "${E2E_OPENVMM_RUNTIME_CONFIG}" \
    || die "runtime VP count does not match the requested IGVM topology"
  ok "OpenVMM SNP runtime installed"
}
