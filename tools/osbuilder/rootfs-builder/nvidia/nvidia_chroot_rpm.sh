#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# RPM-based chroot setup for NVIDIA GPU rootfs (Azure Linux / RHEL9)
# This is the DNF equivalent of nvidia_chroot.sh (APT-based).

set -euo pipefail
[[ -n "${DEBUG}" ]] && set -x

# Error helpers
trap 'echo "chroot: ERROR at line ${LINENO}: ${BASH_COMMAND}" >&2' ERR
die() {
  local msg="${*:-fatal error}"
  echo "chroot: ${msg}" >&2
  exit 1
}

arch_target="${1:?arch_target not specified}"
nvidia_gpu_stack="${2:?nvidia_gpu_stack not specified}"
cuda_repo_osv="${3:?cuda_repo_osv not specified}"
cuda_repo_url="${4:?cuda_repo_url not specified}"
cuda_repo_pkg="${5:?cuda_repo_pkg not specified}"
tools_repo_url="${6:?tools_repo_url not specified}"
tools_repo_pkg="${7:?tools_repo_pkg not specified}"
ctk_version="${8:?ctk_version not specified}"
DNF_INSTALL="dnf install -y --setopt=install_weak_deps=False"

is_feature_enabled() {
	local feature="$1"
	[[ ",${nvidia_gpu_stack}," == *",${feature},"* ]]
}

setup_dnf_repositories() {
	echo "chroot: Setup DNF repositories"

	mkdir -p /etc/yum.repos.d /var/cache/dnf /var/log/dnf

	# Install the CUDA .repo file for NVIDIA packages
	curl -fsSL -o /etc/yum.repos.d/cuda.repo "${cuda_repo_url}/${cuda_repo_pkg}"

	# Tools repository (toolkit, DCGM, etc.) - same .repo file if URL matches,
	# otherwise install separately
	if [[ "${tools_repo_url}" != "${cuda_repo_url}" ]] || \
	   [[ "${tools_repo_pkg}" != "${cuda_repo_pkg}" ]]; then
		curl -fsSL -o /etc/yum.repos.d/nvidia-tools.repo "${tools_repo_url}/${tools_repo_pkg}"
	fi

	# Set priority: NVIDIA repos get higher priority than base repos
	dnf install -y dnf-plugins-core 2>/dev/null || true
	if command -v dnf config-manager &>/dev/null; then
		dnf config-manager --set-enabled cuda-rhel9-x86_64 2>/dev/null || true
	fi

	dnf makecache
}

install_userspace_components() {
	# Extract the driver=XXX part first, then get the value
	if [[ "${nvidia_gpu_stack}" =~ driver=([^,]+) ]]; then
		driver_version="${BASH_REMATCH[1]}"
	fi
	echo "chroot: driver_version: ${driver_version}"

	# In the RHEL9 repo, individual deb packages like libnvidia-cfg1,
	# libnvidia-gl, libnvidia-extra, libnvidia-decode, libnvidia-fbc1,
	# libnvidia-encode are (hopefully) all bundled into nvidia-driver-libs.
	# nvidia-firmware is not available as a separate RPM either.
	eval "${DNF_INSTALL}" \
		"nvidia-driver-libs-${driver_version}" \
		"nvidia-imex-${driver_version}" \
		"libnvidia-nscq-${driver_version}"

	dnf versionlock add \
		"nvidia-driver-libs-${driver_version}" \
		"nvidia-imex-${driver_version}" \
		"libnvidia-nscq-${driver_version}" \
		2>/dev/null || true
}

echo "chroot: Setup NVIDIA GPU rootfs stage one (RPM)"

setup_dnf_repositories
install_userspace_components

echo "chroot: RPM-based NVIDIA GPU rootfs setup - remaining steps not yet implemented"
die "nvidia_chroot_rpm.sh install steps not yet implemented"
