#!/usr/bin/env bash
#
# Copyright (c) 2024 NVIDIA Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Azure Linux 3.0 (CBL-Mariner / azl3) port of the NVIDIA GPU UVM chroot
# stage. This runs INSIDE the freshly-built Azure Linux rootfs (via
# `chroot . /azure_gpus_chroot.sh ...` from azure_gpus_rootfs.sh) and installs the
# NVIDIA userspace stack with tdnf against the NVIDIA azl3 CUDA repository.
#
# The kernel module (nvidia.ko) is NOT installed here: it is built by the
# kata kernel-azure-gpus build and dropped into ./lib/modules by
# azure_gpus_rootfs.sh, so we deliberately do NOT pull kmod-nvidia-open-dkms.

set -euo pipefail
[[ -n "${DEBUG:-}" ]] && set -x

# Error helpers
trap 'echo "chroot: ERROR at line ${LINENO}: ${BASH_COMMAND}" >&2' ERR
die() {
	local msg="${*:-fatal error}"
	echo "chroot: ${msg}" >&2
	exit 1
}

arch_target="${1:?arch_target not specified}"
nvidia_gpu_stack="${2:?nvidia_gpu_stack not specified}"
# cuda_repo_osv is the base-OS version string (e.g. "3.0"); kept for call
# compatibility with the Ubuntu variant but unused for tdnf repo setup.
cuda_repo_osv="${3:?cuda_repo_osv not specified}"
# azl3 CUDA repo base URL (ends in a slash), e.g.
#   https://developer.download.nvidia.com/compute/cuda/repos/azl3/sbsa/
cuda_repo_url="${4:?cuda_repo_url not specified}"
# .repo file name at that base URL, e.g. "cuda-azl3.repo"
cuda_repo_pkg="${5:?cuda_repo_pkg not specified}"
# tools_repo_url / tools_repo_pkg are unused on Azure Linux: the single azl3
# CUDA repo also ships the container toolkit, DCGM, fabricmanager and imex.
# They are still accepted for call compatibility with the Ubuntu variant.
tools_repo_url="${6:-}"
tools_repo_pkg="${7:-}"
# ctk_version comes from versions.yaml in Ubuntu (deb-revisioned) form and does
# not map to the azl3 revisions, so it is not used to pin the toolkit here.
ctk_version="${8:-}"

# --releasever bypasses tdnf's distroverpkg lookup: the Azure Linux release
# package (the distroverpkg target) is not installed in the minimal rootfs, so
# tdnf errors 1022 without it. Matches how the base rootfs install is invoked.
TDNF_INSTALL="tdnf install -y --releasever=${cuda_repo_osv}"

is_feature_enabled() {
	local feature="$1"
	[[ ",${nvidia_gpu_stack}," == *",${feature},"* ]]
}

# Echo the driver version parsed from the 'driver=<ver>' NVIDIA_GPU_STACK
# token (e.g. "610.43.02"), or die if it is missing.
get_driver_version() {
	local driver_version=""
	if [[ "${nvidia_gpu_stack}" =~ driver=([^,]+) ]]; then
		driver_version="${BASH_REMATCH[1]}"
	fi
	[[ -z "${driver_version}" ]] && die "NVIDIA_GPU_STACK must include 'driver=<version>' (e.g. 'driver=610.43.02')"
	echo "${driver_version}"
}

setup_repositories() {
	echo "chroot: Setup NVIDIA azl3 CUDA repository"

	# Drop the NVIDIA azl3 CUDA repo definition. cuda_repo_url already ends
	# in a slash and cuda_repo_pkg is the per-arch .repo file name. The repo
	# dir is created by the azurelinux-repos package, but mkdir defensively in
	# case the base set did not pull it.
	mkdir -p /etc/yum.repos.d
	curl -fsSL -o /etc/yum.repos.d/cuda-azl3.repo "${cuda_repo_url}${cuda_repo_pkg}"

	# The NVIDIA driver packages depend on packages in the Azure Linux
	# "extended" repo (e.g. ocl-icd, required by nvidia-driver-cuda). The
	# minimal rootfs (azurelinux-repos) only ships the base repo, so add the
	# extended repo here. $releasever/$basearch are expanded by tdnf.
	cat > /etc/yum.repos.d/azurelinux-extended.repo <<-'EOF'
	[azurelinux-official-extended]
	name=Azure Linux Official Extended $releasever $basearch
	baseurl=https://packages.microsoft.com/azurelinux/$releasever/prod/extended/$basearch
	gpgkey=file:///etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY
	gpgcheck=1
	repo_gpgcheck=1
	enabled=1
	skip_if_unavailable=True
	sslverify=1
	EOF

	# The CUDA repo file carries a gpgkey= directive; tdnf imports it on demand
	# at install time (gpgme is present), so no rpm --import is needed -- rpm is
	# not in the minimal rootfs. --releasever bypasses the distroverpkg lookup.
	tdnf -y --releasever="${cuda_repo_osv}" makecache || true
}

install_userspace_components() {
	local driver_version
	driver_version="$(get_driver_version)"
	echo "chroot: driver_version: ${driver_version}"

	# On azl3 the driver userspace ships as a small set of versioned RPMs.
	# nvidia-driver-cuda-libs carries libcuda.so.1 + the libnvidia-* set,
	# nvidia-kmod-common carries the GSP firmware (the equivalent of the
	# Ubuntu 'nvidia-firmware' package), and nvidia-imex is required for
	# the GB200 NVLink fabric bring-up. Pin every one to the exact driver
	# version so tdnf never floats them onto a newer branch published in
	# the repo.
	local -a driver_pkgs=(
		"nvidia-driver-cuda-libs-${driver_version}"
		"nvidia-driver-cuda-${driver_version}"
		"nvidia-kmod-common-${driver_version}"
		"nvidia-persistenced-${driver_version}"
		"nvidia-modprobe-${driver_version}"
		"nvidia-imex-${driver_version}"
	)
	# shellcheck disable=SC2086
	${TDNF_INSTALL} "${driver_pkgs[@]}"

	# nvidia-driver-common only started being published on the azl3 CUDA repo
	# with the 610 driver series; it does not exist for the 580 LTS / 595
	# branches, where its files ship inside nvidia-kmod-common. Install it
	# best-effort so 610+ still gets it while 580/595 don't abort the build.
	# shellcheck disable=SC2086
	${TDNF_INSTALL} "nvidia-driver-common-${driver_version}" || \
		echo "chroot: nvidia-driver-common-${driver_version} not in repo; skipping (expected for pre-610 drivers)"

	# Needed for confidential-data-hub and NVAT runtime dependencies. These
	# resolve from the Azure Linux base repositories.
	# shellcheck disable=SC2086
	${TDNF_INSTALL} cryptsetup device-mapper libxml2 e2fsprogs
}

install_nvidia_fabricmanager() {
	is_feature_enabled "nvswitch" || {
		echo "chroot: Skipping NVIDIA fabricmanager installation"
		return
	}
	echo "chroot: Install NVIDIA fabricmanager"

	local driver_version
	driver_version="$(get_driver_version)"

	local -a pkgs=(
		"nvidia-fabricmanager-${driver_version}"
		"libnvidia-nscq-${driver_version}"
	)

	# nvlsm is the NVLink Subnet Manager, required only by multi-node
	# NVSwitch products (e.g. GB200 NVL72). It is date-versioned on azl3
	# (e.g. nvlsm-2025.10.14-1), independent of the driver major, so it is
	# gated on its own token and pinned via 'nvlsm_version=<ver>'.
	if is_feature_enabled "nvlsm"; then
		local nvlsm_version=""
		if [[ "${nvidia_gpu_stack}" =~ nvlsm_version=([^,]+) ]]; then
			nvlsm_version="${BASH_REMATCH[1]}"
		fi
		if [[ -n "${nvlsm_version}" ]]; then
			pkgs+=("nvlsm-${nvlsm_version}")
		else
			pkgs+=("nvlsm")
		fi
	fi

	# shellcheck disable=SC2086
	${TDNF_INSTALL} "${pkgs[@]}"
}

install_nvidia_ctk() {
	echo "chroot: Installing NVIDIA GPU container runtime"
	# nvidia-container-toolkit-base provides nvidia-ctk and the CDI hook.
	# The azl3 revision (1.20.x) differs from the Ubuntu ctk_version, so it
	# is installed unpinned and left to the repo's latest.
	# shellcheck disable=SC2086
	${TDNF_INSTALL} nvidia-container-toolkit-base
}

install_nvidia_dcgm() {
	is_feature_enabled "dcgm" || {
		echo "chroot: Skipping NVIDIA DCGM installation"
		return
	}

	echo "chroot: Install NVIDIA DCGM"

	# DCGM 4.x is split into CUDA-runtime flavors on azl3. Driver 610 pairs
	# with the CUDA 13 runtime.
	# shellcheck disable=SC2086
	${TDNF_INSTALL} datacenter-gpu-manager-4-cuda13 \
		datacenter-gpu-manager-exporter
}

install_devkit_packages() {
	is_feature_enabled "devkit" || {
		echo "chroot: Skipping devkit packages installation"
		return
	}

	echo "chroot: Install devkit packages"

	# shellcheck disable=SC2086
	${TDNF_INSTALL} kmod
}

# Install debug binaries that the rootfs builder will carry into the GPU UVM
# image: a real bash (the kata-static-busybox omits the `sh` applet) and
# strace (the canonical "what syscall failed?" tool for silent
# fabricmanager / NVRC failures). Installed unconditionally; the size cost is
# trivial against the UVM free-space headroom.
install_debug_tools() {
	echo "chroot: Install debug tools (bash + strace)"

	# shellcheck disable=SC2086
	${TDNF_INSTALL} bash strace
}

cleanup_rootfs() {
	echo "chroot: Cleanup NVIDIA GPU rootfs"

	tdnf clean all || true

	# tdnf's repo-key import spawns a gpg-agent that leaves live sockets under
	# /root/.gnupg. Those sockets make the later `tar --remove-files` fail to
	# rmdir the tree, so kill the agent and drop the homedir (rm can unlink
	# sockets; tar cannot).
	gpgconf --kill all 2>/dev/null || true
	rm -rf /root/.gnupg

	rm -rf /var/cache/tdnf/* /var/log/tdnf.log
	rm -f /usr/bin/nvidia-ngx-updater /usr/bin/nvidia-container-runtime

	# Clear and regenerate the ld cache so the freshly installed
	# libcuda / libnvidia-* libraries are resolvable.
	rm -f /etc/ld.so.cache
	ldconfig
}

# Start of script
echo "chroot: Setup NVIDIA GPU rootfs stage one (Azure Linux / tdnf)"

setup_repositories
install_userspace_components
install_nvidia_fabricmanager
install_nvidia_ctk
install_nvidia_dcgm
install_devkit_packages
install_debug_tools
cleanup_rootfs
