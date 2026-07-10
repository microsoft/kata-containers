#!/usr/bin/env bash
#
# Copyright (c) 2024 NVIDIA Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
[[ -n "${DEBUG}" ]] && set -x

shopt -s nullglob
shopt -s extglob

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
APT_INSTALL="apt -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' -yqq --no-install-recommends install"

export DEBIAN_FRONTEND=noninteractive

is_feature_enabled() {
	local feature="$1"
	[[ ",${nvidia_gpu_stack}," == *",${feature},"* ]]
}

# apt-mark hold only the packages from "$@" that are actually installed.
#
# Some NVIDIA packages (notably nvidia-imex and libnvidia-nscq) dropped
# their -${driver_major} branch suffix starting with the 580 driver: the
# CUDA repo still ships the suffixed name as a Provides: alias, so
# `apt install nvidia-imex-580` succeeds and pulls in the real binary
# package `nvidia-imex`, but `apt-mark hold nvidia-imex-580` fails with
# "Can't select installed nor candidate version" because apt-mark does
# not follow Provides:. That non-zero exit trips `set -e` and aborts the
# rootfs build. Filter the list to what dpkg actually has installed so
# the hold succeeds regardless of which alias name apt resolved.
hold_if_installed() {
	local pkg
	local -a installed=()
	for pkg in "$@"; do
		if dpkg-query -W -f='${Status}\n' "${pkg}" 2>/dev/null \
			| grep -q '^install ok installed$'; then
			installed+=("${pkg}")
		fi
	done
	[[ "${#installed[@]}" -eq 0 ]] && return 0
	apt-mark hold "${installed[@]}"
}

install_nvidia_ctk() {
	echo "chroot: Installing NVIDIA GPU container runtime"
	# Base  gives a nvidia-ctk and the nvidia-container-runtime
	eval "${APT_INSTALL}" nvidia-container-toolkit-base="${ctk_version}"
}

install_nvidia_fabricmanager() {
	is_feature_enabled "nvswitch" || {
		echo "chroot: Skipping NVIDIA fabricmanager installation"
		return
	}
	echo "chroot: Install NVIDIA fabricmanager"

	# Pin fabricmanager / nscq / nvlsm to the same driver MAJOR version
	# (see the rationale in install_userspace_components). Without the
	# -${driver_major} suffix apt resolves the unversioned names to
	# whatever the latest driver branch is in the CUDA repo, which can
	# pull in a mismatched nvidia-persistenced and break the build.
	local driver_version=""
	if [[ "${nvidia_gpu_stack}" =~ driver=([^,]+) ]]; then
		driver_version="${BASH_REMATCH[1]}"
	fi
	[[ -z "${driver_version}" ]] && die "NVIDIA_GPU_STACK must include 'driver=<version>'"
	local driver_major="${driver_version%%.*}"

	# nvlsm is the NVIDIA Subnet Manager for NVSwitch fabric. It is only
	# required by certain multi-node NVSwitch products (e.g. GB200 NVL72);
	# single-node NVSwitch hosts (e.g. HGX A100, HGX H100) do not need it,
	# and pulling it in unconditionally drags an extra ~100 MB of NVLSM
	# tooling into every fabricmanager-enabled UVM. Gate it on a dedicated
	# NVIDIA_GPU_STACK token so consumers opt in only when they need it.
	local pkgs="nvidia-fabricmanager-${driver_major} libnvidia-nscq-${driver_major}"
	# nvlsm (NVLink Subnet Manager) is NOT suffixed with the driver major on
	# the aarch64 'sbsa' CUDA repo: it ships under the bare name 'nvlsm' with a
	# date-based version (e.g. nvlsm_2025.10.14-1_arm64.deb), so 'nvlsm-580' has
	# no apt candidate. When the caller pins a version via the
	# 'nvlsm_version=<ver>' token in NVIDIA_GPU_STACK (mirrors the 'driver=<ver>'
	# token), install 'nvlsm=<ver>'; otherwise fall back to the bare 'nvlsm'.
	if is_feature_enabled "nvlsm"; then
		local nvlsm_version=""
		if [[ "${nvidia_gpu_stack}" =~ nvlsm_version=([^,]+) ]]; then
			nvlsm_version="${BASH_REMATCH[1]}"
		fi
		if [[ -n "${nvlsm_version}" ]]; then
			pkgs+=" nvlsm=${nvlsm_version}"
		else
			pkgs+=" nvlsm"
		fi
	fi

	# shellcheck disable=SC2086 # pkgs is an intentionally word-split list
	eval "${APT_INSTALL}" ${pkgs}
	# Include the unversioned aliases: on driver 580+ libnvidia-nscq
	# no longer ships with a -${driver_major} suffix, so apt resolves
	# the request via Provides: to the bare name. See hold_if_installed.
	# apt-mark hold takes bare package names, so hold 'nvlsm' (not 'nvlsm=<ver>').
	# shellcheck disable=SC2086
	hold_if_installed nvidia-fabricmanager-${driver_major} libnvidia-nscq-${driver_major} libnvidia-nscq nvlsm
}

install_userspace_components() {
	# Extract the driver=XXX part first, then get the value
	local driver_version=""
	if [[ "${nvidia_gpu_stack}" =~ driver=([^,]+) ]]; then
		driver_version="${BASH_REMATCH[1]}"
	fi
	[[ -z "${driver_version}" ]] && die "NVIDIA_GPU_STACK must include 'driver=<version>' (e.g. 'driver=570')"
	echo "chroot: driver_version: ${driver_version}"

	eval "${APT_INSTALL}" nvidia-driver-pinning-"${driver_version}"

	# Pin every libnvidia-* / nvidia-imex / nvidia-firmware install to
	# the driver MAJOR version (e.g. "580" from "580.159.04"). The
	# nvidia-driver-pinning-${driver_version} package above drops a pin
	# that covers binary packages produced by src:nvidia-graphics-drivers-
	# ${driver_major} (i.e. libnvidia-compute-580, libnvidia-gl-580, ...),
	# but it does NOT cover the unversioned metapackage names
	# (libnvidia-compute, libnvidia-gl, ...). As soon as the CUDA repo
	# ships a newer driver branch (e.g. 610), those unversioned metas
	# resolve to the new branch and apt fails with unmet dependencies
	# like:
	#   libnvidia-compute : Depends: nvidia-persistenced (= 610.43.02-1ubuntu1)
	# Installing the versioned binary names directly sidesteps the
	# resolver entirely. nvidia-settings is intentionally left unversioned
	# because it is not part of the driver-branch closure.
	local driver_major="${driver_version%%.*}"
	local userspace_pkgs=(
		"nvidia-imex-${driver_major}"
		"nvidia-firmware-${driver_major}"
		"libnvidia-cfg1-${driver_major}"
		"libnvidia-gl-${driver_major}"
		"libnvidia-extra-${driver_major}"
		"libnvidia-decode-${driver_major}"
		"libnvidia-fbc1-${driver_major}"
		"libnvidia-encode-${driver_major}"
		"libnvidia-nscq-${driver_major}"
		"libnvidia-compute-${driver_major}"
		"nvidia-settings"
	)

	eval "${APT_INSTALL}" "${userspace_pkgs[@]}"
	# Include the unversioned aliases for the two packages that dropped
	# their -${driver_major} suffix on driver 580+ (nvidia-imex and
	# libnvidia-nscq); hold_if_installed filters to whatever apt actually
	# resolved so this works on both old and new driver branches.
	hold_if_installed "${userspace_pkgs[@]}" nvidia-imex libnvidia-nscq

	# Needed for confidential-data-hub and NVAT runtime dependencies
	eval "${APT_INSTALL}" cryptsetup-bin dmsetup         \
		libargon2-1 e2fsprogs libxml2

	apt-mark hold cryptsetup-bin dmsetup libargon2-1     \
		e2fsprogs libxml2
}

# Install debug binaries that the chiseled rootfs builder will cherry-pick
# into the GPU UVM image. Specifically:
#
#   bash    -- a real POSIX shell. The kata-static-busybox shipped to the
#              chiseled rootfs is a minimized build that intentionally
#              omits the `sh` applet (saving ~100 KiB at the cost of any
#              shebang-based scripting being broken). Carrying a real bash
#              binary in the chiseled rootfs lets dev-time /init wrappers
#              (e.g. dev-swap-nvrc.sh P5 diagnostic init script) just work
#              with `#!/bin/bash`. ~1 MiB binary + libtinfo dep.
#
#   strace  -- the canonical "what syscall failed?" tool. Several silent
#              fabricmanager / NVRC failures (exit 255 with no useful
#              stderr, hung IOCTLs on /dev/nvidia*) are only diagnosable
#              by tracing the actual syscall sequence inside the UVM. The
#              5 MiB strace + libdw/libelf/libz/libzstd/liblzma deps are
#              negligible against the new ROOT_FREE_SPACE=512 MiB headroom.
#
# These are installed unconditionally (no `is_feature_enabled` gate)
# because the size cost is trivial and the debugging upside is high. If a
# future production tenant cares about the ~10 MiB they can be gated
# behind a new `debug-tools` NVIDIA_GPU_STACK token.
install_debug_tools() {
	echo "chroot: Install debug tools (bash + strace) for chiseled rootfs to pick up"

	eval "${APT_INSTALL}" bash strace
	apt-mark hold bash strace
}

setup_apt_repositories() {
	echo "chroot: Setup APT repositories"

	# Architecture to mirror mapping
	declare -A arch_to_mirror=(
		["x86_64"]="us.archive.ubuntu.com/ubuntu"
		["aarch64"]="ports.ubuntu.com/ubuntu-ports"
	)

	local mirror="${arch_to_mirror[${arch_target}]}"
	[[ -z "${mirror}" ]] && die "Unknown arch_target: ${arch_target}"

	local deb_arch="amd64"
	[[ "${arch_target}" == "aarch64" ]] && deb_arch="arm64"

	mkdir -p /var/cache/apt/archives/partial /var/log/apt                  \
		/var/lib/dpkg/{info,updates,alternatives,triggers,parts}

	touch /var/lib/dpkg/status

	rm -f /etc/apt/sources.list.d/*

	key="/usr/share/keyrings/ubuntu-archive-keyring.gpg"
	comp="main restricted universe multiverse"

	cat <<-CHROOT_EOF > /etc/apt/sources.list.d/"${cuda_repo_osv}".list
		deb [arch=${deb_arch} signed-by=${key}] http://${mirror} ${cuda_repo_osv} ${comp}
		deb [arch=${deb_arch} signed-by=${key}] http://${mirror} ${cuda_repo_osv}-updates ${comp}
		deb [arch=${deb_arch} signed-by=${key}] http://${mirror} ${cuda_repo_osv}-security ${comp}
		deb [arch=${deb_arch} signed-by=${key}] http://${mirror} ${cuda_repo_osv}-backports ${comp}
	CHROOT_EOF

	# Tools repository is always needed for toolkit, DCGM and other helpers
	curl -fsSL -O "${tools_repo_url}/${tools_repo_pkg}"
	dpkg -i "${tools_repo_pkg}" && rm -f "${tools_repo_pkg}"

	# Remote or local CUDA repository
	curl -fsSL -O "${cuda_repo_url}/${cuda_repo_pkg}"
	dpkg -i "${cuda_repo_pkg}" && rm -f "${cuda_repo_pkg}"

	# Copy keyring if local repo was installed
	keyring="/var/cuda-repo-*-local/cuda-*-keyring.gpg"
	# shellcheck disable=SC2128 # Intentional: expect exactly one match
	[[ -e "${keyring}" ]] && cp "${keyring}" /usr/share/keyrings/

	# Set priorities: CUDA repos highest, Ubuntu non-driver next, Ubuntu blocked for driver packages
	cat <<-CHROOT_EOF > /etc/apt/preferences.d/nvidia-priority
		Package: *
		Pin: origin $(dirname "${mirror}")
		Pin-Priority: 400

		Package: nvidia-* libnvidia-*
		Pin: origin $(dirname "${mirror}")
		Pin-Priority: -1

		Package: *
		Pin: origin developer.download.nvidia.com
		Pin-Priority: 800

		Package: *
		Pin: origin ""
		Pin-Priority: 900
	CHROOT_EOF

	apt update
}

install_nvidia_dcgm() {
	is_feature_enabled "dcgm" || {
		echo "chroot: Skipping NVIDIA DCGM installation"
		return
	}

	echo "chroot: Install NVIDIA DCGM"

	eval "${APT_INSTALL}" datacenter-gpu-manager \
		datacenter-gpu-manager-exporter
}

install_devkit_packages() {
	is_feature_enabled "devkit" || {
		echo "chroot: Skipping devkit packages installation"
		return
	}

	echo "chroot: Install devkit packages"

	eval "${APT_INSTALL}" kmod
	apt-mark hold kmod
}

cleanup_rootfs() {
	echo "chroot: Cleanup NVIDIA GPU rootfs"

	apt-mark hold libstdc++6 libzstd1 libgnutls30t64 pciutils linuxptp libnftnl11
	apt autoremove -yqq

	apt clean
	apt autoclean

	rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/apt /var/cache/debconf
	rm -f /etc/apt/sources.list
	rm -f /usr/bin/nvidia-ngx-updater /usr/bin/nvidia-container-runtime
	rm -f /var/log/{nvidia-installer.log,dpkg.log,alternatives.log}

	# Clear and regenerate the ld cache
	rm -f /etc/ld.so.cache
	ldconfig
}

# Start of script
echo "chroot: Setup NVIDIA GPU rootfs stage one"

setup_apt_repositories
install_userspace_components
install_nvidia_fabricmanager
install_nvidia_ctk
install_nvidia_dcgm
install_devkit_packages
install_debug_tools
cleanup_rootfs
