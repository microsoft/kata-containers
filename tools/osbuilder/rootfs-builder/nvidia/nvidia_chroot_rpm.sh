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
DNF_OPTS="--releasever=${cuda_repo_osv}"
DNF_INSTALL="dnf install -y --setopt=install_weak_deps=False ${DNF_OPTS}"

is_feature_enabled() {
	local feature="$1"
	[[ ",${nvidia_gpu_stack}," == *",${feature},"* ]]
}

setup_dnf_repositories() {
	echo "chroot: Setup DNF repositories"

	mkdir -p /etc/yum.repos.d /var/cache/dnf /var/log/dnf

	# The base rootfs was populated by tdnf --installroot from outside
	# the chroot.  Rebuild the RPM database so that DNF inside the chroot
	# recognises already-installed packages (bash, glibc, etc.) and can
	# resolve scriptlet dependencies like /bin/sh.
	rpm --rebuilddb

	if ! grep -q module_hotfixes /etc/dnf/dnf.conf 2>/dev/null; then
		echo "module_hotfixes=True" >> /etc/dnf/dnf.conf
	fi

	# The build container is Ubuntu, so no AZL3 base repos exist.
	# Create the base repo inline so DNF can resolve dependencies (glibc, bash, etc.).
	# Bootstrap with gpgcheck=0 because the GPG key is shipped by
	# azurelinux-repos-shared which we install below.
	if [[ ! -f /etc/yum.repos.d/azurelinux-official-base.repo ]]; then
		cat > /etc/yum.repos.d/azurelinux-official-base.repo <<-'EOF'
		[azurelinux-official-base]
		name=Azure Linux Official Base $releasever $basearch
		baseurl=https://packages.microsoft.com/azurelinux/$releasever/prod/base/$basearch
		gpgcheck=0
		repo_gpgcheck=0
		enabled=1
		skip_if_unavailable=True
		sslverify=1
		EOF
	fi

	# Install the package that ships /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY,
	# then flip the bootstrap repo to full GPG verification.

	# TODO: For better security, we'll need to figure out a better way to embed the certificates
	# a priori in the rootfs, possibly by doing a manual fetch/validation of the RPM azurelinux-repos-shared.
	dnf install -y --setopt=install_weak_deps=False ${DNF_OPTS} azurelinux-repos-shared
	sed -i 's/^gpgcheck=0/gpgcheck=1/' /etc/yum.repos.d/azurelinux-official-base.repo
	sed -i 's/^repo_gpgcheck=0/repo_gpgcheck=1/' /etc/yum.repos.d/azurelinux-official-base.repo
	if ! grep -q '^gpgkey=' /etc/yum.repos.d/azurelinux-official-base.repo; then
		sed -i '/^\[azurelinux-official-base\]/a gpgkey=file:///etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY' /etc/yum.repos.d/azurelinux-official-base.repo
	fi

	# Install the CUDA .repo file for NVIDIA packages
	curl -fsSL -o /etc/yum.repos.d/cuda.repo "${cuda_repo_url}/${cuda_repo_pkg}"

	# Tools repository (toolkit, DCGM, etc.) - same .repo file if URL matches,
	# otherwise install separately
	if [[ "${tools_repo_url}" != "${cuda_repo_url}" ]] || \
	   [[ "${tools_repo_pkg}" != "${cuda_repo_pkg}" ]]; then
		curl -fsSL -o /etc/yum.repos.d/nvidia-tools.repo "${tools_repo_url}/${tools_repo_pkg}"
	fi

	# Set priority and disable modular filtering on NVIDIA repo sections.
	# module_hotfixes=1 tells DNF to skip modular filtering for these third-party repos.
	# cuda.repo (azl3) gets priority=1 (highest) so its packages are preferred
	# over nvidia-tools.repo (rhel9, priority=10) when both provide the same package.
	if [[ -f /etc/yum.repos.d/cuda.repo ]]; then
		sed -i '/^\[/a priority=1\nmodule_hotfixes=1' /etc/yum.repos.d/cuda.repo
	fi
	if [[ -f /etc/yum.repos.d/nvidia-tools.repo ]]; then
		sed -i '/^\[/a priority=10\nmodule_hotfixes=1' /etc/yum.repos.d/nvidia-tools.repo
	fi

	dnf ${DNF_OPTS} makecache
}

install_userspace_components() {
	# Extract the driver=XXX part first, then get the value
	if [[ "${nvidia_gpu_stack}" =~ driver=([^,]+) ]]; then
		driver_version="${BASH_REMATCH[1]}"
	fi
	echo "chroot: driver_version: ${driver_version}"

	# In the azl3 repo, individual deb packages like libnvidia-cfg1,
	# libnvidia-gl, libnvidia-extra, libnvidia-decode, libnvidia-fbc1,
	# libnvidia-encode are bundled into nvidia-driver-cuda-libs.
	# GSP firmware blobs (gsp_ga10x.bin, gsp_tu10x.bin) live in
	# nvidia-kmod-common (installed to /usr/lib/firmware/nvidia/).
	eval "${DNF_INSTALL}" \
		"nvidia-driver-cuda-libs-${driver_version}" \
		"nvidia-kmod-common-${driver_version}" \
		"nvidia-imex-${driver_version}" \
		"libnvidia-nscq-${driver_version}"

	dnf ${DNF_OPTS} versionlock add \
		"nvidia-driver-cuda-libs-${driver_version}" \
		"nvidia-kmod-common-${driver_version}" \
		"nvidia-imex-${driver_version}" \
		"libnvidia-nscq-${driver_version}" \
		2>/dev/null || true
}

install_nvidia_fabricmanager() {
	is_feature_enabled "nvswitch" || {
		echo "chroot: Skipping NVIDIA fabricmanager installation"
		return
	}
	echo "chroot: Install NVIDIA fabricmanager"

	eval "${DNF_INSTALL}" \
		"nvidia-fabricmanager" \
		"libnvidia-nscq" \
		"nvlsm"

	dnf ${DNF_OPTS} versionlock add \
		"nvidia-fabricmanager" \
		"libnvidia-nscq" \
		2>/dev/null || true
}

install_nvidia_ctk() {
	echo "chroot: Installing NVIDIA GPU container runtime"
	eval "${DNF_INSTALL}" "nvidia-container-toolkit-base-${ctk_version}"
}

install_nvidia_dcgm() {
	is_feature_enabled "dcgm" || {
		echo "chroot: Skipping NVIDIA DCGM installation"
		return
	}

	echo "chroot: Install NVIDIA DCGM"

	eval "${DNF_INSTALL}" datacenter-gpu-manager \
		datacenter-gpu-manager-exporter
}

install_devkit_packages() {
	is_feature_enabled "devkit" || {
		echo "chroot: Skipping devkit packages installation"
		return
	}

	echo "chroot: Install devkit packages"

	eval "${DNF_INSTALL}" kmod
	dnf ${DNF_OPTS} versionlock add kmod 2>/dev/null || true
}

cleanup_rootfs() {
	echo "chroot: Cleanup NVIDIA GPU rootfs"

	# Ensure critical transitive dependencies are present — RPM names may
	# differ from the Rhel9 originals pulled in by NVIDIA packages.
	eval "${DNF_INSTALL}" \
		libstdc++ zstd-libs gnutls pciutils linuxptp libnftnl

	dnf ${DNF_OPTS} mark install \
		libstdc++ zstd-libs gnutls pciutils linuxptp libnftnl
	dnf ${DNF_OPTS} versionlock add \
		libstdc++ zstd-libs gnutls pciutils linuxptp libnftnl \
		2>/dev/null || true
	dnf ${DNF_OPTS} autoremove -y

	dnf ${DNF_OPTS} clean all
	rm -rf /var/cache/dnf/* /var/log/dnf
	rm -f /usr/bin/nvidia-ngx-updater /usr/bin/nvidia-container-runtime
	rm -f /var/log/nvidia-installer.log

	# Clear and regenerate the ld cache
	rm -f /etc/ld.so.cache
	ldconfig
}

echo "chroot: Setup NVIDIA GPU rootfs stage one (RPM)"

setup_dnf_repositories
install_userspace_components
install_nvidia_fabricmanager
install_nvidia_ctk
install_nvidia_dcgm
install_devkit_packages
cleanup_rootfs
