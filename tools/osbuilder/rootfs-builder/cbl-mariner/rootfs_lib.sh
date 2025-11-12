#!/usr/bin/env bash
#
# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -x
set -e

setup_nvidia-nvrc() {
	git clone https://github.com/NVIDIA/nvrc.git
	pushd nvrc

	cat <<EOF | tee src/supported.rs
use anyhow::Result;
use std::path::Path;

use super::NVRC;

impl NVRC {
    pub fn check_gpu_supported(&mut self, _supported: Option<&Path>) -> Result<()> {
		self.gpu_supported = true;
		Ok(())
	}
}
EOF

	cargo build --release
	popd
}

build_rootfs()
{
	# Mandatory
	local ROOTFS_DIR="$1"

	[ -z "$ROOTFS_DIR" ] && die "need rootfs"

	# In case of support EXTRA packages, use it to allow
	# users add more packages to the base rootfs
	local EXTRA_PKGS=${EXTRA_PKGS:-""}

	check_root
	mkdir -p "${ROOTFS_DIR}"
	PKG_MANAGER="tdnf"

	DNF="${PKG_MANAGER} -y --installroot=${ROOTFS_DIR} --noplugins --releasever=${OS_VERSION}"

	info "install packages for rootfs"
	$DNF install ${EXTRA_PKGS} ${PACKAGES}

	rm -rf ${ROOTFS_DIR}/usr/share/{bash-completion,cracklib,doc,info,locale,man,misc,pixmaps,terminfo,zoneinfo,zsh}


	script_dir="$(dirname "$(readlink -f "$0")")"
	readonly SCRIPT_DIR="${script_dir}/cbl-mariner"

	pushd "${ROOTFS_DIR}"

	setup_nvidia-nvrc

	mkdir CBL-Mariner-Linux-Kernel
	cp -R "${SCRIPT_DIR}"/CBL-Mariner-Linux-Kernel/* CBL-Mariner-Linux-Kernel/

	run_file_name="NVIDIA-Linux-x86_64-580.95.05.run"
	wget "https://us.download.nvidia.com/tesla/580.95.05/${run_file_name}"
	mv "${run_file_name}" driver.run
	popd

	readonly CHROOT_SCRIPT="azl_chroot.sh"
	cp "${SCRIPT_DIR}/${CHROOT_SCRIPT}" "${ROOTFS_DIR}"
	chmod +x "${ROOTFS_DIR}/${CHROOT_SCRIPT}"
	chroot "${ROOTFS_DIR}" /bin/bash -c "/${CHROOT_SCRIPT}"
}
