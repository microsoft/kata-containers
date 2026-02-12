#!/usr/bin/env bash
#
# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

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

	# Add udev rule for Hyper-V PTP clock source
	mkdir -p "${ROOTFS_DIR}/etc/udev/rules.d"
	cat > "${ROOTFS_DIR}/etc/udev/rules.d/51-ptp-hyperv.rules" <<-EOF
	ACTION=="add", SUBSYSTEM=="ptp", ATTR{clock_name}=="hyperv", TAG+="systemd"
	EOF
}
