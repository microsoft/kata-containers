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

	# Write Azure-optimized chrony NTP configuration
	cat > "${ROOTFS_DIR}/etc/chrony.conf" <<-'EOF'
	# Azure-optimized NTP configuration for Microsoft time services
	# Use Microsoft's public NTP service optimized for Azure
	server time.windows.com iburst prefer
	server time.microsoft.com iburst

	# Backup with Azure-region servers
	server time.windows.com iburst

	# Record the rate at which the system clock gains/losses time.
	driftfile /var/lib/chrony/drift

	# Allow the system clock to be stepped in the first three updates
	# if its offset is larger than 1 second.
	makestep 1.0 3

	# Enable kernel synchronization of the real-time clock (RTC).
	rtcsync

	# Specify file containing keys for NTP authentication.
	keyfile /etc/chrony.keys

	# Save NTS keys and cookies.
	ntsdumpdir /var/lib/chrony

	# Get TAI-UTC offset and leap seconds from the system tz database.
	leapsectz right/UTC

	# Specify directory for log files.
	logdir /var/log/chrony

	# Setting larger 'maxdistance' to tolerate Azure network latency
	maxdistance 16.0

	# Disable listening on UDP port (leaving only Unix socket interface).
	cmdport 0

	# REMOVED: refclock PHC /dev/ptp0 (PTP device not available in kata VMs)
	# Using Microsoft NTP services optimized for Azure instead

	# Step the system clock instead of slewing it if the adjustment is larger than
	# one second, at any time (critical for VMs with large initial offset)
	makestep 1 -1
	EOF
}
