# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

temp_upgrade_cacerts()
{
        rpm -Uhv ca-certificates-tools-2.0.0-17.cm2.noarch.rpm --replacepkgs
	rm ca-certificates-tools-2.0.0-17.cm2.noarch.rpm
	rm /etc/pki/ca-trust/extracted/java/cacerts
	update-ca-trust
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
	set -x
	info "install packages for rootfs"
	$DNF install ${EXTRA_PKGS} ${PACKAGES} rpm wget
	wget https://cameronbairdstorage.blob.core.windows.net/public/ca-certificates-tools-2.0.0-17.cm2.noarch.rpm
	cp ca-certificates-tools-2.0.0-17.cm2.noarch.rpm "${ROOTFS_DIR}"
	export -f temp_upgrade_cacerts
	chroot "${ROOTFS_DIR}" /bin/bash -c "temp_upgrade_cacerts"
	echo "chroot done"
	set +x
	rm -rf ${ROOTFS_DIR}/usr/share/{bash-completion,cracklib,doc,info,locale,man,misc,pixmaps,terminfo,zoneinfo,zsh}
}

