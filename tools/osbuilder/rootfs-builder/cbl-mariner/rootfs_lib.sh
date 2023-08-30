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

	# Reduce the image size, for faster TEE memory measurement.
	local MARINER_REMOVED_PACKAGES=( \
		"bash" \
		"coreutils" \
		"cracklib-dicts" \
		"curl" \
		"curl-libs" \
		"cyrus-sasl-lib" \
		"e2fsprogs" \
		"expat" \
		"findutils" \
		"gmp" \
		"gnupg2" \
		"gpgme" \
		"gzip" \
		"iana-etc" \
		"iproute" \
		"krb5" \
		"libarchive" \
		"libassuan" \
		"libdb" \
		"libksba" \
		"libtool" \
		"libxml2" \
		"libsolv" \
		"libssh2" \
		"libuv" \
		"libpwquality" \
		"lua-libs" \
		"mariner-rpm-macros" \
		"ncurses" \
		"nghttp2" \
		"nettle" \
		"npth" \
		"openldap" \
		"openssh-clients" \
		"openssl" \
		"pinentry" \
		"pcre" \
		"procps-ng" \
		"rpm" \
		"rpm-libs" \
		"shadow-utils" \
		"sqlite-libs" \
		"slang" \
		"sudo" \
		"tar" \
		"tzdata" \
		"zstd-libs" \
	)

	for MARINER_REMOVED_PACKAGE in ${MARINER_REMOVED_PACKAGES[@]}
	do
		info "removing package ${MARINER_REMOVED_PACKAGE}"
		rpm -e "${MARINER_REMOVED_PACKAGE}" --nodeps --root=${ROOTFS_DIR}
	done

	rm -rf ${ROOTFS_DIR}/usr/share/{bash-completion,cracklib,doc,info,locale,man,misc,pixmaps,terminfo,zoneinfo,zsh}
}
