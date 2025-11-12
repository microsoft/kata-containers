#!/usr/bin/env bash
#
# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

OS_NAME=cbl-mariner
OS_VERSION=${OS_VERSION:-3.0}
LIBC="gnu"
PACKAGES="kata-packages-uvm"
[ "$AGENT_INIT" = no ] && PACKAGES+=" systemd"
[ "$SECCOMP" = yes ] && PACKAGES+=" libseccomp"

PACKAGES+=" ca-certificates"
PACKAGES+=" cronie-anacron"
PACKAGES+=" logrotate"
PACKAGES+=" core-packages-base-image"

PACKAGES+=" nano"

PACKAGES+=" pciutils"
PACKAGES+=" awk"
PACKAGES+=" tar"
PACKAGES+=" gzip"
PACKAGES+=" zstd"

PACKAGES+=" elfutils-libelf-devel"
PACKAGES+=" openssl-devel"
PACKAGES+=" build-essential"
PACKAGES+=" git"
PACKAGES+=" less"
PACKAGES+=" flex"
PACKAGES+=" dwarves"
PACKAGES+=" ncurses-devel"

PACKAGES+=" cpio"
PACKAGES+=" diffutils"
PACKAGES+=" gettext"
PACKAGES+=" glib-devel"
PACKAGES+=" grub2-rpm-macros"
PACKAGES+=" kbd"
PACKAGES+=" kmod-devel"
PACKAGES+=" libcap-devel"
PACKAGES+=" libdnet-devel"
PACKAGES+=" libmspack-devel"
PACKAGES+=" libtraceevent-devel"
PACKAGES+=" openssl"
PACKAGES+=" openssl-devel"
PACKAGES+=" pam-devel"
PACKAGES+=" procps-ng-devel"
PACKAGES+=" python3-devel"
PACKAGES+=" sed"
PACKAGES+=" slang-devel"
PACKAGES+=" pciutils-devel"
