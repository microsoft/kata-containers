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

PACKAGES+=" pciutils"
PACKAGES+=" awk"
PACKAGES+=" tar"
PACKAGES+=" gzip"
PACKAGES+=" zstd"

PACKAGES+=" build-essential"
PACKAGES+=" elfutils-libelf-devel"
PACKAGES+=" kernel-devel-6.6.104.2"
