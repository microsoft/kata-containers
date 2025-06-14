#!/usr/bin/env bash
#
# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

OS_NAME=cbl-mariner
OS_VERSION=${OS_VERSION:-3.0}
LIBC="gnu"
PACKAGES="kata-packages-uvm"
[ "$CONF_GUEST" = yes ] && PACKAGES+=" kata-packages-uvm-coco"
[ "$AGENT_INIT" = no ] && PACKAGES+=" systemd"
[ "$SECCOMP" = yes ] && PACKAGES+=" libseccomp"
