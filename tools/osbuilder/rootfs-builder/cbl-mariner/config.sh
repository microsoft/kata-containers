#!/usr/bin/env bash
#
# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

OS_NAME=cbl-mariner
OS_VERSION=${OS_VERSION:-3.0}
LIBC="gnu"
PACKAGES="bash util-linux shadow-utils ca-certificates chrony cryptsetup dbus elfutils-libelf filesystem iptables irqbalance systemd tzdata zlib sudo tdnf binutils pciutils procps-ng net-tools iproute strace lsof socat nc"
[ "$AGENT_INIT" = no ] && PACKAGES+=" systemd"
[ "$SECCOMP" = yes ] && PACKAGES+=" libseccomp"
