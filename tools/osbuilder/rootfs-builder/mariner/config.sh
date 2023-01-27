# Copyright (c) 2022 Dallas Delaney, 2022 Microsoft Inc.
#
# SPDX-License-Identifier: Apache-2.0

OS_NAME=mariner
OS_VERSION=${OS_VERSION:-2.0}
LIBC="gnu"
PACKAGES="chrony iptables kmod core-packages-base-image kernel ca-certificates openssl curl"
[ "$AGENT_INIT" = no ] && PACKAGES+=" systemd"
[ "$KATA_BUILD_CC" = yes ] && PACKAGES+=" cryptsetup-bin e2fsprogs"
[ "$SECCOMP" = yes ] && PACKAGES+=" libseccomp"
