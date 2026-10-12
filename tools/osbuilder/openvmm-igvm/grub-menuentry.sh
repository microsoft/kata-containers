#!/bin/bash
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Retain package-owned root/kernel discovery and add Azure's nested-root flag.
/etc/grub.d/50_mariner_mshv_menuentry |
    sed -e 's/menuentry "Dom0"/menuentry "OpenVMM SNP"/' \
        -e '/chainloader/s/MSHV_FORCE_NESTED=[^[:space:]]*/MSHV_FORCE_NESTED=TRUE/g' \
        -e '/chainloader/ { /MSHV_FORCE_NESTED=TRUE/! s/MSHV_ENABLE=TRUE/MSHV_ENABLE=TRUE MSHV_FORCE_NESTED=TRUE/; }'
