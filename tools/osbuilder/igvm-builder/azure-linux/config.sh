#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034,SC2154

# this is where the kernel-uvm package installation places bzImage, see SPEC file
BZIMAGE_BIN="/usr/share/cloud-hypervisor/bzImage"

# Written by image_builder.sh for MEASURED_ROOTFS=yes and an empty BUILD_VARIANT
ROOT_HASH_FILE="${SCRIPT_DIR}/../root_hash_.txt"
IGVM_MANIFEST_PY="${SCRIPT_DIR}/${DISTRO}/igvm_manifest.py"

# igvmfilegen and snp_bootshim must be built together from the same source
IGVM_TOOLS_REPO="${IGVM_TOOLS_REPO:-https://github.com/microsoft/kata-cc-igvm-tools.git}"
IGVM_TOOLS_REF="${IGVM_TOOLS_REF:-1bb7c3031d686c8400b29ca59083f85a4a44786e}"
IGVM_TOOLS_SRC_DIR="${SCRIPT_DIR}/igvm-tools-src"
IGVM_TOOLS_DIR="${SCRIPT_DIR}/igvm-tools"

IGVM_FILE_NAME="kata-openvmm-snp.bin"
IGVM_DBG_FILE_NAME="kata-openvmm-snp-debug.bin"
