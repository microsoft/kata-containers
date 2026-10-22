#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034,SC2154

# this is where the kernel-uvm package installation places bzImage, see SPEC file
BZIMAGE_BIN="/usr/share/cloud-hypervisor/bzImage"

# Written by image_builder.sh for MEASURED_ROOTFS=yes
ROOT_HASH_FILE="${SCRIPT_DIR}/../root_hash_${BUILD_VARIANT:-}.txt"
IGVM_MANIFEST_PY="${SCRIPT_DIR}/${DISTRO}/igvm_manifest.py"

IGVM_FILE_NAME="kata-containers-igvm.img"
IGVM_DBG_FILE_NAME="kata-containers-igvm-debug.img"
