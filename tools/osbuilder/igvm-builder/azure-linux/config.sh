#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034,SC2154

# this is where the kernel-uvm-cc package installation places bzImage, see SPEC file
BZIMAGE_BIN="${KERNEL_UVM_CC_LOCATION:-/usr/share/kernel-uvm-cc/bzImage}"

# Written by image_builder.sh for MEASURED_ROOTFS=yes and an empty BUILD_VARIANT
ROOT_HASH_FILE="${SCRIPT_DIR}/../root_hash_.txt"
IGVM_MANIFEST_PY="${SCRIPT_DIR}/${DISTRO}/igvm_manifest.py"

# OpenVMM igvmfilegen and snp_bootshim must be built together from the same patched source
OPENVMM_REPO="${OPENVMM_REPO:-https://github.com/microsoft/openvmm.git}"
OPENVMM_PATCH="${SCRIPT_DIR}/${DISTRO}/openvmm-igvmfilegen-launch-sizing.patch"
OPENVMM_SRC_DIR="${SCRIPT_DIR}/openvmm-src"
OPENVMM_TOOLS_DIR="${SCRIPT_DIR}/openvmm-tools"
VERSIONS_YAML="${SCRIPT_DIR}/../../../versions.yaml"

IGVM_FILE_NAME="kata-openvmm-snp.bin"
IGVM_DBG_FILE_NAME="kata-openvmm-snp-debug.bin"
