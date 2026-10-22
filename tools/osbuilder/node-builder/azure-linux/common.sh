#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034

script_dir="$(dirname "$(readlink -f "$0")")"
lib_file="${script_dir}/../../scripts/lib.sh"
# shellcheck source=tools/osbuilder/scripts/lib.sh
source "${lib_file}"

CONF_PODS=${CONF_PODS:-no}
USE_RUNTIME_RS=${USE_RUNTIME_RS:-no}

OS_VERSION=$(sort -r /etc/*-release | gawk 'match($0, /^(VERSION_ID=(.*))$/, a) { print toupper(a[2] a[3]); exit }' | tr -d '"')

[[ "${OS_VERSION}" == "2.0" || "${OS_VERSION}" == "3.0" ]] || die "OS_VERSION: value '${OS_VERSION}' must equal 3.0 (default) or 2.0"

SHIM_CONFIG_FILE_NAME_RUNTIME_GO="configuration-clh.toml"
SHIM_DBG_CONFIG_FILE_NAME_RUNTIME_GO="configuration-clh-debug.toml"
# Preview configs enable VM templating (factory) on top of the runtime-go configs.
SHIM_PREVIEW_CONFIG_FILE_NAME_RUNTIME_GO="configuration-clh-preview.toml"
SHIM_PREVIEW_DBG_CONFIG_FILE_NAME_RUNTIME_GO="configuration-clh-preview-debug.toml"
CONFIG_DIR_RUNTIME_GO="src/runtime/config"
SHIM_CONFIG_FILE_NAME_RUNTIME_RS="configuration-clh-azure-runtime-rs.toml"
SHIM_DBG_CONFIG_FILE_NAME_RUNTIME_RS="configuration-clh-azure-runtime-rs-debug.toml"
SHIM_CONFIG_FILE_NAME_RUNTIME_RS_V2="configuration-clh-azure-runtime-rs-v2.toml"
SHIM_DBG_CONFIG_FILE_NAME_RUNTIME_RS_V2="configuration-clh-azure-runtime-rs-v2-debug.toml"
SHIM_CONFIG_FILE_NAME_OPENVMM_SNP="configuration-openvmm-azure-snp-runtime-rs.toml"
SHIM_DBG_CONFIG_FILE_NAME_OPENVMM_SNP="configuration-openvmm-azure-snp-runtime-rs-debug.toml"
CONFIG_DIR_RUNTIME_RS="src/runtime-rs/config"

if [[ "${CONF_PODS}" == "yes" ]]; then
	INSTALL_PATH_PREFIX="/opt/confidential-containers"
	UVM_TOOLS_PATH_OSB="${INSTALL_PATH_PREFIX}/uvm/tools/osbuilder"
	UVM_TOOLS_PATH_SRC="${INSTALL_PATH_PREFIX}/uvm/src"
	UVM_PATH_DEFAULT="${INSTALL_PATH_PREFIX}/share/kata-containers"
	IMG_FILE_NAME="kata-containers.img"
	IGVM_FILE_NAME="kata-openvmm-snp.bin"
	IGVM_DBG_FILE_NAME="kata-openvmm-snp-debug.bin"
	# igvmfilegen writes the SNP launch measurement of <name>.bin to <name>-snp.{json,cbor,idblock}
	UVM_MEASUREMENT_FILE_NAMES=(
		"kata-openvmm-snp-snp.json"
		"kata-openvmm-snp-snp.cbor"
		"kata-openvmm-snp-snp.idblock"
		"kata-openvmm-snp-debug-snp.json"
		"kata-openvmm-snp-debug-snp.cbor"
		"kata-openvmm-snp-debug-snp.idblock"
	)
	UVM_CHECKSUMS_FILE_NAME="SHA256SUMS"
	SHIM_CONFIG_PATH="${INSTALL_PATH_PREFIX}/share/defaults/kata-containers"
	SHIM_CONFIG_FILE_NAME="${SHIM_CONFIG_FILE_NAME_OPENVMM_SNP}"
	SHIM_CONFIG_INST_FILE_NAME="${SHIM_CONFIG_FILE_NAME}"
	SHIM_DBG_CONFIG_FILE_NAME="${SHIM_DBG_CONFIG_FILE_NAME_OPENVMM_SNP}"
	SHIM_DBG_CONFIG_INST_FILE_NAME="${SHIM_DBG_CONFIG_FILE_NAME}"
	DEBUGGING_BINARIES_PATH="${INSTALL_PATH_PREFIX}/bin"
	SHIM_BINARIES_PATH="/usr/local/bin"
	SHIM_BINARY_NAME="containerd-shim-kata-cc-v2"
else

	# Toggle the default shim implementation installed
	if [[ "${USE_RUNTIME_RS}" == "yes" ]]; then
		SHIM_CONFIG_FILE_NAME="${SHIM_CONFIG_FILE_NAME_RUNTIME_RS}"
		SHIM_DBG_CONFIG_FILE_NAME="${SHIM_DBG_CONFIG_FILE_NAME_RUNTIME_RS}"
	else # runtime-go
		SHIM_CONFIG_FILE_NAME="${SHIM_CONFIG_FILE_NAME_RUNTIME_GO}"
		SHIM_DBG_CONFIG_FILE_NAME="${SHIM_DBG_CONFIG_FILE_NAME_RUNTIME_GO}"
	fi

	INSTALL_PATH_PREFIX="/usr"
	UVM_TOOLS_PATH_OSB="/opt/kata-containers/uvm/tools/osbuilder"
	UVM_TOOLS_PATH_SRC="/opt/kata-containers/uvm/src"
	UVM_PATH_DEFAULT="${INSTALL_PATH_PREFIX}/share/kata-containers"
	IMG_FILE_NAME="kata-containers.img"
	SHIM_CONFIG_PATH="${INSTALL_PATH_PREFIX}/share/defaults/kata-containers"
	SHIM_CONFIG_INST_FILE_NAME="configuration.toml"
	SHIM_DBG_CONFIG_INST_FILE_NAME="${SHIM_DBG_CONFIG_FILE_NAME}"
	DEBUGGING_BINARIES_PATH="${INSTALL_PATH_PREFIX}/local/bin"
	SHIM_BINARIES_PATH="${INSTALL_PATH_PREFIX}/local/bin"
	SHIM_BINARY_NAME="containerd-shim-kata-v2"
fi

# this is where openvmm gets installed (see package SPEC)
OPENVMM_LOCATION="/usr/bin/openvmm"
# this is where kernel-uvm gets installed (see package SPEC)
KERNEL_BINARY_LOCATION="/usr/share/cloud-hypervisor/vmlinux.bin"
# Mariner 3: different binary name
if [[ "${OS_VERSION}" == "2.0" ]]; then
	VIRTIOFSD_BINARY_LOCATION="/usr/libexec/virtiofsd-rs"
else
	VIRTIOFSD_BINARY_LOCATION="/usr/libexec/virtiofsd"
fi

AGENT_INSTALL_DIR="${script_dir}/agent-install"
