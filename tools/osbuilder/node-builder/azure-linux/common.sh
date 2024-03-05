#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

script_dir="$(dirname $(readlink -f $0))"
lib_file="${script_dir}/../../scripts/lib.sh"
source "${lib_file}"

if [ "${CONF_PODS}" == "yes" ]; then
	DEPLOY_PATH_PREFIX="/opt/confidential-containers"
	UVM_PATH="${DEPLOY_PATH_PREFIX}/share/kata-containers"
	IMG_FILE_NAME="kata-containers.img"
	IGVM_FILE_NAME="kata-containers-igvm.img"
	IGVM_DBG_FILE_NAME="kata-containers-igvm-debug.img"
	UVM_MEASUREMENT_FILE_NAME="igvm-measurement.cose"
	UVM_DBG_MEASUREMENT_FILE_NAME="igvm-debug-measurement.cose"
	SHIM_CONFIG_PATH="${DEPLOY_PATH_PREFIX}/share/defaults/kata-containers"
	SHIM_CONFIG_FILE_NAME="configuration-clh-snp.toml"
	SHIM_DBG_CONFIG_FILE_NAME="configuration-clh-snp-debug.toml"
	DEBUGGING_BINARIES_PATH="${DEPLOY_PATH_PREFIX}/bin"
	SHIM_BINARIES_PATH="/usr/local/bin"
	SHIM_BINARY_NAME="containerd-shim-kata-cc-v2"
else
	DEPLOY_PATH_PREFIX="/usr"
	UVM_PATH="/var/cache/kata-containers/osbuilder-images/kernel-uvm"
	initrd_file_name="kata-containers-initrd.img"
	SHIM_CONFIG_PATH="${DEPLOY_PATH_PREFIX}/share/defaults/kata-containers"
	SHIM_CONFIG_FILE_NAME="configuration-clh.toml"
	DEBUGGING_BINARIES_PATH="${DEPLOY_PATH_PREFIX}/local/bin"
	SHIM_BINARIES_PATH="${DEPLOY_PATH_PREFIX}/local/bin"
	SHIM_BINARY_NAME="containerd-shim-kata-v2"
fi

KERNEL_BINARY_LOCATION="/usr/share/cloud-hypervisor/vmlinux.bin"
VIRTIOFSD_BINARY_LOCATION="/usr/libexec/virtiofsd-rs"

set_uvm_kernel_vars() {
	UVM_KERNEL_VERSION=$(rpm -q --queryformat '%{VERSION}' kernel-uvm-devel)
	UVM_KERNEL_RELEASE=$(rpm -q --queryformat '%{RELEASE}' kernel-uvm-devel)
	UVM_KERNEL_HEADER_DIR="/usr/src/linux-headers-${UVM_KERNEL_VERSION}-${UVM_KERNEL_RELEASE}"
}
