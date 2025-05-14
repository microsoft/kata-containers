#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[ -n "$DEBUG" ] && set -x

AGENT_POLICY_FILE="${AGENT_POLICY_FILE:-allow-set-policy.rego}"
CONF_PODS=${CONF_PODS:-no}
IGVM_SVN=${IGVM_SVN:-0}

script_dir="$(dirname $(readlink -f $0))"
repo_dir="${script_dir}/../../../../"

agent_policy_file_abs="${repo_dir}/src/kata-opa/${AGENT_POLICY_FILE}"

common_file="common.sh"
source "${common_file}"

# This ensures that a pre-built agent binary is being injected into the rootfs
rootfs_make_flags="AGENT_SOURCE_BIN=${AGENT_INSTALL_DIR}/usr/bin/kata-agent OS_VERSION=${OS_VERSION}"

if [ "${CONF_PODS}" == "yes" ]; then
	rootfs_make_flags+=" AGENT_POLICY=yes CONF_GUEST=yes AGENT_POLICY_FILE=${agent_policy_file_abs}"
fi

if [ "${CONF_PODS}" == "yes" ]; then
	set_uvm_kernel_vars
	if [ -z "${UVM_KERNEL_HEADER_DIR}}" ]; then
		exit 1
	fi
fi

pushd "${repo_dir}"

echo "Building rootfs and including pre-built agent binary"
pushd tools/osbuilder
# This command requires sudo because of dnf-installing packages into rootfs. As a suite, following commands require sudo as well as make clean
sudo -E PATH=$PATH make ${rootfs_make_flags} -B DISTRO=cbl-mariner rootfs
ROOTFS_PATH="$(readlink -f ./cbl-mariner_rootfs)"
popd

# ADD THIS SECTION HERE - Copy kernel modules into rootfs
echo "Installing kernel modules into rootfs"
# Get the kernel version that the UVM will run
UVM_KERNEL_VERSION=$(uname -r)
# Create modules directory in rootfs
sudo mkdir -p ${ROOTFS_PATH}/lib/modules/
# Copy the kernel modules from host to rootfs
if [ -d "/lib/modules/6.1.58.mshv4" ]; then
    echo "Copying kernel modules for version 6.1.58.mshv4"
    sudo cp -r /lib/modules/6.1.58.mshv4 ${ROOTFS_PATH}/lib/modules/6.1.58.mshv4
    # Run depmod to generate dependency files in the rootfs
    sudo chroot ${ROOTFS_PATH} /sbin/depmod -a 6.1.58.mshv4
else
    echo "Warning: Kernel modules for 6.1.58.mshv4 not found on host"
fi

echo "Installing agent service files into rootfs"
sudo cp ${AGENT_INSTALL_DIR}/usr/lib/systemd/system/kata-containers.target ${ROOTFS_PATH}/usr/lib/systemd/system/kata-containers.target
sudo cp ${AGENT_INSTALL_DIR}/usr/lib/systemd/system/kata-agent.service ${ROOTFS_PATH}/usr/lib/systemd/system/kata-agent.service

if [ "${CONF_PODS}" == "yes" ]; then
	echo "Building tarfs kernel driver and installing into rootfs"
	pushd src/tarfs
	make KDIR=${UVM_KERNEL_HEADER_DIR}
	sudo make KDIR=${UVM_KERNEL_HEADER_DIR} KVER=${UVM_KERNEL_VERSION} INSTALL_MOD_PATH=${ROOTFS_PATH} install
	popd

	echo "Building dm-verity protected image based on rootfs"
	pushd tools/osbuilder
	sudo -E PATH=$PATH make DISTRO=cbl-mariner MEASURED_ROOTFS=yes DM_VERITY_FORMAT=kernelinit image
	popd

	echo "Building IGVM and UVM measurement files"
	pushd tools/osbuilder
	sudo chmod o+r root_hash.txt
	sudo make igvm DISTRO=cbl-mariner IGVM_SVN=${IGVM_SVN}
	popd
else
	echo "Building image based on rootfs"
	pushd tools/osbuilder
	sudo -E PATH=$PATH make DISTRO=cbl-mariner image
	popd
fi

popd