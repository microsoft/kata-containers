#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[ -n "$DEBUG" ] && set -x

CONF_PODS=${CONF_PODS:-no}

script_dir="$(dirname $(readlink -f $0))"
repo_dir="${script_dir}/../../../../"

common_file="common.sh"
source "${common_file}"

# This ensures that a pre-built agent binary is being injected into the rootfs
rootfs_make_flags="AGENT_SOURCE_BIN=${AGENT_INSTALL_DIR}/usr/bin/kata-agent"

if [ "${CONF_PODS}" == "yes" ]; then
	# AGENT_POLICY_FILE=allow-all.rego would build a UVM with permissive security policy.
	# The current variable assignment builds a UVM with prohibitive security policy which is the default on
	# Confidential Containers on AKS
	rootfs_make_flags+=" AGENT_POLICY=yes CONF_GUEST=yes AGENT_POLICY_FILE=allow-all.rego"
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

echo "Installing agent service files into rootfs"
sudo cp ${AGENT_INSTALL_DIR}/usr/lib/systemd/system/kata-containers.target ${ROOTFS_PATH}/usr/lib/systemd/system/kata-containers.target
sudo cp ${AGENT_INSTALL_DIR}/usr/lib/systemd/system/kata-agent.service ${ROOTFS_PATH}/usr/lib/systemd/system/kata-agent.service

if [ "${CONF_PODS}" == "yes" ]; then
	echo "Building tarfs kernel driver and installing into rootfs"
	pushd src/tarfs
	make KDIR=${UVM_KERNEL_HEADER_DIR}
	sudo make KDIR=${UVM_KERNEL_HEADER_DIR} KVER=${UVM_KERNEL_VERSION} INSTALL_MOD_PATH=${ROOTFS_PATH} install
	popd

	echo "Installing ezt scripts"
	sudo cp src/ezt/scripts/eztsetup.sh ${ROOTFS_PATH}/usr/lib/

	echo "Building dm-verity protected image based on rootfs"
	pushd tools/osbuilder
	sudo -E PATH=$PATH make DISTRO=cbl-mariner MEASURED_ROOTFS=yes DM_VERITY_FORMAT=kernelinit image
	popd

	echo "Building IGVM and UVM measurement files"
	pushd tools/osbuilder
	sudo chmod o+r root_hash.txt
	sudo make igvm DISTRO=cbl-mariner
	popd
else
	echo "Creating initrd based on rootfs"
	pushd tools/osbuilder
	sudo -E PATH=$PATH make DISTRO=cbl-mariner TARGET_ROOTFS=${ROOTFS_PATH} initrd
	popd
fi

popd
