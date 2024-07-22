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

agent_install_dir="${script_dir}/agent-install"

# This ensures that a pre-built agent binary is being injected into the rootfs
rootfs_make_flags="AGENT_SOURCE_BIN=${agent_install_dir}/usr/bin/kata-agent"

if [ "${CONF_PODS}" == "yes" ]; then
	# AGENT_POLICY_FILE=allow-all.rego would build a UVM with permissive security policy.
	# The current variable assignment builds a UVM with prohibitive security policy which is the default on
	# Confidential Containers on AKS
	rootfs_make_flags+=" AGENT_POLICY=yes CONF_GUEST=yes AGENT_POLICY_FILE=allow-set-policy.rego"
fi

if [ "${CONF_PODS}" == "yes" ]; then
	set_uvm_kernel_vars
	if [ -z "${UVM_KERNEL_HEADER_DIR}}" ]; then
		exit 1
	fi
fi

pushd "${repo_dir}"

echo "Moving agent build artifacts to staging directory"
pushd src/agent/
make install LIBC=gnu DESTDIR=${agent_install_dir}
popd

echo "Building rootfs and including pre-built agent binary from staging directory"
pushd tools/osbuilder
# This command requires sudo because of dnf-installing packages into rootfs. As a suite, following commands require sudo as well as make clean
sudo -E PATH=$PATH make ${rootfs_make_flags} -B DISTRO=cbl-mariner rootfs
ROOTFS_PATH="$(readlink -f ./cbl-mariner_rootfs)"
popd

# Could call make install-services but above make install already calls make install-services which copied the service files to the staging area
# Further, observing some rustup error when directly calling make install-services
echo "Installing agent service files from staging directory into rootfs"
sudo cp ${agent_install_dir}/usr/lib/systemd/system/kata-containers.target ${ROOTFS_PATH}/usr/lib/systemd/system/kata-containers.target
sudo cp ${agent_install_dir}/usr/lib/systemd/system/kata-agent.service ${ROOTFS_PATH}/usr/lib/systemd/system/kata-agent.service

echo "EZT: Test installing ezt setup scripts inside uvm"
sudo cp -a ezt/scripts/* ${ROOTFS_PATH}/usr/lib/

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
	make igvm DISTRO=cbl-mariner
	popd
else
	echo "Creating initrd based on rootfs"
	pushd tools/osbuilder
	sudo -E PATH=$PATH make DISTRO=cbl-mariner TARGET_ROOTFS=${ROOTFS_PATH} initrd
	popd
fi

popd
