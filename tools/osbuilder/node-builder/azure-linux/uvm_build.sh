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
UVM_BUILD_MODE=${UVM_BUILD_MODE:-release}

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

if [ "${UVM_BUILD_MODE}" == "release" ]; then
	LOCAL_IMAGE_NAME="${IMG_FILE_NAME}"
else 
	LOCAL_IMAGE_NAME="${IMG_DBG_FILE_NAME}"
fi

# We must clean the rootfs build to allow the next build (i.e. a debug image) to be built
# from a clean state with a separate set of packages. 
echo "Cleaning rootfs build"
pushd tools/osbuilder
sudo -E PATH=$PATH make DISTRO=cbl-mariner clean-rootfs
popd

echo "Building ${UVM_BUILD_MODE} rootfs and including pre-built agent binary"
pushd tools/osbuilder
# This command requires sudo because of dnf-installing packages into rootfs. As a suite, following commands require sudo as well as make clean
sudo -E PATH=$PATH UVM_BUILD_MODE=${UVM_BUILD_MODE} make ${rootfs_make_flags} -B DISTRO=cbl-mariner rootfs
ROOTFS_PATH="$(readlink -f ./cbl-mariner_rootfs)"
popd

echo "Installing agent service files into rootfs"
sudo cp ${AGENT_INSTALL_DIR}/usr/lib/systemd/system/kata-containers.target ${ROOTFS_PATH}/usr/lib/systemd/system/kata-containers.target
sudo cp ${AGENT_INSTALL_DIR}/usr/lib/systemd/system/kata-agent.service ${ROOTFS_PATH}/usr/lib/systemd/system/kata-agent.service

if [ "${CONF_PODS}" == "yes" ]; then

	echo "Building utarfs binary"
	pushd src/utarfs/
	make all

	echo "Installing utarfs into rootfs"
	sudo cp target/release/utarfs ${ROOTFS_PATH}/bin/utarfs
	popd

	echo "Building tarfs kernel driver and installing into rootfs"
	pushd src/tarfs
	make KDIR=${UVM_KERNEL_HEADER_DIR}
	sudo make KDIR=${UVM_KERNEL_HEADER_DIR} KVER=${UVM_KERNEL_VERSION} INSTALL_MOD_PATH=${ROOTFS_PATH} install
	popd
	echo "Building dm-verity protected image based on rootfs"
	pushd tools/osbuilder
	sudo -E PATH=${PATH} IMAGE_NAME=${LOCAL_IMAGE_NAME} make DISTRO=cbl-mariner MEASURED_ROOTFS=yes DM_VERITY_FORMAT=kernelinit image
	popd

	echo "Building IGVM and UVM measurement files"
	pushd tools/osbuilder
	sudo chmod o+r root_hash.txt
	sudo make igvm DISTRO=cbl-mariner IMAGE_NAME=${LOCAL_IMAGE_NAME} IGVM_SVN=${IGVM_SVN} UVM_BUILD_MODE=${UVM_BUILD_MODE}
	popd
else
	echo "Building image based on rootfs"
	pushd tools/osbuilder
	sudo -E PATH=$PATH IMAGE_NAME=${LOCAL_IMAGE_NAME} make DISTRO=cbl-mariner image
	popd
fi

popd
