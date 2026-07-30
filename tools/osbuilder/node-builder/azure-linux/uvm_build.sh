#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[[ -n "${DEBUG:-}" ]] && set -x

AGENT_POLICY_FILE="${AGENT_POLICY_FILE:-allow-set-policy.rego}"
BUILD_TARFS=${BUILD_TARFS:-no}
BUILD_VARIANT=${BUILD_VARIANT:-}
CONF_PODS=${CONF_PODS:-no}
IGVM_KERNEL=${IGVM_KERNEL:-}
IGVM_SVN=${IGVM_SVN:-0}

script_dir="$(dirname "$(readlink -f "$0")")"
repo_dir="${script_dir}/../../../../"

agent_policy_file_abs="${repo_dir}/src/kata-opa/${AGENT_POLICY_FILE}"

common_file="${script_dir}/common.sh"
# shellcheck source=tools/osbuilder/node-builder/azure-linux/common.sh
source "${common_file}"

if [[ "${BUILD_TARFS}" != "yes" && "${BUILD_TARFS}" != "no" ]]; then
	die "BUILD_TARFS must be 'yes' or 'no'"
fi

if [[ -n "${IGVM_KERNEL}" ]]; then
	IGVM_KERNEL="$(readlink -f "${IGVM_KERNEL}")"
	[[ -r "${IGVM_KERNEL}" ]] || die "IGVM kernel '${IGVM_KERNEL}' is not readable"
fi

# This ensures that a pre-built agent binary is being injected into the rootfs
rootfs_make_flags=(
	"AGENT_SOURCE_BIN=${AGENT_INSTALL_DIR}/usr/bin/kata-agent"
	"OS_VERSION=${OS_VERSION}"
)

if [[ "${CONF_PODS}" == "yes" ]]; then
	rootfs_make_flags+=(
		"AGENT_POLICY=yes"
		"CONF_GUEST=yes"
		"AGENT_POLICY_FILE=${agent_policy_file_abs}"
	)
fi

if [[ "${CONF_PODS}" == "yes" && "${BUILD_TARFS}" == "yes" ]]; then
	set_uvm_kernel_vars
	if [[ -z "${UVM_KERNEL_HEADER_DIR}" ]]; then
		exit 1
	fi
fi

pushd "${repo_dir}" || exit

echo "Building rootfs and including pre-built agent binary"
pushd tools/osbuilder || exit
# This command requires sudo because of dnf-installing packages into rootfs. As a suite, following commands require sudo as well as make clean
sudo -E PATH="${PATH}" make "${rootfs_make_flags[@]}" -B DISTRO=cbl-mariner rootfs
ROOTFS_PATH="$(readlink -f ./cbl-mariner_rootfs)"
popd || exit

echo "Installing agent service files into rootfs"
sudo cp "${AGENT_INSTALL_DIR}"/usr/lib/systemd/system/kata-containers.target "${ROOTFS_PATH}"/usr/lib/systemd/system/kata-containers.target
sudo cp "${AGENT_INSTALL_DIR}"/usr/lib/systemd/system/kata-agent.service "${ROOTFS_PATH}"/usr/lib/systemd/system/kata-agent.service

if [[ "${CONF_PODS}" == "yes" ]]; then
	if [[ "${BUILD_TARFS}" == "yes" ]]; then
		echo "Building tarfs kernel driver and installing into rootfs"
		pushd src/tarfs || exit
		make KDIR="${UVM_KERNEL_HEADER_DIR}"
		sudo make KDIR="${UVM_KERNEL_HEADER_DIR}" KVER="${UVM_KERNEL_VERSION}" INSTALL_MOD_PATH="${ROOTFS_PATH}" install
		popd || exit
	else
		echo "Skipping tarfs kernel driver"
	fi

	echo "Building dm-verity protected image based on rootfs"
	pushd tools/osbuilder || exit
	sudo -E PATH="${PATH}" make DISTRO=cbl-mariner MEASURED_ROOTFS=yes DM_VERITY_FORMAT=kernelinit IMAGE_SIZE_ALIGNMENT_MB=2 image
	popd || exit

	echo "Building IGVM and UVM measurement files"
	pushd tools/osbuilder || exit
	sudo chmod o+r "root_hash_${BUILD_VARIANT}.txt"
	sudo make igvm BUILD_VARIANT="${BUILD_VARIANT}" DISTRO=cbl-mariner IGVM_KERNEL="${IGVM_KERNEL}" IGVM_SVN="${IGVM_SVN}"
	popd || exit
else
	echo "Building image based on rootfs"
	pushd tools/osbuilder || exit
	sudo -E PATH="${PATH}" make DISTRO=cbl-mariner IMAGE_SIZE_ALIGNMENT_MB=2 image
	popd || exit
fi

popd || exit
