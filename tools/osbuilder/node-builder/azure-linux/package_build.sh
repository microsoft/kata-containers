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

# these options ensure we produce the proper CLH config file
runtime_make_flags="SKIP_GO_VERSION_CHECK=1 QEMUCMD= FCCMD= ACRNCMD= STRATOVIRTCMD= DEFAULT_HYPERVISOR=cloud-hypervisor
	DEFMEMSZ=256 DEFSTATICSANDBOXWORKLOADMEM=1792 DEFVIRTIOFSDAEMON=${VIRTIOFSD_BINARY_LOCATION} PREFIX=${INSTALL_PATH_PREFIX}"

# - for vanilla Kata we use the kernel binary. For ConfPods we use IGVM, so no need to provide kernel path.
# - for vanilla Kata we explicitly set DEFSTATICRESOURCEMGMT_CLH. For ConfPods,
#   the variable DEFSTATICRESOURCEMGMT_TEE is used which defaults to false
# - for ConfPods we explicitly set the cloud-hypervisor path. The path is independent of the PREFIX variable
#   as we have a single CLH binary for both vanilla Kata and ConfPods
if [ "${CONF_PODS}" == "no" ]; then
	runtime_make_flags+=" DEFSTATICRESOURCEMGMT_CLH=true KERNELPATH_CLH=${KERNEL_BINARY_LOCATION}"
else
	runtime_make_flags+=" CLHPATH=${CLOUD_HYPERVISOR_LOCATION}"
fi

# On Mariner 3.0 we use cgroupsv2 with a single sandbox cgroup
if [ "${OS_VERSION}" == "3.0" ]; then
	runtime_make_flags+=" DEFSANDBOXCGROUPONLY=true"
	echo "test1"
fi
echo "test"
# add BUILD_TYPE=debug to build a debug agent (result in significantly increased agent binary size)
# this will require to add same flag to the `make install` section for the agent in uvm_build.sh
agent_make_flags="LIBC=gnu OPENSSL_NO_VENDOR=Y DESTDIR=${AGENT_INSTALL_DIR}"

if [ "${CONF_PODS}" == "yes" ]; then
	agent_make_flags+=" AGENT_POLICY=yes"
fi

pushd "${repo_dir}"

if [ "${CONF_PODS}" == "yes" ]; then

	echo "Building utarfs binary"
	pushd src/utarfs/
	make all
	popd

	echo "Building kata-overlay binary"
	pushd src/overlay/
	make all
	popd

	echo "Building tardev-snapshotter service binary"
	pushd src/tardev-snapshotter/
	make all
	popd
fi

echo "Building shim binary and configuration"
pushd src/runtime/
if [ "${CONF_PODS}" == "yes" ] || [ "${OS_VERSION}" == "3.0" ]; then
	make ${runtime_make_flags}
else
	# Mariner 2 pod sandboxing uses cgroupsv1 - note: cannot add the kernelparams in above assignments,
	# leads to quotation issue. Hence, implementing the conditional check right here at the time of the make command
	make ${runtime_make_flags} KERNELPARAMS="systemd.legacy_systemd_cgroup_controller=yes systemd.unified_cgroup_hierarchy=0"
fi
popd

pushd src/runtime/config/
if [ "${CONF_PODS}" == "yes" ]; then

	echo "Creating SNP shim debug configuration"
	cp "${SHIM_CONFIG_FILE_NAME}" "${SHIM_DBG_CONFIG_FILE_NAME}"
	sed -i "s|${IGVM_FILE_NAME}|${IGVM_DBG_FILE_NAME}|g" "${SHIM_DBG_CONFIG_FILE_NAME}"
	sed -i '/^#enable_debug =/s|^#||g' "${SHIM_DBG_CONFIG_FILE_NAME}"
	sed -i '/^#debug_console_enabled =/s|^#||g' "${SHIM_DBG_CONFIG_FILE_NAME}"
else
	# We currently use the default config snippet from upstream that defaults to IMAGEPATH/image for the config.
	# If we shift to using an image for vanilla Kata, we can use IMAGEPATH to set the proper path (or better make sure the image file gets placed so that default values can be used).
	sed -i -e "s|image = .*$|initrd = \"${UVM_PATH}/${INITRD_FILE_NAME}\"|" "${SHIM_CONFIG_FILE_NAME}"
fi
popd

echo "Building agent binary and generating service files"
pushd src/agent/
make ${agent_make_flags}
make install ${agent_make_flags}
popd

popd
