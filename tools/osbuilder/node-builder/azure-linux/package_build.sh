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
	DEFMEMSZ=256 DEFSTATICSANDBOXWORKLOADMEM=1792 DEFVIRTIOFSDAEMON=${VIRTIOFSD_BINARY_LOCATION} PREFIX=${DEPLOY_PATH_PREFIX}"

if [ "${CONF_PODS}" == "no" ]; then
	runtime_make_flags+=" DEFSTATICRESOURCEMGMT_CLH=true KERNELPATH_CLH=${KERNEL_BINARY_LOCATION}"
fi

# add BUILD_TYPE=debug to build a debug agent (result in significantly increased agent binary size)
# this will require to add same flag to the `make install` section for the agent in uvm_build.sh
agent_make_flags="LIBC=gnu OPENSSL_NO_VENDOR=Y"

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
if [ "${CONF_PODS}" == "yes" ]; then
	make ${runtime_make_flags}
else
	# cannot add the kernelparams in initial assignment, quotation issue
	make ${runtime_make_flags} KERNELPARAMS=""
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
	sed -i -e "s|image = .*$|initrd = \"${UVM_PATH}/${initrd_file_name}\"|" "${SHIM_CONFIG_FILE_NAME}"
fi
popd

echo "Building agent binary"
pushd src/agent/
make ${agent_make_flags}
popd

popd
