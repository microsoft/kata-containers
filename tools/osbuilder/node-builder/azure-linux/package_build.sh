#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[ -n "$DEBUG" ] && set -x

AGENT_BUILD_TYPE=${AGENT_BUILD_TYPE:-release}
CONF_PODS=${CONF_PODS:-no}

script_dir="$(dirname $(readlink -f $0))"
repo_dir="${script_dir}/../../../../"

common_file="common.sh"
source "${common_file}"

# these options ensure we produce a compact runtime-rs CLH shim and config file
# LIBC=gnu dynamically linked c libraries. small effect on binary size (still 13M without using it), but technically should produce a smaller and better performance binary in azl
# LIBC=musl is better for portability as it statically links c libraries

# USE_BUILDIN_DB=false should avoid building dragonball support. However building without it yields openssl build error for some reason:
# warning: openssl-sys@0.9.109: Could not find directory of OpenSSL installation, and this `-sys` crate cannot proceed without this knowledge. If OpenSSL is installed and this crate had trouble finding it,  you can set the `OPENSSL_DIR` environment variable for the compilation process. See stderr section below for further information.
# error: failed to run custom build command for `openssl-sys v0.9.109`

# something about DB bringing in openssl but also passing OPENSSL_NO_VENDOR=1. If we don't pass that either, we build

# if we build without USE_BUILDIN_DB=false and OPENSSL_NO_VENDOR=1, then we build and increase by 10mb ! we don't need dragonball support!
# ➜  runtime-rs git:(saul/preview-runtime-rs) ✗ ls -lh ../../target/x86_64-unknown-linux-musl/release/containerd-shim-kata-v2
# -rwxrwxr-x 2 saulparedes saulparedes 27M Mar 18 09:44 ../../target/x86_64-unknown-linux-musl/release/containerd-shim-kata-v2
# OPENSSL_NO_VENDOR=1 we want to save size and benefit from azl openssl CVE coverage. Looks like building without this does not affects size much from baseline (still 16M)
# ls -lh ../../target/x86_64-unknown-linux-musl/release/containerd-shim-kata-v2
# -rwxrwxr-x 2 saulparedes saulparedes 16M Mar 18 09:49 ../../target/x86_64-unknown-linux-musl/release/containerd-shim-kata-v2

runtime_make_flags="BUILD_TYPE=release \
	LIBC=gnu \
	HYPERVISOR=cloud-hypervisor \
	USE_BUILDIN_DB=false \
	QEMUCMD= \
	FCCMD= \
	DEFMEMSZ=0 \
	DEFSTATICSANDBOXWORKLOADMEM=512 \
	DEFVCPUS=0 \
	DEFSTATICSANDBOXWORKLOADVCPUS=1 \
	DEFVIRTIOFSDAEMON=${VIRTIOFSD_BINARY_LOCATION} \
	PREFIX=${INSTALL_PATH_PREFIX}"

# - for vanilla Kata we use the kernel binary. For ConfPods we use IGVM, so no need to provide kernel path.
# - for vanilla Kata we explicitly set DEFSTATICRESOURCEMGMT_CLH. For ConfPods,
#   the variable DEFSTATICRESOURCEMGMT_TEE is used which defaults to false
# - for ConfPods we explicitly set the cloud-hypervisor path. The path is independent of the PREFIX variable
#   as we have a single CLH binary for both vanilla Kata and ConfPods
if [ "${CONF_PODS}" == "no" ]; then
	runtime_make_flags+=" DEFSTATICRESOURCEMGMT_CLH=true KERNELPATH_CLH=${KERNEL_BINARY_LOCATION} DEFSANDBOXWORKLOADMEMMIN=128"
else
	runtime_make_flags+=" CLHPATH=${CLOUD_HYPERVISOR_LOCATION} DEFSANDBOXWORKLOADMEMMIN=192"
fi

# On Mariner 3.0 we use cgroupsv2 with a single sandbox cgroup
if [ "${OS_VERSION}" == "3.0" ]; then
	runtime_make_flags+=" DEFSANDBOXCGROUPONLY=true"
fi

agent_make_flags="LIBC=gnu OPENSSL_NO_VENDOR=Y DESTDIR=${AGENT_INSTALL_DIR} BUILD_TYPE=${AGENT_BUILD_TYPE}"

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

echo "Building runtime-rs shim binary and configuration"
pushd src/runtime-rs/
make clean-generated-files
if [ "${CONF_PODS}" == "yes" ] || [ "${OS_VERSION}" == "3.0" ]; then
	OPENSSL_NO_VENDOR=1 make optimize ${runtime_make_flags}
else
	# Mariner 2 pod sandboxing uses cgroupsv1 - note: cannot add the kernelparams in above assignments,
	# leads to quotation issue. Hence, implementing the conditional check right here at the time of the make command
	OPENSSL_NO_VENDOR=1 make optimize ${runtime_make_flags} KERNELPARAMS="systemd.legacy_systemd_cgroup_controller=yes systemd.unified_cgroup_hierarchy=0"
fi
popd

pushd src/runtime-rs/config/
echo "Creating shim debug configuration"
cp "${SHIM_CONFIG_FILE_NAME}" "${SHIM_DBG_CONFIG_FILE_NAME}"
sed -i '/^#enable_debug =/s|^#||g' "${SHIM_DBG_CONFIG_FILE_NAME}"
sed -i '/^#debug_console_enabled =/s|^#||g' "${SHIM_DBG_CONFIG_FILE_NAME}"

if [ "${CONF_PODS}" == "yes" ]; then
	echo "Adding debug igvm to SNP shim debug configuration"
	sed -i "s|${IGVM_FILE_NAME}|${IGVM_DBG_FILE_NAME}|g" "${SHIM_DBG_CONFIG_FILE_NAME}"
fi
popd

echo "Building agent binary and generating service files"
pushd src/agent/
make ${agent_make_flags}
make install ${agent_make_flags}
popd

popd
