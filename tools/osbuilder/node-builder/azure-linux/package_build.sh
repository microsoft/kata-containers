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

# Runtime make flags for builds other than kata-agent
runtime_make_flags="SKIP_GO_VERSION_CHECK=1 QEMUCMD= FCCMD= ACRNCMD= STRATOVIRTCMD= DEFAULT_HYPERVISOR=cloud-hypervisor
	DEFMEMSZ=0 DEFSTATICSANDBOXWORKLOADMEM=512 DEFVCPUS=0 DEFSTATICSANDBOXWORKLOADVCPUS=1 DEFVIRTIOFSDAEMON=${VIRTIOFSD_BINARY_LOCATION} PREFIX=${INSTALL_PATH_PREFIX}"

if [ "${CONF_PODS}" == "no" ]; then
	runtime_make_flags+=" DEFSTATICRESOURCEMGMT_CLH=true KERNELPATH_CLH=${KERNEL_BINARY_LOCATION}"
else
	runtime_make_flags+=" CLHPATH=${CLOUD_HYPERVISOR_LOCATION}"
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
fi
popd

# Switch to Rust nightly for Kata Agent
echo "Building agent binary with Rust nightly and hardening options"
rustup override set nightly

export RUSTFLAGS="-Z cf-protection=full -Zsanitizer=address -Z src-hash-algorithm"
export CARGO_BUILD_STD="--build-std --target=x86_64-unknown-linux-musl"

pushd src/agent/
make RUSTFLAGS="${RUSTFLAGS}" CARGO_BUILD_STD="${CARGO_BUILD_STD}"
make install RUSTFLAGS="${RUSTFLAGS}" CARGO_BUILD_STD="${CARGO_BUILD_STD}"
popd

# Switch back to Rust stable globally
rustup override set stable
popd
