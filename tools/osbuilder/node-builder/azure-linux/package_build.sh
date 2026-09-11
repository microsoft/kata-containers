#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[[ -n "${DEBUG:-}" ]] && set -x

AGENT_BUILD_TYPE=${AGENT_BUILD_TYPE:-release}
CONF_PODS=${CONF_PODS:-no}
RELEASE_VERSION=${RELEASE_VERSION:-}
SHIM_REDEPLOY_CONFIG=${SHIM_REDEPLOY_CONFIG:-yes}

if [[ -z "${RELEASE_VERSION}" ]]; then
	echo "RELEASE_VERSION must identify the distro package release (for example, 3.32.0.kata0-6)" >&2
	exit 1
fi

script_dir="$(dirname "$(readlink -f "$0")")"
repo_dir="${script_dir}/../../../../"

common_file="${script_dir}/common.sh"
# shellcheck source=tools/osbuilder/node-builder/azure-linux/common.sh
source "${common_file}"

runtime_go_make_flags=(
	"SKIP_GO_VERSION_CHECK=1"
	# Upstream defaults src/runtime to STATIC=yes on x86_64, which exports
	# CGO_ENABLED=0. The Azure Linux Go toolchain (microsoft/go) defaults to
	# GOEXPERIMENT=systemcrypto for OpenSSL-backed, FIPS-capable crypto, and that
	# requires CGO_ENABLED=1
	"STATIC=no"
	"QEMUCMD="
	"FCCMD="
	"ACRNCMD="
	"STRATOVIRTCMD="
	"DEFAULT_HYPERVISOR=cloud-hypervisor"
	"DEFMEMSZ=0"
	"DEFSTATICSANDBOXWORKLOADMEM=512"
	"DEFVCPUS=0"
	"DEFSTATICSANDBOXWORKLOADVCPUS=1"
	"DEFVIRTIOFSDAEMON=${VIRTIOFSD_BINARY_LOCATION}"
	"PREFIX=${INSTALL_PATH_PREFIX}"
)

runtime_rs_make_flags=(
	"BUILD_TYPE=release"
	"LIBC=gnu"
	"HYPERVISOR=cloud-hypervisor"
	"OPENSSL_NO_VENDOR=Y"
	"RELEASE_VERSION=${RELEASE_VERSION}"
	"USE_BUILTIN_DB=false"
	"QEMUCMD="
	"FCCMD="
	"DEFVIRTIOFSDAEMON=${VIRTIOFSD_BINARY_LOCATION}"
	"PREFIX=${INSTALL_PATH_PREFIX}"
	"IMAGEPATH_CLH_AZURE=${UVM_PATH_DEFAULT}/${IMG_FILE_NAME}"
	"DEFMEMSZ=0"
	"DEFOVERHEADMEMSZ_CLH=0"
	"DEFSTATICSANDBOXWORKLOADMEM=512"
	"DEFVCPUS=0"
	"DEFOVERHEADVCPUS_CLH=0"
	"DEFSTATICSANDBOXWORKLOADVCPUS=1"
)

# - for vanilla Kata we use the kernel binary. For ConfPods we use IGVM, so no need to provide kernel path.
# - for vanilla Kata we explicitly set DEFSTATICRESOURCEMGMT_CLH. For ConfPods,
#   the variable DEFSTATICRESOURCEMGMT_TEE is used which defaults to false
# - for ConfPods we explicitly set the cloud-hypervisor path. The path is independent of the PREFIX variable
#   as we have a single CLH binary for both vanilla Kata and ConfPods
if [[ "${CONF_PODS}" == "no" ]]; then
	runtime_go_make_flags+=("DEFSTATICRESOURCEMGMT_CLH=true" "KERNELPATH_CLH=${KERNEL_BINARY_LOCATION}")
	runtime_rs_make_flags+=("DEFSTATICRESOURCEMGMT_CLH=true" "KERNELPATH_CLH=${KERNEL_BINARY_LOCATION}")
else
	runtime_go_make_flags+=("CLHPATH=${CLOUD_HYPERVISOR_LOCATION}")
	runtime_rs_make_flags+=("CLHPATH=${CLOUD_HYPERVISOR_LOCATION}")
fi

# On Mariner 3.0 we use cgroupsv2 with a single sandbox cgroup
if [[ "${OS_VERSION}" == "3.0" ]]; then
	runtime_go_make_flags+=("DEFSANDBOXCGROUPONLY=true")
	runtime_rs_make_flags+=("DEFSANDBOXCGROUPONLY_CLH=true")
fi

agent_make_flags=(
	"LIBC=gnu"
	"OPENSSL_NO_VENDOR=Y"
	"DESTDIR=${AGENT_INSTALL_DIR}"
	"BUILD_TYPE=${AGENT_BUILD_TYPE}"
)

if [[ "${CONF_PODS}" == "yes" ]]; then
	agent_make_flags+=("AGENT_POLICY=yes")
fi

pushd "${repo_dir}" || exit

if [[ "${CONF_PODS}" == "yes" ]]; then

	echo "Building utarfs binary"
	pushd src/utarfs/ || exit
	make all
	popd || exit

	echo "Building kata-overlay binary"
	pushd src/overlay/ || exit
	make all
	popd || exit

	echo "Building tardev-snapshotter service binary"
	pushd src/tardev-snapshotter/ || exit
	make all
	popd || exit
fi

echo "Building runtime-go shim binary"
pushd src/runtime/ || exit
if [[ "${CONF_PODS}" == "yes" ]] || [[ "${OS_VERSION}" == "3.0" ]]; then
	make "${runtime_go_make_flags[@]}"
else
	# Mariner 2 pod sandboxing uses cgroupsv1 - note: cannot add the kernelparams in above assignments,
	# leads to quotation issue. Hence, implementing the conditional check right here at the time of the make command
	make "${runtime_go_make_flags[@]}" "KERNELPARAMS=systemd.legacy_systemd_cgroup_controller=yes systemd.unified_cgroup_hierarchy=0"
fi
popd || exit

echo "Building runtime-rs shim binary"
pushd src/runtime-rs/ || exit
if [[ "${SHIM_REDEPLOY_CONFIG}" == "yes" ]]; then
	rm -f "config/${SHIM_CONFIG_FILE_NAME_RUNTIME_RS}"
fi
make "${runtime_rs_make_flags[@]}"
popd || exit

echo "Building kata-ctl binary"
pushd src/tools/kata-ctl/ || exit
make "${runtime_rs_make_flags[@]}"
popd || exit

create_debug_shim_config() {
	local config_dir="$1"
	local release_cfg="$2"
	local debug_cfg="$3"

	pushd "${config_dir}" || exit
	echo "Creating shim debug configuration: ${debug_cfg}"
	cp "${release_cfg}" "${debug_cfg}"
	# Ensure debug is enabled in the shim config, regardless of whether the
	# template uses commented or uncommented keys.
	sed -i -E 's|^#?[[:space:]]*enable_debug[[:space:]]*=.*$|enable_debug = true|' "${debug_cfg}"
	sed -i -E 's|^#?[[:space:]]*debug_console_enabled[[:space:]]*=.*$|debug_console_enabled = true|' "${debug_cfg}"

	if [[ "${CONF_PODS}" == "yes" ]]; then
		echo "Adding debug igvm to SNP shim debug configuration"
		sed -i "s|${IGVM_FILE_NAME}|${IGVM_DBG_FILE_NAME}|g" "${debug_cfg}"
	fi
	popd || exit
}

create_preview_shim_config() {
	local config_dir="$1"
	local base_cfg="$2"
	local preview_cfg="$3"

	pushd "${config_dir}" || exit
	echo "Creating shim preview configuration: ${preview_cfg}"
	cp "${base_cfg}" "${preview_cfg}"
	# Enable VM templating and the settings it requires.
	sed -i 's|^\[hypervisor\.clh\]$|[factory]\nenable_template = true\ntemplate_path = "/run/vc/vm/template"\n\n[hypervisor.clh]|' "${preview_cfg}"
	sed -i 's|^shared_fs = "virtio-fs"$|shared_fs = "none"|' "${preview_cfg}"
	sed -i 's|^default_maxmemory = .*$|default_maxmemory = 2048|' "${preview_cfg}"
	popd || exit
}

set_config_value() {
	local config="$1"
	local key="$2"
	local value="$3"

	if ! grep -qE "^${key}[[:space:]]*=" "${config}"; then
		echo "Missing expected configuration key '${key}' in ${config}" >&2
		return 1
	fi
	sed -i -E "s|^${key}[[:space:]]*=.*$|${key} = ${value}|" "${config}"
}

create_v2_shim_config() {
	local config_dir="$1"
	local base_cfg="$2"
	local v2_cfg="$3"

	pushd "${config_dir}" || exit
	echo "Creating runtime-rs kata-v2 configuration: ${v2_cfg}"
	cp "${base_cfg}" "${v2_cfg}"

	if ! grep -qE '^default_maxmemory[[:space:]]*=' "${v2_cfg}"; then
		sed -i -E '/^default_memory[[:space:]]*=/a default_maxmemory = 0' "${v2_cfg}"
	fi
	set_config_value "${v2_cfg}" "default_maxmemory" "0"
	set_config_value "${v2_cfg}" "overhead_vcpus" "0"
	set_config_value "${v2_cfg}" "overhead_memory" "0"
	set_config_value "${v2_cfg}" "memory_restore_mode" '"copyonwrite"'
	set_config_value "${v2_cfg}" "enable_virtio_mem" "false"
	set_config_value "${v2_cfg}" "shared_fs" '"none"'
	set_config_value "${v2_cfg}" "enable_template" "true"
	set_config_value "${v2_cfg}" "emptydir_mode" '"shared-fs"'
	set_config_value "${v2_cfg}" "static_sandbox_default_workload_mem" "2048"
	set_config_value "${v2_cfg}" "static_sandbox_default_workload_vcpus" "2"
	popd || exit
}

create_debug_shim_config  "${CONFIG_DIR_RUNTIME_GO}" "${SHIM_CONFIG_FILE_NAME_RUNTIME_GO}" "${SHIM_DBG_CONFIG_FILE_NAME_RUNTIME_GO}"
create_debug_shim_config "${CONFIG_DIR_RUNTIME_RS}" "${SHIM_CONFIG_FILE_NAME_RUNTIME_RS}" "${SHIM_DBG_CONFIG_FILE_NAME_RUNTIME_RS}"

create_v2_shim_config "${CONFIG_DIR_RUNTIME_RS}" "${SHIM_CONFIG_FILE_NAME_RUNTIME_RS}" "${SHIM_V2_CONFIG_FILE_NAME_RUNTIME_RS}"
create_debug_shim_config "${CONFIG_DIR_RUNTIME_RS}" "${SHIM_V2_CONFIG_FILE_NAME_RUNTIME_RS}" "${SHIM_V2_DBG_CONFIG_FILE_NAME_RUNTIME_RS}"

# Must run after create_debug_shim_config, the preview debug config derives from it.
create_preview_shim_config "${CONFIG_DIR_RUNTIME_GO}" "${SHIM_CONFIG_FILE_NAME_RUNTIME_GO}" "${SHIM_PREVIEW_CONFIG_FILE_NAME_RUNTIME_GO}"
create_preview_shim_config "${CONFIG_DIR_RUNTIME_GO}" "${SHIM_DBG_CONFIG_FILE_NAME_RUNTIME_GO}" "${SHIM_PREVIEW_DBG_CONFIG_FILE_NAME_RUNTIME_GO}"

echo "Building agent binary and generating service files"
pushd src/agent/ || exit
make "${agent_make_flags[@]}"
make install "${agent_make_flags[@]}"
popd || exit

popd || exit
