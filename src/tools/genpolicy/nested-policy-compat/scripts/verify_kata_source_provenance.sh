#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 REPO_ROOT KATA_ROOT KATA_CONFIG" >&2
	exit 2
fi

repo_root=$1
kata_root=$(readlink -f "$2")
kata_config=$3
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

for path in "${repo_root}/.git" "${kata_root}" "${kata_config}"; do
	if [[ ! -e "${path}" ]]; then
		echo "required provenance input not found: ${path}" >&2
		exit 1
	fi
done

runtime_inputs=(
	Cargo.toml
	Cargo.lock
	VERSION
	versions.yaml
	ci/install_yq.sh
	src/libs
	src/dragonball
	src/runtime-rs
	src/tools/genpolicy/nested-policy-compat/scripts/rebuild_kata_stack.sh
	tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh
	tools/packaging/scripts
	tools/packaging/static-build/shim-v2
)
agent_inputs=(
	Cargo.toml
	Cargo.lock
	VERSION
	versions.yaml
	ci/install_libseccomp.sh
	ci/install_yq.sh
	src/libs
	src/agent
	src/tools/genpolicy/nested-policy-compat/scripts/rebuild_kata_stack.sh
	tools/osbuilder
	tools/packaging/guest-image
	tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh
	tools/packaging/kata-deploy/local-build/kata-deploy-copy-libseccomp-installer.sh
	tools/packaging/scripts
	tools/packaging/static-build/agent
	tools/packaging/static-build/coco-guest-components
	tools/packaging/static-build/pause-image
)

confidential_image="${kata_root}/share/kata-containers/kata-containers-confidential.img"
confidential_hash="${kata_root}/share/kata-containers/root_hash_confidential.txt"
if [[ ! -f "${confidential_image}" ]]; then
	echo "confidential guest-pull image not found: ${confidential_image}" >&2
	exit 1
fi
if [[ ! -f "${confidential_hash}" ]]; then
	echo "confidential guest-pull image verity parameters not found: ${confidential_hash}" >&2
	exit 1
fi

resolve_config_path() {
	local section=$1
	local key=$2
	local configured

	configured=$("${script_dir}/kata_config_value.sh" "${kata_config}" "${section}" "${key}")
	case "${configured}" in
	/opt/kata/*)
		configured="${kata_root}${configured#/opt/kata}"
		;;
	*)
		echo "${key} must be located under /opt/kata: ${configured}" >&2
		exit 1
		;;
	esac
	configured=$(readlink -f "${configured}")
	case "${configured}" in
	"${kata_root}"/*) ;;
	*)
		echo "${key} resolves outside KATA_ROOT: ${configured}" >&2
		exit 1
		;;
	esac
	if [[ ! -f "${configured}" ]]; then
		echo "${key} artifact not found: ${configured}" >&2
		exit 1
	fi
	printf '%s\n' "${configured}"
}

hypervisor_name=$("${script_dir}/kata_config_value.sh" \
	"${kata_config}" runtime hypervisor_name)
vmm=$(resolve_config_path "hypervisor.${hypervisor_name}" path)
kernel=$(resolve_config_path "hypervisor.${hypervisor_name}" kernel)

shim_dir=$(readlink -f "${kata_root}/runtime-rs/bin")
case "${shim_dir}" in
"${kata_root}"/*) ;;
*)
	echo "runtime-rs binary directory resolves outside KATA_ROOT: ${shim_dir}" >&2
	exit 1
	;;
esac
shim="${shim_dir}/containerd-shim-kata-v2"
if [[ ! -x "${shim}" ]]; then
	echo "runtime-rs shim not found or not executable: ${shim}" >&2
	exit 1
fi

marker="${kata_root}/share/kata-containers/nested-policy-source-provenance"
if [[ ! -f "${marker}" ]]; then
	echo "installed Kata provenance marker not found: ${marker}" >&2
	echo "rebuild the Kata stack so strict-Agent features and all guest artifacts can be verified" >&2
	exit 1
fi

declare -A provenance=()
while IFS='=' read -r key value; do
	provenance["${key}"]=${value}
done <"${marker}"

runtime_source=$("${script_dir}/source_tree_fingerprint.sh" "${repo_root}" "${runtime_inputs[@]}")
agent_source=$("${script_dir}/source_tree_fingerprint.sh" "${repo_root}" "${agent_inputs[@]}")
shim_sha=$(sha256sum "${shim}" | cut -d ' ' -f 1)
confidential_image_sha=$(sha256sum "${confidential_image}" | cut -d ' ' -f 1)
confidential_hash_sha=$(sha256sum "${confidential_hash}" | cut -d ' ' -f 1)
vmm_sha=$(sha256sum "${vmm}" | cut -d ' ' -f 1)
kernel_sha=$(sha256sum "${kernel}" | cut -d ' ' -f 1)
kata_config_sha=$(sha256sum "${kata_config}" | cut -d ' ' -f 1)
if [[ "${provenance[format]:-}" == 3 &&
	"${provenance[runtime_rs_source]:-}" == "${runtime_source}" &&
	"${provenance[agent_source]:-}" == "${agent_source}" &&
	"${provenance[shim_sha256]:-}" == "${shim_sha}" &&
	"${provenance[confidential_image_sha256]:-}" == "${confidential_image_sha}" &&
	"${provenance[confidential_hash_sha256]:-}" == "${confidential_hash_sha}" &&
	"${provenance[vmm_sha256]:-}" == "${vmm_sha}" &&
	"${provenance[kernel_sha256]:-}" == "${kernel_sha}" &&
	"${provenance[kata_config_sha256]:-}" == "${kata_config_sha}" ]]; then
	echo "installed VMM, kernel, runtime-rs shim, configuration, and strict-Agent confidential guest image match the provenance marker"
	exit 0
fi
echo "installed Kata provenance marker does not match the current source tree or artifacts" >&2
exit 1
