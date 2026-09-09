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

extract_commit() {
	local component=$1
	local version_output=$2
	local commit

	commit=$(sed -nE 's/.*commit( version)?: ([^,)]*-)?([0-9a-f]{40}).*/\3/p' <<<"${version_output}" |
		head -n 1)
	if [[ -z "${commit}" ]]; then
		echo "could not extract ${component} commit from version output:" >&2
		printf '%s\n' "${version_output}" >&2
		exit 1
	fi
	printf '%s\n' "${commit}"
}

verify_source_tree() {
	local component=$1
	local commit=$2
	shift 2
	local source_paths=("$@")
	local untracked

	if ! git -C "${repo_root}" cat-file -e "${commit}^{commit}" 2>/dev/null; then
		echo "${component} commit is not available in this checkout: ${commit}" >&2
		exit 1
	fi
	if ! git -C "${repo_root}" diff --quiet "${commit}" -- "${source_paths[@]}"; then
		echo "${component} build inputs differ from installed commit ${commit}" >&2
		git -C "${repo_root}" --no-pager diff --stat "${commit}" -- "${source_paths[@]}" >&2
		exit 1
	fi
	untracked=$(git -C "${repo_root}" ls-files --others --exclude-standard -- "${source_paths[@]}")
	if [[ -n "${untracked}" ]]; then
		echo "${component} cannot represent untracked build inputs:" >&2
		printf '%s\n' "${untracked}" >&2
		exit 1
	fi
	printf '%s source matches installed commit %s\n' "${component}" "${commit}"
}

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

guest_image=$(
	hypervisor_name=$("${script_dir}/kata_config_value.sh" \
		"${kata_config}" runtime hypervisor_name)
	"${script_dir}/kata_config_value.sh" \
		"${kata_config}" "hypervisor.${hypervisor_name}" image
)
case "${guest_image}" in
/opt/kata/*)
	guest_image="${kata_root}${guest_image#/opt/kata}"
	;;
*)
	echo "guest image must be located under /opt/kata: ${guest_image}" >&2
	exit 1
	;;
esac
guest_image=$(readlink -f "${guest_image}")
case "${guest_image}" in
"${kata_root}"/*) ;;
*)
	echo "guest image resolves outside KATA_ROOT: ${guest_image}" >&2
	exit 1
	;;
esac
if [[ ! -f "${guest_image}" ]]; then
	echo "guest image not found: ${guest_image}" >&2
	exit 1
fi

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
if [[ -f "${marker}" ]]; then
	declare -A provenance=()
	while IFS='=' read -r key value; do
		provenance["${key}"]=${value}
	done <"${marker}"

	runtime_source=$("${script_dir}/source_tree_fingerprint.sh" "${repo_root}" "${runtime_inputs[@]}")
	agent_source=$("${script_dir}/source_tree_fingerprint.sh" "${repo_root}" "${agent_inputs[@]}")
	shim_sha=$(sha256sum "${shim}" | cut -d ' ' -f 1)
	guest_image_sha=$(sha256sum "${guest_image}" | cut -d ' ' -f 1)
	confidential_image_sha=$(sha256sum "${confidential_image}" | cut -d ' ' -f 1)
	confidential_hash_sha=$(sha256sum "${confidential_hash}" | cut -d ' ' -f 1)
	if [[ "${provenance[format]:-}" == 1 &&
		"${provenance[runtime_rs_source]:-}" == "${runtime_source}" &&
		"${provenance[agent_source]:-}" == "${agent_source}" &&
		"${provenance[shim_sha256]:-}" == "${shim_sha}" &&
		"${provenance[guest_image_sha256]:-}" == "${guest_image_sha}" &&
		"${provenance[confidential_image_sha256]:-}" == "${confidential_image_sha}" &&
		"${provenance[confidential_hash_sha256]:-}" == "${confidential_hash_sha}" ]]; then
		echo "installed runtime-rs shim, base Agent image, and confidential guest-pull image match the current source tree"
		exit 0
	fi
	echo "installed Kata provenance marker does not match the current source tree or artifacts" >&2
	exit 1
fi

shim_commit=$(extract_commit "runtime-rs shim" "$("${shim}" --version 2>&1)")
verify_source_tree "runtime-rs shim" "${shim_commit}" "${runtime_inputs[@]}"

workdir=$(mktemp -d)
mount_dir="${workdir}/rootfs"
agent_copy="${workdir}/kata-agent"
loop_device=
cleanup() {
	if mountpoint -q "${mount_dir}" 2>/dev/null; then
		umount "${mount_dir}"
	fi
	if [[ -n "${loop_device}" ]]; then
		losetup -d "${loop_device}"
	fi
	rm -rf "${workdir}"
}
trap cleanup EXIT

mkdir -p "${mount_dir}"
loop_device=$(losetup --find --show --partscan --read-only "${guest_image}")
if [[ ! -b "${loop_device}p1" ]]; then
	echo "guest image has no readable first partition: ${guest_image}" >&2
	exit 1
fi
mount -o ro "${loop_device}p1" "${mount_dir}"
if [[ ! -x "${mount_dir}/usr/bin/kata-agent" ]]; then
	echo "guest Agent not found in ${guest_image}" >&2
	exit 1
fi
cp "${mount_dir}/usr/bin/kata-agent" "${agent_copy}"
umount "${mount_dir}"
losetup -d "${loop_device}"
loop_device=

agent_commit=$(extract_commit "guest Agent" "$("${agent_copy}" --version 2>&1)")
verify_source_tree "guest Agent" "${agent_commit}" "${agent_inputs[@]}"
