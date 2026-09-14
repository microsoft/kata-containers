#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 REPO_ROOT KATA_ROOT KATA_CONFIG CONTAINER_ENGINE" >&2
	exit 2
fi

repo_root=$1
kata_root=$(readlink -f "$2")
kata_config=$3
container_engine=$4
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
local_build_dir="${repo_root}/tools/packaging/kata-deploy/local-build"
build_dir="${local_build_dir}/build"

if [[ ! -x "${container_engine}" ]]; then
	echo "container engine not found or not executable: ${container_engine}" >&2
	exit 1
fi
if [[ ! -d "${kata_root}" || ! -w "${kata_root}" ]]; then
	echo "KATA_ROOT must exist and be writable for automatic installation: ${kata_root}" >&2
	exit 1
fi
if [[ ! -f "${kata_config}" ]]; then
	echo "Kata configuration not found: ${kata_config}" >&2
	exit 1
fi

tool_dir=$(mktemp -d)
stage_dir=$(mktemp -d)
cleanup() {
	rm -rf "${tool_dir}" "${stage_dir}"
}
trap cleanup EXIT

cat >"${tool_dir}/docker" <<'EOF'
#!/usr/bin/env bash
set -o errexit
set -o nounset

if [[ "${1:-}" == "run" && -n "${KATA_AGENT_MAKEFLAGS:-}" ]]; then
	shift
	exec "${REAL_CONTAINER_ENGINE}" run \
		--env "MAKEFLAGS=${KATA_AGENT_MAKEFLAGS}" "$@"
fi
exec "${REAL_CONTAINER_ENGINE}" "$@"
EOF
chmod 0755 "${tool_dir}/docker"
export REAL_CONTAINER_ENGINE="${container_engine}"
if [[ "$(basename "${container_engine}")" == podman ]]; then
	DOCKER_RUNTIME=$("${container_engine}" info --format '{{.Host.OCIRuntime.Name}}')
	export DOCKER_RUNTIME
fi
if ! command -v yq >/dev/null 2>&1; then
	INSTALL_IN_GOPATH=true "${repo_root}/ci/install_yq.sh"
fi
export PATH="${tool_dir}:${GOPATH:-${HOME}/go}/bin:${PATH}"
export ARCH
ARCH=$(uname -m)
export TARGET_ARCH="${ARCH}"
export TARGET_OS=linux
export CROSS_BUILD=false
export DEBUG=false
export RELEASE=no
export EXTRA_PKGS=
export REPO_URL=
export REPO_URL_X86_64=
export REPO_COMPONENTS=
export BUSYBOX_CONF_FILE=
export GUEST_HOOKS_TARBALL_NAME=
export BUILDER_REGISTRY=quay.io/kata-containers/builders
export USE_ORAS_CACHE=yes
export PUSH_TO_REGISTRY=no
unset \
	AGENT_CONTAINER_BUILDER \
	COCO_GUEST_COMPONENTS_CONTAINER_BUILDER \
	PAUSE_IMAGE_CONTAINER_BUILDER \
	SHIM_V2_CONTAINER_BUILDER

mkdir -p "${build_dir}"
"${local_build_dir}/kata-deploy-copy-libseccomp-installer.sh" agent

build_component() {
	local component=$1
	echo "building Kata ${component} from the current checkout"
	(
		cd "${local_build_dir}"
		USE_CACHE=no \
			AGENT_POLICY=yes \
			STRICT_POLICY=yes \
			INIT_DATA=yes \
			USE_DEVMAPPER=yes \
			MEASURED_ROOTFS=no \
			./kata-deploy-binaries.sh --build="${component}"
	)
}

component_archive() {
	case "$1" in
	agent) echo "${build_dir}/kata-static-agent.tar.zst" ;;
	coco-guest-components)
		echo "${build_dir}/kata-static-coco-guest-components.tar.zst"
		;;
	pause-image) echo "${build_dir}/kata-static-pause-image.tar.zst" ;;
	rootfs-image-confidential)
		echo "${build_dir}/kata-static-rootfs-image-confidential.tar.zst"
		;;
	shim-v2-rust) echo "${build_dir}/kata-static-shim-v2-rust.tar.zst" ;;
	*)
		echo "unsupported Kata component: $1" >&2
		exit 2
		;;
	esac
}

component_builder_identity() {
	local component=$1
	local helper
	local reference
	local digest
	local -a base_images

	case "${component}" in
	agent) helper=get_agent_image_name ;;
	coco-guest-components) helper=get_coco_guest_components_image_name ;;
	pause-image) helper=get_pause_image_name ;;
	shim-v2-rust) helper=get_shim_v2_image_name ;;
	rootfs-image-confidential)
		local ubuntu_digest
		local fedora_digest
		ubuntu_digest=$(
			skopeo inspect --format '{{.Digest}}' docker://docker.io/library/ubuntu:noble
		)
		fedora_digest=$(
			skopeo inspect --format '{{.Digest}}' \
				docker://registry.fedoraproject.org/fedora:44
		)
		printf 'ubuntu:noble@%s;fedora:44@%s\n' \
			"${ubuntu_digest}" "${fedora_digest}"
		return
		;;
	esac
	reference=$(
		# shellcheck source=/dev/null
		source "${repo_root}/tools/packaging/scripts/lib.sh"
		"${helper}"
	)
	digest=$(
		skopeo inspect --format '{{.Digest}}' "docker://${reference}" \
			2>/dev/null || true
	)
	if [[ -n "${digest}" ]]; then
		printf '%s@%s\n' "${reference}" "${digest}"
		return
	fi

	case "${component}" in
	coco-guest-components)
		base_images=(docker.io/library/ubuntu:24.04)
		;;
	*)
		base_images=(docker.io/library/ubuntu:22.04)
		;;
	esac
	printf '%s;locally-built-from=' "${reference}"
	for base_image in "${base_images[@]}"; do
		digest=$(
			skopeo inspect --format '{{.Digest}}' "docker://${base_image}"
		)
		printf '%s@%s,' "${base_image}" "${digest}"
	done
	printf '\n'
}

ensure_component() {
	local component=$1
	shift
	local archive
	local fingerprint_file
	local expected
	local actual=

	archive=$(component_archive "${component}")
	fingerprint_file="${build_dir}/.nested-policy-compat-${component}.fingerprint"
	export NPC_COMPONENT_BUILDER_IDENTITY
	NPC_COMPONENT_BUILDER_IDENTITY=$(component_builder_identity "${component}")
	expected=$(
		"${script_dir}/component_input_fingerprint.sh" \
			"${repo_root}" "${component}" "$@"
	)
	if [[ -f "${fingerprint_file}" ]]; then
		actual=$(<"${fingerprint_file}")
	fi
	if [[ -f "${archive}" && "${actual}" == "${expected}" ]]; then
		echo "reusing Kata ${component}: ${archive}"
		return
	fi

	echo "Kata ${component} inputs changed or output is missing"
	rm -rf "${build_dir:?}/${component}"
	rm -f "${archive}" "${fingerprint_file}"
	build_component "${component}"
	if [[ ! -f "${archive}" ]]; then
		echo "Kata build did not produce ${archive}" >&2
		exit 1
	fi
	printf '%s\n' "${expected}" >"${fingerprint_file}.new"
	mv -f "${fingerprint_file}.new" "${fingerprint_file}"
}

export KATA_AGENT_MAKEFLAGS="EXTRA_RUSTFEATURES=allow-unattested-initdata"
ensure_component agent
unset KATA_AGENT_MAKEFLAGS
ensure_component coco-guest-components
ensure_component pause-image
ensure_component rootfs-image-confidential \
	"$(component_archive agent)" \
	"$(component_archive coco-guest-components)" \
	"$(component_archive pause-image)"
ensure_component shim-v2-rust

for archive in \
	"${build_dir}/kata-static-rootfs-image-confidential.tar.zst" \
	"${build_dir}/kata-static-shim-v2-rust.tar.zst"; do
	if [[ ! -f "${archive}" ]]; then
		echo "Kata build did not produce ${archive}" >&2
		exit 1
	fi
	tar --zstd -xf "${archive}" -C "${stage_dir}"
done

new_shim="${stage_dir}/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
new_confidential_image="${stage_dir}/opt/kata/share/kata-containers/kata-containers-confidential.img"
new_confidential_hash="${stage_dir}/opt/kata/share/kata-containers/root_hash_confidential.txt"
if [[ ! -x "${new_shim}" || ! -e "${new_confidential_image}" ||
	! -e "${new_confidential_hash}" ]]; then
	echo "Kata build output is missing the runtime-rs shim or confidential image" >&2
	exit 1
fi

shim_dir=$(readlink -f "${kata_root}/runtime-rs/bin")
share_dir=$(readlink -f "${kata_root}/share/kata-containers")
for install_dir in "${shim_dir}" "${share_dir}"; do
	case "${install_dir}" in
	"${kata_root}"/*) ;;
	*)
		echo "Kata installation directory resolves outside KATA_ROOT: ${install_dir}" >&2
		exit 1
		;;
	esac
done

install -D -m 0755 "${new_shim}" \
	"${shim_dir}/containerd-shim-kata-v2.new"
mv -f "${shim_dir}/containerd-shim-kata-v2.new" \
	"${shim_dir}/containerd-shim-kata-v2"
install -D -m 0644 "${new_confidential_image}" \
	"${share_dir}/kata-containers-confidential.img.new"
mv -f "${share_dir}/kata-containers-confidential.img.new" \
	"${share_dir}/kata-containers-confidential.img"
install -m 0644 "${new_confidential_hash}" \
	"${share_dir}/root_hash_confidential.txt"

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

marker="${share_dir}/nested-policy-source-provenance"
shim_sha=$(sha256sum "${shim_dir}/containerd-shim-kata-v2" | cut -d ' ' -f 1)
confidential_image_sha=$(
	sha256sum "${share_dir}/kata-containers-confidential.img" | cut -d ' ' -f 1
)
confidential_hash_sha=$(
	sha256sum "${share_dir}/root_hash_confidential.txt" | cut -d ' ' -f 1
)
vmm_sha=$(sha256sum "${vmm}" | cut -d ' ' -f 1)
kernel_sha=$(sha256sum "${kernel}" | cut -d ' ' -f 1)
kata_config_sha=$(sha256sum "${kata_config}" | cut -d ' ' -f 1)
runtime_source=$(
	"${script_dir}/source_tree_fingerprint.sh" "${repo_root}" \
		Cargo.toml Cargo.lock VERSION versions.yaml ci/install_yq.sh src/libs \
		src/dragonball src/runtime-rs \
	src/tools/genpolicy/nested-policy-compat/scripts/component_input_fingerprint.sh \
	src/tools/genpolicy/nested-policy-compat/scripts/rebuild_kata_stack.sh \
		tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh \
		tools/packaging/scripts tools/packaging/static-build/shim-v2
)
agent_source=$(
	"${script_dir}/source_tree_fingerprint.sh" "${repo_root}" \
		Cargo.toml Cargo.lock VERSION versions.yaml ci/install_libseccomp.sh \
		ci/install_yq.sh src/libs src/agent tools/osbuilder \
		src/tools/genpolicy/nested-policy-compat/scripts/component_input_fingerprint.sh \
		src/tools/genpolicy/nested-policy-compat/scripts/rebuild_kata_stack.sh \
		tools/packaging/guest-image \
		tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh \
		tools/packaging/kata-deploy/local-build/kata-deploy-copy-libseccomp-installer.sh \
		tools/packaging/scripts tools/packaging/static-build/agent \
		tools/packaging/static-build/coco-guest-components \
		tools/packaging/static-build/pause-image
)
cat >"${marker}.new" <<EOF
format=3
runtime_rs_source=${runtime_source}
agent_source=${agent_source}
shim_sha256=${shim_sha}
confidential_image_sha256=${confidential_image_sha}
confidential_hash_sha256=${confidential_hash_sha}
vmm_sha256=${vmm_sha}
kernel_sha256=${kernel_sha}
kata_config_sha256=${kata_config_sha}
EOF
mv -f "${marker}.new" "${marker}"
echo "installed checkout-built runtime-rs shim and strict-Agent confidential guest image with bound VMM, kernel, and configuration under ${kata_root}"
