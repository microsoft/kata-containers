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

mkdir -p "${build_dir}"
"${local_build_dir}/kata-deploy-copy-libseccomp-installer.sh" agent
rm -rf \
	"${build_dir}/agent" \
	"${build_dir}/coco-guest-components" \
	"${build_dir}/pause-image" \
	"${build_dir}/rootfs-image-confidential" \
	"${build_dir}/shim-v2-rust"
rm -f \
	"${build_dir}/kata-static-agent.tar.zst" \
	"${build_dir}/kata-static-coco-guest-components.tar.zst" \
	"${build_dir}/kata-static-pause-image.tar.zst" \
	"${build_dir}/kata-static-rootfs-image-confidential.tar.zst" \
	"${build_dir}/kata-static-shim-v2-rust.tar.zst"

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

export KATA_AGENT_MAKEFLAGS="EXTRA_RUSTFEATURES=allow-unattested-initdata"
build_component agent
unset KATA_AGENT_MAKEFLAGS
build_component coco-guest-components
build_component pause-image
build_component rootfs-image-confidential
build_component shim-v2-rust

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
		src/tools/genpolicy/nested-policy-compat/scripts/rebuild_kata_stack.sh \
		tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh \
		tools/packaging/scripts tools/packaging/static-build/shim-v2
)
agent_source=$(
	"${script_dir}/source_tree_fingerprint.sh" "${repo_root}" \
		Cargo.toml Cargo.lock VERSION versions.yaml ci/install_libseccomp.sh \
		ci/install_yq.sh src/libs src/agent tools/osbuilder \
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
