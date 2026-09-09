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
	"${build_dir}/rootfs-image" \
	"${build_dir}/rootfs-image-confidential" \
	"${build_dir}/shim-v2-rust"
rm -f \
	"${build_dir}/kata-static-agent.tar.zst" \
	"${build_dir}/kata-static-coco-guest-components.tar.zst" \
	"${build_dir}/kata-static-pause-image.tar.zst" \
	"${build_dir}/kata-static-rootfs-image.tar.zst" \
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
build_component rootfs-image
build_component coco-guest-components
build_component pause-image
build_component rootfs-image-confidential
build_component shim-v2-rust

for archive in \
	"${build_dir}/kata-static-rootfs-image.tar.zst" \
	"${build_dir}/kata-static-rootfs-image-confidential.tar.zst" \
	"${build_dir}/kata-static-shim-v2-rust.tar.zst"; do
	if [[ ! -f "${archive}" ]]; then
		echo "Kata build did not produce ${archive}" >&2
		exit 1
	fi
	tar --zstd -xf "${archive}" -C "${stage_dir}"
done

new_shim="${stage_dir}/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
new_guest_image="${stage_dir}/opt/kata/share/kata-containers/kata-containers.img"
new_confidential_image="${stage_dir}/opt/kata/share/kata-containers/kata-containers-confidential.img"
new_confidential_hash="${stage_dir}/opt/kata/share/kata-containers/root_hash_confidential.txt"
if [[ ! -x "${new_shim}" || ! -e "${new_guest_image}" ||
	! -e "${new_confidential_image}" || ! -e "${new_confidential_hash}" ]]; then
	echo "Kata build output is missing the runtime-rs shim, base image, or confidential image" >&2
	exit 1
fi

configured_guest_image=$(
	hypervisor_name=$("${script_dir}/kata_config_value.sh" \
		"${kata_config}" runtime hypervisor_name)
	"${script_dir}/kata_config_value.sh" \
		"${kata_config}" "hypervisor.${hypervisor_name}" image
)
case "${configured_guest_image}" in
/opt/kata/*)
	configured_guest_image="${kata_root}${configured_guest_image#/opt/kata}"
	;;
*)
	echo "guest image must be located under /opt/kata: ${configured_guest_image}" >&2
	exit 1
	;;
esac
configured_guest_image=$(readlink -f "${configured_guest_image}")
case "${configured_guest_image}" in
"${kata_root}"/*) ;;
*)
	echo "guest image resolves outside KATA_ROOT: ${configured_guest_image}" >&2
	exit 1
	;;
esac

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
install -D -m 0644 "${new_guest_image}" "${configured_guest_image}.new"
mv -f "${configured_guest_image}.new" "${configured_guest_image}"
install -D -m 0644 "${new_confidential_image}" \
	"${share_dir}/kata-containers-confidential.img.new"
mv -f "${share_dir}/kata-containers-confidential.img.new" \
	"${share_dir}/kata-containers-confidential.img"
install -m 0644 "${new_confidential_hash}" \
	"${share_dir}/root_hash_confidential.txt"

root_hash="${stage_dir}/opt/kata/share/kata-containers/root_hash_base.txt"
if [[ -f "${root_hash}" ]]; then
	install -m 0644 "${root_hash}" "${share_dir}/root_hash_base.txt"
fi

marker="${share_dir}/nested-policy-source-provenance"
shim_sha=$(sha256sum "${shim_dir}/containerd-shim-kata-v2" | cut -d ' ' -f 1)
guest_image_sha=$(sha256sum "${configured_guest_image}" | cut -d ' ' -f 1)
confidential_image_sha=$(
	sha256sum "${share_dir}/kata-containers-confidential.img" | cut -d ' ' -f 1
)
confidential_hash_sha=$(
	sha256sum "${share_dir}/root_hash_confidential.txt" | cut -d ' ' -f 1
)
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
format=1
runtime_rs_source=${runtime_source}
agent_source=${agent_source}
shim_sha256=${shim_sha}
guest_image_sha256=${guest_image_sha}
confidential_image_sha256=${confidential_image_sha}
confidential_hash_sha256=${confidential_hash_sha}
EOF
mv -f "${marker}.new" "${marker}"
echo "installed checkout-built runtime-rs shim, strict-Agent base image, and confidential guest-pull image under ${kata_root}"
