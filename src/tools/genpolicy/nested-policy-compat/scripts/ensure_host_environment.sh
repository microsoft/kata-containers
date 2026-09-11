#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 KATA_ROOT KATA_CONFIG CONTAINER_ENGINE" >&2
	exit 2
fi

kata_root=$1
kata_config=$2
container_engine=$3
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../../../../.." && pwd)
artifact_image=${KATA_ARTIFACT_IMAGE:-quay.io/kata-containers/kata-deploy-ci:kata-containers-latest}
artifact_dir=${KATA_ARTIFACT_DIR:-}
approval=${APPROVE_KATA_INSTALL:-no}
genpolicy_target=${GENPOLICY_TARGET:-x86_64-unknown-linux-musl}
rootfs_mode=${ROOTFS_MODE:-unknown}
flat_vmdk_repo=${FLAT_VMDK_CLOUD_HYPERVISOR_REPO:-https://github.com/cloud-hypervisor/cloud-hypervisor.git}
flat_vmdk_commit=${FLAT_VMDK_CLOUD_HYPERVISOR_COMMIT:-f50661fffd0fef38ddfec88c5fafa93f9779149a}

required_devices=(/dev/kvm /dev/net/tun)
for device in "${required_devices[@]}"; do
	if [[ ! -c "${device}" ]]; then
		echo "required device is unavailable: ${device}" >&2
		exit 1
	fi
done
if [[ -z "${container_engine}" || ! -x "${container_engine}" ]]; then
	echo "Podman or Docker is required to install and run the compatibility environment" >&2
	exit 1
fi
for command in cargo find git make python3 rustup sha256sum tar; do
	if ! command -v "${command}" >/dev/null 2>&1; then
		echo "required host command is unavailable: ${command}" >&2
		exit 1
	fi
done
if ! tar --help 2>&1 | grep -F -- --zstd >/dev/null; then
	echo "host tar does not support --zstd" >&2
	exit 1
fi
if [[ "$(stat -fc %T /sys/fs/cgroup)" != cgroup2fs ]]; then
	echo "cgroup v2 is required" >&2
	exit 1
fi
if ! "${container_engine}" info >/dev/null 2>&1; then
	echo "cannot access the selected container engine: ${container_engine}" >&2
	exit 1
fi
if [[ "${rootfs_mode}" == erofs-dmverity ]]; then
	for command in bison dmsetup flex losetup m4 modprobe pkg-config; do
		if ! command -v "${command}" >/dev/null 2>&1; then
			echo "EROFS dm-verity requires host command: ${command}" >&2
			exit 1
		fi
	done
	if [[ ! -c /dev/mapper/control ]]; then
		echo "EROFS dm-verity requires /dev/mapper/control" >&2
		exit 1
	fi
fi

required_artifacts=(
	"${kata_root}/bin/cloud-hypervisor"
	"${kata_root}/share/kata-containers/vmlinux.container"
	"${kata_root}/runtime-rs/bin/containerd-shim-kata-v2"
	"${kata_root}/share/kata-containers/kata-containers-confidential.img"
	"${kata_root}/share/kata-containers/root_hash_confidential.txt"
)
missing=()
yq_missing=no
if ! command -v yq >/dev/null 2>&1; then
	missing+=("repository-pinned mikefarah yq")
	yq_missing=yes
fi
rust_target_missing=no
if ! rustup target list --installed | grep -Fxq "${genpolicy_target}"; then
	missing+=("Rust target ${genpolicy_target}")
	rust_target_missing=yes
fi
for artifact in "${required_artifacts[@]}"; do
	[[ -e "${artifact}" ]] || missing+=("${artifact}")
done
vmm="${kata_root}/bin/cloud-hypervisor"
if [[ "${rootfs_mode}" == erofs-dmverity && -f "${vmm}" ]] &&
	! grep -aF 'FlatVmdk' "${vmm}" >/dev/null; then
	missing+=("${vmm} (lacks flat-VMDK support)")
fi
if [[ "${rootfs_mode}" == erofs-dmverity ]] &&
	! grep -qw erofs /proc/filesystems; then
	missing+=("host EROFS filesystem support (module erofs is not loaded)")
fi
if [[ ! -f "${kata_config}" ]]; then
	missing+=("${kata_config}")
elif ! python3 - "${kata_config}" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as stream:
    configuration = tomllib.load(stream)
runtime = configuration.get("runtime", {})
hypervisor_name = runtime.get("hypervisor_name")
hypervisor = configuration.get("hypervisor", {}).get(hypervisor_name, {})
annotations = hypervisor.get("enable_annotations", [])
raise SystemExit(
    0
    if hypervisor_name == "clh"
    and hypervisor.get("shared_fs") == "none"
    and "cc_init_data" in annotations
    else 1
)
PY
then
	missing+=("${kata_config} (must select clh, enable cc_init_data, and set shared_fs=none)")
fi
if [[ "${#missing[@]}" -eq 0 ]]; then
	exit 0
fi

if [[ "${approval}" != yes ]]; then
	echo "the nested compatibility host environment is incomplete:" >&2
	printf '  missing %s\n' "${missing[@]}" >&2
	cat >&2 <<EOF

Installing it writes Kata binaries, the guest kernel, confidential image, root
hash, and a dedicated runtime configuration under ${kata_root}. By default the
artifacts are pulled from ${artifact_image}; set KATA_ARTIFACT_DIR to use
previously downloaded tarballs instead.
For EROFS, an artifact VMM without flat-VMDK support is replaced by a build of
${flat_vmdk_repo} at pinned commit ${flat_vmdk_commit}.
The approved path also loads the host EROFS kernel module.

Review the image and destination, then approve the installation with:
  make -C src/tools/genpolicy/nested-policy-compat fixture-e2e \\
    APPROVE_KATA_INSTALL=yes \\
    KATA_ROOT=${kata_root} \\
    KATA_CONFIG=${kata_config} \\
    OUTPUT_ROOT=/path/to/test-results
EOF
	exit 1
fi

if [[ "${yq_missing}" == yes ]]; then
	echo "installing repository-pinned mikefarah yq"
	INSTALL_IN_GOPATH=false "${repo_root}/ci/install_yq.sh"
fi
if [[ "${rust_target_missing}" == yes ]]; then
	echo "installing Rust target ${genpolicy_target}"
	rustup target add "${genpolicy_target}"
fi

if [[ -e "${kata_root}" && ! -d "${kata_root}" ]]; then
	echo "KATA_ROOT is not a directory: ${kata_root}" >&2
	exit 1
fi
mkdir -p "${kata_root}"
if [[ ! -w "${kata_root}" ]]; then
	echo "KATA_ROOT is not writable: ${kata_root}" >&2
	exit 1
fi

workdir=$(mktemp -d)
container=
cleanup() {
	if [[ -n "${container}" ]]; then
		"${container_engine}" rm -f "${container}" >/dev/null 2>&1 || true
	fi
	rm -rf "${workdir}"
}
trap cleanup EXIT

if [[ -n "${artifact_dir}" ]]; then
	artifact_dir=$(readlink -f "${artifact_dir}")
	if [[ ! -d "${artifact_dir}" ]]; then
		echo "KATA_ARTIFACT_DIR not found: ${artifact_dir}" >&2
		exit 1
	fi
	echo "installing nested compatibility prerequisites from ${artifact_dir}"
else
	echo "installing nested compatibility prerequisites from ${artifact_image}"
	"${container_engine}" pull "${artifact_image}"
	container=$("${container_engine}" create "${artifact_image}")
	"${container_engine}" cp \
		"${container}:/opt/kata-artifacts/tarballs" "${workdir}/tarballs"
	artifact_dir="${workdir}/tarballs"
fi

for archive in \
	kata-static-cloud-hypervisor.tar.zst \
	kata-static-kernel.tar.zst \
	kata-static-shim-v2-rust.tar.zst \
	kata-static-rootfs-image-confidential.tar.zst; do
	path="${artifact_dir}/${archive}"
	if [[ ! -f "${path}" ]]; then
		echo "artifact image is missing required archive: ${archive}" >&2
		exit 1
	fi
	tar --zstd -xf "${path}" -C "${kata_root}" --strip-components=3
done

source_config="${kata_root}/share/defaults/kata-containers/runtime-rs/configuration-clh-runtime-rs.toml"
if [[ ! -f "${source_config}" ]]; then
	echo "installed artifacts are missing the Cloud Hypervisor runtime-rs configuration" >&2
	exit 1
fi
mkdir -p "$(dirname "${kata_config}")"
python3 - "${source_config}" "${kata_config}" <<'PY'
import json
import sys
import tomllib
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
with source.open("rb") as stream:
    configuration = tomllib.load(stream)

runtime = configuration.get("runtime", {})
hypervisor_name = runtime.get("hypervisor_name")
if hypervisor_name != "clh":
    raise SystemExit(f"expected Cloud Hypervisor configuration, got {hypervisor_name!r}")

lines = source.read_text(encoding="utf-8").splitlines()
in_hypervisor = False
annotations_replaced = False
shared_fs_replaced = False
header = f"[hypervisor.{hypervisor_name}]"
for index, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        in_hypervisor = stripped == header
    elif in_hypervisor and stripped.startswith("enable_annotations"):
        annotations = list(
            configuration["hypervisor"][hypervisor_name].get(
                "enable_annotations", []
            )
        )
        if "cc_init_data" not in annotations:
            annotations.append("cc_init_data")
        lines[index] = f"enable_annotations = {json.dumps(annotations)}"
        annotations_replaced = True
    elif in_hypervisor and stripped.startswith("shared_fs"):
        lines[index] = 'shared_fs = "none"'
        shared_fs_replaced = True

if not annotations_replaced or not shared_fs_replaced:
    raise SystemExit(
        f"{source} lacks enable_annotations or shared_fs in {header}"
    )
destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

if [[ "${rootfs_mode}" == erofs-dmverity ]] &&
	! grep -aF 'FlatVmdk' "${vmm}" >/dev/null; then
	echo "building flat-VMDK Cloud Hypervisor ${flat_vmdk_commit}"
	vmm_source="${workdir}/cloud-hypervisor"
	git init --quiet "${vmm_source}"
	git -C "${vmm_source}" remote add origin "${flat_vmdk_repo}"
	git -C "${vmm_source}" fetch --quiet --depth 1 origin "${flat_vmdk_commit}"
	if [[ "$(git -C "${vmm_source}" rev-parse FETCH_HEAD)" != "${flat_vmdk_commit}" ]]; then
		echo "fetched Cloud Hypervisor commit does not match the pinned revision" >&2
		exit 1
	fi
	git -C "${vmm_source}" checkout --quiet --detach FETCH_HEAD
	cargo build --locked --release \
		--manifest-path "${vmm_source}/Cargo.toml" \
		--package cloud-hypervisor
	install -D -m 0755 \
		"${vmm_source}/target/release/cloud-hypervisor" "${vmm}.new"
	mv -f "${vmm}.new" "${vmm}"
	if ! grep -aF 'FlatVmdk' "${vmm}" >/dev/null; then
		echo "rebuilt Cloud Hypervisor still lacks flat-VMDK support" >&2
		exit 1
	fi
fi

if [[ "${rootfs_mode}" == erofs-dmverity ]] &&
	! grep -qw erofs /proc/filesystems; then
	if ! modprobe erofs; then
		echo "the running host kernel does not provide a loadable EROFS module" >&2
		exit 1
	fi
	if ! grep -qw erofs /proc/filesystems; then
		echo "EROFS is still unavailable after loading the host module" >&2
		exit 1
	fi
fi

echo "installed nested compatibility host environment under ${kata_root}"
