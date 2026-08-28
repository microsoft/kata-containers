#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

kernel_src="${KERNEL_SRC:-${HOME}/src/openvmm-aci-kernel}"
script_dir="$(dirname "$(readlink -f "$0")")"
kernel_config="${KERNEL_CONFIG:-${script_dir}/kernel.config}"
build_dir="${BUILD_DIR:-${kernel_src}/build-kata-openvmm}"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

[[ -f "${kernel_src}/Makefile" ]] ||
	die "kernel source does not exist: ${kernel_src}"
[[ -f "${kernel_config}" ]] ||
	die "kernel config does not exist: ${kernel_config}"

for tool in gcc make; do
	command -v "${tool}" >/dev/null || die "required tool not found: ${tool}"
done

mkdir -p "${build_dir}"
cp "${kernel_config}" "${build_dir}/.config"

"${kernel_src}/scripts/config" --file "${build_dir}/.config" \
	--set-str LOCALVERSION "-aci-kata-openvmm" \
	--enable BLK_DEV_DM \
	--enable DM_VERITY \
	--enable DM_INIT \
	--enable MISC_FILESYSTEMS \
	--enable EROFS_FS \
	--enable EROFS_FS_XATTR \
	--enable EROFS_FS_ZIP \
	--enable EROFS_FS_SECURITY \
	--enable VSOCKETS \
	--enable VIRTIO_VSOCKETS \
	--enable VIRTIO_VSOCKETS_COMMON \
	--enable VIRT_DRIVERS \
	--enable SEV_GUEST \
	--enable PCIEPORTBUS \
	--enable TUN \
	--enable NF_TABLES \
	--enable NF_TABLES_INET \
	--enable NF_TABLES_IPV4 \
	--enable NF_TABLES_IPV6 \
	--enable NF_TABLES_BRIDGE \
	--enable NF_TABLES_ARP \
	--enable NF_TABLES_NETDEV \
	--enable CGROUP_BPF

make -C "${kernel_src}" O="${build_dir}" olddefconfig
make -C "${kernel_src}" O="${build_dir}" -j"$(nproc)" bzImage

image="${build_dir}/arch/x86/boot/bzImage"
embedded_config="${build_dir}/config.embedded"
"${kernel_src}/scripts/extract-ikconfig" "${image}" >"${embedded_config}"

for symbol in \
	DM_INIT \
	EROFS_FS \
	EROFS_FS_ZIP \
	VIRTIO_VSOCKETS \
	SEV_GUEST \
	PCIEPORTBUS \
	TUN \
	NF_TABLES \
	CGROUP_BPF; do
	grep -q "^CONFIG_${symbol}=y$" "${embedded_config}" ||
		die "built kernel is missing CONFIG_${symbol}=y"
done

file "${image}"
sha256sum "${image}"
echo "Built ${image}"
