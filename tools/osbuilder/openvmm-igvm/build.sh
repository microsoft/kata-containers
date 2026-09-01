#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(dirname "$(readlink -f "$0")")"
openvmm_dir="${OPENVMM_DIR:-${HOME}/openvmm-snp-mshv-aci-igvm}"
igvmfilegen="${IGVMFILEGEN:-${openvmm_dir}/target/release/igvmfilegen}"
kernel="${KERNEL:-}"
busybox="${BUSYBOX:-}"
out_dir="${OUT_DIR:-${script_dir}/out}"
boot_mode="${BOOT_MODE:-diagnostic}"
extra_kernel_args="${EXTRA_KERNEL_ARGS:-}"
output_name="${OUTPUT_NAME:-}"
root_hash_file="${ROOT_HASH_FILE:-}"
vp_count="${VP_COUNT:-1}"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

[[ -f "${kernel}" ]] || die "set KERNEL to the ACI bzImage"
[[ -x "${igvmfilegen}" ]] ||
	die "igvmfilegen is not executable: ${igvmfilegen}"
command -v jq >/dev/null || die "required tool not found: jq"
[[ "${vp_count}" =~ ^[1-9][0-9]*$ ]] ||
	die "VP_COUNT must be a positive integer: ${vp_count}"

mkdir -p "${out_dir}"

if [[ "${boot_mode}" == "rootfs" ]]; then
	manifest="${script_dir}/manifest-rootfs.json"
	[[ -n "${root_hash_file}" ]] ||
		die "ROOT_HASH_FILE is required for rootfs mode"
	kernel_cmdline="$(
		jq -r '.guest_configs[0].image.snp_linux_direct.linux.command_line' \
			"${manifest}"
	)"

	if [[ -n "${root_hash_file}" ]]; then
		[[ -f "${root_hash_file}" ]] ||
			die "dm-verity metadata does not exist: ${root_hash_file}"

		declare -A verity
		while IFS='=' read -r name value; do
			verity["${name}"]="${value}"
		done < <(tr ',' '\n' <"${root_hash_file}")

		for name in root_hash salt data_blocks data_block_size hash_block_size; do
			[[ -n "${verity[${name}]:-}" ]] ||
				die "missing ${name} in ${root_hash_file}"
		done

		data_sectors=$((
			verity[data_blocks] * verity[data_block_size] / 512
		))
		dm_create="dm-mod.create=\"dm-verity,,,ro,0 ${data_sectors} verity 1"
		dm_create+=" /dev/vda1 /dev/vda2 ${verity[data_block_size]}"
		dm_create+=" ${verity[hash_block_size]} ${verity[data_blocks]} 0"
		dm_create+=" sha256 ${verity[root_hash]} ${verity[salt]}\""
		before="${kernel_cmdline}"
		kernel_cmdline="${kernel_cmdline/root=\/dev\/vda1 ro rootfstype=ext4/${dm_create} root=\/dev\/dm-0 rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4}"
		[[ "${kernel_cmdline}" != "${before}" ]] ||
			die "dm-verity command line injection did not match ${manifest} — refusing to emit an unprotected image"
	fi

	if [[ -n "${extra_kernel_args}" ]]; then
		kernel_cmdline+=" ${extra_kernel_args}"
	fi

	manifest="${out_dir}/manifest-rootfs-generated.json"
	jq \
		--arg kernel_cmdline "${kernel_cmdline}" \
		--argjson vp_count "${vp_count}" \
		'(.guest_configs[0].image.snp_linux_direct.linux.command_line) =
			$kernel_cmdline |
		(.guest_configs[0].image.snp_linux_direct.processor_topology.proc_count) =
			$vp_count' \
		"${script_dir}/manifest-rootfs.json" >"${manifest}"

	output_name="${output_name:-kata-aci-rootfs-direct-no-initrd-${vp_count}vp.bin}"
	jq -n \
		--arg kernel "$(readlink -f "${kernel}")" \
		'{resources: {linux_kernel: $kernel}}' \
		>"${out_dir}/resources-rootfs.json"

	"${igvmfilegen}" manifest \
		--manifest "${manifest}" \
		--resources "${out_dir}/resources-rootfs.json" \
		--output "${out_dir}/${output_name}"

	echo "Built ${out_dir}/${output_name}"
	exit 0
fi

[[ "${boot_mode}" == "diagnostic" ]] ||
	die "unsupported BOOT_MODE: ${boot_mode}"
[[ -x "${busybox}" ]] || die "set BUSYBOX to a static BusyBox executable"

for tool in cpio file find gzip; do
	command -v "${tool}" >/dev/null || die "required tool not found: ${tool}"
done

file "${busybox}" | grep -q "statically linked" ||
	die "BUSYBOX must be statically linked"

initramfs_dir="${out_dir}/initramfs"
rm -rf -- "${initramfs_dir}"
mkdir -p "${initramfs_dir}"/{bin,dev,etc,proc,sys,tmp}

install -m 0755 "${busybox}" "${initramfs_dir}/bin/busybox"
for applet in cat grep ls mount sh uname; do
	ln -s busybox "${initramfs_dir}/bin/${applet}"
done
install -m 0755 "${script_dir}/init" "${initramfs_dir}/init"

(
	cd "${initramfs_dir}"
	find . -print0 |
		cpio --null --create --format=newc 2>/dev/null |
		gzip -9
) >"${out_dir}/diagnostic-initrd.gz"

jq -n \
	--arg kernel "$(readlink -f "${kernel}")" \
	--arg initrd "$(readlink -f "${out_dir}/diagnostic-initrd.gz")" \
	'{resources: {linux_kernel: $kernel, linux_initrd: $initrd}}' \
	>"${out_dir}/resources.json"

manifest="${script_dir}/manifest.json"
if [[ -n "${extra_kernel_args}" ]]; then
	manifest="${out_dir}/manifest-diagnostic-generated.json"
	jq \
		--arg extra_kernel_args "${extra_kernel_args}" \
		'(.guest_configs[0].image.snp_linux_direct.linux.command_line) +=
			(" " + $extra_kernel_args)' \
		"${script_dir}/manifest.json" >"${manifest}"
fi

output_name="${output_name:-kata-aci-diagnostic-1vp.bin}"
"${igvmfilegen}" manifest \
	--manifest "${manifest}" \
	--resources "${out_dir}/resources.json" \
	--output "${out_dir}/${output_name}"

echo "Built ${out_dir}/${output_name}"
