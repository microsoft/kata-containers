#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(dirname "$(readlink -f "$0")")"
openvmm="${OPENVMM:-${HOME}/openvmm-snp-mshv-aci-igvm/target/release/openvmm}"
igvm="${IGVM:-${script_dir}/out/kata-aci-diagnostic-1vp.bin}"
kata_image="${KATA_IMAGE:-}"
processors="${VP_COUNT:-1}"
memory="${MEMORY:-1G}"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

[[ -x "${openvmm}" ]] || die "OpenVMM is not executable: ${openvmm}"
[[ -f "${igvm}" ]] || die "IGVM does not exist: ${igvm}"
[[ -e /dev/mshv ]] || die "/dev/mshv is not available"
[[ "${processors}" =~ ^[1-9][0-9]*$ ]] ||
	die "VP_COUNT must be a positive integer: ${processors}"

args=(
	--hypervisor mshv
	--isolation snp
	--igvm "${igvm}"
	--igvm-personality linux-direct
	--hv
	--no-vmbus
	--com1 console
	--processors "${processors}"
	--memory "${memory}"
	--pcie-root-complex
	"s0rc0,segment=0,start_bus=0,end_bus=127,low_mmio=256M,high_mmio=16G"
	--pcie-ecam-below-4gb
	--pcie-root-port
	"s0rc0:rootfs,addr=1"
)

if [[ -n "${kata_image}" ]]; then
	[[ -f "${kata_image}" ]] || die "Kata image does not exist: ${kata_image}"
	args+=(--virtio-blk "file:$(readlink -f "${kata_image}"),ro,pcie_port=rootfs")
fi

printf 'Running: sudo %q' "${openvmm}"
printf ' %q' "${args[@]}"
printf '\n'

exec sudo "${openvmm}" "${args[@]}"
