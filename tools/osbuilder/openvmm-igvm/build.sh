#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(git -C "${script_dir}" rev-parse --show-toplevel)"
out="$(realpath -m "${OUT_DIR:-${script_dir}/out}")"
mkdir -p "${out}"
vcpus="${PROFILE_VCPUS:-1}"
memory="${PROFILE_MEMORY_MIB:-1024}"
[[ "${vcpus}" =~ ^[1-9][0-9]*$ && "${vcpus}" -le 8 ]] || { echo "PROFILE_VCPUS must be 1..8" >&2; exit 1; }
[[ "${memory}" =~ ^[1-9][0-9]*$ && "${memory}" -ge 64 && "${memory}" -le 3072 ]] || { echo "PROFILE_MEMORY_MIB must be 64..3072" >&2; exit 1; }

kernel() {
	local source="${KERNEL_SOURCE:?set KERNEL_SOURCE to the guest kernel repository}"
	local revision=a155739c182a97c11746002df305b9f91a0c0c42
	if [[ ! -d "${out}/linux" ]]; then
		git -C "${source}" worktree add --detach "${out}/linux" "${revision}"
	fi
	[[ "$(git -C "${out}/linux" rev-parse HEAD)" == "${revision}" ]]
	git -C "${out}/linux" diff --exit-code
	mkdir -p "${out}/kernel"
	cp "${script_dir}/standard-snp/kernel.config" "${out}/kernel/.config"
	make -C "${out}/linux" O="${out}/kernel" EXTRAVERSION=-mshv1 LOCALVERSION= olddefconfig
	make -C "${out}/linux" O="${out}/kernel" EXTRAVERSION=-mshv1 LOCALVERSION= -j"${JOBS:-8}" bzImage
	cp "${out}/kernel/arch/x86/boot/bzImage" "${out}/bzImage"
}

openvmm() {
	local source="${OPENVMM_SOURCE:?set OPENVMM_SOURCE to the OpenVMM repository}"
	local revision
	revision="$(yq -r '.assets.hypervisor.openvmm.version' "${repo}/versions.yaml")"
	revision="$(git -C "${source}" rev-parse "${revision}^{commit}")"
	if [[ ! -d "${out}/openvmm-src" ]]; then
		git -C "${source}" worktree add --detach "${out}/openvmm-src" "${revision}"
	fi
	[[ "$(git -C "${out}/openvmm-src" rev-parse HEAD)" == "${revision}" ]]
	local patches=(
		"${script_dir}/standard-snp/0001-vmservice-use-low-ECAM-for-isolated-guests.patch"
		"${script_dir}/standard-snp/igvmfilegen-pci-platform.patch"
	)
	if ! git -C "${out}/openvmm-src" apply --reverse --check "${patches[@]}" 2>/dev/null; then
		git -C "${out}/openvmm-src" diff --exit-code
		git -C "${out}/openvmm-src" apply --check "${patches[@]}"
		git -C "${out}/openvmm-src" apply "${patches[@]}"
	fi
	local expected_patch actual_patch
	expected_patch="$(cat "${patches[@]}" | git patch-id --stable | cut -d' ' -f1)"
	actual_patch="$(git -C "${out}/openvmm-src" diff HEAD | git patch-id --stable | cut -d' ' -f1)"
	[[ "${actual_patch}" == "${expected_patch}" ]] || { echo "OpenVMM build tree has additional source changes" >&2; exit 1; }
	local target="${OPENVMM_TARGET_DIR:-${out}/openvmm-target}"
	(
		cd "${out}/openvmm-src"
		export PROTOC="${PROTOC:-$(command -v protoc)}"
		CARGO_TARGET_DIR="${target}" cargo build --locked --release -p openvmm -p igvmfilegen
		MINIMAL_RT_BUILD=1 CARGO_TARGET_DIR="${target}" cargo build --locked --profile boot-release \
			--target x86_64-unknown-none -p snp_bootshim
	)
	cp "${target}/release/openvmm" "${target}/release/igvmfilegen" "${out}/"
	cp "${target}/x86_64-unknown-none/boot-release/snp_bootshim" "${out}/"
}

guest_image() {
	[[ ! -e "${out}/cbl-mariner_rootfs" ]] || { echo "Use a fresh OUT_DIR for guest-image" >&2; exit 1; }
	make -C "${repo}/src/agent" BUILD_TYPE=release LIBC=gnu AGENT_POLICY=yes \
		SECCOMP=yes USE_DEVMAPPER=yes kata-agent kata-agent.service kata-containers.target
	local agent="${AGENT_BINARY:-${CARGO_TARGET_DIR:-${repo}/target}/x86_64-unknown-linux-gnu/release/kata-agent}"
	sudo env PATH="${PATH}" make -C "${repo}/tools/osbuilder" \
		USE_DOCKER= USE_PODMAN= DISTRO=cbl-mariner ROOTFS_BUILD_DEST="${out}" \
		AGENT_SOURCE_BIN="${agent}" AGENT_POLICY=yes CONFIDENTIAL_GUEST=yes \
		AGENT_POLICY_FILE="${AGENT_POLICY_FILE:-${repo}/src/kata-opa/allow-set-policy.rego}" rootfs
	sudo install -m644 "${repo}/src/agent/kata-agent.service" "${repo}/src/agent/kata-containers.target" \
		"${out}/cbl-mariner_rootfs/usr/lib/systemd/system/"
	sudo mkdir -p "${out}/cbl-mariner_rootfs/etc/systemd/system/kata-containers.target.wants"
	sudo ln -sf /usr/lib/systemd/system/kata-agent.service \
		"${out}/cbl-mariner_rootfs/etc/systemd/system/kata-containers.target.wants/kata-agent.service"
	sudo env PATH="${PATH}" make -C "${repo}/tools/osbuilder" \
		USE_DOCKER= USE_PODMAN= DISTRO=cbl-mariner ROOTFS_BUILD_DEST="${out}" \
		IMAGES_BUILD_DEST="${out}" MEASURED_ROOTFS=yes DM_VERITY_FORMAT=kernelinit \
		IMAGE_SIZE_ALIGNMENT_MB=2 image
}

igvm() {
	python3 "${script_dir}/standard-snp/manifest.py" "${out}" "${vcpus}" "${memory}" --svn "${IGVM_SVN:-1}"
	python3 "${script_dir}/standard-snp/manifest.py" "${out}" "${vcpus}" "${memory}" --svn "${IGVM_SVN:-1}" --debug
	local suffix
	for suffix in "" "-debug"; do
		"${out}/igvmfilegen" manifest --manifest "${out}/manifest${suffix}.json" \
			--resources "${out}/resources.json" --output "${out}/kata-openvmm-snp${suffix}.bin"
	done
	(
		cd "${out}"
		sha256sum openvmm bzImage snp_bootshim kata-containers.img \
			kata-openvmm-snp.bin kata-openvmm-snp-debug.bin \
			kata-openvmm-snp-snp.json kata-openvmm-snp-debug-snp.json \
			kata-openvmm-snp-snp.cbor kata-openvmm-snp-debug-snp.cbor \
			kata-openvmm-snp-snp.idblock kata-openvmm-snp-debug-snp.idblock \
			manifest.json manifest-debug.json resources.json root_hash_.txt > SHA256SUMS
	)
	cat "${out}/SHA256SUMS"
}

case "${1:-all}" in
	kernel) kernel ;;
	openvmm) openvmm ;;
	guest-image) guest_image ;;
	igvm) igvm ;;
	all) kernel; openvmm; guest_image; igvm ;;
	*) echo "usage: $0 {kernel|openvmm|guest-image|igvm|all}" >&2; exit 1 ;;
esac
