#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(git -C "${script_dir}" rev-parse --show-toplevel)"
out="$(realpath -m "${OUT_DIR:-${script_dir}/out}")"
mkdir -p "${out}"
[[ -z "${PROFILE_VCPUS:-}${PROFILE_MEMORY_MIB:-}" ]] || {
	echo "Fixed resource profiles are no longer supported; configure CPU/memory at VM launch" >&2
	exit 1
}

packages() {
	local kernel=/usr/share/kernel-uvm-cc/bzImage
	local runtime=/usr/bin/openvmm
	rpm -q kernel-uvm-cc openvmm
	rpm -V --nomode --nomtime kernel-uvm-cc openvmm
	[[ "$(rpm -qf --qf '%{NAME}' "${kernel}")" == kernel-uvm-cc ]]
	[[ "$(rpm -qf --qf '%{NAME}' "${runtime}")" == openvmm ]]
	local version
	version="$(yq -r '.assets.hypervisor.openvmm.version' "${repo}/versions.yaml")"
	[[ "$(rpm -q --qf '%{VERSION}' openvmm)" == "${version#openvmm-v}" ]] || {
		echo "Installed OpenVMM must match the tooling release ${version}" >&2
		exit 1
	}
	cp "${kernel}" "${out}/bzImage"
	cp /usr/share/kernel-uvm-cc/kernel.release "${out}/kernel.release"
	cp "${runtime}" "${out}/openvmm"
	rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
		kernel-uvm-cc openvmm > "${out}/package-versions.txt"
}

tools() {
	local source="${OPENVMM_SOURCE:?set OPENVMM_SOURCE to the OpenVMM repository}"
	local revision
	revision="$(yq -r '.assets.hypervisor.openvmm.version' "${repo}/versions.yaml")"
	revision="$(git -C "${source}" rev-parse "${revision}^{commit}")"
	if [[ ! -d "${out}/openvmm-src" ]]; then
		git -C "${source}" worktree add --detach "${out}/openvmm-src" "${revision}"
	fi
	[[ "$(git -C "${out}/openvmm-src" rev-parse HEAD)" == "${revision}" ]]
	local patches=("${script_dir}/standard-snp/igvmfilegen-launch-sizing.patch")
	if ! git -C "${out}/openvmm-src" apply --reverse --check "${patches[@]}" 2>/dev/null; then
		git -C "${out}/openvmm-src" diff --exit-code
		git -C "${out}/openvmm-src" apply --check "${patches[@]}"
		git -C "${out}/openvmm-src" apply --index "${patches[@]}"
	fi
	local expected_patch actual_patch
	expected_patch="$(cat "${patches[@]}" | git patch-id --stable | cut -d' ' -f1)"
	actual_patch="$(git -C "${out}/openvmm-src" diff HEAD | git patch-id --stable | cut -d' ' -f1)"
	[[ "${actual_patch}" == "${expected_patch}" ]] || { echo "OpenVMM build tree has additional source changes" >&2; exit 1; }
	local target="${OPENVMM_TARGET_DIR:-${out}/openvmm-target}"
	(
		cd "${out}/openvmm-src"
		export PROTOC="${PROTOC:-$(command -v protoc)}"
		CARGO_TARGET_DIR="${target}" cargo build --locked --release -p igvmfilegen
		MINIMAL_RT_BUILD=1 CARGO_TARGET_DIR="${target}" cargo build --locked --profile boot-release \
			--target x86_64-unknown-none -p snp_bootshim
	)
	cp "${target}/release/igvmfilegen" "${out}/"
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
	python3 "${script_dir}/standard-snp/manifest.py" "${out}" --svn "${IGVM_SVN:-1}"
	python3 "${script_dir}/standard-snp/manifest.py" "${out}" --svn "${IGVM_SVN:-1}" --debug
	local suffix
	for suffix in "" "-debug"; do
		"${out}/igvmfilegen" manifest --manifest "${out}/manifest${suffix}.json" \
			--resources "${out}/resources.json" --output "${out}/kata-openvmm-snp${suffix}.bin"
	done
	cp "${script_dir}/runtimeclass.yaml" "${out}/"
	(
		cd "${out}"
		sha256sum openvmm bzImage kernel.release package-versions.txt snp_bootshim kata-containers.img \
			kata-openvmm-snp.bin kata-openvmm-snp-debug.bin \
			kata-openvmm-snp-snp.json kata-openvmm-snp-debug-snp.json \
			kata-openvmm-snp-snp.cbor kata-openvmm-snp-debug-snp.cbor \
			kata-openvmm-snp-snp.idblock kata-openvmm-snp-debug-snp.idblock \
			manifest.json manifest-debug.json resources.json root_hash_.txt runtimeclass.yaml > SHA256SUMS
	)
	cat "${out}/SHA256SUMS"
}

case "${1:-all}" in
	packages) packages ;;
	tools) tools ;;
	guest-image) guest_image ;;
	igvm) igvm ;;
	all) packages; tools; guest_image; igvm ;;
	*) echo "usage: $0 {packages|tools|guest-image|igvm|all}" >&2; exit 1 ;;
esac
