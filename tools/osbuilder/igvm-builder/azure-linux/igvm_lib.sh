#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034,SC2154

install_igvm_tool()
{
	echo "Installing OpenVMM IGVM tools (igvmfilegen, snp_bootshim)"
	if [[ -x "${OPENVMM_TOOLS_DIR}/igvmfilegen" && -f "${OPENVMM_TOOLS_DIR}/snp_bootshim" ]]; then
		echo "${OPENVMM_TOOLS_DIR} already holds the tools, assuming they are installed"
		return
	fi

	local version="${OPENVMM_VERSION:-}"
	if [[ -z "${version}" ]]; then
		[[ -f "${VERSIONS_YAML}" ]] || die "Set OPENVMM_VERSION, '${VERSIONS_YAML}' not found"
		command -v yq &>/dev/null || die "yq is required to read the OpenVMM version from versions.yaml"
		version="$(yq '.assets.hypervisor.openvmm.version' "${VERSIONS_YAML}")"
		[[ -n "${version}" && "${version}" != "null" ]] || die "No OpenVMM version in '${VERSIONS_YAML}'"
	fi

	if [[ ! -d "${OPENVMM_SRC_DIR}" ]]; then
		echo "Cloning OpenVMM ${version} from ${OPENVMM_REPO}"
		git clone --depth 1 --branch "${version}" "${OPENVMM_REPO}" "${OPENVMM_SRC_DIR}"
		git -C "${OPENVMM_SRC_DIR}" apply "${OPENVMM_PATCH}"
	fi

	echo "Building igvmfilegen and snp_bootshim"
	local target_dir="${OPENVMM_SRC_DIR}/target"
	pushd "${OPENVMM_SRC_DIR}" || exit
	PROTOC="${PROTOC:-$(command -v protoc)}" CARGO_TARGET_DIR="${target_dir}" cargo build --locked --release -p igvmfilegen
	MINIMAL_RT_BUILD=1 CARGO_TARGET_DIR="${target_dir}" cargo build --locked --profile boot-release --target x86_64-unknown-none -p snp_bootshim
	popd || exit

	mkdir -p "${OPENVMM_TOOLS_DIR}"
	cp "${target_dir}/release/igvmfilegen" "${OPENVMM_TOOLS_DIR}/"
	cp "${target_dir}/x86_64-unknown-none/boot-release/snp_bootshim" "${OPENVMM_TOOLS_DIR}/"
}

uninstall_igvm_tool()
{
	echo "Uninstalling OpenVMM IGVM tools"

	rm -rf "${OPENVMM_TOOLS_DIR}" "${OPENVMM_SRC_DIR}"
}

build_igvm_files()
{
	# Prebuilt tools (e.g. from a pipeline) take precedence over the ones built by install_igvm_tool
	local igvmfilegen="${IGVMFILEGEN:-${OPENVMM_TOOLS_DIR}/igvmfilegen}"
	local snp_bootshim="${SNP_BOOTSHIM:-${OPENVMM_TOOLS_DIR}/snp_bootshim}"

	[[ -x "${igvmfilegen}" ]] || die "igvmfilegen not found at '${igvmfilegen}': run '$0 -i' or set IGVMFILEGEN"
	[[ -f "${snp_bootshim}" ]] || die "snp_bootshim not found at '${snp_bootshim}': run '$0 -i' or set SNP_BOOTSHIM"
	[[ -f "${BZIMAGE_BIN}" ]] || die "Guest kernel '${BZIMAGE_BIN}' not found: install kernel-uvm-cc or set KERNEL_UVM_CC_LOCATION"
	[[ -f "${ROOT_HASH_FILE}" ]] || die "Could not find image root hash file '${ROOT_HASH_FILE}'"

	local out_dir work_dir
	out_dir="$(readlink -f "${OUT_DIR:-.}")"
	work_dir="$(mktemp -d)"

	echo "Building (debug) IGVM files and their SNP launch measurements"
	local variant debug_flag igvm
	for variant in release debug; do
		debug_flag=()
		igvm="${IGVM_FILE_NAME}"
		if [[ "${variant}" == "debug" ]]; then
			debug_flag=("--debug")
			igvm="${IGVM_DBG_FILE_NAME}"
		fi
		python3 "${IGVM_MANIFEST_PY}" "${ROOT_HASH_FILE}" --svn "${SVN:-0}" "${debug_flag[@]}" \
			--kernel "${BZIMAGE_BIN}" --bootshim "${snp_bootshim}" \
			--manifest "${work_dir}/manifest-${variant}.json" --resources "${work_dir}/resources.json"
		# Also writes the launch measurement next to the IGVM as <name>-snp.{json,cbor,idblock}
		"${igvmfilegen}" manifest --manifest "${work_dir}/manifest-${variant}.json" \
			--resources "${work_dir}/resources.json" --output "${out_dir}/${igvm}"
	done

	rm -rf "${work_dir}"
}
