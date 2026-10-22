#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034,SC2154

install_igvm_tool()
{
	echo "Installing IGVM tools (igvmfilegen, snp_bootshim)"
	if [[ -x "${IGVM_TOOLS_DIR}/igvmfilegen" && -f "${IGVM_TOOLS_DIR}/snp_bootshim" ]]; then
		echo "${IGVM_TOOLS_DIR} already holds the tools, assuming they are installed"
		return
	fi

	if [[ ! -d "${IGVM_TOOLS_SRC_DIR}" ]]; then
		echo "Fetching ${IGVM_TOOLS_REPO} at ${IGVM_TOOLS_REF}"
		git init -q "${IGVM_TOOLS_SRC_DIR}"
		git -C "${IGVM_TOOLS_SRC_DIR}" fetch -q --depth 1 "${IGVM_TOOLS_REPO}" "${IGVM_TOOLS_REF}"
		git -C "${IGVM_TOOLS_SRC_DIR}" checkout -q --detach FETCH_HEAD
	fi

	echo "Building igvmfilegen and snp_bootshim"
	local target_dir="${IGVM_TOOLS_SRC_DIR}/target"
	pushd "${IGVM_TOOLS_SRC_DIR}" || exit
	PROTOC="${PROTOC:-$(command -v protoc)}" OPENSSL_NO_VENDOR=Y CARGO_TARGET_DIR="${target_dir}" cargo build --locked --release -p igvmfilegen
	MINIMAL_RT_BUILD=1 CARGO_TARGET_DIR="${target_dir}" cargo build --locked --profile boot-release --target x86_64-unknown-none -p snp_bootshim
	popd || exit

	mkdir -p "${IGVM_TOOLS_DIR}"
	cp "${target_dir}/release/igvmfilegen" "${IGVM_TOOLS_DIR}/"
	cp "${target_dir}/x86_64-unknown-none/boot-release/snp_bootshim" "${IGVM_TOOLS_DIR}/"
}

uninstall_igvm_tool()
{
	echo "Uninstalling IGVM tools"

	rm -rf "${IGVM_TOOLS_DIR}" "${IGVM_TOOLS_SRC_DIR}"
}

build_igvm_files()
{
	# Prebuilt tools (e.g. from a pipeline) take precedence over the ones built by install_igvm_tool
	local igvmfilegen="${IGVMFILEGEN:-${IGVM_TOOLS_DIR}/igvmfilegen}"
	local snp_bootshim="${SNP_BOOTSHIM:-${IGVM_TOOLS_DIR}/snp_bootshim}"

	[[ -x "${igvmfilegen}" ]] || die "igvmfilegen not found at '${igvmfilegen}': run '$0 -i' or set IGVMFILEGEN"
	[[ -f "${snp_bootshim}" ]] || die "snp_bootshim not found at '${snp_bootshim}': run '$0 -i' or set SNP_BOOTSHIM"
	[[ -f "${BZIMAGE_BIN}" ]] || die "Guest kernel '${BZIMAGE_BIN}' not found: install kernel-uvm"
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
		# Match the legacy generator's ephemeral ID-key behavior. This binds the
		# launch identity/SVN, but is not a trusted publisher endorsement.
		"${igvmfilegen}" add-snp-id-block --input "${out_dir}/${igvm}" \
			--output "${out_dir}/${igvm}" --manifest "${work_dir}/manifest-${variant}.json"
	done

	rm -rf "${work_dir}"
}
