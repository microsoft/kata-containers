#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034,SC2154

install_igvm_tool()
{
	die "igvmfilegen and snp_bootshim are not installed by this script: set IGVMFILEGEN and SNP_BOOTSHIM"
}

uninstall_igvm_tool()
{
	:
}

build_igvm_files()
{
	# Both must come from the same kata-cc-igvm-tools build
	local igvmfilegen="${IGVMFILEGEN:-}"
	local snp_bootshim="${SNP_BOOTSHIM:-}"

	[[ -x "${igvmfilegen}" ]] || die "igvmfilegen not found at '${igvmfilegen}': set IGVMFILEGEN"
	[[ -f "${snp_bootshim}" ]] || die "snp_bootshim not found at '${snp_bootshim}': set SNP_BOOTSHIM"
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
