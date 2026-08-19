#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2034,SC2154

install_igvm_tool()
{
	echo "Installing IGVM tool"
	if [[ ! -d "${IGVM_EXTRACT_FOLDER}" ]]; then
		# the igvm tool on Azure Linux will soon be properly installed through dnf via kata-packages-uvm-build
		# as of now, even when installing with pip3, we cannot delete the source folder as the ACPI tables are not being installed anywhere, hence relying on this folder
		echo "Determining and downloading latest IGVM tooling release, and extracting including ACPI tables"
		IGVM_VER=$(curl -sL "https://api.github.com/repos/microsoft/igvm-tooling/releases/latest" | jq -r .tag_name | sed 's/^v//')
		curl -sL "https://github.com/microsoft/igvm-tooling/archive/refs/tags/${IGVM_VER}.tar.gz" | tar --no-same-owner -xz
		mv "igvm-tooling-${IGVM_VER}" "${IGVM_EXTRACT_FOLDER}"
	else
		echo "Using existing IGVM tooling source from ${IGVM_EXTRACT_FOLDER}"
	fi

	local patch_file="${distro_config_dir}/igvm-tooling-cpuid.patch"
	if patch --batch --forward --dry-run -d "${IGVM_EXTRACT_FOLDER}" -p1 < "${patch_file}"; then
		patch --batch --forward -d "${IGVM_EXTRACT_FOLDER}" -p1 < "${patch_file}"
	elif ! patch --batch --reverse --dry-run -d "${IGVM_EXTRACT_FOLDER}" -p1 < "${patch_file}"; then
		echo "IGVM tooling CPUID patch is incompatible"
		return 1
	fi

	echo "Installing IGVM module msigvm via pip3"
	pushd "${IGVM_EXTRACT_FOLDER}/src" || exit
	pip3 install --no-deps ./
	popd || exit
}

uninstall_igvm_tool()
{
	echo "Uninstalling IGVM tool"

	rm -rf "${IGVM_EXTRACT_FOLDER}"
	pip3 uninstall -y msigvm
}

build_igvm_files()
{
	if [[ ! -r "${BZIMAGE_BIN}" ]]; then
		echo "Could not read IGVM kernel '${BZIMAGE_BIN}', aborting"
		exit 1
	fi

	echo "Using IGVM kernel: ${BZIMAGE_BIN}"
	ROOT_HASH_FILE="${SCRIPT_DIR}/../root_hash_${BUILD_VARIANT:-}.txt"
	echo "Reading Kata image dm-verity information from ${ROOT_HASH_FILE}"

	if [[ ! -f "${ROOT_HASH_FILE}" ]]; then
		echo "Could not find image root hash file '${ROOT_HASH_FILE}', aborting"
		exit 1
	fi

	local -A verity_params
	while IFS='=' read -r name value; do
		verity_params["${name}"]="${value}"
	done < <(tr ',' '\n' < "${ROOT_HASH_FILE}")

	IMAGE_ROOT_HASH="${verity_params[root_hash]:-}"
	IMAGE_SALT="${verity_params[salt]:-}"
	IMAGE_DATA_BLOCKS="${verity_params[data_blocks]:-}"
	IMAGE_DATA_BLOCK_SIZE="${verity_params[data_block_size]:-}"
	IMAGE_HASH_BLOCK_SIZE="${verity_params[hash_block_size]:-}"

	if [[ -z "${IMAGE_ROOT_HASH}" || -z "${IMAGE_SALT}" || -z "${IMAGE_DATA_BLOCKS}" ||
		-z "${IMAGE_DATA_BLOCK_SIZE}" || -z "${IMAGE_HASH_BLOCK_SIZE}" ]]; then
		echo "Invalid dm-verity parameters in '${ROOT_HASH_FILE}', aborting"
		exit 1
	fi

	IMAGE_DATA_SECTORS_PER_BLOCK=$((IMAGE_DATA_BLOCK_SIZE / 512))
	IMAGE_DATA_SECTORS=$((IMAGE_DATA_BLOCKS * IMAGE_DATA_SECTORS_PER_BLOCK))

	# reloading the config file as various variables depend on above values
	load_config_distro

	echo "Building (debug) IGVM files and creating their reference measurement files"
	# we could call into the installed binary '~/.local/bin/igvmgen' when adding to PATH or, better, into 'python3 -m msigvm'
	# however, as we still need the installation directory for the ACPI tables, we leave things as is for now
	# at the same time we seem to need to call pip3 install for invoking the tool at all
	python3 "${IGVM_PY_FILE}" "${IGVM_BUILD_VARS[@]}" -o "${IGVM_FILE_NAME}" -measurement_file "${IGVM_MEASUREMENT_FILE_NAME}" -append "${IGVM_KERNEL_PROD_PARAMS}" -svn "${SVN}"
	python3 "${IGVM_PY_FILE}" "${IGVM_BUILD_VARS[@]}" -o "${IGVM_DBG_FILE_NAME}" -measurement_file "${IGVM_DBG_MEASUREMENT_FILE_NAME}" -append "${IGVM_KERNEL_DEBUG_PARAMS}" -svn "${SVN}"

	out_dir="${OUT_DIR:-.}"
	if [[ "${PWD}" -ef "$(readlink -f "${out_dir}")" ]]; then
		echo "OUT_DIR matches with current dir, not moving build artifacts"
	else
		echo "Moving build artifacts to ${out_dir}"
		mv "${IGVM_FILE_NAME}" "${IGVM_DBG_FILE_NAME}" "${IGVM_MEASUREMENT_FILE_NAME}" "${IGVM_DBG_MEASUREMENT_FILE_NAME}" "${out_dir}"
	fi
}
