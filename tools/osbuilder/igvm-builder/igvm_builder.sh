#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[ -n "$DEBUG" ] && set -x

script_dir="$(dirname $(readlink -f $0))"

# distro-specific config file
typeset -r CONFIG_SH="config.sh"

# Name of an optional distro-specific file which, if it exists, must implement the
# install_igvm() function.
typeset -r LIB_SH="igvm_lib.sh"

build_igvm_distro()
{
	distro_config_dir="${script_dir}/${distro}"

	[ -d "${distro_config_dir}" ] || die "Could not find configuration directory '${distro_config_dir}'"

	if [ -e "${distro_config_dir}/${LIB_SH}" ]; then
		igvm_lib="${distro_config_dir}/${LIB_SH}"
		echo "igvm_lib.sh file found. Loading content"
		source "${igvm_lib}"
	fi

	root_hash_file="${script_dir}/../root_hash.txt"

	if [ ! -f "${root_hash_file}" ]; then
		echo "Could no find image root hash file '${root_hash_file}', aborting"
		exit 1
	fi

	echo "Reading image dm-verity root hash values"
	root_hash=$(sed -e 's/Root hash:\s*//g;t;d' "${root_hash_file}")
	salt=$(sed -e 's/Salt:\s*//g;t;d' "${root_hash_file}")
	data_blocks=$(sed -e 's/Data blocks:\s*//g;t;d' "${root_hash_file}")
	data_block_size=$(sed -e 's/Data block size:\s*//g;t;d' "${root_hash_file}")
	data_sectors_per_block=$((data_block_size / 512))
	data_sectors=$((data_blocks * data_sectors_per_block))
	hash_block_size=$(sed -e 's/Hash block size:\s*//g;t;d' "${root_hash_file}")

	# Source config.sh from distro, depends on root_hash based variables here
	igvm_config="${distro_config_dir}/${CONFIG_SH}"
	source "${igvm_config}"

	echo "Install IGVM tool"
	install_igvm

	echo "Build IGVM (debug) file and calculate reference measurements"
	# we could call into the installed binary '~/.local/bin/igvmgen' when adding to PATH or, better, into 'python3 -m msigvm'
	# however, as we still need the installation directory for the ACPI tables, we leave things as is for now
	# at the same time we seem to need to call pip3 install for invoking the tool at all
	python3 ${igvmgen_py_file} $igvm_vars -o kata-containers-igvm.img -measurement_file igvm-measurement.cose -append "$igvm_kernel_prod_params" -svn $SVN
	python3 ${igvmgen_py_file} $igvm_vars -o kata-containers-igvm-debug.img -measurement_file igvm-debug-measurement.cose -append "$igvm_kernel_debug_params" -svn $SVN

	if [ "${PWD}" -ef "$(readlink -f $OUT_DIR)" ]; then
		echo "OUT_DIR matches with current dir, not moving build artifacts"
	else
		echo "Moving build artifacts to ${OUT_DIR}"
		mv igvm-measurement.cose kata-containers-igvm.img igvm-debug-measurement.cose kata-containers-igvm-debug.img $OUT_DIR
	fi
}

distro="azure-linux"

while getopts ":o:s:" OPTIONS; do
	case "${OPTIONS}" in
		o ) OUT_DIR=$OPTARG ;;
		s ) SVN=$OPTARG ;;
		\? )
			echo "Error - Invalid Option: -$OPTARG" 1>&2
			exit 1
			;;
		: )
			echo "Error - Invalid Option: -$OPTARG requires an argument" 1>&2
			exit 1
			;;
  esac
done

echo "IGVM builder script"
echo "-- OUT_DIR -> $OUT_DIR"
echo "-- SVN -> $SVN"
echo "-- distro -> $distro"

if [ -n "$distro" ]; then
  build_igvm_distro
else
  echo "distro must be specified"
  exit 1
fi
