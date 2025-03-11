#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[ -n "$DEBUG" ] && set -x

SCRIPT_DIR="$(dirname $(readlink -f $0))"

# distro-specific config file
typeset -r CONFIG_SH="config.sh"

# Name of an optional distro-specific file which, if it exists, must implement the
# install_igvm_tool, build_igvm_files, and uninstall_igvm_tool functions.
typeset -r LIB_SH="igvm_lib.sh"

load_config_distro()
{
	distro_config_dir="${SCRIPT_DIR}/${DISTRO}"

	[ -d "${distro_config_dir}" ] || die "Could not find configuration directory '${distro_config_dir}'"

	if [ -e "${distro_config_dir}/${LIB_SH}" ]; then
		igvm_lib="${distro_config_dir}/${LIB_SH}"
		echo "igvm_lib.sh file found. Loading content"
		source "${igvm_lib}"
	fi

	# Source config.sh from distro, depends on root_hash based variables here
	igvm_config="${distro_config_dir}/${CONFIG_SH}"
	source "${igvm_config}"
}

DISTRO="azure-linux"
UVM_BUILD_MODE="release"
OP="build"

while getopts ":o:s:m:iu" OPTIONS; do
	case "${OPTIONS}" in
		o ) OUT_DIR=$OPTARG ;;
		s ) SVN=$OPTARG ;;
		m ) UVM_BUILD_MODE=$OPTARG ;;
		i ) OP="install" ;;
		u ) OP="uninstall" ;;
		
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

# Print igvm configuration variables
# OUT_DIR is the output directory where the image and measurement files are stored
# SVN is the SVN of the image to be built, used by build_igvm_files
# DISTRO is the distribution name, used to load the config file
# OP specifies the operation to be performed, install, uninstall or build
# UVM_BUILD_MODE specifies whether to build the igvm for debug or release images
echo "IGVM builder script"
echo "-- OUT_DIR -> $OUT_DIR"
echo "-- SVN -> $SVN"
echo "-- DISTRO -> $DISTRO"
echo "-- OP -> $OP"
echo "-- UVM_BUILD_MODE -> $UVM_BUILD_MODE"

if [ -n "$DISTRO" ]; then
	load_config_distro
else
	echo "DISTRO must be specified"
	exit 1
fi

case "$OP" in
	"install")
		install_igvm_tool
		;;
	"uninstall")
		uninstall_igvm_tool
		;;
	"build")
		build_igvm_files
		;;
esac
