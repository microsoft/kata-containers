#!/usr/bin/env bash
#
# Copyright (c) 2023 Microsoft Corp.
#
# SPDX-License-Identifier: Apache-2.0

# ./igvm_builder.sh -k /usr/share/cloud-hypervisor-cvm/bzImage -v /work_dir/kata-containers/tools/osbuilder/root_hash.txt -o igvm.img

set -o errexit
set -o pipefail

readonly script_name="${0##*/}"
readonly script_dir="$(dirname $(readlink -f $0))"
readonly lib_file="${script_dir}/../scripts/lib.sh"
source "$lib_file"

usage()
{
	error="${1:-0}"
	cat <<EOF
Usage: ${script_name} [options] <rootfs-dir>
	This script creates a Kata Containers IGVM image file based on the
	<rootfs-dir> directory.

Options:
	-h Show help
	-o Set the path where the generated image file is stored.
	   DEFAULT: the path stored in the environment variable igvm_name

Extra environment variables:
	kernel_bin:  use it to change the expected agent kernel name
		    DEFAULT: bzImage
	AGENT_INIT: use kata agent as init process
		    DEFAULT: no
EOF
exit "${error}"
}

set_igvm_opts() {
	echo "dallas *** checking var dm_verity_file ${dm_verity_file}"
	echo "dallas *** checking var 1 ${1}"
	# set_igvm_opts "${dm_verity_file}" "${initrd_bin}"

	# initialize igvm options
	igvm_vars="-kernel ${kernel_bin} -boot_mode x64 -vtl 0 -svme 1 -encrypted_page 1 -pvalidate_opt 1 -acpi igvm/acpi/acpi-clh/"

	# set config options for dm-verity and initrd based images
	if [ -n "${dm_verity_file}" ] ; then
		if [ ! -f "${dm_verity_file}" ] ; then
			popd
			rm -rf "${igvm_dir}"
			die "${dm_verity_file} is not a file"
		fi

		info "Setting options for dm-verity image based on ${dm_verity_file}"
		root_hash=$(sudo sed -e 's/Root hash:\s*//g;t;d' "${dm_verity_file}")
		salt=$(sudo sed -e 's/Salt:\s*//g;t;d' "${dm_verity_file}")
		data_blocks=$(sudo sed -e 's/Data blocks:\s*//g;t;d' "${dm_verity_file}")
		data_block_size=$(sudo sed -e 's/Data block size:\s*//g;t;d' "${dm_verity_file}")
		data_sectors_per_block=$((data_block_size / 512))
		data_sectors=$((data_blocks * data_sectors_per_block))
		hash_block_size=$(sudo sed -e 's/Hash block size:\s*//g;t;d' "${dm_verity_file}")

		igvm_params="dm-mod.create=\"dm-verity,,,ro,0 ${data_sectors} verity 1 /dev/vda1 /dev/vda2 ${data_block_size} ${hash_block_size} ${data_blocks} 0 sha256 ${root_hash} ${salt}\" root=/dev/dm-0"

	elif [ -n "${initrd_bin}" ] ; then
		if [ ! -f "${initrd_bin}" ] ; then
			popd
			rm -rf "${igvm_dir}"
			die "${initrd_bin} is not a file"
		fi 

		info "Setting options for initrd image based on ${initrd_bin}"
		igvm_vars+=" -rdinit ${initrd_bin}"
		igvm_params="root=/dev/vda1"
	fi

	igvm_params+=" rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 panic=1 no_timer_check noreplace-smp systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service \
	systemd.mask=systemd-networkd.socket agent.enable_signature_verification=false"

	if "${debug_image}" ; then
		info "Applying debug options"
		igvm_params+=" console=hvc0 systemd.log_target=console agent.log=debug agent.debug_console agent.debug_console_vport=1026"
	else
		igvm_params+=" quiet"  
	fi
}

build_image() {
	
	igvm_cmd="python3 ${igvm_vars} -o ${igvm_name} -measurement_file igvm-measurement.cose -append "${igvm_params}" -svn 0"
	info "Building IGVM image: ${igvm_cmd}"
	python3 igvm/igvmgen.py ${igvm_vars} -o ${igvm_name} -measurement_file igvm-measurement.cose -append "${igvm_params}" -svn 0

}


main() {
	debug_image=false
	while getopts "ho:di:v:k:" opt

	do
		case "$opt" in
			h)	usage ;;
			o)	igvm_name="${OPTARG}" ;;
			d)	debug_image=true ;;
			i)	initrd_bin="${OPTARG}" ;;
			v)	dm_verity_file="${OPTARG}" ;;
			k)	kernel_bin="${OPTARG}" ;;
			*) break ;;
		esac
	done

	shift $(( $OPTIND - 1 ))


	# download and install igvm tool, if not already present
	readonly igvm_dir="${script_dir}/msigvm-1.2.0"
	if [ ! -d "$igvm_dir" ] ; then
		info "cloning igvm tool"
		wget https://kataccstorage.blob.core.windows.net/aks-rpms/msigvm-1.2.0.tar.gz
		(echo "76dd03153121cc6cc4374ca76fb4e5602adccd7ac286f4fb41e6f20a66dec7c0  msigvm-1.2.0.tar.gz" | sha256sum --check) || exit 1
		tar --no-same-owner -xf msigvm-1.2.0.tar.gz
		rm msigvm-1.2.0.tar.gz
	fi
	pushd $igvm_dir

	set_igvm_opts "${dm_verity_file}" "${initrd_bin}"

	build_image
	mv ${igvm_name} ${script_dir}
	
	popd
}

main "$@"

