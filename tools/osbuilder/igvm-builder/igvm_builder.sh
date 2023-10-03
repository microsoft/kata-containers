#!/usr/bin/env bash
#
# Copyright (c) 2023 Microsoft Corp.
#
# SPDX-License-Identifier: Apache-2.0

# ./igvm_builder.sh -k /usr/share/cloud-hypervisor-cvm/bzImage -v /work_dir/kata-containers/tools/osbuilder/root_hash.txt -o igvm.img
der/root_hash.txt -d -o igvm.img

[ -z "${DEBUG}" ] || set -x

set -o errexit
# set -o nounset
set -o pipefail

script_name="${0##*/}"
script_dir="$(dirname $(readlink -f $0))"

lib_file="${script_dir}/../scripts/lib.sh"
source "$lib_file"

# IGVM_IMAGE="${IGVM_IMAGE:-kata-containers-igvm.img}"
# KERNEL_BIN=${KERNEL_BIN:-bzImage}

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
	   DEFAULT: the path stored in the environment variable IGVM_IMAGE

Extra environment variables:
	KERNEL_BIN:  use it to change the expected agent kernel name
		    DEFAULT: bzImage
	AGENT_INIT: use kata agent as init process
		    DEFAULT: no
EOF
exit "${error}"
}

while getopts "ho:di:v:k:" opt
do
	case "$opt" in
		h)	usage ;;
		o)	IGVM_IMAGE="${OPTARG}" ;;
		d)	DEBUG="${OPTARG}" ;;
		i)	INITRD_FILE="${OPTARG}" ;;
		v)	DM_VERITY_FILE="${OPTARG}" ;;
		k)	KERNEL_BIN="${OPTARG}" ;;
	esac
done

shift $(( $OPTIND - 1 ))


# [ -d "${ROOTFS}" ] || die "${ROOTFS} is not a directory"

# IMAGE_DIR=$(dirname ${IGVM_IMAGE})
# IMAGE_DIR=$(readlink -f ${IMAGE_DIR})
# IMAGE_NAME=$(basename ${IGVM_IMAGE})

# download and install igvm tool, if not already present
readonly igvm_dir="$(mktemp -d)"
pushd $igvm_dir

wget https://kataccstorage.blob.core.windows.net/aks-rpms/msigvm-1.2.0.tar.gz
(echo "76dd03153121cc6cc4374ca76fb4e5602adccd7ac286f4fb41e6f20a66dec7c0  msigvm-1.2.0.tar.gz" | sha256sum --check) || exit 1
tar --no-same-owner -xf msigvm-1.2.0.tar.gz
mv msigvm*/* .

# set image config options
if [ -n "${DM_VERITY_FILE}" ] ; then
	if [ ! -f "${DM_VERITY_FILE}" ] ; then
		popd
		rm -rf "${igvm_dir}"
		die "${DM_VERITY_FILE} is not a file"
	fi

	info "Parsing dm-verity info based on file ${DM_VERITY_FILE}"
	root_hash=$(sudo sed -e 's/Root hash:\s*//g;t;d' "${DM_VERITY_FILE}")
	salt=$(sudo sed -e 's/Salt:\s*//g;t;d' "${DM_VERITY_FILE}")
	data_blocks=$(sudo sed -e 's/Data blocks:\s*//g;t;d' "${DM_VERITY_FILE}")
	data_block_size=$(sudo sed -e 's/Data block size:\s*//g;t;d' "${DM_VERITY_FILE}")
	data_sectors_per_block=$((data_block_size / 512))
	data_sectors=$((data_blocks * data_sectors_per_block))
	hash_block_size=$(sudo sed -e 's/Hash block size:\s*//g;t;d' "${DM_VERITY_FILE}")

	igvm_params="dm-mod.create=\"dm-verity,,,ro,0 ${data_sectors} verity 1 /dev/vda1 /dev/vda2 ${data_block_size} ${hash_block_size} ${data_blocks} 0 sha256 ${root_hash} ${salt}\" root=/dev/dm-0"

elif [ -n "${INITRD_FILE}" ] ; then
	if [ ! -f "${INITRD_FILE}" ] ; then
		popd
		rm -rf "${igvm_dir}"
		die "${INITRD_FILE} is not a file"
	fi 

	igvm_params="root=/dev/vda1"
fi

igvm_vars="-kernel ${KERNEL_BIN} -boot_mode x64 -vtl 0 -svme 1 -encrypted_page 1 -pvalidate_opt 1 -acpi igvm/acpi/acpi-clh/"
igvm_params+=" rootflags=data=ordered,errors=remount-ro ro rootfstype=ext4 panic=1 no_timer_check noreplace-smp systemd.unit=kata-containers.target systemd.mask=systemd-networkd.service \
  systemd.mask=systemd-networkd.socket agent.enable_signature_verification=false"

if [ -z "${DEBUG}" ] ; then
	info "Applying debug options"
	igvm_params+=" console=hvc0 systemd.log_target=console agent.log=debug agent.debug_console agent.debug_console_vport=1026"
else
	igvm_params+=" quiet"
fi


igvm_cmd="python3 ${igvm_vars} -o ${IGVM_IMAGE} -measurement_file igvm-measurement.cose -append "${igvm_params}" -svn 0"
info "Building IGVM image: ${igvm_cmd}"
python3 igvm/igvmgen.py ${igvm_vars} -o ${IGVM_IMAGE} -measurement_file igvm-measurement.cose -append "${igvm_params}" -svn 0

mv ${IGVM_IMAGE} ${script_dir}

popd
rm -rf "${igvm_dir}"
