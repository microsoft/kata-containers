#!/usr/bin/env bash
#
# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -x
set -e

prepare_run_file_drivers() {
	echo "chroot: Prepare NVIDIA run file drivers"
	pushd / >> /dev/null
	chmod +x "${run_file_name}"
	./"${run_file_name}" -x

	# DMFIX
	sed -i 's/\/dev\/null//g' NVIDIA-Linux-x86_64-580.95.05/kernel-open/Kbuild

	popd >> /dev/null
}

build_nvidia_drivers() {
	driver_source_files="NVIDIA-Linux-x86_64-580.95.05/kernel-open"

	echo "chroot: Build NVIDIA drivers"
	pushd "${driver_source_files}" >> /dev/null

	local certs_dir
	local kernel_version
	local ARCH
	for version in /lib/modules/*; do
		kernel_version=$(basename "${version}")
		certs_dir=/lib/modules/"${kernel_version}"/build/certs
		signing_key=${certs_dir}/signing_key.pem

	    echo "chroot: Building GPU modules for: ${kernel_version}"
		cp /boot/System.map-"${kernel_version}" /lib/modules/"${kernel_version}"/build/System.map

		ln -sf /lib/modules/"${kernel_version}"/build/arch/x86 /lib/modules/"${kernel_version}"/build/arch/amd64
		ARCH=x86_64

		echo "chroot: Building GPU modules for: ${kernel_version} ${ARCH}"

		make -j "$(nproc)" CC=gcc SYSSRC=/lib/modules/"${kernel_version}"/build > /dev/null

		if [[ -n "${KBUILD_SIGN_PIN}" ]]; then
			mkdir -p "${certs_dir}" && mv /signing_key.* "${certs_dir}"/.
			check_kernel_sig_config
		fi

		make INSTALL_MOD_STRIP=1 -j "$(nproc)" CC=gcc SYSSRC=/lib/modules/"${kernel_version}"/build modules_install
		make -j "$(nproc)" CC=gcc SYSSRC=/lib/modules/"${kernel_version}"/build clean > /dev/null
		# The make clean above should clear also the certs directory but just in case something
		# went wrong make sure the signing_key.pem is removed
		[[ -e "${signing_key}" ]] && rm -f "${signing_key}"
	done
	popd >> /dev/null
}


driver_type="-open"
run_file_name="driver.run"
prepare_run_file_drivers
build_nvidia_drivers

#wget https://developer.download.nvidia.cn/compute/cuda/redist/fabricmanager/linux-x86_64/fabricmanager-linux-x86_64-580.95.05-archive.tar.xz

