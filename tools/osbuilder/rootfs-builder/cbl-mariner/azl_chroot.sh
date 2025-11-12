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
	pushd "${driver_source_files}"

	make -j "$(nproc)" CC=gcc SYSSRC=/CBL-Mariner-Linux-Kernel && \
	make INSTALL_MOD_STRIP=1 -j "$(nproc)" CC=gcc SYSSRC=/CBL-Mariner-Linux-Kernel modules_install

	popd
}

azl_clean_up() {
	tdnf erase -y \
elfutils-libelf-devel \
openssl-devel \
build-essential \
git \
glib-devel \
openssl-devel

	tdnf clean -y all

	rm -f /driver.run
	rm -rf /NVIDIA-*
	rm -rf /CBL-Mariner*
	rm -rf /nvrc
}

setup_nvidia-nvrc() {
	mv /nvrc/target/release/NVRC /usr/bin/
}

setup_nvidia-nvrc

driver_type="-open"
run_file_name="driver.run"
prepare_run_file_drivers
build_nvidia_drivers

azl_clean_up
