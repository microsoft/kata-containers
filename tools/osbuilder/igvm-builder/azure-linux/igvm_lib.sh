#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

install_igvm()
{
	if [ -d ${igvm_extract_folder} ]; then
		echo "${igvm_extract_folder} folder already exists, assuming tool is already installed"
		return
	fi

	# the igvm tool on Azure Linux will soon be properly installed through dnf via kata-packages-uvm-build
	# as of now, even when installing with pip3, we cannot delete the source folder as the ACPI tables are not being installed anywhere, hence relying on this folder
	echo "Determining and downloading latest IGVM tooling release, and extracting including ACPI tables"
	IGVM_VER=$(curl -sL "https://api.github.com/repos/microsoft/igvm-tooling/releases/latest" | jq -r .tag_name | sed 's/^v//')
	curl -sL "https://github.com/microsoft/igvm-tooling/archive/refs/tags/${IGVM_VER}.tar.gz" | tar --no-same-owner -xz
	mv igvm-tooling-${IGVM_VER} ${igvm_extract_folder}

	echo "Installing IGVM module msigvm via pip3"
	pushd ${igvm_extract_folder}/src
	pip3 install --no-deps ./
	popd
}
