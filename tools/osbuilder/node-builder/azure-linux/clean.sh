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
repo_dir="${script_dir}/../../../../"

common_file="common.sh"
source "${common_file}"

agent_install_dir="${script_dir}/agent-install"

pushd "${repo_dir}"

echo "Clean runtime build"
pushd src/runtime/
make clean SKIP_GO_VERSION_CHECK=1
popd

echo "Clean agent build"
pushd src/agent/
make clean
popd

rm -rf ${agent_install_dir}

echo "Clean UVM build"
pushd tools/osbuilder/
sudo -E PATH=$PATH make DISTRO=cbl-mariner clean
popd

if [ "${CONF_PODS}" == "yes" ]; then

	echo "Clean SNP debug shim config"
	pushd src/runtime/config/
	rm -f "${SHIM_DBG_CONFIG_FILE_NAME}"
	popd

	echo "Clean tardev-snapshotter tarfs driver build"
	pushd src/tarfs
	set_uvm_kernel_vars
	if [ -n "${UVM_KERNEL_HEADER_DIR}" ]; then
		make clean KDIR=${UVM_KERNEL_HEADER_DIR}
	fi
	popd

	echo "Clean utarfs binary build"
	pushd src/utarfs/
	make clean
	popd

	echo "Clean tardev-snapshotter overlay binary build"
	pushd src/overlay/
	make clean
	popd

	echo "Clean tardev-snapshotter service build"
	pushd src/tardev-snapshotter/
	make clean
	popd
fi

popd
