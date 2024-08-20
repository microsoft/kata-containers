#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[ -n "$DEBUG" ] && set -x

CONF_PODS=${CONF_PODS:-no}
PREFIX=${PREFIX:-}
START_SERVICES=${START_SERVICES:-yes}

script_dir="$(dirname $(readlink -f $0))"
repo_dir="${script_dir}/../../../../"

common_file="common.sh"
source "${common_file}"

pushd "${repo_dir}"

echo "Creating target directories"
mkdir -p "${PREFIX}/${SHIM_CONFIG_PATH}"
mkdir -p "${PREFIX}/${DEBUGGING_BINARIES_PATH}"
mkdir -p "${PREFIX}/${SHIM_BINARIES_PATH}"

if [ "${CONF_PODS}" == "yes" ]; then
	echo "Installing tardev-snapshotter binaries and service file"
	mkdir -p ${PREFIX}/usr/sbin
	cp -a --backup=numbered src/utarfs/target/release/utarfs ${PREFIX}/usr/sbin/mount.tar
	mkdir -p ${PREFIX}/usr/bin
	cp -a --backup=numbered src/overlay/target/release/kata-overlay ${PREFIX}/usr/bin/
	cp -a --backup=numbered src/tardev-snapshotter/target/release/tardev-snapshotter ${PREFIX}/usr/bin/
	mkdir -p ${PREFIX}/usr/lib/systemd/system/
	cp -a --backup=numbered src/tardev-snapshotter/tardev-snapshotter.service ${PREFIX}/usr/lib/systemd/system/

	echo "Installing SNP shim debug configuration"
	cp -a --backup=numbered src/runtime/config/"${SHIM_DBG_CONFIG_FILE_NAME}" "${PREFIX}/${SHIM_CONFIG_PATH}"/"${SHIM_DBG_CONFIG_INST_FILE_NAME}"

	echo "Enabling and starting snapshotter service"
	if [ "${START_SERVICES}" == "yes" ]; then
		systemctl enable tardev-snapshotter && systemctl daemon-reload && systemctl restart tardev-snapshotter
	fi
fi

echo "Installing diagnosability binaries (monitor, runtime, collect-data script)"
cp -a --backup=numbered src/runtime/kata-monitor "${PREFIX}/${DEBUGGING_BINARIES_PATH}"
cp -a --backup=numbered src/runtime/kata-runtime "${PREFIX}/${DEBUGGING_BINARIES_PATH}"
chmod +x src/runtime/data/kata-collect-data.sh
cp -a --backup=numbered src/runtime/data/kata-collect-data.sh "${PREFIX}/${DEBUGGING_BINARIES_PATH}"

echo "Installing shim binary and configuration"
cp -a --backup=numbered src/runtime/containerd-shim-kata-v2 "${PREFIX}/${SHIM_BINARIES_PATH}"/"${SHIM_BINARY_NAME}"

cp -a --backup=numbered src/runtime/config/"${SHIM_CONFIG_FILE_NAME}" "${PREFIX}/${SHIM_CONFIG_PATH}/${SHIM_CONFIG_INST_FILE_NAME}"

popd
