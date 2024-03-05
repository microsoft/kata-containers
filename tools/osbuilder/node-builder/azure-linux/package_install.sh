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

script_dir="$(dirname $(readlink -f $0))"
repo_dir="${script_dir}/../../../../"

common_file="common.sh"
source "${common_file}"

pushd "${repo_dir}"

echo "Creating target directories"
mkdir -p "${SHIM_CONFIG_PATH}"
mkdir -p "${DEBUGGING_BINARIES_PATH}"
mkdir -p "${SHIM_BINARIES_PATH}"

if [ "${CONF_PODS}" == "yes" ]; then
	echo "Installing tardev-snapshotter binaries and service file"
	cp -a --backup=numbered src/utarfs/target/release/utarfs /usr/sbin/mount.tar
	cp -a --backup=numbered src/overlay/target/release/kata-overlay /usr/bin/
	cp -a --backup=numbered src/tardev-snapshotter/target/release/tardev-snapshotter /usr/bin/
	cp -a --backup=numbered src/tardev-snapshotter/tardev-snapshotter.service /usr/lib/systemd/system/

	echo "Installing SNP shim debug configuration"
	cp -a --backup=numbered src/runtime/config/"${SHIM_DBG_CONFIG_FILE_NAME}" "${SHIM_CONFIG_PATH}"

	echo "Enabling and starting snapshotter service"
	systemctl enable tardev-snapshotter && systemctl daemon-reload && systemctl restart tardev-snapshotter
fi

echo "Installing diagnosability binaries (monitor, runtime, collect-data script)"
cp -a --backup=numbered src/runtime/kata-monitor "${DEBUGGING_BINARIES_PATH}"
cp -a --backup=numbered src/runtime/kata-runtime "${DEBUGGING_BINARIES_PATH}"
chmod +x src/runtime/data/kata-collect-data.sh
cp -a --backup=numbered src/runtime/data/kata-collect-data.sh "${DEBUGGING_BINARIES_PATH}"

echo "Installing shim binary and configuration"
cp -a --backup=numbered src/runtime/containerd-shim-kata-v2 "${SHIM_BINARIES_PATH}"/"${SHIM_BINARY_NAME}"

cp -a --backup=numbered src/runtime/config/"${SHIM_CONFIG_FILE_NAME}" "${SHIM_CONFIG_PATH}"

popd
