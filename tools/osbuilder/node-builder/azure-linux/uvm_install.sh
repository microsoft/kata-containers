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

UVM_PATH=${UVM_PATH:-${UVM_PATH_DEFAULT}}

pushd "${repo_dir}"

pushd tools/osbuilder

echo "Creating target directory"
mkdir -p "${UVM_PATH}"

echo "Installing UVM files to target directory"
if [ "${CONF_PODS}" == "yes" ]; then
	CONF_PODS_INSTALL_SUCCESS=false
	if [ -f "${IGVM_FILE_NAME}" ]; then
		cp -a --backup=numbered "${IGVM_FILE_NAME}" "${UVM_PATH}"
		cp -a --backup=numbered "${UVM_MEASUREMENT_FILE_NAME}" "${UVM_PATH}"
		CONF_PODS_INSTALL_SUCCESS=true
	else
		echo "release UVM files not built; skipping."
	fi

	if [ -f "${IGVM_DBG_FILE_NAME}" ]; then
		cp -a --backup=numbered "${IGVM_DBG_FILE_NAME}" "${UVM_PATH}"
		cp -a --backup=numbered "${UVM_DBG_MEASUREMENT_FILE_NAME}" "${UVM_PATH}"
		CONF_PODS_INSTALL_SUCCESS=true
	else
		echo "debug UVM files not built; skipping."
	fi

	if [ $CONF_PODS_INSTALL_SUCCESS != true ]; then
		echo "Failed to install ConfPods measurement/igvm files, no release or debug files present."
		exit 1
	fi
fi

INSTALL_SUCCESS=false
if [ -f "${IMG_FILE_NAME}" ]; then
	cp -a --backup=numbered "${IMG_FILE_NAME}" "${UVM_PATH}/${IMG_FILE_NAME}"
	INSTALL_SUCCESS=true
else
	echo "release UVM files not built; skipping."
fi

if [ -f "${IMG_DBG_FILE_NAME}" ]; then
	cp -a --backup=numbered "${IMG_DBG_FILE_NAME}" "${UVM_PATH}/${IMG_DBG_FILE_NAME}"
	INSTALL_SUCCESS=true
else
	echo "debug UVM files not built; skipping."
fi

if [ $INSTALL_SUCCESS != true ]; then
	echo "Failed to install UVM files, no release or debug files present."
	exit 1
fi

popd

popd
