#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[[ -n "${DEBUG:-}" ]] && set -x

script_dir="$(dirname "$(readlink -f "$0")")"
repo_dir="${script_dir}/../../../../"

common_file="${script_dir}/common.sh"
# shellcheck source=tools/osbuilder/node-builder/azure-linux/common.sh
source "${common_file}"

pushd "${repo_dir}" || exit

echo "Clean debug shim config"
pushd src/runtime/config/ || exit
rm -f "${SHIM_DBG_CONFIG_FILE_NAME}"
popd || exit

echo "Clean runtime build"
pushd src/runtime/ || exit
make clean SKIP_GO_VERSION_CHECK=1
popd || exit

echo "Clean agent build"
pushd src/agent/ || exit
make clean
popd || exit

rm -rf "${AGENT_INSTALL_DIR}"

echo "Clean UVM build"
pushd tools/osbuilder/ || exit
sudo -E PATH="${PATH}" make DISTRO=cbl-mariner clean
if [[ "${CONF_PODS}" == "yes" ]]; then
	sudo rm -f root_hash_.txt "${UVM_CHECKSUMS_FILE_NAME}"
fi
popd || exit

popd || exit
