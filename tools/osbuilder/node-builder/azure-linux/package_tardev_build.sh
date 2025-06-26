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

pushd "${repo_dir}"

echo "Building utarfs binary"
pushd src/utarfs/
make all
popd

echo "Building kata-overlay binary"
pushd src/overlay/
make all
popd

echo "Building tardev-snapshotter service binary"
pushd src/tardev-snapshotter/
make all
popd

popd
