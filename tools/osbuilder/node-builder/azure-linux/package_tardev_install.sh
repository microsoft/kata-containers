#!/usr/bin/env bash
#
# Copyright (c) 2024 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o errtrace

[ -n "$DEBUG" ] && set -x

PREFIX=${PREFIX:-}
START_SERVICES=${START_SERVICES:-yes}

script_dir="$(dirname $(readlink -f $0))"
repo_dir="${script_dir}/../../../../"

common_file="common.sh"
source "${common_file}"

pushd "${repo_dir}"

echo "Installing utarfs and kata-overlay binaries"
mkdir -p ${PREFIX}/usr/sbin
cp -a --backup=numbered src/utarfs/target/release/utarfs ${PREFIX}/usr/sbin/mount.tar
mkdir -p ${PREFIX}/usr/bin
cp -a --backup=numbered src/overlay/target/release/kata-overlay ${PREFIX}/usr/bin/
mkdir -p ${PREFIX}/usr/lib/systemd/system/

echo "Installing tardev-snapshotter binaries and service file"
mkdir -p ${PREFIX}/usr/bin
cp -a --backup=numbered src/tardev-snapshotter/target/release/tardev-snapshotter ${PREFIX}/usr/bin/
mkdir -p ${PREFIX}/usr/lib/systemd/system/
cp -a --backup=numbered src/tardev-snapshotter/tardev-snapshotter.service ${PREFIX}/usr/lib/systemd/system/

if [ "${START_SERVICES}" == "yes" ]; then
    echo "Enabling and starting snapshotter service"
    systemctl enable tardev-snapshotter && systemctl daemon-reload && systemctl restart tardev-snapshotter
fi

popd
