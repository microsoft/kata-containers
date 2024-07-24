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

script_dir="$(dirname $(readlink -f $0))"
repo_dir="${script_dir}/../../../../"

common_file="common.sh"
source "${common_file}"

pushd "${repo_dir}"

# CONTINUE HERE - VANILLA kata-containers.spec only so far
echo "Creating target directories"
mkdir -p "${PREFIX}/${UVM_TOOLS_PATH}/scripts"
mkdir -p "${PREFIX}/${UVM_TOOLS_PATH}/rootfs-builder/cbl-mariner"
mkdir -p "${PREFIX}/${UVM_TOOLS_PATH}/initrd-builder"
mkdir -p "${PREFIX}/${UVM_TOOLS_PATH}/node-builder/azure-linux/agent-install/usr/bin"
mkdir -p "${PREFIX}/${UVM_TOOLS_PATH}/node-builder/azure-linux/agent-install/usr/lib/systemd/system"

echo "Installing UVM build scripting"
cp -a --backup=numbered tools/osbuilder/Makefile "${PREFIX}/${UVM_TOOLS_PATH}/Makefile"
cp -a --backup=numbered tools/osbuilder/scripts/lib.sh "${PREFIX}/${UVM_TOOLS_PATH}/scripts/lib.sh"
cp -a --backup=numbered tools/osbuilder/rootfs-builder/rootfs.sh "${PREFIX}/${UVM_TOOLS_PATH}/rootfs-builder/rootfs.sh"
cp -a --backup=numbered tools/osbuilder/rootfs-builder/cbl-mariner/config.sh "${PREFIX}/${UVM_TOOLS_PATH}/rootfs-builder/cbl-mariner/config.sh"
cp -a --backup=numbered tools/osbuilder/rootfs-builder/cbl-mariner/rootfs_lib.sh "${PREFIX}/${UVM_TOOLS_PATH}/rootfs-builder/cbl-mariner/rootfs_lib.sh"
cp -a --backup=numbered tools/osbuilder/initrd-builder/initrd_builder.sh "${PREFIX}/${UVM_TOOLS_PATH}/initrd-builder/initrd_builder.sh"
cp -a --backup=numbered tools/osbuilder/node-builder/azure-linux/Makefile "${PREFIX}/${UVM_TOOLS_PATH}/node-builder/azure-linux/Makefile"
cp -a --backup=numbered tools/osbuilder/node-builder/azure-linux/clean.sh "${PREFIX}/${UVM_TOOLS_PATH}/node-builder/azure-linux/clean.sh"
cp -a --backup=numbered tools/osbuilder/node-builder/azure-linux/common.sh "${PREFIX}/${UVM_TOOLS_PATH}node-builder/azure-linux/common.sh"
cp -a --backup=numbered tools/osbuilder/node-builder/azure-linux/uvm_build.sh "${PREFIX}/${UVM_TOOLS_PATH}/node-builder/azure-linux/uvm_build.sh"

echo "Installing agent binary and service files"
cp -a --backup=numbered tools/osbuilder/node-builder/azure-linux/agent-install/usr/bin/kata-agent "${PREFIX}/${UVM_TOOLS_PATH}/node-builder/azure-linux/agent-install/usr/bin/kata-agent"
cp -a --backup=numbered tools/osbuilder/node-builder/azure-linux/agent-install/usr/lib/systemd/system/kata-containers.target "${PREFIX}/${UVM_TOOLS_PATH}/node-builder/azure-linux/agent-install/usr/lib/systemd/system/kata-containers.target"
cp -a --backup=numbered tools/osbuilder/node-builder/azure-linux/agent-install/usr/lib/systemd/system/kata-agent.service "${PREFIX}/${UVM_TOOLS_PATH}/node-builder/azure-linux/agent-install/usr/lib/systemd/system/kata-agent.service"
popd
