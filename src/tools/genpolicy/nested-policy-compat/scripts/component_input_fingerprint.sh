#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 REPO_ROOT COMPONENT [DEPENDENCY_ARCHIVE...]" >&2
	exit 2
fi

repo_root=$1
component=$2
shift 2
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

case "${component}" in
agent)
	inputs=(
		Cargo.toml Cargo.lock VERSION versions.yaml
		ci/install_libseccomp.sh ci/install_yq.sh
		src/agent src/libs
		tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh
		tools/packaging/kata-deploy/local-build/kata-deploy-copy-libseccomp-installer.sh
		tools/packaging/scripts tools/packaging/static-build/agent
	)
	options=(
		"AGENT_POLICY=yes"
		"STRICT_POLICY=yes"
		"INIT_DATA=yes"
		"USE_DEVMAPPER=yes"
		"MEASURED_ROOTFS=no"
		"EXTRA_RUSTFEATURES=allow-unattested-initdata"
	)
	;;
coco-guest-components)
	inputs=(
		VERSION versions.yaml
		tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh
		tools/packaging/scripts
		tools/packaging/static-build/coco-guest-components
	)
	options=("MEASURED_ROOTFS=no")
	;;
pause-image)
	inputs=(
		VERSION versions.yaml
		tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh
		tools/packaging/scripts
		tools/packaging/static-build/pause-image
	)
	options=("MEASURED_ROOTFS=no")
	;;
rootfs-image-confidential)
	inputs=(
		VERSION versions.yaml
		tools/osbuilder
		tools/packaging/guest-image
		tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh
		tools/packaging/scripts
	)
	options=(
		"AGENT_POLICY=yes"
		"STRICT_POLICY=yes"
		"INIT_DATA=yes"
		"USE_DEVMAPPER=yes"
		"MEASURED_ROOTFS=no"
	)
	;;
shim-v2-rust)
	inputs=(
		Cargo.toml Cargo.lock VERSION versions.yaml ci/install_yq.sh
		src/dragonball src/libs src/runtime-rs
		tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh
		tools/packaging/scripts tools/packaging/static-build/shim-v2
	)
	options=(
		"INIT_DATA=yes"
		"USE_DEVMAPPER=yes"
		"MEASURED_ROOTFS=no"
	)
	;;
*)
	echo "unsupported Kata component: ${component}" >&2
	exit 2
	;;
esac

inputs+=(
	src/tools/genpolicy/nested-policy-compat/scripts/component_input_fingerprint.sh
	src/tools/genpolicy/nested-policy-compat/scripts/source_tree_fingerprint.sh
)
source_fingerprint=$(
	"${script_dir}/source_tree_fingerprint.sh" "${repo_root}" "${inputs[@]}"
)

{
	printf 'component=%s\n' "${component}"
	printf 'source=%s\n' "${source_fingerprint}"
	printf '%s\n' "${options[@]}"
	printf 'builder=%s\n' "${NPC_COMPONENT_BUILDER_IDENTITY:-none}"
	for variable in \
		ARCH TARGET_ARCH TARGET_OS CROSS_BUILD DEBUG RELEASE \
		EXTRA_PKGS REPO_URL REPO_URL_X86_64 REPO_COMPONENTS \
		BUSYBOX_CONF_FILE GUEST_HOOKS_TARBALL_NAME BUILDER_REGISTRY; do
		printf '%s=%s\n' "${variable}" "${!variable-}"
	done
	for dependency in "$@"; do
		[[ -f "${dependency}" ]] || {
			echo "component dependency archive not found: ${dependency}" >&2
			exit 1
		}
		printf 'dependency=%s:' "$(basename "${dependency}")"
		sha256sum "${dependency}" | cut -d ' ' -f 1
	done
} | sha256sum | cut -d ' ' -f 1
