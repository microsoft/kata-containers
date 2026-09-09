#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 REPO_ROOT PROFILE_FILE KATA_ROOT KATA_CONFIG" >&2
	exit 2
fi

repo_root=$1
profile_file=$2
kata_root=$3
kata_config=$4
staged_genpolicy="${repo_root}/src/tools/genpolicy/nested-policy-compat/build/genpolicy"

if [[ ! -f "${profile_file}" ]]; then
	echo "profile file not found: ${profile_file}" >&2
	exit 1
fi

inputs=(
	"${repo_root}/Cargo.lock"
	"${repo_root}/Cargo.toml"
	"${repo_root}/src/agent"
	"${repo_root}/src/runtime-rs"
	"${repo_root}/src/tools/genpolicy"
)

if [[ -n "${kata_config}" ]]; then
	if [[ ! -f "${kata_config}" ]]; then
		echo "Kata configuration not found: ${kata_config}" >&2
		exit 1
	fi
	inputs+=("${kata_config}")
fi

if [[ -n "${kata_root}" ]]; then
	for installed_input in \
		"${kata_root}/runtime-rs/bin/containerd-shim-kata-v2" \
		"${kata_root}/bin/kata-agent" \
		"${kata_root}/share/kata-containers/kata-containers-confidential.img" \
		"${kata_root}/share/kata-containers/root_hash_confidential.txt"; do
		[[ ! -f "${installed_input}" ]] || inputs+=("${installed_input}")
	done
fi

{
	printf 'profile=%s\n' "${profile_file}"
	printf 'staged-genpolicy\0'
	if [[ -f "${staged_genpolicy}" ]]; then
		sha256sum "${staged_genpolicy}"
	else
		printf 'missing\n'
	fi
	while IFS= read -r -d '' input; do
		relative=${input#"${repo_root}/"}
		printf '%s\0' "${relative}"
		sha256sum "${input}"
	done < <(
		find "${inputs[@]}" \
			-type d \( \
				-name .git -o \
				-name build -o \
				-name target -o \
				-name __pycache__ \
			\) -prune -o \
			-type f ! -name '*.pyc' ! -name '*.md' -print0 |
			sort -z
	)
} | sha256sum | cut -d ' ' -f 1
