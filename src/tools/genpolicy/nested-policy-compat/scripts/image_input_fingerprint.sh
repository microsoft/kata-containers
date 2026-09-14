#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 REPO_ROOT PROFILE_FILE EROFS_UTILS_VERSION" >&2
	exit 2
fi

repo_root=$1
profile_file=$2
erofs_utils_version=$3

if [[ ! -f "${profile_file}" ]]; then
	echo "profile file not found: ${profile_file}" >&2
	exit 1
fi

inputs=(
	"${repo_root}/src/tools/genpolicy/nested-policy-compat/Dockerfile"
	"${repo_root}/src/tools/genpolicy/nested-policy-compat/appliance/config"
	"${repo_root}/src/tools/genpolicy/nested-policy-compat/appliance/scripts"
	"${repo_root}/src/tools/genpolicy/nested-policy-compat/config"
	"${repo_root}/src/tools/genpolicy/nested-policy-compat/scripts/compat_report.py"
	"${repo_root}/src/tools/genpolicy/nested-policy-compat/scripts/entrypoint.sh"
	"${repo_root}/src/tools/genpolicy/nested-policy-compat/scripts/hvsock_capture.py"
	"${repo_root}/src/tools/genpolicy/nested-policy-compat/scripts/image_input_fingerprint.sh"
	"${profile_file}"
)

{
	printf 'erofs-utils-version=%s\n' "${erofs_utils_version}"
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
