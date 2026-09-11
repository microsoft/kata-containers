#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -lt 2 ]]; then
	echo "usage: $0 REPO_ROOT SOURCE_PATH..." >&2
	exit 2
fi

repo_root=$1
shift

git -C "${repo_root}" ls-files --cached --others --exclude-standard -z -- "$@" |
	sort -z |
	{
		while IFS= read -r -d '' path; do
			printf '%s\0' "${path}"
			if [[ -L "${repo_root}/${path}" ]]; then
				printf 'mode=120000\n'
				readlink "${repo_root}/${path}"
			elif [[ -f "${repo_root}/${path}" ]]; then
				if [[ -x "${repo_root}/${path}" ]]; then
					printf 'mode=100755\n'
				else
					printf 'mode=100644\n'
				fi
				sha256sum "${repo_root}/${path}" | cut -d ' ' -f 1
			else
				printf 'missing\n'
			fi
		done
	} |
	sha256sum |
	cut -d ' ' -f 1
