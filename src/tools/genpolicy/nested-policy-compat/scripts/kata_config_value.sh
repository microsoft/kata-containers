#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 CONFIG SECTION KEY" >&2
	exit 2
fi

value=$(
	awk -v wanted_section="$2" -v wanted_key="$3" '
		/^[[:space:]]*\[/ {
			section = $0
			sub(/^[[:space:]]*\[/, "", section)
			sub(/\][[:space:]]*(#.*)?$/, "", section)
			next
		}
		section == wanted_section {
			line = $0
			sub(/[[:space:]]*#.*$/, "", line)
			if (line !~ "^[[:space:]]*" wanted_key "[[:space:]]*=") {
				next
			}
			sub("^[[:space:]]*" wanted_key "[[:space:]]*=[[:space:]]*", "", line)
			sub(/[[:space:]]*$/, "", line)
			if (line ~ /^"[^"]*"$/) {
				sub(/^"/, "", line)
				sub(/"$/, "", line)
				print line
				exit
			}
		}
	' "$1"
)

if [[ -z "${value}" ]]; then
	echo "missing quoted TOML value [$2] $3 in $1" >&2
	exit 1
fi
printf '%s\n' "${value}"
