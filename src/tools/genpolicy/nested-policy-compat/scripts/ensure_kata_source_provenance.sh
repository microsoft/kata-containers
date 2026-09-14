#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 REPO_ROOT KATA_ROOT KATA_CONFIG CONTAINER_ENGINE" >&2
	exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if "${script_dir}/verify_kata_source_provenance.sh" "$1" "$2" "$3"; then
	exit 0
fi

echo "installed Kata components are stale; rebuilding from the current checkout"
"${script_dir}/rebuild_kata_stack.sh" "$1" "$2" "$3" "$4"
"${script_dir}/verify_kata_source_provenance.sh" "$1" "$2" "$3"
