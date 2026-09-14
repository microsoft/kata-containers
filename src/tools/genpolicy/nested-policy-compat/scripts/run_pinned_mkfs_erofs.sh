#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bundle_dir=${GENPOLICY_EROFS_BUNDLE_DIR:-${script_dir}/erofs-runtime}

exec "${bundle_dir}/lib64/ld-linux-x86-64.so.2" \
	--library-path "${bundle_dir}/lib/x86_64-linux-gnu" \
	"${bundle_dir}/bin/mkfs.erofs" "$@"
