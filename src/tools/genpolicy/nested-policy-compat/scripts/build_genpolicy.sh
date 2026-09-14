#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 REPO_ROOT TARGET BUILT_BINARY STAGED_BINARY" >&2
	exit 2
fi

repo_root=$1
target=$2
built_binary=$3
staged_binary=$4
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fingerprint_file="${staged_binary}.fingerprint"

source_fingerprint=$(
	"${script_dir}/source_tree_fingerprint.sh" "${repo_root}" \
		Cargo.toml Cargo.lock \
		src/libs/kata-types src/libs/protocols \
		src/tools/genpolicy/Cargo.toml \
		src/tools/genpolicy/src \
		src/tools/genpolicy/nested-policy-compat/scripts/build_genpolicy.sh
)
expected=$(
	{
		printf 'source=%s\n' "${source_fingerprint}"
		printf 'target=%s\n' "${target}"
		rustc -Vv
		cargo -V
	} | sha256sum | cut -d ' ' -f 1
)
actual=
if [[ -f "${fingerprint_file}" ]]; then
	actual=$(<"${fingerprint_file}")
fi
if [[ -x "${staged_binary}" && "${actual}" == "${expected}" ]]; then
	echo "reusing checkout-built GenPolicy: ${staged_binary}"
	exit 0
fi

make --always-make \
	--directory "${repo_root}/src/tools/genpolicy" \
	src/version.rs
cargo build --locked --release --package genpolicy \
	--target "${target}" \
	--manifest-path "${repo_root}/Cargo.toml"
[[ -x "${built_binary}" ]] || {
	echo "GenPolicy build did not produce ${built_binary}" >&2
	exit 1
}
mkdir -p "$(dirname "${staged_binary}")"
install -m 0755 "${built_binary}" "${staged_binary}.new"
mv -f "${staged_binary}.new" "${staged_binary}"
printf '%s\n' "${expected}" >"${fingerprint_file}.new"
mv -f "${fingerprint_file}.new" "${fingerprint_file}"
