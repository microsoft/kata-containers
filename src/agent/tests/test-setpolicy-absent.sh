#!/usr/bin/env bash
#
# Copyright (c) 2025 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# FR-2 / B2: the `SetPolicy` RPC handler must not exist in a strict agent binary.
#
# Three assertions, not one, so the test cannot pass vacuously:
#
#   1. The non-strict control binary DOES carry the handler -- otherwise the probe is
#      broken and a clean strict binary proves nothing.
#   2. The strict binary carries neither the handler override nor its `do_set_policy`
#      worker.
#   3. The strict binary DOES carry the ttRPC trait's default `set_policy`, which is what
#      returns "unimplemented". Its presence is what makes the removal safe: the request
#      still lands somewhere well defined.
#
# `drop_in_place<...>` entries are compiler drop glue named after the future type and are
# emitted either way, so they are filtered out.

set -euo pipefail

agent_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${agent_dir}"

target_dir="${CARGO_TARGET_DIR:-$(cd "${agent_dir}/../.." && pwd)/target}"

# Count function symbols matching $2, excluding drop glue.
syms() {
	nm -C "$1" 2>/dev/null | sed 's/^[0-9a-f]* //' | grep -v "drop_in_place" | grep -c "$2" || true
}

build() {
	local features="$1" out="$2"
	echo "building agent (${features})..." >&2
	cargo build --features "${features}" >&2
	cp "${target_dir}/debug/kata-agent" "${out}"
}

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

build "agent-policy" "${tmp}/nonstrict"
build "strict-policy,agent-policy" "${tmp}/strict"

handler="kata_agent::rpc::AgentService as .*::set_policy"
worker="kata_agent::policy::do_set_policy"
trait_default="protocols::agent_ttrpc_async::AgentService::set_policy"

fail=0

check() {
	local label="$1" want="$2" got="$3"
	if [[ "${want}" == "present" && "${got}" -eq 0 ]]; then
		echo "FAIL: ${label}: expected present, found none"
		fail=1
	elif [[ "${want}" == "absent" && "${got}" -ne 0 ]]; then
		echo "FAIL: ${label}: expected none, found ${got}"
		fail=1
	else
		echo "PASS: ${label} (${got} symbol(s))"
	fi
}

# 1. Control: the probe must be able to see the handler where it does exist.
check "non-strict carries the SetPolicy handler" present "$(syms "${tmp}/nonstrict" "${handler}")"
check "non-strict carries do_set_policy" present "$(syms "${tmp}/nonstrict" "${worker}")"

# 2. The strict binary has no handler and no worker.
check "strict has no SetPolicy handler" absent "$(syms "${tmp}/strict" "${handler}")"
check "strict has no do_set_policy" absent "$(syms "${tmp}/strict" "${worker}")"

# 3. ...but does fall back to the ttRPC default, which answers "unimplemented".
check "strict falls back to the ttRPC default" present "$(syms "${tmp}/strict" "${trait_default}")"

if [[ "${fail}" -ne 0 ]]; then
	echo
	echo "strict set_policy symbols:"
	nm -C "${tmp}/strict" | grep "set_policy" || true
fi

exit "${fail}"
