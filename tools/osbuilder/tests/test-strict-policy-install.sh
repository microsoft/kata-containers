#!/usr/bin/env bash
#
# Copyright (c) 2025 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# FR-2 / A9: a strict rootfs must not ship a rego policy file.
#
# Rather than restate the logic, this extracts the policy-install block straight out of
# rootfs.sh and runs it against a throwaway ROOTFS_DIR, so the test fails if the guard is
# ever removed from the real script.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rootfs_sh="${script_dir}/../rootfs-builder/rootfs.sh"

[[ -f "${rootfs_sh}" ]] || { echo "FAIL: cannot find ${rootfs_sh}"; exit 1; }

# Pull out the policy-install block. There are several `AGENT_POLICY == "yes"` blocks in
# rootfs.sh, so anchor on the last one that opens before the STRICT_POLICY guard, then walk
# forward tracking if/fi depth.
start_line="$(awk '
	/if \[\[ "\$\{AGENT_POLICY\}" == "yes" \]\]; then/ { cand = NR }
	/if \[\[ "\$\{STRICT_POLICY\}" == "yes" \]\]; then/ && cand { print cand; exit }
' "${rootfs_sh}")"

[[ -n "${start_line}" ]] || { echo "FAIL: could not locate the policy-install block"; exit 1; }

block="$(awk -v start="${start_line}" '
	NR < start { next }
	NR == start { depth = 1; print; next }
	{
		print
		if ($0 ~ /(^|[[:space:]])if[[:space:]]*\[\[/) depth++
		if ($0 ~ /^[[:space:]]*fi[[:space:]]*$/) { depth--; if (depth == 0) exit }
	}
' "${rootfs_sh}")"

[[ "${block}" == *"kata-opa"* ]] || {
	echo "FAIL: extracted block does not look like the policy-install block"
	exit 1
}

# Run the extracted block with STRICT_POLICY set to $1, leaving the produced tree in the
# global WORKDIR. Returns non-zero if the block itself errored.
run_case() {
	local strict="$1"
	WORKDIR="$(mktemp -d)"

	printf 'package agent_policy\ndefault CreateContainerRequest := true\n' \
		> "${WORKDIR}/allow-all.rego"
	mkdir -p "${WORKDIR}/rootfs"

	(
		set -euo pipefail
		info() { :; }
		# `install -o root -g root` needs privileges a plain test run does not have, so
		# stand in a version that keeps the copy but drops the ownership flags.
		install() {
			local src="" dst=""
			while (($#)); do
				case "$1" in
					-o | -g | -m) shift 2 ;;
					-D | -T) shift ;;
					*)
						if [[ -z "${src}" ]]; then src="$1"; else dst="$1"; fi
						shift
						;;
				esac
			done
			mkdir -p "$(dirname "${dst}")"
			cp "${src}" "${dst}"
		}

		AGENT_POLICY="yes"
		STRICT_POLICY="${strict}"
		ROOTFS_DIR="${WORKDIR}/rootfs"
		agent_policy_file="${WORKDIR}/allow-all.rego"

		# The extracted block declares `local` variables, which bash only permits inside a
		# function -- so run it as one.
		eval "run_block() { ${block}
		}"
		run_block
	)
}

fail=0

if run_case yes; then
	if [[ -e "${WORKDIR}/rootfs/etc/kata-opa" ]]; then
		echo "FAIL: STRICT_POLICY=yes installed $(ls "${WORKDIR}/rootfs/etc/kata-opa")"
		fail=1
	else
		echo "PASS: STRICT_POLICY=yes leaves no /etc/kata-opa"
	fi
else
	echo "FAIL: the extracted block errored with STRICT_POLICY=yes"
	fail=1
fi
rm -rf "${WORKDIR}"

if run_case no; then
	if [[ -e "${WORKDIR}/rootfs/etc/kata-opa/default-policy.rego" ]]; then
		echo "PASS: STRICT_POLICY=no still installs the default policy"
	else
		echo "FAIL: STRICT_POLICY=no did not install the default policy"
		fail=1
	fi
else
	echo "FAIL: the extracted block errored with STRICT_POLICY=no"
	fail=1
fi
rm -rf "${WORKDIR}"

exit "${fail}"
