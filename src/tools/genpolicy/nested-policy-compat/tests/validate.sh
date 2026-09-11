#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

bash -n "${root}/scripts/entrypoint.sh"
bash -n "${root}/scripts/ensure_host_environment.sh"
bash -n "${root}/scripts/ensure_kata_source_provenance.sh"
bash -n "${root}/scripts/generate_policy.sh"
bash -n "${root}/scripts/image_input_fingerprint.sh"
bash -n "${root}/scripts/kata_config_value.sh"
bash -n "${root}/scripts/rebuild_kata_stack.sh"
bash -n "${root}/scripts/source_tree_fingerprint.sh"
bash -n "${root}/scripts/verify_kata_source_provenance.sh"
bash -n "${root}/appliance/scripts/entrypoint.sh"
python3 -m py_compile \
	"${root}/appliance/scripts/exercise_runtime_operations.py" \
	"${root}/scripts/hvsock_capture.py" \
	"${root}/scripts/compat_report.py"
python3 -m unittest discover -s "${root}/tests" -p 'test_*.py'
grep -Fq 'input.rule == "CreateSandboxRequest"' \
	"${root}/tests/policy/create-sandbox-reasons.rego.inc"
grep -Fq 'KATA_AGENT_MAKEFLAGS="EXTRA_RUSTFEATURES=allow-unattested-initdata"' \
	"${root}/scripts/rebuild_kata_stack.sh"
grep -Fq 'MEASURED_ROOTFS=no' \
	"${root}/scripts/rebuild_kata_stack.sh"
for profile in "${root}"/appliance/profiles/*.env; do
	(
		# shellcheck source=/dev/null
		source "${profile}"
		# shellcheck disable=SC2154
		case "${ROOTFS_MODE}:${CONTAINERD_VERSION#v}" in
		erofs-dmverity:2.* | guest-pull:1.7.* | guest-pull:2.*) ;;
		*)
			echo "unsupported rootfs/containerd profile combination: ${profile}" >&2
			exit 1
			;;
		esac
		# Values are loaded from the selected profile.
		# shellcheck disable=SC2154
		for required_file in \
			"${root}/appliance/profiles/${GENPOLICY_SETTINGS}" \
			"${root}/config/${GENPOLICY_CONTAINERD_CONFIG}" \
			"${root}/config/${RUNTIME_CONTAINERD_CONFIG}"; do
			[[ -f "${required_file}" ]]
		done
	)
done
python3 - \
	"${root}/appliance/profiles/erofs-dmverity.settings.json" \
	"${root}/appliance/profiles/guest-pull.settings.json" \
	"${root}/appliance/profiles/guest-pull-containerd-1.7.settings.json" <<'PY'
import json
import sys

patches = {patch["path"]: patch["value"] for patch in json.load(open(sys.argv[1], encoding="utf-8"))}
assert patches["/cluster_config/emptydir_type"] == "block-encrypted"
assert patches["/volumes/emptyDir_encrypted/driver"] == "local"
assert patches["/volumes/emptyDir_encrypted/source"] == "local"
assert patches["/volumes/emptyDir_encrypted/fstype"] == "local"
assert patches["/volumes/emptyDir_encrypted/mount_type"] == "local"
assert patches["/volumes/emptyDir_encrypted/shared"] is False

guest_pull = {patch["path"]: patch["value"] for patch in json.load(open(sys.argv[2], encoding="utf-8"))}
assert guest_pull["/common/image_layer_verification"] == "none"
assert guest_pull["/common/allow_guest_pull_images"] is True
assert guest_pull["/common/require_pinned_image_digests"] is True
assert guest_pull["/cluster_config/guest_pull"] is True

guest_pull_17 = {patch["path"]: patch["value"] for patch in json.load(open(sys.argv[3], encoding="utf-8"))}
assert guest_pull_17["/common/allow_guest_pull_images"] is True
assert guest_pull_17["/common/require_pinned_image_digests"] is True
assert guest_pull_17["/cluster_config/guest_pull"] is True
assert guest_pull_17["/kata_config/oci_version"] == "1.1.0"
PY

if command -v shellcheck >/dev/null 2>&1; then
	shellcheck \
		"${root}/scripts/entrypoint.sh" \
		"${root}/scripts/ensure_host_environment.sh" \
		"${root}/scripts/ensure_kata_source_provenance.sh" \
		"${root}/scripts/generate_policy.sh" \
		"${root}/scripts/image_input_fingerprint.sh" \
		"${root}/scripts/kata_config_value.sh" \
		"${root}/scripts/rebuild_kata_stack.sh" \
		"${root}/scripts/source_tree_fingerprint.sh" \
		"${root}/scripts/verify_kata_source_provenance.sh" \
		"${root}/appliance/scripts/entrypoint.sh" \
		"${root}/tests/fixture-matrix-e2e.sh" \
		"${root}/tests/validate.sh"
fi
