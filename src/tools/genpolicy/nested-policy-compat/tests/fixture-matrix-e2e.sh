#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
engine=${CONTAINER_ENGINE:?CONTAINER_ENGINE is required}
nested_image=${NESTED_IMAGE:?NESTED_IMAGE is required}
kata_root=${KATA_ROOT:?KATA_ROOT is required}
kata_config=${KATA_CONFIG:?KATA_CONFIG is required}
output_root=${OUTPUT_ROOT:?OUTPUT_ROOT is required}
output_marker="${output_root}/.nested-policy-compat-output"

device_args=(--device /dev/kvm --device /dev/net/tun)
if [[ -e /dev/vhost-vsock ]]; then
	device_args+=(--device /dev/vhost-vsock)
fi

if [[ -e "${output_root}" && ! -d "${output_root}" ]]; then
	echo "matrix output path is not a directory: ${output_root}" >&2
	exit 2
fi
mkdir -p "${output_root}"
if [[ ! -f "${output_marker}" ]] &&
	find "${output_root}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
	echo "refusing nonempty matrix output directory without harness marker: ${output_root}" >&2
	exit 2
fi
touch "${output_marker}"
rm -rf "${output_root}/cases"
mkdir -p "${output_root}/cases"

default_fixtures=(
	pod.yaml
	policy-matrix-env-pod.yaml
	policy-matrix-process-pod.yaml
	complex-workload.yaml
	service-account-workload.yaml
	local-emptydir-workload.yaml
	storage-classes-workload.yaml
	runtime-operations-workload.yaml
)
if [[ -n "${FIXTURES:-}" ]]; then
	read -r -a fixtures <<<"${FIXTURES}"
else
	fixtures=("${default_fixtures[@]}")
fi

failures=0
for fixture in "${fixtures[@]}"; do
	name=${fixture%.yaml}
	case_dir="${output_root}/cases/${name}"
	mkdir -p "${case_dir}/generation-input" "${case_dir}/generation-output" \
		"${case_dir}/nested-input/images" "${case_dir}/nested-output"
	cp "${script_dir}/fixtures/${fixture}" \
		"${case_dir}/generation-input/workload.yaml"

	set +o errexit
	"${engine}" run --rm --privileged --network=none --cgroupns=host \
		-v "${case_dir}/generation-input:/input:ro" \
		-v "${case_dir}/generation-output:/output" \
		--entrypoint /opt/nested-policy-compat/scripts/generate_policy.sh \
		"${nested_image}" >"${case_dir}/generation.log" 2>&1
	generation_status=$?
	set -o errexit
	if [[ "${generation_status}" -ne 0 ]]; then
		printf '%s\t%s\tgeneration-failed\n' "${name}" "${generation_status}"
		((failures += 1))
		continue
	fi
	if ! grep -Fq "reason :=" \
		"${case_dir}/generation-output/policy.rego"; then
		printf '%s\t1\treason-rules-missing\n' "${name}"
		((failures += 1))
		continue
	fi

	python3 "${script_dir}/annotate_workload.py" \
		--workload "${case_dir}/generation-output/workload.yaml" \
		--policy "${case_dir}/generation-output/policy.rego" \
		--registry-ca <(
			"${engine}" run --rm --entrypoint /bin/cat "${nested_image}" \
				/opt/genpolicy/registry-tls/registry.crt
		) \
		--output "${case_dir}/nested-input/workload.yaml"
	"${engine}" run --rm --entrypoint /bin/cat "${nested_image}" \
		/opt/genpolicy/images/busybox.tar \
		>"${case_dir}/nested-input/images/busybox.tar"

	set +o errexit
	"${engine}" run --rm --privileged --cgroupns=host \
		"${device_args[@]}" \
		-e GENPOLICY_POD_READY_TIMEOUT="${POD_READY_TIMEOUT:-180s}" \
		-e NESTED_KATA_CONFIG=/nested-policy-compat/configuration.toml \
		-v "${kata_root}:/opt/kata:ro" \
		-v "${kata_config}:/nested-policy-compat/configuration.toml:ro" \
		-v "${case_dir}/nested-input:/input:ro" \
		-v "${case_dir}/nested-output:/output" \
		"${nested_image}" >"${case_dir}/nested.log" 2>&1
	status=$?
	set -o errexit

	result=$(python3 - "${case_dir}/nested-output/compatibility.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
print(json.loads(path.read_text(encoding="utf-8"))["result"] if path.exists() else "missing")
PY
)
	printf '%s\t%s\t%s\n' "${name}" "${status}" "${result}"
	if [[ "${status}" -ne 0 || "${result}" != "compatible" ]]; then
		((failures += 1))
	fi
done

exit "${failures}"
