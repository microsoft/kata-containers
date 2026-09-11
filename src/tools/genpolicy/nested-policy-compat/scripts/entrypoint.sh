#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

readonly harness_root="${NESTED_POLICY_COMPAT_ROOT:-/opt/nested-policy-compat}"
readonly appliance_root="${GENPOLICY_APPLIANCE_ROOT:-/opt/genpolicy/appliance}"
readonly input_dir="${GENPOLICY_INPUT_DIR:-/input}"
readonly output_dir="${GENPOLICY_OUTPUT_DIR:-/output}"
readonly workload="${input_dir}/workload.yaml"
readonly kata_root="${NESTED_KATA_ROOT:-/opt/kata}"
readonly kata_config="${NESTED_KATA_CONFIG:-${kata_root}/share/defaults/kata-containers/runtime-rs/configuration.toml}"
readonly timeout_seconds="${NESTED_POLICY_TIMEOUT_SECONDS:-240}"
readonly profile="${GENPOLICY_PROFILE_NAME:-unknown}"
readonly profile_path="${appliance_root}/profiles/${profile}.env"
runtime_kata_config="${kata_config}"

[[ -f "${profile_path}" ]] || {
	echo "ERROR: unknown compatibility profile: ${profile}" >&2
	exit 1
}
# shellcheck source=/dev/null
source "${profile_path}"

base_pid=
relay_pid=

cleanup() {
	if [[ -n "${base_pid}" ]]; then
		kill "${base_pid}" 2>/dev/null || true
	fi
	if [[ -n "${relay_pid}" ]]; then
		kill "${relay_pid}" 2>/dev/null || true
	fi
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

[[ "$(id -u)" == "0" ]] || fail "the harness must run as root"
[[ -f "${workload}" ]] || fail "${workload} is required"
[[ -f "${kata_config}" ]] || fail "Kata configuration not found: ${kata_config}"
[[ -c /dev/kvm ]] || fail "/dev/kvm is required; enable nested virtualization in the L1 VM"
[[ -x "${appliance_root}/scripts/entrypoint.sh" ]] ||
	fail "base appliance entrypoint is missing"

export PATH="${kata_root}/runtime-rs/bin:${kata_root}/bin:${PATH}"
command -v containerd-shim-kata-v2 >/dev/null ||
	fail "containerd-shim-kata-v2 was not found under ${kata_root}"

# ROOTFS_MODE is loaded from the selected profile.
# shellcheck disable=SC2154
python3 - "${workload}" "${kata_config}" "${ROOTFS_MODE}" <<'PY'
import re
import sys
import tomllib
import yaml
from pathlib import Path

annotation = "io.katacontainers.config.hypervisor.cc_init_data"
annotation_name = "cc_init_data"
paths = (
    ("metadata", "annotations"),
    ("spec", "template", "metadata", "annotations"),
    ("spec", "jobTemplate", "spec", "template", "metadata", "annotations"),
)

def nested(value, path):
    for part in path:
        if not isinstance(value, dict):
            return {}
        value = value.get(part, {})
    return value if isinstance(value, dict) else {}

with open(sys.argv[1], encoding="utf-8") as source:
    documents = [value for value in yaml.safe_load_all(source) if value]

if not any(annotation in nested(document, path) for document in documents for path in paths):
    raise SystemExit(
        f"workload does not contain externally generated {annotation} annotation"
    )

with open(sys.argv[2], "rb") as source:
    configuration = tomllib.load(source)
runtime = configuration.get("runtime", {})
hypervisor_name = runtime.get("hypervisor_name")
hypervisor = configuration.get("hypervisor", {}).get(hypervisor_name, {})
enabled = hypervisor.get("enable_annotations", [])
if not any(re.fullmatch(pattern, annotation_name) for pattern in enabled):
    raise SystemExit(
        f"Kata configuration does not enable the {annotation_name} annotation"
    )

if hypervisor.get("shared_fs") != "none":
    raise SystemExit(
        "nested policy compatibility profiles require the selected Kata hypervisor "
        'configuration to set shared_fs = "none"'
    )

if sys.argv[3] == "erofs-dmverity" and hypervisor_name == "clh":
    vmm_path = Path(hypervisor.get("path", ""))
    if not vmm_path.is_file():
        raise SystemExit(f"Cloud Hypervisor binary not found: {vmm_path}")
    if b"FlatVmdk" not in vmm_path.read_bytes():
        raise SystemExit(
            "EROFS dm-verity with Cloud Hypervisor requires flat VMDK support "
            "(cloud-hypervisor/cloud-hypervisor PR #8599)"
        )
PY

mkdir -p "${output_dir}/logs" "${output_dir}/agent-rpcs"
chmod 0700 "${output_dir}/agent-rpcs"

containerd_version=$(containerd --version)
confidential_image="${kata_root}/share/kata-containers/kata-containers-confidential.img"
confidential_hash="${kata_root}/share/kata-containers/root_hash_confidential.txt"
[[ -f "${confidential_image}" ]] ||
	fail "monolithic compatibility guest image not found: ${confidential_image}"
[[ -f "${confidential_hash}" ]] ||
	fail "monolithic compatibility guest image verity parameters not found: ${confidential_hash}"
runtime_kata_config=/run/nested-policy-compat-kata.toml
python3 - \
	"${kata_config}" "${runtime_kata_config}" \
	"${confidential_image}" "${confidential_hash}" "${ROOTFS_MODE}" <<'PY'
import json
import sys
import tomllib
from pathlib import Path

source, destination, confidential_image, confidential_hash = map(Path, sys.argv[1:5])
rootfs_mode = sys.argv[5]
with source.open("rb") as stream:
    configuration = tomllib.load(stream)

runtime = configuration.get("runtime", {})
experimental = list(runtime.get("experimental", []))
if rootfs_mode == "guest-pull" and "force_guest_pull" not in experimental:
    experimental.append("force_guest_pull")
if rootfs_mode != "guest-pull" and "force_guest_pull" in experimental:
    experimental.remove("force_guest_pull")

hypervisor_name = runtime.get("hypervisor_name")

lines = source.read_text(encoding="utf-8").splitlines()
in_runtime = False
in_hypervisor = False
runtime_replaced = False
image_replaced = False
verity_replaced = False
hypervisor_header = f"[hypervisor.{hypervisor_name}]"
hypervisor_end = None
for index, line in enumerate(lines):
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        if in_hypervisor:
            hypervisor_end = index
        in_runtime = stripped == "[runtime]"
        in_hypervisor = stripped == hypervisor_header
    elif in_runtime and stripped.startswith("experimental"):
        lines[index] = f"experimental = {json.dumps(experimental)}"
        runtime_replaced = True
    elif in_hypervisor and stripped.startswith("image ="):
        lines[index] = f"image = {json.dumps(str(confidential_image))}"
        image_replaced = True
    elif in_hypervisor and stripped.startswith("kernel_verity_params ="):
        lines[index] = (
            "kernel_verity_params = "
            f"{json.dumps(confidential_hash.read_text(encoding='utf-8').strip())}"
        )
        verity_replaced = True
if not runtime_replaced:
    raise SystemExit("Kata configuration has no runtime.experimental setting")
if not image_replaced:
    raise SystemExit(f"Kata configuration has no image setting in {hypervisor_header}")
if not verity_replaced:
    if hypervisor_end is None:
        hypervisor_end = len(lines)
    lines.insert(
        hypervisor_end,
        "kernel_verity_params = "
        f"{json.dumps(confidential_hash.read_text(encoding='utf-8').strip())}",
    )
destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

case "${ROOTFS_MODE}" in
erofs-dmverity)
	case "${containerd_version}" in
	*" v2."*) ;;
	*) fail "EROFS dm-verity profile requires containerd 2.x: ${containerd_version}" ;;
	esac
	;;
guest-pull)
	;;
*) fail "unsupported rootfs mode: ${ROOTFS_MODE}" ;;
esac

# RUNTIME_CONTAINERD_CONFIG and PAUSE_IMAGE are loaded from the selected profile.
# shellcheck disable=SC2154
python3 - \
		"${harness_root}/config/${RUNTIME_CONTAINERD_CONFIG}" \
		"${appliance_root}/config/nested-policy-compat.toml" \
		"${runtime_kata_config}" "${PAUSE_IMAGE}" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
kata_config = Path(sys.argv[3])
pause_image = sys.argv[4]
text = source.read_text(encoding="utf-8")
destination.write_text(
    text.replace("@KATA_CONFIG@", str(kata_config)).replace(
        "@PAUSE_IMAGE@",
        pause_image,
    ),
    encoding="utf-8",
)
PY

{
	echo "profile=${profile}"
	kubelet --version
	containerd --version
	containerd-shim-kata-v2 --version || true
	uname -a
} >"${output_dir}/component-versions.txt" 2>&1

{
	sha256sum "$(command -v containerd-shim-kata-v2)" "${runtime_kata_config}"
	find "${kata_root}/share/kata-containers" -maxdepth 1 -type f \
		-exec sha256sum {} +
} >"${output_dir}/kata-artifacts.sha256" 2>"${output_dir}/logs/kata-artifacts.log"

relay_args=(
	--root /run/vc
	--root /run/kata
	--root /run/kata-containers
	--name ch-vm.sock
	--name kata.hvsock
	--name vsock.sock
	--output "${output_dir}/agent-rpcs"
)
python3 "${harness_root}/scripts/hvsock_capture.py" "${relay_args[@]}" \
	>"${output_dir}/logs/hvsock-capture.log" 2>&1 &
relay_pid=$!

export CONTAINERD_CONFIG=nested-policy-compat.toml
export GENPOLICY_NESTED_RUNTIME_ONLY=1

"${appliance_root}/scripts/entrypoint.sh" \
	>"${output_dir}/logs/base-appliance.log" 2>&1 &
base_pid=$!

ready=0
base_exit=0
deadline=$((SECONDS + timeout_seconds))
while ((SECONDS < deadline)); do
	if [[ -f "${output_dir}/runtime-operations.json" ]]; then
		if python3 - "${output_dir}/runtime-operations.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if report.get("complete") is True else 1)
PY
		then
			ready=1
			break
		fi
	fi

	if ! kill -0 "${base_pid}" 2>/dev/null; then
		set +o errexit
		wait "${base_pid}"
		base_exit=$?
		set -o errexit
		base_pid=
		break
	fi
	sleep 1
done

if [[ "${ready}" == "1" ]]; then
	cp "${output_dir}/pod-status-ready.json" "${output_dir}/pod-status.json"
	kubectl --kubeconfig /etc/kubernetes/kubeconfig get events --all-namespaces \
		--sort-by=.metadata.creationTimestamp >"${output_dir}/events.txt" 2>&1 || true
	kill "${base_pid}" 2>/dev/null || true
	set +o errexit
	wait "${base_pid}"
	set -o errexit
	base_pid=
	base_exit=0
elif [[ -n "${base_pid}" ]]; then
	kill "${base_pid}" 2>/dev/null || true
	set +o errexit
	wait "${base_pid}"
	base_exit=$?
	set -o errexit
	base_pid=
	[[ "${base_exit}" -ne 0 ]] || base_exit=124
fi

sleep 1
kill "${relay_pid}" 2>/dev/null || true
set +o errexit
wait "${relay_pid}"
set -o errexit
relay_pid=

capture_state="${output_dir}/agent-rpcs/state.json"
report_args=(
	--base-exit-code "${base_exit}"
	--capture-state "${capture_state}"
	--kata-config "${kata_config}"
	--logs "${output_dir}/logs"
	--output "${output_dir}/compatibility.json"
	--profile "${profile}"
	--workload "${workload}"
)
[[ "${ready}" == "1" ]] && report_args+=(--ready)
python3 "${harness_root}/scripts/compat_report.py" "${report_args[@]}"

connections=$(python3 - "${capture_state}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
print(json.loads(path.read_text(encoding="utf-8")).get("connections", 0) if path.exists() else 0)
PY
)
[[ "${connections}" -gt 0 ]] ||
	fail "no hybrid-vsock connection was captured; use a supported hvsock Kata configuration"

result=$(python3 - "${output_dir}/compatibility.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["result"])
PY
)
echo "nested policy compatibility result: ${result}"
[[ "${result}" == "compatible" ]]
