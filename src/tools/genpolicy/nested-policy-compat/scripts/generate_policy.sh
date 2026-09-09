#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

readonly input_dir="${GENPOLICY_INPUT_DIR:-/input}"
readonly output_dir="${GENPOLICY_OUTPUT_DIR:-/output}"
readonly workload="${input_dir}/workload.yaml"
readonly appliance_root="${GENPOLICY_APPLIANCE_ROOT:-/opt/genpolicy/appliance}"
readonly harness_root="${NESTED_POLICY_COMPAT_ROOT:-/opt/nested-policy-compat}"

profile="${GENPOLICY_PROFILE_NAME:?GENPOLICY_PROFILE_NAME is required}"
# shellcheck source=/dev/null
source "${appliance_root}/profiles/${profile}.env"

pids=()
cleanup() {
	local pid
	for pid in "${pids[@]}"; do
		kill "${pid}" 2>/dev/null || true
	done
}
trap cleanup EXIT

wait_for() {
	local description=$1
	shift
	local _
	for _ in $(seq 1 120); do
		if "$@" >/dev/null 2>&1; then
			return
		fi
		sleep 1
	done
	echo "timed out waiting for ${description}" >&2
	exit 1
}

[[ -f "${workload}" ]] || {
	echo "${workload} is required" >&2
	exit 1
}
# LOCAL_REGISTRY is loaded from the selected profile.
# shellcheck disable=SC2154
mkdir -p "${output_dir}" /etc/containerd/certs.d/"${LOCAL_REGISTRY}" \
	/etc/docker/registry /var/lib/registry /run/containerd /var/lib/containerd
cp "${workload}" "${output_dir}/workload.yaml"
readonly writable_workload="${output_dir}/workload.yaml"

# Guest-pull profiles use the CNI bridge gateway as a registry address that is
# reachable from both this isolated generator and the nested guest.
# ROOTFS_MODE and LOCAL_REGISTRY are loaded from the selected profile.
# shellcheck disable=SC2154
if [[ "${ROOTFS_MODE}" == "guest-pull" ]]; then
	registry_host=${LOCAL_REGISTRY%:*}
	ip address add "${registry_host}/32" dev lo
	python3 - \
		"${writable_workload}" "${LOCAL_REGISTRY}" "${CONTAINERD_VERSION}" <<'PY'
import sys
from pathlib import Path

import yaml

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8").replace("genpolicy.local:5000", sys.argv[2])
documents = list(yaml.safe_load_all(text))
if sys.argv[3].startswith("v1."):
    for document in documents:
        if not isinstance(document, dict):
            continue
        templates = [document]
        if document.get("kind") in {"Deployment", "DaemonSet", "StatefulSet", "Job"}:
            templates = [document.get("spec", {}).get("template", {})]
        elif document.get("kind") == "CronJob":
            templates = [
                document.get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
            ]
        for template in templates:
            for container in template.get("spec", {}).get("containers", []):
                lifecycle = container.get("lifecycle")
                if isinstance(lifecycle, dict):
                    lifecycle.pop("stopSignal", None)
                    if not lifecycle:
                        container.pop("lifecycle", None)
path.write_text(yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8")
PY
else
	printf '127.0.0.1 genpolicy.local\n' >>/etc/hosts
fi

cat >"/etc/containerd/certs.d/${LOCAL_REGISTRY}/hosts.toml" <<EOF
server = "http://${LOCAL_REGISTRY}"

[host."http://${LOCAL_REGISTRY}"]
  capabilities = ["pull", "resolve", "push"]
EOF
cat >/etc/docker/registry/config.yml <<EOF
version: 0.1
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: ${LOCAL_REGISTRY}
EOF

registry serve /etc/docker/registry/config.yml \
	>"${output_dir}/registry.log" 2>&1 &
pids+=("$!")
wait_for registry curl -fsS "http://${LOCAL_REGISTRY}/v2/"

# GENPOLICY_CONTAINERD_CONFIG is loaded from the selected profile.
# shellcheck disable=SC2154
python3 - \
	"${harness_root}/config/${GENPOLICY_CONTAINERD_CONFIG}" \
	/run/containerd-generation.toml "${PAUSE_IMAGE}" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
destination.write_text(
    source.read_text(encoding="utf-8").replace("@PAUSE_IMAGE@", sys.argv[3]),
    encoding="utf-8",
)
PY
containerd --config /run/containerd-generation.toml \
	>"${output_dir}/containerd.log" 2>&1 &
pids+=("$!")
wait_for containerd ctr --address /run/containerd/containerd.sock version

for image in /opt/genpolicy/images/*.tar; do
	ctr --address /run/containerd/containerd.sock --namespace k8s.io \
		images import --digests "${image}" >/dev/null
done
if [[ "${PAUSE_IMAGE}" != "genpolicy.local:5000/pause:3.10" ]]; then
	ctr --address /run/containerd/containerd.sock --namespace k8s.io \
		images tag "genpolicy.local:5000/pause:3.10" "${PAUSE_IMAGE}" >/dev/null
fi
if [[ -d "${input_dir}/images" ]]; then
	while IFS= read -r -d '' image; do
		ctr --address /run/containerd/containerd.sock --namespace k8s.io \
			images import --digests "${image}" >/dev/null
	done < <(find "${input_dir}/images" -type f -name '*.tar' -print0)
fi

python3 "${appliance_root}/scripts/submit_workload.py" \
	--input "${writable_workload}" \
	--images-output "${output_dir}/requested-images.txt" \
	--allow-unsafe-identity-delivery \
	--validate-only

while IFS= read -r image_ref; do
	digest=${image_ref##*@}
	if ctr --address /run/containerd/containerd.sock --namespace k8s.io \
		images list -q | grep -Fxq "${image_ref}"; then
		continue
	fi
	source_ref=$(
		ctr --address /run/containerd/containerd.sock --namespace k8s.io images list |
			awk -v digest="${digest}" 'NR > 1 && $3 == digest { print $1; exit }'
	)
	[[ -n "${source_ref}" ]] || {
		echo "no imported image has requested manifest digest ${digest}" >&2
		exit 1
	}
	ctr --address /run/containerd/containerd.sock --namespace k8s.io \
		images tag "${source_ref}" "${image_ref}" >/dev/null
done <"${output_dir}/requested-images.txt"

while IFS= read -r image_ref; do
	[[ "${image_ref}" == "${LOCAL_REGISTRY}/"* ]] || continue
	ctr --address /run/containerd/containerd.sock --namespace k8s.io \
		images push --plain-http "${image_ref}" >/dev/null
done < <(ctr --address /run/containerd/containerd.sock --namespace k8s.io images list -q)

settings_dir="${output_dir}/settings"
mkdir -p "${settings_dir}/genpolicy-settings.d"
cp /opt/genpolicy/policy/settings/genpolicy-settings.json "${settings_dir}/"
cp /opt/genpolicy/policy/settings/genpolicy-settings.d/*.json \
	"${settings_dir}/genpolicy-settings.d/"
python3 - \
	"${settings_dir}/genpolicy-settings.d/10-appliance.json" \
	"${PAUSE_IMAGE}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
patches = json.loads(path.read_text(encoding="utf-8"))
for patch in patches:
    if patch["path"] == "/cluster_config/pause_container_image":
        patch["value"] = sys.argv[2]
        break
else:
    raise SystemExit("appliance settings do not set pause_container_image")
path.write_text(json.dumps(patches, indent=2) + "\n", encoding="utf-8")
PY
# GENPOLICY_SETTINGS is loaded from the selected profile.
# shellcheck disable=SC2154
profile_settings="${appliance_root}/profiles/${GENPOLICY_SETTINGS}"
[[ -f "${profile_settings}" ]] || {
	echo "profile settings not found: ${profile_settings}" >&2
	exit 1
}
cp "${profile_settings}" "${settings_dir}/genpolicy-settings.d/20-profile.json"

genpolicy \
	--yaml-file "${writable_workload}" \
	--rego-rules-path /opt/genpolicy/policy/rules.rego \
	--json-settings-path "${settings_dir}" \
	--containerd-socket-path=/run/containerd/containerd.sock \
	--insecure-registry "${LOCAL_REGISTRY}" \
	--silent-unsupported-fields \
	--raw-out >"${output_dir}/policy.rego" \
	2>"${output_dir}/genpolicy.log"

test -s "${output_dir}/policy.rego"
