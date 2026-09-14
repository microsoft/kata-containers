#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

readonly engine=${CONTAINER_ENGINE:?CONTAINER_ENGINE is required}
readonly genpolicy_bin=${GENPOLICY_BIN:?GENPOLICY_BIN is required}
readonly erofs_bundle=${GENPOLICY_EROFS_BUNDLE_DIR:?GENPOLICY_EROFS_BUNDLE_DIR is required}
readonly erofs_utils_version=${EROFS_UTILS_VERSION:?EROFS_UTILS_VERSION is required}
readonly profile_file=${PROFILE_FILE:?PROFILE_FILE is required}
readonly repo_root=${REPO_ROOT:?REPO_ROOT is required}
readonly input_dir=${GENPOLICY_INPUT_DIR:?GENPOLICY_INPUT_DIR is required}
readonly output_dir=${GENPOLICY_OUTPUT_DIR:?GENPOLICY_OUTPUT_DIR is required}
readonly reference_images_dir=${GENPOLICY_REFERENCE_IMAGES_DIR:?GENPOLICY_REFERENCE_IMAGES_DIR is required}
readonly layer_cache=${GENPOLICY_LAYER_CACHE:-${output_dir}/layers-cache.json}
readonly workload=${input_dir}/workload.yaml
readonly harness_root=${repo_root}/src/tools/genpolicy/nested-policy-compat
readonly registry_image=${GENPOLICY_REGISTRY_IMAGE:-docker.io/library/registry:2.8.3}
export GENPOLICY_EROFS_BUNDLE_DIR="${erofs_bundle}"

work_dir=$(mktemp -d)
registry_container=
cleanup() {
	if [[ -n "${registry_container}" ]]; then
		"${engine}" rm -f "${registry_container}" >/dev/null 2>&1 || true
	fi
	rm -rf "${work_dir}"
}
trap cleanup EXIT

[[ -x "${engine}" ]] || {
	echo "container engine not found or not executable: ${engine}" >&2
	exit 1
}
[[ -x "${genpolicy_bin}" ]] || {
	echo "GenPolicy binary not found or not executable: ${genpolicy_bin}" >&2
	exit 1
}
readonly mkfs_erofs_wrapper=${harness_root}/scripts/run_pinned_mkfs_erofs.sh
[[ -x "${mkfs_erofs_wrapper}" ]] || {
	echo "pinned mkfs.erofs wrapper not found: ${mkfs_erofs_wrapper}" >&2
	exit 1
}
[[ -x "${erofs_bundle}/bin/mkfs.erofs" ]] || {
	echo "pinned mkfs.erofs runtime bundle not found: ${erofs_bundle}" >&2
	exit 1
}
actual_erofs_version=$("${mkfs_erofs_wrapper}" --version 2>&1 | head -n 1)
[[ "${actual_erofs_version}" == *" ${erofs_utils_version}" ]] || {
	echo "mkfs.erofs version mismatch: expected ${erofs_utils_version}, got ${actual_erofs_version}" >&2
	exit 1
}
erofs_runtime_fingerprint=$(
	find "${erofs_bundle}" -type f -print0 |
		sort -z |
		xargs -0 sha256sum |
		sha256sum |
		cut -d ' ' -f 1
)
export GENPOLICY_EROFS_RUNTIME_FINGERPRINT="${erofs_runtime_fingerprint}"
wrapper_dir="${work_dir}/bin"
mkdir -p "${wrapper_dir}"
ln -s "${mkfs_erofs_wrapper}" "${wrapper_dir}/mkfs.erofs"
PATH="${wrapper_dir}:${PATH}"
export PATH
command -v skopeo >/dev/null 2>&1 || {
	echo "skopeo is required to publish fixture images without changing their digests" >&2
	exit 1
}
[[ -f "${profile_file}" ]] || {
	echo "profile file not found: ${profile_file}" >&2
	exit 1
}
[[ -f "${workload}" ]] || {
	echo "${workload} is required" >&2
	exit 1
}
[[ -d "${reference_images_dir}" ]] || {
	echo "reference image directory not found: ${reference_images_dir}" >&2
	exit 1
}

# shellcheck source=/dev/null
source "${profile_file}"

wait_for_registry() {
	local endpoint=$1
	local _
	for _ in $(seq 1 120); do
		if curl -fsS "http://${endpoint}/v2/" >/dev/null 2>&1; then
			return
		fi
		sleep 1
	done
	echo "timed out waiting for host generation registry ${endpoint}" >&2
	exit 1
}

registry_port=$(
	python3 - <<'PY'
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)
readonly host_registry="127.0.0.1:${registry_port}"
registry_container=$(
	"${engine}" run --detach --rm \
		--publish "127.0.0.1:${registry_port}:5000" \
		"${registry_image}"
)
wait_for_registry "${host_registry}"

mkdir -p "${output_dir}" "${work_dir}/settings/genpolicy-settings.d"
cp "${workload}" "${output_dir}/workload.yaml"
readonly writable_workload=${output_dir}/workload.yaml

# ROOTFS_MODE, LOCAL_REGISTRY, and CONTAINERD_VERSION are profile inputs.
# shellcheck disable=SC2154
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

python3 "${harness_root}/appliance/scripts/submit_workload.py" \
	--input "${writable_workload}" \
	--images-output "${work_dir}/requested-images.txt" \
	--allow-unsafe-identity-delivery \
	--validate-only
# PAUSE_IMAGE is loaded from the profile and is also resolved by GenPolicy.
# shellcheck disable=SC2154
printf '%s\n' "${PAUSE_IMAGE}" >>"${work_dir}/requested-images.txt"
sort -u -o "${work_dir}/requested-images.txt" "${work_dir}/requested-images.txt"

map_file="${work_dir}/registry-map.tsv"
: >"${map_file}"
image_index=0
while IFS= read -r image_ref; do
	if [[ "${image_ref}" == "${LOCAL_REGISTRY}/"* ]]; then
		image_path=${image_ref#"${LOCAL_REGISTRY}/"}
	else
		image_path=${image_ref}
	fi
	if [[ "${image_ref}" == *@sha256:* ]]; then
		repository=${image_path%@*}
		[[ "${image_ref}" == "${LOCAL_REGISTRY}/"* ]] ||
			repository="fixture-${image_index}"
		image_suffix="@${image_path##*@}"
		generation_ref="${host_registry}/${repository}${image_suffix}"
		temporary_tag="${host_registry}/${repository}:nested-policy-${$}-${image_index}"
	else
		[[ "${image_ref}" == "${LOCAL_REGISTRY}/"* ]] || {
			echo "non-local compatibility image is not digest-pinned: ${image_ref}" >&2
			exit 1
		}
		repository=${image_path%:*}
		image_suffix=":${image_path##*:}"
		generation_ref="${host_registry}/${repository}${image_suffix}"
		temporary_tag="${generation_ref}"
	fi
	target_archive="${work_dir}/requested-image-${image_index}.tar"
	source_reference=${image_ref/"${LOCAL_REGISTRY}"/genpolicy.local:5000}
	if [[ "${source_reference}" == *@sha256:* ]]; then
		python3 "${harness_root}/appliance/scripts/reference_oci_image.py" \
			--reference "${source_reference}" \
			--output "${target_archive}" \
			"${reference_images_dir}"/*.tar
	else
		target_archive=$(
			python3 - "${source_reference}" "${reference_images_dir}"/*.tar <<'PY'
import json
import sys
import tarfile

reference = sys.argv[1]
for archive in sys.argv[2:]:
    with tarfile.open(archive) as stream:
        index = json.load(stream.extractfile("index.json"))
    if any(
        descriptor.get("annotations", {}).get("org.opencontainers.image.ref.name")
        == reference
        for descriptor in index.get("manifests", [])
    ):
        print(archive)
        break
else:
    raise SystemExit(f"no OCI archive contains tagged reference {reference}")
PY
		)
	fi

	skopeo copy \
		--preserve-digests \
		--dest-tls-verify=false \
		"oci-archive:${target_archive}" \
		"docker://${temporary_tag}" >/dev/null
	printf '%s\t%s\n' "${image_ref}" "${generation_ref}" >>"${map_file}"
	image_index=$((image_index + 1))
done <"${work_dir}/requested-images.txt"

python3 - "${writable_workload}" "${map_file}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
for line in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    original, replacement = line.split("\t", 1)
    text = text.replace(original, replacement)
path.write_text(text, encoding="utf-8")
PY

cp "${repo_root}/src/tools/genpolicy/genpolicy-settings.json" \
	"${work_dir}/settings/"
cp "${harness_root}/appliance/policy-settings.d/"*.json \
	"${work_dir}/settings/genpolicy-settings.d/"
# GENPOLICY_SETTINGS is loaded from the selected profile.
# shellcheck disable=SC2154
profile_settings="${harness_root}/appliance/profiles/${GENPOLICY_SETTINGS}"
[[ -f "${profile_settings}" ]] || {
	echo "profile settings not found: ${profile_settings}" >&2
	exit 1
}
cp "${profile_settings}" \
	"${work_dir}/settings/genpolicy-settings.d/20-profile.json"

pause_generation_ref=$(
	awk -F '\t' -v image="${PAUSE_IMAGE}" '$1 == image { print $2; exit }' "${map_file}"
)
[[ -n "${pause_generation_ref}" ]] || {
	echo "pause image was not published to the host registry: ${PAUSE_IMAGE}" >&2
	exit 1
}
python3 - \
	"${work_dir}/settings/genpolicy-settings.d/10-appliance.json" \
	"${pause_generation_ref}" <<'PY'
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

cp "${repo_root}/src/tools/genpolicy/rules.rego" "${work_dir}/rules.rego"
printf '\n' >>"${work_dir}/rules.rego"
cat "${harness_root}/tests/policy/create-sandbox-reasons.rego.inc" \
	>>"${work_dir}/rules.rego"

"${genpolicy_bin}" \
	--yaml-file "${writable_workload}" \
	--rego-rules-path "${work_dir}/rules.rego" \
	--json-settings-path "${work_dir}/settings" \
	--insecure-registry "${host_registry}" \
	--layers-cache-file-path="${layer_cache}" \
	--silent-unsupported-fields \
	--raw-out >"${output_dir}/policy.rego" \
	2>"${output_dir}/genpolicy.log"

python3 - \
	"${output_dir}/workload.yaml" "${output_dir}/policy.rego" \
	"${map_file}" <<'PY'
import sys
from pathlib import Path

for name in sys.argv[1:3]:
    path = Path(name)
    text = path.read_text(encoding="utf-8")
    for line in Path(sys.argv[3]).read_text(encoding="utf-8").splitlines():
        original, replacement = line.split("\t", 1)
        text = text.replace(replacement, original)
    path.write_text(text, encoding="utf-8")
PY

{
	sha256sum "${genpolicy_bin}" "${work_dir}/rules.rego"
	find "${work_dir}/settings" -type f -print0 |
		sort -z |
		xargs -0 sha256sum
} >"${output_dir}/generation-inputs.sha256"

test -s "${output_dir}/policy.rego"
