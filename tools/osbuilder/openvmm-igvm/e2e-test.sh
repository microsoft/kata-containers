#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(dirname "$(readlink -f "$0")")"
runtime_endpoint="${RUNTIME_ENDPOINT:-unix:///run/containerd/containerd.sock}"
image_endpoint="${IMAGE_ENDPOINT:-${runtime_endpoint}}"
runtime_handler="${RUNTIME_HANDLER:-kata-cc}"
image="${IMAGE:-docker.io/library/busybox:latest}"
pause_image="${PAUSE_IMAGE:-registry.k8s.io/pause:3.10.1}"
request_timeout="${CRI_REQUEST_TIMEOUT:-120s}"
keep_sandbox="${KEEP_SANDBOX:-no}"
expected_vps="${VP_COUNT:-2}"
# The direct CRI path does not invoke a CNI plugin, so the fixtures deliberately
# use NamespaceMode::NODE and share the host network namespace.
pod_config="${POD_CONFIG:-${script_dir}/e2e-pod.json}"
container_config="${CONTAINER_CONFIG:-${script_dir}/e2e-container.json}"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

for tool in crictl ctr grep pgrep systemctl; do
	command -v "${tool}" >/dev/null || die "required tool not found: ${tool}"
done
[[ -f "${pod_config}" ]] || die "pod config does not exist: ${pod_config}"
[[ -f "${container_config}" ]] || die "container config does not exist: ${container_config}"
systemctl is-active --quiet containerd || die "containerd is not active"
[[ "${expected_vps}" =~ ^[1-9][0-9]*$ ]] ||
	die "VP_COUNT must be a positive integer: ${expected_vps}"

cri=(
	sudo crictl
	--runtime-endpoint "${runtime_endpoint}"
	--image-endpoint "${image_endpoint}"
)
pod_id=""
container_id=""

cleanup()
{
	if [[ "${keep_sandbox}" == "yes" ]]; then
		echo "Keeping pod ${pod_id} and container ${container_id}"
		return
	fi
	if [[ -n "${container_id}" ]]; then
		"${cri[@]}" stop "${container_id}" >/dev/null 2>&1 || true
		"${cri[@]}" rm "${container_id}" >/dev/null 2>&1 || true
	fi
	if [[ -n "${pod_id}" ]]; then
		"${cri[@]}" stopp "${pod_id}" >/dev/null 2>&1 || true
		"${cri[@]}" rmp "${pod_id}" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

sudo ctr -n k8s.io images pull \
	--local \
	--snapshotter erofs \
	--platform linux/amd64 \
	"${pause_image}" >/dev/null
sudo ctr -n k8s.io images pull \
	--local \
	--snapshotter erofs \
	--platform linux/amd64 \
	"${image}" >/dev/null
pod_id="$(
	"${cri[@]}" runp \
		--cancel-timeout "${request_timeout}" \
		--runtime "${runtime_handler}" \
		"${pod_config}"
)"
[[ -n "${pod_id}" ]] || die "CRI did not return a pod ID"

container_id="$(
	"${cri[@]}" create \
		--cancel-timeout "${request_timeout}" \
		--no-pull \
		"${pod_id}" \
		"${container_config}" \
		"${pod_config}"
)"
[[ -n "${container_id}" ]] || die "CRI did not return a container ID"
"${cri[@]}" start "${container_id}" >/dev/null

marker="$(
	"${cri[@]}" exec "${container_id}" \
		sh -c 'printf "%s\n" OPENVMM_EROFS_CONTAINER_OK'
)"
[[ "${marker}" == "OPENVMM_EROFS_CONTAINER_OK" ]] ||
	die "container did not return the expected marker"

kernel="$("${cri[@]}" exec "${container_id}" uname -r)"
root_mount="$("${cri[@]}" exec "${container_id}" sh -c 'mount | head -n 1')"
guest_vps="$("${cri[@]}" exec "${container_id}" nproc)"
[[ "${guest_vps}" == "${expected_vps}" ]] ||
	die "guest has ${guest_vps} VPs, expected ${expected_vps}"

sudo ctr -n k8s.io snapshots --snapshotter erofs ls |
	grep -q "${container_id}" ||
	die "container does not have an active EROFS snapshot"

openvmm_pid="$(
	pgrep -f "openvmm.*${pod_id}" 2>/dev/null | head -n 1 || true
)"
if [[ -z "${openvmm_pid}" ]]; then
	openvmm_pid="$(pgrep -f 'openvmm.*--ttrpc' 2>/dev/null | head -n 1 || true)"
fi
[[ -n "${openvmm_pid}" ]] || die "OpenVMM process was not found"

echo "OPENVMM_KATACC_E2E_OK"
echo "  pod: ${pod_id}"
echo "  container: ${container_id}"
echo "  guest kernel: ${kernel}"
echo "  guest VPs: ${guest_vps}"
echo "  container root: ${root_mount}"
echo "  OpenVMM pid: ${openvmm_pid}"
