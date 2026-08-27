#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(dirname "$(readlink -f "$0")")"
manifest="${K8S_MANIFEST:-${script_dir}/e2e-k8s.yaml}"
pod_name="${K8S_POD_NAME:-openvmm-kata-e2e}"
expected_vps="${VP_COUNT:-2}"
keep_sandbox="${KEEP_SANDBOX:-no}"
image="${IMAGE:-docker.io/library/busybox:latest}"
pause_image="${PAUSE_IMAGE:-registry.k8s.io/pause:3.10.1}"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

for tool in crictl ctr grep kubectl pgrep systemctl; do
	command -v "${tool}" >/dev/null || die "required tool not found: ${tool}"
done
[[ -f "${manifest}" ]] || die "Kubernetes manifest does not exist: ${manifest}"
[[ "${expected_vps}" =~ ^[1-9][0-9]*$ ]] ||
	die "VP_COUNT must be a positive integer: ${expected_vps}"
systemctl is-active --quiet containerd || die "containerd is not active"
kubectl get --raw=/readyz >/dev/null || die "Kubernetes API is not ready"

cleanup()
{
	if [[ "${keep_sandbox}" == "yes" ]]; then
		echo "Keeping Kubernetes pod ${pod_name}"
		return
	fi
	kubectl delete pod "${pod_name}" --ignore-not-found --wait=false >/dev/null
}
trap cleanup EXIT

kubectl delete pod "${pod_name}" --ignore-not-found --wait=true >/dev/null
sudo ctr -n k8s.io images pull --local --snapshotter erofs \
	--platform linux/amd64 "${pause_image}" >/dev/null
sudo ctr -n k8s.io images pull --local --snapshotter erofs \
	--platform linux/amd64 "${image}" >/dev/null
kubectl apply -f "${manifest}" >/dev/null

if ! kubectl wait --for=condition=Ready "pod/${pod_name}" --timeout=300s; then
	kubectl describe pod "${pod_name}"
	kubectl get events --sort-by=.lastTimestamp | tail -30
	die "Kubernetes pod did not become ready"
fi

marker="$(kubectl exec "${pod_name}" -- sh -c 'printf OPENVMM_KUBERNETES_E2E_OK')"
[[ "${marker}" == "OPENVMM_KUBERNETES_E2E_OK" ]] ||
	die "container did not return the expected marker"
guest_vps="$(kubectl exec "${pod_name}" -- nproc)"
[[ "${guest_vps}" == "${expected_vps}" ]] ||
	die "guest has ${guest_vps} VPs, expected ${expected_vps}"
kernel="$(kubectl exec "${pod_name}" -- uname -r)"

container_id="$(
	sudo crictl ps \
		--label "io.kubernetes.pod.name=${pod_name}" \
		--name busybox -q |
		head -1
)"
[[ -n "${container_id}" ]] || die "CRI container ID was not found"
sudo ctr -n k8s.io snapshots --snapshotter erofs ls |
	grep -q "${container_id}" ||
	die "container does not have an active EROFS snapshot"
pgrep -f 'openvmm.*--ttrpc' >/dev/null || die "OpenVMM process was not found"
snp_dmesg="$(kubectl exec "${pod_name}" -- dmesg)"
grep -q 'Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP' \
	<<<"${snp_dmesg}" ||
	die "guest did not report SEV-SNP"

echo "OPENVMM_KUBERNETES_E2E_OK"
echo "  pod: ${pod_name}"
echo "  guest kernel: ${kernel}"
echo "  guest VPs: ${guest_vps}"
echo "  container: ${container_id}"
