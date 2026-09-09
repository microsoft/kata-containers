#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

readonly appliance_root="${GENPOLICY_APPLIANCE_ROOT:-/opt/genpolicy/appliance}"
readonly input_dir="${GENPOLICY_INPUT_DIR:-/input}"
readonly output_dir="${GENPOLICY_OUTPUT_DIR:-/output}"
readonly workload="${input_dir}/workload.yaml"

profile_name="${GENPOLICY_PROFILE_NAME:-k8s-1.36-containerd-2.3-erofs-dmverity}"
profile_path="${appliance_root}/profiles/${profile_name}.env"
[[ -f "${profile_path}" ]] || {
	echo "ERROR: unknown compatibility profile: ${profile_name}" >&2
	exit 1
}
# shellcheck source=/dev/null
source "${profile_path}"

pids=()
cleanup() {
	local pid
	for pid in "${pids[@]}"; do
		kill "${pid}" 2>/dev/null || true
	done
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

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
	fail "timed out waiting for ${description}"
}

[[ "$(id -u)" == "0" ]] || fail "the appliance must run as root"
[[ -f "${workload}" ]] || fail "${workload} is required"
[[ "$(stat -fc %T /sys/fs/cgroup)" == "cgroup2fs" ]] ||
	fail "cgroup v2 is required"
# ROOTFS_MODE is loaded from the selected profile.
# shellcheck disable=SC2154
case "${ROOTFS_MODE}" in
erofs-dmverity | guest-pull) ;;
*) fail "unsupported rootfs mode: ${ROOTFS_MODE}" ;;
esac
[[ "${GENPOLICY_NESTED_RUNTIME_ONLY:-0}" == "1" ]] ||
	fail "the appliance entrypoint is only supported through the nested harness"
[[ -n "${CONTAINERD_CONFIG:-}" ]] ||
	fail "CONTAINERD_CONFIG is required"

mkdir -p "${output_dir}/logs"

python3 "${appliance_root}/scripts/submit_workload.py" \
	--input "${workload}" \
	--images-output "${output_dir}/requested-images.txt" \
	--allow-unsafe-identity-delivery \
	--validate-only

install -D -m 0644 \
	"${appliance_root}/config/${CONTAINERD_CONFIG}" \
	/etc/containerd/config.toml
install -D -m 0644 \
	"${appliance_root}/config/kubelet.yaml" \
	/etc/kubernetes/kubelet.yaml
install -D -m 0644 \
	"${appliance_root}/config/10-genpolicy.conflist" \
	/etc/cni/net.d/10-genpolicy.conflist

# LOCAL_REGISTRY is loaded from the selected profile.
# shellcheck disable=SC2154
if [[ "${ROOTFS_MODE}" == "guest-pull" ]]; then
	registry_host=${LOCAL_REGISTRY%:*}
	ip link add genpolicy0 type bridge
	ip address add "${registry_host}/16" dev genpolicy0
	ip link set genpolicy0 up

	mkdir -p /etc/docker/registry /var/lib/registry
	cat >/etc/docker/registry/config.yml <<EOF
version: 0.1
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: ${LOCAL_REGISTRY}
  tls:
    certificate: /opt/genpolicy/registry-tls/registry.crt
    key: /opt/genpolicy/registry-tls/registry.key
EOF
	registry serve /etc/docker/registry/config.yml \
		>"${output_dir}/logs/registry.log" 2>&1 &
	pids+=("$!")
	wait_for registry curl -fsS \
		--cacert /opt/genpolicy/registry-tls/registry.crt \
		"https://${LOCAL_REGISTRY}/v2/"
fi

/lib/systemd/systemd-udevd --daemon
wait_for udev udevadm control --ping
python3 "${appliance_root}/scripts/watch_device_mapper_nodes.py" \
	>"${output_dir}/logs/device-mapper-nodes.log" 2>&1 &
pids+=("$!")

# LOCAL_REGISTRY is loaded from the selected profile.
# shellcheck disable=SC2154
mkdir -p "/etc/containerd/certs.d/${LOCAL_REGISTRY}"
cat >"/etc/containerd/certs.d/${LOCAL_REGISTRY}/hosts.toml" <<EOF
server = "https://${LOCAL_REGISTRY}"

[host."https://${LOCAL_REGISTRY}"]
  capabilities = ["pull", "resolve", "push"]
  ca = "/opt/genpolicy/registry-tls/registry.crt"
EOF

mkdir -p \
	/etc/kubernetes/pki \
	/var/lib/etcd \
	/var/lib/kubelet \
	/var/lib/containerd \
	/run/containerd
printf '127.0.0.1 genpolicy.local\n' >>/etc/hosts
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj "/CN=kube-apiserver" \
	-addext "subjectAltName=IP:127.0.0.1,DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc" \
	-keyout /etc/kubernetes/pki/apiserver.key \
	-out /etc/kubernetes/pki/apiserver.crt \
	>"${output_dir}/logs/openssl.log" 2>&1
openssl genrsa -out /etc/kubernetes/pki/sa.key 2048 \
	>>"${output_dir}/logs/openssl.log" 2>&1
openssl rsa -in /etc/kubernetes/pki/sa.key -pubout \
	-out /etc/kubernetes/pki/sa.pub \
	>>"${output_dir}/logs/openssl.log" 2>&1
printf '%s\n' \
	'genpolicy-clean-room-token,genpolicy,1000,"system:masters"' \
	>/etc/kubernetes/token.csv

etcd \
	--data-dir=/var/lib/etcd \
	--listen-client-urls=http://127.0.0.1:2379 \
	--advertise-client-urls=http://127.0.0.1:2379 \
	>"${output_dir}/logs/etcd.log" 2>&1 &
pids+=("$!")
wait_for etcd etcdctl --endpoints=http://127.0.0.1:2379 endpoint health

kube-apiserver \
	--advertise-address="$(hostname -i | awk '{print $1}')" \
	--allow-privileged=true \
	--anonymous-auth=true \
	--authorization-mode=AlwaysAllow \
	--disable-admission-plugins=DefaultStorageClass,DefaultTolerationSeconds,ServiceAccount \
	--etcd-servers=http://127.0.0.1:2379 \
	--feature-gates=ContainerStopSignals=true \
	--kubelet-preferred-address-types=InternalIP,Hostname \
	--secure-port=6443 \
	--service-account-issuer=https://kubernetes.default.svc \
	--service-account-key-file=/etc/kubernetes/pki/sa.pub \
	--service-account-signing-key-file=/etc/kubernetes/pki/sa.key \
	--service-cluster-ip-range=10.96.0.0/12 \
	--tls-cert-file=/etc/kubernetes/pki/apiserver.crt \
	--tls-private-key-file=/etc/kubernetes/pki/apiserver.key \
	--token-auth-file=/etc/kubernetes/token.csv \
	>"${output_dir}/logs/kube-apiserver.log" 2>&1 &
pids+=("$!")
wait_for kube-apiserver curl -kfsS \
	-H 'Authorization: Bearer genpolicy-clean-room-token' \
	https://127.0.0.1:6443/livez

cat >/etc/kubernetes/kubeconfig <<'EOF'
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
users:
- name: genpolicy
  user:
    token: genpolicy-clean-room-token
contexts:
- name: local
  context:
    cluster: local
    user: genpolicy
current-context: local
EOF
export KUBECONFIG=/etc/kubernetes/kubeconfig

kubectl get namespace default >/dev/null 2>&1 ||
	kubectl create namespace default >/dev/null
kubectl get namespace kube-system >/dev/null 2>&1 ||
	kubectl create namespace kube-system >/dev/null
cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
handler: kata
EOF

containerd --config /etc/containerd/config.toml \
	>"${output_dir}/logs/containerd.log" 2>&1 &
pids+=("$!")
wait_for containerd ctr --address /run/containerd/containerd.sock version

ctr --address /run/containerd/containerd.sock --namespace k8s.io images import \
	--digests /opt/genpolicy/images/pause.tar >/dev/null
# PAUSE_IMAGE is loaded from the selected profile.
# shellcheck disable=SC2154
if [[ "${PAUSE_IMAGE}" != "genpolicy.local:5000/pause:3.10" ]]; then
	ctr --address /run/containerd/containerd.sock --namespace k8s.io \
		images tag "genpolicy.local:5000/pause:3.10" "${PAUSE_IMAGE}" >/dev/null
fi
image_archives=(/opt/genpolicy/images/busybox.tar)
if [[ -d "${input_dir}/images" ]]; then
	while IFS= read -r -d '' image; do
		image_archives+=("${image}")
	done < <(find "${input_dir}/images" -type f -name '*.tar' -print0)
fi

referenced_image_dir=/run/genpolicy-requested-images
mkdir -p "${referenced_image_dir}"
image_number=0
while IFS= read -r image_ref; do
	referenced_archive="${referenced_image_dir}/requested-image-${image_number}.tar"
	if python3 "${appliance_root}/scripts/reference_oci_image.py" \
		--reference "${image_ref}" \
		--output "${referenced_archive}" \
		"${image_archives[@]}"; then
		ctr --address /run/containerd/containerd.sock --namespace k8s.io images import \
			"${referenced_archive}" >/dev/null
	else
		[[ "${image_ref}" != "${LOCAL_REGISTRY}/"* ]] ||
			fail "no imported image has requested manifest digest ${image_ref##*@}"
		ctr --address /run/containerd/containerd.sock --namespace k8s.io \
			images pull --hosts-dir /etc/containerd/certs.d "${image_ref}" >/dev/null
	fi
	image_number=$((image_number + 1))
done <"${output_dir}/requested-images.txt"

if [[ "${ROOTFS_MODE}" == "guest-pull" ]]; then
	while IFS= read -r image_ref; do
		[[ "${image_ref}" == "${LOCAL_REGISTRY}/"* ]] || continue
		ctr --address /run/containerd/containerd.sock --namespace k8s.io \
			images push --hosts-dir /etc/containerd/certs.d "${image_ref}" >/dev/null
	done < <(ctr --address /run/containerd/containerd.sock --namespace k8s.io images list -q)
fi

iptables --flush OUTPUT
iptables --append OUTPUT --out-interface lo --jump ACCEPT
if [[ "${ROOTFS_MODE}" == "guest-pull" ]]; then
	iptables --append OUTPUT --out-interface genpolicy0 \
		--protocol tcp --source-port 5000 --destination 10.188.0.0/16 \
		--match conntrack --ctstate ESTABLISHED --jump ACCEPT
fi
iptables --policy OUTPUT DROP
iptables --flush FORWARD
iptables --policy FORWARD DROP
ip6tables --flush OUTPUT
ip6tables --append OUTPUT --out-interface lo --jump ACCEPT
ip6tables --policy OUTPUT DROP
ip6tables --flush FORWARD
ip6tables --policy FORWARD DROP
[[ "$(iptables --list-rules OUTPUT | head -n 1)" == "-P OUTPUT DROP" ]] ||
	fail "failed to seal IPv4 outbound traffic"
iptables --check OUTPUT --out-interface lo --jump ACCEPT
if [[ "${ROOTFS_MODE}" == "guest-pull" ]]; then
	iptables --check OUTPUT --out-interface genpolicy0 \
		--protocol tcp --source-port 5000 --destination 10.188.0.0/16 \
		--match conntrack --ctstate ESTABLISHED --jump ACCEPT
fi
[[ "$(iptables --list-rules FORWARD | head -n 1)" == "-P FORWARD DROP" ]] ||
	fail "failed to seal IPv4 forwarded traffic"
[[ "$(ip6tables --list-rules OUTPUT | head -n 1)" == "-P OUTPUT DROP" ]] ||
	fail "failed to seal IPv6 outbound traffic"
ip6tables --check OUTPUT --out-interface lo --jump ACCEPT
[[ "$(ip6tables --list-rules FORWARD | head -n 1)" == "-P FORWARD DROP" ]] ||
	fail "failed to seal IPv6 forwarded traffic"

# NODE_NAME is loaded from the selected profile.
# shellcheck disable=SC2154
kubelet \
	--config=/etc/kubernetes/kubelet.yaml \
	--hostname-override="${NODE_NAME}" \
	--kubeconfig=/etc/kubernetes/kubeconfig \
	--node-ip="$(hostname -i | awk '{print $1}')" \
	--root-dir=/var/lib/kubelet \
	>"${output_dir}/logs/kubelet.log" 2>&1 &
pids+=("$!")
wait_for kubelet-node kubectl get "node/${NODE_NAME}"

python3 "${appliance_root}/scripts/submit_workload.py" \
	--input "${workload}" \
	--allow-unsafe-identity-delivery \
	--node-name "${NODE_NAME}" \
	--objects-output "${output_dir}/submitted-objects.json" \
	--pods-output "${output_dir}/pods.json" \
	--dynamic-output "${output_dir}/dynamic-values.json"

while IFS=$'\t' read -r namespace pod_name; do
	kubectl wait \
		--namespace "${namespace}" \
		--for=condition=Ready \
		--timeout="${GENPOLICY_POD_READY_TIMEOUT:-180s}" \
		"pod/${pod_name}"
done < <(python3 - "${output_dir}/pods.json" <<'PY'
import json
import sys

for pod in json.load(open(sys.argv[1], encoding="utf-8")):
    metadata = pod["metadata"]
    print(metadata.get("namespace", "default"), metadata["name"], sep="\t")
PY
)

kubectl get pods --all-namespaces -o json \
	>"${output_dir}/pod-status-ready.json"
python3 "${appliance_root}/scripts/exercise_runtime_operations.py" \
	--pods "${output_dir}/pods.json" \
	--containerd-version "$(containerd --version)" \
	--output "${output_dir}/runtime-operations.json"

while sleep 3600; do
	:
done
