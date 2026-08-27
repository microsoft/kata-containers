#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

kubernetes_version="${KUBERNETES_VERSION:-v1.32.0}"
cni_version="${CNI_VERSION:-v1.6.2}"
pod_cidr="${POD_CIDR:-10.244.0.0/16}"
arch="${ARCH:-amd64}"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

for tool in curl install sha256sum systemctl tar; do
	command -v "${tool}" >/dev/null || die "required tool not found: ${tool}"
done
systemctl is-active --quiet containerd || die "containerd is not active"

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "${tmp_dir}"' EXIT

for binary in kubeadm kubelet kubectl; do
	url="https://dl.k8s.io/release/${kubernetes_version}/bin/linux/${arch}/${binary}"
	curl --fail --location --retry 3 --output "${tmp_dir}/${binary}" "${url}"
	curl --fail --location --retry 3 \
		--output "${tmp_dir}/${binary}.sha256" "${url}.sha256"
	printf '%s  %s\n' \
		"$(<"${tmp_dir}/${binary}.sha256")" "${tmp_dir}/${binary}" |
		sha256sum --check -
	sudo install -m 0755 "${tmp_dir}/${binary}" "/usr/local/bin/${binary}"
done

cni_archive="cni-plugins-linux-${arch}-${cni_version}.tgz"
cni_url="https://github.com/containernetworking/plugins/releases/download/${cni_version}"
curl --fail --location --retry 3 \
	--output "${tmp_dir}/${cni_archive}" "${cni_url}/${cni_archive}"
curl --fail --location --retry 3 \
	--output "${tmp_dir}/${cni_archive}.sha256" \
	"${cni_url}/${cni_archive}.sha256"
(
	cd "${tmp_dir}"
	sha256sum --check "${cni_archive}.sha256"
)
sudo mkdir -p /opt/cni/bin /etc/cni/net.d \
	/etc/systemd/system/kubelet.service.d
sudo tar -C /opt/cni/bin -xzf "${tmp_dir}/${cni_archive}"

service_file="$(mktemp)"
kubeadm_dropin="$(mktemp)"
cni_config="$(mktemp)"
trap 'rm -rf -- "${tmp_dir}"; rm -f -- "${service_file}" "${kubeadm_dropin}" "${cni_config}"' EXIT

cat >"${service_file}" <<'EOF'
[Unit]
Description=kubelet: The Kubernetes Node Agent
Documentation=https://kubernetes.io/docs/
Wants=network-online.target
After=network-online.target containerd.service

[Service]
ExecStart=/usr/local/bin/kubelet
Restart=always
StartLimitInterval=0
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

cat >"${kubeadm_dropin}" <<'EOF'
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
EnvironmentFile=-/etc/default/kubelet
ExecStart=
ExecStart=/usr/local/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
EOF

cat >"${cni_config}" <<EOF
{
  "cniVersion": "1.0.0",
  "name": "kata-bridge",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "ipMasq": true,
      "hairpinMode": true,
      "ipam": {
        "type": "host-local",
        "ranges": [[{"subnet": "${pod_cidr}"}]],
        "routes": [{"dst": "0.0.0.0/0"}]
      }
    },
    {"type": "portmap", "capabilities": {"portMappings": true}}
  ]
}
EOF

sudo install -m 0644 "${service_file}" /etc/systemd/system/kubelet.service
sudo install -m 0644 "${kubeadm_dropin}" \
	/etc/systemd/system/kubelet.service.d/10-kubeadm.conf
sudo install -m 0644 "${cni_config}" /etc/cni/net.d/10-kata-bridge.conflist
sudo modprobe overlay
sudo modprobe br_netfilter
printf '%s\n' overlay br_netfilter |
	sudo tee /etc/modules-load.d/k8s.conf >/dev/null
printf '%s\n' \
	'net.bridge.bridge-nf-call-iptables = 1' \
	'net.bridge.bridge-nf-call-ip6tables = 1' \
	'net.ipv4.ip_forward = 1' |
	sudo tee /etc/sysctl.d/99-kubernetes-cri.conf >/dev/null
sudo sysctl --system >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable kubelet >/dev/null

if [[ ! -f /etc/kubernetes/admin.conf ]]; then
	sudo kubeadm init \
		--kubernetes-version "${kubernetes_version}" \
		--cri-socket unix:///run/containerd/containerd.sock \
		--pod-network-cidr "${pod_cidr}"
fi

mkdir -p "${HOME}/.kube"
sudo cp /etc/kubernetes/admin.conf "${HOME}/.kube/config"
sudo chown "$(id -u):$(id -g)" "${HOME}/.kube/config"
kubectl taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true
kubectl wait --for=condition=Ready node --all --timeout=120s
kubectl get nodes -o wide
