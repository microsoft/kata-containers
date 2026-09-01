#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(dirname "$(readlink -f "$0")")"
repo_dir="$(readlink -f "${script_dir}/../../..")"
runtime_dir="${repo_dir}/src/runtime-rs"
openvmm_dir="${OPENVMM_DIR:-${HOME}/openvmm-snp-mshv-aci-igvm}"
openvmm="${OPENVMM:-${openvmm_dir}/target/release/openvmm}"
vp_count="${VP_COUNT:-2}"
default_workload_vcpus=1
((vp_count > default_workload_vcpus)) ||
	die "VP_COUNT must exceed the default workload vCPU count (${default_workload_vcpus})"
base_vcpus=$((vp_count - default_workload_vcpus))
out_dir="${OUT_DIR:-${script_dir}/out}"
kernel_override="${KERNEL:-}"
kata_image_override="${KATA_IMAGE:-}"
root_hash_override="${ROOT_HASH_FILE:-}"
igvm_override="${IGVM:-}"
igvm="${IGVM:-${out_dir}/kata-aci-agent-dmverity-reserve-416b-${vp_count}vp.bin}"
kernel_src="${KERNEL_SRC:-}"
kernel_config="${KERNEL_CONFIG:-${script_dir}/kernel.config}"
kernel_build_dir="${KERNEL_BUILD_DIR:-${out_dir}/kernel}"
kernel="${KERNEL:-${kernel_build_dir}/arch/x86/boot/bzImage}"
kata_image="${KATA_IMAGE:-${out_dir}/kata-containers.img}"
root_hash_file="${ROOT_HASH_FILE:-${out_dir}/root_hash_.txt}"
runtime_config="${RUNTIME_CONFIG:-${out_dir}/configuration-openvmm-snp-runtime-rs.toml}"
shim_path="${SHIM_PATH:-/usr/local/bin/containerd-shim-kata-cc-v2}"
containerd_config="${CONTAINERD_CONFIG:-/etc/containerd/config-openvmm.toml}"
containerd_dropin="${CONTAINERD_DROPIN:-/etc/systemd/system/containerd.service.d/20-kata-openvmm.conf}"
crictl_config="${CRICTL_CONFIG:-/etc/crictl.yaml}"
configure_containerd="${CONFIGURE_CONTAINERD:-yes}"
network_model="${NETWORK_MODEL:-none}"
disable_new_netns="${DISABLE_NEW_NETNS:-yes}"
agent_policy="${AGENT_POLICY:-yes}"
agent_policy_file="${AGENT_POLICY_FILE:-${repo_dir}/src/kata-opa/allow-all.rego}"
strict_policy="${STRICT_POLICY:-no}"

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

for tool in awk cargo containerd crictl install jq make modprobe systemctl; do
	command -v "${tool}" >/dev/null || die "required tool not found: ${tool}"
done
[[ "${vp_count}" =~ ^[1-9][0-9]*$ ]] ||
	die "VP_COUNT must be a positive integer: ${vp_count}"
[[ "${disable_new_netns}" == "yes" || "${disable_new_netns}" == "no" ]] ||
	die "DISABLE_NEW_NETNS must be yes or no: ${disable_new_netns}"

[[ -e /dev/mshv ]] || die "/dev/mshv is not available"
[[ -d "${openvmm_dir}/.git" ]] || die "OpenVMM checkout does not exist: ${openvmm_dir}"
[[ -f "${runtime_dir}/Makefile" ]] || die "runtime-rs source does not exist: ${runtime_dir}"
grep -q '^message IgvmBoot' \
	"${openvmm_dir}/openvmm/openvmm_ttrpc_vmservice/src/vmservice.proto" ||
	die "OpenVMM checkout does not contain the IGVM VM-service extension"

mkdir -p "${out_dir}" "$(dirname "${runtime_config}")"

if [[ -n "${kernel_override}" ]]; then
	[[ -f "${kernel}" ]] || die "prebuilt kernel does not exist: ${kernel}"
elif [[ ! -f "${kernel}" ]]; then
	[[ -n "${kernel_src}" ]] ||
		die "set KERNEL_SRC or provide a prebuilt KERNEL"
	make -C "${script_dir}" kernel \
		KERNEL_SRC="${kernel_src}" \
		KERNEL_CONFIG="${kernel_config}" \
		KERNEL_BUILD_DIR="${kernel_build_dir}" \
		OUT_DIR="${out_dir}"
fi

if [[ -n "${kata_image_override}" || -n "${root_hash_override}" ]]; then
	[[ -n "${kata_image_override}" && -n "${root_hash_override}" ]] ||
		die "KATA_IMAGE and ROOT_HASH_FILE must be provided together"
	[[ -f "${kata_image}" ]] || die "prebuilt Kata image does not exist: ${kata_image}"
	[[ -f "${root_hash_file}" ]] ||
		die "prebuilt dm-verity metadata does not exist: ${root_hash_file}"
elif [[ ! -f "${kata_image}" || ! -f "${root_hash_file}" ]]; then
	make -C "${script_dir}" guest-image \
		OUT_DIR="${out_dir}" \
		AGENT_POLICY="${agent_policy}" \
		AGENT_POLICY_FILE="${agent_policy_file}" \
		STRICT_POLICY="${strict_policy}" \
		KATA_IMAGE="${kata_image}" \
		ROOT_HASH_FILE="${root_hash_file}"
fi
[[ -f "${kata_image}" ]] || die "Kata image was not built: ${kata_image}"
[[ -f "${root_hash_file}" ]] ||
	die "dm-verity metadata was not built: ${root_hash_file}"

make -C "${script_dir}" openvmm OPENVMM_DIR="${openvmm_dir}"

if [[ -n "${igvm_override}" && ! -f "${igvm}" ]]; then
	die "prebuilt IGVM does not exist: ${igvm}"
fi
if [[ -z "${igvm_override}" &&
	(! -f "${igvm}" || "${REBUILD_IGVM:-no}" == "yes") ]]; then
	make -C "${script_dir}" agent-dmverity-igvm \
		OPENVMM_DIR="${openvmm_dir}" \
		KERNEL="${kernel}" \
		ROOT_HASH_FILE="${root_hash_file}" \
		VP_COUNT="${vp_count}" \
		OUT_DIR="${out_dir}"
fi
[[ -f "${igvm}" ]] || die "IGVM was not built: ${igvm}"

make -B -C "${runtime_dir}" \
	HYPERVISOR=openvmm-runtime-rs \
	OPENVMMPATH="${openvmm}" \
	IGVMPATH_OPENVMM_SNP="${igvm}" \
	IMAGEPATH_OPENVMM_AZURE="${kata_image}" \
	DEFNETWORKMODEL_OPENVMM="${network_model}" \
	DEFSTATICSANDBOXWORKLOADVCPUS="${default_workload_vcpus}" \
	crates/shim/src/config.rs \
	config/configuration-openvmm-snp-runtime-rs.toml

(
	cd "${repo_dir}"
	CARGO_PROFILE_RELEASE_LTO=true \
	CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
	RUSTFLAGS="--deny warnings" \
		cargo build --release -p runtime-rs --features openvmm
)

generated_config="${runtime_dir}/config/configuration-openvmm-snp-runtime-rs.toml"
sed_args=(-e "s/^default_vcpus = .*/default_vcpus = ${base_vcpus}/")
if [[ "${disable_new_netns}" == "yes" ]]; then
	sed_args+=(-e 's/^disable_new_netns = false$/disable_new_netns = true/')
fi
sed "${sed_args[@]}" "${generated_config}" >"${runtime_config}"

shim="${repo_dir}/target/release/containerd-shim-kata-v2"
[[ -x "${shim}" ]] || die "runtime-rs shim was not built: ${shim}"

sudo install -D -m 0755 "${shim}" "${shim_path}"

if [[ "${configure_containerd}" == "no" ]]; then
	echo "Installed OpenVMM Kata runtime:"
	echo "  OpenVMM: ${openvmm}"
	echo "  IGVM: ${igvm}"
	echo "  VPs: ${vp_count}"
	echo "  Kata image: ${kata_image}"
	echo "  Shim: ${shim_path}"
	echo "  Runtime config: ${runtime_config}"
	exit 0
fi
[[ "${configure_containerd}" == "yes" ]] ||
	die "CONFIGURE_CONTAINERD must be yes or no: ${configure_containerd}"

containerd_tmp="$(mktemp)"
dropin_tmp="$(mktemp)"
crictl_tmp="$(mktemp)"
trap 'rm -f -- "${containerd_tmp}" "${dropin_tmp}" "${crictl_tmp}"' EXIT

cat >"${containerd_tmp}" <<EOF
version = 2

[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    [plugins."io.containerd.grpc.v1.cri".containerd]
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
          runtime_type = "io.containerd.runc.v2"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            SystemdCgroup = true
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-cc]
          snapshotter = "erofs"
          runtime_type = "io.containerd.kata-cc.v2"
          privileged_without_host_devices = true
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-cc.options]
            ConfigPath = "${runtime_config}"

[plugins."io.containerd.snapshotter.v1.erofs"]
  default_size = "0"

[plugins."io.containerd.service.v1.diff-service"]
  default = ["erofs", "walking"]
EOF

cat >"${dropin_tmp}" <<EOF
[Service]
ExecStartPre=
ExecStartPre=/sbin/modprobe overlay
ExecStartPre=/sbin/modprobe erofs
ExecStart=
ExecStart=$(command -v containerd) --config ${containerd_config}
EOF

cat >"${crictl_tmp}" <<EOF
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 120
debug: false
EOF

sudo install -D -m 0644 "${containerd_tmp}" "${containerd_config}"
sudo install -D -m 0644 "${dropin_tmp}" "${containerd_dropin}"
if [[ ! -e "${crictl_config}" ]]; then
	sudo install -D -m 0644 "${crictl_tmp}" "${crictl_config}"
fi
sudo modprobe erofs
sudo systemctl daemon-reload
sudo systemctl restart containerd

for _ in $(seq 1 30); do
	[[ -S /run/containerd/containerd.sock ]] && break
	sleep 1
done
[[ -S /run/containerd/containerd.sock ]] ||
	die "containerd socket did not become ready"

sudo ctr plugins ls |
	awk '$1 == "io.containerd.snapshotter.v1" && $2 == "erofs" && $4 == "ok" {
		found = 1
	} END {
		exit !found
	}' ||
	die "containerd EROFS snapshotter is not healthy"
systemctl is-active --quiet containerd ||
	die "containerd did not become active"

echo "Installed OpenVMM Kata runtime:"
echo "  OpenVMM: ${openvmm}"
echo "  IGVM: ${igvm}"
echo "  VPs: ${vp_count}"
echo "  Kata image: ${kata_image}"
echo "  Shim: ${shim_path}"
echo "  Runtime config: ${runtime_config}"
