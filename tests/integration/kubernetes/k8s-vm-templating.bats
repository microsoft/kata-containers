#!/usr/bin/env bats
#
# Copyright (c) 2024 Kata Containers
#
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Kata VM templating (factory) functionality in Kubernetes integration mode

load "${BATS_TEST_DIRNAME}/lib.sh"
load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/confidential_common.sh"
load "${BATS_TEST_DIRNAME}/tests_common.sh"

# With setup_file and teardown_file being used, we use >&3 in some places to
# direct output to the terminal. setup_file is used in BATS for one-time
# initialization for all tests in the file.
setup_file() {
	if [[ "${KATA_HYPERVISOR}" != "clh" ]] || is_confidential_runtime_class; then
		export skip_vm_templating_tests=true
		return 0
	fi

	setup_common || die "setup_common failed"

	# Get ALL kata nodes
	mapfile -t all_nodes < <(kubectl get nodes -l katacontainers.io/kata-runtime=true -o name | sed 's|^node/||')
	[[ "${#all_nodes[@]}" -gt 0 ]] || die "No Kata nodes found"

	# Build a single Kata runtime config drop-in that enables VM templating and
	# disables shared_fs for the clh shim.
	local runtime_config_dropin_file="${BATS_FILE_TMPDIR}/99-k8s-vm-templating.toml"
	cat > "${runtime_config_dropin_file}" <<DROPIN
[hypervisor.clh]
shared_fs = "none"

[factory]
enable_template = true
template_path = "/run/vc/vm/template"
DROPIN

	# Track per-node drop-in paths so teardown_file() can remove them.
	declare -ag dropin_paths=()

	# Apply the drop-in and initialize VM templates on all Kata nodes.
	for n in "${all_nodes[@]}"; do
		echo "Applying VM templating drop-in on node: $n" >&3
		local dropin_path
		dropin_path="$(set_kata_runtime_config_dropin_file "$n" "${runtime_config_dropin_file}")" \
			|| die "Failed to install Kata runtime config drop-in on node $n"
		dropin_paths+=("${n}=${dropin_path}")

		echo "Initializing VM template on node: $n" >&3
		exec_host "$n" "sudo kata-runtime factory init" \
			|| die "Failed to initialize VM template on node $n"
	done

	export all_nodes
	export dropin_paths

	echo "VM templates initialized on ${#all_nodes[@]} nodes" >&3
}

setup() {
	if [[ "${skip_vm_templating_tests:-false}" == "true" ]]; then
		skip "VM templating is only supported for non-confidential clh hypervisor"
	fi

	setup_common || die "setup_common failed"
}

@test "VM template factory is initialized" {
	for n in "${all_nodes[@]}"; do
		exec_host "$n" "test -d /run/vc/vm/template" || skip "VM template directory not found on $n"
	done
}

@test "Pod can be created with templated VM" {
	pod_name="test-templated-pod"
	ctr_name="test-container"

	pod_config=$(mktemp --tmpdir pod_config.XXXXXX.yaml)
	cp "$pod_config_dir/busybox-template.yaml" "$pod_config"

	sed -i "s/POD_NAME/$pod_name/" "$pod_config"
	sed -i "s/CTR_NAME/$ctr_name/" "$pod_config"

	kubectl create -f "${pod_config}"
	kubectl wait --for=condition=Ready --timeout=120s "pod/${pod_name}" || die "Pod failed to reach Ready state"

	kubectl get pod "${pod_name}" | grep Running || die "Pod is not in Running state"

	kubectl exec "${pod_name}" -- sh -c "echo 'Hello from templated VM' && exit 0"
}

teardown() {
	if [[ "${skip_vm_templating_tests:-false}" == "true" ]]; then
		return 0
	fi

	# Best-effort cleanup of any pod/yaml created by a test in this file.
	kubectl delete pod test-templated-pod --ignore-not-found=true --wait=false || true
	[[ -n "${pod_config:-}" && -f "${pod_config}" ]] && rm -f "${pod_config}"

	teardown_common "${node:-}" "${node_start_time:-}"
}

teardown_file() {
	if [[ "${skip_vm_templating_tests:-false}" == "true" ]]; then
		return 0
	fi

	# Destroy templates and remove the runtime config drop-in on each node.
	# Iterate dropin_paths so we always try to remove what setup_file installed,
	# even if a node has been removed from all_nodes mid-run.
	for entry in "${dropin_paths[@]:-}"; do
		[[ -z "${entry}" ]] && continue
		local n="${entry%%=*}"
		local dropin_path="${entry#*=}"

		echo "Destroying VM template on node: $n" >&3
		exec_host "$n" "sudo kata-runtime factory destroy" \
			|| echo "Warning: Failed to destroy VM template on node $n" >&3

		echo "Removing VM templating drop-in on node: $n" >&3
		remove_kata_runtime_config_dropin_file "$n" "${dropin_path}" \
			|| echo "Warning: Failed to remove Kata runtime config drop-in on node $n" >&3
	done

	echo "VM templates destroyed on ${#dropin_paths[@]} nodes" >&3
}
