#!/usr/bin/env bats
#
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/tests_common.sh"

setup() {
	pod_name="footubuntu"
	config_name="ssh-config-map"
	get_pod_config_dir

	# Creates ssh-key
	key_path=$(mktemp footloose.XXXXX)
	public_key_path="${key_path}.pub"
	echo -e 'y\n' | ssh-keygen -t rsa -N "" -f "$key_path"

	# Create ConfigMap.yaml
	configmap_yaml="${pod_config_dir}/footloose-rsa-configmap.yaml"
	sed -e "/\${ssh_key}/r ${public_key_path}" -e "/\${ssh_key}/d" \
		"${pod_config_dir}/footloose-configmap.yaml" > "$configmap_yaml"
	sed -i 's/ssh-rsa/      ssh-rsa/' "$configmap_yaml"

	# Add policy to the pod yaml file.
	pod_yaml="${pod_config_dir}/pod-footloose.yaml"
	cmd="uname -r"
	exec_command=(sh -c "${cmd}")
	pod_policy_settings_dir="$(create_tmp_policy_settings_dir "${pod_config_dir}")"
	add_exec_to_policy_settings "${pod_policy_settings_dir}" "${exec_command[@]}"
	auto_generate_policy "${pod_policy_settings_dir}" "${pod_yaml}" "${configmap_yaml}"
}

@test "Footloose pod" {
	sleep_connect="10"

	# Create ConfigMap
	kubectl create -f "$configmap_yaml"

	# Create pod
	kubectl create -f "${pod_yaml}"

	# Check pod creation
	kubectl wait --for=condition=Ready --timeout=$timeout pod "$pod_name"

	# Get pod ip
	pod_ip=$(kubectl get pod $pod_name --template={{.status.podIP}})

	# Exec to the pod
	kubectl exec $pod_name -- "${exec_command[@]}"

	# Connect to the VM
	sleep "$sleep_connect"
	ssh -i "$key_path" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no 2>/dev/null root@"$pod_ip" "$cmd"
}

teardown() {
	kubectl delete pod "$pod_name"
	kubectl delete configmap "$config_name"
	sudo rm -rf "$public_key_path"
	sudo rm -rf "$key_path"
	sudo rm -rf "$configmap_yaml"
	delete_tmp_policy_settings_dir "${pod_policy_settings_dir}"
}
