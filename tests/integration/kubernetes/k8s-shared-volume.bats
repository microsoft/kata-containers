#!/usr/bin/env bats
#
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

load "${BATS_TEST_DIRNAME}/lib.sh"
load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/tests_common.sh"

setup() {
	[[ "${KATA_HYPERVISOR}" == qemu-se* ]] && \
		skip "See: https://github.com/kata-containers/kata-containers/issues/10002"
	setup_common || die "setup_common failed"
}

@test "initContainer with shared volume" {

	pod_name="initcontainer-shared-volume"
	last_container="last"
	cmd='test $(cat /volume/initContainer) -lt $(cat /volume/container)'
	yaml_file="${pod_config_dir}/initContainer-shared-volume.yaml"

	# Add policy to the yaml file
	policy_settings_dir="$(create_tmp_policy_settings_dir "${pod_config_dir}")"

	exec_command=(sh -c "${cmd}")
	add_exec_to_policy_settings "${policy_settings_dir}" "${exec_command[@]}"

	add_requests_to_policy_settings "${policy_settings_dir}" "ReadStreamRequest"
	auto_generate_policy "${policy_settings_dir}" "${yaml_file}"

	# Create pod
	kubectl create -f "${yaml_file}"

	# Check pods
	kubectl wait --for=condition=Ready --timeout=15s pod $pod_name

	# kubectl exec "$pod_name" -c "$last_container" -- "${exec_command[@]}"
}

teardown() {
	[[ "${KATA_HYPERVISOR}" == qemu-se* ]] && \
		skip "See: https://github.com/kata-containers/kata-containers/issues/10002"
	# Debugging information
	kubectl describe "pod/$pod_name" || true

	kubectl delete pod "$pod_name" || true
	delete_tmp_policy_settings_dir "${policy_settings_dir}"
	teardown_common "${node}" "${node_start_time:-}"
}
