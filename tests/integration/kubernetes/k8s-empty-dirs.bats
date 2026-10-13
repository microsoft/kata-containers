#!/usr/bin/env bats
#
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

load "${BATS_TEST_DIRNAME}/lib.sh"
load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/tests_common.sh"
load "${BATS_TEST_DIRNAME}/emptydir_common.sh"

assert_equal() {
	local expected=$1
	local actual=$2
	if [[ "$expected" != "$actual" ]]; then
	echo "expected: $expected, got: $actual"
	return 1
	fi
}

setup() {
	pod_name="sharevol-kata"
	pod_logs_file=""
	setup_common || die "setup_common failed"

	policy_settings_dir="$(create_tmp_policy_settings_dir "${pod_config_dir}")"
	add_requests_to_policy_settings "${policy_settings_dir}" "ReadStreamRequest"
}

@test "Empty dir volumes" {
	local yaml_file
	local mount_command
	local dd_command

	yaml_file="${pod_config_dir}/pod-empty-dir.yaml"

	mount_command=(sh -c "mount | grep cache")
	add_exec_to_policy_settings "${policy_settings_dir}" "${mount_command[@]}"

	dd_command=(sh -c "dd if=/dev/zero of=/tmp/cache/file1 bs=1M count=50; echo $?")
	add_exec_to_policy_settings "${policy_settings_dir}" "${dd_command[@]}"

	# Add policy to yaml
	auto_generate_policy "${policy_settings_dir}" "${yaml_file}"

	# Create the pod
	kubectl create -f "${yaml_file}"

	# Check pod creation
	kubectl wait --for=condition=Ready --timeout=$timeout pod "$pod_name"

	# Check volume mounts
	kubectl exec $pod_name -- "${mount_command[@]}" | grep "/tmp/cache type tmpfs"

	# Check it can write up to the volume limit (50M)
	kubectl exec $pod_name -- "${dd_command[@]}" | tail -1 | grep 0
}

teardown() {
	[ ! -f "$pod_logs_file" ] || rm -f "$pod_logs_file"
	[[ -n "${pod_config_dir:-}" ]] && rm -f "${pod_config_dir}/pod-empty-dir-fsgroup.yaml"

	delete_tmp_policy_settings_dir "${policy_settings_dir}"
	teardown_common "${node}" "${node_start_time:-}"
}
