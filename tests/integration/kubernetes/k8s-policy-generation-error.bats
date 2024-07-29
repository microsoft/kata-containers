#!/usr/bin/env bats
#
# Copyright (c) 2024 Microsoft.
#
# SPDX-License-Identifier: Apache-2.0
#

load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/tests_common.sh"

setup() {
	auto_generate_policy_enabled || skip "Auto-generated policy tests are disabled."

	get_pod_config_dir
}


@test "Docker image volume definition missing from K8s YAML" {
    pod_yaml="${pod_config_dir}/k8s-policy-generation-error.yaml"
    error_output="$(auto_generate_policy "${pod_config_dir}" "${pod_yaml}" 2>&1)" || true
	info "genpolicy error output:"
	info "${error_output}"
	echo "${error_output}" | grep "ERROR" | grep "Please define volume mount"
}

teardown() {
	auto_generate_policy_enabled || skip "Auto-generated policy tests are disabled."
}
