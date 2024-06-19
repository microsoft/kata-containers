#
# Copyright (c) 2018 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/tests_common.sh"

setup() {
	auto_generate_policy_enabled || skip "Auto-generated policy tests are disabled."

	get_pod_config_dir

	pod_yaml="policy-yaml-pod.yaml"

	# Save some time by executing genpolicy a single time.
	if [ "${BATS_TEST_NUMBER}" == "1" ]; then
		# Add policy
		auto_generate_policy "${pod_config_dir}" "${pod_yaml}"
	fi
}

@test "Pod yaml support" {
	pod_name="policy-yaml-pod"

	# Create pod
	kubectl create -f "${pod_config_dir}/${pod_yaml}"

	# View pod
	kubectl wait --for=condition=Available --timeout=$timeout \
		pod/${pod_name}
}

teardown() {
	auto_generate_policy_enabled || skip "Auto-generated policy tests are disabled."

	# Debugging information
	kubectl describe pod ${pod_name}

	# Clean-up
	kubectl delete pod ${pod_name}
}
