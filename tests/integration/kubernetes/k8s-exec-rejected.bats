#!/usr/bin/env bats
#
# Copyright (c) 2023 Microsoft.
#
# SPDX-License-Identifier: Apache-2.0
#

load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/tests_common.sh"

setup() {
	get_pod_config_dir
	pod_name="busybox"
	pod_yaml="${pod_config_dir}/busybox-pod.yaml"
	allow_all_except_exec_policy=$(base64 -w 0 "${pod_config_dir}/allow-all-except-exec-process.rego")
}

@test "Kubectl exec rejected by policy" {
	# Add to the YAML file a policy that rejects ExecProcessRequest.
	yq write -i "${pod_yaml}" \
		'metadata.annotations."io.katacontainers.config.agent.policy"' \
		"${allow_all_except_exec_policy}"

	# Create the pod
	kubectl create -f "${pod_yaml}"

	# Wait for pod to start
	kubectl wait --for=condition=Ready --timeout=$timeout pod "$pod_name"

	# Try executing a command in the Pod - an action rejected by the agent policy.
	kubectl exec "$pod_name" -- date 2>&1 | grep "ExecProcessRequest is blocked by policy"
}

@test "AllowRequestsFailingPolicy := true" {
	# Add to the YAML file a policy using just AllowRequestsFailingPolicy := true. Evaluating the rules
	# for any Kata Agent request will return false, but AllowRequestsFailingPolicy := true will allow
	# those request to be executed.
	#
	# Warning: this is an insecure policy that shouldn't be used when protecting the confidentiality
	#          of a pod is important. However, this policy could be useful while debugging a pod.
	policy_text=$(printf "package agent_policy\ndefault AllowRequestsFailingPolicy := true")
	policy_base64=$(echo "${policy_text}" | base64 -w 0 -)

	yq -i \
		".metadata.annotations.\"io.katacontainers.config.agent.policy\" = \"${policy_base64}\"" \
		"${pod_yaml}"

	# Create the pod
	kubectl create -f "${pod_yaml}"

	# Wait for pod to start
	echo "timeout=${timeout}"
	kubectl wait --for=condition=Ready --timeout=$timeout pod "$pod_name"
}

teardown() {
	# Debugging information
	kubectl describe "pod/$pod_name"

	kubectl delete pod "$pod_name"
}
