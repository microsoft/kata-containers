#!/usr/bin/env bats
#
# Copyright (c) 2018 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

load "${BATS_TEST_DIRNAME}/lib.sh"
load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/tests_common.sh"

setup() {
	setup_common || die "setup_common failed"
}

process_subdir() {
	declare -r subdir="$1"
	declare -r samples_root_dir="/home/azureuser/msft.kata-containers/src/agent/samples/policy/yaml"

	bats_unbuffered_info "********************************** Processing subdir: ${subdir}"
	for current_yaml_file in "${samples_root_dir}/${subdir}"/*.yaml
	do
		process_yaml_file "${current_yaml_file}"
	done
}

process_yaml_file() {
	declare -r yaml_file="$1"

	is_exception "${yaml_file}" && return 0

	bats_unbuffered_info "Removing policy annotation from ${yaml_file}"
	yq -i 'del(.metadata.annotations."io.katacontainers.config.agent.policy")' "${yaml_file}" || true
	yq -i 'del(.spec.template.metadata.annotations."io.katacontainers.config.agent.policy")' "${yaml_file}" || true
	
	auto_generate_policy "${pod_config_dir}" "${yaml_file}"
}

is_exception() {
	declare -r yaml_file="$1"
	declare -r excepted_files=(\
		"/home/azureuser/msft.kata-containers/src/agent/samples/policy/yaml/secrets/pull-secrets.yaml" \
	)

	for current_exception in "${excepted_files[@]}"
	do
		[[ "${current_exception}" == "${yaml_file}" ]] && \
		bats_unbuffered_info "Skipping exception file: ${yaml_file}" && \
		return 0
	done

	return 1
}

@test "msft samples" {
	declare -r samples_subdirs=( \
		"configmap" \
		"cron-job" \
		"deployment" \
		"job" \
		"kubernetes/conformance" \
		"kubernetes/conformance2" \
		"kubernetes/fixtures" \
		"kubernetes/fixtures2" \
		"kubernetes/incomplete-init" \
		"pod" \
		"replica-set" \
		"secrets" \
		"stateful-set" \
	)

	bats_unbuffered_info "Parsing pod starting files"

	for current_subdir in "${samples_subdirs[@]}"
	do
		process_subdir "${current_subdir}"
	done
}

teardown(){
	#teardown_common "${node}" "${node_start_time:-}"
	bats_unbuffered_info "teardown complete"
}
