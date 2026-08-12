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

@test "msft samples" {
	declare -r samples_root_dir="/home/azureuser/msft.kata-containers/src/agent/samples/policy/yaml"

	bats_unbuffered_info "Parsing pod starting files"

	for yaml_file in "${samples_root_dir}"/pod/*.yaml
	do
		bats_unbuffered_info "${yaml_file}"
		auto_generate_policy "${pod_config_dir}" "${yaml_file}"
	done
}

teardown(){
	teardown_common "${node}" "${node_start_time:-}"
}
