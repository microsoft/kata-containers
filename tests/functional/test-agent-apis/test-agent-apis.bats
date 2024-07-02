#!/usr/bin/env bats

load "${BATS_TEST_DIRNAME}/../../common.bash"
load "${BATS_TEST_DIRNAME}/setup_common.sh"

setup() {
    setup
}

@test "Test CopyFile API: Copy a file to /run/kata-containers" {
    info "Copy file to /run/kata-containers."
}

@test "Test CopyFile API: Copy a symlink to /run/kata-containers" {
    info "Copy symlink to /run/kata-containers"
}

@test "Test CopyFile API: Copy a directory to /run/kata-containers" {
    info "Copy directory to /run/kata-containers"
}

@test "Test CopyFile API: Copy a file to an unallowed destination" {
    info "Copy file to /tmp"
}

@test "Test CopyFile API: Copy a large file to /run/kata-containers" {
    info "Copy large file to /run/kata-containers"
}