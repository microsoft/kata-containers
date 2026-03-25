// Copyright (c) 2022-2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use anyhow::{Ok, Result};
use kata_types::build_path;

use crate::{utils::get_sandbox_path, utils::get_uvm_path, JAILER_ROOT};

// The socket used to connect to CH. This is used for CH API communications.
const CH_API_SOCKET_NAME: &str = "ch-api.sock";

// The socket that allows runtime-rs to connect direct through to the Kata
// Containers agent running inside the CH hosted VM.
const CH_VM_SOCKET_NAME: &str = "ch-vm.sock";

// Return the path for a _hypothetical_ API socket path:
// the path does *not* exist yet, and for this reason safe-path cannot be
// used.
pub fn get_api_socket_path(id: &str, uvm_id: &str) -> Result<String> {
    info!(sl!(), "get_api_socket_path: id = {id} , uvm_id = {uvm_id}");

    let sandbox_path = if let Some(uvm_path) = get_uvm_path(uvm_id) {
        uvm_path
    } else {
        get_sandbox_path(id, uvm_id)
    };

    let path = [&sandbox_path, CH_API_SOCKET_NAME].join("/");

    info!(sl!(), "get_api_socket_path: returning {path}");
    Ok(path)
}

// Return the path for a _hypothetical_ sandbox specific VSOCK socket path:
// the path does *not* exist yet, and for this reason safe-path cannot be
// used.
pub fn get_vsock_path(id: &str, uvm_id: &str) -> Result<String> {
    info!(sl!(), "get_vsock_path: id = {id} , uvm_id = {uvm_id}");

    let sandbox_path = if let Some(uvm_path) = get_uvm_path(uvm_id) {
        uvm_path
    } else {
        get_sandbox_path(id, uvm_id)
    };

    let path = [&sandbox_path, CH_VM_SOCKET_NAME].join("/");

    info!(sl!(), "get_vsock_path: returning {path}");
    Ok(path)
}

/// Returns the symlink path of the sandbox for the virtio-fs socket in rootless mode.
pub fn get_rootless_symlink_sandbox_path(id: &str) -> String {
    Path::new(build_path(id).as_str())
        .to_string_lossy()
        .to_string()
}

/// Returns the symlink path of the sandbox's jailer root for the virtio-fs socket in rootless mode.
pub fn get_rootless_symlink_sandbox_jailer_root(id: &str) -> String {
    let sandbox_path = get_rootless_symlink_sandbox_path(id);

    [&sandbox_path, JAILER_ROOT].join("/")
}


pub fn socket_exists(socket_path: &str) -> bool {
    let metadata = fs::metadata(&socket_path);
    if metadata.is_ok() {
        if metadata.unwrap().file_type().is_socket() {
            info!(sl!(), "socket_exists: found existing socket at {:?}", &socket_path);
            return true;
        }
    }

    info!(sl!(), "socket_exists: socket not found at {:?}", &socket_path);
    false
}
