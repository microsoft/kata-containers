// Copyright (c) 2022-2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use anyhow::{Ok, Result};
use kata_types::build_path;

use crate::{utils::get_sandbox_path, JAILER_ROOT};

// The socket used to connect to CH. This is used for CH API communications.
const CH_API_SOCKET_NAME: &str = "ch-api.sock";

// The socket that allows runtime-rs to connect direct through to the Kata
// Containers agent running inside the CH hosted VM.
const CH_VM_SOCKET_NAME: &str = "ch-vm.sock";

// Return the path for a _hypothetical_ API socket path:
// the path does *not* exist yet, and for this reason safe-path cannot be
// used.
pub fn get_api_socket_path(id: &str) -> Result<String> {
    let sandbox_path = get_sandbox_path(id);

    let path = [&sandbox_path, CH_API_SOCKET_NAME].join("/");

    Ok(path)
}

pub fn get_api_socket_path_already_existing() -> Option<String> {
    get_socket_path_already_existing(CH_API_SOCKET_NAME)
}

// Return the path for a _hypothetical_ sandbox specific VSOCK socket path:
// the path does *not* exist yet, and for this reason safe-path cannot be
// used.
pub fn get_vsock_path(id: &str) -> Result<String> {
    if let Some(existing) = get_socket_path_already_existing(CH_VM_SOCKET_NAME) {
        return Ok(existing);
    }

    let sandbox_path = get_sandbox_path(id);

    let path = [&sandbox_path, CH_VM_SOCKET_NAME].join("/");

    Ok(path)
}

pub fn get_vsock_path_already_existing() -> Option<String> {
    get_socket_path_already_existing(CH_VM_SOCKET_NAME)
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

pub fn get_socket_path_already_existing(socket_name: &str) -> Option<String> {
    let path = std::path::Path::new("/run/kata");
    if path.is_dir() {
        for entity in fs::read_dir(path).unwrap() {
            let entity_path = entity.unwrap().path();
            if entity_path.is_dir() {
                let socket_path = entity_path.join(socket_name);
                let metadata = fs::metadata(&socket_path);
                if metadata.is_ok() {
                    if metadata.unwrap().file_type().is_socket() {
                        info!(sl!(), "CLH: found existing socket at {:?}", &socket_path);
                        return Some(socket_path.to_str().unwrap().to_string());
                    }
                }
            }
        }
    }
    None
}
