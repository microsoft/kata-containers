// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Type used to pass optional state between cooperating API calls.
pub type Options = HashMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_address: String,
    pub bundle_dir: String,
    pub timeout_nano: i64,
    pub hybrid_vsock_port: u64,
    pub interactive: bool,
    pub hybrid_vsock: bool,
    pub ignore_errors: bool,
    pub no_auto_values: bool,
}

// create sandbox request input struct
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateSandboxInput {
    pub sandbox_id: String,
}

// create container request input struct
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MountPoints {
    pub src: String,
    pub dest: String, 
    // space separated list of string slices for providing additional mount options
    pub options: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateContainerInput {
    pub container_id: String,
    pub container_type: String,
    pub sandbox_id: String,
    // rootfs path as prepared by snapshotter
    pub root_fs_path: String,
    // args that the container should run
    pub args: Vec<String>,
    // mount options
    pub mnt_options: Vec<MountPoints>,
}

// Simplified copy file request
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CopyFileInput {
    pub src: String,
    pub dest: String,
}

// SetPolicy input request
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SetPolicyInput {
    pub policy_file: String,
}