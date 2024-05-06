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

// CreateSandbox struct to save cmdline inputs and generate the actual struct
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateSandboxInput {
    pub sandbox_id: String,
}