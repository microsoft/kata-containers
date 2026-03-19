// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::Result;
use std::sync::Arc;

use crate::config::{ConfigPlugin, TomlConfig};

use super::register_hypervisor_plugin;

/// Hypervisor name for openvmm, used to index `TomlConfig::hypervisor`.
pub const HYPERVISOR_NAME_OPENVMM: &str = "openvmm";

/// Maximum number of vCPUs for openvmm.
pub const MAX_OPENVMM_VCPUS: u32 = 256;

/// Minimum memory size in MiB for openvmm.
pub const MIN_OPENVMM_MEMORY_SIZE_MB: u32 = 64;

/// Default memory size in MiB for openvmm.
pub const DEFAULT_OPENVMM_MEMORY_SIZE_MB: u32 = 128;

/// Default memory slots for openvmm.
pub const DEFAULT_OPENVMM_MEMORY_SLOTS: u32 = 128;

/// Configuration information for openvmm.
#[derive(Default, Debug)]
pub struct OpenVmmConfig {}

impl OpenVmmConfig {
    /// Create a new instance of `OpenVmmConfig`.
    pub fn new() -> Self {
        OpenVmmConfig {}
    }

    /// Register the openvmm plugin.
    pub fn register(self) {
        let plugin = Arc::new(self);
        register_hypervisor_plugin(HYPERVISOR_NAME_OPENVMM, plugin);
    }
}

impl ConfigPlugin for OpenVmmConfig {
    fn get_max_cpus(&self) -> u32 {
        MAX_OPENVMM_VCPUS
    }

    fn get_min_memory(&self) -> u32 {
        MIN_OPENVMM_MEMORY_SIZE_MB
    }

    fn name(&self) -> &str {
        HYPERVISOR_NAME_OPENVMM
    }

    /// Adjust the configuration information after loading from configuration file.
    fn adjust_config(&self, conf: &mut TomlConfig) -> Result<()> {
        if let Some(ovmm) = conf.hypervisor.get_mut(HYPERVISOR_NAME_OPENVMM) {
            if ovmm.memory_info.default_memory == 0 {
                ovmm.memory_info.default_memory = DEFAULT_OPENVMM_MEMORY_SIZE_MB;
            }
            if ovmm.memory_info.memory_slots == 0 {
                ovmm.memory_info.memory_slots = DEFAULT_OPENVMM_MEMORY_SLOTS;
            }
            if ovmm.cpu_info.default_maxvcpus > MAX_OPENVMM_VCPUS {
                ovmm.cpu_info.default_maxvcpus = MAX_OPENVMM_VCPUS;
            }
        }
        Ok(())
    }

    /// Validate the configuration information.
    fn validate(&self, conf: &TomlConfig) -> Result<()> {
        if let Some(ovmm) = conf.hypervisor.get(HYPERVISOR_NAME_OPENVMM) {
            if ovmm.memory_info.default_memory < MIN_OPENVMM_MEMORY_SIZE_MB {
                return Err(std::io::Error::other(format!(
                    "OpenVMM hypervisor has minimal memory limitation {MIN_OPENVMM_MEMORY_SIZE_MB}",
                )));
            }
        }
        Ok(())
    }
}
