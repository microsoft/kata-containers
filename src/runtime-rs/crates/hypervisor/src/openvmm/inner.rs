// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Inner state for the OpenVMM hypervisor integration.

use crate::{device::DeviceType, hypervisor_persist::HypervisorState, VmmState};
use anyhow::Result;
use kata_types::{
    capabilities::{Capabilities, CapabilityBits},
    config::hypervisor::Hypervisor as HypervisorConfig,
};
use std::collections::HashSet;
use tokio::sync::mpsc;

use super::vmm_instance::VmmInstance;

/// Inner state for the OpenVMM hypervisor.
#[allow(dead_code)]
pub(crate) struct OpenVmmInner {
    pub(crate) id: String,
    pub(crate) vm_path: String,
    pub(crate) jailer_root: String,
    pub(crate) netns: Option<String>,
    pub(crate) config: HypervisorConfig,
    pub(crate) state: VmmState,
    pub(crate) run_dir: String,
    pub(crate) pending_devices: Vec<DeviceType>,
    pub(crate) cached_block_devices: HashSet<String>,
    pub(crate) capabilities: Capabilities,
    pub(crate) guest_memory_block_size_mb: u32,
    pub(crate) vmm_instance: VmmInstance,
}

impl std::fmt::Debug for OpenVmmInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVmmInner")
            .field("id", &self.id)
            .field("state", &self.state)
            .finish()
    }
}

impl OpenVmmInner {
    pub(crate) fn new(exit_notify: mpsc::Sender<i32>) -> Self {
        let mut capabilities = Capabilities::new();
        capabilities.set(CapabilityBits::BlockDeviceSupport | CapabilityBits::FsSharingSupport);

        OpenVmmInner {
            id: String::new(),
            vm_path: String::new(),
            jailer_root: String::new(),
            netns: None,
            config: HypervisorConfig::default(),
            state: VmmState::NotReady,
            run_dir: String::new(),
            pending_devices: Vec::new(),
            cached_block_devices: HashSet::new(),
            capabilities,
            guest_memory_block_size_mb: 0,
            vmm_instance: VmmInstance::new(exit_notify),
        }
    }

    pub(crate) fn set_hypervisor_config(&mut self, config: HypervisorConfig) {
        self.config = config;
    }

    pub(crate) fn hypervisor_config(&self) -> HypervisorConfig {
        self.config.clone()
    }

    pub(crate) async fn capabilities(&self) -> Result<Capabilities> {
        Ok(self.capabilities.clone())
    }

    pub(crate) fn set_capabilities(&mut self, flag: CapabilityBits) {
        self.capabilities.set(flag);
    }

    pub(crate) fn set_guest_memory_block_size(&mut self, size: u32) {
        self.guest_memory_block_size_mb = size;
    }

    pub(crate) fn guest_memory_block_size_mb(&self) -> u32 {
        self.guest_memory_block_size_mb
    }

    pub(crate) async fn save(&self) -> Result<HypervisorState> {
        Ok(HypervisorState {
            hypervisor_type: "openvmm".to_string(),
            id: self.id.clone(),
            vm_path: self.vm_path.clone(),
            netns: self.netns.clone(),
            config: self.config.clone(),
            run_dir: self.run_dir.clone(),
            cached_block_devices: self.cached_block_devices.clone(),
            ..Default::default()
        })
    }

    pub(crate) async fn restore(
        exit_notify: mpsc::Sender<i32>,
        state: HypervisorState,
    ) -> Result<Self> {
        let mut inner = OpenVmmInner::new(exit_notify);
        inner.id = state.id;
        inner.vm_path = state.vm_path;
        inner.netns = state.netns;
        inner.config = state.config;
        inner.run_dir = state.run_dir;
        inner.cached_block_devices = state.cached_block_devices;
        Ok(inner)
    }
}
