// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Inner state for the OpenVMM hypervisor integration.

use crate::{
    device::DeviceType, hypervisor_persist::HypervisorState, VmmState,
};
use anyhow::Result;
use kata_types::{
    capabilities::{Capabilities, CapabilityBits},
    config::hypervisor::Hypervisor as HypervisorConfig,
};
use std::collections::HashSet;
use tokio::sync::mpsc;

use virt_mshv::LinuxMshv;

/// Inner state for the OpenVMM hypervisor.
#[derive(Debug)]
pub(crate) struct OpenVmmInner {
    /// sandbox id
    pub(crate) id: String,
    /// vm path
    pub(crate) vm_path: String,
    /// netns
    pub(crate) netns: Option<String>,
    /// hypervisor config
    pub(crate) config: HypervisorConfig,
    /// vmm state
    pub(crate) state: VmmState,
    /// hypervisor run dir
    pub(crate) run_dir: String,
    /// pending devices (queued before VM boot)
    pub(crate) pending_devices: Vec<DeviceType>,
    /// cached block device IDs
    pub(crate) cached_block_devices: HashSet<String>,
    /// openvmm capabilities
    pub(crate) capabilities: Capabilities,
    /// guest memory block size in MB
    pub(crate) guest_memory_block_size_mb: u32,
    /// exit notification channel
    pub(crate) _exit_notify: mpsc::Sender<i32>,
    /// MSHV hypervisor handle
    pub(crate) mshv: LinuxMshv,
}

impl OpenVmmInner {
    pub(crate) fn new(exit_notify: mpsc::Sender<i32>) -> Self {
        let mut capabilities = Capabilities::new();
        capabilities.set(
            CapabilityBits::BlockDeviceSupport | CapabilityBits::FsSharingSupport,
        );

        OpenVmmInner {
            id: String::new(),
            vm_path: String::new(),
            netns: None,
            config: HypervisorConfig::default(),
            state: VmmState::NotReady,
            run_dir: String::new(),
            pending_devices: Vec::new(),
            cached_block_devices: HashSet::new(),
            capabilities,
            guest_memory_block_size_mb: 0,
            _exit_notify: exit_notify,
            mshv: LinuxMshv,
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
