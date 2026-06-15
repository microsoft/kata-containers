// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM hypervisor backend for kata-containers runtime-rs.
//!
//! This module integrates the OpenVMM VMM as an in-process hypervisor,
//! using the MSHV (Microsoft Hypervisor) backend. It follows the same
//! architectural pattern as the Dragonball integration.

mod inner;
mod inner_device;
mod inner_hypervisor;
mod vmm_instance;

use inner::OpenVmmInner;
use persist::sandbox_persist::Persist;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use kata_types::capabilities::{Capabilities, CapabilityBits};
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::instrument;

use super::HypervisorState;
use crate::{DeviceType, Hypervisor, MemoryConfig, VcpuThreadIds};

pub(crate) const OPENVMM_ROOTFS_PCI_PORT: &str = "rp0";
pub(crate) const OPENVMM_SHAREFS_PCI_PORT: &str = "rp1";
pub(crate) const OPENVMM_NET_PCI_PORT: &str = "rp2";
pub(crate) const OPENVMM_VSOCK_PCI_PORT: &str = "rp3";
pub(crate) const OPENVMM_CONSOLE_PCI_PORT: &str = "rp4";
pub(crate) const OPENVMM_STATIC_PCI_PORT_COUNT: u8 = 5;
pub(crate) const OPENVMM_BLOCK_HOTPLUG_PORT_PREFIX: &str = "hp";
// OpenVMM packs root ports into multi-function device slots (see
// `GenericPcieRootComplex::new` in microsoft/openvmm:
// `vm/devices/pci/pcie/src/root.rs`): port index `i` lands at PCI
// `device = i / 8, function = i % 8` on bus 0 of the root complex
// (assuming `first_port_device_number = 0`, which the openvmm worker
// uses when no IOMMU is attached). That gives us up to 8 root ports
// per device slot and 32 device slots, i.e. 256 ports total — far
// beyond anything kata needs.
//
// Each cold-plug root port still consumes a bridge MMIO32 window for
// the device's 32-bit BARs, so the practical ceiling is the size of
// the low_mmio window allocated above, not the PCI device-number
// space. The numbers below cover any Azure SKU we know about (HGX
// A100 8-GPU baseboard = 14 VFIO devices, HGX H100 = 16, plus IB VFs).
pub(crate) const OPENVMM_BLOCK_HOTPLUG_PORT_COUNT: u8 = 24;
/// Number of pre-reserved PCIe root ports for cold-plug VFIO pass-through
/// devices (e.g., GPUs, NVSwitches). These ports are created with
/// `hotplug: false` so the guest sees the assigned devices at boot.
pub(crate) const OPENVMM_VFIO_COLDPLUG_PORT_PREFIX: &str = "vfio";
pub(crate) const OPENVMM_VFIO_COLDPLUG_PORT_COUNT: u8 = 32;

/// Map an OpenVMM PCIe root-port index (0..256) to the corresponding
/// guest PciPath. OpenVMM packs root ports into multi-function device
/// slots, so port `i` is at `device = i / 8, function = i % 8` on bus 0
/// of the root complex. The endpoint device sits at function 0 of the
/// root port's secondary bus, which kata represents as the second
/// PciSlot in the path.
///
/// We need this because the original single-function layout
/// (`root_slot = STATIC + BLOCK_HOTPLUG + port_index`) overflowed PCI's
/// 5-bit slot field (32 slot numbers) as soon as the shim allocated
/// more than 3 VFIO ports on a build that also keeps the full 24-slot
/// block-hotplug pool. The multi-function layout matches what OpenVMM
/// itself programs into the guest's PCIe config space, so the agent's
/// QOM-path → pci_path parser also accepts what we send.
pub(crate) fn openvmm_port_pci_path(
    port_index: u8,
) -> anyhow::Result<crate::device::pci_path::PciPath> {
    use crate::device::pci_path::{PciPath, PciSlot};
    let device = port_index / 8;
    let function = port_index % 8;
    let root = PciSlot::with_function(device, function)?;
    let endpoint = PciSlot::new(0);
    PciPath::new(vec![root, endpoint])
        .ok_or_else(|| anyhow::anyhow!("openvmm: failed to build PciPath for port {}", port_index))
}

/// The OpenVMM hypervisor struct, wrapping inner state behind a lock.
pub struct OpenVmm {
    inner: Arc<RwLock<OpenVmmInner>>,
    exit_waiter: Mutex<(mpsc::Receiver<i32>, i32)>,
}

impl std::fmt::Debug for OpenVmm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVmm").finish()
    }
}

impl Default for OpenVmm {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenVmm {
    pub fn new() -> Self {
        let (exit_notify, exit_waiter) = mpsc::channel(1);

        Self {
            inner: Arc::new(RwLock::new(OpenVmmInner::new(exit_notify))),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        }
    }

    pub async fn set_hypervisor_config(&self, config: HypervisorConfig) {
        let mut inner = self.inner.write().await;
        inner.set_hypervisor_config(config);
    }
}

#[async_trait]
impl Hypervisor for OpenVmm {
    #[instrument]
    async fn prepare_vm(
        &self,
        id: &str,
        netns: Option<String>,
        _annotations: &HashMap<String, String>,
        _selinux_label: Option<String>,
    ) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.prepare_vm(id, netns).await
    }

    #[instrument]
    async fn start_vm(&self, timeout: i32) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.start_vm(timeout).await
    }

    async fn stop_vm(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.stop_vm().await
    }

    async fn wait_vm(&self) -> Result<i32> {
        let mut waiter = self.exit_waiter.lock().await;
        if let Some(exit_code) = waiter.0.recv().await {
            waiter.1 = exit_code;
        }
        Ok(waiter.1)
    }

    async fn pause_vm(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.pause_vm().await
    }

    async fn resume_vm(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.resume_vm().await
    }

    async fn save_vm(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.save_vm().await
    }

    async fn resize_vcpu(&self, old_vcpus: u32, new_vcpus: u32) -> Result<(u32, u32)> {
        let inner = self.inner.read().await;
        inner.resize_vcpu(old_vcpus, new_vcpus).await
    }

    async fn add_device(&self, device: DeviceType) -> Result<DeviceType> {
        let mut inner = self.inner.write().await;
        inner.add_device(device).await
    }

    async fn remove_device(&self, device: DeviceType) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.remove_device(device).await
    }

    async fn update_device(&self, device: DeviceType) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.update_device(device).await
    }

    async fn get_agent_socket(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_agent_socket().await
    }

    async fn disconnect(&self) {
        let mut inner = self.inner.write().await;
        inner.disconnect().await;
    }

    async fn hypervisor_config(&self) -> HypervisorConfig {
        let inner = self.inner.read().await;
        inner.hypervisor_config()
    }

    async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        let inner = self.inner.read().await;
        inner.get_thread_ids().await
    }

    async fn cleanup(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.cleanup().await
    }

    async fn get_pids(&self) -> Result<Vec<u32>> {
        let inner = self.inner.read().await;
        inner.get_pids().await
    }

    async fn get_vmm_master_tid(&self) -> Result<u32> {
        let inner = self.inner.read().await;
        inner.get_vmm_master_tid().await
    }

    async fn get_ns_path(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_ns_path().await
    }

    async fn check(&self) -> Result<()> {
        let inner = self.inner.read().await;
        inner.check().await
    }

    async fn get_jailer_root(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_jailer_root().await
    }

    async fn save_state(&self) -> Result<HypervisorState> {
        self.save().await
    }

    async fn capabilities(&self) -> Result<Capabilities> {
        let inner = self.inner.read().await;
        inner.capabilities().await
    }

    async fn get_hypervisor_metrics(&self) -> Result<String> {
        let inner = self.inner.read().await;
        inner.get_hypervisor_metrics().await
    }

    async fn set_capabilities(&self, flag: CapabilityBits) {
        let mut inner = self.inner.write().await;
        inner.set_capabilities(flag);
    }

    async fn set_guest_memory_block_size(&self, size: u32) {
        let mut inner = self.inner.write().await;
        inner.set_guest_memory_block_size(size);
    }

    async fn guest_memory_block_size(&self) -> u32 {
        let inner = self.inner.read().await;
        inner.guest_memory_block_size_mb()
    }

    async fn resize_memory(&self, new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        let mut inner = self.inner.write().await;
        inner.resize_memory(new_mem_mb).await
    }

    async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        let inner = self.inner.read().await;
        inner.get_passfd_listener_addr().await
    }
}

#[async_trait]
impl Persist for OpenVmm {
    type State = HypervisorState;
    type ConstructorArgs = ();

    async fn save(&self) -> Result<Self::State> {
        let inner = self.inner.read().await;
        inner.save().await.context("save openvmm hypervisor state")
    }

    async fn restore(
        _hypervisor_args: Self::ConstructorArgs,
        hypervisor_state: Self::State,
    ) -> Result<Self> {
        let (exit_notify, exit_waiter) = mpsc::channel(1);
        let inner = OpenVmmInner::restore(exit_notify, hypervisor_state).await?;
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            exit_waiter: Mutex::new((exit_waiter, 0)),
        })
    }
}
