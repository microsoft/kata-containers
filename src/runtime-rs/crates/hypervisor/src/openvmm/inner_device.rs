// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM device management over the standalone VM service.

use anyhow::{anyhow, Context, Result};

use super::inner::OpenVmmInner;
use crate::device::DeviceType;
use crate::{VmmState, KATA_BLK_DEV_TYPE};

fn format_openvmm_mac(address: Option<&crate::Address>, index: usize) -> String {
    address
        .map(|mac| {
            format!(
                "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]
            )
        })
        .unwrap_or_else(|| format!("02-00-00-00-00-{:02X}", index + 1))
}

impl OpenVmmInner {
    pub(crate) async fn add_device(&mut self, device: DeviceType) -> Result<DeviceType> {
        if self.state == VmmState::NotReady {
            info!(sl!(), "openvmm: VMM not ready, queueing device {}", device);
            self.pending_devices.push(device.clone());
            return Ok(device);
        }

        match device {
            DeviceType::Block(mut block) => {
                if block.config.driver_option != KATA_BLK_DEV_TYPE {
                    return Err(anyhow!(
                        "openvmm only supports '{}' block hotplug, got '{}'",
                        KATA_BLK_DEV_TYPE,
                        block.config.driver_option
                    ));
                }

                if block.config.path_on_host.is_empty() {
                    return Err(anyhow!("openvmm block hotplug requires a host path"));
                }

                let port = self.reserve_block_hotplug_port(&block.device_id)?;
                let hotplug_result = self
                    .vmm_instance
                    .add_pcie_device(
                        &port.name,
                        block.config.path_on_host.clone(),
                        block.config.is_readonly,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "failed to hotplug block device {} into PCIe port {}",
                            block.config.path_on_host, port.name
                        )
                    });

                if let Err(err) = hotplug_result {
                    let _ = self.release_block_hotplug_port(&block.device_id);
                    return Err(err);
                }

                info!(
                    sl!(),
                    "openvmm: hotplugged block device {} as virtio-blk-pci at port {} (pci_path {})",
                    block.config.path_on_host,
                    port.name,
                    port.pci_path
                );

                // The agent resolves the device from its guest PCI path; make
                // sure no stale SCSI address is left set.
                block.config.pci_path = Some(port.pci_path.clone());
                block.config.scsi_addr = None;
                Ok(DeviceType::Block(block))
            }
            DeviceType::Network(net) => {
                if net.config.host_dev_name.is_empty() {
                    return Err(anyhow!(
                        "openvmm network hotplug requires host tap name for {}",
                        net.device_id
                    ));
                }

                let port = self.reserve_net_hotplug_port(&net.device_id)?;
                let guest_mac = format_openvmm_mac(net.config.guest_mac.as_ref(), 0);

                let hotplug_result = self
                    .vmm_instance
                    .add_pcie_network_device(
                        &port.name,
                        net.config.host_dev_name.clone(),
                        guest_mac,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "failed to hotplug network device {} into PCIe port {}",
                            net.config.host_dev_name, port.name
                        )
                    });

                if let Err(err) = hotplug_result {
                    let _ = self.release_net_hotplug_port(&net.device_id);
                    return Err(err);
                }

                info!(
                    sl!(),
                    "openvmm: hotplugged network device {} at port {} (pci_path {})",
                    net.config.host_dev_name,
                    port.name,
                    port.pci_path
                );

                Ok(DeviceType::Network(net))
            }
            other => {
                if matches!(other, DeviceType::Vfio(_)) {
                    return Err(anyhow!(
                        "openvmm: VFIO devices are cold-plug only and must be \
                         added before start_vm; got {} after VMM start",
                        other
                    ));
                }
                warn!(sl!(), "openvmm: add_device stub for {}", other);
                Ok(other)
            }
        }
    }

    pub(crate) async fn remove_device(&mut self, device: DeviceType) -> Result<()> {
        match device {
            DeviceType::Block(block) => {
                let Some(port) = self.release_block_hotplug_port(&block.device_id) else {
                    warn!(
                        sl!(),
                        "openvmm: no hotplug mapping found for block device {}", block.device_id
                    );
                    return Ok(());
                };

                self.vmm_instance
                    .remove_pcie_device(&port.name)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to hot-remove block device {} from PCIe port {}",
                            block.device_id, port.name
                        )
                    })?;

                info!(
                    sl!(),
                    "openvmm: hot-removed block device {} from PCIe port {}",
                    block.device_id,
                    port.name
                );
                Ok(())
            }
            DeviceType::Network(net) => {
                let Some(port) = self.release_net_hotplug_port(&net.device_id) else {
                    warn!(
                        sl!(),
                        "openvmm: no hotplug mapping found for network device {}",
                        net.device_id
                    );
                    return Ok(());
                };

                self.vmm_instance
                    .remove_pcie_device(&port.name)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to hot-remove network device {} from PCIe port {}",
                            net.device_id, port.name
                        )
                    })?;

                info!(
                    sl!(),
                    "openvmm: hot-removed network device {} from PCIe port {}",
                    net.device_id,
                    port.name
                );
                Ok(())
            }
            other => {
                warn!(sl!(), "openvmm: remove_device stub for {}", other);
                Ok(())
            }
        }
    }

    pub(crate) async fn update_device(&mut self, device: DeviceType) -> Result<()> {
        warn!(sl!(), "openvmm: update_device stub for {}", device);
        Ok(())
    }
}
