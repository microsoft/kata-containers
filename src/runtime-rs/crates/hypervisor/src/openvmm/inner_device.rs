// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM device management over the standalone VM service.

use anyhow::{anyhow, Context, Result};

use super::inner::OpenVmmInner;
use super::inner_hypervisor::{blk_device_kind, mac_address, net_device_kind};
use crate::device::DeviceType;
use crate::{VmmState, KATA_BLK_DEV_TYPE};

/// Hotplug port key of a hot-added NIC. Network endpoints are detached with a
/// `NetworkDevice` rebuilt from their config (empty device_id), so the port is
/// keyed by the host TAP name, which is unique within the sandbox netns.
fn net_hotplug_key(tap_name: &str) -> String {
    format!("net:{}", tap_name)
}

impl OpenVmmInner {
    pub(crate) async fn add_device(&mut self, device: DeviceType) -> Result<DeviceType> {
        if self.state == VmmState::NotReady {
            info!(sl!(), "openvmm: VMM not ready, queueing device {}", device);
            self.pending_devices.push(device.clone());
            return Ok(device);
        }

        match device {
            DeviceType::BlockModern(block_device) => {
                let (device_id, path_on_host, is_readonly, driver_option) = {
                    let block = block_device.lock().await;
                    (
                        block.device_id.clone(),
                        block.config.path_on_host.clone(),
                        block.config.is_readonly,
                        block.config.driver_option.clone(),
                    )
                };

                if driver_option != KATA_BLK_DEV_TYPE {
                    return Err(anyhow!(
                        "openvmm only supports '{}' block hotplug, got '{}'",
                        KATA_BLK_DEV_TYPE,
                        driver_option
                    ));
                }

                if path_on_host.is_empty() {
                    return Err(anyhow!("openvmm block hotplug requires a host path"));
                }

                let port = self.reserve_hotplug_port(&device_id)?;
                let hotplug_result = self
                    .vmm_instance
                    .add_pcie_device(
                        &port.name,
                        blk_device_kind(path_on_host.clone(), is_readonly),
                    )
                    .await
                    .context(format!(
                        "failed to hotplug block device {} into PCIe port {}",
                        path_on_host, port.name
                    ));

                if let Err(err) = hotplug_result {
                    let _ = self.release_hotplug_port(&device_id);
                    return Err(err);
                }

                info!(
                    sl!(),
                    "openvmm: hotplugged block device {} as virtio-blk-pci at port {} (pci_path {})",
                    path_on_host,
                    port.name,
                    port.pci_path
                );

                // The agent resolves the device from its guest PCI path; make
                // sure no stale SCSI address is left set.
                let mut block = block_device.lock().await;
                block.config.pci_path = Some(port.pci_path.clone());
                block.config.scsi_addr = None;
                drop(block);
                Ok(DeviceType::BlockModern(block_device))
            }
            DeviceType::Network(mut net_device) => {
                // NICs added after start_vm: nerdctl, for example, creates the
                // container network in a createRuntime hook that runs after the
                // VM started, so the netns was still empty at cold-plug time.
                let tap_name = net_device.config.host_dev_name.clone();
                if tap_name.is_empty() {
                    return Err(anyhow!("openvmm network hotplug requires a host TAP name"));
                }
                if net_device.config.guest_mac.is_none() {
                    return Err(anyhow!(
                        "openvmm network hotplug of TAP {} requires a guest MAC address",
                        tap_name
                    ));
                }
                let mac = mac_address(&net_device, 0);

                let port_key = net_hotplug_key(&tap_name);
                let port = self.reserve_hotplug_port(&port_key)?;
                let hotplug_result = self
                    .vmm_instance
                    .add_pcie_device(&port.name, net_device_kind(mac.clone(), tap_name.clone()))
                    .await
                    .context(format!(
                        "failed to hotplug network device over TAP {} into PCIe port {}",
                        tap_name, port.name
                    ));

                if let Err(err) = hotplug_result {
                    let _ = self.release_hotplug_port(&port_key);
                    return Err(err);
                }

                info!(
                    sl!(),
                    "openvmm: hotplugged virtio-net-pci over TAP {} (mac {}) at port {} (pci_path {})",
                    tap_name,
                    mac,
                    port.name,
                    port.pci_path
                );

                // The agent waits for the NIC at this guest PCI path before
                // configuring it (update_interface device_path).
                net_device.config.pci_path = Some(port.pci_path.clone());
                Ok(DeviceType::Network(net_device))
            }
            other => {
                if matches!(other, DeviceType::VfioModern(_) | DeviceType::Vfio(_)) {
                    return Err(anyhow!(
                        "openvmm: VFIO devices are cold-plug only and must be \
                         added before start_vm; got {} after VMM start",
                        other
                    ));
                }
                // Data-path devices the workload would silently miss.
                if matches!(
                    other,
                    DeviceType::VhostUserNetwork(_) | DeviceType::VhostUserBlk(_)
                ) {
                    return Err(anyhow!(
                        "openvmm does not support hotplugging {} after VMM start",
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
            DeviceType::BlockModern(block_device) => {
                let device_id = block_device.lock().await.device_id.clone();
                let Some(port) = self.hotplug_port(&device_id) else {
                    warn!(
                        sl!(),
                        "openvmm: no hotplug mapping found for block device {}", device_id
                    );
                    return Ok(());
                };

                self.vmm_instance
                    .remove_pcie_device(&port.name)
                    .await
                    .context(format!(
                        "failed to hot-remove block device {} from PCIe port {}",
                        device_id, port.name
                    ))?;

                let _ = self.release_hotplug_port(&device_id);

                info!(
                    sl!(),
                    "openvmm: hot-removed block device {} from PCIe port {}", device_id, port.name
                );
                Ok(())
            }
            DeviceType::Network(net_device) => {
                let tap_name = net_device.config.host_dev_name;
                let port_key = net_hotplug_key(&tap_name);
                let Some(port) = self.hotplug_port(&port_key) else {
                    // Cold-plugged at start_vm; it stays until VM teardown.
                    info!(
                        sl!(),
                        "openvmm: network device over TAP {} is cold-plugged; nothing to hot-remove",
                        tap_name
                    );
                    return Ok(());
                };

                // After stop_vm the NIC went away with the VM; only free the port.
                if self.state == VmmState::VmRunning {
                    self.vmm_instance
                        .remove_pcie_device(&port.name)
                        .await
                        .context(format!(
                            "failed to hot-remove network device over TAP {} from PCIe port {}",
                            tap_name, port.name
                        ))?;
                }

                let _ = self.release_hotplug_port(&port_key);

                info!(
                    sl!(),
                    "openvmm: released network device over TAP {} from PCIe port {}",
                    tap_name,
                    port.name
                );
                Ok(())
            }
            DeviceType::VfioModern(_) | DeviceType::Vfio(_) => Err(anyhow!(
                "openvmm: VFIO devices are cold-plug only and remain attached until VM teardown"
            )),
            other => {
                warn!(sl!(), "openvmm: remove_device stub for {}", other);
                Ok(())
            }
        }
    }

    pub(crate) async fn update_device(&mut self, device: DeviceType) -> Result<()> {
        match device {
            DeviceType::VfioModern(_) | DeviceType::Vfio(_) => Err(anyhow!(
                "openvmm: VFIO devices are cold-plug only and cannot be updated after VM creation"
            )),
            other => {
                warn!(sl!(), "openvmm: update_device stub for {}", other);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::driver::vfio_device::VfioDeviceModern;
    use crate::device::driver::vhost_user_blk::VhostUserBlkDevice;
    use crate::{
        Address, BlockConfigModern, BlockDeviceModernHandle, NetworkConfig, NetworkDevice,
        VfioDevice, VhostUserNetDevice,
    };
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex};

    #[tokio::test]
    async fn remove_block_device_keeps_port_reserved_when_rpc_fails() {
        let (exit_notify, _exit_waiter) = watch::channel(None);
        let mut inner = OpenVmmInner::new(exit_notify);
        let device_id = "block0";
        let port = inner.reserve_hotplug_port(device_id).unwrap();
        let free_ports = inner.free_hotplug_ports.len();
        let device = DeviceType::BlockModern(
            BlockDeviceModernHandle::new(device_id.to_string(), BlockConfigModern::default()).arc(),
        );

        assert!(inner.remove_device(device).await.is_err());

        let attached_port = inner.hotplug_port(device_id).unwrap();
        assert_eq!(attached_port.name, port.name);
        assert_eq!(inner.free_hotplug_ports.len(), free_ports);

        let released_port = inner.release_hotplug_port(device_id).unwrap();
        assert_eq!(released_port.name, port.name);
        assert!(inner.hotplug_port(device_id).is_none());
        assert_eq!(inner.free_hotplug_ports.len(), free_ports + 1);
    }

    #[tokio::test]
    async fn vfio_devices_are_cold_plug_only_after_vm_start() {
        let (exit_notify, _exit_waiter) = watch::channel(None);
        let mut inner = OpenVmmInner::new(exit_notify);
        inner.state = VmmState::VmRunning;
        let modern = DeviceType::VfioModern(Arc::new(Mutex::new(VfioDeviceModern::default())));
        let legacy = DeviceType::Vfio(VfioDevice::default());

        for device in [modern, legacy] {
            assert!(inner.add_device(device.clone()).await.is_err());
            assert!(inner.remove_device(device.clone()).await.is_err());
            assert!(inner.update_device(device).await.is_err());
        }
    }

    fn running_inner() -> OpenVmmInner {
        let (exit_notify, _exit_waiter) = watch::channel(None);
        let mut inner = OpenVmmInner::new(exit_notify);
        inner.state = VmmState::VmRunning;
        inner
    }

    fn tap_nic(tap_name: &str, mac: Option<[u8; 6]>) -> DeviceType {
        DeviceType::Network(NetworkDevice {
            config: NetworkConfig {
                host_dev_name: tap_name.to_string(),
                guest_mac: mac.map(Address),
                ..Default::default()
            },
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn network_hotplug_releases_port_when_rpc_fails() {
        let mut inner = running_inner();
        let free_ports = inner.free_hotplug_ports.len();

        // No OpenVMM process is running, so the AddPcieDevice RPC fails.
        let nic = tap_nic("tap0_kata", Some([0x02, 0, 0, 0, 0, 0x10]));
        assert!(inner.add_device(nic).await.is_err());

        assert!(inner.hotplug_port(&net_hotplug_key("tap0_kata")).is_none());
        assert_eq!(inner.free_hotplug_ports.len(), free_ports);
    }

    #[tokio::test]
    async fn network_hotplug_requires_tap_and_mac() {
        let mut inner = running_inner();
        let free_ports = inner.free_hotplug_ports.len();

        assert!(inner
            .add_device(tap_nic("", Some([2, 0, 0, 0, 0, 1])))
            .await
            .is_err());
        assert!(inner.add_device(tap_nic("tap0_kata", None)).await.is_err());
        assert_eq!(inner.free_hotplug_ports.len(), free_ports);
    }

    #[tokio::test]
    async fn network_remove_after_vm_stop_only_frees_the_port() {
        let (exit_notify, _exit_waiter) = watch::channel(None);
        let mut inner = OpenVmmInner::new(exit_notify);
        let port_key = net_hotplug_key("tap0_kata");
        inner.reserve_hotplug_port(&port_key).unwrap();
        let free_ports = inner.free_hotplug_ports.len();

        // Detach rebuilds the device from its config: empty device_id, no MAC.
        inner
            .remove_device(tap_nic("tap0_kata", None))
            .await
            .unwrap();

        assert!(inner.hotplug_port(&port_key).is_none());
        assert_eq!(inner.free_hotplug_ports.len(), free_ports + 1);
    }

    #[tokio::test]
    async fn cold_plugged_network_remove_is_a_no_op() {
        let mut inner = running_inner();
        let free_ports = inner.free_hotplug_ports.len();

        inner
            .remove_device(tap_nic("tap0_kata", None))
            .await
            .unwrap();

        assert_eq!(inner.free_hotplug_ports.len(), free_ports);
    }

    #[tokio::test]
    async fn vhost_user_devices_are_rejected_after_vm_start() {
        let mut inner = running_inner();

        let net = DeviceType::VhostUserNetwork(VhostUserNetDevice::default());
        assert!(inner.add_device(net).await.is_err());
        let blk = DeviceType::VhostUserBlk(VhostUserBlkDevice::default());
        assert!(inner.add_device(blk).await.is_err());
    }
}
