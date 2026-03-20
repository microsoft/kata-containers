// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io::{self, Error};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hypervisor::device::device_manager::{do_handle_device, DeviceManager};
use hypervisor::device::driver::NetworkConfig;
use hypervisor::device::{DeviceConfig, DeviceType};
use hypervisor::{device::driver, Hypervisor, NetworkDevice};
use hypervisor::{get_vfio_device, VfioConfig};
use tokio::sync::RwLock;

use super::endpoint_persist::{EndpointState, PhysicalEndpointState};
use super::Endpoint;
use crate::network::network_pair::{NetworkInterface, NetworkPair};
use crate::network::utils::{self, link};

#[derive(Debug)]
pub struct VendorDevice {
    vendor_id: String,
    device_id: String,
}

impl VendorDevice {
    pub fn new(vendor_id: &str, device_id: &str) -> Result<Self> {
        if vendor_id.is_empty() || device_id.is_empty() {
            return Err(anyhow!(
                "invalid parameters vendor_id {} device_id {}",
                vendor_id,
                device_id
            ));
        }
        Ok(Self {
            vendor_id: vendor_id.to_string(),
            device_id: device_id.to_string(),
        })
    }

    pub fn vendor_device_id(&self) -> String {
        format!("{}_{}", &self.vendor_id, &self.device_id)
    }
}

#[derive(Debug)]
pub struct PhysicalEndpoint {
    iface_name: String,
    hard_addr: String,
    bdf: String,
    driver: String,
    vendor_device_id: VendorDevice,
    is_vf: bool,
    bus_type: link::BusType,
    net_pair: NetworkPair,
    d: Arc<RwLock<DeviceManager>>,
}

impl PhysicalEndpoint {
    /// Create a new PhysicalEndpoint.
    ///
    /// For VF (SR-IOV Virtual Function) devices, the NIC will be passed through
    /// to the VM via VFIO — no tap/bridge pair is needed, so we create a minimal
    /// stub NetworkPair.
    ///
    /// For non-VF physical NICs, we need a real tap+bridge pair (like veth
    /// endpoints use) so that traffic can flow between the host NIC and the VM
    /// through the hypervisor's TAP backend. The `handle`, `idx`, `model`, and
    /// `queues` parameters are required to create this pair.
    pub async fn new(
        handle: &rtnetlink::Handle,
        name: &str,
        hardware_addr: &[u8],
        idx: u32,
        model: &str,
        queues: usize,
        d: Arc<RwLock<DeviceManager>>,
    ) -> Result<Self> {
        // Determine bus type (PCI or VMBus) and resolve the sysfs device path.
        // For PCI: uses ethtool to get BDF, path = /sys/bus/pci/devices/<bdf>
        // For VMBus: resolves device symlink, path = /sys/bus/vmbus/devices/<guid>
        let (sys_iface_device_path, bdf, bus_type) =
            link::get_iface_device_path(name).context("get iface device path")?;
        let sys_device_path = Path::new(&sys_iface_device_path);

        // Get driver by following symlink <device_path>/driver
        let driver_path = sys_device_path.join("driver");
        let link_target = driver_path.read_link().context("read link")?;
        let driver = link_target
            .file_name()
            .map_or(String::new(), |v| v.to_str().unwrap().to_owned());

        // Get vendor and device id from sysfs device path
        let iface_device_path = sys_device_path.join("device");
        let device_id = std::fs::read_to_string(&iface_device_path)
            .with_context(|| format!("read device path {:?}", &iface_device_path))?;

        let iface_vendor_path = sys_device_path.join("vendor");
        let vendor_id = std::fs::read_to_string(&iface_vendor_path)
            .with_context(|| format!("read vendor path {:?}", &iface_vendor_path))?;
        let is_vf = link::is_vf(name).context("check if is vf")?;

        // VF devices use VFIO passthrough — no real tap/bridge needed.
        // Non-VF devices need a real tap+bridge pair for the hypervisor to
        // connect the host NIC traffic into the VM, matching Go's
        // createNetworkInterfacePair() call in createPhysicalEndpoint().
        let net_pair = if is_vf {
            NetworkPair::new_for_physical(name, hardware_addr, is_vf)
                .context("new network pair for physical vf endpoint")?
        } else {
            NetworkPair::new(handle, idx, name, model, queues)
                .await
                .context("new network pair for physical non-vf endpoint")?
        };

        Ok(Self {
            iface_name: name.to_string(),
            hard_addr: utils::get_mac_addr(hardware_addr).context("get mac addr")?,
            vendor_device_id: VendorDevice::new(&vendor_id, &device_id)
                .context("new vendor device")?,
            driver,
            bdf,
            is_vf,
            bus_type,
            net_pair,
            d,
        })
    }

    pub fn network_pair(&self) -> &NetworkPair {
        &self.net_pair
    }

    fn get_network_config(&self) -> Result<NetworkConfig> {
        let iface = &self.net_pair.tap.tap_iface;
        let guest_mac = utils::parse_mac(&iface.hard_addr).ok_or_else(|| {
            Error::new(
                io::ErrorKind::InvalidData,
                format!("hard_addr {}", &iface.hard_addr),
            )
        })?;

        Ok(NetworkConfig {
            host_dev_name: iface.name.clone(),
            virt_iface_name: self.net_pair.virt_iface.name.clone(),
            guest_mac: Some(guest_mac),
            ..Default::default()
        })
    }
}

#[async_trait]
impl Endpoint for PhysicalEndpoint {
    async fn name(&self) -> String {
        self.iface_name.clone()
    }

    async fn hardware_addr(&self) -> String {
        self.hard_addr.clone()
    }

    async fn attach(&self) -> Result<()> {
        if self.is_vf {
            // bind physical interface from host driver and bind to vfio
            driver::bind_device_to_vfio(
                &self.bdf,
                &self.driver,
                &self.vendor_device_id.vendor_device_id(),
            )
            .with_context(|| format!("bind physical endpoint from {} to vfio", &self.driver))?;

            let vfio_device =
                get_vfio_device(self.bdf.clone()).context("get vfio device failed.")?;
            let vfio_dev_config = &mut VfioConfig {
                host_path: vfio_device.clone(),
                dev_type: "pci".to_string(),
                hostdev_prefix: "physical_nic_".to_owned(),
                ..Default::default()
            };

            // create and insert VFIO device into Kata VM
            do_handle_device(&self.d, &DeviceConfig::VfioCfg(vfio_dev_config.clone()))
                .await
                .context("do handle device failed.")?;

            Ok(())
        } else {
            self.net_pair
                .add_network_model()
                .await
                .context("add network model")?;
            let config = self.get_network_config().context("get network config")?;
            do_handle_device(&self.d, &DeviceConfig::NetworkCfg(config))
                .await
                .context("do handle network Physical endpoint device failed.")?;
            Ok(())
        }
    }

    // detach for physical endpoint unbinds the physical network interface from vfio-pci
    // and binds it back to the saved host driver.
    async fn detach(&self, _hypervisor: &dyn Hypervisor) -> Result<()> {
        if self.is_vf {
            driver::bind_device_to_host(
                &self.bdf,
                &self.driver,
                &self.vendor_device_id.vendor_device_id(),
            )
            .with_context(|| {
                format!(
                    "bind physical endpoint device from vfio to {}",
                    &self.driver
                )
            })?;
            Ok(())
        } else {
            self.net_pair
                .del_network_model()
                .await
                .context("del network model")?;
            let config = self.get_network_config().context("get network config")?;
            _hypervisor
                .remove_device(DeviceType::Network(NetworkDevice {
                    config,
                    ..Default::default()
                }))
                .await
                .context("remove Physical endpoint device by hypervisor failed.")?;
            Ok(())
        }
    }

    async fn save(&self) -> Option<EndpointState> {
        Some(EndpointState {
            physical_endpoint: Some(PhysicalEndpointState {
                bdf: self.bdf.clone(),
                driver: self.driver.clone(),
                vendor_id: self.vendor_device_id.vendor_id.clone(),
                device_id: self.vendor_device_id.device_id.clone(),
                hard_addr: self.hard_addr.clone(),
                is_vf: self.is_vf,
                iface_name: self.iface_name.clone(),
                bus_type: match self.bus_type {
                    link::BusType::Pci => "pci".to_string(),
                    link::BusType::Vmbus => "vmbus".to_string(),
                },
            }),
            ..Default::default()
        })
    }
}
