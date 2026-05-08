// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

mod create;
pub use create::{create_link, LinkType};
mod driver_info;
pub use driver_info::get_driver_info;
mod macros;
mod manager;
pub use manager::get_link_from_message;

use std::path::Path;

use anyhow::{anyhow, Context, Result};

/// The bus type backing a physical network interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusType {
    Pci,
    Vmbus,
}

/// Determines the bus type of a network interface by reading the
/// `/sys/class/net/<name>/device/subsystem` symlink.
///
/// Returns `Some(BusType)` for PCI or VMBus devices, `None` for virtual
/// interfaces that have no backing hardware device (veth, bridge, etc.).
pub fn get_bus_type(name: &str) -> Result<Option<BusType>> {
    let subsystem_path = Path::new("/sys/class/net")
        .join(name)
        .join("device/subsystem");
    match std::fs::read_link(&subsystem_path) {
        Ok(target) => {
            let bus_name = target.file_name().and_then(|f| f.to_str()).unwrap_or("");
            match bus_name {
                "pci" => Ok(Some(BusType::Pci)),
                "vmbus" => Ok(Some(BusType::Vmbus)),
                _ => Ok(None),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!(e).context(format!(
            "failed to read subsystem symlink for interface {}",
            name
        ))),
    }
}

/// Returns the sysfs device path and device identifier for a network interface.
///
/// For PCI devices, uses ethtool to get the BDF (e.g. "0000:01:00.0") and
/// returns `/sys/bus/pci/devices/<bdf>`.
///
/// For VMBus devices, resolves `/sys/class/net/<name>/device` to get the
/// device GUID and returns `/sys/bus/vmbus/devices/<guid>`.
///
/// This mirrors Go's `getIfaceDevicePath()` which branches on
/// `link.Attrs().ParentDevBus`.
pub fn get_iface_device_path(name: &str) -> Result<(String, String, BusType)> {
    let bus_type = get_bus_type(name)?
        .ok_or_else(|| anyhow!("unsupported or no bus for interface {}", name))?;

    match bus_type {
        BusType::Pci => {
            let driver_info = get_driver_info(name).context("get driver info")?;
            let bdf = driver_info.bus_info;
            let path = Path::new("/sys/bus/pci/devices").join(&bdf);
            Ok((path.to_string_lossy().into_owned(), bdf, BusType::Pci))
        }
        BusType::Vmbus => {
            let device_link = Path::new("/sys/class/net").join(name).join("device");
            let resolved =
                std::fs::canonicalize(&device_link).context("resolve vmbus device path")?;
            let guid = resolved
                .file_name()
                .and_then(|f| f.to_str())
                .ok_or_else(|| anyhow!("failed to get vmbus device guid"))?
                .to_string();
            let path = Path::new("/sys/bus/vmbus/devices").join(&guid);
            Ok((path.to_string_lossy().into_owned(), guid, BusType::Vmbus))
        }
    }
}

use std::os::unix::io::RawFd;

use netlink_packet_route::link::State;

#[cfg(test)]
pub use create::net_test_utils;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Namespace {
    NetNsPid(u32),
    #[allow(dead_code)]
    NetNsFd(RawFd),
}
impl Default for Namespace {
    fn default() -> Self {
        Self::NetNsPid(0)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LinkStatistics {
    #[allow(dead_code)]
    Stats(LinkStatistics32),
    Stats64(LinkStatistics64),
}
impl Default for LinkStatistics {
    fn default() -> Self {
        Self::Stats64(LinkStatistics64::default())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct LinkStatistics32 {
    pub rx_packets: u32,
    pub tx_packets: u32,
    pub rx_bytes: u32,
    pub tx_bytes: u32,
    pub rx_errors: u32,
    pub tx_errors: u32,
    pub rx_dropped: u32,
    pub tx_dropped: u32,
    pub multicast: u32,
    pub collisions: u32,
    pub rx_length_errors: u32,
    pub rx_over_errors: u32,
    pub rx_crc_errors: u32,
    pub rx_frame_errors: u32,
    pub rx_fifo_errors: u32,
    pub rx_missed_errors: u32,
    pub tx_aborted_errors: u32,
    pub tx_carrier_errors: u32,
    pub tx_fifo_errors: u32,
    pub tx_heartbeat_errors: u32,
    pub tx_window_errors: u32,
    pub rx_compressed: u32,
    pub tx_compressed: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct LinkStatistics64 {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
    pub rx_length_errors: u64,
    pub rx_over_errors: u64,
    pub rx_crc_errors: u64,
    pub rx_frame_errors: u64,
    pub rx_fifo_errors: u64,
    pub rx_missed_errors: u64,
    pub tx_aborted_errors: u64,
    pub tx_carrier_errors: u64,
    pub tx_fifo_errors: u64,
    pub tx_heartbeat_errors: u64,
    pub tx_window_errors: u64,
    pub rx_compressed: u64,
    pub tx_compressed: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct LinkXdp {
    pub fd: RawFd,
    pub attached: bool,
    pub flags: u32,
    pub prog_id: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OperState(State);
impl Default for OperState {
    fn default() -> Self {
        Self(State::Unknown)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct LinkAttrs {
    pub index: u32,
    pub mtu: u32,
    pub txq_len: u32,

    pub name: String,
    pub hardware_addr: Vec<u8>,
    pub flags: u32,
    pub parent_index: u32,
    pub master_index: u32,
    pub namespace: Namespace,
    pub alias: String,
    pub statistics: LinkStatistics,
    pub promisc: u32,
    pub xdp: LinkXdp,
    pub link_layer_type: u16,
    pub proto_info: Vec<u8>,
    pub oper_state: OperState,
    pub net_ns_id: i32,
    pub num_tx_queues: u32,
    pub num_rx_queues: u32,
    pub gso_max_size: u32,
    pub gso_max_seqs: u32,
    pub vfs: Vec<u8>,
    pub group: u32,
}

pub trait Link: Send + Sync {
    fn attrs(&self) -> &LinkAttrs;
    fn set_attrs(&mut self, attr: LinkAttrs);
    fn r#type(&self) -> &str;
}
