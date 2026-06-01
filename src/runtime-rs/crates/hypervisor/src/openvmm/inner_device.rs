// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM device management (stubs).

use std::os::unix::fs::FileTypeExt;

use anyhow::{anyhow, Context, Result};
use vm_resource::IntoResource;

use super::inner::OpenVmmInner;
use crate::device::DeviceType;
use crate::{VmmState, KATA_BLK_DEV_TYPE};

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
                let hotplug_result = async {
                    let metadata =
                        std::fs::metadata(&block.config.path_on_host).with_context(|| {
                            format!(
                                "failed to stat block device path {}",
                                block.config.path_on_host
                            )
                        })?;

                    let disk = if metadata.file_type().is_block_device() {
                        let file = disk_blockdevice::open_file_for_block(
                            std::path::Path::new(&block.config.path_on_host),
                            block.config.is_readonly,
                            true,
                        )
                        .with_context(|| {
                            format!(
                                "failed to open host block device {}",
                                block.config.path_on_host
                            )
                        })?;

                        disk_backend_resources::BlockDeviceDiskHandle { file }.into_resource()
                    } else {
                        let mut options = std::fs::OpenOptions::new();
                        options.read(true);
                        if !block.config.is_readonly {
                            options.write(true);
                        }

                        let file = options.open(&block.config.path_on_host).with_context(|| {
                            format!(
                                "failed to open block device path {}",
                                block.config.path_on_host
                            )
                        })?;

                        disk_backend_resources::FileDiskHandle(file).into_resource()
                    };

                    let resource = virtio_resources::VirtioPciDeviceHandle(
                        virtio_resources::blk::VirtioBlkHandle {
                            disk,
                            read_only: block.config.is_readonly,
                        }
                        .into_resource(),
                    )
                    .into_resource();

                    self.vmm_instance
                        .add_pcie_device(port.name.clone(), resource)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to hotplug block device {} on {}",
                                block.config.path_on_host, port.name
                            )
                        })?;

                    Ok::<(), anyhow::Error>(())
                }
                .await;

                if let Err(err) = hotplug_result {
                    let _ = self.release_block_hotplug_port(&block.device_id);
                    return Err(err);
                }

                info!(
                    sl!(),
                    "openvmm: hotplugged block device {} on port {} ({})",
                    block.config.path_on_host,
                    port.name,
                    port.pci_path
                );

                block.config.pci_path = Some(port.pci_path);
                Ok(DeviceType::Block(block))
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
                    .remove_pcie_device(port.name.clone())
                    .await
                    .with_context(|| {
                        format!(
                            "failed to hot-remove block device {} from {}",
                            block.device_id, port.name
                        )
                    })?;

                info!(
                    sl!(),
                    "openvmm: hot-removed block device {} from port {}", block.device_id, port.name
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
