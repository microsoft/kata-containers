// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM device management over the standalone VM service.

use anyhow::{anyhow, Context, Result};

use super::inner::OpenVmmInner;
use super::OPENVMM_BLOCK_HOTPLUG_PORT_PREFIX;
use crate::device::DeviceType;
use crate::{VmmState, KATA_BLK_DEV_TYPE};

fn scsi_lun_from_hotplug_port(port_name: &str) -> Result<u32> {
    let index = port_name
        .strip_prefix(OPENVMM_BLOCK_HOTPLUG_PORT_PREFIX)
        .ok_or_else(|| anyhow!("invalid openvmm hotplug port name {}", port_name))?
        .parse::<u32>()
        .with_context(|| format!("invalid openvmm hotplug port name {}", port_name))?;

    Ok(index + 1)
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
                let lun = scsi_lun_from_hotplug_port(&port.name)?;
                let hotplug_result = async {
                    self.vmm_instance
                        .add_scsi_disk(
                            lun,
                            block.config.path_on_host.clone(),
                            block.config.is_readonly,
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "failed to hotplug block device {} as SCSI lun {}",
                                block.config.path_on_host, lun
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
                    "openvmm: hotplugged block device {} as SCSI lun {} via RPC",
                    block.config.path_on_host,
                    lun
                );

                block.config.scsi_addr = Some(format!("0:{}", lun));
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

                let lun = scsi_lun_from_hotplug_port(&port.name)?;

                self.vmm_instance
                    .remove_scsi_disk(lun)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to hot-remove block device {} from SCSI lun {}",
                            block.device_id, lun
                        )
                    })?;

                info!(
                    sl!(),
                    "openvmm: hot-removed block device {} from SCSI lun {}", block.device_id, lun
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
