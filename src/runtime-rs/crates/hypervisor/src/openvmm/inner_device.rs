// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM device management (stubs).

use anyhow::Result;

use super::inner::OpenVmmInner;
use crate::device::DeviceType;
use crate::VmmState;

impl OpenVmmInner {
    pub(crate) async fn add_device(
        &mut self,
        device: DeviceType,
    ) -> Result<DeviceType> {
        if self.state == VmmState::NotReady {
            info!(sl!(), "openvmm: VMM not ready, queueing device {}", device);
            self.pending_devices.push(device.clone());
            return Ok(device);
        }

        // TODO: Map kata DeviceType to OpenVMM device configuration
        // and add it to the running VM via the MSHV partition.
        warn!(sl!(), "openvmm: add_device stub for {}", device);
        Ok(device)
    }

    pub(crate) async fn remove_device(
        &mut self,
        device: DeviceType,
    ) -> Result<()> {
        warn!(sl!(), "openvmm: remove_device stub for {}", device);
        Ok(())
    }

    pub(crate) async fn update_device(
        &mut self,
        device: DeviceType,
    ) -> Result<()> {
        warn!(sl!(), "openvmm: update_device stub for {}", device);
        Ok(())
    }
}
