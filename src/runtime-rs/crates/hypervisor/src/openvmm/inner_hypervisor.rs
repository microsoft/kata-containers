// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM hypervisor lifecycle management (stubs).

use anyhow::{anyhow, Result};

use super::inner::OpenVmmInner;
use crate::utils::{get_jailer_root, get_sandbox_path};
use crate::{MemoryConfig, VcpuThreadIds, VmmState};

impl OpenVmmInner {
    pub(crate) async fn prepare_vm(
        &mut self,
        id: &str,
        netns: Option<String>,
    ) -> Result<()> {
        info!(sl!(), "openvmm: prepare_vm id={}", id);
        self.id = id.to_string();
        self.state = VmmState::NotReady;
        self.vm_path = get_sandbox_path(id);
        self.netns = netns;
        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, _timeout: i32) -> Result<()> {
        info!(sl!(), "openvmm: start_vm (stub)");
        // TODO: Create MSHV partition using virt_mshv::LinuxMshv,
        // set up devices, load kernel/initrd, and boot the VM.
        self.state = VmmState::VmRunning;
        Err(anyhow!("openvmm start_vm not yet implemented"))
    }

    pub(crate) async fn stop_vm(&mut self) -> Result<()> {
        info!(sl!(), "openvmm: stop_vm (stub)");
        self.state = VmmState::NotReady;
        Ok(())
    }

    pub(crate) async fn pause_vm(&self) -> Result<()> {
        Err(anyhow!("openvmm pause_vm not yet implemented"))
    }

    pub(crate) async fn resume_vm(&self) -> Result<()> {
        Err(anyhow!("openvmm resume_vm not yet implemented"))
    }

    pub(crate) async fn save_vm(&self) -> Result<()> {
        Err(anyhow!("openvmm save_vm not yet implemented"))
    }

    pub(crate) async fn resize_vcpu(
        &self,
        old_vcpus: u32,
        _new_vcpus: u32,
    ) -> Result<(u32, u32)> {
        // No-op stub: return current vcpu count unchanged.
        Ok((old_vcpus, old_vcpus))
    }

    pub(crate) async fn resize_memory(
        &mut self,
        new_mem_mb: u32,
    ) -> Result<(u32, MemoryConfig)> {
        Ok((
            new_mem_mb,
            MemoryConfig {
                ..Default::default()
            },
        ))
    }

    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        // TODO: Return the hvsocket/vsock path for agent communication.
        Ok(format!("hvsock://{}/kata.hvsock", self.vm_path))
    }

    pub(crate) async fn disconnect(&mut self) {
        info!(sl!(), "openvmm: disconnect (stub)");
    }

    pub(crate) async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        Ok(VcpuThreadIds::default())
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn get_pids(&self) -> Result<Vec<u32>> {
        Ok(vec![std::process::id()])
    }

    pub(crate) async fn get_vmm_master_tid(&self) -> Result<u32> {
        Ok(nix::unistd::gettid().as_raw() as u32)
    }

    pub(crate) async fn get_ns_path(&self) -> Result<String> {
        let pid = std::process::id();
        let tid = nix::unistd::gettid().as_raw() as u32;
        Ok(format!("/proc/{}/task/{}/ns", pid, tid))
    }

    pub(crate) async fn check(&self) -> Result<()> {
        // TODO: Health check — verify MSHV device is accessible.
        Ok(())
    }

    pub(crate) async fn get_jailer_root(&self) -> Result<String> {
        Ok(get_jailer_root(&self.id))
    }

    pub(crate) async fn get_hypervisor_metrics(&self) -> Result<String> {
        Ok(String::new())
    }

    pub(crate) async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        Err(anyhow!(
            "openvmm get_passfd_listener_addr not yet implemented"
        ))
    }
}
