// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    types::{ContainerProcess, SandboxConfig, SandboxExitInfo, SandboxStatus},
    ContainerManager,
};

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct SandboxNetworkEnv {
    pub netns: Option<String>,
    pub network_created: bool,
}

impl std::fmt::Debug for SandboxNetworkEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxNetworkEnv")
            .field("netns", &self.netns)
            .field("network_created", &self.network_created)
            .finish()
    }
}

#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn add_sandbox(&self, config: SandboxConfig) -> Result<()>;
    async fn start(&self, sandbox_id: &str) -> Result<()>;
    async fn start_template(&self) -> Result<()>;
    async fn stop(&self, sandbox_id: &str) -> Result<()>;
    async fn cleanup(&self) -> Result<()>;
    async fn shutdown(&self, sandbox_id: &str, force: bool) -> Result<()>;
    async fn status(&self, sandbox_id: &str) -> Result<SandboxStatus>;
    async fn wait(&self, sandbox_id: &str) -> Result<SandboxExitInfo>;

    // utils
    async fn set_iptables(&self, is_ipv6: bool, data: Vec<u8>) -> Result<Vec<u8>>;
    async fn get_iptables(&self, is_ipv6: bool) -> Result<Vec<u8>>;
    async fn direct_volume_stats(&self, volume_path: &str) -> Result<String>;
    async fn direct_volume_resize(&self, resize_req: agent::ResizeVolumeRequest) -> Result<()>;
    async fn agent_sock(&self) -> Result<String>;
    async fn wait_process(
        &self,
        cm: Arc<dyn ContainerManager>,
        process_id: ContainerProcess,
        shim_pid: u32,
    ) -> Result<()>;

    // Docker 26+ network rescan: discover interfaces that Docker configured
    // between the Create and Start RPCs.
    async fn rescan_network(&self) -> Result<()>;

    // metrics function
    async fn agent_metrics(&self) -> Result<String>;
    async fn hypervisor_metrics(&self) -> Result<String>;

    // set agent policy
    async fn set_policy(&self, policy: &str) -> Result<()>;
}
