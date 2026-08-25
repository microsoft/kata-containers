// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::types::{
    ContainerConfig, ContainerID, ContainerProcess, ContainerSnapshotInventory, ExecProcessRequest,
    KillRequest, ProcessExitStatus, ProcessStateInfo, ResizePTYRequest, ShutdownRequest, StatsInfo,
    UpdateRequest, PID,
};
use anyhow::Result;
use async_trait::async_trait;
use oci_spec::runtime as oci;

#[async_trait]
pub trait ContainerManager: Send + Sync {
    // container lifecycle
    async fn create_container(&self, config: ContainerConfig, spec: oci::Spec) -> Result<PID>;
    async fn pause_container(&self, container_id: &ContainerID) -> Result<()>;
    async fn resume_container(&self, container_id: &ContainerID) -> Result<()>;
    async fn stats_container(&self, container_id: &ContainerID) -> Result<StatsInfo>;
    async fn update_container(&self, req: UpdateRequest) -> Result<()>;
    async fn connect_container(&self, container_id: &ContainerID) -> Result<PID>;

    // process lifecycle
    async fn close_process_io(&self, process_id: &ContainerProcess) -> Result<()>;
    async fn delete_process(&self, process_id: &ContainerProcess) -> Result<ProcessStateInfo>;
    async fn exec_process(&self, req: ExecProcessRequest) -> Result<()>;
    async fn kill_process(&self, req: &KillRequest) -> Result<()>;
    async fn resize_process_pty(&self, req: &ResizePTYRequest) -> Result<()>;
    async fn start_process(&self, process_id: &ContainerProcess) -> Result<PID>;
    async fn state_process(&self, process_id: &ContainerProcess) -> Result<ProcessStateInfo>;
    async fn wait_process(&self, process_id: &ContainerProcess) -> Result<ProcessExitStatus>;
    async fn prepare_restored_container(&self, host_id: &str, guest_id: &str) -> Result<()>;
    async fn mark_restored_container_running(&self, host_id: &str) -> Result<PID>;

    // utility
    async fn pid(&self) -> Result<PID>;
    async fn need_shutdown_sandbox(&self, req: &ShutdownRequest) -> bool;
    async fn is_sandbox_container(&self, process_id: &ContainerProcess) -> bool;
    async fn snapshot_inventory(&self) -> Result<ContainerSnapshotInventory>;
}
