// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate slog;

logging::logger_with_subsystem!(sl, "agent");

pub mod kata;
mod log_forwarder;
mod sock;
pub mod types;
pub use types::{
    ARPNeighbor, ARPNeighbors, AddArpNeighborRequest, AddSwapPathRequest, AddSwapRequest,
    BlkioStatsEntry, CheckRequest, CloseStdinRequest, ContainerID, ContainerProcessID,
    CopyFileRequest, CreateContainerRequest, CreateSandboxRequest, Empty, ExecProcessRequest,
    FSGroup, FSGroupChangePolicy, GetDiagnosticDataRequest, GetDiagnosticDataResponse,
    GetGuestDetailsRequest, GetIPTablesRequest, GetIPTablesResponse, GuestDetailsResponse,
    HealthCheckResponse, IPAddress, IPFamily, Interface, Interfaces, ListProcessesRequest,
    MemHotplugByProbeRequest, MetricsResponse, OnlineCPUMemRequest, OomEventResponse,
    PrepareGuestMountRequest, ReadStreamRequest, ReadStreamResponse, RebindContainer,
    RebindSandboxRequest, RemoveContainerRequest, ReseedRandomDevRequest, ResizeVolumeRequest,
    Route, Routes, SetGuestDateTimeRequest, SetIPTablesRequest, SetIPTablesResponse,
    SignalProcessRequest, StatsContainerResponse, Storage, TtyWinResizeRequest,
    UpdateContainerRequest, UpdateInterfaceRequest, UpdateRoutesRequest, VersionCheckResponse,
    VolumeStatsRequest, VolumeStatsResponse, WaitProcessRequest, WaitProcessResponse,
    WriteStreamRequest, WriteStreamResponse,
};

use anyhow::Result;
use async_trait::async_trait;

use kata_types::config::Agent as AgentConfig;

use crate::types::SetPolicyRequest;

pub const AGENT_KATA: &str = "kata";

/// Proof that a reconnect belongs to one planned disconnect generation.
///
/// The token is returned only after new agent work has been blocked and writes
/// have drained. Keeping its generation private prevents an unrelated or stale
/// reconnect from attaching to the wrong VM state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentDisconnectToken {
    generation: u64,
}

impl AgentDisconnectToken {
    pub fn generation(self) -> u64 {
        self.generation
    }
}

#[async_trait]
pub trait AgentManager: Send + Sync {
    async fn start(&self, address: &str) -> Result<()>;
    async fn stop(&self);
    /// Close the transport permanently unless `prepare_disconnect` was called.
    async fn disconnect(&self) -> Result<()>;
    /// Enter a planned-disconnect generation and wait for non-replayable writes.
    async fn prepare_disconnect(&self) -> Result<AgentDisconnectToken>;
    /// Connect the next generation using the token from `prepare_disconnect`.
    async fn reconnect(&self, address: &str, token: AgentDisconnectToken) -> Result<()>;

    async fn agent_sock(&self) -> Result<String>;
    async fn agent_config(&self) -> AgentConfig;
}

#[async_trait]
pub trait HealthService: Send + Sync {
    async fn check(&self, req: CheckRequest) -> Result<HealthCheckResponse>;
    async fn version(&self, req: CheckRequest) -> Result<VersionCheckResponse>;
}

#[async_trait]
pub trait Agent: AgentManager + HealthService + Send + Sync {
    // sandbox
    async fn create_sandbox(&self, req: CreateSandboxRequest) -> Result<Empty>;
    async fn destroy_sandbox(&self, req: Empty) -> Result<Empty>;
    async fn online_cpu_mem(&self, req: OnlineCPUMemRequest) -> Result<Empty>;
    async fn reseed_random_dev(&self, req: ReseedRandomDevRequest) -> Result<Empty>;
    async fn set_guest_date_time(&self, req: SetGuestDateTimeRequest) -> Result<Empty>;

    // network
    async fn add_arp_neighbors(&self, req: AddArpNeighborRequest) -> Result<Empty>;
    async fn list_interfaces(&self, req: Empty) -> Result<Interfaces>;
    async fn list_routes(&self, req: Empty) -> Result<Routes>;
    async fn update_interface(&self, req: UpdateInterfaceRequest) -> Result<Interface>;
    async fn update_routes(&self, req: UpdateRoutesRequest) -> Result<Routes>;

    // container
    async fn create_container(&self, req: CreateContainerRequest) -> Result<Empty>;
    async fn pause_container(&self, req: ContainerID) -> Result<Empty>;
    async fn remove_container(&self, req: RemoveContainerRequest) -> Result<Empty>;
    async fn resume_container(&self, req: ContainerID) -> Result<Empty>;
    async fn start_container(&self, req: ContainerID) -> Result<Empty>;
    async fn stats_container(&self, req: ContainerID) -> Result<StatsContainerResponse>;
    async fn update_container(&self, req: UpdateContainerRequest) -> Result<Empty>;
    async fn rebind_sandbox(&self, req: RebindSandboxRequest) -> Result<Empty>;
    async fn prepare_guest_mount(&self, req: PrepareGuestMountRequest) -> Result<Empty>;

    // process
    async fn exec_process(&self, req: ExecProcessRequest) -> Result<Empty>;
    async fn signal_process(&self, req: SignalProcessRequest) -> Result<Empty>;
    async fn wait_process(&self, req: WaitProcessRequest) -> Result<WaitProcessResponse>;

    // io and tty
    async fn close_stdin(&self, req: CloseStdinRequest) -> Result<Empty>;
    async fn read_stderr(&self, req: ReadStreamRequest) -> Result<ReadStreamResponse>;
    async fn read_stdout(&self, req: ReadStreamRequest) -> Result<ReadStreamResponse>;
    async fn tty_win_resize(&self, req: TtyWinResizeRequest) -> Result<Empty>;
    async fn write_stdin(&self, req: WriteStreamRequest) -> Result<WriteStreamResponse>;

    // utils
    async fn copy_file(&self, req: CopyFileRequest) -> Result<Empty>;
    async fn get_metrics(&self, req: Empty) -> Result<MetricsResponse>;
    async fn get_oom_event(&self, req: Empty) -> Result<OomEventResponse>;
    async fn get_ip_tables(&self, req: GetIPTablesRequest) -> Result<GetIPTablesResponse>;
    async fn set_ip_tables(&self, req: SetIPTablesRequest) -> Result<SetIPTablesResponse>;
    async fn get_volume_stats(&self, req: VolumeStatsRequest) -> Result<VolumeStatsResponse>;
    async fn resize_volume(&self, req: ResizeVolumeRequest) -> Result<Empty>;
    async fn get_guest_details(&self, req: GetGuestDetailsRequest) -> Result<GuestDetailsResponse>;
    async fn add_swap(&self, req: AddSwapRequest) -> Result<Empty>;
    async fn add_swap_path(&self, req: AddSwapPathRequest) -> Result<Empty>;
    async fn set_policy(&self, req: SetPolicyRequest) -> Result<Empty>;

    // diagnostics
    async fn get_diagnostic_data(
        &self,
        req: GetDiagnosticDataRequest,
    ) -> Result<GetDiagnosticDataResponse>;
}
