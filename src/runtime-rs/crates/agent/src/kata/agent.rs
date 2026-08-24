// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::instrument;
use ttrpc::context as ttrpc_ctx;

use kata_types::config::Agent as AgentConfig;

use crate::{
    kata::{ActivityKind, KataAgent},
    Agent, AgentDisconnectToken, AgentManager, HealthService,
};

/// millisecond to nanosecond
const MILLISECOND_TO_NANOSECOND: i64 = 1_000_000;

/// new ttrpc context with timeout
fn new_ttrpc_ctx(timeout: i64) -> ttrpc_ctx::Context {
    ttrpc_ctx::with_timeout(timeout)
}

#[async_trait]
impl AgentManager for KataAgent {
    #[instrument]
    async fn start(&self, address: &str) -> Result<()> {
        info!(sl!(), "begin to connect agent {:?}", address);
        self.start_connection(address, None).await
    }

    async fn stop(&self) {
        self.stop_log_forwarder().await;
    }

    async fn agent_sock(&self) -> Result<String> {
        self.agent_sock().await
    }

    async fn agent_config(&self) -> AgentConfig {
        self.agent_config().await
    }

    async fn disconnect(&self) -> Result<()> {
        self.disconnect().await.context("disconnect agent")
    }

    async fn prepare_disconnect(&self) -> Result<AgentDisconnectToken> {
        self.prepare_disconnect().await
    }

    async fn reconnect(&self, address: &str, token: AgentDisconnectToken) -> Result<()> {
        self.reconnect(address, token).await
    }
}

// implement for health service
macro_rules! impl_health_service {
    ($($name: tt | $req: ty | $resp: ty),*) => {
        #[async_trait]
        impl HealthService for KataAgent {
            $(async fn $name(&self, req: $req) -> Result<$resp> {
                let r = req.into();
                let (client, timeout, _) = self.get_health_client().await.context("get health client")?;
                let resp = client.$name(new_ttrpc_ctx(timeout * MILLISECOND_TO_NANOSECOND), &r).await?;
                Ok(resp.into())
            })*
        }
    };
}

impl_health_service!(
    check | crate::CheckRequest | crate::HealthCheckResponse,
    version | crate::CheckRequest | crate::VersionCheckResponse
);

macro_rules! impl_agent {
    ($($name: tt | $req: ty | $resp: ty | $new_timeout: expr),*) => {
        #[async_trait]
        impl Agent for KataAgent {
            #[instrument(skip(req))]
            $(async fn $name(&self, req: $req) -> Result<$resp> {
                let r = req.into();
                let (client, mut timeout, _) = self.get_agent_client().await.context("get client")?;

                // update new timeout
                if let Some(v) = $new_timeout {
                    timeout = v;
                }

                let resp = client.$name(new_ttrpc_ctx(timeout * MILLISECOND_TO_NANOSECOND), &r).await?;
                Ok(resp.into())
            })*

            // Wait/read/OOM calls are unbounded observers and may span a
            // snapshot. On an error they retry only when the same generation
            // is undergoing a planned disconnect. The waiter guard then
            // acknowledges acquisition of the replacement generation.
            async fn wait_process(
                &self,
                req: crate::WaitProcessRequest,
            ) -> Result<crate::WaitProcessResponse> {
                let mut awaiting_new_generation_guard = None;
                loop {
                    let (client, _, generation, old_generation_guard) = self
                        .acquire_agent_client(ActivityKind::Reconnectable)
                        .await?;
                    drop(awaiting_new_generation_guard.take());
                    let request = req.clone().into();
                    let result = client.wait_process(new_ttrpc_ctx(0), &request).await;
                    match result {
                        Ok(response) => {
                            drop(old_generation_guard);
                            return Ok(response.into());
                        }
                        Err(_) if self.should_retry_generation(generation).await => {
                            awaiting_new_generation_guard =
                                Some(self.register_reconnect_waiter());
                            drop(old_generation_guard);
                            continue;
                        }
                        Err(error) => {
                            drop(old_generation_guard);
                            return Err(error.into());
                        }
                    }
                }
            }

            async fn read_stdout(
                &self,
                req: crate::ReadStreamRequest,
            ) -> Result<crate::ReadStreamResponse> {
                let mut awaiting_new_generation_guard = None;
                loop {
                    let (client, _, generation, old_generation_guard) = self
                        .acquire_agent_client(ActivityKind::Reconnectable)
                        .await?;
                    drop(awaiting_new_generation_guard.take());
                    let request = req.clone().into();
                    let result = client.read_stdout(new_ttrpc_ctx(0), &request).await;
                    match result {
                        Ok(response) => {
                            drop(old_generation_guard);
                            return Ok(response.into());
                        }
                        Err(_) if self.should_retry_generation(generation).await => {
                            awaiting_new_generation_guard =
                                Some(self.register_reconnect_waiter());
                            drop(old_generation_guard);
                            continue;
                        }
                        Err(error) => {
                            drop(old_generation_guard);
                            return Err(error.into());
                        }
                    }
                }
            }

            async fn read_stderr(
                &self,
                req: crate::ReadStreamRequest,
            ) -> Result<crate::ReadStreamResponse> {
                let mut awaiting_new_generation_guard = None;
                loop {
                    let (client, _, generation, old_generation_guard) = self
                        .acquire_agent_client(ActivityKind::Reconnectable)
                        .await?;
                    drop(awaiting_new_generation_guard.take());
                    let request = req.clone().into();
                    let result = client.read_stderr(new_ttrpc_ctx(0), &request).await;
                    match result {
                        Ok(response) => {
                            drop(old_generation_guard);
                            return Ok(response.into());
                        }
                        Err(_) if self.should_retry_generation(generation).await => {
                            awaiting_new_generation_guard =
                                Some(self.register_reconnect_waiter());
                            drop(old_generation_guard);
                            continue;
                        }
                        Err(error) => {
                            drop(old_generation_guard);
                            return Err(error.into());
                        }
                    }
                }
            }

            async fn write_stdin(
                &self,
                req: crate::WriteStreamRequest,
            ) -> Result<crate::WriteStreamResponse> {
                // Input cannot be replayed without risking duplicate bytes.
                // Tracking it as Write makes prepare_disconnect wait for it.
                // The _guard is dropped upon return.
                let (client, _, _, _guard) =
                    self.acquire_agent_client(ActivityKind::Write).await?;
                let request = req.into();
                let response = client.write_stdin(new_ttrpc_ctx(0), &request).await?;
                Ok(response.into())
            }

            async fn get_oom_event(&self, req: crate::Empty) -> Result<crate::OomEventResponse> {
                let mut awaiting_new_generation_guard = None;
                loop {
                    let (client, _, generation, old_generation_guard) = self
                        .acquire_agent_client(ActivityKind::Reconnectable)
                        .await?;
                    drop(awaiting_new_generation_guard.take());
                    let request = req.clone().into();
                    let result = client.get_oom_event(new_ttrpc_ctx(0), &request).await;
                    match result {
                        Ok(response) => {
                            drop(old_generation_guard);
                            return Ok(response.into());
                        }
                        Err(_) if self.should_retry_generation(generation).await => {
                            awaiting_new_generation_guard =
                                Some(self.register_reconnect_waiter());
                            drop(old_generation_guard);
                            continue;
                        }
                        Err(error) => {
                            drop(old_generation_guard);
                            return Err(error.into());
                        }
                    }
                }
            }
        }
    };
}

impl_agent!(
    create_container | crate::CreateContainerRequest | crate::Empty | None,
    start_container | crate::ContainerID | crate::Empty | None,
    remove_container | crate::RemoveContainerRequest | crate::Empty | None,
    exec_process | crate::ExecProcessRequest | crate::Empty | None,
    signal_process | crate::SignalProcessRequest | crate::Empty | None,
    update_container | crate::UpdateContainerRequest | crate::Empty | None,
    rebind_sandbox | crate::RebindSandboxRequest | crate::Empty | None,
    prepare_guest_mount | crate::PrepareGuestMountRequest | crate::Empty | None,
    stats_container | crate::ContainerID | crate::StatsContainerResponse | None,
    pause_container | crate::ContainerID | crate::Empty | None,
    resume_container | crate::ContainerID | crate::Empty | None,
    close_stdin | crate::CloseStdinRequest | crate::Empty | None,
    tty_win_resize | crate::TtyWinResizeRequest | crate::Empty | None,
    update_interface | crate::UpdateInterfaceRequest | crate::Interface | None,
    update_routes | crate::UpdateRoutesRequest | crate::Routes | None,
    add_arp_neighbors | crate::AddArpNeighborRequest | crate::Empty | None,
    list_interfaces | crate::Empty | crate::Interfaces | None,
    list_routes | crate::Empty | crate::Routes | None,
    create_sandbox | crate::CreateSandboxRequest | crate::Empty | None,
    destroy_sandbox | crate::Empty | crate::Empty | None,
    copy_file | crate::CopyFileRequest | crate::Empty | None,
    get_ip_tables | crate::GetIPTablesRequest | crate::GetIPTablesResponse | None,
    set_ip_tables | crate::SetIPTablesRequest | crate::SetIPTablesResponse | None,
    get_volume_stats | crate::VolumeStatsRequest | crate::VolumeStatsResponse | None,
    resize_volume | crate::ResizeVolumeRequest | crate::Empty | None,
    online_cpu_mem | crate::OnlineCPUMemRequest | crate::Empty | None,
    reseed_random_dev | crate::ReseedRandomDevRequest | crate::Empty | None,
    set_guest_date_time | crate::SetGuestDateTimeRequest | crate::Empty | None,
    get_metrics | crate::Empty | crate::MetricsResponse | None,
    get_guest_details | crate::GetGuestDetailsRequest | crate::GuestDetailsResponse | None,
    add_swap | crate::AddSwapRequest | crate::Empty | None,
    add_swap_path | crate::AddSwapPathRequest | crate::Empty | None,
    set_policy | crate::SetPolicyRequest | crate::Empty | None,
    get_diagnostic_data | crate::GetDiagnosticDataRequest | crate::GetDiagnosticDataResponse | None
);
