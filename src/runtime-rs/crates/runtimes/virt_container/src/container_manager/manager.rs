// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;

use std::{collections::HashMap, sync::Arc};

use agent::Agent;
use common::{
    error::Error,
    types::{
        ContainerConfig, ContainerID, ContainerProcess, ContainerSnapshotIdentity,
        ExecProcessRequest, KillRequest, ProcessExitStatus, ProcessStateInfo, ProcessStatus,
        ProcessType, ResizePTYRequest, ShutdownRequest, StatsInfo, UpdateRequest, PID,
    },
    ContainerManager,
};
use hypervisor::Hypervisor;
use oci::Process as OCIProcess;
use oci_spec::runtime as oci;
use resource::ResourceManager;
use runtime_spec as spec;
use tokio::sync::{OnceCell, RwLock};
use tracing::instrument;

use kata_sys_util::{hooks::HookStates, netns::NetnsGuard};
use kata_types::k8s::container_type;

use crate::container_manager::is_termination_signal;
use crate::restore::{
    canonical_oci_identity, CreateAction, RestoreCoordinator, StartAction, OCI_IDENTITY_VERSION,
};

use super::{logger_with_process, Container};

pub struct VirtContainerManager {
    sid: String,
    pid: u32,
    containers: Arc<RwLock<HashMap<String, Container>>>,
    resource_manager: Arc<ResourceManager>,
    agent: Arc<dyn Agent>,
    hypervisor: Arc<dyn Hypervisor>,
    vmm_master_tid: OnceCell<u32>,
    restore_coordinator: Arc<RestoreCoordinator>,
}

impl std::fmt::Debug for VirtContainerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtContainerManager")
            .field("sid", &self.sid)
            .field("pid", &self.pid)
            .finish()
    }
}

fn from_hooks(hooks: &Option<Vec<oci::Hook>>) -> &[oci::Hook] {
    match hooks {
        Some(hooks_vec) => hooks_vec.as_slice(),
        None => &[],
    }
}

impl VirtContainerManager {
    pub fn new(
        sid: &str,
        pid: u32,
        agent: Arc<dyn Agent>,
        hypervisor: Arc<dyn Hypervisor>,
        resource_manager: Arc<ResourceManager>,
        restore_coordinator: Arc<RestoreCoordinator>,
    ) -> Self {
        Self {
            sid: sid.to_string(),
            pid,
            containers: Default::default(),
            resource_manager,
            agent,
            hypervisor,
            vmm_master_tid: OnceCell::new(),
            restore_coordinator,
        }
    }

    async fn get_vmm_master_tid(&self) -> Result<u32> {
        self.vmm_master_tid
            .get_or_try_init(|| self.hypervisor.get_vmm_master_tid())
            .await
            .copied()
    }
}

#[async_trait]
impl ContainerManager for VirtContainerManager {
    #[instrument]
    async fn create_container(&self, config: ContainerConfig, spec: oci::Spec) -> Result<PID> {
        let vmm_master_tid = self.get_vmm_master_tid().await?;
        let is_pause = container_type(&spec).is_pod_sandbox();
        let mut cri_name = kata_types::k8s::container_name(&spec);
        if cri_name.is_empty() && is_pause {
            cri_name = "POD".to_string();
        }
        let mut container = Container::new(
            vmm_master_tid,
            config.clone(),
            spec.clone(),
            self.agent.clone(),
            self.resource_manager.clone(),
            self.hypervisor.get_passfd_listener_addr().await.ok(),
        )
        .await
        .context("prepare container host state")?;
        let create_action = self
            .restore_coordinator
            .classify_create(
                &config.container_id,
                &cri_name,
                is_pause,
                &canonical_oci_identity(&spec)?,
            )
            .await?;
        if !matches!(create_action, CreateAction::ColdCreate) {
            if spec.hooks().is_some() {
                return Err(anyhow!("OCI hooks are not supported for restored tasks"));
            }
            if self
                .containers
                .write()
                .await
                .insert(config.container_id, container)
                .is_some()
            {
                self.restore_coordinator.fail().await;
                return Err(anyhow!("restored target container already exists"));
            }
            return Ok(PID {
                pid: vmm_master_tid,
            });
        }

        // CreateContainer Hooks:
        // * should be run in vmm namespace (hook path in runtime namespace)
        // * should be run after the vm is started, before container is created, and after CreateRuntime Hooks
        // * spec details: https://github.com/opencontainers/runtime-spec/blob/c1662686cff159595277b79322d0272f5182941b/config.md#createcontainer-hooks
        let vmm_ns_path = self.hypervisor.get_ns_path().await?;
        let vmm_netns_path = format!("{}/{}", vmm_ns_path, "net");
        let state = spec::State {
            version: spec.version().clone(),
            id: config.container_id.clone(),
            status: spec::ContainerState::Creating,
            pid: vmm_master_tid as i32,
            bundle: config.bundle.clone(),
            annotations: spec.annotations().clone().unwrap_or_default(),
        };

        // new scope, CreateContainer hooks in which will execute in a new network namespace
        {
            let _netns_guard = NetnsGuard::new(&vmm_netns_path).context("vmm netns guard")?;
            if let Some(hooks) = spec.hooks().as_ref() {
                let mut create_container_hook_states = HookStates::new();
                create_container_hook_states
                    .execute_hooks(from_hooks(hooks.create_container()), Some(state))?;
            }
        }

        let mut containers = self.containers.write().await;
        if let Err(e) = container.create(spec).await {
            if let Err(inner_e) = container.cleanup().await {
                warn!(sl!(), "failed to cleanup container {:?}", inner_e);
            }

            return Err(e);
        }

        containers.insert(container.container_id.to_string(), container);
        Ok(PID {
            pid: vmm_master_tid,
        })
    }

    #[instrument]
    async fn close_process_io(&self, process: &ContainerProcess) -> Result<()> {
        let containers = self.containers.read().await;
        let container_id = &process.container_id.to_string();
        let c = containers
            .get(container_id)
            .ok_or_else(|| Error::ContainerNotFound(container_id.clone()))?;

        c.close_io(process).await.context("close io")?;
        Ok(())
    }

    #[instrument]
    async fn delete_process(&self, process: &ContainerProcess) -> Result<ProcessStateInfo> {
        let container_id = &process.container_id.container_id;
        match process.process_type {
            ProcessType::Container => {
                let mut containers = self.containers.write().await;
                let c = containers
                    .remove(container_id)
                    .ok_or_else(|| Error::ContainerNotFound(container_id.to_string()))?;

                // Poststop Hooks:
                // * should be run in runtime namespace
                // * should be run after the container is deleted but before delete operation returns
                // * spec details: https://github.com/opencontainers/runtime-spec/blob/c1662686cff159595277b79322d0272f5182941b/config.md#poststop
                let c_spec = c.spec().await;

                let vmm_pid = self.get_vmm_master_tid().await?;
                let state = spec::State {
                    version: c_spec.version().clone(),
                    id: c.container_id.to_string(),
                    status: spec::ContainerState::Stopped,
                    pid: vmm_pid as i32,
                    bundle: c.config().await.bundle,
                    annotations: c_spec.annotations().clone().unwrap_or_default(),
                };
                if let Some(hooks) = c_spec.hooks().as_ref() {
                    let mut poststop_hook_states = HookStates::new();
                    poststop_hook_states
                        .execute_hooks(from_hooks(hooks.poststop()), Some(state))?;
                }

                let state = c.state_process(process).await.context("state process")?;
                self.restore_coordinator
                    .forget_synthetic_init(container_id)
                    .await;
                Ok(state)
            }
            ProcessType::Exec => {
                let containers = self.containers.read().await;
                let c = containers
                    .get(container_id)
                    .ok_or_else(|| Error::ContainerNotFound(container_id.to_string()))?;
                let state = c.state_process(process).await.context("state process");
                c.delete_exec_process(process)
                    .await
                    .context("delete process")?;
                return state;
            }
        }
    }

    #[instrument]
    async fn exec_process(&self, req: ExecProcessRequest) -> Result<()> {
        if req.spec_type_url.is_empty() {
            return Err(anyhow!("invalid type url"));
        }
        let mut oci_process: OCIProcess =
            serde_json::from_slice(&req.spec_value).context("serde from slice")?;

        oci_process.set_apparmor_profile(None);
        oci_process.set_capabilities(None);

        let containers = self.containers.read().await;
        let container_id = &req.process.container_id.container_id;
        let c = containers
            .get(container_id)
            .ok_or_else(|| Error::ContainerNotFound(container_id.clone()))?;
        c.exec_process(
            &req.process,
            req.stdin,
            req.stdout,
            req.stderr,
            req.terminal,
            oci_process,
        )
        .await
        .context("container exec")
    }

    #[instrument]
    async fn kill_process(&self, req: &KillRequest) -> Result<()> {
        if is_termination_signal(req.signal)
            && self
                .restore_coordinator
                .is_adopted_pause(req.process.container_id())
                .await
        {
            if let Some(container) = self.containers.read().await.get(req.process.container_id()) {
                container.complete_locally(0).await;
            }
            return Ok(());
        }
        let containers = self.containers.read().await;
        let container_id = &req.process.container_id.container_id;

        // According to CRI specs, kubelet will call StopPodSandbox()
        // at least once before calling RemovePodSandbox and this call
        // is idempotent. It must not return an error if all relevant
        // resources have already been reclaimed
        let c = match containers.get(container_id) {
            Some(c) => c,
            None => {
                // Container already removed - this is OK for SIGKILL/SIGTERM
                if is_termination_signal(req.signal) {
                    warn!(
                        sl!(),
                        "Signal {} ignored due to container not existing", req.signal;
                        "container" => container_id,
                        "signal" => req.signal
                    );
                    return Ok(());
                }
                return Err(Error::ContainerNotFound(container_id.clone()).into());
            }
        };

        // According to CRI specs, kubelet will call StopPodSandbox()
        // at least once before calling RemovePodSandbox, and this call
        // is idempotent, and must not return an error if all relevant
        // resources have already been reclaimed. And in that call it will
        // send a SIGKILL signal first to try to stop the container, thus
        // once the container has terminated, here should ignore this signal
        // and return directly.
        //
        // When the VM/agent is dead (e.g., QEMU killed externally), the ttrpc
        // connection will fail with AgentConnectionClosed error.
        // Additionally, if the container's init process is already gone, the
        // agent returns ProcessAlreadyTerminated error.
        // For SIGKILL/SIGTERM, we should treat these as success since the
        // container is effectively terminated.
        c.kill_process(&req.process, req.signal, req.all)
            .await
            .or_else(|err| {
                let is_term_signal = is_termination_signal(req.signal);

                // Check for typed errors using downcast_ref
                let is_expected_error = matches!(
                    err.downcast_ref::<Error>(),
                    Some(Error::AgentConnectionClosed) | Some(Error::ProcessAlreadyTerminated)
                );

                if is_term_signal && is_expected_error {
                    warn!(
                        sl!(),
                        "Signal encounters expected error, VM/process already terminated";
                        "container" => container_id,
                        "process" => ?&req.process,
                        "signal" => req.signal,
                    );
                    Ok(())
                } else {
                    Err(err)
                }
            })
    }

    #[instrument]
    async fn wait_process(&self, process: &ContainerProcess) -> Result<ProcessExitStatus> {
        let logger = logger_with_process(process);

        let containers = self.containers.read().await;
        let container_id = &process.container_id.container_id;
        let c = containers
            .get(container_id)
            .ok_or_else(|| Error::ContainerNotFound(container_id.clone()))?;
        let (watcher, status) = c.wait_process(process).await.context("wait")?;
        drop(containers);

        match watcher {
            Some(mut watcher) => {
                info!(logger, "begin wait exit");
                while watcher.changed().await.is_ok() {}
                info!(logger, "end wait exited");
            }
            None => {
                warn!(logger, "failed to find watcher for wait process");
            }
        }

        let status = status.read().await;

        info!(logger, "wait process exit status {:?}", status);

        Ok(status.clone())
    }

    #[instrument]
    async fn start_process(&self, process: &ContainerProcess) -> Result<PID> {
        if process.process_type == ProcessType::Container {
            match self
                .restore_coordinator
                .classify_start(process.container_id())
                .await?
            {
                StartAction::ColdStart => {}
                StartAction::Stage => {
                    if self
                        .restore_coordinator
                        .is_adopted_pause(process.container_id())
                        .await
                    {
                        let containers = self.containers.read().await;
                        let container =
                            containers.get(process.container_id()).ok_or_else(|| {
                                Error::ContainerNotFound(process.container_id().to_string())
                            })?;
                        container.set_state(ProcessStatus::Running).await;
                    }
                    return Ok(PID {
                        pid: self.get_vmm_master_tid().await?,
                    });
                }
                StartAction::CompleteSyntheticInit => {
                    let containers = self.containers.read().await;
                    let container = containers.get(process.container_id()).ok_or_else(|| {
                        Error::ContainerNotFound(process.container_id().to_string())
                    })?;
                    container.set_state(ProcessStatus::Running).await;
                    return Ok(PID {
                        pid: self.get_vmm_master_tid().await?,
                    });
                }
                StartAction::Finalize => {
                    return Ok(PID {
                        pid: self.get_vmm_master_tid().await?,
                    });
                }
            }
        }
        let containers = self.containers.read().await;
        let container_id = &process.container_id.container_id;
        let c = containers
            .get(container_id)
            .ok_or_else(|| Error::ContainerNotFound(container_id.clone()))?;
        c.start(self.containers.clone(), process)
            .await
            .context("start")?;

        // Poststart Hooks:
        // * should be run in runtime namespace
        // * should be run after user-specific command is executed but before start operation returns
        // * spec details: https://github.com/opencontainers/runtime-spec/blob/c1662686cff159595277b79322d0272f5182941b/config.md#poststart
        let c_spec = c.spec().await;
        let vmm_master_tid = self.get_vmm_master_tid().await?;
        let state = spec::State {
            version: c_spec.version().clone(),
            id: c.container_id.to_string(),
            status: spec::ContainerState::Running,
            pid: vmm_master_tid as i32,
            bundle: c.config().await.bundle,
            annotations: c_spec.annotations().clone().unwrap_or_default(),
        };
        if let Some(hooks) = c_spec.hooks().as_ref() {
            let mut poststart_hook_states = HookStates::new();
            poststart_hook_states.execute_hooks(from_hooks(hooks.poststart()), Some(state))?;
        }

        Ok(PID {
            pid: vmm_master_tid,
        })
    }

    async fn complete_synthetic_init(&self, process: &ContainerProcess) -> Result<()> {
        let Some(exit_code) = self
            .restore_coordinator
            .take_synthetic_init_exit_code(process.container_id())
            .await
        else {
            return Ok(());
        };
        let containers = self.containers.read().await;
        let container = containers
            .get(process.container_id())
            .ok_or_else(|| Error::ContainerNotFound(process.container_id().to_string()))?;
        container.complete_locally(exit_code).await;
        Ok(())
    }

    #[instrument]
    async fn state_process(&self, process: &ContainerProcess) -> Result<ProcessStateInfo> {
        let containers = self.containers.read().await;
        let container_id = &process.container_id.container_id;

        // When using Sandbox API, the sandbox container (container_id == sandbox_id)
        // is not stored in the containers map. Return a synthetic state for it.
        if let Some(c) = containers.get(container_id) {
            c.state_process(process).await.context("state process")
        } else if container_id == &self.sid {
            let vmm_pid = self.get_vmm_master_tid().await?;
            Ok(ProcessStateInfo {
                container_id: self.sid.clone(),
                exec_id: String::new(),
                pid: PID { pid: vmm_pid },
                bundle: String::new(),
                stdin: None,
                stdout: None,
                stderr: None,
                terminal: false,
                status: ProcessStatus::Running,
                exit_status: 0,
                exited_at: None,
            })
        } else {
            Err(Error::ContainerNotFound(container_id.clone()).into())
        }
    }

    #[instrument]
    async fn pause_container(&self, id: &ContainerID) -> Result<()> {
        let containers = self.containers.read().await;
        let c = containers
            .get(&id.container_id)
            .ok_or_else(|| Error::ContainerNotFound(id.container_id.clone()))?;
        c.pause().await.context("pause")?;
        Ok(())
    }

    #[instrument]
    async fn resume_container(&self, id: &ContainerID) -> Result<()> {
        let containers = self.containers.read().await;
        let c = containers
            .get(&id.container_id)
            .ok_or_else(|| Error::ContainerNotFound(id.container_id.clone()))?;
        c.resume().await.context("resume")?;
        Ok(())
    }

    async fn container_ids(&self) -> Vec<ContainerID> {
        let ids = self
            .containers
            .read()
            .await
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            if !self.restore_coordinator.is_synthetic_init(&id).await {
                if let Ok(id) = ContainerID::new(&id) {
                    result.push(id);
                }
            }
        }
        result
    }

    #[instrument]
    async fn resize_process_pty(&self, req: &ResizePTYRequest) -> Result<()> {
        let containers = self.containers.read().await;
        let c = containers
            .get(&req.process.container_id.container_id)
            .ok_or_else(|| {
                Error::ContainerNotFound(req.process.container_id.container_id.clone())
            })?;
        c.resize_pty(&req.process, req.width, req.height)
            .await
            .context("resize pty")?;
        Ok(())
    }

    #[instrument]
    async fn stats_container(&self, id: &ContainerID) -> Result<StatsInfo> {
        let containers = self.containers.read().await;
        let c = containers
            .get(&id.container_id)
            .ok_or_else(|| Error::ContainerNotFound(id.container_id.clone()))?;
        let stats = c.stats().await.context("stats")?;
        Ok(StatsInfo::from(stats))
    }

    #[instrument]
    async fn update_container(&self, req: UpdateRequest) -> Result<()> {
        let resource = serde_json::from_slice::<oci::LinuxResources>(&req.value)
            .context("deserialize LinuxResource")?;
        let containers = self.containers.read().await;
        let container_id = &req.container_id;
        let c = containers
            .get(container_id)
            .ok_or_else(|| Error::ContainerNotFound(container_id.to_string()))?;
        c.update(&resource).await.context("update_container")
    }

    #[instrument]
    async fn pid(&self) -> Result<PID> {
        let vmm_pid = self.get_vmm_master_tid().await?;
        Ok(PID { pid: vmm_pid })
    }

    #[instrument]
    async fn connect_container(&self, _id: &ContainerID) -> Result<PID> {
        let vmm_pid = self.get_vmm_master_tid().await?;
        Ok(PID { pid: vmm_pid })
    }

    #[instrument]
    async fn need_shutdown_sandbox(&self, req: &ShutdownRequest) -> bool {
        req.is_now || self.sid == req.container_id
    }

    #[instrument]
    async fn is_sandbox_container(&self, process: &ContainerProcess) -> bool {
        process.process_type == ProcessType::Container
            && process.container_id.container_id == self.sid
    }

    async fn snapshot_identities(&self) -> Result<Vec<ContainerSnapshotIdentity>> {
        let containers = self.containers.read().await;
        let mut identities = Vec::with_capacity(containers.len());
        for (host_id, container) in containers.iter() {
            if self.restore_coordinator.is_synthetic_init(host_id).await {
                continue;
            }
            let spec = container.spec().await;
            let mut cri_name = kata_types::k8s::container_name(&spec);
            if cri_name.is_empty() && container_type(&spec).is_pod_sandbox() {
                cri_name = "POD".to_string();
            }
            if cri_name.is_empty() {
                return Err(anyhow!("container {host_id} has no CRI name"));
            }
            identities.push(ContainerSnapshotIdentity {
                host_id: host_id.clone(),
                cri_name,
                oci_identity_version: OCI_IDENTITY_VERSION,
                oci_identity_sha256: canonical_oci_identity(&spec)?,
                guest_mounts: container.snapshot_guest_mounts().await?,
            });
        }
        identities.sort_by(|left, right| left.host_id.cmp(&right.host_id));
        Ok(identities)
    }

    async fn restore_container_specs(
        &self,
        target_ids: &[String],
    ) -> Result<Vec<(String, oci::Spec)>> {
        let containers = self.containers.read().await;
        let mut specs = Vec::with_capacity(target_ids.len());
        for target_id in target_ids {
            let container = containers
                .get(target_id)
                .ok_or_else(|| Error::ContainerNotFound(target_id.clone()))?;
            specs.push((target_id.clone(), container.spec().await));
        }
        Ok(specs)
    }

    async fn activate_restored_containers(&self, target_ids: &[String]) -> Result<()> {
        let containers = self.containers.read().await;
        for target_id in target_ids {
            if target_id == &self.sid {
                continue;
            }
            let container = containers
                .get(target_id)
                .ok_or_else(|| Error::ContainerNotFound(target_id.clone()))?;
            let process = ContainerProcess::new(target_id, "")?;
            container
                .activate_restored(self.containers.clone(), &process)
                .await?;
        }
        Ok(())
    }
}
