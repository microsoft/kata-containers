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
        CompletedContainerSnapshot, ContainerConfig, ContainerID, ContainerProcess,
        ContainerSnapshotInventory, ExecProcessRequest, KillRequest, ProcessExitStatus,
        ProcessStateInfo, ProcessStatus, ProcessType, ResizePTYRequest, ShutdownRequest, StatsInfo,
        UpdateRequest, PID,
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
use kata_types::k8s::{container_name, container_type};

use crate::container_manager::is_termination_signal;

use super::{logger_with_process, Container};

pub struct VirtContainerManager {
    sid: String,
    pid: u32,
    containers: Arc<RwLock<HashMap<String, Container>>>,
    completed_containers: Arc<RwLock<HashMap<String, CompletedContainerSnapshot>>>,
    resource_manager: Arc<ResourceManager>,
    agent: Arc<dyn Agent>,
    hypervisor: Arc<dyn Hypervisor>,
    vmm_master_tid: OnceCell<u32>,
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

#[derive(Debug, PartialEq, Eq)]
enum SnapshotContainerLifecycle {
    Live { cri_name: String },
    Completed(CompletedContainerSnapshot),
}

fn snapshot_container_lifecycle(
    host_id: &str,
    spec: &oci::Spec,
    state: &ProcessStateInfo,
) -> Result<SnapshotContainerLifecycle> {
    let mut cri_name = container_name(spec);
    if cri_name.is_empty() && container_type(spec).is_pod_sandbox() {
        cri_name = "POD".to_string();
    }
    if cri_name.is_empty() {
        return Err(anyhow!("container {host_id} has no CRI name"));
    }
    match state.status {
        ProcessStatus::Running | ProcessStatus::Paused => {
            Ok(SnapshotContainerLifecycle::Live { cri_name })
        }
        ProcessStatus::Stopped if container_type(spec).is_pod_container() => Ok(
            SnapshotContainerLifecycle::Completed(CompletedContainerSnapshot {
                cri_name,
                exit_code: state.exit_status,
            }),
        ),
        status => Err(anyhow!(
            "container {host_id} is in transitional snapshot state {status:?}"
        )),
    }
}

impl VirtContainerManager {
    pub fn new(
        sid: &str,
        pid: u32,
        agent: Arc<dyn Agent>,
        hypervisor: Arc<dyn Hypervisor>,
        resource_manager: Arc<ResourceManager>,
    ) -> Self {
        Self {
            sid: sid.to_string(),
            pid,
            containers: Default::default(),
            completed_containers: Default::default(),
            resource_manager,
            agent,
            hypervisor,
            vmm_master_tid: OnceCell::new(),
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

        let mut container = Container::new(
            vmm_master_tid,
            config.clone(),
            spec.clone(),
            self.agent.clone(),
            self.resource_manager.clone(),
            self.hypervisor.get_passfd_listener_addr().await.ok(),
        )
        .await
        .context("new container")?;

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

        let cri_name = container_name(&spec);
        let is_pod_container = container_type(&spec).is_pod_container();
        let mut containers = self.containers.write().await;
        if let Err(e) = container.create(spec).await {
            if let Err(inner_e) = container.cleanup().await {
                warn!(sl!(), "failed to cleanup container {:?}", inner_e);
            }

            return Err(e);
        }

        containers.insert(container.container_id.to_string(), container);
        if !cri_name.is_empty() && is_pod_container {
            self.completed_containers.write().await.remove(&cri_name);
        }
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

                let process_state = c.state_process(process).await.context("state process")?;
                let cri_name = container_name(&c_spec);
                if process_state.status == ProcessStatus::Stopped
                    && container_type(&c_spec).is_pod_container()
                    && !cri_name.is_empty()
                {
                    self.completed_containers.write().await.insert(
                        cri_name.clone(),
                        CompletedContainerSnapshot {
                            cri_name,
                            exit_code: process_state.exit_status,
                        },
                    );
                }
                Ok(process_state)
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

    async fn snapshot_inventory(&self) -> Result<ContainerSnapshotInventory> {
        let containers = self.containers.read().await;
        let mut completed = self.completed_containers.read().await.clone();
        let mut live_container_ids = Vec::new();
        for (host_id, container) in containers.iter() {
            let process = ContainerProcess::new(host_id, "")?;
            let state = container.state_process(&process).await?;
            let spec = container.spec().await;
            match snapshot_container_lifecycle(host_id, &spec, &state)? {
                SnapshotContainerLifecycle::Live { cri_name } => {
                    completed.remove(&cri_name);
                    live_container_ids.push(ContainerID::new(host_id)?);
                }
                SnapshotContainerLifecycle::Completed(record) => {
                    completed.insert(record.cri_name.clone(), record);
                }
            }
        }
        live_container_ids.sort_by(|left, right| left.container_id.cmp(&right.container_id));
        let mut completed_containers = completed.into_values().collect::<Vec<_>>();
        completed_containers.sort_by(|left, right| left.cri_name.cmp(&right.cri_name));
        Ok(ContainerSnapshotInventory {
            live_container_ids,
            completed_containers,
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_spec(name: &str, container_type_value: &str) -> oci::Spec {
        let mut spec = oci::Spec::default();
        spec.set_annotations(Some(HashMap::from([
            (
                kata_types::annotations::cri_containerd::CONTAINER_NAME_LABEL_KEY.to_string(),
                name.to_string(),
            ),
            (
                kata_types::annotations::cri_containerd::CONTAINER_TYPE_LABEL_KEY.to_string(),
                container_type_value.to_string(),
            ),
        ])));
        spec
    }

    fn process_state(status: ProcessStatus, exit_status: i32) -> ProcessStateInfo {
        ProcessStateInfo {
            container_id: "host-id".to_string(),
            exec_id: String::new(),
            pid: PID { pid: 1 },
            bundle: String::new(),
            stdin: None,
            stdout: None,
            stderr: None,
            terminal: false,
            status,
            exit_status,
            exited_at: None,
        }
    }

    #[test]
    fn stopped_pod_container_is_completed() {
        let spec = pod_spec("setup", kata_types::annotations::cri_containerd::CONTAINER);
        let lifecycle = snapshot_container_lifecycle(
            "host-id",
            &spec,
            &process_state(ProcessStatus::Stopped, 17),
        )
        .unwrap();
        assert_eq!(
            lifecycle,
            SnapshotContainerLifecycle::Completed(CompletedContainerSnapshot {
                cri_name: "setup".to_string(),
                exit_code: 17,
            })
        );
    }

    #[test]
    fn running_pod_container_is_live() {
        let spec = pod_spec("app", kata_types::annotations::cri_containerd::CONTAINER);
        let lifecycle = snapshot_container_lifecycle(
            "host-id",
            &spec,
            &process_state(ProcessStatus::Running, 0),
        )
        .unwrap();
        assert_eq!(
            lifecycle,
            SnapshotContainerLifecycle::Live {
                cri_name: "app".to_string(),
            }
        );
    }

    #[test]
    fn created_container_is_rejected_as_transitional() {
        let spec = pod_spec("app", kata_types::annotations::cri_containerd::CONTAINER);
        assert!(snapshot_container_lifecycle(
            "host-id",
            &spec,
            &process_state(ProcessStatus::Created, 0),
        )
        .is_err());
    }

    #[test]
    fn stopped_sandbox_is_not_a_completed_container() {
        let spec = pod_spec("POD", kata_types::annotations::cri_containerd::SANDBOX);
        assert!(snapshot_container_lifecycle(
            "host-id",
            &spec,
            &process_state(ProcessStatus::Stopped, 0),
        )
        .is_err());
    }
}
