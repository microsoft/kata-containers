// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use agent::Agent;
use anyhow::{anyhow, Context, Result};
use common::{
    error::{is_no_such_process_error, Error},
    types::{ContainerID, ContainerProcess, ProcessExitStatus, ProcessStatus, ProcessType},
};
use hypervisor::device::device_manager::DeviceManager;
use nix::sys::signal::Signal;
use oci::LinuxResources;
use oci_spec::runtime as oci;
use resource::{rootfs::Rootfs, volume::Volume};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use crate::container_manager::{convert_agent_error, logger_with_process};

use super::{
    io::ContainerIo,
    process::{Process, ProcessWatcher},
    Exec,
};

pub struct ContainerInner {
    agent: Arc<dyn Agent>,
    logger: slog::Logger,
    pub(crate) init_process: Process,
    pub(crate) exec_processes: HashMap<String, Exec>,
    pub(crate) rootfs: Vec<Arc<dyn Rootfs>>,
    pub(crate) volumes: Vec<Arc<dyn Volume>>,
    pub(crate) linux_resources: Option<LinuxResources>,
    guest_removed: bool,
}

impl ContainerInner {
    pub(crate) fn new(
        agent: Arc<dyn Agent>,
        init_process: Process,
        logger: slog::Logger,
        linux_resources: Option<LinuxResources>,
    ) -> Self {
        Self {
            agent,
            logger,
            init_process,
            exec_processes: HashMap::new(),
            rootfs: vec![],
            volumes: vec![],
            linux_resources,
            guest_removed: false,
        }
    }

    fn container_id(&self) -> &str {
        self.init_process.process.container_id()
    }

    pub(crate) async fn check_state(&self, states: Vec<ProcessStatus>) -> Result<()> {
        let state = self.init_process.get_status().await;
        if states.contains(&state) {
            return Ok(());
        }

        Err(anyhow!(
            "failed to check state {:?} for {:?}",
            state,
            states
        ))
    }

    pub(crate) async fn set_state(&mut self, state: ProcessStatus) {
        let mut status = self.init_process.status.write().await;
        *status = state;
    }

    pub(crate) async fn start_exec_process(&mut self, process: &ContainerProcess) -> Result<()> {
        let exec = self
            .exec_processes
            .get_mut(&process.exec_id)
            .ok_or_else(|| Error::ProcessNotFound(process.clone()))?;

        self.agent
            .exec_process(agent::ExecProcessRequest {
                process_id: process.clone().into(),
                string_user: None,
                process: Some(exec.oci_process.clone()),
                stdin_port: exec.process.passfd_io.as_ref().and_then(|io| io.stdin_port),
                stdout_port: exec
                    .process
                    .passfd_io
                    .as_ref()
                    .and_then(|io| io.stdout_port),
                stderr_port: exec
                    .process
                    .passfd_io
                    .as_ref()
                    .and_then(|io| io.stderr_port),
            })
            .await
            .context("exec process")?;
        exec.process.set_status(ProcessStatus::Running).await;
        Ok(())
    }

    pub(crate) async fn win_resize_process(
        &self,
        process: &ContainerProcess,
        height: u32,
        width: u32,
    ) -> Result<()> {
        self.check_state(vec![ProcessStatus::Created, ProcessStatus::Running])
            .await
            .context("check state")?;

        self.agent
            .tty_win_resize(agent::TtyWinResizeRequest {
                process_id: process.clone().into(),
                row: height,
                column: width,
            })
            .await?;
        Ok(())
    }

    pub fn fetch_exit_watcher(&self, process: &ContainerProcess) -> Result<ProcessWatcher> {
        match process.process_type {
            ProcessType::Container => self.init_process.fetch_exit_watcher(),
            ProcessType::Exec => {
                let exec = self
                    .exec_processes
                    .get(&process.exec_id)
                    .ok_or_else(|| Error::ProcessNotFound(process.clone()))?;
                exec.process.fetch_exit_watcher()
            }
        }
    }

    pub(crate) async fn start_container(&mut self, cid: &ContainerID) -> Result<()> {
        self.check_state(vec![ProcessStatus::Created, ProcessStatus::Stopped])
            .await
            .context("check state")?;

        self.agent
            .start_container(agent::ContainerID {
                container_id: cid.container_id.clone(),
            })
            .await
            .context("start container")?;

        self.set_state(ProcessStatus::Running).await;

        Ok(())
    }

    async fn get_exit_status(&self) -> Arc<RwLock<ProcessExitStatus>> {
        self.init_process.exit_status.clone()
    }

    pub(crate) fn add_exec_process(&mut self, id: &str, exec: Exec) -> Option<Exec> {
        self.exec_processes.insert(id.to_string(), exec)
    }

    pub(crate) async fn delete_exec_process(&mut self, eid: &str) -> Result<()> {
        match self.exec_processes.remove(eid) {
            Some(_) => {
                debug!(self.logger, " delete process eid {}", eid);
                Ok(())
            }
            None => Err(anyhow!(
                "failed to find cid {} eid {}",
                self.container_id(),
                eid
            )),
        }
    }

    pub(crate) async fn cleanup_container(
        &mut self,
        cid: &str,
        force: bool,
        device_manager: &RwLock<DeviceManager>,
    ) -> Result<()> {
        // wait until the container process
        // terminated and the status write lock released.
        info!(self.logger, "wait on container terminated");
        let exit_status = self.get_exit_status().await;
        let _locked_exit_status = exit_status.read().await;
        info!(self.logger, "container terminated");
        if !self.guest_removed {
            let remove_request = agent::RemoveContainerRequest {
                container_id: cid.to_string(),
                ..Default::default()
            };
            match self.agent.remove_container(remove_request).await {
                Ok(_) => self.guest_removed = true,
                Err(e) if force => {
                    warn!(
                        self.logger,
                        "stop container: agent remove container failed: {}", e
                    );
                }
                Err(e) => return Err(e),
            }
        }

        // close the exit channel to wakeup wait service
        // send to notify watchers who are waiting for the process exit
        self.init_process.stop().await;

        self.clean_volumes(device_manager)
            .await
            .context("clean volumes")?;
        self.clean_rootfs(device_manager)
            .await
            .context("clean rootfs")?;

        Ok(())
    }

    pub(crate) async fn stop_process(
        &mut self,
        process: &ContainerProcess,
        force: bool,
        device_manager: &RwLock<DeviceManager>,
    ) -> Result<()> {
        let logger = logger_with_process(process);
        info!(logger, "begin to stop process");

        // do not stop again when state stopped, may cause multi cleanup resource
        let state = self.init_process.get_status().await;
        if state == ProcessStatus::Stopped {
            return Ok(());
        }

        self.check_state(vec![ProcessStatus::Running])
            .await
            .context("check state")?;

        // Send kill signal to the container's init process.
        //
        // We must never abort teardown when signaling fails: the process may
        // already have exited (or the agent connection may already be gone
        // during sandbox shutdown), and in all of these cases we still have to
        // clean up the container's resources. Failing to do so leaves the
        // container's mounts in place, which later makes the sandbox-level
        // virtiofs cleanup fail with "Resource busy"/"Directory not empty".
        //
        // Errors indicating the process is already gone are logged at info
        // level; any other failure is logged as a warning, but cleanup always
        // proceeds.
        if let Err(e) = self
            .signal_process(process, Signal::SIGKILL as u32, false)
            .await
        {
            if is_no_such_process_error(&e) {
                info!(
                    logger,
                    "signal_process: init process is already gone, treat it as stopped"
                );
            } else {
                warn!(logger, "failed to send kill signal to process: {:?}", e);
            }
        }

        match process.process_type {
            ProcessType::Container => self
                .cleanup_container(&process.container_id.container_id, force, device_manager)
                .await
                .context("stop container")?,
            ProcessType::Exec => {
                let exec = self
                    .exec_processes
                    .get_mut(&process.exec_id)
                    .ok_or_else(|| anyhow!("failed to find exec"))?;
                exec.process.stop().await;
            }
        }

        Ok(())
    }

    pub(crate) async fn signal_process(
        &mut self,
        process: &ContainerProcess,
        signal: u32,
        all: bool,
    ) -> Result<()> {
        if self.check_state(vec![ProcessStatus::Stopped]).await.is_ok() {
            return Ok(());
        }

        let mut process_id: agent::ContainerProcessID = process.clone().into();
        if all {
            // force signal init process
            process_id.exec_id.clear();
        };

        self.agent
            .signal_process(agent::SignalProcessRequest { process_id, signal })
            .await
            .map_err(convert_agent_error)?;

        Ok(())
    }

    pub async fn new_container_io(&self, process: &ContainerProcess) -> Result<ContainerIo> {
        Ok(ContainerIo::new(self.agent.clone(), process.clone()))
    }

    pub async fn close_io(&mut self, process: &ContainerProcess) -> Result<()> {
        match process.process_type {
            ProcessType::Container => self.init_process.close_io(self.agent.clone()).await,
            ProcessType::Exec => {
                let exec = self
                    .exec_processes
                    .get_mut(&process.exec_id)
                    .ok_or_else(|| Error::ProcessNotFound(process.clone()))?;
                exec.process.close_io(self.agent.clone()).await;
            }
        };

        Ok(())
    }

    async fn clean_volumes(&mut self, device_manager: &RwLock<DeviceManager>) -> Result<()> {
        let mut unhandled = Vec::new();
        let mut first_error = None;
        for v in self.volumes.iter() {
            if let Err(err) = v.cleanup(device_manager).await {
                unhandled.push(Arc::clone(v));
                warn!(
                    sl!(),
                    "Failed to clean the volume = {:?}, error = {:?}",
                    v.get_volume_mount(),
                    err
                );
                first_error.get_or_insert(err);
            }
        }
        self.volumes = unhandled;
        if let Some(err) = first_error {
            return Err(err).context("failed to clean container volumes");
        }
        Ok(())
    }

    async fn clean_rootfs(&mut self, device_manager: &RwLock<DeviceManager>) -> Result<()> {
        let mut unhandled = Vec::new();
        let mut first_error = None;
        for rootfs in self.rootfs.iter() {
            if let Err(err) = rootfs.cleanup(device_manager).await {
                unhandled.push(Arc::clone(rootfs));
                warn!(
                    sl!(),
                    "Failed to umount rootfs, cid = {:?}, error = {:?}",
                    self.container_id(),
                    err
                );
                first_error.get_or_insert(err);
            }
        }
        self.rootfs = unhandled;
        if let Some(err) = first_error {
            return Err(err).context("failed to clean container rootfs");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct RetryRootfs {
        fail: AtomicBool,
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Rootfs for RetryRootfs {
        async fn get_guest_rootfs_path(&self) -> Result<String> {
            Ok(String::new())
        }

        async fn get_rootfs_mount(&self) -> Result<Vec<oci_spec::runtime::Mount>> {
            Ok(Vec::new())
        }

        async fn get_storage(&self) -> Option<Vec<agent::Storage>> {
            None
        }

        async fn get_device_id(&self) -> Result<Option<String>> {
            Ok(None)
        }

        async fn cleanup(&self, _device_manager: &RwLock<DeviceManager>) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.swap(false, Ordering::SeqCst) {
                return Err(anyhow!("guest disk is busy"));
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn rootfs_cleanup_propagates_errors_and_retains_only_failed_resources() {
        let process = ContainerProcess::new("test-container", "").unwrap();
        let process = Process::new(&process, 0, "", None, None, None, false);
        let mut inner = ContainerInner::new(
            Arc::new(agent::kata::KataAgent::new(Default::default())),
            process,
            slog::Logger::root(slog::Discard, slog::o!()),
            None,
        );
        let successful = Arc::new(RetryRootfs {
            fail: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let retry = Arc::new(RetryRootfs {
            fail: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
        });
        inner.rootfs = vec![successful.clone(), retry.clone()];
        let dm = RwLock::new(
            DeviceManager::new(Arc::new(hypervisor::qemu::Qemu::new()), None)
                .await
                .unwrap(),
        );

        let err = inner.clean_rootfs(&dm).await.unwrap_err();
        assert!(format!("{err:#}").contains("guest disk is busy"));
        assert_eq!(inner.rootfs.len(), 1);
        inner.clean_rootfs(&dm).await.unwrap();
        assert!(inner.rootfs.is_empty());
        assert_eq!(successful.calls.load(Ordering::SeqCst), 1);
        assert_eq!(retry.calls.load(Ordering::SeqCst), 2);

        // A host cleanup retry must not repeat a successful guest RemoveContainer.
        inner.guest_removed = true;
        inner
            .cleanup_container("test-container", false, &dm)
            .await
            .unwrap();
    }
}
