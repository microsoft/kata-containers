// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! External OpenVMM process wrapper using OpenVMM's TTRPC VM service.

use anyhow::{anyhow, Context, Result};
use openvmm_ttrpc_vmservice as vmservice;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::utils::enter_netns;

const OPENVMM_READY_TIMEOUT: Duration = Duration::from_secs(20);
const OPENVMM_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const OPENVMM_RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Wrapper around an external OpenVMM process, providing VM lifecycle control.
pub(crate) struct VmmInstance {
    pid: Option<u32>,
    ttrpc_socket_path: Option<String>,
    wait_task: Option<JoinHandle<()>>,
    exit_notify: Option<mpsc::Sender<i32>>,
}

impl std::fmt::Debug for VmmInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmmInstance")
            .field("pid", &self.pid)
            .field("ttrpc_socket_path", &self.ttrpc_socket_path)
            .finish()
    }
}

impl VmmInstance {
    pub(crate) fn new(exit_notify: mpsc::Sender<i32>) -> Self {
        Self {
            pid: None,
            ttrpc_socket_path: None,
            wait_task: None,
            exit_notify: Some(exit_notify),
        }
    }

    pub(crate) async fn launch(
        &mut self,
        configured_path: &str,
        ttrpc_socket_path: String,
        request: vmservice::CreateVmRequest,
        netns: Option<String>,
        log_dir: Option<String>,
    ) -> Result<()> {
        if self.pid.is_some() {
            anyhow::bail!("openvmm process is already running");
        }

        let openvmm_path = resolve_openvmm_path(configured_path)?;
        let _ = std::fs::remove_file(&ttrpc_socket_path);

        let mut command = Command::new(&openvmm_path);
        command
            .arg("--ttrpc")
            .arg(&ttrpc_socket_path)
            .stdin(Stdio::null())
            .kill_on_drop(false);

        if let Some(log_dir) = &log_dir {
            std::fs::create_dir_all(log_dir)
                .with_context(|| format!("failed to create openvmm log dir {log_dir}"))?;
            let log_path = Path::new(log_dir).join("openvmm.log");
            let log_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .with_context(|| {
                    format!("failed to create openvmm log file {}", log_path.display())
                })?;
            command
                .stdout(Stdio::from(
                    log_file.try_clone().context("failed to clone log file")?,
                ))
                .stderr(Stdio::from(log_file));
        } else {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }

        if let Some(netns_path) = netns {
            unsafe {
                command.pre_exec(move || {
                    enter_netns(&netns_path).map_err(|err| std::io::Error::other(err.to_string()))
                });
            }
        }

        info!(
            sl!(),
            "openvmm: launching external process path={} socket={}",
            openvmm_path.display(),
            ttrpc_socket_path
        );

        let mut child = command
            .spawn()
            .with_context(|| format!("failed to spawn openvmm at {}", openvmm_path.display()))?;
        let pid = child.id().context("failed to get openvmm pid")?;

        let exit_notify = self.exit_notify.clone();
        let wait_task = tokio::spawn(async move {
            let exit_code = match child.wait().await {
                Ok(status) => status.code().unwrap_or(1),
                Err(err) => {
                    warn!(
                        sl!(),
                        "openvmm: failed waiting for process {}: {:?}", pid, err
                    );
                    1
                }
            };

            if let Some(exit_notify) = exit_notify {
                let _ = exit_notify.try_send(exit_code);
            }
        });

        self.pid = Some(pid);
        self.ttrpc_socket_path = Some(ttrpc_socket_path.clone());
        self.wait_task = Some(wait_task);

        wait_for_socket(&ttrpc_socket_path, OPENVMM_READY_TIMEOUT)
            .await
            .with_context(|| {
                format!("openvmm TTRPC socket did not become ready: {ttrpc_socket_path}")
            })?;
        self.create_vm(request).await
    }

    pub(crate) async fn resume(&self) -> Result<()> {
        let socket_path = self.socket_path()?;
        rpc_call(socket_path, |client| async move {
            client
                .call()
                .wait_ready(true)
                .timeout(Some(OPENVMM_RPC_TIMEOUT))
                .start(vmservice::Vm::ResumeVm, ())
                .await
        })
        .await
    }

    pub(crate) async fn pause(&self) -> Result<()> {
        let socket_path = self.socket_path()?;
        rpc_call(socket_path, |client| async move {
            client
                .call()
                .wait_ready(true)
                .timeout(Some(OPENVMM_RPC_TIMEOUT))
                .start(vmservice::Vm::PauseVm, ())
                .await
        })
        .await
    }

    pub(crate) async fn add_scsi_disk(
        &self,
        lun: u32,
        host_path: String,
        read_only: bool,
    ) -> Result<()> {
        let request = vmservice::ModifyResourceRequest {
            r#type: vmservice::ModifyType::Add as i32,
            resource: Some(vmservice::modify_resource_request::Resource::ScsiDisk(
                vmservice::ScsiDisk {
                    controller: 0,
                    lun,
                    host_path,
                    r#type: vmservice::DiskType::ScsiDiskTypePhysical as i32,
                    read_only,
                },
            )),
        };

        let socket_path = self.socket_path()?;
        rpc_call(socket_path, move |client| async move {
            client
                .call()
                .wait_ready(true)
                .timeout(Some(OPENVMM_RPC_TIMEOUT))
                .start(vmservice::Vm::ModifyResource, request)
                .await
        })
        .await
    }

    pub(crate) async fn remove_scsi_disk(&self, lun: u32) -> Result<()> {
        let request = vmservice::ModifyResourceRequest {
            r#type: vmservice::ModifyType::Remove as i32,
            resource: Some(vmservice::modify_resource_request::Resource::ScsiDisk(
                vmservice::ScsiDisk {
                    controller: 0,
                    lun,
                    host_path: String::new(),
                    r#type: vmservice::DiskType::ScsiDiskTypePhysical as i32,
                    read_only: true,
                },
            )),
        };

        let socket_path = self.socket_path()?;
        rpc_call(socket_path, move |client| async move {
            client
                .call()
                .wait_ready(true)
                .timeout(Some(OPENVMM_RPC_TIMEOUT))
                .start(vmservice::Vm::ModifyResource, request)
                .await
        })
        .await
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        if self.pid.is_none() {
            return Ok(());
        }

        if let Err(err) = self.teardown_vm().await {
            warn!(sl!(), "openvmm: teardown RPC failed: {:?}", err);
        }
        if let Err(err) = self.quit().await {
            warn!(sl!(), "openvmm: quit RPC failed: {:?}", err);
        }

        if let Some(wait_task) = self.wait_task.take() {
            if let Err(err) = tokio::time::timeout(OPENVMM_STOP_TIMEOUT, wait_task).await {
                warn!(sl!(), "openvmm: process did not exit after quit: {:?}", err);
                if let Some(pid) = self.pid {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid as i32),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
            }
        }

        if let Some(socket_path) = self.ttrpc_socket_path.take() {
            let _ = std::fs::remove_file(socket_path);
        }
        self.pid = None;

        Ok(())
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        self.pid
    }

    async fn create_vm(&self, request: vmservice::CreateVmRequest) -> Result<()> {
        let socket_path = self.socket_path()?;
        rpc_call(socket_path, move |client| async move {
            client
                .call()
                .wait_ready(true)
                .timeout(Some(OPENVMM_RPC_TIMEOUT))
                .start(vmservice::Vm::CreateVm, request)
                .await
        })
        .await
    }

    async fn teardown_vm(&self) -> Result<()> {
        let socket_path = self.socket_path()?;
        rpc_call(socket_path, |client| async move {
            client
                .call()
                .wait_ready(true)
                .timeout(Some(OPENVMM_RPC_TIMEOUT))
                .start(vmservice::Vm::TeardownVm, ())
                .await
        })
        .await
    }

    async fn quit(&self) -> Result<()> {
        let socket_path = self.socket_path()?;
        rpc_call(socket_path, |client| async move {
            client
                .call()
                .wait_ready(true)
                .timeout(Some(OPENVMM_RPC_TIMEOUT))
                .start(vmservice::Vm::Quit, ())
                .await
        })
        .await
    }

    fn socket_path(&self) -> Result<String> {
        self.ttrpc_socket_path
            .as_ref()
            .context("openvmm process not launched")
            .cloned()
    }
}

async fn rpc_call<T, F, Fut>(socket_path: String, call: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(mesh_rpc::Client) -> Fut + Send + 'static,
    Fut: Future<Output = std::result::Result<T, mesh_rpc::service::Status>> + Send + 'static,
{
    tokio::task::spawn_blocking(move || -> Result<T> {
        let (result_send, result_recv) = std::sync::mpsc::channel();

        std::thread::Builder::new()
            .name("openvmm-rpc-client".to_string())
            .spawn(move || {
                ovmm_pal_async::DefaultPool::run_with(
                    |driver: ovmm_pal_async::DefaultDriver| async move {
                        let dialer =
                            mesh_rpc::client::UnixDialier::new(driver.clone(), socket_path);
                        let mut builder = mesh_rpc::client::ClientBuilder::new();
                        builder.retry_timeout(Duration::from_millis(100));
                        let client = builder.build(&driver, dialer);
                        let result = call(client)
                            .await
                            .map_err(|status| anyhow!("openvmm RPC failed: {:?}", status));
                        let _ = result_send.send(result);
                    },
                );
            })
            .context("failed to spawn openvmm RPC client thread")?;

        result_recv
            .recv()
            .context("openvmm RPC client thread exited without a result")?
    })
    .await
    .context("openvmm RPC task join failed")?
}

async fn wait_for_socket(path: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if Path::new(path).exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    anyhow::bail!("timed out waiting for socket {path}")
}

fn resolve_openvmm_path(configured_path: &str) -> Result<PathBuf> {
    if !configured_path.is_empty() {
        return Ok(PathBuf::from(configured_path));
    }

    for candidate in [
        "/usr/bin/openvmm",
        "/usr/local/bin/openvmm",
        "/mnt/data/openvmm",
        "/mnt/data/openvmm-repo/target/release/openvmm",
        "/mnt/data/openvmm-repo/target/debug/openvmm",
    ] {
        if Path::new(candidate).exists() {
            return Ok(PathBuf::from(candidate));
        }
    }

    Ok(PathBuf::from("openvmm"))
}
