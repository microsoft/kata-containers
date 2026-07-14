// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! External OpenVMM process wrapper using OpenVMM's TTRPC VM service.

use anyhow::{anyhow, Context, Result};
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
use protobuf::Message;
use std::io::{IoSlice, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::empty::Empty;
use super::inner_hypervisor::{blk_device_kind, net_device_kind};
use super::vmservice;
use super::vmservice_ttrpc::VmClient;
use crate::utils::enter_netns;
use protobuf::MessageField;

const OPENVMM_READY_TIMEOUT: Duration = Duration::from_secs(20);
const OPENVMM_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const OPENVMM_RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Wrapper around an external OpenVMM process, providing VM lifecycle control.
pub(crate) struct VmmInstance {
    pid: Option<u32>,
    ttrpc_socket_path: Option<String>,
    wait_task: Option<JoinHandle<()>>,
    exit_notify: Option<mpsc::Sender<i32>>,
    /// Persistent ttrpc async client for the OpenVMM `vmservice.VM` service,
    /// established once the process is launched and reused for every RPC.
    client: Option<VmClient>,
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
            client: None,
        }
    }

    pub(crate) async fn launch(
        &mut self,
        configured_path: &str,
        ttrpc_socket_path: String,
        request: vmservice::CreateVMRequest,
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

        // Wait for the OpenVMM TTRPC server to start accepting connections.
        // `Client::connect` performs a one-shot `connect(2)`, so `connect_client`
        // retries until the child has created the socket and begun listening (or
        // the timeout elapses). This single readiness loop intentionally
        // replaces a separate "does the socket file exist yet?" poll: a missing
        // socket file and a not-yet-listening server are both just transient
        // connect errors that the retry already handles.
        let client = connect_client(&ttrpc_socket_path, OPENVMM_READY_TIMEOUT)
            .await
            .with_context(|| {
                format!("openvmm TTRPC socket did not become ready: {ttrpc_socket_path}")
            })?;
        self.client = Some(client);

        self.create_vm(request).await
    }

    pub(crate) async fn resume(&self) -> Result<()> {
        self.client()?
            .resume_vm(rpc_ctx(), &Empty::new())
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("openvmm resume_vm RPC failed: {:?}", e))
    }

    pub(crate) async fn pause(&self) -> Result<()> {
        self.client()?
            .pause_vm(rpc_ctx(), &Empty::new())
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("openvmm pause_vm RPC failed: {:?}", e))
    }

    /// Hot-add a virtio-blk-pci device behind the named (pre-declared) PCIe
    /// hotplug port.
    pub(crate) async fn add_pcie_device(
        &self,
        port_name: &str,
        host_path: String,
        read_only: bool,
    ) -> Result<()> {
        let request = vmservice::AddPcieDeviceRequest {
            port_name: port_name.to_string(),
            device: MessageField::some(blk_device_kind(host_path, read_only)),
            ..Default::default()
        };

        self.client()?
            .add_pcie_device(rpc_ctx(), &request)
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("openvmm add_pcie_device RPC failed: {:?}", e))
    }

    /// Hot-add a virtio-net-pci device behind the named (pre-declared) PCIe
    /// hotplug port.
    pub(crate) async fn add_net_pcie_device(
        &self,
        port_name: &str,
        mac_address: &str,
        tap_name: &str,
        tap_file: std::fs::File,
    ) -> Result<()> {
        let request = vmservice::AddPcieDeviceRequest {
            port_name: port_name.to_string(),
            device: MessageField::some(net_device_kind(
                mac_address.to_string(),
                tap_name.to_string(),
            )),
            ..Default::default()
        };

        self.add_pcie_device_with_tap_fd(request, tap_file).await
    }

    /// Hot-remove the device behind the named PCIe hotplug port.
    pub(crate) async fn remove_pcie_device(&self, port_name: &str) -> Result<()> {
        let request = vmservice::RemovePcieDeviceRequest {
            port_name: port_name.to_string(),
            ..Default::default()
        };

        self.client()?
            .remove_pcie_device(rpc_ctx(), &request)
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("openvmm remove_pcie_device RPC failed: {:?}", e))
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
        self.client = None;
        self.pid = None;

        Ok(())
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        self.pid
    }

    async fn create_vm(&self, request: vmservice::CreateVMRequest) -> Result<()> {
        self.client()?
            .create_vm(rpc_ctx(), &request)
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("openvmm create_vm RPC failed: {:?}", e))
    }

    async fn teardown_vm(&self) -> Result<()> {
        self.client()?
            .teardown_vm(rpc_ctx(), &Empty::new())
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("openvmm teardown_vm RPC failed: {:?}", e))
    }

    async fn quit(&self) -> Result<()> {
        self.client()?
            .quit(rpc_ctx(), &Empty::new())
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("openvmm quit RPC failed: {:?}", e))
    }

    fn client(&self) -> Result<&VmClient> {
        self.client
            .as_ref()
            .context("openvmm TTRPC client not connected")
    }

    async fn add_pcie_device_with_tap_fd(
        &self,
        request: vmservice::AddPcieDeviceRequest,
        tap_file: std::fs::File,
    ) -> Result<()> {
        let socket_path = self
            .ttrpc_socket_path
            .as_ref()
            .context("openvmm TTRPC socket path is not set")?
            .clone();

        tokio::task::spawn_blocking(move || {
            add_pcie_device_with_tap_fd_blocking(&socket_path, &request, tap_file)
        })
        .await
        .map_err(|e| anyhow!("openvmm add_pcie_device task join failed: {e}"))??;

        Ok(())
    }
}

fn add_pcie_device_with_tap_fd_blocking(
    socket_path: &str,
    request: &vmservice::AddPcieDeviceRequest,
    tap_file: std::fs::File,
) -> Result<()> {
    let request_payload = request
        .write_to_bytes()
        .context("failed to serialize AddPcieDeviceRequest")?;

    let mut ttrpc_request = ttrpc::Request::new();
    ttrpc_request.set_service("vmservice.VM".to_string());
    ttrpc_request.set_method("AddPcieDevice".to_string());
    ttrpc_request.set_payload(request_payload);
    ttrpc_request.set_timeout_nano(OPENVMM_RPC_TIMEOUT.as_nanos() as i64);

    let request_bytes = ttrpc_request
        .write_to_bytes()
        .context("failed to serialize ttrpc request")?;

    let mut frame: Vec<u8> = Vec::with_capacity(10 + request_bytes.len());
    frame.extend_from_slice(&(request_bytes.len() as u32).to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.push(1);
    frame.push(0);
    frame.extend_from_slice(&request_bytes);

    let mut stream = UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect to openvmm ttrpc socket {socket_path}"))?;
    stream
        .set_read_timeout(Some(OPENVMM_RPC_TIMEOUT))
        .context("failed to set openvmm ttrpc read timeout")?;
    stream
        .set_write_timeout(Some(OPENVMM_RPC_TIMEOUT))
        .context("failed to set openvmm ttrpc write timeout")?;

    send_frame_with_fd(&mut stream, &frame, tap_file.as_raw_fd())
        .context("failed to send AddPcieDevice ttrpc request with TAP fd")?;

    let response = read_ttrpc_response(&mut stream)
        .context("failed to read AddPcieDevice ttrpc response")?;

    if response.status().code() != ttrpc::Code::OK {
        return Err(anyhow!(
            "openvmm add_pcie_device RPC failed: {:?}: {}",
            response.status().code(),
            response.status().message()
        ));
    }

    Ok(())
}

fn send_frame_with_fd(stream: &mut UnixStream, frame: &[u8], fd: RawFd) -> Result<()> {
    let iov = [IoSlice::new(frame)];
    let cmsgs = [ControlMessage::ScmRights(&[fd])];
    let sent = sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
        .context("sendmsg failed")?;

    if sent < frame.len() {
        stream
            .write_all(&frame[sent..])
            .context("failed to write remaining ttrpc frame bytes")?;
    }

    Ok(())
}

fn read_ttrpc_response(stream: &mut UnixStream) -> Result<ttrpc::Response> {
    let mut header = [0u8; 10];
    stream
        .read_exact(&mut header)
        .context("failed to read ttrpc response header")?;

    let payload_len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let message_type = header[8];
    if message_type != 2 {
        return Err(anyhow!(
            "unexpected ttrpc message type {}, expected response type 2",
            message_type
        ));
    }

    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .context("failed to read ttrpc response payload")?;

    ttrpc::Response::parse_from_bytes(&payload).context("failed to decode ttrpc response")
}

/// Build a per-call ttrpc context carrying the standard OpenVMM RPC timeout.
fn rpc_ctx() -> ttrpc::context::Context {
    ttrpc::context::with_timeout(OPENVMM_RPC_TIMEOUT.as_nanos() as i64)
}

/// Connect a ttrpc async client to the OpenVMM `vmservice` Unix socket, retrying
/// until the server accepts connections or `timeout` elapses.
async fn connect_client(socket_path: &str, timeout: Duration) -> Result<VmClient> {
    let address = format!("unix://{socket_path}");
    let deadline = Instant::now() + timeout;

    loop {
        match ttrpc::asynchronous::Client::connect(&address) {
            Ok(inner) => return Ok(VmClient::new(inner)),
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(anyhow!(
                        "failed to connect to openvmm TTRPC socket {socket_path}: {err:?}"
                    ));
                }
                // Back off between attempts so we don't busy-spin on
                // ECONNREFUSED/ENOENT while the child process is still starting.
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
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
