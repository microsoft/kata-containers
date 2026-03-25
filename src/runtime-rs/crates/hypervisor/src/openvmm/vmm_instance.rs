// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! VmmInstance wrapper for OpenVMM's in-process VM worker.
//!
//! Analogous to dragonball's VmmInstance, this wraps the mesh_worker
//! WorkerHandle and VmRpc channels for controlling the VM lifecycle.

use anyhow::{Context, Result};
use openvmm_defs::config::Config;
use openvmm_defs::rpc::VmRpc;
use openvmm_defs::worker::{VmWorkerParameters, VM_WORKER};
use ovmm_mesh::rpc::RpcSend;
use ovmm_mesh_worker::RegisteredWorkers;
use ovmm_vmm_core_defs::HaltReason;
use tokio::sync::mpsc;

/// Wrapper around OpenVMM's VmWorker, providing VM lifecycle control.
#[allow(dead_code)]
pub(crate) struct VmmInstance {
    /// Handle to the running worker (for stop/join)
    worker_handle: Option<ovmm_mesh_worker::WorkerHandle>,
    /// Channel for sending VmRpc commands (pause, resume, etc.)
    worker_rpc: Option<ovmm_mesh::Sender<VmRpc>>,
    /// Channel for receiving VM halt notifications
    _notify_recv: Option<ovmm_mesh::Receiver<HaltReason>>,
    /// Exit notification channel (kata-side)
    exit_notify: Option<mpsc::Sender<i32>>,
}

impl std::fmt::Debug for VmmInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmmInstance")
            .field("running", &self.worker_handle.is_some())
            .finish()
    }
}

#[allow(dead_code)]
impl VmmInstance {
    pub(crate) fn new(exit_notify: mpsc::Sender<i32>) -> Self {
        VmmInstance {
            worker_handle: None,
            worker_rpc: None,
            _notify_recv: None,
            exit_notify: Some(exit_notify),
        }
    }

    /// Launch the VmWorker with the given configuration.
    ///
    /// This spawns the VM in a separate thread via mesh_worker.
    /// After this call, the VM is created but paused — call resume() to boot.
    pub(crate) async fn launch(&mut self, config: Config) -> Result<()> {
        let (rpc_send, rpc_recv) = ovmm_mesh::channel();
        let (notify_send, notify_recv) = ovmm_mesh::channel();

        // Create a worker host and spawn its runner as a detached task.
        // The runner listens for worker launch requests and spawns OS threads.
        let (host, runner) = ovmm_mesh_worker::worker_host();

        // We need a pal_async driver to spawn the runner task.
        // Use a dedicated thread for the worker host event loop.
        let runner_thread = std::thread::Builder::new()
            .name("ovmm-worker-host".to_string())
            .spawn(move || {
                ovmm_pal_async::DefaultPool::run_with(|driver: ovmm_pal_async::DefaultDriver| async move {
                    use ovmm_pal_async::task::Spawn;
                    driver
                        .spawn("worker-host-runner", runner.run(RegisteredWorkers))
                        .detach();

                    // Keep the pool alive; it will be dropped when the worker stops.
                    std::future::pending::<()>().await;
                });
            })
            .context("failed to spawn worker host thread")?;

        // Give the worker host thread a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Launch the VM worker. This sends parameters to the runner thread,
        // which spawns a new OS thread for the VmWorker.
        let worker = host
            .launch_worker(
                VM_WORKER,
                VmWorkerParameters {
                    hypervisor: None, // Auto-detect (will find MSHV)
                    cfg: config,
                    saved_state: None,
                    shared_memory: None,
                    rpc: rpc_recv,
                    notify: notify_send,
                },
            )
            .await
            .context("failed to launch VM worker")?;

        self.worker_handle = Some(worker);
        self.worker_rpc = Some(rpc_send);
        self._notify_recv = Some(notify_recv);

        // Forget the runner thread handle — it runs for the lifetime of the VM
        std::mem::forget(runner_thread);

        Ok(())
    }

    /// Resume (boot) the VM. Must be called after launch().
    pub(crate) async fn resume(&self) -> Result<()> {
        let rpc = self
            .worker_rpc
            .as_ref()
            .context("VM not launched")?;
        let result = rpc.call(VmRpc::Resume, ()).await;
        match result {
            Ok(true) => Ok(()),
            Ok(false) => anyhow::bail!("VM resume returned false"),
            Err(e) => anyhow::bail!("VM resume failed: {:?}", e),
        }
    }

    /// Pause the VM.
    pub(crate) async fn pause(&self) -> Result<()> {
        let rpc = self
            .worker_rpc
            .as_ref()
            .context("VM not launched")?;
        let result = rpc.call(VmRpc::Pause, ()).await;
        match result {
            Ok(true) => Ok(()),
            Ok(false) => anyhow::bail!("VM pause returned false"),
            Err(e) => anyhow::bail!("VM pause failed: {:?}", e),
        }
    }

    /// Stop and teardown the VM.
    pub(crate) async fn stop(&mut self) -> Result<()> {
        if let Some(mut worker_handle) = self.worker_handle.take() {
            worker_handle.stop();
            if let Err(err) = worker_handle.join().await {
                warn!(
                    sl!(),
                    "openvmm: VM worker failed during shutdown: {:?}", err
                );
            }
        }
        self.worker_rpc = None;
        self._notify_recv = None;

        // Notify kata of exit
        if let Some(exit_notify) = &self.exit_notify {
            let _ = exit_notify.try_send(0);
        }

        Ok(())
    }
}
