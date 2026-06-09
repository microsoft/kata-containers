// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! VmmInstance wrapper for OpenVMM's in-process VM worker.

use anyhow::{anyhow, Context, Result};
use openvmm_defs::config::Config;
use openvmm_defs::rpc::VmRpc;
use openvmm_defs::worker::{VmWorkerParameters, VM_WORKER};
use ovmm_mesh::rpc::RpcSend;
use ovmm_mesh_worker::RegisteredWorkers;
use ovmm_vmm_core_defs::HaltReason;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vm_resource::IntoResource;

use super::OPENVMM_VSOCK_PCI_PORT;
use crate::utils::{enter_netns, open_named_tuntap};

#[derive(Debug)]
pub(crate) struct DeferredNetworkDevice {
    pub(crate) port_name: String,
    pub(crate) tap_name: String,
    pub(crate) mac_address: String,
}

// Force linker to include openvmm_resources which registers the VmWorker
// via linkme::distributed_slice.
extern crate openvmm_resources as _;

/// Wrapper around OpenVMM's VmWorker, providing VM lifecycle control.
#[allow(dead_code)]
pub(crate) struct VmmInstance {
    worker_handle: Option<ovmm_mesh_worker::WorkerHandle>,
    worker_rpc: Option<ovmm_mesh::Sender<VmRpc>>,
    /// Background task that consumes guest-halt notifications from the
    /// in-process VmWorker and signals `exit_notify` so that `wait_vm()`
    /// (and therefore the containerd-shim main loop) returns when the
    /// guest powers off on its own (e.g. agent-initiated shutdown,
    /// kernel panic, triple fault, OOM-killed init, etc.).
    halt_watcher: Option<JoinHandle<()>>,
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
            halt_watcher: None,
            exit_notify: Some(exit_notify),
        }
    }

    /// Launch the VmWorker with the given configuration.
    ///
    /// `vsock_uds_path` is the Unix socket path for virtio-vsock. The listener
    /// is bound inside the worker thread to avoid FD transfer issues.
    ///
    /// If `disk_path` is Some, the disk file will be opened inside the worker
    /// thread and patched into the first PCIe device's virtio-blk resource.
    pub(crate) async fn launch(
        &mut self,
        mut config: Config,
        vsock_uds_path: String,
        disk_path: Option<String>,
        network_devices: Vec<DeferredNetworkDevice>,
        netns: Option<String>,
        log_dir: Option<String>,
    ) -> Result<()> {
        let (rpc_send, rpc_recv) = ovmm_mesh::channel();
        let (notify_send, notify_recv) = ovmm_mesh::channel();

        // Use a oneshot channel to get the worker handle from the pal_async thread.
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();

        // Run everything in a single pal_async thread: bind listener, create
        // worker host, launch worker. This ensures the UnixListener FD stays
        // in the same async runtime as the VmWorker.
        std::thread::Builder::new()
            .name("ovmm-worker-host".to_string())
            .spawn(move || {
                // Set up tracing for the VmWorker thread.
                // Write openvmm tracing output to a log file for debugging.
                //
                // We install the subscriber globally (rather than thread-local
                // via `set_default`) because `DefaultPool::run_with` may
                // execute spawned tasks on its own internal threads where a
                // thread-local subscriber would not be visible.
                //
                // `try_init()` is a no-op if a global subscriber is already
                // installed (e.g. by an earlier sandbox in the same shim
                // process). Kata normally creates a fresh shim per sandbox,
                // so the first launch wins and configures verbosity.
                //
                // Verbosity is controlled by the `RUST_LOG` environment
                // variable; default is `info`. For VM-launch debugging use
                // e.g. `RUST_LOG=info,openvmm=debug,virt_mshv=debug`.
                if let Some(ref dir) = log_dir {
                    let log_file_path = format!("{}/openvmm-worker.log", dir);
                    if let Ok(file) = std::fs::File::create(&log_file_path) {
                        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
                        let _ = tracing_subscriber::fmt()
                            .with_writer(std::sync::Mutex::new(file))
                            .with_ansi(false)
                            .with_env_filter(filter)
                            .try_init();
                    }
                }

                if let Some(ref netns_path) = netns {
                    if let Err(err) = enter_netns(netns_path) {
                        let _ = result_tx.send(Err(
                            err.context(format!("failed to enter netns {}", netns_path))
                        ));
                        return;
                    }
                }

                let add_network_devices = || -> Result<()> {
                    for network_device in network_devices {
                        let fd = open_named_tuntap(&network_device.tap_name, 1)
                            .with_context(|| {
                                format!(
                                    "failed to open TAP device {} for openvmm",
                                    network_device.tap_name
                                )
                            })?
                            .into_iter()
                            .next()
                            .ok_or_else(|| {
                                anyhow!(
                                    "no TAP file descriptors returned for {}",
                                    network_device.tap_name
                                )
                            })?
                            .into();

                        let endpoint = net_backend_resources::tap::TapHandle { fd }.into_resource();
                        let net_handle = virtio_resources::net::VirtioNetHandle {
                            max_queues: None,
                            mac_address: network_device.mac_address.parse().unwrap_or_else(|_| {
                                net_backend_resources::mac_address::MacAddress::from([0u8; 6])
                            }),
                            endpoint,
                        };

                        config
                            .pcie_devices
                            .push(openvmm_defs::config::PcieDeviceConfig {
                                port_name: network_device.port_name,
                                resource: virtio_resources::VirtioPciDeviceHandle(
                                    net_handle.into_resource(),
                                )
                                .into_resource(),
                            });
                    }

                    Ok(())
                };

                if let Err(err) = add_network_devices() {
                    let _ = result_tx.send(Err(err.context("failed to configure network devices")));
                    return;
                }

                // Bind virtio-vsock listener inside this thread and add
                // the device as a PCIe virtio device.
                {
                    let _ = std::fs::remove_file(&vsock_uds_path);
                    match ovmm_unix_socket::UnixListener::bind(&vsock_uds_path) {
                        Ok(listener) => {
                            let has_vsock_port =
                                config.pcie_root_complexes.iter().any(|root_complex| {
                                    root_complex
                                        .ports
                                        .iter()
                                        .any(|port| port.name == OPENVMM_VSOCK_PCI_PORT)
                                });

                            if !has_vsock_port {
                                let _ = result_tx.send(Err(anyhow::anyhow!(
                                    "missing preconfigured OpenVMM vsock PCIe port {}",
                                    OPENVMM_VSOCK_PCI_PORT
                                )));
                                return;
                            }

                            let vsock_handle = virtio_resources::vsock::VirtioVsockHandle {
                                guest_cid: 3, // standard guest CID
                                base_path: vsock_uds_path.clone(),
                                listener,
                            };
                            config
                                .pcie_devices
                                .push(openvmm_defs::config::PcieDeviceConfig {
                                    port_name: OPENVMM_VSOCK_PCI_PORT.to_string(),
                                    resource: virtio_resources::VirtioPciDeviceHandle(
                                        vsock_handle.into_resource(),
                                    )
                                    .into_resource(),
                                });
                        }
                        Err(e) => {
                            let _ = result_tx.send(Err(anyhow::anyhow!(
                                "failed to bind vsock listener at {}: {}",
                                vsock_uds_path,
                                e
                            )));
                            return;
                        }
                    }
                }

                // Open disk file inside this thread to avoid FD loss through
                // mesh channel serialization. Replace the first PCIe device's
                // virtio-blk resource with one backed by the freshly-opened file.
                if let Some(ref path) = disk_path {
                    match std::fs::OpenOptions::new().read(true).open(path) {
                        Ok(file) => {
                            let disk_resource =
                                disk_backend_resources::FileDiskHandle(file).into_resource();
                            let blk_handle = virtio_resources::blk::VirtioBlkHandle {
                                disk: disk_resource,
                                read_only: true,
                            };
                            config
                                .pcie_devices
                                .push(openvmm_defs::config::PcieDeviceConfig {
                                    port_name: "rp0".to_string(),
                                    resource: virtio_resources::VirtioPciDeviceHandle(
                                        blk_handle.into_resource(),
                                    )
                                    .into_resource(),
                                });
                        }
                        Err(e) => {
                            let _ = result_tx.send(Err(anyhow::anyhow!(
                                "failed to open disk at {}: {}",
                                path,
                                e
                            )));
                            return;
                        }
                    }
                }

                ovmm_pal_async::DefaultPool::run_with(
                    |driver: ovmm_pal_async::DefaultDriver| async move {
                        use ovmm_pal_async::task::Spawn;

                        let (host, runner) = ovmm_mesh_worker::worker_host();
                        driver
                            .spawn("worker-host-runner", runner.run(RegisteredWorkers))
                            .detach();

                        let hypervisor = match std::fs::File::open("/dev/mshv") {
                            Ok(mshv) => hypervisor_resources::MshvHandle { mshv }.into_resource(),
                            Err(err) => {
                                let _ = result_tx.send(Err(anyhow::anyhow!(
                                    "failed to open /dev/mshv for openvmm: {}",
                                    err
                                )));
                                return;
                            }
                        };

                        let result = host
                            .launch_worker(
                                VM_WORKER,
                                VmWorkerParameters {
                                    hypervisor,
                                    cfg: config,
                                    saved_state: None,
                                    rpc: rpc_recv,
                                    notify: notify_send,
                                    shared_memory: None,
                                },
                            )
                            .await;

                        let _ = result_tx.send(result.context("failed to launch VM worker"));

                        // Keep the pool alive for the VM's lifetime.
                        std::future::pending::<()>().await;
                    },
                );
            })
            .context("failed to spawn worker host thread")?;

        // Wait for the worker to start from the tokio context.
        let worker = result_rx.await.context("worker host thread died")??;

        self.worker_handle = Some(worker);
        self.worker_rpc = Some(rpc_send);
        self.halt_watcher = Some(spawn_halt_watcher(notify_recv, self.exit_notify.clone()));

        Ok(())
    }

    /// Resume (boot) the VM.
    pub(crate) async fn resume(&self) -> Result<()> {
        let rpc = self.worker_rpc.as_ref().context("VM not launched")?;
        let result = rpc.call(VmRpc::Resume, ()).await;
        match result {
            Ok(true) => Ok(()),
            Ok(false) => anyhow::bail!("VM resume returned false"),
            Err(e) => anyhow::bail!("VM resume failed: {:?}", e),
        }
    }

    /// Pause the VM.
    pub(crate) async fn pause(&self) -> Result<()> {
        let rpc = self.worker_rpc.as_ref().context("VM not launched")?;
        let result = rpc.call(VmRpc::Pause, ()).await;
        match result {
            Ok(true) => Ok(()),
            Ok(false) => anyhow::bail!("VM pause returned false"),
            Err(e) => anyhow::bail!("VM pause failed: {:?}", e),
        }
    }

    pub(crate) async fn add_pcie_device(
        &self,
        port_name: String,
        resource: vm_resource::Resource<vm_resource::kind::PciDeviceHandleKind>,
    ) -> Result<()> {
        let rpc = self.worker_rpc.as_ref().context("VM not launched")?;
        rpc.call_failable(VmRpc::AddPcieDevice, (port_name, resource))
            .await
            .context("failed to hotplug PCIe device")?;
        Ok(())
    }

    pub(crate) async fn remove_pcie_device(&self, port_name: String) -> Result<()> {
        let rpc = self.worker_rpc.as_ref().context("VM not launched")?;
        rpc.call_failable(VmRpc::RemovePcieDevice, port_name)
            .await
            .context("failed to hot-remove PCIe device")?;
        Ok(())
    }

    /// Stop and teardown the VM.
    pub(crate) async fn stop(&mut self) -> Result<()> {
        // Stop the halt watcher first so it does not race with the
        // explicit exit_notify send below. Aborting the task is safe
        // because it only borrows owned values (the mesh Receiver and
        // a clone of the exit_notify Sender).
        if let Some(handle) = self.halt_watcher.take() {
            handle.abort();
        }

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

        if let Some(exit_notify) = &self.exit_notify {
            let _ = exit_notify.try_send(0);
        }

        Ok(())
    }
}

/// Spawn a tokio task that watches the OpenVMM halt-notification
/// channel and signals `exit_notify` when the guest reaches a terminal
/// halt state (anything other than a guest-initiated reset, which the
/// VmWorker handles internally via `automatic_guest_reset = true`).
///
/// Without this watcher, `OpenVmm::wait_vm()` would block forever after
/// the guest powers off, because the in-process VmWorker has no child
/// process for the shim to reap and no other code reads the halt
/// channel. That stall surfaces as the kata-shim hanging on container
/// teardown.
fn spawn_halt_watcher(
    mut notify_recv: ovmm_mesh::Receiver<HaltReason>,
    exit_notify: Option<mpsc::Sender<i32>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match notify_recv.recv().await {
                Ok(HaltReason::Reset) => {
                    // The VmWorker is configured with
                    // `automatic_guest_reset = true`, so it should
                    // handle resets internally and not forward them
                    // here. Be defensive in case that ever changes.
                    info!(sl!(), "openvmm: guest-initiated reset (ignored)");
                    continue;
                }
                Ok(reason) => {
                    info!(
                        sl!(),
                        "openvmm: guest halted, signaling shim exit: {:?}", reason
                    );
                    if let Some(tx) = &exit_notify {
                        let _ = tx.try_send(0);
                    }
                    return;
                }
                Err(err) => {
                    // The sender side was dropped — typically because
                    // `stop()` tore down the worker. Nothing more to do.
                    info!(
                        sl!(),
                        "openvmm: halt notification channel closed: {:?}", err
                    );
                    return;
                }
            }
        }
    })
}
