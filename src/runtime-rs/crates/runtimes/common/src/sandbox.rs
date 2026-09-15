// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    types::{ContainerProcess, SandboxExitInfo, SandboxStatus},
    ContainerManager,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct SnapshotRequest {
    cancellation: CancellationToken,
    deadline: Instant,
    publication_lock: Arc<Mutex<()>>,
}

impl SnapshotRequest {
    pub fn new(timeout: Duration) -> Self {
        Self {
            cancellation: CancellationToken::new(),
            deadline: Instant::now() + timeout,
            publication_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn cancel(&self) {
        let _publication = self.publication_lock.lock().unwrap();
        self.cancellation.cancel();
    }

    pub fn check_cancelled(&self) -> Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(anyhow!("snapshot request cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(anyhow!("snapshot request deadline exceeded"));
        }
        Ok(())
    }

    pub async fn cancelled(&self) {
        tokio::select! {
            _ = self.cancellation.cancelled() => {}
            _ = tokio::time::sleep_until(self.deadline.into()) => {}
        }
    }

    pub fn publish<T>(&self, publish: impl FnOnce() -> Result<T>) -> Result<T> {
        let _publication = self.publication_lock.lock().unwrap();
        self.check_cancelled()?;
        publish()
    }
}

#[derive(Clone, Default)]
pub struct SandboxNetworkEnv {
    pub netns: Option<String>,
    pub network_created: bool,
}

impl std::fmt::Debug for SandboxNetworkEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxNetworkEnv")
            .field("netns", &self.netns)
            .field("network_created", &self.network_created)
            .finish()
    }
}

#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn start_template(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn cleanup(&self) -> Result<()>;
    async fn shutdown(&self) -> Result<()>;
    async fn status(&self) -> Result<SandboxStatus>;
    async fn wait(&self) -> Result<SandboxExitInfo>;

    // utils
    async fn set_iptables(&self, is_ipv6: bool, data: Vec<u8>) -> Result<Vec<u8>>;
    async fn get_iptables(&self, is_ipv6: bool) -> Result<Vec<u8>>;
    async fn direct_volume_stats(&self, volume_path: &str) -> Result<String>;
    async fn direct_volume_resize(&self, resize_req: agent::ResizeVolumeRequest) -> Result<()>;
    async fn agent_sock(&self) -> Result<String>;
    async fn wait_process(
        &self,
        cm: Arc<dyn ContainerManager>,
        process_id: ContainerProcess,
        shim_pid: u32,
    ) -> Result<()>;

    // Docker 26+ network rescan: discover interfaces that Docker configured
    // between the Create and Start RPCs.
    async fn rescan_network(&self) -> Result<()>;

    // metrics function
    async fn agent_metrics(&self) -> Result<String>;
    async fn hypervisor_metrics(&self) -> Result<String>;

    async fn snapshot(
        &self,
        container_manager: Arc<dyn ContainerManager>,
        destination: &Path,
        request: SnapshotRequest,
    ) -> Result<()>;

    // set agent policy
    async fn set_policy(&self, policy: &str) -> Result<()>;
}

#[cfg(test)]
mod snapshot_request_tests {
    use super::*;

    #[test]
    fn cancellation_prevents_snapshot_publication() {
        let request = SnapshotRequest::new(Duration::from_secs(60));
        request.clone().cancel();
        assert!(request.check_cancelled().is_err());
        assert!(request
            .publish(|| -> Result<()> { panic!("published cancelled snapshot") })
            .is_err());
    }

    #[test]
    fn deadline_prevents_snapshot_publication_without_timer_polling() {
        let request = SnapshotRequest::new(Duration::ZERO);
        assert!(request
            .publish(|| -> Result<()> { panic!("published expired snapshot") })
            .is_err());
    }

    #[test]
    fn active_snapshot_can_publish() {
        let request = SnapshotRequest::new(Duration::from_secs(60));
        assert_eq!(request.publish(|| Ok(42)).unwrap(), 42);
    }

    #[test]
    fn publication_and_cancellation_are_serialized() {
        let request = SnapshotRequest::new(Duration::from_secs(60));
        let worker_request = request.clone();
        let (cancel_started_tx, cancel_started_rx) = std::sync::mpsc::channel();
        let (cancel_finished_tx, cancel_finished_rx) = std::sync::mpsc::channel();
        let worker = request
            .publish(|| {
                let worker = std::thread::spawn(move || {
                    cancel_started_tx.send(()).unwrap();
                    worker_request.cancel();
                    cancel_finished_tx.send(()).unwrap();
                });
                cancel_started_rx
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
                assert!(cancel_finished_rx.try_recv().is_err());
                assert!(request.check_cancelled().is_ok());
                Ok(worker)
            })
            .unwrap();
        worker.join().unwrap();
        cancel_finished_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        assert!(request.check_cancelled().is_err());
    }

    #[tokio::test]
    async fn cancellation_wakes_waiter() {
        let request = SnapshotRequest::new(Duration::from_secs(60));
        request.cancel();
        tokio::time::timeout(Duration::from_secs(1), request.cancelled())
            .await
            .unwrap();
    }
}
