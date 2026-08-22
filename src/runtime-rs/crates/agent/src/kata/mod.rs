// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

mod agent;
mod trans;

use std::{
    os::unix::io::{IntoRawFd, RawFd},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use kata_types::config::Agent as AgentConfig;
use nix::sys::socket::{shutdown, Shutdown};
use protocols::{agent_ttrpc_async as agent_ttrpc, health_ttrpc_async as health_ttrpc};
use tokio::sync::{watch, Notify, RwLock};
use ttrpc::asynchronous::Client;

use crate::{log_forwarder::LogForwarder, sock, AgentDisconnectToken};

// Planned snapshot disconnects are retried; ordinary disconnects are not.
//
// Startup:  Disconnected -> Reconnecting -> Connected
// Snapshot: Connected -> PlannedDisconnect -> Disconnected
//                    -> Reconnecting -> Connected (next generation)
// Teardown: Connected -> PermanentlyClosed
//
// Only Connected lends out clients. Transient states therefore form a gate:
// new calls wait, while calls from the old generation either drain or rearm on
// the next generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionStatus {
    Connected,
    PlannedDisconnect,
    Disconnected,
    Reconnecting,
    PermanentlyClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConnectionState {
    // Planned-disconnect states retain the current generation. A reconnect
    // attempts the next generation and rolls back if connection setup fails.
    generation: u64,
    status: ConnectionStatus,
}

// A call participates only when snapshot correctness requires it to remain
// logically pending, or when interruption/replay would be ambiguous. Bounded,
// disposable reads use the ordinary client path and may return an error.
#[derive(Clone, Copy)]
pub(super) enum ActivityKind {
    /// An unbounded observer that is safe to reissue after reconnect.
    Reconnectable,
    /// A non-replayable write that must finish before disconnect.
    Write,
}

/// RAII membership in an agent activity barrier.
///
/// Every exit path decrements the counter and wakes tasks waiting for a drain.
pub(super) struct ActivityGuard {
    count: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
        self.notify.notify_waiters();
    }
}

// https://github.com/firecracker-microvm/firecracker/blob/master/docs/vsock.md
#[derive(Debug, Default)]
pub struct Vsock {
    pub context_id: u64,
    pub port: u32,
}

pub(crate) struct KataAgentInner {
    /// TTRPC client
    pub client: Option<Client>,

    /// Borrowed client fd used only to shut down the ttrpc-owned socket.
    pub client_fd: RawFd,

    /// Unix domain socket address
    pub socket_address: String,

    /// Agent config
    config: AgentConfig,

    /// Log forwarder
    log_forwarder: LogForwarder,

    connection: ConnectionState,
}

impl std::fmt::Debug for KataAgentInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KataAgentInner")
            .field("client_fd", &self.client_fd)
            .field("socket_address", &self.socket_address)
            .field("config", &self.config)
            .finish()
    }
}

unsafe impl Send for KataAgent {}
unsafe impl Sync for KataAgent {}
#[derive(Debug)]
pub struct KataAgent {
    pub(crate) inner: Arc<RwLock<KataAgentInner>>,
    /// Broadcasts state changes to calls waiting for a usable generation.
    connection_tx: watch::Sender<ConnectionState>,
    /// Old-generation observer RPCs that must fail before the VM is paused.
    reconnectable_calls: Arc<AtomicUsize>,
    /// Observers between generations that must rearm before recovery.
    reconnect_waiters: Arc<AtomicUsize>,
    /// Non-replayable writes that must drain before transport shutdown.
    writes: Arc<AtomicUsize>,
    activity_notify: Arc<Notify>,
}

impl KataAgent {
    pub fn new(config: AgentConfig) -> Self {
        let initial_connection = ConnectionState {
            generation: 0,
            status: ConnectionStatus::Disconnected,
        };
        let (connection_tx, _) = watch::channel(initial_connection);
        KataAgent {
            inner: Arc::new(RwLock::new(KataAgentInner {
                client: None,
                client_fd: -1,
                socket_address: "".to_string(),
                config,
                log_forwarder: LogForwarder::new(),
                connection: initial_connection,
            })),
            connection_tx,
            reconnectable_calls: Arc::new(AtomicUsize::new(0)),
            reconnect_waiters: Arc::new(AtomicUsize::new(0)),
            writes: Arc::new(AtomicUsize::new(0)),
            activity_notify: Arc::new(Notify::new()),
        }
    }

    fn publish_connection(&self, state: ConnectionState) {
        self.connection_tx.send_replace(state);
    }

    async fn set_connection(&self, state: ConnectionState) {
        self.inner.write().await.connection = state;
        self.publish_connection(state);
    }

    async fn wait_for_activity(&self, count: &AtomicUsize, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, async {
            loop {
                // Arm the notification before reading the counter so a final
                // guard cannot disappear between the check and the await.
                let notified = self.activity_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if count.load(Ordering::Acquire) == 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for agent RPCs to quiesce"))
    }

    pub(super) async fn acquire_agent_client(
        &self,
        kind: ActivityKind,
    ) -> Result<(agent_ttrpc::AgentServiceClient, i64, u64, ActivityGuard)> {
        let mut connection_rx = self.connection_tx.subscribe();
        loop {
            let inner = self.inner.read().await;
            match inner.connection.status {
                ConnectionStatus::Connected => {
                    let client = inner
                        .client
                        .as_ref()
                        .map(|client| agent_ttrpc::AgentServiceClient::new(client.clone()))
                        .ok_or_else(|| anyhow!("connected agent has no ttrpc client"))?;
                    let count = match kind {
                        ActivityKind::Reconnectable => self.reconnectable_calls.clone(),
                        ActivityKind::Write => self.writes.clone(),
                    };
                    // State transitions need the write lock. Registering while
                    // holding this read lock makes "Connected + counted"
                    // atomic with respect to prepare_disconnect().
                    count.fetch_add(1, Ordering::AcqRel);
                    return Ok((
                        client,
                        inner.config.request_timeout_ms as i64,
                        inner.connection.generation,
                        ActivityGuard {
                            count,
                            notify: self.activity_notify.clone(),
                        },
                    ));
                }
                ConnectionStatus::PermanentlyClosed => {
                    return Err(anyhow!("agent connection is permanently closed"));
                }
                _ => drop(inner),
            }
            connection_rx
                .changed()
                .await
                .context("agent connection state channel closed")?;
        }
    }

    pub(super) async fn should_retry_generation(&self, generation: u64) -> bool {
        let connection = self.inner.read().await.connection;
        // Retry only errors caused by our planned transition. A real transport
        // failure, or an error from an older generation, remains fatal.
        connection.generation == generation
            && matches!(
                connection.status,
                ConnectionStatus::PlannedDisconnect
                    | ConnectionStatus::Disconnected
                    | ConnectionStatus::Reconnecting
            )
    }

    pub(super) fn register_reconnect_waiter(&self) -> ActivityGuard {
        // The awaiting-new-generation guard is registered before releasing the
        // old-generation guard. Reconnect waits for it to drop after the
        // caller acquires the new generation.
        self.reconnect_waiters.fetch_add(1, Ordering::AcqRel);
        ActivityGuard {
            count: self.reconnect_waiters.clone(),
            notify: self.activity_notify.clone(),
        }
    }

    pub async fn get_health_client(&self) -> Option<(health_ttrpc::HealthClient, i64, RawFd)> {
        let inner = self.inner.read().await;
        if inner.connection.status != ConnectionStatus::Connected {
            return None;
        }
        inner.client.as_ref().map(|c| {
            (
                health_ttrpc::HealthClient::new(c.clone()),
                inner.config.health_check_request_timeout_ms as i64,
                inner.client_fd,
            )
        })
    }

    pub async fn get_agent_client(&self) -> Option<(agent_ttrpc::AgentServiceClient, i64, RawFd)> {
        let inner = self.inner.read().await;
        if inner.connection.status != ConnectionStatus::Connected {
            return None;
        }
        inner.client.as_ref().map(|c| {
            (
                agent_ttrpc::AgentServiceClient::new(c.clone()),
                inner.config.request_timeout_ms as i64,
                inner.client_fd,
            )
        })
    }

    pub(crate) async fn connect_agent_server(&self) -> Result<()> {
        let (address, server_port, config) = {
            let inner = self.inner.read().await;
            (
                inner.socket_address.clone(),
                inner.config.server_port,
                sock::ConnectConfig::new(
                    inner.config.dial_timeout_ms as u64,
                    inner.config.reconnect_timeout_ms as u64,
                ),
            )
        };
        let sock = sock::new(&address, server_port).context("new sock")?;
        info!(sl!(), "try to connect agent server through {:?}", sock);
        let stream = sock.connect(&config).await.context("connect")?;
        let fd = stream.into_raw_fd();
        info!(
            sl!(),
            "get stream raw fd {:?} with socket address: {:?} and server_port {:?}",
            fd,
            address,
            server_port
        );
        let c = Client::new(fd);
        let mut inner = self.inner.write().await;
        inner.client = Some(c);
        inner.client_fd = fd;
        Ok(())
    }

    pub(crate) async fn start_log_forwarder(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        let config = sock::ConnectConfig::new(
            inner.config.dial_timeout_ms as u64,
            inner.config.reconnect_timeout_ms as u64,
        );
        let address = inner.socket_address.clone();
        let port = inner.config.log_port;
        inner
            .log_forwarder
            .start(&address, port, config)
            .await
            .context("start log forwarder")?;
        Ok(())
    }

    pub(crate) async fn stop_log_forwarder(&self) {
        let mut inner = self.inner.write().await;
        inner.log_forwarder.stop();
    }

    pub(crate) async fn agent_sock(&self) -> Result<String> {
        let inner = self.inner.read().await;
        Ok(format!(
            "{}:{}",
            inner.socket_address.clone(),
            inner.config.server_port
        ))
    }

    pub(crate) async fn agent_config(&self) -> AgentConfig {
        let inner = self.inner.read().await;
        inner.config.clone()
    }

    pub(crate) async fn start_connection(
        &self,
        address: &str,
        token: Option<AgentDisconnectToken>,
    ) -> Result<()> {
        let (previous, connecting) = {
            let mut inner = self.inner.write().await;
            let previous = inner.connection;
            if let Some(token) = token {
                // A token may advance exactly the disconnected generation that
                // minted it; stale and out-of-order reconnects are rejected.
                if previous.status != ConnectionStatus::Disconnected
                    || previous.generation != token.generation()
                {
                    return Err(anyhow!(
                        "stale agent reconnect token for generation {}",
                        token.generation()
                    ));
                }
            } else if !matches!(
                previous.status,
                ConnectionStatus::Disconnected | ConnectionStatus::PermanentlyClosed
            ) {
                return Err(anyhow!("agent connection is already active"));
            }

            let connecting = ConnectionState {
                generation: previous.generation + 1,
                status: ConnectionStatus::Reconnecting,
            };
            inner.socket_address = address.to_string();
            inner.connection = connecting;
            (previous, connecting)
        };
        self.publish_connection(connecting);

        let result = async {
            self.connect_agent_server()
                .await
                .context("connect agent server")?;
            self.start_log_forwarder()
                .await
                .context("connect log forwarder")?;
            Ok(())
        }
        .await;

        if let Err(error) = result {
            let _ = self.close_client().await;
            self.set_connection(ConnectionState {
                generation: previous.generation,
                status: ConnectionStatus::Disconnected,
            })
            .await;
            return Err(error);
        }

        self.set_connection(ConnectionState {
            generation: connecting.generation,
            status: ConnectionStatus::Connected,
        })
        .await;
        // Publishing Connected wakes old observers. Do not report recovery
        // until each one has acquired this new generation.
        let timeout =
            Duration::from_millis(self.inner.read().await.config.reconnect_timeout_ms as u64);
        self.wait_for_activity(&self.reconnect_waiters, timeout)
            .await
            .context("rearm reconnectable agent RPCs")?;
        Ok(())
    }

    pub(crate) async fn prepare_disconnect(&self) -> Result<AgentDisconnectToken> {
        let (token, timeout) = {
            let mut inner = self.inner.write().await;
            if inner.connection.status != ConnectionStatus::Connected {
                return Err(anyhow!("agent is not connected"));
            }
            let token = AgentDisconnectToken {
                generation: inner.connection.generation,
            };
            // Change state first: no new call can register after the write
            // drain has begun.
            inner.connection.status = ConnectionStatus::PlannedDisconnect;
            (
                token,
                Duration::from_millis(inner.config.reconnect_timeout_ms as u64),
            )
        };
        self.publish_connection(ConnectionState {
            generation: token.generation(),
            status: ConnectionStatus::PlannedDisconnect,
        });

        if let Err(error) = self.wait_for_activity(&self.writes, timeout).await {
            self.set_connection(ConnectionState {
                generation: token.generation(),
                status: ConnectionStatus::Connected,
            })
            .await;
            return Err(error.context("drain agent writes"));
        }
        Ok(token)
    }

    async fn close_client(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.log_forwarder.stop();
        // ttrpc owns the fd and cloned clients can keep RPCs pending. shutdown
        // wakes every clone without stealing ownership or risking double-close.
        let shutdown_result = if inner.client_fd >= 0 {
            shutdown(inner.client_fd, Shutdown::Both).context("failed to shut down agent client fd")
        } else {
            Ok(())
        };
        inner.client.take();
        inner.client_fd = -1;
        shutdown_result
    }

    /// Disconnect from the agent gRPC server and clean up related resources.
    pub(crate) async fn disconnect(&self) -> Result<()> {
        let (connection, timeout) = {
            let inner = self.inner.read().await;
            (
                inner.connection,
                Duration::from_millis(inner.config.reconnect_timeout_ms as u64),
            )
        };
        let planned = connection.status == ConnectionStatus::PlannedDisconnect;
        let close_result = self.close_client().await;
        let disconnected = ConnectionState {
            generation: connection.generation,
            status: if planned {
                ConnectionStatus::Disconnected
            } else {
                ConnectionStatus::PermanentlyClosed
            },
        };
        self.set_connection(disconnected).await;
        if planned {
            // shutdown makes old RPCs fail; wait for their guards before the
            // caller pauses the VM so no host request is captured in flight.
            self.wait_for_activity(&self.reconnectable_calls, timeout)
                .await
                .context("quiesce reconnectable agent RPCs")?;
        }
        close_result
    }

    pub(crate) async fn reconnect(&self, address: &str, token: AgentDisconnectToken) -> Result<()> {
        self.start_connection(address, Some(token)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent() -> Arc<KataAgent> {
        let mut config = AgentConfig::default();
        config.reconnect_timeout_ms = 1_000;
        Arc::new(KataAgent::new(config))
    }

    async fn set_connected(agent: &KataAgent, generation: u64) {
        agent
            .set_connection(ConnectionState {
                generation,
                status: ConnectionStatus::Connected,
            })
            .await;
    }

    async fn wait_for_status(agent: &KataAgent, status: ConnectionStatus) {
        let mut connection_rx = agent.connection_tx.subscribe();
        loop {
            if connection_rx.borrow().status == status {
                return;
            }
            connection_rx.changed().await.unwrap();
        }
    }

    #[tokio::test]
    async fn prepare_disconnect_waits_for_writes() {
        let agent = test_agent();
        set_connected(&agent, 7).await;
        agent.writes.fetch_add(1, Ordering::AcqRel);
        let write_guard = ActivityGuard {
            count: agent.writes.clone(),
            notify: agent.activity_notify.clone(),
        };

        let prepare_task = {
            let agent = agent.clone();
            tokio::spawn(async move { agent.prepare_disconnect().await })
        };
        wait_for_status(&agent, ConnectionStatus::PlannedDisconnect).await;
        assert!(!prepare_task.is_finished());

        drop(write_guard);
        let token = prepare_task.await.unwrap().unwrap();
        assert_eq!(token.generation(), 7);
    }

    #[tokio::test]
    async fn planned_disconnect_waits_for_reconnectable_calls() {
        let agent = test_agent();
        set_connected(&agent, 11).await;
        let token = agent.prepare_disconnect().await.unwrap();
        agent.reconnectable_calls.fetch_add(1, Ordering::AcqRel);
        let call_guard = ActivityGuard {
            count: agent.reconnectable_calls.clone(),
            notify: agent.activity_notify.clone(),
        };

        let disconnect_task = {
            let agent = agent.clone();
            tokio::spawn(async move { agent.disconnect().await })
        };
        wait_for_status(&agent, ConnectionStatus::Disconnected).await;
        assert!(!disconnect_task.is_finished());

        drop(call_guard);
        disconnect_task.await.unwrap().unwrap();
        assert_eq!(token.generation(), 11);
    }

    #[tokio::test]
    async fn stale_reconnect_token_is_rejected_before_dialing() {
        let agent = test_agent();
        agent
            .set_connection(ConnectionState {
                generation: 5,
                status: ConnectionStatus::Disconnected,
            })
            .await;

        let error = agent
            .reconnect("unused", AgentDisconnectToken { generation: 4 })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("stale agent reconnect token"));
        assert_eq!(
            agent.inner.read().await.connection,
            ConnectionState {
                generation: 5,
                status: ConnectionStatus::Disconnected,
            }
        );
    }

    #[tokio::test]
    async fn unplanned_disconnect_is_permanent() {
        let agent = test_agent();
        set_connected(&agent, 3).await;

        agent.disconnect().await.unwrap();

        assert_eq!(
            agent.inner.read().await.connection,
            ConnectionState {
                generation: 3,
                status: ConnectionStatus::PermanentlyClosed,
            }
        );
    }

    #[tokio::test]
    async fn close_client_cancels_requests_held_by_cloned_clients() {
        let agent = test_agent();
        let (client_socket, peer_socket) = std::os::unix::net::UnixStream::pair().unwrap();
        peer_socket.set_nonblocking(true).unwrap();
        let client_fd = client_socket.into_raw_fd();
        let client = Client::new(client_fd);
        {
            let mut inner = agent.inner.write().await;
            inner.client = Some(client.clone());
            inner.client_fd = client_fd;
        }

        let request_task =
            tokio::spawn(async move { client.request(ttrpc::proto::Request::new()).await });
        let peer_socket = tokio::net::UnixStream::from_std(peer_socket).unwrap();
        peer_socket.readable().await.unwrap();
        let mut request = [0_u8; 1024];
        assert!(peer_socket.try_read(&mut request).unwrap() > 0);

        agent.close_client().await.unwrap();

        let request_result = tokio::time::timeout(Duration::from_secs(1), request_task)
            .await
            .expect("in-flight request was not canceled")
            .unwrap();
        assert!(request_result.is_err());
        let inner = agent.inner.read().await;
        assert!(inner.client.is_none());
        assert_eq!(inner.client_fd, -1);
    }
}
