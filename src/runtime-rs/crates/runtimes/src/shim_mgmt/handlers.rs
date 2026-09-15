// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

// This defines the handlers corresponding to the url when a request is sent to destined url,
// the handler function should be invoked, and the corresponding data will be in the response

use crate::shim_metrics::get_shim_metrics;
use agent::ResizeVolumeRequest;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use common::{RuntimeInstance, Sandbox, SnapshotRequest};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use std::{
    future::Future,
    path::PathBuf,
    str,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

use shim_interface::shim_mgmt::{
    AGENT_POLICY_URL, AGENT_URL, DIRECT_VOLUME_PATH_KEY, DIRECT_VOLUME_RESIZE_URL,
    DIRECT_VOLUME_STATS_URL, IP6_TABLE_URL, IP_TABLE_URL, METRICS_URL, SNAPSHOT_DEADLINE_HEADER,
    SNAPSHOT_TIMEOUT, SNAPSHOT_URL,
};

struct CancelSnapshotOnDrop(SnapshotRequest);

impl Drop for CancelSnapshotOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn run_snapshot_task(
    request: SnapshotRequest,
    operation_lock: Arc<tokio::sync::RwLock<()>>,
    operation: impl Future<Output = Result<()>> + Send + 'static,
) -> Result<()> {
    let _cancel_on_drop = CancelSnapshotOnDrop(request.clone());
    tokio::spawn(async move {
        let _operation = tokio::select! {
            biased;
            _ = request.cancelled() => return Err(anyhow!("snapshot request cancelled while waiting for operation lock")),
            operation = operation_lock.write() => operation,
        };
        request.check_cancelled()?;
        let result = operation.await;
        if let Err(error) = &result {
            warn!(sl!(), "Snapshot transaction failed: {:#}", error);
        }
        result
    }).await.context("join portable snapshot task")?
}

fn snapshot_request(headers: &hyper::HeaderMap) -> Result<SnapshotRequest> {
    let timeout = match headers.get(SNAPSHOT_DEADLINE_HEADER) {
        Some(deadline) => {
            let millis = deadline
                .to_str()?
                .parse::<u64>()
                .context("invalid snapshot deadline")?;
            UNIX_EPOCH
                .checked_add(Duration::from_millis(millis))
                .context("snapshot deadline overflow")?
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO)
                .min(SNAPSHOT_TIMEOUT)
        }
        None => SNAPSHOT_TIMEOUT,
    };
    Ok(SnapshotRequest::new(timeout))
}

// main router for response, this works as a multiplexer on
// http arrival which invokes the corresponding handler function
pub(crate) async fn handler_mux(
    instance: Arc<RuntimeInstance>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    info!(
        sl!(),
        "mgmt-svr(mux): recv req, method: {}, uri: {}",
        req.method(),
        req.uri().path()
    );
    let sandbox = instance.sandbox.clone();
    match (req.method(), req.uri().path()) {
        (&Method::GET, AGENT_URL) => agent_url_handler(sandbox, req).await,
        (&Method::PUT, IP_TABLE_URL) | (&Method::GET, IP_TABLE_URL) => {
            ip_table_handler(sandbox, req).await
        }
        (&Method::PUT, IP6_TABLE_URL) | (&Method::GET, IP6_TABLE_URL) => {
            ipv6_table_handler(sandbox, req).await
        }
        (&Method::POST, DIRECT_VOLUME_STATS_URL) => direct_volume_stats_handler(sandbox, req).await,
        (&Method::POST, DIRECT_VOLUME_RESIZE_URL) => {
            direct_volume_resize_handler(sandbox, req).await
        }
        (&Method::GET, METRICS_URL) => metrics_url_handler(sandbox, req).await,
        (&Method::PUT, AGENT_POLICY_URL) => set_agent_policy_handler(sandbox, req).await,
        (&Method::PUT, SNAPSHOT_URL) => snapshot_handler(instance, req).await,
        (_, SNAPSHOT_URL) => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::new()))
            .map_err(Into::into),
        _ => Ok(not_found(req).await),
    }
}

async fn snapshot_handler(
    instance: Arc<RuntimeInstance>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    const MAX_SNAPSHOT_PATH_BYTES: usize = 4096;

    let request = snapshot_request(req.headers())?;
    let body = req.into_body().collect().await?.to_bytes();
    if body.is_empty() || body.len() > MAX_SNAPSHOT_PATH_BYTES {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("snapshot path is empty or too long")))
            .map_err(Into::into);
    }
    let destination = str::from_utf8(&body)
        .context("snapshot path is not valid UTF-8")?
        .trim();
    if destination.contains('\0') {
        return Err(anyhow!("snapshot path contains NUL"));
    }
    let destination = PathBuf::from(destination);
    let snapshot_destination = destination.clone();
    let snapshot_request = request.clone();
    let snapshot = run_snapshot_task(request, instance.operation_lock.clone(), async move {
        instance
            .sandbox
            .snapshot(
                instance.container_manager.clone(),
                &snapshot_destination,
                snapshot_request,
            )
            .await
            .context("create portable snapshot")
    });
    if let Err(error) = snapshot.await {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Full::new(Bytes::from(format!("{error:#}"))))
            .map_err(Into::into);
    }

    Ok(Response::new(Full::new(Bytes::from(
        destination.to_string_lossy().to_string(),
    ))))
}

// url not found
async fn not_found(_req: Request<Incoming>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("URL NOT FOUND")))
        .unwrap()
}

// returns the url for agent
async fn agent_url_handler(
    sandbox: Arc<dyn Sandbox>,
    _req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let agent_sock = sandbox
        .agent_sock()
        .await
        .unwrap_or_else(|_| String::from(""));
    Ok(Response::new(Full::new(Bytes::from(agent_sock))))
}

/// the ipv4 handler of iptable operation
async fn ip_table_handler(
    sandbox: Arc<dyn Sandbox>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    generic_ip_table_handler(sandbox, req, false).await
}

/// the ipv6 handler of iptable operation
async fn ipv6_table_handler(
    sandbox: Arc<dyn Sandbox>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    generic_ip_table_handler(sandbox, req, true).await
}

/// the generic iptable handler, for both ipv4 and ipv6
/// this requires iptables-series binaries to be inside guest rootfs
async fn generic_ip_table_handler(
    sandbox: Arc<dyn Sandbox>,
    req: Request<Incoming>,
    is_ipv6: bool,
) -> Result<Response<Full<Bytes>>> {
    info!(sl!(), "handler: iptable  ipv6?: {}", is_ipv6);
    match *req.method() {
        Method::GET => match sandbox.get_iptables(is_ipv6).await {
            Ok(data) => {
                let body = Full::new(Bytes::from(data));
                Response::builder().body(body).map_err(|e| anyhow!(e))
            }
            _ => Err(anyhow!("Failed to get iptable")),
        },

        Method::PUT => {
            let data = req.into_body().collect().await?.to_bytes();
            match sandbox.set_iptables(is_ipv6, data.to_vec()).await {
                Ok(resp_data) => Response::builder()
                    .body(Full::new(Bytes::from(resp_data)))
                    .map_err(|e| anyhow!(e)),
                _ => Err(anyhow!("Failed to set iptable")),
            }
        }

        _ => Err(anyhow!("IP Tables only takes PUT and GET")),
    }
}

async fn direct_volume_stats_handler(
    sandbox: Arc<dyn Sandbox>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let params = Url::parse(&req.uri().to_string())
        .map_err(|e| anyhow!(e))?
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<String, String>>();
    let volume_path = params
        .get(DIRECT_VOLUME_PATH_KEY)
        .context("shim-mgmt: volume path key not found in request params")?;
    let result = sandbox.direct_volume_stats(volume_path).await;
    match result {
        Ok(stats) => Ok(Response::new(Full::new(Bytes::from(stats)))),
        _ => Err(anyhow!("handler: Failed to get volume stats")),
    }
}

async fn direct_volume_resize_handler(
    sandbox: Arc<dyn Sandbox>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let body = req.into_body().collect().await?.to_bytes();

    // unserialize json body into resizeRequest struct
    let resize_req: ResizeVolumeRequest =
        serde_json::from_slice(&body).context("shim-mgmt: deserialize resizeRequest failed")?;
    let result = sandbox.direct_volume_resize(resize_req).await;

    match result {
        Ok(_) => Ok(Response::new(Full::new(Bytes::from("")))),
        _ => Err(anyhow!("handler: Failed to resize volume")),
    }
}

// returns the url for metrics
async fn metrics_url_handler(
    sandbox: Arc<dyn Sandbox>,
    _req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    // get metrics from agent, hypervisor, and shim
    let agent_metrics = sandbox.agent_metrics().await.unwrap_or_default();
    let hypervisor_metrics = sandbox.hypervisor_metrics().await.unwrap_or_default();
    let shim_metrics = get_shim_metrics().unwrap_or_default();

    Ok(Response::new(Full::new(Bytes::from(format!(
        "{agent_metrics}{hypervisor_metrics}{shim_metrics}"
    )))))
}

/// The set agent policy handler, for setting agent policy
async fn set_agent_policy_handler(
    sandbox: Arc<dyn Sandbox>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    match *req.method() {
        Method::PUT => {
            let data = req.into_body().collect().await?.to_bytes();
            let policy: &str = str::from_utf8(&data)?;
            sandbox
                .set_policy(policy)
                .await
                .context("set agent policy handler failed")?;
            Ok(Response::new(Full::new(Bytes::from(""))))
        }
        _ => Err(anyhow!("Set agent policy only takes PUT method")),
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use hyper::{server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::{
        io::AsyncWriteExt,
        sync::{oneshot, RwLock},
    };

    #[tokio::test]
    async fn dropped_request_keeps_recovery_running_and_prevents_publication() {
        let request = SnapshotRequest::new(Duration::from_secs(60));
        let worker_request = request.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let (finish_capture_tx, finish_capture_rx) = oneshot::channel();
        let (recovered_tx, recovered_rx) = oneshot::channel();
        let publication = Arc::new(AtomicBool::new(false));
        let worker_publication = publication.clone();
        let lock = Arc::new(RwLock::new(()));
        let waiter = tokio::spawn(run_snapshot_task(
            request.clone(),
            lock.clone(),
            async move {
                started_tx.send(()).unwrap();
                finish_capture_rx.await.unwrap();
                let captured = worker_request.check_cancelled();
                tokio::task::yield_now().await;
                recovered_tx.send(()).unwrap();
                captured?;
                worker_request.publish(|| {
                    worker_publication.store(true, Ordering::SeqCst);
                    Ok(())
                })
            },
        ));
        started_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(request.check_cancelled().is_err());
        assert!(lock.try_write().is_err());
        finish_capture_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), recovered_rx)
            .await
            .unwrap()
            .unwrap();
        let _operation = tokio::time::timeout(Duration::from_secs(5), lock.write())
            .await
            .unwrap();
        assert!(!publication.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancelled_request_waiting_for_lock_does_not_start_capture() {
        let request = SnapshotRequest::new(Duration::from_secs(60));
        let lock = Arc::new(RwLock::new(()));
        let _busy = lock.write().await;
        let waiter = tokio::spawn(run_snapshot_task(request.clone(), lock.clone(), async {
            panic!("cancelled snapshot started capture");
        }));
        request.cancel();
        let result = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dropped_request_during_recovery_does_not_interrupt_remaining_recovery() {
        let request = SnapshotRequest::new(Duration::from_secs(60));
        let worker_request = request.clone();
        let (vm_resumed_tx, vm_resumed_rx) = oneshot::channel();
        let (resume_containers_tx, resume_containers_rx) = oneshot::channel();
        let (completed_tx, completed_rx) = oneshot::channel();
        let waiter = tokio::spawn(run_snapshot_task(
            request.clone(),
            Arc::new(RwLock::new(())),
            async move {
                vm_resumed_tx.send(()).unwrap();
                resume_containers_rx.await.unwrap();
                let result = worker_request
                    .publish(|| -> Result<()> { panic!("published during cancellation") });
                completed_tx.send(result.is_err()).unwrap();
                result
            },
        ));
        vm_resumed_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        resume_containers_tx.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), completed_rx)
            .await
            .unwrap()
            .unwrap());
    }

    #[tokio::test]
    async fn deadline_expiry_during_capture_keeps_recovery_running() {
        let request = SnapshotRequest::new(Duration::from_millis(50));
        let worker_request = request.clone();
        let recovered = Arc::new(AtomicBool::new(false));
        let worker_recovered = recovered.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_snapshot_task(request, Arc::new(RwLock::new(())), async move {
                worker_request.cancelled().await;
                tokio::task::yield_now().await;
                worker_recovered.store(true, Ordering::SeqCst);
                worker_request.publish(|| -> Result<()> { panic!("published expired snapshot") })
            }),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(recovered.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn http_disconnect_cancels_snapshot_but_allows_recovery() {
        let request = SnapshotRequest::new(Duration::from_secs(60));
        let server_request = request.clone();
        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let started = Arc::new(tokio::sync::Notify::new());
        let server_started = started.clone();
        let recovered = Arc::new(tokio::sync::Notify::new());
        let server_recovered = recovered.clone();
        let published = Arc::new(AtomicBool::new(false));
        let server_published = published.clone();
        let connection = tokio::spawn(async move {
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(server),
                    service_fn(move |req: Request<Incoming>| {
                        let request = server_request.clone();
                        let worker_request = request.clone();
                        let started = server_started.clone();
                        let recovered = server_recovered.clone();
                        let published = server_published.clone();
                        async move {
                            req.into_body().collect().await?;
                            run_snapshot_task(request, Arc::new(RwLock::new(())), async move {
                                started.notify_one();
                                worker_request.cancelled().await;
                                tokio::task::yield_now().await;
                                recovered.notify_one();
                                worker_request.publish(|| {
                                    published.store(true, Ordering::SeqCst);
                                    Ok(())
                                })
                            })
                            .await?;
                            Ok::<_, anyhow::Error>(Response::new(Full::new(Bytes::new())))
                        }
                    }),
                )
                .await
        });
        client
            .write_all(
                b"PUT /snapshot HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\n/snapshot",
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .unwrap();
        drop(client);
        tokio::time::timeout(Duration::from_secs(5), request.cancelled())
            .await
            .expect("disconnect did not cancel snapshot");
        tokio::time::timeout(Duration::from_secs(5), recovered.notified())
            .await
            .expect("recovery was aborted");
        let _ = tokio::time::timeout(Duration::from_secs(5), connection)
            .await
            .unwrap()
            .unwrap();
        assert!(!published.load(Ordering::SeqCst));
    }

    #[test]
    fn client_deadline_is_honored_and_invalid_deadline_is_rejected() {
        let mut headers = hyper::HeaderMap::new();
        assert!(snapshot_request(&headers)
            .unwrap()
            .check_cancelled()
            .is_ok());
        headers.insert(SNAPSHOT_DEADLINE_HEADER, "0".parse().unwrap());
        assert!(snapshot_request(&headers)
            .unwrap()
            .check_cancelled()
            .is_err());
        headers.insert(SNAPSHOT_DEADLINE_HEADER, "invalid".parse().unwrap());
        assert!(snapshot_request(&headers).is_err());
    }
}
