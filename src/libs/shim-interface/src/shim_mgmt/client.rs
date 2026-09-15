#![allow(dead_code)]
// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

// Defines the general client functions used by other components acting like
// clients. To be specific, a client first connect to the socket, then send
// request to destined URL, and finally handle the request(or not)

use std::{
    path::Path,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{SNAPSHOT_DEADLINE_HEADER, SNAPSHOT_URL};

use crate::mgmt_socket_addr;
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, Method, Request, Response};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri};

/// Shim management client with timeout
pub struct MgmtClient {
    /// The socket *file path* on host file system
    sock_path: PathBuf,

    /// The http client connect to the long standing shim mgmt server
    client: Client<UnixConnector, Full<Bytes>>,

    /// Timeout value for each dial, usually 200ms will be enough
    /// For heavier workload, you may want longer timeout
    timeout: Option<Duration>,
}

impl MgmtClient {
    /// Construct a new client connecting to shim mgmt server
    pub fn new(sid: &str, timeout: Option<Duration>) -> Result<Self> {
        let unix_socket_path = mgmt_socket_addr(sid).context("Failed to get unix socket path")?;
        let s_addr = unix_socket_path
            .strip_prefix("unix:")
            .context("failed to strip prefix")?;
        let sock_path = Path::new("/").join(s_addr).as_path().to_owned();
        let client = Client::unix();
        Ok(Self {
            sock_path,
            client,
            timeout,
        })
    }

    /// The http GET method for client, return a raw response. Further handling should be done by caller.
    /// Parameter uri should be like "/agent-url" etc.
    pub async fn get(&self, uri: &str) -> Result<Response<Incoming>> {
        let url: hyper::Uri = Uri::new(&self.sock_path, uri).into();
        let req = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Full::new(Bytes::new()))?;
        self.send_request(req).await
    }

    /// The HTTP Post method for client
    pub async fn post(
        &self,
        uri: &str,
        content_type: &str,
        content: &str,
    ) -> Result<Response<Incoming>> {
        let url: hyper::Uri = Uri::new(&self.sock_path, uri).into();

        // build body from content
        let body = Full::new(Bytes::from(content.to_string()));
        let req = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header("content-type", content_type)
            .body(body)?;
        self.send_request(req).await
    }

    /// The http PUT method for client
    pub async fn put(&self, uri: &str, data: Vec<u8>) -> Result<Response<Incoming>> {
        let url: hyper::Uri = Uri::new(&self.sock_path, uri).into();
        let mut builder = Request::builder().method(Method::PUT).uri(url);
        if uri == SNAPSHOT_URL {
            if let Some(timeout) = self.timeout {
                let deadline = SystemTime::now()
                    .checked_add(timeout)
                    .context("snapshot deadline overflow")?
                    .duration_since(UNIX_EPOCH)?
                    .as_millis();
                builder = builder.header(SNAPSHOT_DEADLINE_HEADER, deadline.to_string());
            }
        }
        let req = builder.body(Full::new(Bytes::from(data)))?;
        self.send_request(req).await
    }

    async fn send_request(&self, req: Request<Full<Bytes>>) -> Result<Response<Incoming>> {
        let msg = format!("Request ({:?}) to uri {:?}", req.method(), req.uri());
        let resp = self.client.request(req);
        match self.timeout {
            Some(timeout) => match tokio::time::timeout(timeout, resp).await {
                Ok(result) => result.map_err(|e| anyhow!(e)),
                Err(_) => Err(anyhow!("{:?} timeout after {:?}", msg, self.timeout)),
            },
            // if client timeout is not set, request waits with no deadline
            None => resp.await.context(format!("{msg:?} failed")),
        }
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use hyper::{server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use tokio::{net::UnixListener, sync::oneshot};

    #[tokio::test]
    async fn snapshot_client_sends_deadline_before_local_timeout() {
        let temp_dir = tempfile::tempdir().unwrap();
        let sock_path = temp_dir.path().join("mgmt.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let (deadline_tx, deadline_rx) = oneshot::channel();
        let deadline_tx = std::sync::Arc::new(std::sync::Mutex::new(Some(deadline_tx)));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req: Request<Incoming>| {
                        let deadline = req
                            .headers()
                            .get(SNAPSHOT_DEADLINE_HEADER)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .parse::<u64>()
                            .unwrap();
                        deadline_tx
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(deadline)
                            .unwrap();
                        async move {
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                Bytes::from("/snapshot"),
                            )))
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let timeout = Duration::from_secs(1);
        let client = MgmtClient {
            sock_path,
            client: Client::unix(),
            timeout: Some(timeout),
        };
        let earliest = SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + timeout;
        let response = client
            .put(SNAPSHOT_URL, b"/snapshot".to_vec())
            .await
            .unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let latest = SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + timeout;
        let deadline = u128::from(deadline_rx.await.unwrap());
        assert!(deadline >= earliest.as_millis());
        assert!(deadline <= latest.as_millis());
        server.await.unwrap();
    }
}
