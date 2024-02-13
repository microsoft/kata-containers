// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use nix::sys::stat;
use protobuf::MessageDyn;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slog::Drain;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};

use crate::rpc::ttrpc_error;
use crate::AGENT_POLICY;

static EMPTY_JSON_INPUT: &str = "{\"input\":{}}";

static OPA_DATA_PATH: &str = "/data";
static OPA_POLICIES_PATH: &str = "/policies";

static POLICY_LOG_FILE: &str = "/tmp/policy.txt";

/// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

async fn allow_request(policy: &mut AgentPolicy, ep: &str, request: &str) -> ttrpc::Result<()> {
    if !policy.allow_request(ep, request).await {
        warn!(sl!(), "{ep} is blocked by policy");
        Err(ttrpc_error(
            ttrpc::Code::PERMISSION_DENIED,
            format!("{ep} is blocked by policy"),
        ))
    } else {
        Ok(())
    }
}

pub async fn is_allowed(req: &(impl MessageDyn + serde::Serialize)) -> ttrpc::Result<()> {
    let request = serde_json::to_string(req).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, req.descriptor_dyn().name(), &request).await
}

/// PolicyCopyFileRequest is very similar to CopyFileRequest from src/libs/protocols, except:
/// - When creating a symbolic link, the symlink_src field is a string representation of the
///   data bytes vector from CopyFileRequest. It's easier to verify a string compared with
///   a bytes vector in OPA.
/// - When not creating a symbolic link, the data bytes field from CopyFileRequest is not
///   present in PolicyCopyFileRequest, because it might be large and probably unused by OPA.
#[derive(::serde::Serialize)]
struct PolicyCopyFileRequest {
    path: String,
    file_size: i64,
    file_mode: u32,
    dir_mode: u32,
    uid: i32,
    gid: i32,
    offset: i64,

    symlink_src: PathBuf,
}

pub async fn is_allowed_copy_file(req: &protocols::agent::CopyFileRequest) -> ttrpc::Result<()> {
    let sflag = stat::SFlag::from_bits_truncate(req.file_mode);
    let symlink_src = if sflag.contains(stat::SFlag::S_IFLNK) {
        // The symlink source path
        PathBuf::from(OsStr::from_bytes(&req.data))
    } else {
        // If this CopyFile request is not creating a symlink, remove the incoming data bytes,
        // to avoid sending large amounts of data to OPA, that is unlikely to be use this data anyway.
        PathBuf::new()
    };

    let policy_req = PolicyCopyFileRequest {
        path: req.path.clone(),
        file_size: req.file_size,
        file_mode: req.file_mode,
        dir_mode: req.dir_mode,
        uid: req.uid,
        gid: req.gid,
        offset: req.offset,

        symlink_src,
    };

    let request = serde_json::to_string(&policy_req).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, "CopyFileRequest", &request).await
}

pub async fn do_set_policy(req: &protocols::agent::SetPolicyRequest) -> ttrpc::Result<()> {
    let request = serde_json::to_string(req).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, "SetPolicyRequest", &request).await?;
    policy
        .set_policy(&req.policy)
        .await
        .map_err(|e| ttrpc_error(ttrpc::Code::INVALID_ARGUMENT, e))
}

/// Example of HTTP response from OPA: {"result":true}
#[derive(Debug, Serialize, Deserialize)]
struct AllowResponse {
    result: bool,
}

/// Singleton policy object.
#[derive(Debug, Default)]
pub struct AgentPolicy {
    /// When true policy errors are ignored, for debug purposes.
    allow_failures: bool,

    /// OPA path used to query if an Agent gRPC request should be allowed.
    /// The request name (e.g., CreateContainerRequest) must be added to
    /// this path.
    query_path: String,

    /// OPA path used to add or delete a rego format Policy.
    policy_path: String,

    /// Client used to connect a single time to the OPA service and reused
    /// for all the future communication with OPA.
    opa_client: Option<reqwest::Client>,

    /// "/tmp/policy.txt" log file for policy activity.
    log_file: Option<tokio::fs::File>,

    /// Shadow regorus engine
    engine: regorus::Engine,
}

impl AgentPolicy {
    /// Create AgentPolicy object.
    pub fn new() -> Self {
        Self {
            allow_failures: false,
            engine: regorus::Engine::new(),
            ..Default::default()
        }
    }

    /// Wait for OPA to start and connect to it.
    pub async fn initialize(
        &mut self,
        launch_opa: bool,
        opa_addr: &str,
        policy_name: &str,
        default_policy: &str,
    ) -> Result<()> {
        if sl!().is_enabled(slog::Level::Debug) {
            self.log_file = Some(
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(POLICY_LOG_FILE)
                    .await?,
            );
            debug!(sl!(), "policy: log file: {}", POLICY_LOG_FILE);
        }

        self.engine
            .add_policy(policy_name.to_string(), default_policy.to_string())?;

        if launch_opa {
            start_opa(opa_addr)?;
        }

        let opa_uri = format!("http://{opa_addr}/v1");
        self.query_path = format!("{opa_uri}{OPA_DATA_PATH}{policy_name}/");
        self.policy_path = format!("{opa_uri}{OPA_POLICIES_PATH}{policy_name}");
        let opa_client = reqwest::Client::builder().http1_only().build()?;
        let policy = tokio::fs::read_to_string(default_policy).await?;

        // This loop is necessary to get the opa_client connected to the
        // OPA service while that service is starting. Future requests to
        // OPA are expected to work without retrying, after connecting
        // successfully for the first time.
        for i in 0..50 {
            if i > 0 {
                sleep(Duration::from_millis(100)).await;
                debug!(sl!(), "policy initialize: PUT failed, retrying");
            }

            // Set-up the default policy.
            if opa_client
                .put(&self.policy_path)
                .body(policy.clone())
                .send()
                .await
                .is_ok()
            {
                self.opa_client = Some(opa_client);

                // Check if requests causing policy errors should actually
                // be allowed. That is an insecure configuration but is
                // useful for allowing insecure pods to start, then connect to
                // them and inspect Guest logs for the root cause of a failure.
                //
                // Note that post_query returns Ok(false) in case
                // AllowRequestsFailingPolicy was not defined in the policy.
                self.allow_failures = self
                    .post_query("AllowRequestsFailingPolicy", EMPTY_JSON_INPUT)
                    .await?;
                return Ok(());
            }
        }
        bail!("Failed to connect to OPA")
    }

    /// Ask OPA to check if an API call should be allowed or not.
    async fn allow_request(&mut self, ep: &str, request: &str) -> bool {
        let post_input = format!("{{\"input\":{request}}}");
        self.log_opa_input(ep, &post_input).await;

        match self.post_query(ep, &post_input).await {
            Err(e) => {
                debug!(
                    sl!(),
                    "policy: failed to query endpoint {}: {:?}. Returning false.", ep, e
                );
                false
            }
            Ok(allowed) => allowed,
        }
    }

    /// Replace the Policy in OPA.
    pub async fn set_policy(&mut self, policy: &str) -> Result<()> {
        check_policy_hash(policy)?;

        // Replace the engine instance.
        self.engine = regorus::Engine::new();
        self.engine
            .add_policy("agent_policy.rego".to_string(), policy.to_string())?;

        if let Some(opa_client) = &mut self.opa_client {
            // Delete the old rules.
            opa_client.delete(&self.policy_path).send().await?;

            // Put the new rules.
            opa_client
                .put(&self.policy_path)
                .body(policy.to_string())
                .send()
                .await?;

            // Check if requests causing policy errors should actually be allowed.
            // That is an insecure configuration but is useful for allowing insecure
            // pods to start, then connect to them and inspect Guest logs for the
            // root cause of a failure.
            //
            // Note that post_query returns Ok(false) in case
            // AllowRequestsFailingPolicy was not defined in the policy.
            self.allow_failures = self
                .post_query("AllowRequestsFailingPolicy", EMPTY_JSON_INPUT)
                .await?;

            Ok(())
        } else {
            bail!("Agent Policy is not initialized")
        }
    }

    // Post query to OPA.
    async fn post_query(&mut self, ep: &str, post_input: &str) -> Result<bool> {
        debug!(sl!(), "policy check: {ep}");

        self.engine.set_input_json(post_input)?;
        let regorus_result = self.engine.eval_bool_query(ep.to_string(), false)?;

        if let Some(opa_client) = &mut self.opa_client {
            let uri = format!("{}{ep}", &self.query_path);
            let response = opa_client
                .post(uri)
                .body(post_input.to_string())
                .send()
                .await?;

            if response.status() != http::StatusCode::OK {
                bail!("policy: POST {} response status {}", ep, response.status());
            }

            let http_response = response.text().await?;
            let opa_response: serde_json::Result<AllowResponse> =
                serde_json::from_str(&http_response);

            match opa_response {
                Ok(resp) => {
                    if !resp.result {
                        if self.allow_failures {
                            warn!(
                                sl!(),
                                "policy: POST {} response <{}>. Ignoring error!", ep, http_response
                            );
                            return Ok(true);
                        } else {
                            error!(sl!(), "policy: POST {} response <{}>", ep, http_response);
                        }
                    }
                    assert_eq!(resp.result, regorus_result);
                    Ok(resp.result)
                }
                Err(_) => {
                    if self.allow_failures {
                        warn!(
                            sl!(),
                            "policy: POST {} undefined response <{}>. Ignoring error!",
                            ep,
                            http_response
                        );
                        return Ok(true);
                    } else {
                        warn!(
                            sl!(),
                            "policy: POST {} undefined response <{}>.", ep, http_response
                        );
                    }
                    Ok(false)
                }
            }
        } else {
            bail!("Agent Policy is not initialized")
        }
    }

    async fn log_opa_input(&mut self, ep: &str, input: &str) {
        if let Some(log_file) = &mut self.log_file {
            match ep {
                "StatsContainerRequest" | "ReadStreamRequest" | "SetPolicyRequest" => {
                    // - StatsContainerRequest and ReadStreamRequest are called
                    //   relatively often, so we're not logging them, to avoid
                    //   growing this log file too much.
                    // - Confidential Containers Policy documents are relatively
                    //   large, so we're not logging them here, for SetPolicyRequest.
                    //   The Policy text can be obtained directly from the pod YAML.
                }
                _ => {
                    let log_entry = format!("[\"ep\":\"{ep}\",{input}],\n\n");

                    if let Err(e) = log_file.write_all(log_entry.as_bytes()).await {
                        warn!(sl!(), "policy: log_opa_input: write_all failed: {}", e);
                    } else if let Err(e) = log_file.flush().await {
                        warn!(sl!(), "policy: log_opa_input: flush failed: {}", e);
                    }
                }
            }
        }
    }
}

fn start_opa(opa_addr: &str) -> Result<()> {
    let bin_dirs = vec!["/bin", "/usr/bin", "/usr/local/bin"];
    for bin_dir in &bin_dirs {
        let opa_path = bin_dir.to_string() + "/opa";
        if std::fs::metadata(&opa_path).is_ok() {
            // args copied from kata-opa.service.in.
            std::process::Command::new(&opa_path)
                .arg("run")
                .arg("--server")
                .arg("--disable-telemetry")
                .arg("--addr")
                .arg(opa_addr)
                .arg("--log-level")
                .arg("info")
                .spawn()?;
            return Ok(());
        }
    }
    bail!("OPA binary not found in {:?}", &bin_dirs);
}

pub fn check_policy_hash(policy: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(policy.as_bytes());
    let digest = hasher.finalize();
    debug!(sl!(), "policy: calculated hash ({:?})", digest.as_slice());

    let mut firmware = sev::firmware::guest::Firmware::open()?;
    let report_data: [u8; 64] = [0; 64];
    let report = firmware.get_report(None, Some(report_data), Some(0))?;

    if report.host_data != digest.as_slice() {
        bail!(
            "Unexpected policy hash ({:?}), expected ({:?})",
            digest.as_slice(),
            report.host_data
        );
    }

    Ok(())
}
