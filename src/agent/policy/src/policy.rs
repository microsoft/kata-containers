// Copyright (c) 2023 Microsoft Corporation
// Copyright (c) 2024 Edgeless Systems GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Policy evaluation for the kata-agent.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use slog::{debug, error, warn};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

static POLICY_LOG_FILE: &str = "/tmp/policy.txt";

/// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

/// PolicyCopyFileRequest is very similar to CopyFileRequest from src/libs/protocols, except:
/// - When creating a symbolic link, the symlink_src field is a string representation of the
///   data bytes vector from CopyFileRequest. It's easier to verify a string compared with
///   a bytes vector in OPA.
/// - When not creating a symbolic link, the data bytes field from CopyFileRequest is not
///   present in PolicyCopyFileRequest, because it might be large and probably unused by OPA.
#[derive(::serde::Serialize, ::serde::Deserialize, Default)]
#[serde(default)]
pub struct PolicyCopyFileRequest {
    pub path: String,
    pub file_size: i64,
    pub file_mode: u32,
    pub dir_mode: u32,
    pub uid: i32,
    pub gid: i32,
    pub offset: i64,

    pub symlink_src: PathBuf,
}

/// PolicyCreateContainerRequest is very similar to CreateContainerRequest from src/libs/protocols, except:
/// - It wraps the base CreateContainerRequest.
/// - It has an env_map field which is a map of environment variable names to expanded values.
///   This makes it easier to validate the environment variables inside the rego rules.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PolicyCreateContainerRequest {
    pub base: protocols::agent::CreateContainerRequest,
    // a map of environment variable names to value
    pub env_map: std::collections::BTreeMap<String, String>,
}

/// Singleton policy object.
#[derive(Debug, Default)]
pub struct AgentPolicy {
    /// When true policy errors are ignored, for debug purposes.
    allow_failures: bool,

    /// "/tmp/policy.txt" log file for policy activity.
    log_file: Option<tokio::fs::File>,

    /// Regorus engine
    engine: regorus::Engine,
}

#[derive(serde::Deserialize, Debug)]
struct MetadataResponse {
    allowed: bool,
    ops: Option<json_patch::Patch>,
}

impl AgentPolicy {
    /// Create AgentPolicy object.
    pub fn new() -> Self {
        Self {
            allow_failures: false,
            engine: Self::new_engine(),
            ..Default::default()
        }
    }

    fn new_engine() -> regorus::Engine {
        let mut engine = regorus::Engine::new();
        engine.set_strict_builtin_errors(false);
        engine.set_gather_prints(true);
        // assign a slice of the engine data "pstate" to be used as policy state
        engine
            .add_data(
                regorus::Value::from_json_str(
                    r#"{
                        "pstate": {}
                    }"#,
                )
                .unwrap(),
            )
            .unwrap();
        engine
    }

    /// Initialize regorus.
    pub async fn initialize(
        &mut self,
        log_level: usize,
        default_policy_file: &str,
        log_file: Option<String>,
    ) -> Result<()> {
        // log file path
        let log_file_path = match log_file {
            Some(path) => path,
            None => POLICY_LOG_FILE.to_string(),
        };
        let log_file_path = log_file_path.as_str();

        if log_level >= slog::Level::Debug.as_usize() {
            self.log_file = Some(
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(log_file_path)
                    .await?,
            );
            debug!(sl!(), "policy: log file: {}", log_file_path);
        }

        self.engine.add_policy_from_file(default_policy_file)?;
        self.update_allow_failures_flag().await?;
        Ok(())
    }

    async fn apply_patch_to_state(&mut self, patch: json_patch::Patch) -> Result<()> {
        // Convert the current engine data to a JSON value
        let mut state = serde_json::to_value(self.engine.get_data())?;

        // Apply the patch to the state
        json_patch::patch(&mut state, &patch)?;

        // Clear the existing data in the engine
        self.engine.clear_data();

        // Add the patched state back to the engine
        self.engine
            .add_data(regorus::Value::from_json_str(&state.to_string())?)?;

        Ok(())
    }

    /// Ask regorus if an API call should be allowed or not.
    pub async fn allow_request(&mut self, ep: &str, ep_input: &str) -> Result<(bool, String)> {
        debug!(sl!(), "policy check: {ep}");
        self.log_request(ep, ep_input).await;

        let query = format!("data.agent_policy.{ep}");
        self.engine.set_input_json(ep_input)?;

        let results = self.engine.eval_query(query, false)?;

        let prints = match self.engine.take_prints() {
            Ok(p) => p.join(" "),
            Err(e) => format!("Failed to get policy log: {e}"),
        };

        if results.result.len() != 1 {
            // Results are empty when AllowRequestsFailingPolicy is used to allow a Request that hasn't been defined in the policy
            if self.allow_failures {
                return Ok((true, prints));
            }
            bail!(
                "policy check: unexpected eval_query result len {:?}",
                results
            );
        }

        if results.result[0].expressions.len() != 1 {
            bail!(
                "policy check: unexpected eval_query result expressions {:?}",
                results
            );
        }

        let mut allow = match &results.result[0].expressions[0].value {
            regorus::Value::Bool(b) => *b,

            // Match against a specific variant that could be interpreted as MetadataResponse
            regorus::Value::Object(obj) => {
                let json_str = serde_json::to_string(obj)?;

                self.log_request(ep, &json_str).await;

                let metadata_response: MetadataResponse = serde_json::from_str(&json_str)?;

                if metadata_response.allowed {
                    if let Some(ops) = metadata_response.ops {
                        self.apply_patch_to_state(ops).await?;
                    }
                }
                metadata_response.allowed
            }

            _ => {
                error!(sl!(), "allow_request: unexpected eval_query result type");
                bail!(
                    "policy check: unexpected eval_query result type {:?}",
                    results
                );
            }
        };

        if !allow {
            self.log_request(ep, &prints).await;
            if self.allow_failures {
                warn!(sl!(), "policy: ignoring error for {ep}");
                allow = true;
            }
        }

        Ok((allow, prints))
    }

    /// Replace the Policy in regorus.
    pub async fn set_policy(&mut self, policy: &str) -> Result<()> {
        check_policy_hash(policy)?;
        self.engine = Self::new_engine();
        self.engine
            .add_policy("agent_policy".to_string(), policy.to_string())?;
        self.update_allow_failures_flag().await?;
        Ok(())
    }

    async fn log_request(&mut self, ep: &str, input: &str) {
        if let Some(log_file) = &mut self.log_file {
            match ep {
                "StatsContainerRequest"
                | "ReadStreamRequest"
                | "SetPolicyRequest"
                | "AllowRequestsFailingPolicy" => {
                    // Logging these request types would create too much unnecessary output.
                }
                _ => {
                    let log_entry = format!("[\"ep\":\"{ep}\",{input}],\n\n");

                    if let Err(e) = log_file.write_all(log_entry.as_bytes()).await {
                        warn!(sl!(), "policy: log_request: write_all failed: {}", e);
                    } else if let Err(e) = log_file.flush().await {
                        warn!(sl!(), "policy: log_request: flush failed: {}", e);
                    }
                }
            }
        }
    }

    async fn update_allow_failures_flag(&mut self) -> Result<()> {
        self.allow_failures = match self.allow_request("AllowRequestsFailingPolicy", "{}").await {
            Ok((allowed, _prints)) => {
                if allowed {
                    warn!(
                        sl!(),
                        "policy: AllowRequestsFailingPolicy is enabled - will ignore errors"
                    );
                }
                allowed
            }
            Err(_) => false,
        };
        Ok(())
    }
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
