// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use nix::sys::stat;
use protobuf::MessageDyn;
use sha2::{Digest, Sha256};
use slog::Drain;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

use crate::rpc::ttrpc_error;
use crate::AGENT_POLICY;

static POLICY_LOG_FILE: &str = "/tmp/policy.txt";

/// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

async fn allow_request(policy: &mut AgentPolicy, ep: &str, request: &str) -> ttrpc::Result<()> {
    match policy.allow_request(ep, request).await {
        Ok((allowed, prints)) => {
            if allowed {
                Ok(())
            } else {
                Err(ttrpc_error(
                    ttrpc::Code::PERMISSION_DENIED,
                    format!("{ep} is blocked by policy: {prints}"),
                ))
            }
        }
        Err(e) => Err(ttrpc_error(
            ttrpc::Code::INTERNAL,
            format!("{ep}: internal error {e}"),
        )),
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

pub async fn is_allowed_create_container(
    req: &protocols::agent::CreateContainerRequest,
) -> ttrpc::Result<()> {
    let env_map = oci::get_env_map(&req.OCI.Process.Env);

    let create_container_request = PolicyCreateContainerRequest {
        base: req.clone(),
        env_map,
    };

    let request = serde_json::to_string(&create_container_request).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, "CreateContainerRequest", &request).await
}

// pub async fn is_allowed_create_container_test(
//     req: &protocols::agent::CreateContainerRequest,
//     mut policy: AgentPolicy,
// ) -> ttrpc::Result<()> {
//     let env_map = oci::get_env_map(&req.OCI.Process.Env);

//     let create_container_request = PolicyCreateContainerRequest {
//         base: req.clone(),
//         env_map,
//     };

//     let request = serde_json::to_string(&create_container_request).unwrap();
//     // let mut policy = AGENT_POLICY.lock().await;
//     allow_request(&mut policy, "CreateContainerRequest", &request).await
// }

pub async fn do_set_policy(req: &protocols::agent::SetPolicyRequest) -> ttrpc::Result<()> {
    let request = serde_json::to_string(req).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, "SetPolicyRequest", &request).await?;
    policy
        .set_policy(&req.policy)
        .await
        .map_err(|e| ttrpc_error(ttrpc::Code::INVALID_ARGUMENT, e))
}

/// PolicyCreateContainerRequest is very similar to CreateContainerRequest from src/libs/protocols, except:
/// - It wraps the base CreateContainerRequest.
/// - It has an env_map field which is a map of environment variable names to expanded values.
/// This makes it easier to validate the environment variables inside the rego rules.
#[derive(Debug, serde::Serialize)]
struct PolicyCreateContainerRequest {
    base: protocols::agent::CreateContainerRequest,
    // a map of environment variable names to value
    env_map: std::collections::HashMap<String, String>,
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

#[cfg(test)]
mod tests {
    use super::*; // Import the function and structs to be tested

    #[tokio::test]
    async fn test_allow_request() {
        let mut policy = AgentPolicy::new();

        let data =
            std::fs::read_to_string("../tools/genpolicy/create.json").expect("Unable to read file");

        let request: protocols::agent::CreateContainerRequest =
            serde_json::from_str(&data).expect("JSON was not well-formatted");

        let request = serde_json::to_string(&request).unwrap();
        let ep = "CreateContainerRequest";

        policy
            .engine
            .add_policy_from_file("../tools/genpolicy/exec2.rego")
            .unwrap();

        // Call the function
        let result = policy.allow_request(ep, &request).await;

        // Assert the expected result
        match result {
            Ok((allowed, _)) => assert!(allowed, "Expected the request to be allowed"),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }

        // assert!(false, "fail");
    }
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
    pub async fn initialize(&mut self, default_policy_file: &str) -> Result<()> {
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
    async fn allow_request(&mut self, ep: &str, ep_input: &str) -> Result<(bool, String)> {
        debug!(sl!(), "policy check: {ep}");

        self.log_request(ep, ep_input).await;

        let query = format!("data.agent_policy.{ep}");
        self.engine.set_input_json(ep_input)?;

        let results = self.engine.eval_query(query, false)?;

        let prints = match self.engine.take_prints() {
            Ok(p) => p.join("\n"),
            Err(e) => format!("Failed to get policy log: {e}"),
        };

        println!("Policy prints: {}", prints);

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
