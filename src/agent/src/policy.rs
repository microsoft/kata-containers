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
use tokio::fs::File;
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

pub async fn do_set_policy(req: &protocols::agent::SetPolicyRequest) -> ttrpc::Result<()> {
    let request = serde_json::to_string(req).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, "SetPolicyRequest", &request).await?;
    // If we have something like a network policy file, just dump in filesystem.
    if &req.policy.contains("NetworkPolicy") {
        warn!(sl!(), "EZT: Setpolicy contains network document");
        let mut file = File::create_new("/tmp/networkpolicy.txt").await?;
        file.write_all(&req.policy.as_bytes()).await?;
        // file copy logic
        return Ok(());
    }
    policy
        .set_policy(&req.policy)
        .await
        .map_err(|e| ttrpc_error(ttrpc::Code::INVALID_ARGUMENT, e))
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
        self.engine.set_input_json("{}")?;
        self.allow_failures = match self.allow_request("AllowRequestsFailingPolicy", "{}").await {
            Ok((allowed, _prints)) => allowed,
            Err(_) => false,
        };
        Ok(())
    }

    /// Ask regorus if an API call should be allowed or not.
    async fn allow_request(&mut self, ep: &str, ep_input: &str) -> Result<(bool, String)> {
        debug!(sl!(), "policy check: {ep}");
        self.log_eval_input(ep, ep_input).await;

        let query = format!("data.agent_policy.{ep}");
        self.engine.set_input_json(ep_input)?;

        let mut allow = self.engine.eval_bool_query(query, false)?;
        if !allow && self.allow_failures {
            allow = true;
        }

        let prints = match self.engine.take_prints() {
            Ok(p) => p.join(" "),
            Err(e) => format!("Failed to get policy log: {e}"),
        };

        Ok((allow, prints))
    }

    /// Replace the Policy in regorus.
    pub async fn set_policy(&mut self, policy: &str) -> Result<()> {
        check_policy_hash(policy)?;
        self.engine = Self::new_engine();
        self.engine
            .add_policy("agent_policy".to_string(), policy.to_string())?;
        Ok(())
    }

    async fn log_eval_input(&mut self, ep: &str, input: &str) {
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
                        warn!(sl!(), "policy: log_eval_input: write_all failed: {}", e);
                    } else if let Err(e) = log_file.flush().await {
                        warn!(sl!(), "policy: log_eval_input: flush failed: {}", e);
                    }
                }
            }
        }
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
