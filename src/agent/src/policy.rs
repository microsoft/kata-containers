// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use nix::sys::stat;
use protobuf::MessageDyn;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::rpc::ttrpc_error;
use crate::AGENT_POLICY;
use kata_agent_policy::policy::AgentPolicy;

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

/// PolicyCreateContainerRequest is very similar to CreateContainerRequest from src/libs/protocols, except:
/// - It wraps the base CreateContainerRequest.
/// - It has an env_map field which is a map of environment variable names to expanded values.
/// This makes it easier to validate the environment variables inside the rego rules.
#[derive(Debug, serde::Serialize)]
struct PolicyCreateContainerRequest {
    base: protocols::agent::CreateContainerRequest,
    // a map of environment variable names to value
    env_map: std::collections::BTreeMap<String, String>,
}

pub async fn is_allowed_create_container(
    req: &protocols::agent::CreateContainerRequest,
) -> ttrpc::Result<()> {
    let env_map = get_env_map(&req.OCI.Process.Env);

    let create_container_request = PolicyCreateContainerRequest {
        base: req.clone(),
        env_map,
    };

    let request = serde_json::to_string(&create_container_request).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, "CreateContainerRequest", &request).await
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

// todo: move to common crate shared with genpolicy
fn get_env_map(env: &[String]) -> std::collections::BTreeMap<String, String> {
    let env_map: std::collections::BTreeMap<String, String> = env
        .iter()
        .filter_map(|v| {
            // split by leftmost '='
            let split = v.split_once('=');
            if let Some((key, value)) = split {
                Some((key.to_string(), value.to_string()))
            } else {
                None
            }
        })
        .collect();
    env_map
}
