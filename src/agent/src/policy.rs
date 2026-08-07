// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use protobuf::MessageDyn;

use crate::rpc::ttrpc_error;
use crate::AGENT_POLICY;
use kata_agent_policy::policy::AgentPolicy;

async fn allow_request(policy: &mut AgentPolicy, ep: &str, request: &str) -> ttrpc::Result<()> {
    match policy.allow_request(ep, request).await {
        Ok((allowed, explanation)) => {
            if allowed {
                Ok(())
            } else {
                // `explanation` already names the endpoint and the checks that failed, so
                // this does not prefix it further: every byte spent here is a byte of the
                // reason that containerd truncates away.
                Err(ttrpc_error(ttrpc::Code::PERMISSION_DENIED, explanation))
            }
        }
        Err(e) => Err(ttrpc_error(
            ttrpc::Code::INTERNAL,
            format!("{ep}: internal error {e}"),
        )),
    }
}

pub async fn is_allowed(req: &(impl MessageDyn + serde::Serialize)) -> ttrpc::Result<()> {
    is_allowed_with_entrypoint(req.descriptor_dyn().name(), &req).await
}

pub async fn is_allowed_with_entrypoint(
    ep: &str,
    req: &impl serde::Serialize,
) -> ttrpc::Result<()> {
    let request = serde_json::to_string(req).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, ep, &request).await
}

/// Handle the `SetPolicy` RPC. Compiled out in strict builds, where policy is delivered
/// exclusively through initdata and there is no host-facing policy mutation channel.
#[cfg(not(feature = "strict-policy"))]
pub async fn do_set_policy(req: &protocols::agent::SetPolicyRequest) -> ttrpc::Result<()> {
    let request = serde_json::to_string(req).unwrap();
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, "SetPolicyRequest", &request).await?;
    policy
        .set_policy(&req.policy)
        .await
        .map_err(|e| ttrpc_error(ttrpc::Code::INVALID_ARGUMENT, e))
}
