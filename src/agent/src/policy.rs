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

/// Test-only support for driving handlers through the real policy gate.
///
/// A handler's first statement is `is_allowed`, which reads the process-global
/// `AGENT_POLICY`. A freshly constructed `AgentPolicy` has an empty engine, so every
/// query returns no results and `allow_request` bails — meaning any test that wants to
/// reach the body of a handler has to put a policy in place first.
///
/// Two properties make that harder than a bare `set_policy` call, and both are the
/// reason this is a shared helper rather than something each test open-codes:
///
///  1. `AGENT_POLICY` is process-global and the test binary is a single process, so two
///     tests that install different policies will race. The lock below serializes them.
///  2. Under `strict-policy`, `AgentPolicy::set_policy` is one-shot: the second
///     activation is refused so a host cannot weaken policy at runtime. Assigning a
///     fresh `AgentPolicy` over the global clears that flag, which keeps the guarantee
///     intact for production (the check is untouched) while letting each test start from
///     a known state.
///
/// Hold the returned guard for as long as the installed policy must stay in effect.
#[cfg(test)]
pub(crate) mod test_support {
    use super::AgentPolicy;
    use crate::AGENT_POLICY;
    use lazy_static::lazy_static;
    use tokio::sync::{Mutex, MutexGuard};

    lazy_static! {
        static ref POLICY_TEST_LOCK: Mutex<()> = Mutex::new(());
    }

    /// Serializes policy-driven tests. Dropping it releases the next waiter; the policy
    /// itself is left in place, since the next holder replaces it wholesale.
    pub(crate) struct PolicyTestGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    /// Install `policy` as the active agent policy and block any other test that wants
    /// to do the same until the returned guard is dropped.
    pub(crate) async fn install_policy(policy: &str) -> PolicyTestGuard {
        let guard = POLICY_TEST_LOCK.lock().await;

        let mut active = AGENT_POLICY.lock().await;
        // Replace rather than mutate: this resets `policy_activated`, so the one-shot
        // activation lock does not make the *second* test to run fail closed.
        *active = AgentPolicy::new();
        active
            .set_policy(policy)
            .await
            .expect("test policy must load");

        PolicyTestGuard(guard)
    }
}
