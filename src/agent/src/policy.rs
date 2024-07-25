// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use protobuf::MessageDyn;
use serde::{Deserialize, Serialize};
use slog::Drain;
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

async fn allow_request(
    policy: &mut AgentPolicy,
    ep: &str,
    req: &(impl MessageDyn + serde::Serialize),
) -> ttrpc::Result<()> {
    match policy.allow_request(ep, req).await {
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
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, req.descriptor_dyn().name(), req).await
}

pub async fn do_set_policy(req: &protocols::agent::SetPolicyRequest) -> ttrpc::Result<()> {
    let mut policy = AGENT_POLICY.lock().await;
    allow_request(&mut policy, "SetPolicyRequest", req).await?;
    policy
        .set_policy(&req.policy)
        .await
        .map_err(|e| ttrpc_error(ttrpc::Code::INVALID_ARGUMENT, e))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AgentPolicyState {
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_name: Option<String>,
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

    state: AgentPolicyState,
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
        self.allow_failures = match self
            .allow_request_string("AllowRequestsFailingPolicy", "{}")
            .await
        {
            Ok((allowed, _prints)) => allowed,
            Err(_) => false,
        };
        Ok(())
    }

    /// Ask regorus if an API call should be allowed or not.
    // async fn allow_request(&mut self, ep: &str, ep_input: &str) -> Result<(bool, String)> {
    async fn allow_request(
        &mut self,
        ep: &str,
        req: &(impl MessageDyn + serde::Serialize),
    ) -> Result<(bool, String)> {
        let mut root_value = serde_json::to_value(req).unwrap();
        root_value["policy_state"] = serde_json::to_value(&self.state).unwrap();
        let ep_input = serde_json::to_string(&root_value).unwrap();

        return self.allow_request_string(ep, &ep_input).await;
    }

    struct MetadataResponse {
        allowed: Boolean,
        metadata: Option<serde_json::Value>,
    }

    #[derive(serde::Deserialize)]
    struct Metadata {
        action: String,
        name: String,
        key: String,
        value: serde_json::Value,
    }

    fn process_metadata(metadata: Value) -> Result<(), Box<dyn std::error::Error>> {
        // Deserialize the metadata from a JSON value
        let metadata_map: std::collections::HashMap<String, Metadata> = serde_json::from_value(metadata)?;
        
        // Iterate over each metadataAction in the metadata map
        for (_, metadata_action) in metadata_map {
            // Check if the action is "add"
            match metadata_action.action.as_str() {
                "add" => {
                    // Create the JSON value with the action's key and name
                    let json_value = json!({
                        metadata_action.name: {
                            metadata_action.key: metadata_action.value
                        }
                    });
                    
                    // Add data to the engine using the JSON value
                    self.engine.add_data(regorus::Value::from_json_value(json_value)?)?;
                },
                _ => {
                    // Handle other actions or do nothing
                }
            }
        }
        
        Ok(())
    }

    async fn allow_request_string(&mut self, ep: &str, ep_input: &str) -> Result<(bool, String)> {
        debug!(sl!(), "policy check: {ep}");
        self.log_eval_input(ep, ep_input).await;

        let query = format!("data.agent_policy.{ep}");
        self.engine.set_input_json(ep_input)?;

        let results = self.engine.eval_query(query, false)?;
        if results.result.len() != 1 {
            bail!("policy check: unexpected eval_query results {:?}", results);
        }
        if results.result[0].expressions.len() != 1 {
            bail!(
                "policy check: unexpected eval_query result expressions {:?}",
                results
            );
        }
        let mut allow = match results.result[0].expressions[0].value {
            regorus::Value::Bool(b) => b,

            MetadataResponse { allowed, metadata } => {
                if allowed {
                    if let Some(metadata) = metadata {
                        // perform state changes based on metadata
                        process_metadata(metadata)?;
                    }
                }
                allowed
            }

            _ => bail!(
                "policy check: unexpected eval_query result type {:?}",
                results
            ),
        };

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
