// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};

static EMPTY_JSON_INPUT: &str = "{\"input\":{}}";

static OPA_V1_URI: &str = "http://localhost:8181/v1";
static OPA_DATA_PATH: &str = "/data";
static OPA_POLICIES_PATH: &str = "/policies";

static COCO_POLICY_NAME: &str = "/coco_policy";

// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

// Example of HTTP response from OPA: {"result":true}
#[derive(Debug, Serialize, Deserialize)]
struct AllowResponse {
    result: bool,
}

// OPA input data for CreateContainerRequest.
#[derive(Debug, Serialize, Deserialize)]
struct CreateContainerRequestInput {
    input: CreateContainerRequestData,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateContainerRequestData {
    oci: oci::Spec,
    storages: Vec<SerializedStorage>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SerializedStorage {
    driver: String,
    driver_options: Vec<String>,
    source: String,
    fstype: String,
    options: Vec<String>,
    mount_point: String,
    fs_group: SerializedFsGroup,
}

#[derive(Debug, Serialize, Deserialize)]
struct SerializedFsGroup {
    group_id: u32,
    group_change_policy: u32,
}

/// OPA input data for CreateSandboxRequest.
#[derive(Debug, Serialize, Deserialize)]
struct CreateSandboxRequestInput {
    input: CreateSandboxRequestData,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateSandboxRequestData {
    storages: Vec<SerializedStorage>,
}

/// OPA input data for ExecProcessRequest.
#[derive(Debug, Serialize)]
struct ExecProcessRequestInput {
    input: ExecProcessRequestData,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecProcessRequestData {
	// container_id: String,
	// exec_id: String,
	// user: oci::User,
	process: oci::Process,
}

/// OPA input data for PullImageRequest.
#[derive(Debug, Serialize, Deserialize)]
struct PullImageRequestInput {
    input: PullImageRequestData,
}

#[derive(Debug, Serialize, Deserialize)]
struct PullImageRequestData {
    image: String,
}

// Singleton policy object.
#[derive(Debug)]
pub struct AgentPolicy {
    allow_failures: bool,
    request_count: u64,

    // opa_data_uri: String,
    coco_policy_query_prefix: String,
    coco_policy_id_uri: String,

    opa_client: Client,
}

impl AgentPolicy {
    // Create AgentPolicy object.
    pub fn new() -> Result<Self> {
        Ok(AgentPolicy {
            allow_failures: false,
            request_count: 0,

            // opa_data_uri: OPA_V1_URI.to_string() + OPA_DATA_PATH,
            coco_policy_query_prefix: OPA_V1_URI.to_string()
                + OPA_DATA_PATH
                + COCO_POLICY_NAME
                + "/",
            coco_policy_id_uri: OPA_V1_URI.to_string() + OPA_POLICIES_PATH + COCO_POLICY_NAME,

            opa_client: Client::builder().http1_only().build()?,
        })
    }

    // Wait for OPA to start.
    pub async fn initialize(&mut self) -> Result<()> {
        for i in 0..50 {
            if i > 0 {
                sleep(Duration::from_millis(100)).await;
                println!("policy initialize: POST failed, retrying");
            }

            // Check in a loop if requests causing policy errors should
            // actually be allowed. That is an unsecure configuration but is
            // useful for allowing unsecure pods to start, then connect to
            // them and inspect OPA logs for the root cause of a failure.
            //
            // The loop is necessary to get the opa_client connected to the
            // OPA service. Future requests to OPA are expected to work
            // without retrying, once the OPA Service had a chance to start.
            if let Ok(allow_failures) = self
                .post_query("AllowRequestsFailingPolicy", EMPTY_JSON_INPUT)
                .await
            {
                self.allow_failures = allow_failures;
                return Ok(());
            }
        }
        Err(anyhow!("failed to connect to OPA"))
    }

    // Post query for endpoints that don't require OPA input data.
    pub async fn is_allowed_endpoint(&mut self, ep: &str) -> bool {
        self.post_query(ep, EMPTY_JSON_INPUT).await.unwrap_or(false)
    }

    // Post CreateContainerRequest input to OPA.
    pub async fn is_allowed_create_container(
        &mut self,
        ep: &str,
        req: &protocols::agent::CreateContainerRequest,
    ) -> bool {
        let grpc_spec = req.OCI.clone();
        if grpc_spec.is_none() {
            error!(sl!(), "no oci spec in the create container request!");
            return false;
        }

        let mut opa_input = CreateContainerRequestInput {
            input: CreateContainerRequestData {
                oci: rustjail::grpc_to_oci(&grpc_spec.unwrap()),
                storages: Vec::new(),
            },
        };

        Self::convert_storages(req.storages.to_vec(), &mut opa_input.input.storages);
        let post_input = serde_json::to_string(&opa_input).unwrap();

        // TODO: remove this log.
        Self::log_create_container_input(&post_input).await;

        self.post_query(ep, &post_input).await.unwrap_or(false)
    }

    // Post CreateSandboxRequest input to OPA.
    pub async fn is_allowed_create_sandbox(
        &mut self,
        ep: &str,
        req: &protocols::agent::CreateSandboxRequest,
    ) -> bool {
        let mut opa_input = CreateSandboxRequestInput {
            input: CreateSandboxRequestData {
                storages: Vec::new(),
            },
        };

        Self::convert_storages(req.storages.to_vec(), &mut opa_input.input.storages);
        let post_input = serde_json::to_string(&opa_input).unwrap();
        self.post_query(ep, &post_input).await.unwrap_or(false)
    }

    // Post ExecProcessRequest input to OPA.
    pub async fn is_allowed_exec_process(
        &mut self,
        ep: &str,
        req: &protocols::agent::ExecProcessRequest,
    ) -> bool {
        let grpc_process = req.process.clone();
        if grpc_process.is_none() {
            error!(sl!(), "failed to convert process for ExecProcess request!");
            return false;
        }

        let opa_input = ExecProcessRequestInput {
            input: ExecProcessRequestData {
                // TODO: should other fields of grpc_process be validated as well?
                process: rustjail::process_grpc_to_oci(&grpc_process.unwrap()),
            },
        };

        let post_input = serde_json::to_string(&opa_input).unwrap();
        self.post_query(ep, &post_input).await.unwrap_or(false)
    }

    // Post query with PullImageRequest input data to OPA.
    pub async fn is_allowed_pull_image_endpoint(
        &mut self,
        ep: &str,
        req: &protocols::image::PullImageRequest,
    ) -> bool {
        let opa_input = PullImageRequestInput {
            input: PullImageRequestData {
                image: req.image.to_string(),
            },
        };

        let post_input = serde_json::to_string(&opa_input).unwrap();
        self.post_query(ep, &post_input).await.unwrap_or(false)
    }

    // Replace the security policy in OPA.
    pub async fn set_policy(&mut self, policy: &str) -> Result<()> {
        // Delete the old rules.
        let mut uri = self.coco_policy_id_uri.clone();
        info!(sl!(), "set_policy: deleting rules, uri {}", uri);
        self.opa_client
            .delete(uri)
            .send()
            .await
            .map_err(|e| anyhow!(e))?;

        // Put the new rules.
        uri = self.coco_policy_id_uri.clone();
        info!(sl!(), "set_policy: rules uri {}", uri);
        self.opa_client
            .put(uri)
            .body(policy.to_string())
            .send()
            .await
            .map_err(|e| anyhow!(e))?;

        // Check if requests causing policy errors should actually be allowed.
        // That is an unsecure configuration but is useful for allowing unsecure
        // pods to start, then connect to them and inspect OPA logs for the root
        // cause of a failure.
        self.allow_failures = self
            .post_query("AllowRequestsFailingPolicy", EMPTY_JSON_INPUT)
            .await?;
        Ok(())
    }

    // Post query to OPA.
    async fn post_query(&mut self, ep: &str, post_input: &str) -> Result<bool> {
        if self.request_count == 0 {
            info!(
                sl!(),
                "policy: post_query: base uri {}", &self.coco_policy_query_prefix
            );
        }
        self.request_count += 1;
        info!(sl!(), "policy check: {}", ep);

        let uri = self.coco_policy_query_prefix.clone() + ep;
        let response = self
            .opa_client
            .post(uri)
            .body(post_input.to_owned())
            .send()
            .await
            .map_err(|e| anyhow!(e))?;

        if response.status() != http::StatusCode::OK {
            return Err(anyhow!(
                "policy: post_query: POST response status {}",
                response.status()
            ));
        }

        let http_response = response.text().await.unwrap();
        let opa_response: serde_json::Result<AllowResponse> = serde_json::from_str(&http_response);

        match opa_response {
            Ok(resp) => {
                if !resp.result {
                    if self.allow_failures {
                        warn!(
                            sl!(),
                            "policy: post_query: response <{}>. Ignoring error!", http_response
                        );
                        return Ok(true);
                    } else {
                        error!(sl!(), "policy: post_query: response <{}>", http_response);
                    }
                }
                Ok(resp.result)
            }
            Err(_) => {
                // Return a policy failure for undefined requests.
                warn!(
                    sl!(),
                    "policy: post_query: {} not found in policy. Returning false.", ep,
                );
                Ok(false)
            }
        }
    }

    fn convert_storages(
        grpc_storages: Vec<protocols::agent::Storage>,
        serialized_storages: &mut Vec<SerializedStorage>,
    ) {
        for grpc_storage in grpc_storages {
            let protocol_fsgroup = grpc_storage.fs_group();

            serialized_storages.push(SerializedStorage {
                driver: grpc_storage.driver.clone(),
                driver_options: grpc_storage.driver_options.to_vec(),
                source: grpc_storage.source.clone(),
                fstype: grpc_storage.fstype.clone(),
                options: grpc_storage.options.to_vec(),
                mount_point: grpc_storage.mount_point.clone(),
                fs_group: SerializedFsGroup {
                    group_id: protocol_fsgroup.group_id,
                    group_change_policy: protocol_fsgroup.group_change_policy.value() as u32,
                },
            });
        }
    }

    async fn log_create_container_input(ci: &str) {
        let log_entry = ci.to_string() + "\n\n";

        let mut f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/oci.json")
            .await
            .unwrap();
        f.write_all(log_entry.as_bytes()).await.unwrap();
        f.flush().await.unwrap();
    }
}
