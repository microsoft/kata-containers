// Copyright (c) 2021 Alibaba Cloud
// Copyright (c) 2021, 2023 IBM Corporation
// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use protocols::image;
use tokio::sync::Mutex;
use ttrpc::{self, error::get_rpc_status as ttrpc_error};

use crate::rpc::{verify_cid, CONTAINER_BASE};
use crate::sandbox::Sandbox;
use crate::AGENT_CONFIG;
use crate::AGENT_POLICY;

use image_rs::image::ImageClient;
use std::io::Write;

const AA_PATH: &str = "/usr/local/bin/attestation-agent";
const AA_KEYPROVIDER_PORT: &str = "127.0.0.1:50000";
const AA_GETRESOURCE_PORT: &str = "127.0.0.1:50001";
const OCICRYPT_CONFIG_PATH: &str = "/tmp/ocicrypt_config.json";
// kata rootfs is readonly, use tmpfs before CC storage is implemented.
const KATA_CC_IMAGE_WORK_DIR: &str = "/run/image/";
const KATA_CC_PAUSE_BUNDLE: &str = "/pause_bundle";
const CONFIG_JSON: &str = "config.json";

// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

macro_rules! is_allowed_pull_image {
    ($req:ident) => {
        if !AGENT_POLICY
            .lock()
            .await
            .is_allowed_pull_image_endpoint("PullImageRequest", &$req)
            .await
        {
            return Err(anyhow!("Image {} is blocked by policy", $req.image));
        }
    }
}


pub struct ImageService {
    sandbox: Arc<Mutex<Sandbox>>,
    attestation_agent_started: AtomicBool,
    image_client: Arc<Mutex<ImageClient>>,
}

impl ImageService {
    pub fn new(sandbox: Arc<Mutex<Sandbox>>) -> Self {
        env::set_var("CC_IMAGE_WORK_DIR", KATA_CC_IMAGE_WORK_DIR);
        Self {
            sandbox,
            attestation_agent_started: AtomicBool::new(false),
            image_client: Arc::new(Mutex::new(ImageClient::default())),
        }
    }

    // pause image is packaged in rootfs for CC
    fn unpack_pause_image(cid: &str) -> Result<()> {
        let cc_pause_bundle = Path::new(KATA_CC_PAUSE_BUNDLE);
        if !cc_pause_bundle.exists() {
            return Err(anyhow!("Pause image not present in rootfs"));
        }

        info!(sl!(), "use guest pause image cid {:?}", cid);
        let pause_bundle = Path::new(CONTAINER_BASE).join(cid);
        let pause_rootfs = pause_bundle.join("rootfs");
        let pause_config = pause_bundle.join(CONFIG_JSON);
        let pause_binary = pause_rootfs.join("pause");
        fs::create_dir_all(&pause_rootfs)?;
        if !pause_config.exists() {
            fs::copy(
                cc_pause_bundle.join(CONFIG_JSON),
                pause_bundle.join(CONFIG_JSON),
            )?;
        }
        if !pause_binary.exists() {
            fs::copy(cc_pause_bundle.join("rootfs").join("pause"), pause_binary)?;
        }

        Ok(())
    }

    // If we fail to start the AA, ocicrypt won't be able to unwrap keys
    // and container decryption will fail.
    fn init_attestation_agent() -> Result<()> {
        let config_path = OCICRYPT_CONFIG_PATH;

        // The image will need to be encrypted using a keyprovider
        // that has the same name (at least according to the config).
        let ocicrypt_config = serde_json::json!({
            "key-providers": {
                "attestation-agent":{
                    "grpc":AA_KEYPROVIDER_PORT
                }
            }
        });

        let mut config_file = fs::File::create(config_path)?;
        config_file.write_all(ocicrypt_config.to_string().as_bytes())?;

        // The Attestation Agent will run for the duration of the guest.
        Command::new(AA_PATH)
            .arg("--keyprovider_sock")
            .arg(AA_KEYPROVIDER_PORT)
            .arg("--getresource_sock")
            .arg(AA_GETRESOURCE_PORT)
            .spawn()?;
        Ok(())
    }

    /// Determines the container id (cid) to use for a given request.
    ///
    /// If the request specifies a non-empty id, use it; otherwise derive it from the image path.
    /// In either case, verify that the chosen id is valid.
    fn cid_from_request(req: &image::PullImageRequest) -> Result<String> {
        let req_cid = req.get_container_id();
        let cid = if !req_cid.is_empty() {
            req_cid.to_string()
        } else if let Some(last) = req.get_image().rsplit('/').next() {
            // ':' not valid for container id
            last.replace(':', "_")
        } else {
            return Err(anyhow!("Invalid image name. {}", req.get_image()));
        };
        verify_cid(&cid)?;
        Ok(cid)
    }

    async fn pull_image(&self, req: &image::PullImageRequest) -> Result<String> {
        is_allowed_pull_image!(req);

        env::set_var("OCICRYPT_KEYPROVIDER_CONFIG", OCICRYPT_CONFIG_PATH);

        let https_proxy = &AGENT_CONFIG.read().await.https_proxy;
        if !https_proxy.is_empty() {
            env::set_var("HTTPS_PROXY", https_proxy);
        }

        let no_proxy = &AGENT_CONFIG.read().await.no_proxy;
        if !no_proxy.is_empty() {
            env::set_var("NO_PROXY", no_proxy);
        }

        let cid = Self::cid_from_request(req)?;
        let image = req.get_image();
        if cid.starts_with("pause") {
            Self::unpack_pause_image(&cid)?;

            let mut sandbox = self.sandbox.lock().await;
            sandbox.images.insert(String::from(image), cid);
            return Ok(image.to_owned());
        }

        let aa_kbc_params = &AGENT_CONFIG.read().await.aa_kbc_params;
        if !aa_kbc_params.is_empty() {
            match self.attestation_agent_started.compare_exchange_weak(
                false,
                true,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => Self::init_attestation_agent()?,
                Err(_) => info!(sl!(), "Attestation Agent already running"),
            }
        }
        // If the attestation-agent is being used, then enable the authenticated credentials support
        info!(
            sl!(),
            "image_client.config.auth set to: {}",
            !aa_kbc_params.is_empty()
        );
        self.image_client.lock().await.config.auth = !aa_kbc_params.is_empty();

        // Read enable signature verification from the agent config and set it in the image_client
        let enable_signature_verification =
            &AGENT_CONFIG.read().await.enable_signature_verification;
        info!(
            sl!(),
            "enable_signature_verification set to: {}", enable_signature_verification
        );
        self.image_client.lock().await.config.security_validate = *enable_signature_verification;

        let source_creds = (!req.get_source_creds().is_empty()).then(|| req.get_source_creds());

        let bundle_path = Path::new(CONTAINER_BASE).join(&cid);
        fs::create_dir_all(&bundle_path)?;

        let decrypt_config = format!("provider:attestation-agent:{}", aa_kbc_params);

        info!(sl!(), "pull image {:?}, bundle path {:?}", cid, bundle_path);
        // Image layers will store at KATA_CC_IMAGE_WORK_DIR, generated bundles
        // with rootfs and config.json will store under CONTAINER_BASE/cid.
        let res = self
            .image_client
            .lock()
            .await
            .pull_image(image, &bundle_path, &source_creds, &Some(&decrypt_config))
            .await;

        match res {
            Ok(image) => {
                info!(
                    sl!(),
                    "pull and unpack image {:?}, cid: {:?}, with image-rs succeed. ", image, cid
                );
            }
            Err(e) => {
                error!(
                    sl!(),
                    "pull and unpack image {:?}, cid: {:?}, with image-rs failed with {:?}. ",
                    image,
                    cid,
                    e.to_string()
                );
                return Err(e);
            }
        };

        let mut sandbox = self.sandbox.lock().await;
        sandbox.images.insert(String::from(image), cid);
        Ok(image.to_owned())
    }
}

#[async_trait]
impl protocols::image_ttrpc_async::Image for ImageService {
    async fn pull_image(
        &self,
        _ctx: &ttrpc::r#async::TtrpcContext,
        req: image::PullImageRequest,
    ) -> ttrpc::Result<image::PullImageResponse> {
        match self.pull_image(&req).await {
            Ok(r) => {
                let mut resp = image::PullImageResponse::new();
                resp.image_ref = r;
                return Ok(resp);
            }
            Err(e) => {
                return Err(ttrpc_error(ttrpc::Code::INTERNAL, e.to_string()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ImageService;
    use protocols::image;

    #[test]
    fn test_cid_from_request() {
        struct Case {
            cid: &'static str,
            image: &'static str,
            result: Option<&'static str>,
        }

        let cases = [
            Case {
                cid: "",
                image: "",
                result: None,
            },
            Case {
                cid: "..",
                image: "",
                result: None,
            },
            Case {
                cid: "",
                image: "..",
                result: None,
            },
            Case {
                cid: "",
                image: "abc/..",
                result: None,
            },
            Case {
                cid: "",
                image: "abc/",
                result: None,
            },
            Case {
                cid: "",
                image: "../abc",
                result: Some("abc"),
            },
            Case {
                cid: "",
                image: "../9abc",
                result: Some("9abc"),
            },
            Case {
                cid: "some-string.1_2",
                image: "",
                result: Some("some-string.1_2"),
            },
            Case {
                cid: "0some-string.1_2",
                image: "",
                result: Some("0some-string.1_2"),
            },
            Case {
                cid: "a:b",
                image: "",
                result: None,
            },
            Case {
                cid: "",
                image: "prefix/a:b",
                result: Some("a_b"),
            },
            Case {
                cid: "",
                image: "/a/b/c/d:e",
                result: Some("d_e"),
            },
        ];

        for case in &cases {
            let mut req = image::PullImageRequest::new();
            req.set_image(case.image.to_string());
            req.set_container_id(case.cid.to_string());
            let ret = ImageService::cid_from_request(&req);
            match (case.result, ret) {
                (Some(expected), Ok(actual)) => assert_eq!(expected, actual),
                (None, Err(_)) => (),
                (None, Ok(r)) => panic!("Expected an error, got {}", r),
                (Some(expected), Err(e)) => {
                    panic!("Expected {} but got an error ({})", expected, e)
                }
            }
        }
    }
}