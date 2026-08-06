// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use super::new_device;
use crate::confidential_data_hub;
use crate::confidential_data_hub::image::{is_sandbox, unpack_pause_image};
use crate::rpc::CONTAINER_BASE;
use crate::storage::{StorageContext, StorageHandler};
use anyhow::{anyhow, Result};
use kata_types::mount::KATA_VIRTUAL_VOLUME_IMAGE_GUEST_PULL;
use kata_types::mount::{ImagePullVolume, StorageDevice};
use protocols::agent::Storage;
use safe_path::scoped_join;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::instrument;

#[derive(Debug)]
pub struct ImagePullHandler {}

/// The `source` the runtime gives the sandbox (pause) container's guest-pull storage.
/// `get_image_reference` in `runtime-rs/crates/resource/src/rootfs/virtual_volume.rs`
/// returns this literal for `ContainerType::PodSandbox`, because the pause image ships
/// inside the measured guest rootfs and is never pulled from a registry.
const PAUSE_IMAGE_SOURCE: &str = "pause";

impl ImagePullHandler {
    fn get_image_info(storage: &Storage) -> Result<ImagePullVolume> {
        for option in storage.driver_options.iter() {
            if let Some((key, value)) = option.split_once('=') {
                if key == KATA_VIRTUAL_VOLUME_IMAGE_GUEST_PULL {
                    let imagepull_volume: ImagePullVolume = serde_json::from_str(value)?;
                    return Ok(imagepull_volume);
                }
            }
        }
        Err(anyhow!("missing Image information for ImagePull volume"))
    }
}

/// Decide whether this guest-pull storage belongs to the sandbox (pause) container,
/// requiring the two host-supplied copies of that fact to agree.
///
/// `is_sandbox` reads `storage.driver_options`, which the policy does not examine for
/// this driver. `storage.source()` is policy-bound: rules.rego requires a guest-pull
/// source to equal the image reference this container's declaration names, and admits
/// the `pause` sentinel only for a declaration typed `sandbox` that names no image.
/// Requiring agreement therefore promotes the unchecked copy to a policy-checked fact
/// without needing the OCI spec, which `StorageContext` does not carry. Disagreement
/// means the host set one copy and not the other, which no honest runtime does.
fn agreed_is_sandbox(metadata: &HashMap<String, String>, image_name: &str) -> Result<bool> {
    let claims_sandbox = is_sandbox(metadata);
    let is_pause_source = image_name == PAUSE_IMAGE_SOURCE;
    if claims_sandbox != is_pause_source {
        return Err(anyhow!(
            "RM-32: guest-pull sandbox flag disagrees with the policy-bound image \
             reference (driver_options says sandbox={}, source={:?})",
            claims_sandbox,
            image_name
        ));
    }
    Ok(claims_sandbox)
}

#[async_trait::async_trait]
impl StorageHandler for ImagePullHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[KATA_VIRTUAL_VOLUME_IMAGE_GUEST_PULL]
    }

    #[instrument]
    async fn create_device(
        &self,
        storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        //Currently the image metadata is not used to pulling image in the guest.
        let image_pull_volume = Self::get_image_info(&storage)?;
        debug!(ctx.logger, "image_pull_volume = {:?}", image_pull_volume);
        let image_name = storage.source();
        debug!(ctx.logger, "image_name = {:?}", image_name);

        let cid = ctx
            .cid
            .clone()
            .ok_or_else(|| anyhow!("failed to get container id"))?;

        info!(
            ctx.logger,
            "image metadata: {:?}", image_pull_volume.metadata
        );

        // RM-32: `is_sandbox` answers "is this the pause container?" from
        // `storage.driver_options`, which the policy does not examine for this driver,
        // and it answered it *before* the BL-3 gate below -- so the pause branch skipped
        // the image allowlist entirely. The same question is answered a second time,
        // from the policy-checked OCI annotations, in
        // `confidential_data_hub::image::get_process`. Two host-supplied copies of one
        // fact, only one of them checked.
        //
        // `storage.source()` is now policy-bound: rules.rego requires a guest-pull
        // source to equal the image reference this container's declaration names, and
        // admits the "pause" sentinel only for a declaration that is typed "sandbox" and
        // names no image. Requiring the two answers to agree therefore makes the pause
        // decision a policy-checked fact without needing the OCI spec here, which
        // `StorageContext` does not carry. Disagreement means the host set one copy and
        // not the other, which no honest runtime does.
        let claims_sandbox = agreed_is_sandbox(&image_pull_volume.metadata, image_name)?;

        if claims_sandbox {
            let mount_path = unpack_pause_image(&cid)?;
            return new_device(mount_path);
        }

        // generated bundles with rootfs and config.json will store under CONTAINER_BASE/cid/images.
        let bundle_path = scoped_join(CONTAINER_BASE, &cid)?;

        // BL-3: authorize the guest-pull image against the measured allowlist BEFORE pulling.
        // The registry/CDH verify content↔digest when pulling by digest; this gate proves the
        // manifest digest is one the tenant approved, so a host cannot substitute a different
        // (self-consistent) image. Fail-closed in strict builds; opt-in (no enforcement) when
        // no allowlist is configured.
        #[cfg(feature = "strict-policy")]
        {
            let store = crate::VERIFIED_IMAGES.lock().await;
            store
                .verify(image_name)
                .map_err(|e| anyhow!("BL-3: guest-pull image not authorized: {}", e))?;
        }

        let bundle_path = match confidential_data_hub::pull_image(image_name, bundle_path).await {
            Ok(path) => {
                info!(
                    ctx.logger,
                    "pull and unpack image {image_name}, cid: {cid} succeeded."
                );
                path
            }
            Err(e) => {
                error!(
                    ctx.logger,
                    "pull and unpack image {image_name}, cid: {cid} failed with {:?}.",
                    e.to_string()
                );
                return Err(e);
            }
        };

        new_device(bundle_path)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use kata_types::mount::{ImagePullVolume, KATA_VIRTUAL_VOLUME_IMAGE_GUEST_PULL};
    use protocols::agent::Storage;

    use crate::storage::image_pull_handler::{agreed_is_sandbox, ImagePullHandler};

    #[test]
    fn test_get_image_info() {
        let mut res = HashMap::new();
        res.insert("key1".to_string(), "value1".to_string());
        res.insert("key2".to_string(), "value2".to_string());

        let image_pull = ImagePullVolume {
            metadata: res.clone(),
        };

        let image_pull_str = serde_json::to_string(&image_pull);
        assert!(image_pull_str.is_ok());

        let storage = Storage {
            driver: KATA_VIRTUAL_VOLUME_IMAGE_GUEST_PULL.to_string(),
            driver_options: vec![format!("image_guest_pull={}", image_pull_str.ok().unwrap())],
            ..Default::default()
        };

        match ImagePullHandler::get_image_info(&storage) {
            Ok(image_info) => {
                assert_eq!(image_info.metadata, res);
            }
            Err(e) => panic!("err = {}", e),
        }
    }

    // RM-32: the sandbox flag lives in driver_options, which the policy does not check
    // for this driver; the source is policy-bound. Requiring the two to agree is what
    // stops a host from routing an arbitrary image through the pause branch, which
    // returns before the guest-pull image allowlist gate.
    fn metadata(container_type: Option<&str>) -> HashMap<String, String> {
        let mut m = HashMap::new();
        if let Some(t) = container_type {
            m.insert("io.kubernetes.cri.container-type".to_string(), t.to_string());
        }
        m
    }

    #[test]
    fn test_agreed_is_sandbox_honest_pairings() {
        assert!(agreed_is_sandbox(&metadata(Some("sandbox")), "pause").unwrap());
        assert!(!agreed_is_sandbox(&metadata(Some("container")), "quay.io/x@sha256:ab").unwrap());
        assert!(!agreed_is_sandbox(&metadata(None), "quay.io/x@sha256:ab").unwrap());
    }

    #[test]
    fn test_agreed_is_sandbox_rejects_disagreement() {
        // The attack: claim sandbox in driver_options while naming a real image, so the
        // pause branch is taken and the allowlist gate is never reached.
        let err = agreed_is_sandbox(&metadata(Some("sandbox")), "quay.io/evil@sha256:ab")
            .expect_err("sandbox flag with a non-pause source must be rejected");
        assert!(err.to_string().contains("RM-32"), "err = {}", err);

        // The converse, for completeness: the pause sentinel without the sandbox flag.
        let err = agreed_is_sandbox(&metadata(Some("container")), "pause")
            .expect_err("pause source without the sandbox flag must be rejected");
        assert!(err.to_string().contains("RM-32"), "err = {}", err);
    }
}
