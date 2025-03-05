
use std::{path::PathBuf, process::{Command, Stdio}, io::Write};

use anyhow::{Context, Error};
use base64::{engine::general_purpose, Engine};
use futures::future;
use oci_distribution::manifest::OciImageManifest;
use serde::{Deserialize, Serialize};

use crate::{registry, utils};

const ROOT_HASH_LABEL: &str = "io.katacontainers.dm-verity.root-hash";
const ROOT_HASH_SIG_LABEL: &str = "io.katacontainers.dm-verity.root-hash-sig";

/// Aggregates per-image layer information. While the image name is not strictly
/// necessary, it is convenient for human inspection of the manifest.
#[derive(Serialize, Deserialize)]
pub(super) struct ImageInfo {
    name: String,
    layers: Vec<LayerInfo>,
}

/// Per-layer information, including the layer digest, the dm-verity root hash, and
/// the signature of the root hash. The signature is a base64-encoded
/// DER-encoded signature of the root hash. The digest is the sha256 digest of
/// the layer, which is used by the snapshotter to identify the layer. While the
/// root hash is not strictly necessary, it is convenient for more friendly
/// error messages in case of any mismatch.
#[derive(Serialize, Deserialize)]
struct LayerInfo {
    digest: String,
    root_hash: String,
    signature: String,
}

/// Get the root hashes and their signatures for all the layers of images specified in the configuration.
pub(super) async fn get_root_hash_signatures(
    config: &utils::Config,
    image_tags: &Vec<String>,
) -> Result<Vec<ImageInfo>, Error> {
    let images = future::try_join_all(
        image_tags
            .iter()
            .map(|image| get_container_image_root_hashes(&image, config)),
    )
    .await
    .context("Failed to gather signatures for requested images")?;

    Ok(images)
}

/// Get the root hashes and their signatures for all the layers of images specified in the configuration.
pub(super) async fn get_manifest_with_root_hash_signatures(
    config: &utils::Config,
    image_tags: &Vec<String>,
) -> Result<Vec<OciImageManifest>, Error> {
    let manifests = future::try_join_all(
        image_tags
            .iter()
            .map(|image| get_container_image_manifest_with_root_hashes(&image, config)),
    )
    .await
    .context("Failed to gather signatures for requested images")?;

    Ok(manifests)
}

/// Get the root hashes and their signatures for all the layers of a container image.
async fn get_container_image_manifest_with_root_hashes(
    image: &str,
    config: &utils::Config,
) -> Result<OciImageManifest, Error> {
    let container = registry::get_container(&config, image)
        .await
        .context("Failed to get container image")?;
    let hash_signatures = get_container_image_root_hashes(image, config)
        .await
        .context("Failed to get hashes")?;

    let annotated_layers = container
        .manifest
        .layers
        .iter()
        .map(|layer| {
            let mut layer = layer.clone();
            let layer_info = hash_signatures
                .layers
                .iter()
                .find(|layer_info| layer_info.digest == layer.digest)
                .expect("Layer info not found");
            let mut annotations = layer.annotations.unwrap_or_default();
            annotations.insert(
                ROOT_HASH_SIG_LABEL.to_string(),
                layer_info.signature.clone(),
            );
            annotations.insert(
                ROOT_HASH_LABEL.to_string(),
                layer_info.root_hash.clone(),
            );
            layer.annotations = Some(annotations);
            layer
        })
        .collect::<Vec<_>>();
    let mut manifest = container.manifest.clone();
    manifest.layers = annotated_layers;
    Ok(manifest)
}

/// Get the root hashes and their signatures for all the layers of a container image.
async fn get_container_image_root_hashes(
    image: &str,
    config: &utils::Config,
) -> Result<ImageInfo, Error> {
    let container = registry::get_container(&config, image)
        .await
        .context("Failed to get container image")?;
    let layers = container.get_image_layers();
    let hash_signatures = layers
        .iter()
        .map(|layer| {
            let digest = layer.digest.clone();
            let root_hash = layer.verity_hash.clone();
            let signature = sign_hash(&root_hash, &config.key, &config.passphrase, &config.signer)
                .context("Failed to sign hash")?;
            Ok(LayerInfo {
                digest,
                root_hash,
                signature,
            })
        })
        .collect::<Result<Vec<_>, Error>>()
        .context("Failed to collect hash signatures")?;

    Ok(ImageInfo {
        name: image.to_string(),
        layers: hash_signatures,
    })
}

/// Sign a hash using openssl.
fn sign_hash(
    hash: &String,
    key: &PathBuf,
    password: &String,
    signer: &PathBuf,
) -> Result<String, Error> {
    let openssl = Command::new("openssl")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("smime")
        .arg("-sign")
        .arg("-nocerts")
        .arg("-noattr")
        .arg("-binary")
        .arg("-inkey")
        .arg(key)
        .arg("-passin")
        .arg(password)
        .arg("-signer")
        .arg(signer)
        .arg("-outform")
        .arg("der")
        .spawn()
        .context("Failed to spawn openssl")?;

    write!(
        openssl
            .stdin
            .as_ref()
            .context("Failed to open openssl stdin")?,
        "{}",
        hash
    )
    .context("Failed to write hash to openssl stdin")?;
    let output = openssl
        .wait_with_output()
        .context("Failed to retrieve openssl output")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Openssl failed with exit code: {}",
            output.status
        ));
    }
    let base64_output = general_purpose::STANDARD.encode(&output.stdout);

    Ok(base64_output)
}