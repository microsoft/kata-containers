use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    collections::BTreeMap,
};

use anyhow::{Context, Error};
use base64::{engine::general_purpose, Engine};
use futures::future;
use oci_client::manifest::{OciDescriptor, OciManifest, OciImageManifest};
use oci_client::client::{Client, linux_amd64_resolver, ClientConfig};
use oci_client::secrets::RegistryAuth;
use oci_client::{RegistryOperation, Reference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{registry, utils};

const ROOT_HASH_LABEL: &str = "io.katacontainers.dm-verity.root-hash";
const ROOT_HASH_SIG_LABEL: &str = "io.katacontainers.dm-verity.root-hash-sig";

const IMAGE_NAME_LABEL: &str = "image.ref.name";
const IMAGE_LAYER_DIGEST_LABEL: &str = "image.layer.digest";
const IMAGE_LAYER_ROOT_HASH_LABEL: &str = "image.layer.root_hash";
const IMAGE_LAYER_SIGNATURE_LABEL: &str = "image.layer.signature";
const SIGNATURE_ARTIFACT_TYPE: &str = "application/vnd.oci.mt.pkcs7";
const SIGNATURE_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.erofs.sig";
const SIGNATURE_FILE_NAME: &str = "signature.blob.name";

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

pub(super) async fn attach_signatures(
    image: &ImageInfo
) -> Result<(), Error> {
    let image_ref: Reference = image.name.to_string().parse().unwrap();
    let client = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_amd64_resolver)),
            ..Default::default()
        });
    // Authenticate with the registry (if needed)
    let auth: RegistryAuth = registry::build_auth(&image_ref);
    let op = RegistryOperation::Push;
    client.auth(&image_ref, &auth, op).await?;

    let accepted_media_types = &[
        oci_client::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
        oci_client::manifest::OCI_IMAGE_MEDIA_TYPE,
        oci_client::manifest::IMAGE_MANIFEST_LIST_MEDIA_TYPE,
        oci_client::manifest::IMAGE_MANIFEST_MEDIA_TYPE,
    ];
    // 1. Resolve the subject descriptor
    let (raw_bytes, subject_digest) = client
        .pull_manifest_raw(&image_ref, &auth, accepted_media_types)
        .await?;
    // Parse the raw_bytes into an OCI manifest
    let image_manifest: OciManifest = serde_json::from_slice(&raw_bytes)
        .context("Failed to parse raw bytes into OCI manifest")?;
    // Print the digest, raw bytes length, the manifest media type
    println!("Subject Digest: {}", subject_digest);
    println!("Raw bytes length: {}", raw_bytes.len());

    let subject_descriptor = OciDescriptor {
        digest: subject_digest, // Digest of the manifest to attach
        size: raw_bytes.len() as i64, // Size in bytes
        media_type: image_manifest.content_type().to_string(),
        ..Default::default()
    };

    // 2. Prepare the signature blobs to be attached
    let sig_descriptors: Vec<OciDescriptor> = future::try_join_all(
        image.layers.iter().map(|layer| {
            let client = &client;
            let image_ref = &image_ref;
            async move {
                let json_obj = serde_json::json!({
                    "layer_digest": layer.digest,
                    "root_hash": layer.root_hash,
                    "signature": layer.signature,
                });
                let file_name = format!("signature_for_layer_{}.json", layer.digest.trim_start_matches("sha256:"));
                fs::write(&file_name, serde_json::to_string_pretty(&json_obj)?)?;
                println!("Wrote signature info for layer {} to {}", layer.digest, file_name);
                let blob_bytes = fs::read(file_name.clone())?;
                let blob_digest = format!("sha256:{:x}", Sha256::digest(&blob_bytes));
                println!("Blob size and Digest: {}, {}", blob_bytes.len(), blob_digest);

                let mut annotations = BTreeMap::new();
                annotations.insert(IMAGE_LAYER_DIGEST_LABEL.to_string(), layer.digest.clone());
                annotations.insert(IMAGE_LAYER_ROOT_HASH_LABEL.to_string(), layer.root_hash.clone());
                annotations.insert(IMAGE_LAYER_SIGNATURE_LABEL.to_string(), layer.signature.clone());
                annotations.insert(SIGNATURE_FILE_NAME.to_string(), file_name.clone());

                // Push each signature blob to the repository
                client.push_blob(
                    image_ref,
                    &blob_bytes,
                    &blob_digest,
                ).await
                .context("Blob pushed failed")?;

                // Create the signature descriptor
                Ok::<OciDescriptor, Error>(OciDescriptor {
                    media_type: SIGNATURE_MEDIA_TYPE.to_string(),
                    digest: blob_digest,
                    size: blob_bytes.len() as i64,
                    annotations: Some(annotations),
                    urls: None,
                    ..Default::default()
                })
            }
        })
    ).await?
    .into_iter()
    .collect();
    // 3. Create the signature manifest with the subject descriptor, empty config, artifact type, and annotations
    let mut annotations = BTreeMap::new();
    annotations.insert(IMAGE_NAME_LABEL.to_string(), image.name.clone());
    annotations.insert(
        "org.opencontainers.image.created".to_string(),
        chrono::Utc::now().to_rfc3339(),
    );
    // Empty Descriptor for config, as per OCI spec, this is required for the manifest, refer to https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidance-for-an-empty-descriptor
    let empty_config_digest = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
    let config_descriptor = OciDescriptor {
        media_type: "application/vnd.oci.empty.v1+json".to_string(),
        digest:empty_config_digest.to_string(),
        size: 2,
        annotations: None,
        urls: None,
    };
    // Ensure the empty config blob exists in the registry
    client.push_blob(
        &image_ref,
        b"{}",
        empty_config_digest,
    ).await.context("Failed to push empty config blob")?;
    let sig_manifest = oci_client::manifest::OciImageManifest {
        schema_version: 2,
        media_type: Some(oci_client::manifest::OCI_IMAGE_MEDIA_TYPE.to_string()),
        artifact_type: Some(SIGNATURE_ARTIFACT_TYPE.to_string()),
        config: config_descriptor,
        layers: sig_descriptors.clone(),
        subject: Some(subject_descriptor.clone()),
        annotations: Some(annotations.clone()),
    };

    // 4. Push the signature manifest to a new reference (e.g., with a ".erofs.sig" suffix)
    let sig_ref: Reference = Reference::with_tag(
            image_ref.registry().to_string(),
            image_ref.repository().to_string(),
            format!("{}.erofs.sig", image_ref.tag().unwrap()),
        );
    if let Err(e) = client.push_manifest(&sig_ref, &OciManifest::Image(sig_manifest)).await {
        eprintln!(
            "Failed to push signature manifest to {}: {}",
            sig_ref, e
        );
    }
    println!("Signature manifest pushed successfully to: {}", sig_ref);
    Ok(())
}

async fn get_image_root_hashes(image: &str, config: &utils::Config) -> Result<ImageInfo, Error> {
    let container = registry::get_container(&config, image)
        .await
        .context("Failed to get container image")?;
    let hash_signatures = get_container_image_root_hashes(image, config, &container)
        .await
        .context("Failed to get hashes")?;

    Ok(hash_signatures)
}

/// Get the root hashes and their signatures for all the layers of images specified in the configuration.
pub(super) async fn get_root_hash_signatures(
    config: &utils::Config,
    image_tags: &Vec<String>,
) -> Result<Vec<ImageInfo>, Error> {
    let images = future::try_join_all({
        image_tags
            .iter()
            .map(|image| get_image_root_hashes(image, config))
    })
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
    let hash_signatures = get_container_image_root_hashes(image, config, &container)
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
            annotations.insert(ROOT_HASH_LABEL.to_string(), layer_info.root_hash.clone());
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
    container: &registry::Container,
) -> Result<ImageInfo, Error> {
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
