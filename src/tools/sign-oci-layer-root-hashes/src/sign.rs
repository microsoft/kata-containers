use std::{
    collections::BTreeMap, io::Write,path::PathBuf, process::{Command, Stdio}
};

use anyhow::{Context, Error};
use base64::{engine::general_purpose, Engine};
use futures::future;
use oci_client::manifest::{OciDescriptor, OciImageManifest};
use oci_client::Reference;
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

const EMPTY_CONFIG_DIGEST: &str = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

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

/// Attach signatures to the image manifests as referrers without repushing the image manifests
pub(super) async fn attach_root_hash_signatures(
    config: &utils::Config,
    image_tags: &Vec<String>,
) -> Result<(), Error> {
    future::try_join_all(
        image_tags.iter().map(|image| attach_image_signatures(image, config))
    ).await?;
    Ok(())
}

/// This function will create a new signature manifest with the subject descriptor (which references the image manifest)
/// and a list of signature blobs for each layer in the image. Per layer signature blob contains
/// the layer digest, the dm-verity root hash of each layer in the image, and the root hash signature.
/// Theoretically signature blob should contain the info needed for verification and kernel checks both root hash and signature.
/// Now as much info as possible is included, could remove them in the future.
/// It will then push this signature manifest to the registry with a new reference that
/// has a ".erofs.sig-<serial number of the signer certificate>" suffix.
/// The serial number of the signer certificate appended to the tag can ensure uniqueness
/// and can be used by snapshotter to pick signatures for a specific signer.
async fn attach_image_signatures(
    image: &str,
    config: &utils::Config
) -> Result<(), Error> {
    let image_ref: Reference = image.to_string().parse().unwrap();

    // 1. Resolve the subject descriptor
    let container = registry::get_container(&config, image)
        .await
        .context("Failed to get container image")?;
    let subject_descriptor = get_subject_descriptor(&container)
        .context("Failed to get subject descriptor")?;

    // 2. Prepare the signature blobs to be attached
    let sig_descriptors = prepare_sig_descriptors(image, config, &container)
        .await
        .context("Failed to prepare signature descriptors")?;

    // 3. Create the signature manifest with the subject descriptor, empty config, artifact type, and annotations
    let mut annotations = BTreeMap::new();
    annotations.insert(IMAGE_NAME_LABEL.to_string(), image.to_string());
    annotations.insert(
        "org.opencontainers.image.created".to_string(),
        chrono::Utc::now().to_rfc3339(),
    );
    let empty_config_descriptor = get_empty_config_descriptor(image_ref.clone())
        .await
        .context("Failed to get empty config descriptor")?;
    let sig_manifest = oci_client::manifest::OciImageManifest {
        schema_version: 2,
        media_type: Some(oci_client::manifest::OCI_IMAGE_MEDIA_TYPE.to_string()),
        artifact_type: Some(SIGNATURE_ARTIFACT_TYPE.to_string()),
        config: empty_config_descriptor.clone(),
        layers: sig_descriptors.clone(),
        subject: Some(subject_descriptor.clone()),
        annotations: Some(annotations.clone()),
    };

    // 4. Push the signature manifest to a new reference (e.g., with a ".erofs.sig-<serial number>" suffix)
    let serial_number = get_serial_number_from_cert(&config.signer)?;
    let sig_ref = format!(
        "{}/{}:{}.erofs.sig-{}",
        image_ref.registry(),
        image_ref.repository(),
        image_ref.tag().unwrap(),
        serial_number
    );
    if let Err(e) = registry::Container::push_manifest(sig_ref.clone(), sig_manifest.clone()).await {
        eprintln!(
            "Failed to push signature manifest to {}: {}",
            sig_ref, e
        );
    }
    println!("Signature manifest pushed successfully to: {}", sig_ref);
    Ok(())
}

/// This function retrieves the subject descriptor for the signed image manifest.
fn get_subject_descriptor(
    container: &registry::Container,
) -> Result<OciDescriptor, Error> {
    // Calculate the digest of the manifest (sha256 of the canonical JSON bytes)
    let manifest_bytes = serde_json::to_vec(&container.manifest)
        .context("Failed to serialize manifest to bytes")?;
    let manifest_digest = format!("sha256:{:x}", Sha256::digest(&manifest_bytes));
    // Print the image manifest digest, raw bytes length
    println!("Subject Digest: {}", manifest_digest);
    println!("Raw bytes length: {}", manifest_bytes.len());

    Ok(OciDescriptor {
        digest: manifest_digest, // Digest of the image manifest to attach
        size: manifest_bytes.len() as i64, // Size in bytes
        media_type: container.manifest.media_type.clone().unwrap_or_else(|| oci_client::manifest::OCI_IMAGE_MEDIA_TYPE.to_string()), // the media type of the image manifest
        ..Default::default()
    })
}

/// This function retrieves the root hashes and signatures for each layer of the image,
/// serializes them to JSON, and pushes them as blobs to the registry.
/// It returns a vector of `OciDescriptor` objects representing the signature blobs.
/// Each descriptor contains the media type, digest, size, and annotations for the signature blob.
/// The annotations include the layer digest, root hash, signature, and a file name for the signature blob.
async fn prepare_sig_descriptors(
    image: &str,
    config: &utils::Config,
    container: &registry::Container,
) -> Result<Vec<OciDescriptor>, Error> {
    let image_info = get_container_image_root_hashes(image, config, &container).await?;
    let sig_descriptors: Vec<OciDescriptor> = future::try_join_all(
        image_info.layers.iter().map(|layer| {
            let image_ref: Reference = image.to_string().parse().unwrap();
            async move {
                let json_obj = serde_json::json!({
                    "layer_digest": layer.digest,
                    "root_hash": layer.root_hash,
                    "signature": layer.signature,
                });

                // Serialize the signature info to JSON in memory
                let blob_bytes = serde_json::to_vec_pretty(&json_obj)?;
                let blob_digest = format!("sha256:{:x}", Sha256::digest(&blob_bytes));
                println!("Blob size and Digest: {}, {}", blob_bytes.len(), blob_digest);

                let mut annotations = BTreeMap::new();
                annotations.insert(IMAGE_LAYER_DIGEST_LABEL.to_string(), layer.digest.clone());
                annotations.insert(IMAGE_LAYER_ROOT_HASH_LABEL.to_string(), layer.root_hash.clone());
                annotations.insert(IMAGE_LAYER_SIGNATURE_LABEL.to_string(), layer.signature.clone());
                annotations.insert(SIGNATURE_FILE_NAME.to_string(), format!("signature_for_layer_{}.json", layer.digest.trim_start_matches("sha256:")));

                // Push each signature blob to the repository
                registry::Container::push_blob(
                    image_ref.clone(),
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
    Ok(sig_descriptors)
}

/// This function creates an empty config descriptor for the signature manifest.
/// It pushes an empty JSON blob to the registry and returns the descriptor.
/// The empty config is required by the OCI spec for the manifest, even if it contains no configuration data.
/// refer to https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidance-for-an-empty-descriptor
async fn get_empty_config_descriptor(image_ref: Reference) -> Result<OciDescriptor, Error> {
    let empty_config_descriptor = OciDescriptor {
        media_type: "application/vnd.oci.empty.v1+json".to_string(),
        digest:EMPTY_CONFIG_DIGEST.to_string(),
        size: 2,
        annotations: None,
        urls: None,
    };
    // Ensure the empty config blob exists in the registry
    registry::Container::push_blob(
        image_ref.clone(),
        b"{}",
        EMPTY_CONFIG_DIGEST,
    ).await.context("Failed to push empty config blob")?;
    Ok(empty_config_descriptor)
}

/// This function retrieves the serial number from the signer certificate using openssl.
fn get_serial_number_from_cert(
    cert_path: &PathBuf,
) -> Result<String, Error> {
    let output = Command::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(cert_path)
        .arg("-noout")
        .arg("-serial")
        .output()
        .context("Failed to run openssl to get certificate serial number")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to get certificate serial number: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let serial_line = String::from_utf8_lossy(&output.stdout);
    // Output is like: "serial=0123456789ABCDEF\n"
    let serial_number = serial_line
        .trim()
        .strip_prefix("serial=")
        .unwrap_or(serial_line.trim())
        .to_string();
    println!("Signer certificate serial number: {}", serial_number);
    Ok(serial_number)
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
