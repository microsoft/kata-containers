// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow Docker image config field names.
#![allow(non_snake_case)]

use crate::verity;

use crate::utils::Config;
use anyhow::{anyhow, Context, Result};
use docker_credential::{CredentialRetrievalError, DockerCredential};
use fs2::FileExt;
use log::warn;
use log::{debug, info, LevelFilter};
use oci_distribution::client::{linux_amd64_resolver, ClientConfig};
use oci_distribution::manifest::{OciImageManifest, OciManifest};
use oci_distribution::RegistryOperation;
use oci_distribution::{manifest, secrets::RegistryAuth, Client, Reference};
use serde::{Deserialize, Serialize};
use sha2::{digest::typenum::Unsigned, digest::OutputSizeUser, Sha256};
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::{io, io::Seek, io::Write, path::Path, process::Command, fs::File};
use tokio::io::AsyncWriteExt;
use erofs_common::constants::EROFS_BLOCK_ALIGNMENT;
use erofs_common::constants::EROFS_METADATA_UUID;

/// Container image properties obtained from an OCI repository.
#[derive(Clone, Debug, Default)]
pub struct Container {
    pub manifest: OciImageManifest,
    pub image_layers: Vec<ImageLayer>,
}

/// Image config layer properties.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DockerConfigLayer {
    architecture: String,
    config: DockerImageConfig,
    pub rootfs: DockerRootfs,
}

/// Image config properties.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DockerImageConfig {
    User: Option<String>,
    Tty: Option<bool>,
    Env: Option<Vec<String>>,
    Cmd: Option<Vec<String>>,
    WorkingDir: Option<String>,
    Entrypoint: Option<Vec<String>>,
}

/// Container rootfs information.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DockerRootfs {
    r#type: String,
    pub diff_ids: Vec<String>,
}

/// This application's image layer properties.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageLayer {
    pub diff_id: String,
    pub digest: String,
    pub verity_hash: String,
}

impl Container {
    pub async fn push_manifest(image: String, manifest: OciImageManifest) -> Result<String> {
        let reference: Reference = image.parse()?;
        let auth = build_auth(&reference);

        let mut client = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_amd64_resolver)),
            ..Default::default()
        });

        let op = RegistryOperation::Push;
        client.auth(&reference, &auth, op).await?;

        client
            .push_manifest(&reference, &OciManifest::Image(manifest))
            .await
            .context("Failed to push manifest")
    }

    pub async fn new(use_cached_files: bool, image: &str) -> Result<Self> {
        info!("============================================");
        info!("Pulling manifest and config for {:?}", image);
        let reference: Reference = image.to_string().parse()?;
        let auth = build_auth(&reference);

        let mut client = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_amd64_resolver)),
            ..Default::default()
        });

        match client.pull_manifest_and_config(&reference, &auth).await {
            Ok((manifest, digest_hash, config_layer_str)) => {
                debug!("digest_hash: {:?}", digest_hash);
                debug!(
                    "manifest: {}",
                    serde_json::to_string_pretty(&manifest).unwrap()
                );

                // Log the contents of the config layer.
                if log::max_level() >= LevelFilter::Debug {
                    let mut deserializer = serde_json::Deserializer::from_str(&config_layer_str);
                    let mut serializer = serde_json::Serializer::pretty(io::stderr());
                    serde_transcode::transcode(&mut deserializer, &mut serializer).unwrap();
                }

                let config_layer: DockerConfigLayer =
                    serde_json::from_str(&config_layer_str).unwrap();
                let image_layers = get_image_layers(
                    use_cached_files,
                    &mut client,
                    &reference,
                    &manifest,
                    &config_layer,
                )
                .await
                .unwrap();

                Ok(Container {
                    manifest: manifest,
                    image_layers,
                })
            }
            Err(oci_distribution::errors::OciDistributionError::AuthenticationFailure(message)) => {
                panic!("Container image registry authentication failure ({}). Are docker credentials set-up for current user?", &message);
            }
            Err(e) => {
                panic!(
                    "Failed to pull container image manifest and config - error: {:#?}",
                    &e
                );
            }
        }
    }

    pub fn get_image_layers(&self) -> Vec<ImageLayer> {
        self.image_layers.clone()
    }
}

async fn get_image_layers(
    use_cached_files: bool,
    client: &mut Client,
    reference: &Reference,
    manifest: &manifest::OciImageManifest,
    config_layer: &DockerConfigLayer,
) -> Result<Vec<ImageLayer>> {
    let mut layer_index = 0;
    let mut layers = Vec::new();

    for layer in &manifest.layers {
        if layer
            .media_type
            .eq(manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE)
            || layer.media_type.eq(manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE)
            || layer.media_type.eq(manifest::IMAGE_LAYER_MEDIA_TYPE)
            || layer
                .media_type
                .eq(manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE)
        {
            if layer_index < config_layer.rootfs.diff_ids.len() {
                let diff_id = &config_layer.rootfs.diff_ids[layer_index];
                let verity_hash = get_verity_hash(
                    use_cached_files,
                    client,
                    reference,
                    &layer.digest,
                    &diff_id,
                    layer.media_type.eq(manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE)
                        || layer
                            .media_type
                            .eq(manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE),
                )
                .await?;
                layers.push(ImageLayer {
                    diff_id: diff_id.clone(),
                    digest: layer.digest.clone(),
                    verity_hash: verity_hash,
                });
            } else {
                return Err(anyhow!("Too many Docker gzip layers"));
            }

            layer_index += 1;
        } else {
            return Err(anyhow!(
                "Unsupported layer media type: {}",
                layer.media_type
            ));
        }
    }

    Ok(layers)
}

async fn get_verity_hash(
    use_cached_files: bool,
    client: &mut Client,
    reference: &Reference,
    layer_digest: &str,
    diff_id: &str,
    compressed: bool,
) -> Result<String> {
    let temp_dir = tempfile::tempdir_in(".")?;
    let base_dir = temp_dir.path();
    let cache_file = "layers-cache.json";
    // Use file names supported by both Linux and Windows.
    let file_name = str::replace(layer_digest, ":", "-");
    let mut decompressed_path = base_dir.join(file_name);
    let erofs_path = decompressed_path.clone().with_extension("erofs");
    decompressed_path.set_extension("tar");

    let mut compressed_path = decompressed_path.clone();
    compressed_path.set_extension("gz");

    // get value from store and return if it exists
    let verity_hash = if use_cached_files {
        let verity_hash = read_verity_from_store(cache_file, diff_id)?;
        info!("Using cache file");

        verity_hash
    } else {
        None
    };

    // create the layer files
    let verity_hash_result = match verity_hash {
        Some(v) => Ok(v),
        None => {
            create_decompressed_layer_file(
                client,
                reference,
                layer_digest,
                &decompressed_path,
                if compressed {
                    Some(&compressed_path)
                } else {
                    None
                },
            )
            .await
            .context("Failed to create verity hash for {layer_digest}")?;

            let root_hash =
                get_verity_hash_value(&erofs_path).context("Failed to get verity hash")?;
            if use_cached_files {
                add_verity_to_store(cache_file, diff_id, layer_digest, &root_hash)?;
            }

            Ok(root_hash)
        }
    };

    temp_dir.close()?;
    match &verity_hash_result {
        Ok(root_hash) => {
            info!("dm-verity root hash: {}", root_hash);
        }
        Err(_) => {
            // remove the cache file if we're using it
            if use_cached_files {
                std::fs::remove_file(cache_file)?;
            }
        }
    };

    verity_hash_result
}

// the store is a json file that matches layer hashes to verity hashes
#[allow(unstable_name_collisions)]
pub(crate) fn add_verity_to_store(
    cache_file: &str,
    diff_id: &str,
    digest: &str,
    verity_hash: &str,
) -> Result<()> {
    // open the json file in read mode, create it if it doesn't exist
    let read_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(cache_file)?;

    let mut data: Vec<ImageLayer> = if let Ok(vec) = serde_json::from_reader(read_file) {
        vec
    } else {
        // Delete the malformed file here if it's present
        Vec::new()
    };

    // Add new data to the deserialized JSON
    data.push(ImageLayer {
        diff_id: diff_id.to_string(),
        digest: digest.to_string(),
        verity_hash: verity_hash.to_string(),
    });

    // Serialize in pretty format
    let serialized = serde_json::to_string_pretty(&data)?;

    // Open the JSON file to write
    let file = OpenOptions::new().write(true).open(cache_file)?;

    // try to lock the file, if it fails, get the error
    let result = file.try_lock_exclusive();
    if result.is_err() {
        warn!("Waiting to lock file: {cache_file}");
        file.lock_exclusive()?;
    }
    // Write the serialized JSON to the file
    let mut writer = BufWriter::new(&file);
    writeln!(writer, "{}", serialized)?;
    writer.flush()?;
    file.unlock()?;
    Ok(())
}

// helper function to read the verity hash from the store
// returns empty string if not found or file does not exist
pub(crate) fn read_verity_from_store(cache_file: &str, diff_id: &str) -> Result<Option<String>> {
    match OpenOptions::new().read(true).open(cache_file) {
        Ok(file) => match serde_json::from_reader(file) {
            Result::<Vec<ImageLayer>, _>::Ok(layers) => {
                for layer in layers {
                    if layer.diff_id == diff_id {
                        return Ok(Some(layer.verity_hash));
                    }
                }
            }
            Err(e) => {
                warn!("read_verity_from_store: failed to read cached image layers: {e}");
            }
        },
        Err(e) => {
            info!("read_verity_from_store: failed to open cache file: {e}");
        }
    }

    Ok(None)
}

// compressed_path is optional, as they layer might not be compressed (e.g. tar format)
async fn create_decompressed_layer_file(
    client: &mut Client,
    reference: &Reference,
    layer_digest: &str,
    decompressed_path: &Path,
    compressed_path: Option<&Path>,
) -> Result<()> {
    match compressed_path {
        Some(compressed_path) => {
            pull_layer_file(client, reference, layer_digest, compressed_path)
                .await
                .context("Failed to pull layer file")?;
            decompress_file(compressed_path, decompressed_path)
                .context("Failed to decompress layer file")?;
        }
        None => pull_layer_file(client, reference, layer_digest, decompressed_path)
            .await
            .context("Failed to pull layer file")?,
    }
    attach_erofs_meta(decompressed_path).context("Failed to attach erofs meta")?;

    Ok(())
}

async fn pull_layer_file(
    client: &mut Client,
    reference: &Reference,
    layer_digest: &str,
    path: &Path,
) -> Result<()> {
    info!("Pulling layer {:?}", layer_digest);
    let mut file = tokio::fs::File::create(&path)
        .await
        .map_err(|e| anyhow!(e))?;
    client
        .pull_blob(reference, layer_digest, &mut file)
        .await
        .map_err(|e| anyhow!(e))?;
    file.flush().await.map_err(|e| anyhow!(e))?;

    Ok(())
}

fn decompress_file(compressed_path: &Path, decompressed_path: &Path) -> Result<()> {
    info!("Decompressing layer");
    let compressed_file = std::fs::File::open(compressed_path).map_err(|e| anyhow!(e))?;
    let mut decompressed_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(decompressed_path)?;
    let mut gz_decoder = flate2::read::MultiGzDecoder::new(compressed_file);
    std::io::copy(&mut gz_decoder, &mut decompressed_file).map_err(|e| anyhow!(e))?;
    decompressed_file.flush().map_err(|e| anyhow!(e))?;

    Ok(())
}

fn attach_erofs_meta(path: &Path) -> Result<()> {
    info!("Creating erofs meta. Appending decompressed tar to erofs meta");

    // Create an erofs image using mkfs.erofs
    let erofs_path = path.with_extension("erofs");
    debug!(
        "Creating erofs meta image {:?} from {:?}",
        &erofs_path, &path
    );

    let status = Command::new("mkfs.erofs")
        .args([
            "--tar=i",
            "-T", "0", // zero out unix time
            "--mkfs-time", // clear out mkfs time in superblock, but keep per-inode mtime
            "-U", EROFS_METADATA_UUID, // set UUID to something specific
            "--aufs", // needed to convert OCI whiteouts/opaque to overlayfs metadata
            "--quiet",
            erofs_path.to_str().unwrap(),
            path.to_str().unwrap(),
        ])
        .status()
        .context("Failed to execute mkfs.erofs command")?;

    if !status.success() {
        return Err(anyhow!(
            "mkfs.erofs failed with status: {}",
            status.code().unwrap_or(-1)
        ));
    }

    // Append the decompressed tar file to the erofs image
    debug!(
        "Appending decompressed tar file {:?} to erofs image {:?}",
        &path, &erofs_path
    );
    let mut erofs_file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(&erofs_path)
        .context("failed to open erofs image for appending")?;
    let mut base_file = File::open(&path)
        .context("failed to open decompressed tar file for reading")?;
    std::io::copy(&mut base_file, &mut erofs_file)
        .context("failed to append decompressed tar file to erofs image")?;

    // get size of erofs meta + tar
    let erofs_file_size = erofs_file.metadata()
    .expect("Failed to get metadata")
    .len();

    // Align the size to 512 bytes
    let alignment = EROFS_BLOCK_ALIGNMENT;
    let padding = (alignment - (erofs_file_size % alignment)) % alignment;

    if padding > 0 {
        let padding_bytes = vec![0u8; padding as usize];
        erofs_file.write_all(&padding_bytes)
            .expect("Failed to write padding");
        debug!("Added {} bytes of padding to align to {} bytes", padding, alignment);
    }

    // get size of erofs meta + tar after padding
    let erofs_file_size = erofs_file.metadata()
    .expect("Failed to get metadata")
    .len();
    debug!("Size of erofs meta + tar: {}", erofs_file_size);

    erofs_file.flush()
        .map_err(|e| anyhow!(e))
        .context("Failed to flush erofs file changes")?;

    Ok(())
}

pub fn get_verity_hash_value(path: &Path) -> Result<String> {
    info!("Calculating dm-verity root hash");
    let mut file = std::fs::File::open(path)?;
    let size = file.seek(std::io::SeekFrom::End(0))?;
    if size < 4096 {
        return Err(anyhow!("Block device {:?} is too small: {size}", &path));
    }

    let salt = [0u8; <Sha256 as OutputSizeUser>::OutputSize::USIZE];
    let v = verity::Verity::<Sha256>::new(size, 512, 512, &salt, 0)?;
    let hash = verity::traverse_file(&mut file, 0, false, v, &mut verity::no_write)?;
    let result = format!("{:x}", hash);

    Ok(result)
}

#[cfg(target_os = "linux")]
pub async fn get_container(config: &Config, image: &str) -> Result<Container> {
    if let Some(socket_path) = &config.containerd_socket_path {
        return Container::new_containerd_pull(config.use_cache, image, socket_path).await;
    }
    Container::new(config.use_cache, image).await
}

#[cfg(target_os = "windows")]
pub async fn get_container(config: &Config, image: &str) -> Result<Container> {
    Container::new(config.use_cache, image).await
}

fn build_auth(reference: &Reference) -> RegistryAuth {
    debug!("build_auth: {:?}", reference);

    let server = reference
        .resolve_registry()
        .strip_suffix('/')
        .unwrap_or_else(|| reference.resolve_registry());

    match docker_credential::get_credential(server) {
        Ok(DockerCredential::UsernamePassword(username, password)) => {
            debug!("build_auth: Found docker credentials");
            return RegistryAuth::Basic(username, password);
        }
        Ok(DockerCredential::IdentityToken(_)) => {
            warn!("build_auth: Cannot use contents of docker config, identity token not supported. Using anonymous access.");
        }
        Err(CredentialRetrievalError::ConfigNotFound) => {
            debug!("build_auth: Docker config not found - using anonymous access.");
        }
        Err(CredentialRetrievalError::NoCredentialConfigured) => {
            debug!("build_auth: Docker credentials not configured - using anonymous access.");
        }
        Err(CredentialRetrievalError::ConfigReadError) => {
            debug!("build_auth: Cannot read docker credentials - using anonymous access.");
        }
        Err(CredentialRetrievalError::HelperFailure { stdout, stderr }) => {
            if stdout == "credentials not found in native keychain\n" {
                // On WSL, this error is generated when credentials are not
                // available in ~/.docker/config.json.
                debug!("build_auth: Docker credentials not found - using anonymous access.");
            } else {
                warn!("build_auth: Docker credentials not found - using anonymous access. stderr = {}, stdout = {}",
                    &stderr, &stdout);
            }
        }
        Err(e) => panic!("Error handling docker configuration file: {}", e),
    }

    RegistryAuth::Anonymous
}
