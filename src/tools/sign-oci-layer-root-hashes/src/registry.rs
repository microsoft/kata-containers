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
use oci_distribution::{manifest, secrets::RegistryAuth, Client, Reference};
use rand::rngs::ThreadRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{digest::typenum::Unsigned, digest::OutputSizeUser, Sha256};
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::{io, io::Seek, io::Write, path::Path};
use tokio::io::AsyncWriteExt;

pub(crate) type Salt = [u8; <Sha256 as OutputSizeUser>::OutputSize::USIZE];

#[derive(Debug)]
pub(crate) struct VerityHash {
    pub root_hash: String,
    pub salt: Salt,
}

/// Container image properties obtained from an OCI repository.
#[derive(Clone, Debug, Default)]
pub struct Container {
    pub config_layer: DockerConfigLayer,
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
    pub digest: String,
    pub verity_hash: String,
    pub salt: Salt,
}

impl Container {
    pub async fn new(use_cached_files: bool, image: &str) -> Result<Self> {
        info!("============================================");
        info!("Pulling manifest and config for {:?}", image);
        let reference: Reference = image.to_string().parse().unwrap();
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
                    config_layer,
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
    let mut rng = rand::thread_rng();

    for layer in &manifest.layers {
        if layer
            .media_type
            .eq(manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE)
            || layer.media_type.eq(manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE)
            || layer.media_type.eq(manifest::IMAGE_LAYER_MEDIA_TYPE)
        {
            if layer_index < config_layer.rootfs.diff_ids.len() {
                let verity_hash = get_verity_hash(
                    use_cached_files,
                    &layer.digest,
                    client,
                    reference,
                    &mut rng,
                    layer.media_type.eq(manifest::IMAGE_LAYER_MEDIA_TYPE),
                )
                .await?;
                layers.push(ImageLayer {
                    digest: layer.digest.clone(),
                    verity_hash: verity_hash.root_hash,
                    salt: verity_hash.salt,
                });
            } else {
                return Err(anyhow!("Too many Docker gzip layers"));
            }

            layer_index += 1;
        }
    }

    Ok(layers)
}

async fn get_verity_hash(
    use_cached_files: bool,
    layer_digest: &str,
    client: &mut Client,
    reference: &Reference,
    rng: &mut ThreadRng,
    decompressed: bool,
) -> Result<VerityHash> {
    let temp_dir = tempfile::tempdir_in(".")?;
    let base_dir = temp_dir.path();
    let cache_file = "layers-cache.json";
    // Use file names supported by both Linux and Windows.
    let file_name = str::replace(layer_digest, ":", "-");
    let mut decompressed_path = base_dir.join(file_name);
    decompressed_path.set_extension("tar");

    let mut compressed_path = decompressed_path.clone();
    compressed_path.set_extension("gz");

    // get value from store and return if it exists
    let verity_hash = if use_cached_files {
        let verity_hash = read_verity_from_store(cache_file, layer_digest)?;
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
                if decompressed {
                    None
                } else {
                    Some(&compressed_path)
                },
            )
            .await
            .context("Failed to create verity hash for {layer_digest}")?;

            let salt: Salt = rng.gen();
            let root_hash = get_verity_hash_value(&decompressed_path, &salt)
                .context("Failed to get verity hash")?;
            let verity_hash = VerityHash { root_hash, salt };
            if use_cached_files {
                add_verity_to_store(cache_file, layer_digest, &verity_hash)?;
            }

            Ok(verity_hash)
        }
    };

    temp_dir.close()?;
    match &verity_hash_result {
        Ok(v) => {
            info!("dm-verity root hash: {}", v.root_hash);
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
pub(crate) fn add_verity_to_store(
    cache_file: &str,
    digest: &str,
    verity_hash: &VerityHash,
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
        digest: digest.into(),
        verity_hash: verity_hash.root_hash.clone(),
        salt: verity_hash.salt,
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
pub(crate) fn read_verity_from_store(cache_file: &str, digest: &str) -> Result<Option<VerityHash>> {
    match OpenOptions::new().read(true).open(cache_file) {
        Ok(file) => match serde_json::from_reader(file) {
            Result::<Vec<ImageLayer>, _>::Ok(layers) => {
                for layer in layers {
                    if layer.digest == digest {
                        return Ok(Some(VerityHash {
                            root_hash: layer.verity_hash,
                            salt: layer.salt,
                        }));
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

async fn create_decompressed_layer_file(
    client: &mut Client,
    reference: &Reference,
    layer_digest: &str,
    decompressed_path: &Path,
    compressed_path: Option<&Path>,
) -> Result<()> {
    match compressed_path {
        Some(compressed_path) => {
            pull_layer_file(client, reference, layer_digest, compressed_path).await?;
            decompress_file(compressed_path, decompressed_path)?;
        }
        None => pull_layer_file(client, reference, layer_digest, decompressed_path).await?,
    }
    attach_tarfs_index(decompressed_path)?;

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
    let mut gz_decoder = flate2::read::GzDecoder::new(compressed_file);
    std::io::copy(&mut gz_decoder, &mut decompressed_file).map_err(|e| anyhow!(e))?;
    decompressed_file.flush().map_err(|e| anyhow!(e))?;

    Ok(())
}

fn attach_tarfs_index(path: &Path) -> Result<()> {
    info!("Adding tarfs index to layer");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    tarindex::append_index(&mut file).map_err(|e| anyhow!(e))?;
    file.flush().map_err(|e| anyhow!(e))?;

    Ok(())
}

pub fn get_verity_hash_value(path: &Path, salt: &Salt) -> Result<String> {
    info!("Calculating dm-verity root hash");
    let mut file = std::fs::File::open(path)?;
    let size = file.seek(std::io::SeekFrom::End(0))?;
    if size < 4096 {
        return Err(anyhow!("Block device {:?} is too small: {size}", &path));
    }

    let v = verity::Verity::<Sha256>::new(size, 4096, 4096, salt, 0)?;
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
