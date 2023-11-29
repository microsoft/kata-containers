// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow Docker image config field names.
#![allow(non_snake_case)]
use crate::policy;
use crate::verity;

use anyhow::{anyhow, Result};
use containerd_client::services::v1::GetImageRequest;
use containerd_client::with_namespace;
use log::warn;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use sha2::{digest::typenum::Unsigned, digest::OutputSizeUser, Sha256};
use std::{io::Seek, io::Write, path::Path};
use tokio::{fs, io::AsyncWriteExt};
use k8s_cri::v1::image_service_client::ImageServiceClient;
use std::collections::HashMap;
use std::convert::TryFrom;
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;
use tonic::Request;

/// Container image properties obtained from an OCI repository.
#[derive(Clone, Debug, Default)]
pub struct Container {
    config_layer: DockerConfigLayer,
    image_layers: Vec<ImageLayer>,
}

/// Image config layer properties.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DockerConfigLayer {
    architecture: String,
    config: DockerImageConfig,
    rootfs: DockerRootfs,
}

/// Image config properties.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DockerImageConfig {
    User: Option<String>,
    Tty: Option<bool>,
    Env: Vec<String>,
    Cmd: Option<Vec<String>>,
    WorkingDir: Option<String>,
    Entrypoint: Option<Vec<String>>,
}

/// Container rootfs information.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DockerRootfs {
    r#type: String,
    diff_ids: Vec<String>,
}

/// This application's image layer properties.
#[derive(Clone, Debug)]
pub struct ImageLayer {
    pub diff_id: String,
    pub verity_hash: String,
}

impl Container {
    pub async fn new(use_cached_files: bool, image: &str) -> Result<Self> {
        info!("============================================");
        info!("Pulling image and layers for {:?}", image);

        let containerd_socket_path = "/var/run/containerd/containerd.sock";

        pull_image(image.to_string(), containerd_socket_path.to_string()).await?;
        let manifest = get_image_manifest(image.to_string(), containerd_socket_path.to_string()).await.unwrap();

        let config_layer = get_config_layer(image.to_string(), containerd_socket_path.to_string()).await.unwrap();
                    
        let image_layers = get_image_layers(
            use_cached_files,
            &image,
            &manifest,
            &config_layer,
        )
        .await
        .unwrap();

        Ok(Container {
            config_layer,
            image_layers})
    }

    // Convert Docker image config to policy data.
    pub fn get_process(
        &self,
        process: &mut policy::KataProcess,
        yaml_has_command: bool,
        yaml_has_args: bool,
    ) {
        debug!("Getting process field from docker config layer...");
        let docker_config = &self.config_layer.config;

        if let Some(image_user) = &docker_config.User {
            if !image_user.is_empty() {
                debug!("Splitting Docker config user = {:?}", image_user);
                let user: Vec<&str> = image_user.split(':').collect();
                if !user.is_empty() {
                    debug!("Parsing uid from user[0] = {}", &user[0]);
                    match user[0].parse() {
                        Ok(id) => process.User.UID = id,
                        Err(e) => {
                            // "image: prom/prometheus" has user = "nobody", but
                            // process.User.UID is an u32 value.
                            warn!(
                                "Failed to parse {} as u32, using uid = 0 - error {e}",
                                &user[0]
                            );
                            process.User.UID = 0;
                        }
                    }
                }
                if user.len() > 1 {
                    debug!("Parsing gid from user[1] = {:?}", user[1]);
                    process.User.GID = user[1].parse().unwrap();
                }
            }
        }

        if let Some(terminal) = docker_config.Tty {
            process.Terminal = terminal;
        } else {
            process.Terminal = false;
        }

        for env in &docker_config.Env {
            process.Env.push(env.clone());
        }

        let policy_args = &mut process.Args;
        debug!("Already existing policy args: {:?}", policy_args);

        if let Some(entry_points) = &docker_config.Entrypoint {
            debug!("Image Entrypoint: {:?}", entry_points);
            if !yaml_has_command {
                debug!("Inserting Entrypoint into policy args");

                let mut reversed_entry_points = entry_points.clone();
                reversed_entry_points.reverse();

                for entry_point in reversed_entry_points {
                    policy_args.insert(0, entry_point.clone());
                }
            } else {
                debug!("Ignoring image Entrypoint because YAML specified the container command");
            }
        } else {
            debug!("No image Entrypoint");
        }

        debug!("Updated policy args: {:?}", policy_args);

        if yaml_has_command {
            debug!("Ignoring image Cmd because YAML specified the container command");
        } else if yaml_has_args {
            debug!("Ignoring image Cmd because YAML specified the container args");
        } else if let Some(commands) = &docker_config.Cmd {
            debug!("Adding to policy args the image Cmd: {:?}", commands);

            for cmd in commands {
                policy_args.push(cmd.clone());
            }
        } else {
            debug!("Image Cmd field is not present");
        }

        debug!("Updated policy args: {:?}", policy_args);

        if let Some(working_dir) = &docker_config.WorkingDir {
            if !working_dir.is_empty() {
                process.Cwd = working_dir.clone();
            }
        }

        debug!("get_process succeeded.");
    }

    pub fn get_image_layers(&self) -> Vec<ImageLayer> {
        self.image_layers.clone()
    }
}

async fn get_config_layer(image_ref: String, socket_path: String) ->  Result<DockerConfigLayer, Box<dyn std::error::Error>>{
    
    let socket = socket_path.clone(); // todo: figure out how not to clone everything to get it working
    let channel = Endpoint::try_from("http://[::]")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| UnixStream::connect(socket.clone())))
        .await
        .expect("Could not create client.");

    let mut client = ImageServiceClient::new(channel);

    let req =   k8s_cri::v1::ImageStatusRequest {
        image: Some(k8s_cri::v1::ImageSpec {
            image: image_ref,
            annotations: HashMap::new(),
        }),
        verbose: true
    };

    let resp = client.image_status(req).await?;
    let image_layers = resp.into_inner();

    let status_info: serde_json::Value = serde_json::from_str(image_layers.info.get("info").unwrap())?;
    let image_spec = status_info["imageSpec"].as_object().unwrap();
    let docker_config_layer: DockerConfigLayer = serde_json::from_value(serde_json::to_value(image_spec)?).unwrap();

    Ok(docker_config_layer)
}

pub async fn pull_image(image_ref: String, socket_path: String) ->  Result<(), anyhow::Error>{
    let socket = socket_path.clone(); // todo: figure out how not to have to clone everything just to get it working
    let channel = Endpoint::try_from("http://[::]")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| UnixStream::connect(socket.clone())))
        .await
        .expect("Could not create client.");

    let mut client = ImageServiceClient::new(channel);

    let req =   k8s_cri::v1::PullImageRequest {
        image: Some(k8s_cri::v1::ImageSpec {
            image: image_ref.clone(),
            annotations: HashMap::new(),
        }),
        auth: None,
        sandbox_config: None,
    };

    let resp = client.pull_image(req).await?;

    println!("pull image response: {:?}\n", resp);
    Err(anyhow!("Unable to get image manifest"))
}

async fn get_image_manifest (image_ref: String, socket_path: String) ->  Result<serde_json::Value, anyhow::Error>{
    let client = match containerd_client::Client::from_path(socket_path).await {
        Ok(c) => {
            c
        },
        Err(e) => {
            return Err(anyhow!("Failed to connect to containerd: {e:?}"));
        }
    };

    let mut imageChannel = client.images();

    let req = GetImageRequest{
        name: image_ref.clone()
    };
    let req = with_namespace!(req, "k8s.io");
    let resp = imageChannel.get(req).await?;

    let image_digest = resp.into_inner().image.unwrap().target.clone().unwrap().digest.to_string();
    println!("image digest used to query layers: {:?}\n", image_digest);

    let req = containerd_client::services::v1::ReadContentRequest {
        digest: image_digest.to_string(),
        offset: 0,
        size: 0,
    };
    let req = with_namespace!(req, "k8s.io");
    let mut c = client.content();
    let resp = c.read(req).await?;
    let mut stream = resp.into_inner();

    while let Some(chunk) = stream.message().await? {
        if chunk.offset < 0 {
            print!("oop")
        }
        else {
            let manifest: serde_json::Value = serde_json::from_slice(&chunk.data)?;
            return Ok(manifest);
        }
    }
    Err(anyhow!("Unable to get image manifest"))
}

async fn get_image_layers(
    use_cached_files: bool,
    reference: &str,
    manifest: &serde_json::Value,
    config_layer: &DockerConfigLayer,
) -> Result<Vec<ImageLayer>> {
    let mut layer_index = 0;
    let mut layersVec = Vec::new();
    
    
    let isv2_manifest = manifest.get("manifests") != None; // v2 has manifest["manifests"]

    let layers = if isv2_manifest {
        info!("v2 layers for {}:", reference);
        manifest["manifests"].as_array().unwrap()
    }
    else {
        info!("v1 layers for {}: ", reference);
        manifest["layers"].as_array().unwrap()
    };
    
    for layer in layers {
        if layer["mediaType"].as_str().unwrap()
        .eq("application/vnd.docker.image.rootfs.diff.tar.gzip")
    {
        if layer_index < config_layer.rootfs.diff_ids.len() {
            layersVec.push(ImageLayer {
                diff_id: config_layer.rootfs.diff_ids[layer_index].clone(),
                verity_hash: get_verity_hash(
                    use_cached_files,
                    layer["digest"].as_str().unwrap()
                )
                .await?,
            });
        } else {
            return Err(anyhow!("Too many Docker gzip layers"));
        }

        layer_index += 1;
    }
    }

    Ok(layersVec)
}

fn delete_files(decompressed_path: &Path, compressed_path: &Path, verity_path: &Path) {
    let _ = fs::remove_file(&decompressed_path);
    let _ = fs::remove_file(&compressed_path);
    let _ = fs::remove_file(&verity_path);
}

async fn get_verity_hash(
    use_cached_files: bool,
    layer_digest: &str,
) -> Result<String> {
    let base_dir = std::path::Path::new("layers_cache");

    // Use file names supported by both Linux and Windows.
    let file_name = str::replace(&layer_digest, ":", "-");

    let mut decompressed_path = base_dir.join(file_name);
    decompressed_path.set_extension("tar");

    let mut compressed_path = decompressed_path.clone();
    compressed_path.set_extension("gz");

    let mut verity_path = decompressed_path.clone();
    verity_path.set_extension("verity");

    let mut verity_hash = "".to_string();
    let mut error_message = "".to_string();
    let mut error = false;

    if use_cached_files && verity_path.exists() {
        info!("Using cached file {:?}", &verity_path);
    } else if let Err(e) = create_verity_hash_file(
        use_cached_files,
        layer_digest,
        &base_dir,
        &decompressed_path,
        &compressed_path,
        &verity_path,
    )
    .await
    {
        error = true;
        error_message = format!("Failed to create verity hash for {layer_digest}, error {e}");
    }

    if !error {
        match std::fs::read_to_string(&verity_path) {
            Err(e) => {
                error = true;
                error_message = format!("Failed to read {:?}, error {e}", &verity_path);
            }
            Ok(v) => {
                verity_hash = v;
                info!("dm-verity root hash: {verity_hash}");
            }
        }
    }

    if !use_cached_files {
        let _ = std::fs::remove_dir_all(&base_dir);
    } else if error {
        delete_files(&decompressed_path, &compressed_path, &verity_path);
    }

    if error {
        panic!("{error_message}");
    } else {
        Ok(verity_hash)
    }
}

async fn create_verity_hash_file(
    use_cached_files: bool,
    layer_digest: &str,
    base_dir: &Path,
    decompressed_path: &Path,
    compressed_path: &Path,
    verity_path: &Path,
) -> Result<()> {
    if use_cached_files && decompressed_path.exists() {
        info!("Using cached file {:?}", &decompressed_path);
    } else {
        std::fs::create_dir_all(&base_dir)?;

        create_decompressed_layer_file(
            use_cached_files,
            layer_digest,
            &decompressed_path,
            &compressed_path,
        )
        .await?;
    }

    do_create_verity_hash_file(decompressed_path, verity_path)
}

async fn create_decompressed_layer_file(
    use_cached_files: bool,
    layer_digest: &str,
    decompressed_path: &Path,
    compressed_path: &Path,
) -> Result<()> {
    if use_cached_files && compressed_path.exists() {
        info!("Using cached file {:?}", &compressed_path);
    } else {
        info!("Pulling layer {layer_digest}");
        let mut file = tokio::fs::File::create(&compressed_path)
            .await
            .map_err(|e| anyhow!(e))?;
        // no need to do this since image gets pulled at the start
        // client
        //     .pull_blob(&reference, layer_digest, &mut file)
        //     .await
        //     .map_err(|e| anyhow!(e))?;
        file.flush().await.map_err(|e| anyhow!(e))?;
    }

    info!("Decompressing layer");
    let compressed_file = std::fs::File::open(&compressed_path).map_err(|e| anyhow!(e))?;
    let mut decompressed_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&decompressed_path)?;
    let mut gz_decoder = flate2::read::GzDecoder::new(compressed_file);
    std::io::copy(&mut gz_decoder, &mut decompressed_file).map_err(|e| anyhow!(e))?;

    info!("Adding tarfs index to layer");
    decompressed_file.seek(std::io::SeekFrom::Start(0))?;
    tarindex::append_index(&mut decompressed_file).map_err(|e| anyhow!(e))?;
    decompressed_file.flush().map_err(|e| anyhow!(e))?;

    Ok(())
}

fn do_create_verity_hash_file(path: &Path, verity_path: &Path) -> Result<()> {
    info!("Calculating dm-verity root hash");
    let mut file = std::fs::File::open(path)?;
    let size = file.seek(std::io::SeekFrom::End(0))?;
    if size < 4096 {
        return Err(anyhow!("Block device {:?} is too small: {size}", &path));
    }

    let salt = [0u8; <Sha256 as OutputSizeUser>::OutputSize::USIZE];
    let v = verity::Verity::<Sha256>::new(size, 4096, 4096, &salt, 0)?;
    let hash = verity::traverse_file(&mut file, 0, false, v, &mut verity::no_write)?;
    let result = format!("{:x}", hash);

    let mut verity_file = std::fs::File::create(verity_path).map_err(|e| anyhow!(e))?;
    verity_file
        .write_all(result.as_bytes())
        .map_err(|e| anyhow!(e))?;
    verity_file.flush().map_err(|e| anyhow!(e))?;

    Ok(())
}

pub async fn get_container(use_cache: bool, image: &str) -> Result<Container> {
    Container::new(use_cache, image).await
}

// fn build_auth(reference: &Reference) -> RegistryAuth {
//     debug!("build_auth: {:?}", reference);

//     let server = reference
//         .resolve_registry()
//         .strip_suffix("/")
//         .unwrap_or_else(|| reference.resolve_registry());

//     match docker_credential::get_credential(server) {
//         Ok(DockerCredential::UsernamePassword(username, password)) => {
//             debug!("build_auth: Found docker credentials");
//             return RegistryAuth::Basic(username, password);
//         }
//         Ok(DockerCredential::IdentityToken(_)) => {
//             warn!("build_auth: Cannot use contents of docker config, identity token not supported. Using anonymous access.");
//         }
//         Err(CredentialRetrievalError::ConfigNotFound) => {
//             debug!("build_auth: Docker config not found - using anonymous access.");
//         }
//         Err(CredentialRetrievalError::NoCredentialConfigured) => {
//             debug!("build_auth: Docker credentials not configured - using anonymous access.");
//         }
//         Err(CredentialRetrievalError::ConfigReadError) => {
//             debug!("build_auth: Cannot read docker credentials - using anonymous access.");
//         }
//         Err(CredentialRetrievalError::HelperFailure { stdout, stderr }) => {
//             if stdout == "credentials not found in native keychain\n" {
//                 // On WSL, this error is generated when credentials are not
//                 // available in ~/.docker/config.json.
//                 debug!("build_auth: Docker credentials not found - using anonymous access.");
//             } else {
//                 warn!("build_auth: Docker credentials not found - using anonymous access. stderr = {}, stdout = {}",
//                     &stderr, &stdout);
//             }
//         }
//         Err(e) => panic!("Error handling docker configuration file: {}", e),
//     }

//     RegistryAuth::Anonymous
// }
