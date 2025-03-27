// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::{Context, Error};
use base64::{engine::general_purpose, Engine};
use futures::future;
use serde::{Deserialize, Serialize};
use std::io::Write;

mod registry;
#[cfg(target_os = "linux")]
mod registry_containerd;
mod utils;
mod verity;
mod version;

#[derive(Serialize, Deserialize)]
struct ImageInfo {
    name: String,
    layers: Vec<LayerInfo>,
}

#[derive(Serialize, Deserialize)]
struct LayerInfo {
    digest: String,
    root_hash: String,
    signature: String,
    salt: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let config = utils::Config::new();

    if config.version {
        println!(
            "SOLaR tool: id: {}, version: {}, commit: {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            version::COMMIT_INFO
        );
        return Ok(());
    }

    if config.images.is_none() && config.image.is_none() {
        return Err(anyhow::anyhow!("No images specified"));
    }

    if config.signer.exists() {
        if !config.signer.is_file() {
            return Err(anyhow::anyhow!("Signer certificate is not a file"));
        }
    } else {
        return Err(anyhow::anyhow!("Signer certificate does not exist"));
    }

    if config.key.exists() {
        if !config.key.is_file() {
            return Err(anyhow::anyhow!("Key file is not a file"));
        }
    } else {
        return Err(anyhow::anyhow!("Key file does not exist"));
    }

    get_root_hashes(&config)
        .await
        .context("Failed to get root hashes")?;

    Ok(())
}

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
                salt: hex::encode(layer.salt),
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

async fn get_root_hashes(config: &utils::Config) -> Result<Vec<ImageInfo>, Error> {
    let mut image_tags: Vec<String> = vec![];
    if let Some(images) = &config.images {
        image_tags.append(
            fs::read_to_string(images)
                .context("Failed to read image tags file")?
                .lines()
                .map(|line| line.to_string())
                .collect::<Vec<String>>()
                .as_mut(),
        );
    } else if let Some(images) = &config.image {
        image_tags.append(images.clone().as_mut());
    } else {
        return Err(anyhow::anyhow!("No images specified"));
    };
    let images = future::try_join_all(
        image_tags
            .iter()
            .map(|image| get_container_image_root_hashes(&image, config)),
    )
    .await
    .context("Failed to gather signatures for requested images")?;

    let signatures_json =
        serde_json::to_string(&images).context("Failed to serialize hash signatures to json")?;
    if config.output.is_some() {
        std::fs::create_dir_all(
            config
                .output
                .as_ref()
                .context("Failed to get output path")?
                .parent()
                .context("Failed to get output directory path")?,
        )
        .context("Failed to create the output directory")?;
        std::fs::write(
            config
                .output
                .as_ref()
                .context("Failed to get output path")?,
            signatures_json,
        )
        .context("Failed to save the output json to a file")?;
    } else {
        println!("{}", signatures_json);
    }

    Ok(images)
}
