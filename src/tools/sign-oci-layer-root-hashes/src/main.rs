// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::PathBuf;

use anyhow::{Context, Error};
use futures::future;
use oci_client::manifest::OciImageManifest;
use sign::ImageInfo;

mod registry;
#[cfg(target_os = "linux")]
mod registry_containerd;
mod sign;
mod utils;
mod verity;
mod version;

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

    let image_tags =
        utils::get_image_tags(&config.images, &config.image).context("Failed to get image tags")?;
    if image_tags.is_empty() {
        return Err(anyhow::anyhow!("No images specified"));
    }

    match config.command {
        utils::Commands::GenerateStandaloneSignaturesManifest { ref output } => {
            let images = sign::get_root_hash_signatures(&config, &image_tags)
                .await
                .context("Failed to get root hashes")?;

            output_signature_manifest(&images, output).context("Failed to output signatures")?;
        }
        utils::Commands::InjectSignaturesToImageManifest {
            ref output_image_group,
        } => {
            let output_image_tags = match output_image_group {
                Some(ref output_image_group) => {
                    utils::get_image_tags(&output_image_group.images, &output_image_group.image)
                        .context("Failed to get output image tags")?
                }
                None => image_tags.clone(),
            };

            let manifests = sign::get_manifest_with_root_hash_signatures(&config, &image_tags)
                .await
                .context("Failed to get updates manifests")?;

            push_oci_manifests(output_image_tags, manifests)
                .await
                .context("Failed to push updated manifests")?;
        }
        utils::Commands::AttachSignaturesToImageManifest {
            ref output_image_group
        } => {
            let output_image_tags = match output_image_group {
                Some(ref output_image_group) => {
                    utils::get_image_tags(&output_image_group.images, &output_image_group.image)
                        .context("Failed to get output image tags")?
                }
                None => image_tags.clone(),
            };
            sign::attach_root_hash_signatures(&config, &output_image_tags)
                .await
                .context("Failed to attach root hash sigantures")?;
        }

    }

    Ok(())
}

async fn push_oci_manifests(
    image_tags: Vec<String>,
    manifests: Vec<OciImageManifest>,
) -> Result<(), Error> {
    future::try_join_all(
        manifests
            .iter()
            .zip(image_tags)
            .map(|(manifest, output_image_tag)| {
                registry::Container::push_manifest(output_image_tag, manifest.clone())
            }),
    )
    .await
    .context("Failed to push the updated image manifest")?;
    Ok(())
}

/// Output the signatures to a file or stdout.
fn output_signature_manifest(
    images: &Vec<ImageInfo>,
    output: &Option<PathBuf>,
) -> Result<(), Error> {
    let signatures_json =
        serde_json::to_string(&images).context("Failed to serialize hash signatures to json")?;
    match output {
        Some(output) => {
            std::fs::create_dir_all(
                output
                    .parent()
                    .context("Failed to get output directory path")?,
            )
            .context("Failed to create the output directory")?;
            std::fs::write(output, signatures_json)
                .context("Failed to save the output json to a file")?;
        }
        None => {
            println!("{}", signatures_json);
        }
    }

    Ok(())
}
