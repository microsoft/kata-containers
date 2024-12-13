// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{path::PathBuf, process::{Command, Stdio}};

use base64::{engine, Engine};
use log::info;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::Write;

mod registry;
#[cfg(target_os = "linux")]
mod registry_containerd;
mod utils;
mod verity;
mod version;

#[derive(Serialize, Deserialize)]
struct LayerInfo {
    diff_id: String,
    root_hash: String,
    signature: String,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let config = utils::Config::new();

    if config.version {
        println!(
            "SOLaR tool: id: {}, version: {}, commit: {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            version::COMMIT_INFO
        );
        return;
    }

    get_root_hashes(&config).await.unwrap();

    info!("Success!");
}

fn sign_hash(hash: &String, key: &PathBuf, password: &String, signer: &PathBuf) -> Result<String> {
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
        .spawn()?;

    write!(openssl.stdin.as_ref().unwrap(), "{}", hash)?;
    let output = openssl.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to sign hash"));
    }
    let base64_output = engine::general_purpose::STANDARD.encode(&output.stdout);
    Ok(base64_output)
}

async fn get_root_hashes(config: &utils::Config) -> Result<Vec<LayerInfo>> {
    let container = registry::get_container(&config, &config.image).await?;
    let layers = container.get_image_layers();
    let hash_signatures = layers.iter().map(|layer| {
        let diff_id = layer.diff_id.clone();
        let root_hash = layer.verity_hash.clone();
        let signature = sign_hash(&root_hash, &config.key, &config.passphrase, &config.signer)?;
        Ok(LayerInfo { diff_id, root_hash, signature })
    }).collect::<Result<Vec<_>>>()?;

    let signatures_json = serde_json::to_string(&hash_signatures)?;
    if config.output.is_some() {
        std::fs::write(config.output.as_ref().unwrap(), signatures_json)?;
    }
    else {
        println!("{}", signatures_json);
    }

    Ok(hash_signatures)
}