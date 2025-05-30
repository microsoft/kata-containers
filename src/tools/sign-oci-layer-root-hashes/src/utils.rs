// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    fmt::{Display, Formatter},
    fs,
    path::PathBuf,
};

use anyhow::{Context, Error};
use clap::{Parser, Subcommand};

#[derive(Debug, clap::Args, Clone)]
#[group(required = true, multiple = false)]
pub struct ImageGroup {
    #[clap(short = 'i', long, help = "Image tag, can be specified multiple times")]
    image: Option<Vec<String>>,

    #[clap(
        short = 'l',
        long,
        help = "Path to a file containing a newline-separated list of image tags"
    )]
    images: Option<PathBuf>,
}

#[derive(Debug, clap::Args, Clone)]
#[group(required = false, multiple = false)]
pub struct OutputImageGroup {
    #[clap(
        short = 'I',
        long,
        help = "Image tag to repush, can be specified multiple times"
    )]
    pub image: Option<Vec<String>>,

    #[clap(
        short = 'L',
        long,
        help = "Path to a file containing a newline-separated list of image tags to repush"
    )]
    pub images: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct CommandLineOptions {
    #[clap(flatten)]
    image_group: ImageGroup,

    #[clap(
        short,
        long,
        help = "Create and use a cache of container image layer contents and dm-verity information (in ./layers_cache/)"
    )]
    use_cached_files: bool,

    #[clap(
        short = 'd',
        long,
        help = "If specified, will use existing containerd service to pull container images. This option is only supported on Linux",
        // from https://docs.rs/clap/4.1.8/clap/struct.Arg.html#method.default_missing_value
        default_missing_value = "/var/run/containerd/containerd.sock", // used if flag is present but no value is given
        num_args = 0..=1,
        require_equals= true
    )]
    containerd_socket_path: Option<String>,

    #[clap(short, long, help = "Print version information and exit")]
    version: bool,

    #[clap(short, long, help = "Signer certificate")]
    signer: PathBuf,

    #[clap(short, long, help = "Key file")]
    key: PathBuf,

    #[clap(short, long, help = "OpenSSL key file pass phrase")]
    passphrase: String,

    #[clap(subcommand)]
    command: Commands,
}

impl Commands {
    pub fn name(&self) -> &'static str {
        match self {
            Commands::GenerateStandaloneSignaturesManifest { .. } => {
                "generate-standalone-signatures-manifest"
            }
            Commands::InjectSignaturesToImageManifest { .. } => {
                "inject-signatures-to-image-manifest"
            }
            Commands::AttachSignaturesToImageManifest { .. } => {
                "attach-signatures-to-image-manifest"
            }
        }
    }
}

impl Display for Commands {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Generate a standalone JSON manifest with signatures
    GenerateStandaloneSignaturesManifest {
        #[clap(short, long, help = "Signatures JSON file path output")]
        output: Option<PathBuf>,
    },

    /// Embed signatures into the image manifest and repush updated manifest
    InjectSignaturesToImageManifest {
        #[clap(flatten)]
        output_image_group: Option<OutputImageGroup>,
    },

    /// Attach signatures to the image manifest as referrers without repushing the manifest
    AttachSignaturesToImageManifest {
        #[clap(flatten)]
        output_image_group: Option<OutputImageGroup>,
    },
}

/// Application configuration, derived from on command line parameters.
#[derive(Clone, Debug)]
pub struct Config {
    pub use_cache: bool,

    pub image: Option<Vec<String>>,
    pub images: Option<PathBuf>,

    pub containerd_socket_path: Option<String>,
    pub version: bool,
    pub signer: PathBuf,
    pub key: PathBuf,
    pub passphrase: String,

    pub command: Commands,
}

impl Config {
    pub fn new() -> Self {
        let args = CommandLineOptions::parse();
        Self {
            use_cache: args.use_cached_files,
            image: args.image_group.image,
            images: args.image_group.images,
            containerd_socket_path: args.containerd_socket_path,
            version: args.version,
            signer: args.signer,
            key: args.key,
            passphrase: args.passphrase,
            command: args.command,
        }
    }
}

/// Get the input image tags from the configuration.
pub fn get_image_tags(
    images: &Option<PathBuf>,
    image: &Option<Vec<String>>,
) -> Result<Vec<String>, Error> {
    let mut image_tags: Vec<String> = vec![];
    if let Some(images) = &images {
        image_tags.append(
            fs::read_to_string(images)
                .context("Failed to read image tags file")?
                .lines()
                .map(|line| line.to_string())
                .collect::<Vec<String>>()
                .as_mut(),
        );
    } else if let Some(images) = &image {
        image_tags.append(images.clone().as_mut());
    };
    Ok(image_tags)
}
