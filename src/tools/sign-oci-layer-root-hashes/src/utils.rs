// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::{PathBuf};

use clap::Parser;

#[derive(Debug, Parser)]
struct CommandLineOptions {
    #[clap(short, long, help = "Image tag")]
    image: Vec<String>,

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

    #[clap(short, long, help = "Signatures JSON file path output")]
    output: Option<PathBuf>,
}

/// Application configuration, derived from on command line parameters.
#[derive(Clone, Debug)]
pub struct Config {
    pub use_cache: bool,

    pub image: Vec<String>,

    pub containerd_socket_path: Option<String>,
    pub version: bool,
    pub signer: PathBuf,
    pub key: PathBuf,
    pub passphrase: String,
    pub output: Option<PathBuf>,
}

impl Config {
    pub fn new() -> Self {
        let args = CommandLineOptions::parse();
        Self {
            use_cache: args.use_cached_files,
            image: args.image,
            containerd_socket_path: args.containerd_socket_path,
            version: args.version,
            signer: args.signer,
            key: args.key,
            passphrase: args.passphrase,
            output: args.output,
        }
    }
}
