// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

<<<<<<< HEAD
use log::debug;

=======
use clap::Parser;
use log::debug;

#[derive(Debug, Parser)]
struct CommandLineOptions {
    #[clap(
        short,
        long,
        help = "Kubernetes input/output YAML file path. stdin/stdout get used if this option is not specified."
    )]
    yaml_file: Option<String>,

    #[clap(
        short,
        long,
        help = "Optional Kubernetes config map YAML input file path"
    )]
    config_map_file: Option<String>,

    #[clap(
        short = 'j',
        long,
        default_value_t = String::from("genpolicy-settings.json"),
        help = "genpolicy settings file name"
    )]
    settings_file_name: String,

    #[clap(
        short,
        long,
        default_value_t = String::from("."),
        help = "Path to the rules.rego and settings input files"
    )]
    input_files_path: String,

    #[clap(
        short,
        long,
        help = "Create and use a cache of container image layer contents and dm-verity information (in ./layers_cache/)"
    )]
    use_cached_files: bool,

    #[clap(
        short,
        long,
        help = "Print the output Rego policy text to standard output"
    )]
    raw_out: bool,

    #[clap(
        short,
        long,
        help = "Print the base64 encoded output Rego policy to standard output"
    )]
    base64_out: bool,

    #[clap(
        short,
        long,
        help = "Ignore unsupported input Kubernetes YAML fields. This is not recommeded unless you understand exactly how genpolicy works!"
    )]
    silent_unsupported_fields: bool,
}

>>>>>>> upstream/main
/// Application configuration, derived from on command line parameters.
#[derive(Clone, Debug)]
pub struct Config {
    pub use_cache: bool,

    pub yaml_file: Option<String>,
    pub rules_file: String,
    pub settings_file: String,
    pub config_map_files: Option<Vec<String>>,

    pub silent_unsupported_fields: bool,
    pub raw_out: bool,
    pub base64_out: bool,
}

impl Config {
<<<<<<< HEAD
    pub fn new(
        use_cache: bool,
        yaml_file: Option<String>,
        input_files_path: &str,
        settings_file_name: &str,
        config_map_files: &Vec<String>,
        silent_unsupported_fields: bool,
        raw_out: bool,
        base64_out: bool,
    ) -> Self {
        let rules_file = format!("{input_files_path}/rules.rego");
        debug!("Rules file: {rules_file}");

        let settings_file = format!("{input_files_path}/{settings_file_name}");
        debug!("Settings file: {settings_file}");
=======
    pub fn new() -> Self {
        let args = CommandLineOptions::parse();

        let mut config_map_files = Vec::new();
        if let Some(config_map_file) = &args.config_map_file {
            config_map_files.push(config_map_file.clone());
        }
>>>>>>> upstream/main

        let cm_files = if !config_map_files.is_empty() {
            Some(config_map_files.clone())
        } else {
            None
        };

<<<<<<< HEAD
        Self {
            use_cache,
            yaml_file,
            rules_file,
            settings_file,
            config_map_files: cm_files,
            silent_unsupported_fields,
            raw_out,
            base64_out,
=======
        let rules_file = format!("{}/rules.rego", &args.input_files_path);
        debug!("Rules file: {rules_file}");

        let settings_file = format!("{}/{}", &args.input_files_path, &args.settings_file_name);
        debug!("Settings file: {settings_file}");

        Self {
            use_cache: args.use_cached_files,
            yaml_file: args.yaml_file,
            rules_file,
            settings_file,
            config_map_files: cm_files,
            silent_unsupported_fields: args.silent_unsupported_fields,
            raw_out: args.raw_out,
            base64_out: args.base64_out,
>>>>>>> upstream/main
        }
    }
}
