// Copyright 2025 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use common::RuntimeHandler;
use hypervisor::HYPERVISOR_NAME_CH;
use kata_sys_util::mount::umount_all;
use kata_types::config::TomlConfig;
use serde::{Deserialize, Serialize};
use slog::{error, info, warn};

use crate::factory::{template::Template, vm::VmConfig};
use crate::VirtContainer;

pub mod template;
pub mod vm;

/// Returns the path to the hypervisor's device-state artifact in the template directory.
pub(crate) fn template_device_state_path(hypervisor_name: &str, template_path: &Path) -> PathBuf {
    let state_file = match hypervisor_name {
        HYPERVISOR_NAME_CH => "state.json",
        _ => "state",
    };

    template_path.join(state_file)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FactoryConfig {
    /// Path to the directory where VM templates are stored.
    #[serde(default)]
    pub template_path: String,

    /// Full configuration of the virtual machine to be used.
    #[serde(default)]
    pub vm_config: VmConfig,

    /// Whether VM template feature is enabled.
    #[serde(default)]
    pub template: bool,
}

impl FactoryConfig {
    pub fn new(toml_config: &TomlConfig) -> Self {
        let mut vm_config = VmConfig::new(toml_config);
        if toml_config.runtime.static_sandbox_resource_mgmt {
            if vm_config.hypervisor_config.memory_info.default_memory == 0
                && toml_config.runtime.static_sandbox_default_workload_mem > 0
            {
                vm_config.hypervisor_config.memory_info.default_memory =
                    toml_config.runtime.static_sandbox_default_workload_mem;
            }

            if vm_config.hypervisor_config.cpu_info.default_vcpus == 0.0
                && toml_config.runtime.static_sandbox_default_workload_vcpus > 0.0
            {
                vm_config.hypervisor_config.cpu_info.default_vcpus =
                    toml_config.runtime.static_sandbox_default_workload_vcpus;
            }
        }

        Self {
            template: toml_config.get_factory().enable_template,
            template_path: toml_config.get_factory().template_path,
            vm_config,
        }
    }
}

/// Load and validate factory configuration
fn load_and_validate_factory_config(
    config_path: Option<&Path>,
) -> Result<(TomlConfig, FactoryConfig)> {
    VirtContainer::init().context("initialize runtime handler")?;

    let (toml_config, _) = match config_path {
        Some(path) => TomlConfig::load_from_file(path),
        None => TomlConfig::load_from_file(""),
    }
    .context("load toml config")?;

    let factory_config = FactoryConfig::new(&toml_config);

    if !factory_config.template {
        return Err(anyhow!("vm factory is not enabled"));
    }

    Ok((toml_config, factory_config))
}

pub async fn init_factory_command(config_path: Option<&Path>) -> Result<()> {
    let (toml_config, mut factory_config) = load_and_validate_factory_config(config_path)?;

    new_factory(&mut factory_config, toml_config, false)
        .await
        .context("new factory")?;

    info!(sl!(), "create vm factory successfully");

    Ok(())
}

pub async fn destroy_factory_command(config_path: Option<&Path>) -> Result<()> {
    let (toml_config, mut factory_config) = load_and_validate_factory_config(config_path)?;

    new_factory(&mut factory_config, toml_config, true)
        .await
        .context("new factory")?;

    close_factory(&mut factory_config).context(" close VM factory")?;

    info!(sl!(), "vm factory destroyed");
    Ok(())
}

pub async fn status_factory_command(config_path: Option<&Path>) -> Result<()> {
    let (toml_config, mut factory_config) = load_and_validate_factory_config(config_path)?;

    if new_factory(&mut factory_config, toml_config, true)
        .await
        .is_ok()
    {
        info!(sl!(), "vm factory is on");
    } else {
        info!(sl!(), "vm factory is off");
    }

    Ok(())
}

pub async fn new_factory(
    config: &mut FactoryConfig,
    toml_config: TomlConfig,
    fetch_only: bool,
) -> Result<()> {
    if !config.template {
        anyhow::bail!("template must be enabled");
    } else {
        VmConfig::validate_hypervisor_config(&mut config.vm_config.hypervisor_config)
            .context("validate hypervisor config")?;

        let path: PathBuf = config.template_path.clone().into();
        if fetch_only {
            Template::fetch(config.vm_config.clone(), path).context("fetch VM template")?;
        } else {
            Template::create(config.vm_config.clone(), toml_config, path)
                .await
                .context("initialize VM template factory")?;
        }
    }

    Ok(())
}

pub fn close_factory(config: &mut FactoryConfig) -> Result<()> {
    let state_path = Path::new(&config.template_path);

    // Check if the path exists
    if !state_path.exists() {
        warn!(
            sl!(),
            "Template path {:?} does not exist, skipping unmount", state_path
        );
        return Ok(());
    }

    // Use umount_all to unmount all filesystems at the mountpoint
    // First try normal umount (lazy_umount = false)
    if let Err(e) = umount_all(state_path, false) {
        error!(sl!(), "Normal umount failed for {:?}: {}", state_path, e);

        // If normal umount fails, try lazy umount (with MNT_DETACH flag)
        umount_all(state_path, true)
            .with_context(|| format!("Failed to lazy unmount {}", state_path.display()))?;

        info!(sl!(), "Lazy umount succeeded for {:?}", state_path);
    } else {
        info!(sl!(), "Normal umount succeeded for {:?}", state_path);
    }

    // Remove the directory after successful unmount
    fs::remove_dir_all(state_path)
        .with_context(|| format!("failed to remove {}", state_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use kata_types::config::Hypervisor;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn load_factory_config_from_explicit_path() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("configuration.toml");
        fs::write(
            &config_path,
            r#"
[runtime]
hypervisor_name = "clh"
static_sandbox_resource_mgmt = true
static_sandbox_default_workload_mem = 512
static_sandbox_default_workload_vcpus = 1.5

[hypervisor.clh]
path = "/bin/true"
kernel = "/bin/true"
image = "/bin/true"
shared_fs = "none"

[hypervisor.clh.factory]
enable_template = true
template_path = "/run/vc/vm/preview-template"
"#,
        )
        .unwrap();

        let (toml_config, factory_config) =
            load_and_validate_factory_config(Some(&config_path)).unwrap();

        assert!(factory_config.template);
        assert_eq!(factory_config.template_path, "/run/vc/vm/preview-template");
        assert_eq!(
            factory_config
                .vm_config
                .hypervisor_config
                .memory_info
                .default_memory,
            512
        );
        assert_eq!(
            factory_config
                .vm_config
                .hypervisor_config
                .cpu_info
                .default_vcpus,
            1.5
        );
        assert!(toml_config
            .hypervisor
            .get("clh")
            .unwrap()
            .shared_fs
            .shared_fs
            .is_none());
    }

    #[test]
    fn static_factory_defaults_only_replace_zero_base_sizes() {
        let mut config = TomlConfig::default();
        config.runtime.hypervisor_name = "clh".to_string();
        config.runtime.static_sandbox_resource_mgmt = true;
        config.runtime.static_sandbox_default_workload_mem = 512;
        config.runtime.static_sandbox_default_workload_vcpus = 1.5;
        config.hypervisor.insert(
            "clh".to_string(),
            Hypervisor {
                memory_info: kata_types::config::hypervisor::MemoryInfo {
                    default_memory: 256,
                    ..Default::default()
                },
                cpu_info: kata_types::config::hypervisor::CpuInfo {
                    default_vcpus: 2.0,
                    ..Default::default()
                },
                ..Default::default()
            },
        );

        let factory_config = FactoryConfig::new(&config);
        assert_eq!(
            factory_config
                .vm_config
                .hypervisor_config
                .memory_info
                .default_memory,
            256
        );
        assert_eq!(
            factory_config
                .vm_config
                .hypervisor_config
                .cpu_info
                .default_vcpus,
            2.0
        );

        config.runtime.static_sandbox_resource_mgmt = false;
        let hypervisor = config.hypervisor.get_mut("clh").unwrap();
        hypervisor.memory_info.default_memory = 0;
        hypervisor.cpu_info.default_vcpus = 0.0;

        let factory_config = FactoryConfig::new(&config);
        assert_eq!(
            factory_config
                .vm_config
                .hypervisor_config
                .memory_info
                .default_memory,
            0
        );
        assert_eq!(
            factory_config
                .vm_config
                .hypervisor_config
                .cpu_info
                .default_vcpus,
            0.0
        );
    }
}
