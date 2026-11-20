// Copyright 2025 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use common::RuntimeHandler;
use kata_sys_util::mount::umount_all;
use kata_types::config::TomlConfig;
use resource::cpu_mem::initial_size::InitialSizeManager;
use serde::{Deserialize, Serialize};
use slog::{error, info, warn};

use crate::factory::{template::Template, vm::VmConfig};
use crate::VirtContainer;

pub mod template;
pub mod vm;

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
        Self {
            template: toml_config.get_factory().enable_template,
            template_path: toml_config.get_factory().template_path,
            vm_config: VmConfig::new(toml_config),
        }
    }
}

/// Load and validate factory configuration.
///
/// Mirrors the shim's config pipeline: load and adjust, then size as a
/// sandbox with no resource limits so a clone restored for such a sandbox
/// matches the saved template VM.
fn load_and_validate_factory_config(
    config_path: Option<&Path>,
) -> Result<(TomlConfig, FactoryConfig)> {
    // adjust_config() needs the hypervisor plugins; kata-ctl does not register them.
    VirtContainer::init().context("initialize runtime handler")?;

    // An empty path makes load_from_file() probe the default locations.
    let config_path = config_path.map(Path::as_os_str).unwrap_or_default();
    let (mut toml_config, _) =
        TomlConfig::load_from_file(config_path).context("load toml config")?;

    InitialSizeManager::new_from(&HashMap::new())
        .context("construct static resource manager")?
        .setup_config(&mut toml_config)
        .context("apply static sandbox sizing")?;

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
            Template::fetch(config.vm_config.clone(), &toml_config, path)
                .await
                .context("fetch VM template")?;
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
    use super::*;

    #[test]
    fn load_factory_config_from_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("configuration.toml");
        fs::write(
            &config_path,
            r#"
[runtime]
hypervisor_name = "qemu"

[hypervisor.qemu]
path = "/bin/true"
kernel = "/bin/true"
image = "/bin/true"
default_memory = 512
shared_fs = "none"

[hypervisor.qemu.factory]
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
        // adjust_config() must have run: "none" is normalized to None.
        assert!(toml_config
            .hypervisor
            .get("qemu")
            .unwrap()
            .shared_fs
            .shared_fs
            .is_none());
    }

    #[test]
    fn load_factory_config_rejects_disabled_template() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("configuration.toml");
        fs::write(
            &config_path,
            r#"
[runtime]
hypervisor_name = "qemu"

[hypervisor.qemu]
path = "/bin/true"
kernel = "/bin/true"
image = "/bin/true"
"#,
        )
        .unwrap();

        let error = load_and_validate_factory_config(Some(&config_path)).unwrap_err();
        assert!(error.to_string().contains("vm factory is not enabled"));
    }

    fn load_factory_config_from_toml(contents: &str) -> Result<(TomlConfig, FactoryConfig)> {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("configuration.toml");
        fs::write(&config_path, contents).unwrap();
        load_and_validate_factory_config(Some(&config_path))
    }

    #[test]
    fn template_is_sized_like_a_sandbox_without_limits() {
        let (_, factory_config) = load_factory_config_from_toml(
            r#"
[runtime]
hypervisor_name = "qemu"
static_sandbox_resource_mgmt = true
static_sandbox_default_workload_mem = 512
static_sandbox_default_workload_vcpus = 1.5

[hypervisor.qemu]
path = "/bin/true"
kernel = "/bin/true"
image = "/bin/true"
default_memory = 0
default_vcpus = 0
overhead_memory = 64
overhead_vcpus = 0.5

[hypervisor.qemu.factory]
enable_template = true
"#,
        )
        .unwrap();

        let hv = &factory_config.vm_config.hypervisor_config;
        assert_eq!(hv.memory_info.default_memory, 576);
        assert_eq!(hv.cpu_info.default_vcpus, 2.0);
        assert_eq!(hv.cpu_info.default_maxvcpus, 2);
    }

    #[test]
    fn template_keeps_toml_sizes_without_static_resource_mgmt() {
        let (_, factory_config) = load_factory_config_from_toml(
            r#"
[runtime]
hypervisor_name = "qemu"
static_sandbox_resource_mgmt = false
static_sandbox_default_workload_mem = 512

[hypervisor.qemu]
path = "/bin/true"
kernel = "/bin/true"
image = "/bin/true"
default_memory = 256
default_vcpus = 2

[hypervisor.qemu.factory]
enable_template = true
"#,
        )
        .unwrap();

        let hv = &factory_config.vm_config.hypervisor_config;
        assert_eq!(hv.memory_info.default_memory, 256);
        assert_eq!(hv.cpu_info.default_vcpus, 2.0);
    }
}
