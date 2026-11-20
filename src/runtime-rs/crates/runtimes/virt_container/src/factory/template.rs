// Copyright 2025 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fmt::Debug;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hypervisor::{Hypervisor, VmSnapshot};
use kata_types::config::TomlConfig;
use nix::mount::{mount, MsFlags};
use slog::warn;

use crate::factory::vm::{TemplateVm, VmConfig};

/// Maximum time to wait for the Kata Agent to become ready when initializing a template VM.
const TEMPLATE_WAIT_FOR_AGENT: Duration = Duration::from_secs(2);

/// Headroom (in MB) on top of guest memory for the hypervisor's device-state artifacts.
const TEMPLATE_DEVICE_STATE_SIZE_MB: u32 = 8;

/// Return the snapshot implementation for `hypervisor`, or an error if it has none.
pub(crate) fn snapshot_support<'a>(
    hypervisor: &'a dyn Hypervisor,
    name: &str,
) -> Result<&'a dyn VmSnapshot> {
    hypervisor
        .snapshot()
        .ok_or_else(|| anyhow!("hypervisor '{name}' does not support VM snapshots"))
}

#[derive(Debug)]
pub struct Template {
    pub state_path: PathBuf,
    pub config: VmConfig,
}

impl Template {
    /// Creates a new Template instance with the given configuration and path.
    pub fn new(config: VmConfig, template_path: PathBuf) -> Self {
        Template {
            state_path: template_path,
            config,
        }
    }

    /// Return the existing template at `template_path`, or an error if the
    /// hypervisor does not recognise a complete snapshot there.
    pub async fn fetch(
        config: VmConfig,
        toml_config: &TomlConfig,
        template_path: PathBuf,
    ) -> Result<Box<Template>> {
        let t = Template::new(config, template_path);

        t.validate_template(toml_config)
            .await
            .context("no template vm found")?;

        Ok(Box::new(t))
    }

    /// Creates and saves a new template VM to disk.
    /// This will prepare template files, create a VM, and save its state.
    pub async fn create(
        config: VmConfig,
        toml_config: TomlConfig,
        template_path: PathBuf,
    ) -> Result<Box<Template>> {
        let t = Template::new(config, template_path);

        if t.validate_template(&toml_config).await.is_ok() {
            return Err(anyhow!(
                "There is already a VM template in {:?}",
                t.state_path
            ));
        }

        t.prepare_template_files()
            .context("prepare template files")?;
        t.save_to_template(toml_config)
            .await
            .context("create template files")?;

        Ok(Box::new(t))
    }

    /// Ask the hypervisor whether `state_path` holds a complete template.
    pub async fn validate_template(&self, toml_config: &TomlConfig) -> Result<()> {
        let hypervisor = TemplateVm::new_hypervisor(&self.config, toml_config)
            .await
            .context("new hypervisor")?;
        snapshot_support(hypervisor.as_ref(), &self.config.hypervisor_name)?
            .validate_snapshot(&self.state_path)
    }

    pub fn prepare_template_files(&self) -> Result<()> {
        // Create state directory
        std::fs::create_dir_all(&self.state_path)
            .context(format!("failed to create directory: {:?}", self.state_path))?;

        // Verify directory was created and is accessible
        if !self.state_path.exists() {
            return Err(anyhow!(
                "state path {:?} does not exist after creation",
                self.state_path
            ));
        }

        // Mount tmpfs to store template VM memory data in memory for:
        // - Accelerating VM cloning by avoiding disk I/O
        // - Enhancing security by keeping sensitive data in memory
        let opts = format!(
            "size={}M",
            self.config.hypervisor_config.memory_info.default_memory
                + TEMPLATE_DEVICE_STATE_SIZE_MB
        );
        mount(
            Some("tmpfs"),
            &self.state_path,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some(opts.as_str()),
        )
        .context(format!("failed to mount tmpfs at {:?}", self.state_path))?;

        // Verify mount successfully by checking if directory is still accessible
        if !self.state_path.is_dir() {
            return Err(anyhow!(
                "state path {:?} is not a directory after mount",
                self.state_path
            ));
        }

        Ok(())
    }

    pub async fn save_to_template(&self, toml_config: TomlConfig) -> Result<()> {
        let vm = TemplateVm::new_vm(self.config.clone(), toml_config)
            .await
            .context("new template vm")?;

        // Save the result so teardown still runs if any creation step fails.
        let result: Result<()> = async {
            vm.disconnect().await.context("disconnect template vm")?;

            // Sleep a bit to let the agent grpc server clean up
            // See: src/runtime/virtcontainers/factory/template/template_linux.go#L139-L145
            // When we close connection to the agent, it needs sometime to cleanup
            // and restart listening on the communication( serial or vsock) port.
            // That time can be saved if we sleep a bit to wait for the agent to
            // come around and start listening again. The sleep is only done when
            // creating new vm templates and saves time for every new vm that are
            // created from template, so it worth the invest.
            sleep(TEMPLATE_WAIT_FOR_AGENT);

            vm.pause().await.context("pause template vm")?;
            vm.save(&self.state_path).await.context("save template vm")
        }
        .await;

        let teardown_result = vm.teardown().await;

        if let Err(teardown_error) = teardown_result {
            if result.is_ok() {
                return Err(teardown_error);
            }
            warn!(
                sl!(),
                "failed to tear down template VM after template creation failed: {}",
                teardown_error
            );
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_validate_template_requires_hypervisor_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let template = Template::new(
            VmConfig {
                hypervisor_name: hypervisor::HYPERVISOR_QEMU.to_string(),
                ..Default::default()
            },
            dir.path().to_path_buf(),
        );
        let toml_config = TomlConfig::default();

        assert!(template.validate_template(&toml_config).await.is_err());

        std::fs::write(dir.path().join("state"), b"{}").unwrap();
        template.validate_template(&toml_config).await.unwrap();
    }

    #[tokio::test]
    async fn test_validate_template_rejects_unsupported_hypervisor() {
        let template = Template::new(
            VmConfig {
                hypervisor_name: "firecracker".to_string(),
                ..Default::default()
            },
            PathBuf::from("/template"),
        );

        let error = template
            .validate_template(&TomlConfig::default())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("Unsupported hypervisor"));
    }
}
