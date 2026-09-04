// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate slog;

logging::logger_with_subsystem!(sl, "virt-container");

mod container_manager;
pub mod factory;
pub mod health_check;
pub mod sandbox;
pub mod sandbox_persist;

use std::path::Path;
use std::sync::Arc;

use agent::{kata::KataAgent, Agent, AGENT_KATA};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use common::{message::Message, types::SandboxConfig, RuntimeHandler, RuntimeInstance};
use hypervisor::Hypervisor;
#[cfg(all(
    feature = "dragonball",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use hypervisor::{dragonball::Dragonball, HYPERVISOR_DRAGONBALL};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use hypervisor::{firecracker::Firecracker, HYPERVISOR_FIRECRACKER};
use hypervisor::{qemu::Qemu, HYPERVISOR_QEMU};
use hypervisor::{remote::Remote, HYPERVISOR_REMOTE};
#[cfg(all(
    feature = "dragonball",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use kata_types::config::DragonballConfig;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kata_types::config::FirecrackerConfig;
use kata_types::config::RemoteConfig;
use kata_types::config::{hypervisor::register_hypervisor_plugin, Factory, QemuConfig, TomlConfig};

#[cfg(all(
    feature = "cloud-hypervisor",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use hypervisor::ch::CloudHypervisor;
#[cfg(all(
    feature = "cloud-hypervisor",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use kata_types::config::{hypervisor::HYPERVISOR_NAME_CH, CloudHypervisorConfig};

#[cfg(all(
    feature = "openvmm",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use hypervisor::{openvmm::OpenVmm, HYPERVISOR_NAME_OPENVMM};
#[cfg(all(
    feature = "openvmm",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use kata_types::config::OpenVmmConfig;

use crate::factory::{template::Template, vm::VmConfig};
use resource::cpu_mem::initial_size::InitialSizeManager;
use resource::ResourceManager;
use sandbox::VIRTCONTAINER;
use tokio::sync::mpsc::Sender;
use tracing::instrument;

unsafe impl Send for VirtContainer {}
unsafe impl Sync for VirtContainer {}
#[derive(Debug)]
pub struct VirtContainer {}

#[async_trait]
impl RuntimeHandler for VirtContainer {
    fn init() -> Result<()> {
        // Before start logging with virt-container, regist it
        logging::register_subsystem_logger("runtimes", "virt-container");

        // register
        #[cfg(all(
            feature = "dragonball",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            let dragonball_config = Arc::new(DragonballConfig::new());
            register_hypervisor_plugin("dragonball", dragonball_config);
        }

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let firecracker_config = Arc::new(FirecrackerConfig::new());
            register_hypervisor_plugin("firecracker", firecracker_config);
        }

        let qemu_config = Arc::new(QemuConfig::new());
        register_hypervisor_plugin("qemu", qemu_config);

        #[cfg(all(
            feature = "cloud-hypervisor",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            let ch_config = Arc::new(CloudHypervisorConfig::new());
            register_hypervisor_plugin(HYPERVISOR_NAME_CH, ch_config);
        }

        let remote_config = Arc::new(RemoteConfig::new());
        register_hypervisor_plugin("remote", remote_config);

        #[cfg(all(
            feature = "openvmm",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            let openvmm_config = Arc::new(OpenVmmConfig::new());
            register_hypervisor_plugin(HYPERVISOR_NAME_OPENVMM, openvmm_config);
        }

        Ok(())
    }

    fn name() -> String {
        VIRTCONTAINER.to_string()
    }

    fn new_handler() -> Arc<dyn RuntimeHandler> {
        Arc::new(VirtContainer {})
    }

    #[instrument]
    async fn new_instance(
        &self,
        sid: &str,
        msg_sender: Sender<Message>,
        config: Arc<TomlConfig>,
        init_size_manager: InitialSizeManager,
        sandbox_config: SandboxConfig,
    ) -> Result<RuntimeInstance> {
        let (hypervisor, agent, factory) = new_vm_components(&config).await?;

        let resource_manager = Arc::new(
            ResourceManager::new(
                sid,
                agent.clone(),
                hypervisor.clone(),
                config,
                init_size_manager,
            )
            .await?,
        );
        let pid = std::process::id();

        let sandbox = sandbox::VirtSandbox::new(
            sid,
            msg_sender,
            agent.clone(),
            hypervisor.clone(),
            resource_manager.clone(),
            sandbox_config,
            factory,
        )
        .await
        .context("new virt sandbox")?;
        let container_manager = container_manager::VirtContainerManager::new(
            sid,
            pid,
            agent,
            hypervisor,
            resource_manager,
        );
        Ok(RuntimeInstance {
            sandbox: Arc::new(sandbox),
            container_manager: Arc::new(container_manager),
        })
    }

    fn cleanup(&self, _id: &str) -> Result<()> {
        // TODO
        Ok(())
    }
}

async fn new_vm_components(
    toml_config: &TomlConfig,
) -> Result<(Arc<dyn Hypervisor>, Arc<dyn Agent>, Factory)> {
    let mut factory = toml_config.get_factory();
    if factory.enable_template {
        let template = Template::fetch(
            VmConfig::new(toml_config),
            Path::new(&factory.template_path).to_path_buf(),
        );

        match template {
            Ok(_) => match build_vm_from_template(toml_config).await {
                Ok((hypervisor, agent)) => return Ok((hypervisor, agent, factory)),
                Err(error) => warn!(
                    sl!(),
                    "failed to configure VM from factory, falling back to normal boot: {:#}", error
                ),
            },
            Err(error) => warn!(
                sl!(),
                "failed to get VM from factory, falling back to normal boot: {:#}", error
            ),
        }

        factory.enable_template = false;
    }

    let hypervisor = new_hypervisor(toml_config)
        .await
        .context("new hypervisor")?;
    let agent = new_agent(toml_config).context("new agent")? as Arc<dyn Agent>;
    Ok((hypervisor, agent, factory))
}

async fn build_vm_from_template(
    toml_config: &TomlConfig,
) -> Result<(Arc<dyn Hypervisor>, Arc<dyn Agent>)> {
    let hypervisor_name = toml_config.runtime.hypervisor_name.clone();
    let mut hypervisor_config = toml_config
        .hypervisor
        .get(&hypervisor_name)
        .cloned()
        .ok_or_else(|| anyhow!("hypervisor '{}' not found", hypervisor_name))?;
    let path = Path::new(&hypervisor_config.factory.template_path);
    hypervisor_config.file_backed_memory = Some(kata_types::config::hypervisor::FileBackedMemory {
        path: path.join("memory").to_string_lossy().to_string(),
        shared: false,
    });
    VmConfig::validate_hypervisor_config(&mut hypervisor_config)
        .context("validate template hypervisor config")?;

    let hypervisor = new_hypervisor_with_config(toml_config, &hypervisor_config)
        .await
        .context("new hypervisor")?;
    let agent = new_agent(toml_config).context("new agent")? as Arc<dyn agent::Agent>;

    Ok((hypervisor, agent))
}

async fn new_hypervisor(toml_config: &TomlConfig) -> Result<Arc<dyn Hypervisor>> {
    let hypervisor_name = &toml_config.runtime.hypervisor_name;
    let hypervisor_config = toml_config
        .hypervisor
        .get(hypervisor_name)
        .ok_or_else(|| anyhow!("failed to get hypervisor for {}", &hypervisor_name))
        .context("get hypervisor")?;

    new_hypervisor_with_config(toml_config, hypervisor_config).await
}

async fn new_hypervisor_with_config(
    toml_config: &TomlConfig,
    hypervisor_config: &kata_types::config::Hypervisor,
) -> Result<Arc<dyn Hypervisor>> {
    let hypervisor_name = &toml_config.runtime.hypervisor_name;

    // TODO: support other hypervisor
    // issue: https://github.com/kata-containers/kata-containers/issues/4634
    match hypervisor_name.as_str() {
        #[cfg(all(
            feature = "dragonball",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        HYPERVISOR_DRAGONBALL => {
            let hypervisor = Dragonball::new();
            hypervisor
                .set_hypervisor_config(hypervisor_config.clone())
                .await;
            if toml_config.runtime.use_passfd_io {
                hypervisor
                    .set_passfd_listener_port(toml_config.runtime.passfd_listener_port)
                    .await;
            }
            Ok(Arc::new(hypervisor))
        }
        HYPERVISOR_QEMU => {
            let hypervisor = Qemu::new();
            hypervisor
                .set_hypervisor_config(hypervisor_config.clone())
                .await;
            Ok(Arc::new(hypervisor))
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        HYPERVISOR_FIRECRACKER => {
            let hypervisor = Firecracker::new();
            hypervisor
                .set_hypervisor_config(hypervisor_config.clone())
                .await;
            Ok(Arc::new(hypervisor))
        }
        #[cfg(all(
            feature = "cloud-hypervisor",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        HYPERVISOR_NAME_CH => {
            let hypervisor = CloudHypervisor::new();
            hypervisor
                .set_hypervisor_config(hypervisor_config.clone())
                .await;
            Ok(Arc::new(hypervisor))
        }
        HYPERVISOR_REMOTE => {
            let hypervisor = Remote::new();
            hypervisor
                .set_hypervisor_config(hypervisor_config.clone())
                .await;
            Ok(Arc::new(hypervisor))
        }
        #[cfg(all(
            feature = "openvmm",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        HYPERVISOR_NAME_OPENVMM => {
            let hypervisor = OpenVmm::new();
            hypervisor
                .set_hypervisor_config(hypervisor_config.clone())
                .await;
            Ok(Arc::new(hypervisor))
        }
        _ => Err(anyhow!("Unsupported hypervisor {}", &hypervisor_name)),
    }
}

fn new_agent(toml_config: &TomlConfig) -> Result<Arc<KataAgent>> {
    let agent_name = &toml_config.runtime.agent_name;
    let agent_config = toml_config
        .agent
        .get(agent_name)
        .ok_or_else(|| anyhow!("failed to get agent for {}", &agent_name))
        .context("get agent")?;
    match agent_name.as_str() {
        AGENT_KATA => {
            let agent = KataAgent::new(agent_config.clone());
            Ok(Arc::new(agent))
        }
        _ => Err(anyhow!("Unsupported agent {}", &agent_name)),
    }
}

#[cfg(test)]
mod test {

    use super::*;

    fn default_toml_config_agent() -> Result<TomlConfig> {
        let config_content = r#"
[agent.kata]
container_pipe_size=1

[runtime]
agent_name="kata"
        "#;
        TomlConfig::load(config_content).map_err(|e| anyhow!("can not load config toml: {}", e))
    }

    #[test]
    fn test_new_agent() {
        let toml_config = default_toml_config_agent().unwrap();

        let res = new_agent(&toml_config);
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_new_hypervisor() {
        VirtContainer::init().unwrap();

        let toml_config = {
            let config_content = r#"
[hypervisor.qemu]
path = "/bin/echo"
kernel = "/bin/echo"
image = "/bin/echo"
firmware = ""

[runtime]
hypervisor_name="qemu"
"#;
            TomlConfig::load(config_content).map_err(|e| anyhow!("can not load config toml: {}", e))
        }
        .unwrap();

        let res = new_hypervisor(&toml_config).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_build_vm_from_template_uses_active_config() {
        VirtContainer::init().unwrap();

        let toml_config = TomlConfig::load(
            r#"
[hypervisor.qemu]
path = "/bin/echo"
kernel = "/bin/echo"
image = "/bin/echo"
default_memory = 768

[hypervisor.qemu.factory]
enable_template = true
template_path = "/run/vc/vm/active-template"

[agent.kata]
container_pipe_size = 1

[runtime]
hypervisor_name = "qemu"
agent_name = "kata"
"#,
        )
        .unwrap();

        let (hypervisor, _) = build_vm_from_template(&toml_config).await.unwrap();
        let hypervisor_config = hypervisor.hypervisor_config().await;

        assert_eq!(hypervisor_config.memory_info.default_memory, 768);
        assert_eq!(
            hypervisor_config.file_backed_memory.unwrap().path,
            "/run/vc/vm/active-template/memory"
        );
    }

    #[tokio::test]
    async fn test_missing_factory_template_falls_back_to_normal_boot() {
        VirtContainer::init().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let template_path = dir.path().join("missing-template");
        let toml_config = TomlConfig::load(&format!(
            r#"
[hypervisor.qemu]
path = "/bin/echo"
kernel = "/bin/echo"
image = "/bin/echo"
default_memory = 512

[hypervisor.qemu.factory]
enable_template = true
template_path = "{}"

[agent.kata]
container_pipe_size = 1

[runtime]
hypervisor_name = "qemu"
agent_name = "kata"
"#,
            template_path.display()
        ))
        .unwrap();

        let (hypervisor, _, factory) = new_vm_components(&toml_config).await.unwrap();
        let hypervisor_config = hypervisor.hypervisor_config().await;

        assert!(!factory.enable_template);
        assert!(hypervisor_config.file_backed_memory.is_none());
        assert_eq!(hypervisor_config.memory_info.default_memory, 512);
    }
}
