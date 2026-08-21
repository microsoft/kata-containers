// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::health_check::HealthCheck;
use agent::kata::KataAgent;
use agent::types::{KernelModule, SetPolicyRequest};
use agent::{
    self, Agent, GetGuestDetailsRequest, GetIPTablesRequest, SetIPTablesRequest, VolumeStatsRequest,
};
use anyhow::{anyhow, ensure, Context, Result};
use async_trait::async_trait;
use common::error::is_normal_oom_shutdown_error;
use common::types::utils::option_system_time_into;
use common::types::ContainerProcess;
use common::{
    message::{Action, Message},
    types::DEFAULT_SHM_SIZE,
};
use common::{
    types::{SandboxConfig, SandboxExitInfo, SandboxStatus},
    ContainerManager, Sandbox, SandboxNetworkEnv,
};

use containerd_shim_protos::events::task::{TaskExit, TaskOOM};
#[cfg(all(
    feature = "cloud-hypervisor",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use hypervisor::ch::CloudHypervisor;
use hypervisor::device::topology::PCIePort;
use hypervisor::device::util::{get_host_path, DEVICE_TYPE_CHAR};
use hypervisor::remote::Remote;
use hypervisor::VsockConfig;
use hypervisor::HYPERVISOR_REMOTE;
#[cfg(all(
    feature = "dragonball",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use hypervisor::{dragonball::Dragonball, HYPERVISOR_DRAGONBALL};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use hypervisor::{firecracker::Firecracker, HYPERVISOR_FIRECRACKER};
use hypervisor::{is_vfio_ap_device, VfioDeviceBase};
use hypervisor::{qemu::Qemu, HYPERVISOR_QEMU};
use hypervisor::{
    utils::{get_hvsock_path, uses_native_ccw_bus},
    HybridVsockConfig, DEFAULT_GUEST_VSOCK_CID,
};
use hypervisor::{BlockConfig, Hypervisor};
use hypervisor::{BlockDeviceAio, PortDeviceConfig};
use hypervisor::{ProtectionDeviceConfig, SevSnpConfig, TdxConfig};
use kata_sys_util::hooks::HookStates;
use kata_sys_util::protection::{available_guest_protection, GuestProtection};
use kata_sys_util::spec::load_oci_spec;
use kata_types::capabilities::CapabilityBits;
use kata_types::config::hypervisor::Hypervisor as HypervisorConfig;
#[cfg(all(
    feature = "cloud-hypervisor",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use kata_types::config::hypervisor::HYPERVISOR_NAME_CH;
use kata_types::config::{hypervisor::Factory, TomlConfig};
use kata_types::initdata::{calculate_initdata_digest, ProtectedPlatform};
use oci_spec::runtime as oci;
use persist::{self, sandbox_persist::Persist};
use pod_resources_rs::handle_cdi_devices;
use protobuf::SpecialFields;
use resource::coco_data::initdata::{
    kata_shared_init_data_path, InitDataConfig, KATA_INIT_DATA_IMAGE,
};
use resource::coco_data::initdata_block;
use resource::manager::ManagerArgs;
use resource::network::{dan_config_path, DanNetworkConfig, NetworkConfig, NetworkWithNetNsConfig};
use resource::{ResourceConfig, ResourceManager};
use runtime_spec as spec;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use strum::Display;
use tokio::sync::{mpsc::Sender, watch, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

pub(crate) const VIRTCONTAINER: &str = "virt_container";
const POD_SET_UID_ANNOTATION: &str = "io.podset/set_uid";

pub(crate) struct SandboxMembers {
    pod_set_uid: Option<String>,
    configs: HashMap<String, SandboxConfig>,
    active: HashSet<String>,
    started: HashSet<String>,
}

#[derive(Debug, PartialEq)]
enum MemberDeactivation {
    Legacy,
    AlreadyInactive,
    Removed { last: bool },
}

impl SandboxMembers {
    pub(crate) fn new(config: SandboxConfig) -> Self {
        let pod_set_uid = config
            .annotations
            .get(POD_SET_UID_ANNOTATION)
            .filter(|uid| !uid.is_empty())
            .cloned();
        let sid = config.sandbox_id.clone();
        Self {
            pod_set_uid,
            configs: HashMap::from([(sid.clone(), config)]),
            active: HashSet::from([sid]),
            started: HashSet::new(),
        }
    }

    fn legacy(sid: String) -> Self {
        Self {
            pod_set_uid: None,
            configs: HashMap::new(),
            active: HashSet::from([sid]),
            started: HashSet::new(),
        }
    }

    fn add(&mut self, config: SandboxConfig) -> Result<()> {
        let pod_set_uid = config
            .annotations
            .get(POD_SET_UID_ANNOTATION)
            .filter(|uid| !uid.is_empty());
        ensure!(
            self.pod_set_uid.as_ref() == pod_set_uid,
            "sandbox {} does not belong to this PodSet",
            config.sandbox_id
        );
        ensure!(
            self.pod_set_uid.is_some(),
            "cannot add a sandbox to a non-PodSet VM"
        );
        if self.configs.contains_key(&config.sandbox_id) {
            return Ok(());
        }
        self.active.insert(config.sandbox_id.clone());
        self.configs.insert(config.sandbox_id.clone(), config);
        Ok(())
    }

    pub(crate) fn is_pod_set(&self) -> bool {
        self.pod_set_uid.is_some()
    }

    fn deactivate(&mut self, sandbox_id: &str) -> MemberDeactivation {
        if !self.is_pod_set() || !self.configs.contains_key(sandbox_id) {
            return MemberDeactivation::Legacy;
        }
        if !self.active.remove(sandbox_id) {
            return MemberDeactivation::AlreadyInactive;
        }
        MemberDeactivation::Removed {
            last: self.active.is_empty(),
        }
    }

    fn begin_start(&mut self, sandbox_id: &str) -> Result<Option<SandboxConfig>> {
        let config = self
            .configs
            .get(sandbox_id)
            .cloned()
            .with_context(|| format!("sandbox {sandbox_id} is not registered"))?;
        if !self.is_pod_set() || !self.started.insert(sandbox_id.to_string()) {
            return Ok(None);
        }
        Ok(Some(config))
    }

    fn start_failed(&mut self, sandbox_id: &str) {
        self.started.remove(sandbox_id);
    }

    fn is_active(&self, sandbox_id: &str) -> bool {
        self.active.contains(sandbox_id)
    }

    fn has_active_members(&self) -> bool {
        !self.active.is_empty()
    }

    pub(crate) fn contains(&self, sandbox_id: &str) -> bool {
        self.configs.contains_key(sandbox_id)
    }
}

pub struct SandboxRestoreArgs {
    pub sid: String,
    pub toml_config: TomlConfig,
    pub sender: Sender<Message>,
}

#[derive(Clone, Copy, PartialEq, Debug, Display)]
pub enum SandboxState {
    Init,
    Running,
    Stopped,
}

impl SandboxState {
    fn to_cri_state(self) -> &'static str {
        match self {
            SandboxState::Running => "SANDBOX_READY",
            SandboxState::Init | SandboxState::Stopped => "SANDBOX_NOTREADY",
        }
    }
}

struct SandboxInner {
    state: SandboxState,
    exit_info: Option<SandboxExitInfo>,
    created_at: Option<SystemTime>,
}

impl SandboxInner {
    pub fn new() -> Self {
        Self {
            state: SandboxState::Init,
            exit_info: None,
            created_at: None,
        }
    }
}

#[derive(Clone)]
pub struct VirtSandbox {
    sid: String,
    msg_sender: Arc<Mutex<Sender<Message>>>,
    inner: Arc<RwLock<SandboxInner>>,
    resource_manager: Arc<ResourceManager>,
    agent: Arc<dyn Agent>,
    hypervisor: Arc<dyn Hypervisor>,
    monitor: Arc<HealthCheck>,
    exit_notify_tx: watch::Sender<bool>,
    sandbox_config: Option<SandboxConfig>,
    shm_size: u64,
    factory: Option<Factory>,
    cancel_token: CancellationToken,
    members: Arc<RwLock<SandboxMembers>>,
}

impl std::fmt::Debug for VirtSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtSandbox")
            .field("sid", &self.sid)
            .field("msg_sender", &self.msg_sender)
            .field("inner", &"<SandboxInner>")
            .field("resource_manager", &self.resource_manager)
            .field("agent", &"<Agent>")
            .field("hypervisor", &self.hypervisor)
            .field("monitor", &"<HealthCheck>")
            .field("exit_notify_tx", &"<watch::Sender<bool>>")
            .field("sandbox_config", &self.sandbox_config)
            .field("factory", &self.factory)
            .finish()
    }
}

impl VirtSandbox {
    pub(crate) async fn new(
        sid: &str,
        msg_sender: Sender<Message>,
        agent: Arc<dyn Agent>,
        hypervisor: Arc<dyn Hypervisor>,
        resource_manager: Arc<ResourceManager>,
        sandbox_config: SandboxConfig,
        factory: Factory,
    ) -> Result<Self> {
        let config = resource_manager.config().await;
        let keep_abnormal = config.runtime.keep_abnormal;
        let (exit_notify_tx, _) = watch::channel(false);
        let cancel_token = CancellationToken::new();
        Ok(Self {
            sid: sid.to_string(),
            msg_sender: Arc::new(Mutex::new(msg_sender)),
            inner: Arc::new(RwLock::new(SandboxInner::new())),
            agent,
            hypervisor,
            resource_manager,
            monitor: Arc::new(HealthCheck::new(true, keep_abnormal)),
            exit_notify_tx,
            shm_size: sandbox_config.shm_size,
            members: Arc::new(RwLock::new(SandboxMembers::new(sandbox_config.clone()))),
            sandbox_config: Some(sandbox_config),
            factory: Some(factory),
            cancel_token,
        })
    }

    pub(crate) fn members(&self) -> Arc<RwLock<SandboxMembers>> {
        self.members.clone()
    }

    async fn start_pod_sandbox(&self, sandbox_id: &str, setup_network: bool) -> Result<()> {
        let config = {
            let mut members = self.members.write().await;
            members.begin_start(sandbox_id)?
        };
        let Some(config) = config else {
            return Ok(());
        };
        let request = agent::CreatePodSandboxRequest {
            hostname: config.hostname.clone(),
            dns: config.dns.clone(),
            sandbox_id: sandbox_id.to_string(),
        };
        if let Err(error) = self.agent.create_pod_sandbox(request).await {
            self.members.write().await.start_failed(sandbox_id);
            return Err(error).context("create pod sandbox");
        }
        let setup_result = async {
            if setup_network {
                if let Some(netns_path) = config.network_env.netns {
                    let runtime_config = self.resource_manager.config().await;
                    if !runtime_config.runtime.disable_new_netns
                        && !dan_config_path(&runtime_config, &self.sid).exists()
                    {
                        self.resource_manager
                            .setup_pod_network(
                                NetworkConfig::NetNs(NetworkWithNetNsConfig {
                                    network_model: runtime_config
                                        .runtime
                                        .internetworking_model
                                        .clone(),
                                    netns_path,
                                    queues: self
                                        .hypervisor
                                        .hypervisor_config()
                                        .await
                                        .network_info
                                        .network_queues
                                        as usize,
                                    network_created: config.network_env.network_created,
                                }),
                                sandbox_id,
                            )
                            .await
                            .context("setup pod network")?;
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = setup_result {
            self.members.write().await.start_failed(sandbox_id);
            let _ = self
                .agent
                .destroy_pod_sandbox(agent::DestroyPodSandboxRequest {
                    sandbox_id: sandbox_id.to_string(),
                })
                .await;
            return Err(error);
        }
        Ok(())
    }

    async fn stop_vm(&self) -> Result<()> {
        let state = self.inner.read().await.state;
        if state == SandboxState::Stopped {
            return Ok(());
        }

        self.cancel_token.cancel();
        info!(sl!(), "begin stop sandbox");
        if state == SandboxState::Init {
            let _ = self.hypervisor.stop_vm().await;
            self.record_stop(0, SystemTime::now()).await;
            info!(sl!(), "sandbox stopped during Init");
            return Ok(());
        }

        self.hypervisor.stop_vm().await.context("stop vm")?;
        self.wait_for_vm_exit()
            .await
            .context("wait for vm exit after stop")?;
        info!(sl!(), "sandbox stopped");
        Ok(())
    }

    async fn wait_for_vm_exit(&self) -> Result<SandboxExitInfo> {
        if self.inner.read().await.state == SandboxState::Stopped {
            return Ok(self
                .inner
                .read()
                .await
                .exit_info
                .clone()
                .unwrap_or_default());
        }
        let mut exit_notify_rx = self.exit_notify_tx.subscribe();
        while !*exit_notify_rx.borrow() {
            exit_notify_rx
                .changed()
                .await
                .context("wait for sandbox stop notification")?;
        }
        Ok(self
            .inner
            .read()
            .await
            .exit_info
            .clone()
            .unwrap_or_default())
    }

    pub fn get_agent(&self) -> Arc<dyn Agent> {
        self.agent.clone()
    }

    pub fn get_sid(&self) -> String {
        self.sid.clone()
    }

    pub fn get_hypervisor(&self) -> Arc<dyn Hypervisor> {
        self.hypervisor.clone()
    }

    async fn record_stop(&self, exit_status: u32, exited_at: std::time::SystemTime) {
        let mut inner = self.inner.write().await;
        if inner.state == SandboxState::Stopped {
            return;
        }

        inner.state = SandboxState::Stopped;
        inner.exit_info = Some(SandboxExitInfo {
            exit_status,
            exited_at: Some(exited_at),
        });
        let _ = self.exit_notify_tx.send(true);
    }

    #[instrument]
    async fn prepare_for_start_sandbox(
        &self,
        id: &str,
        sandbox_config: &SandboxConfig,
    ) -> Result<Vec<ResourceConfig>> {
        let mut resource_configs = vec![];

        info!(sl!(), "prepare vm socket config for sandbox.");
        let vm_socket_config = self
            .prepare_vm_socket_config()
            .await
            .context("failed to prepare vm socket config")?;
        resource_configs.push(vm_socket_config);

        let network_env: SandboxNetworkEnv = sandbox_config.network_env.clone();
        // prepare network config
        if !network_env.network_created {
            if let Some(network_resource) = self.prepare_network_resource(&network_env).await {
                resource_configs.push(network_resource);
            }
        }

        // prepare sharefs device config
        let virtio_fs_config =
            ResourceConfig::ShareFs(self.hypervisor.hypervisor_config().await.shared_fs);
        resource_configs.push(virtio_fs_config);

        // prepare VM rootfs device config
        if let Some(block_config) = self
            .prepare_rootfs_config()
            .await
            .context("failed to prepare rootfs device config")?
        {
            let vm_rootfs = ResourceConfig::VmRootfs(block_config);
            resource_configs.push(vm_rootfs);
        }

        // prepare protection device config
        let init_data = if let Some(initdata) = self
            .prepare_initdata_device_config(&self.hypervisor.hypervisor_config().await)
            .await
            .context("failed to prepare initdata device config")?
        {
            resource_configs.push(ResourceConfig::InitData(initdata.0));

            Some(initdata.1)
        } else {
            None
        };

        // Cold-plug VFIO devices using two mutually exclusive paths:
        // 1. CDI path: Query Kubernetes Pod Resources API for devices managed by device plugins
        //    (typical in K8s environments with device plugins)
        // 2. Raw VFIO path: Parse OCI spec's linux.devices for directly specified VFIO devices
        //    (typical in standalone containers like `ctr --device /dev/vfio/0`)
        //
        // These paths are mutually exclusive from a user perspective:
        // - In K8s, devices come through device plugins, not raw OCI device specs
        // - In standalone containers, there's no Pod Resources API available
        //
        // Therefore, we only attempt the raw VFIO path if CDI finds no devices,
        // avoiding unnecessary file I/O and OCI spec parsing in the common K8s case.
        let mut vfio_devices = self.prepare_coldplug_cdi_devices(sandbox_config).await?;
        if vfio_devices.is_empty() {
            let raw_vfio = self
                .prepare_coldplug_raw_vfio_devices(sandbox_config)
                .await?;
            vfio_devices.extend(raw_vfio);
        }
        if !vfio_devices.is_empty() {
            info!(
                sl!(),
                "prepare pod devices {vfio_devices:?} for sandbox done."
            );
            resource_configs.extend(vfio_devices);
        } else {
            info!(sl!(), "no pod devices to prepare for sandbox.");
        }

        // prepare protection device config
        if let Some(protection_dev_config) = self
            .prepare_protection_device_config(&self.hypervisor.hypervisor_config().await, init_data)
            .await
            .context("failed to prepare protection device config")?
        {
            resource_configs.push(ResourceConfig::Protection(protection_dev_config));
        }

        // prepare pcie port device config
        if let Some(port_dev_config) = self.prepare_pcie_port_devices().await {
            resource_configs.push(ResourceConfig::PortDevice(port_dev_config));
        }

        Ok(resource_configs)
    }

    async fn prepare_pcie_port_devices(&self) -> Option<PortDeviceConfig> {
        // Fetch the device manager and read the PCIe topology
        let device_manager = self.resource_manager.get_device_manager().await;
        let dm = device_manager.read().await;

        // Get the PCIe topology and port information
        match dm.get_pcie_topology().and_then(|t| t.get_pcie_port()) {
            Some((port_type, total_ports)) if total_ports > 0 => {
                info!(
                    sl!(),
                    "Preparing PCIe {:?} with {} devices for VM.", port_type, total_ports
                );
                Some(PortDeviceConfig::new(port_type, total_ports))
            }
            Some((_, 0)) => {
                info!(sl!(), "No PCIe ports available for VM.");
                None
            }
            _ => {
                info!(
                    sl!(),
                    "Invalid PCIe configuration or no topology available."
                );
                None
            }
        }
    }

    async fn prepare_coldplug_cdi_devices(
        &self,
        sandbox_config: &SandboxConfig,
    ) -> Result<Vec<ResourceConfig>> {
        let hypervisor_config = self.hypervisor.hypervisor_config().await;
        let cold_plug_vfio = &hypervisor_config.device_info.cold_plug_vfio;
        if cold_plug_vfio.is_empty() || cold_plug_vfio == "no-port" {
            return Ok(Vec::new());
        }

        let port = match cold_plug_vfio.as_str() {
            "root-port" => PCIePort::RootPort,
            other => {
                return Err(anyhow!(
                    "unsupported cold_plug_vfio value {:?}; only \"root-port\" is supported",
                    other
                ))
            }
        };

        let config = self.resource_manager.config().await;
        let pod_resource_socket = &config.runtime.pod_resource_api_sock;
        info!(
            sl!(),
            "sandbox pod_resource_socket: {:?}", pod_resource_socket
        );
        if pod_resource_socket.is_empty() || !Path::new(pod_resource_socket).exists() {
            return Ok(Vec::new());
        }

        let annotations = &sandbox_config.annotations;
        debug!(
            sl!(),
            "cold-plug: sandbox-name={:?} sandbox-namespace={:?}",
            annotations.get("io.kubernetes.cri.sandbox-name"),
            annotations.get("io.kubernetes.cri.sandbox-namespace")
        );

        let cdi_devices =
            pod_resources_rs::pod_resources::get_pod_cdi_devices(pod_resource_socket, annotations)
                .await
                .context("failed to query Pod Resources CDI devices")?;
        info!(sl!(), "pod cdi devices: {:?}", cdi_devices);

        let device_nodes = handle_cdi_devices(&cdi_devices).await?;
        let paths: Vec<String> = device_nodes
            .iter()
            .filter_map(pod_resources_rs::device_node_host_path)
            .collect();

        let mut vfio_configs = Vec::new();
        for path in paths.iter() {
            let dev_info = VfioDeviceBase {
                host_path: path.clone(),
                iommu_group_devnode: PathBuf::from(path),
                dev_type: "c".to_string(),
                port,
                hostdev_prefix: "vfio_device".to_owned(),
                ..Default::default()
            };
            vfio_configs.push(dev_info);
        }

        Ok(vfio_configs
            .into_iter()
            .map(ResourceConfig::VfioDeviceModern)
            .collect())
    }

    // Fallback cold-plug path for standalone containers (e.g. `ctr --device /dev/vfio/0`).
    // Reads the OCI spec from the bundle and cold-plugs any VFIO char devices found in
    // linux.devices before VM boot, mirroring Go's coldOrHotPlugVFIO().
    // Returns empty when the pod resources API path already handles devices (K8s) or
    // when cold_plug_vfio is not configured.
    async fn prepare_coldplug_raw_vfio_devices(
        &self,
        sandbox_config: &SandboxConfig,
    ) -> Result<Vec<ResourceConfig>> {
        let hypervisor_config = self.hypervisor.hypervisor_config().await;
        let cold_plug_vfio = &hypervisor_config.device_info.cold_plug_vfio;
        if cold_plug_vfio.is_empty() || cold_plug_vfio == "no-port" {
            return Ok(Vec::new());
        }

        let port = match cold_plug_vfio.as_str() {
            "root-port" => PCIePort::RootPort,
            other => {
                return Err(anyhow!(
                    "unsupported cold_plug_vfio value {:?}; only \"root-port\" is supported",
                    other
                ))
            }
        };

        let bundle = &sandbox_config.state.bundle;
        if bundle.is_empty() {
            return Ok(Vec::new());
        }

        let spec_path = format!("{}/{}", bundle, spec::OCI_SPEC_CONFIG_FILE_NAME);
        let oci_spec = match oci::Spec::load(&spec_path) {
            Ok(s) => s,
            Err(e) => {
                info!(
                    sl!(),
                    "no OCI spec at {:?}: {:?}, skipping raw VFIO cold-plug", spec_path, e
                );
                return Ok(Vec::new());
            }
        };

        let linux_devices = oci_spec
            .linux()
            .as_ref()
            .and_then(|l| l.devices().as_ref())
            .cloned()
            .unwrap_or_default();

        let mut vfio_configs = Vec::new();
        for d in linux_devices.iter() {
            if d.typ() != oci::LinuxDeviceType::C {
                continue;
            }
            let host_path = match get_host_path(DEVICE_TYPE_CHAR, d.major(), d.minor()) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        sl!(),
                        "failed to resolve host path for {:?}: {:?}",
                        d.path(),
                        e
                    );
                    continue;
                }
            };
            // Only process VFIO passthrough devices under /dev/vfio/*.
            // Skip non-VFIO devices and the legacy VFIO control node (/dev/vfio/vfio).
            if !host_path.starts_with("/dev/vfio/") || host_path == "/dev/vfio/vfio" {
                continue;
            }
            let device_port = if is_vfio_ap_device(Path::new(&host_path)) {
                PCIePort::NoPort
            } else {
                port
            };
            vfio_configs.push(VfioDeviceBase {
                host_path: host_path.clone(),
                iommu_group_devnode: PathBuf::from(&host_path),
                dev_type: "c".to_string(),
                port: device_port,
                hostdev_prefix: "vfio_device".to_owned(),
                ..Default::default()
            });
        }
        info!(sl!(), "raw VFIO cold-plug candidates: {:?}", vfio_configs);

        Ok(vfio_configs
            .into_iter()
            .map(ResourceConfig::VfioDeviceModern)
            .collect())
    }

    async fn prepare_network_resource(
        &self,
        network_env: &SandboxNetworkEnv,
    ) -> Option<ResourceConfig> {
        let config = self.resource_manager.config().await;
        let dan_path = dan_config_path(&config, &self.sid);

        // Network priority: DAN > NetNS
        if dan_path.exists() {
            Some(ResourceConfig::Network(NetworkConfig::Dan(
                DanNetworkConfig {
                    dan_conf_path: dan_path,
                },
            )))
        } else if let Some(netns_path) = network_env.netns.as_ref() {
            Some(ResourceConfig::Network(NetworkConfig::NetNs(
                NetworkWithNetNsConfig {
                    network_model: config.runtime.internetworking_model.clone(),
                    netns_path: netns_path.to_owned(),
                    queues: self
                        .hypervisor
                        .hypervisor_config()
                        .await
                        .network_info
                        .network_queues as usize,
                    network_created: network_env.network_created,
                },
            )))
        } else {
            None
        }
    }

    async fn execute_oci_hook_functions(
        &self,
        prestart_hooks: &[oci::Hook],
        create_runtime_hooks: &[oci::Hook],
        state: &spec::State,
    ) -> Result<()> {
        let mut st = state.clone();
        // for dragonball, we use vmm_master_tid
        let vmm_pid = self
            .hypervisor
            .get_vmm_master_tid()
            .await
            .context("get vmm master tid")?;
        st.pid = vmm_pid as i32;

        // Prestart Hooks [DEPRECATED in newest oci spec]:
        // * should be run in runtime namespace
        // * should be run after vm is started, but before container is created
        //      if Prestart Hook and CreateRuntime Hook are both supported
        // * spec details: https://github.com/opencontainers/runtime-spec/blob/c1662686cff159595277b79322d0272f5182941b/config.md#prestart
        let mut prestart_hook_states = HookStates::new();
        prestart_hook_states.execute_hooks(prestart_hooks, Some(st.clone()))?;

        // CreateRuntime Hooks:
        // * should be run in runtime namespace
        // * should be run when creating the runtime
        // * spec details: https://github.com/opencontainers/runtime-spec/blob/c1662686cff159595277b79322d0272f5182941b/config.md#createruntime-hooks
        let mut create_runtime_hook_states = HookStates::new();
        create_runtime_hook_states.execute_hooks(create_runtime_hooks, Some(st.clone()))?;
        Ok(())
    }

    // store_guest_details will get the information from the guest OS, like memory block size, agent details and is memory hotplug probe support
    async fn store_guest_details(&self) -> Result<()> {
        // get the information from agent
        let guest_details = self
            .agent
            .get_guest_details(GetGuestDetailsRequest {
                mem_block_size: true,
                mem_hotplug_probe: true,
            })
            .await
            .context("failed to store guest details")?;

        // set memory block size
        self.hypervisor
            .set_guest_memory_block_size(guest_details.mem_block_size_bytes as u32)
            .await;

        // set memory hotplug probe
        if guest_details.support_mem_hotplug_probe {
            self.hypervisor
                .set_capabilities(CapabilityBits::GuestMemoryProbe)
                .await;
        }
        info!(
            sl!(),
            "memory block size is {}, memory probe support {}",
            self.hypervisor.guest_memory_block_size().await,
            self.hypervisor
                .capabilities()
                .await?
                .is_mem_hotplug_probe_supported()
        );
        Ok(())
    }

    async fn prepare_rootfs_config(&self) -> Result<Option<BlockConfig>> {
        let boot_info = self.hypervisor.hypervisor_config().await.boot_info;
        let security_info = self.hypervisor.hypervisor_config().await.security_info;

        if !boot_info.initrd.is_empty() {
            return Ok(None);
        }

        if boot_info.image.is_empty() {
            let is_remote_hypervisor = Arc::clone(&self.resource_manager.config().await)
                .runtime
                .hypervisor_name
                == "remote";
            if (uses_native_ccw_bus() && security_info.confidential_guest) || is_remote_hypervisor {
                return Ok(None);
            } else {
                return Err(anyhow!("both of image and initrd isn't set"));
            }
        }

        Ok(Some(BlockConfig {
            path_on_host: boot_info.image.clone(),
            is_readonly: true,
            driver_option: boot_info.vm_rootfs_driver,
            ..Default::default()
        }))
    }

    async fn set_agent_policy(&self) -> Result<()> {
        // TODO: Exclude policy-related items from the annotations.
        let toml_config = self.resource_manager.config().await;
        if let Some(agent_config) = toml_config.agent.get(&toml_config.runtime.agent_name) {
            // If a Policy has been specified, send it to the agent.
            if !agent_config.policy.is_empty() {
                info!(
                    sl!(),
                    "Setting Agent Policy with {:?}.", &agent_config.policy
                );
                self.agent
                    .set_policy(SetPolicyRequest {
                        policy: agent_config.policy.clone(),
                    })
                    .await
                    .context("sandbox: set policy failed")?;
            }
        }

        Ok(())
    }

    async fn prepare_vm_socket_config(&self) -> Result<ResourceConfig> {
        // It will check the hypervisor's capabilities to see if it supports hybrid-vsock.
        // If it does not, it'll assume that it only supports legacy vsock.
        let vm_socket = if self
            .hypervisor
            .capabilities()
            .await?
            .is_hybrid_vsock_supported()
        {
            // Firecracker/Dragonball/CLH use the hybrid-vsock device model.
            ResourceConfig::HybridVsock(HybridVsockConfig {
                guest_cid: DEFAULT_GUEST_VSOCK_CID,
                uds_path: get_hvsock_path(&self.sid),
            })
        } else {
            // Qemu uses the vsock device model.
            ResourceConfig::Vsock(VsockConfig {
                guest_cid: libc::VMADDR_CID_ANY,
            })
        };

        Ok(vm_socket)
    }

    async fn prepare_protection_device_config(
        &self,
        hypervisor_config: &HypervisorConfig,
        init_data: Option<String>,
    ) -> Result<Option<ProtectionDeviceConfig>> {
        // No guest protection requested: skip host detection and run without
        // a protection device (also avoids failing on hosts that advertise a
        // protection they cannot use, e.g. SEV without SEV-SNP).
        if !hypervisor_config.security_info.confidential_guest {
            return Ok(None);
        }

        let available_protection = available_guest_protection()?;
        info!(
            sl!(),
            "sandbox: available protection: {:?}", available_protection
        );

        match available_protection {
            GuestProtection::Sev(details) => {
                if hypervisor_config.boot_info.firmware.is_empty() {
                    return Err(anyhow!("SEV protection requires a path to firmaware"));
                }

                Ok(Some(ProtectionDeviceConfig::SevSnp(SevSnpConfig {
                    is_snp: false,
                    cbitpos: details.cbitpos,
                    phys_addr_reduction: details.phys_addr_reduction,
                    firmware: hypervisor_config.boot_info.firmware.clone(),
                    host_data: None,
                })))
            }
            GuestProtection::Snp(details) => {
                if hypervisor_config.boot_info.firmware.is_empty() {
                    return Err(anyhow!("SEV-SNP protection requires a path to firmaware"));
                }

                // If we got here SEV-SNP is available.  However, if
                // 'sev_snp_guest' is 'false' in the configuration file we
                // still have to revert to SEV.
                let is_snp = hypervisor_config.security_info.sev_snp_guest;
                if !is_snp {
                    info!(sl!(), "reverting to SEV even though SEV-SNP is available as requested by 'sev_snp_guest'");
                }

                Ok(Some(ProtectionDeviceConfig::SevSnp(SevSnpConfig {
                    is_snp,
                    cbitpos: details.cbitpos,
                    phys_addr_reduction: details.phys_addr_reduction,
                    firmware: hypervisor_config.boot_info.firmware.clone(),
                    host_data: init_data,
                })))
            }
            GuestProtection::Se => {
                Ok(Some(ProtectionDeviceConfig::Se))
            }
            GuestProtection::Tdx => {
                Ok(Some(ProtectionDeviceConfig::Tdx(TdxConfig {
                    id: "tdx".to_owned(),
                    firmware: hypervisor_config.boot_info.firmware.clone(),
                    qgs_port: hypervisor_config.security_info.qgs_port,
                    mrconfigid: init_data,
                    debug: false,
                })))
            },
            GuestProtection::NoProtection => Ok(None),
            _ => Err(anyhow!("confidential_guest requested by configuration but no supported protection available"))
        }
    }

    async fn prepare_initdata_device_config(
        &self,
        hypervisor_config: &HypervisorConfig,
    ) -> Result<Option<InitDataConfig>> {
        let initdata = hypervisor_config.security_info.initdata.clone();
        if initdata.is_empty() {
            return Ok(None);
        }
        debug!(sl!(), "Init Data Content String: {:?}", &initdata);
        let available_protection = available_guest_protection()?;
        info!(
            sl!(),
            "sandbox: available protection: {:?}", available_protection
        );
        let initdata_digest = match available_protection {
            GuestProtection::Tdx => calculate_initdata_digest(&initdata, ProtectedPlatform::Tdx)?,
            GuestProtection::Snp(_details) => {
                calculate_initdata_digest(&initdata, ProtectedPlatform::Snp)?
            }
            GuestProtection::Se => calculate_initdata_digest(&initdata, ProtectedPlatform::Se)?,
            GuestProtection::NoProtection => {
                calculate_initdata_digest(&initdata, ProtectedPlatform::NoProtection)?
            }
            // TODO: there's more `GuestProtection` types to be supported.
            _ => return Ok(None),
        };
        info!(sl!(), "initdata  digest {:?}", &initdata_digest);

        // initdata within compressed rawblock
        let image_path = Path::new(kata_shared_init_data_path().as_str())
            .join(&self.sid)
            .join(KATA_INIT_DATA_IMAGE);
        initdata_block::push_data(&image_path, &initdata)?;
        info!(
            sl!(),
            "initdata push data into compressed block: {:?}", &image_path
        );
        let block_driver = &hypervisor_config.blockdev_info.block_device_driver;
        let block_config = BlockConfig {
            path_on_host: image_path.display().to_string(),
            is_readonly: true,
            driver_option: block_driver.clone(),
            blkdev_aio: BlockDeviceAio::Native,
            ..Default::default()
        };
        let initdata_config = InitDataConfig(block_config, initdata_digest);
        info!(sl!(), "initdata config: {:?}", initdata_config.clone());

        Ok(Some(initdata_config))
    }

    fn has_prestart_hooks(
        &self,
        prestart_hooks: &[oci::Hook],
        create_runtime_hooks: &[oci::Hook],
    ) -> bool {
        !prestart_hooks.is_empty() || !create_runtime_hooks.is_empty()
    }

    /// Build a network rescan config targeting the hypervisor's network
    /// namespace.  Docker 26+ bind-mounts `/proc/<vmm_pid>/ns/net` and
    /// configures veth pairs there between Create and Start, so the
    /// hypervisor netns is where the interfaces will appear — regardless
    /// of whether we earlier created a placeholder netns (network_created)
    /// or not.  This mirrors the Go shim's `detectHypervisorNetns` logic
    /// inside `addAllEndpoints` (commit f7878cc).
    async fn netns_rescan_config(&self) -> Option<NetworkWithNetNsConfig> {
        let toml = self.resource_manager.config().await;
        if toml.runtime.disable_new_netns {
            return None;
        }
        if dan_config_path(&toml, &self.sid).exists() {
            return None;
        }
        self.sandbox_config.as_ref()?;

        let vmm_pid = match self.hypervisor.get_vmm_master_tid().await {
            Ok(pid) => pid,
            Err(e) => {
                warn!(sl!(), "netns_rescan_config: cannot get VMM PID: {:?}", e);
                return None;
            }
        };
        let netns_path = format!("/proc/{}/ns/net", vmm_pid);

        let queues = self
            .hypervisor
            .hypervisor_config()
            .await
            .network_info
            .network_queues as usize;
        Some(NetworkWithNetNsConfig {
            network_model: toml.runtime.internetworking_model.clone(),
            netns_path,
            queues,
            network_created: false,
        })
    }
}

#[async_trait]
impl Sandbox for VirtSandbox {
    async fn add_sandbox(&self, config: SandboxConfig) -> Result<()> {
        self.members.write().await.add(config)
    }

    #[instrument(name = "sb: start")]
    async fn start(&self, sandbox_id: &str) -> Result<()> {
        let id = &self.sid;

        if self.sandbox_config.is_none() {
            return Err(anyhow!("sandbox config is missing"));
        }
        let sandbox_config = self.sandbox_config.as_ref().unwrap();

        // if sandbox is not in SandboxState::Init then return,
        // otherwise try to create sandbox

        let mut inner = self.inner.write().await;
        if inner.state != SandboxState::Init {
            drop(inner);
            return self.start_pod_sandbox(sandbox_id, true).await;
        }
        let selinux_label = load_oci_spec().ok().and_then(|spec| {
            spec.process()
                .as_ref()
                .and_then(|process| process.selinux_label().clone())
        });

        self.hypervisor
            .prepare_vm(
                id,
                sandbox_config.network_env.netns.clone(),
                &sandbox_config.annotations,
                selinux_label,
            )
            .await
            .context("prepare vm")?;

        // generate device and setup before start vm
        // should after hypervisor.prepare_vm
        let resources = self.prepare_for_start_sandbox(id, sandbox_config).await?;

        self.resource_manager
            .prepare_before_start_vm(resources)
            .await
            .context("set up device before start vm")?;

        // start vm
        self.hypervisor.start_vm(10_000).await.context("start vm")?;
        info!(sl!(), "start vm");

        let sandbox = self.clone();
        // wait for vm exit in background, and record the exit status and time when vm exited.
        tokio::spawn(async move {
            match sandbox.hypervisor.wait_vm().await {
                Ok(exit_code) => {
                    sandbox
                        .record_stop(exit_code as u32, SystemTime::now())
                        .await;
                }
                Err(err) => {
                    warn!(sl!(), "failed waiting for sandbox VM exit: {:?}", err);
                    sandbox.record_stop(255, SystemTime::now()).await;
                }
            }
        });

        // execute pre-start hook functions, including Prestart Hooks and CreateRuntime Hooks
        let (prestart_hooks, create_runtime_hooks) =
            if let Some(hooks) = sandbox_config.hooks.as_ref() {
                (
                    hooks.prestart().clone().unwrap_or_default(),
                    hooks.create_runtime().clone().unwrap_or_default(),
                )
            } else {
                (Vec::new(), Vec::new())
            };

        self.execute_oci_hook_functions(
            &prestart_hooks,
            &create_runtime_hooks,
            &sandbox_config.state,
        )
        .await?;

        // 1. if there are pre-start hook functions, network config might have been changed.
        //    We need to rescan the netns to handle the change.
        // 2. Do not scan the netns if we want no network for the VM.
        // TODO In case of vm factory, scan the netns to hotplug interfaces after the VM is started.
        let config = self.resource_manager.config().await;
        if self.has_prestart_hooks(&prestart_hooks, &create_runtime_hooks)
            && !config.runtime.disable_new_netns
            && !dan_config_path(&config, &self.sid).exists()
        {
            if let Some(netns_path) = &sandbox_config.network_env.netns {
                let network_resource = NetworkConfig::NetNs(NetworkWithNetNsConfig {
                    network_model: config.runtime.internetworking_model.clone(),
                    netns_path: netns_path.to_owned(),
                    queues: self
                        .hypervisor
                        .hypervisor_config()
                        .await
                        .network_info
                        .network_queues as usize,
                    network_created: sandbox_config.network_env.network_created,
                });
                self.resource_manager
                    .handle_network(network_resource)
                    .await
                    .context("set up device after start vm")?;
            }
        }

        // connect agent
        // set agent socket
        let address = self
            .hypervisor
            .get_agent_socket()
            .await
            .context("get agent socket")?;
        self.agent
            .start(&address)
            .await
            .context(format!("connect to address {:?}", &address))?;
        self.set_agent_policy().await.context("set agent policy")?;

        let pod_set = self.members.read().await.is_pod_set();
        if pod_set {
            self.start_pod_sandbox(sandbox_id, false).await?;
        }

        self.resource_manager
            .setup_after_start_vm(if pod_set { sandbox_id } else { "" })
            .await
            .context("setup device after start vm")?;

        // create sandbox in vm
        let agent_config = self.agent.agent_config().await;
        let kernel_modules = KernelModule::set_kernel_modules(agent_config.kernel_modules)?;
        let req = agent::CreateSandboxRequest {
            hostname: sandbox_config.hostname.clone(),
            dns: sandbox_config.dns.clone(),
            storages: self
                .resource_manager
                .get_storage_for_sandbox(self.shm_size)
                .await
                .context("get storages for sandbox")?,
            sandbox_pidns: false,
            sandbox_id: id.to_string(),
            guest_hook_path: self
                .hypervisor
                .hypervisor_config()
                .await
                .security_info
                .guest_hook_path,
            kernel_modules,
            pod_set_uid: sandbox_config
                .annotations
                .get(POD_SET_UID_ANNOTATION)
                .cloned()
                .unwrap_or_default(),
        };

        self.agent
            .create_sandbox(req)
            .await
            .context("create sandbox")?;

        inner.state = SandboxState::Running;
        inner.created_at = Some(std::time::SystemTime::now());

        // get and store guest details
        self.store_guest_details()
            .await
            .context("failed to store guest details")?;

        let agent = self.agent.clone();
        let sender = self.msg_sender.clone();
        let cancel_token = self.cancel_token.clone();

        info!(sl!(), "oom watcher start");
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        // Sandbox or VM is shutting down, gracefully exit watcher
                        info!(sl!(), "oom watcher cancelled, sandbox is stopping");
                        break;
                    }
                    res = agent.get_oom_event(agent::Empty::new()) => {
                        match res.context("get oom event") {
                            Ok(resp) => {
                                let cid = &resp.container_id;
                                warn!(sl!(), "send oom event for container {}", &cid);
                                let event = TaskOOM {
                                    container_id: cid.to_string(),
                                    ..Default::default()
                                };
                                let msg = Message::new(Action::Event(Arc::new(event)));
                                let lock_sender = sender.lock().await;
                                if let Err(err) = lock_sender.send(msg).await.context("send event") {
                                    error!(
                                        sl!(),
                                        "failed to send oom event for {} error {:?}", cid, err
                                    );
                                }
                            }
                            Err(err) => {
                                // Handle errors by type
                                if is_normal_oom_shutdown_error(&err) {
                                    info!(sl!(), "oom watcher exit on sandbox shutdown: {:?}", err);
                                    break;
                                } else {
                                    warn!(sl!(), "failed to get oom event error {:?}", err);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        });

        self.monitor.start(id, self.agent.clone());
        self.save().await.context("save state")?;

        Ok(())
    }

    /// Core function for starting a VM from a template
    ///
    /// This function is responsible for creating and starting a VM sandbox from a predefined template,
    /// serving as the core implementation of the template mechanism.
    async fn start_template(&self) -> Result<()> {
        info!(sl!(), "sandbox::start_template()"; "sandbox:" => format!("{:?}", self));
        let id = &self.sid;

        let sandbox_config = self.sandbox_config.as_ref().unwrap();

        // if sandbox is not in SandboxState::Init then return,
        // otherwise try to create sandbox
        let inner = self.inner.write().await;
        if inner.state != SandboxState::Init {
            return Ok(());
        }
        let selinux_label = load_oci_spec().ok().and_then(|spec| {
            spec.process()
                .as_ref()
                .and_then(|process| process.selinux_label().clone())
        });

        self.hypervisor
            .prepare_vm(
                id,
                sandbox_config.network_env.netns.clone(),
                &sandbox_config.annotations,
                selinux_label,
            )
            .await
            .context("prepare vm")?;

        // generate device and setup before start vm
        // should after hypervisor.prepare_vm
        let resources = self
            .prepare_for_start_sandbox(id, sandbox_config)
            .await
            .context("prepare resources before start vm")?;

        self.resource_manager
            .prepare_before_start_vm(resources)
            .await
            .context("set up device before start vm")?;

        self.hypervisor
            .start_vm(10_000)
            .await
            .context("start template vm")?;
        info!(sl!(), "vm started from template");

        let sandbox = self.clone();
        tokio::spawn(async move {
            match sandbox.hypervisor.wait_vm().await {
                Ok(exit_code) => {
                    sandbox
                        .record_stop(exit_code as u32, SystemTime::now())
                        .await;
                }
                Err(err) => {
                    warn!(sl!(), "failed waiting for sandbox VM exit: {:?}", err);
                    sandbox.record_stop(255, SystemTime::now()).await;
                }
            }
        });

        Ok(())
    }

    async fn status(&self, sandbox_id: &str) -> Result<SandboxStatus> {
        let inner = self.inner.read().await;
        let active = self.members.read().await.is_active(sandbox_id);
        let state = if active {
            inner.state.to_cri_state()
        } else {
            SandboxState::Stopped.to_cri_state()
        }
        .to_string();

        Ok(SandboxStatus {
            sandbox_id: sandbox_id.to_string(),
            pid: std::process::id(),
            state,
            info: std::collections::HashMap::new(),
            created_at: inner.created_at,
        })
    }

    async fn wait(&self, sandbox_id: &str) -> Result<SandboxExitInfo> {
        info!(sl!(), "wait sandbox");
        if !self.members.read().await.is_active(sandbox_id) {
            return Ok(SandboxExitInfo {
                exit_status: 0,
                exited_at: Some(SystemTime::now()),
            });
        }
        self.wait_for_vm_exit().await
    }

    async fn stop(&self, sandbox_id: &str) -> Result<()> {
        match self.members.write().await.deactivate(sandbox_id) {
            MemberDeactivation::Legacy => {}
            MemberDeactivation::AlreadyInactive => return Ok(()),
            MemberDeactivation::Removed { last } => {
                self.agent
                    .destroy_pod_sandbox(agent::DestroyPodSandboxRequest {
                        sandbox_id: sandbox_id.to_string(),
                    })
                    .await
                    .context("destroy pod sandbox")?;
                if !last {
                    return Ok(());
                }
            }
        }
        self.stop_vm().await
    }

    async fn shutdown(&self, sandbox_id: &str, force: bool) -> Result<()> {
        info!(sl!(), "shutdown");

        if force && !self.members.read().await.is_pod_set() {
            self.stop_vm().await.context("force stop")?;
        } else {
            self.stop(sandbox_id).await.context("stop")?;
            if self.members.read().await.has_active_members() {
                return Ok(());
            }
        }

        self.cleanup().await.context("do the clean up")?;

        info!(sl!(), "stop monitor");
        self.monitor.stop().await;

        info!(sl!(), "stop agent");
        self.agent.stop().await;

        // stop server
        info!(sl!(), "send shutdown message");
        let msg = Message::new(Action::Shutdown);
        let sender = self.msg_sender.clone();
        let sender = sender.lock().await;
        sender.send(msg).await.context("send shutdown msg")?;
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        info!(sl!(), "delete hypervisor");
        self.hypervisor
            .cleanup()
            .await
            .context("delete hypervisor")?;

        info!(sl!(), "resource clean up");
        self.resource_manager
            .cleanup()
            .await
            .context("resource clean up")?;

        // TODO: cleanup other sandbox resource
        Ok(())
    }

    async fn rescan_network(&self) -> Result<()> {
        if let Some(net_cfg) = self.netns_rescan_config().await {
            info!(
                sl!(),
                "rescan_network: scanning netns={}", net_cfg.netns_path
            );
            self.resource_manager
                .rescan_network_if_unconfigured(net_cfg)
                .await
                .context("network rescan during start")?;
        }
        Ok(())
    }

    async fn wait_process(
        &self,
        cm: Arc<dyn ContainerManager>,
        process_id: ContainerProcess,
        shim_pid: u32,
    ) -> Result<()> {
        let exit_status = cm.wait_process(&process_id).await?;
        info!(sl!(), "container process exited with {:?}", exit_status);

        if cm.is_sandbox_container(&process_id).await {
            self.stop(process_id.container_id())
                .await
                .context("stop sandbox")?;
        }

        let cid = process_id.container_id();
        if cid.is_empty() {
            return Err(anyhow!("container id is empty"));
        }
        let eid = process_id.exec_id();
        let id = if eid.is_empty() {
            cid.to_string()
        } else {
            eid.to_string()
        };

        let event = TaskExit {
            container_id: cid.to_string(),
            id,
            pid: shim_pid,
            exit_status: exit_status.exit_code as u32,
            exited_at: option_system_time_into(exit_status.exit_time),
            special_fields: SpecialFields::new(),
        };
        let msg = Message::new(Action::Event(Arc::new(event)));
        let lock_sender = self.msg_sender.lock().await;
        lock_sender.send(msg).await.context("send exit event")?;
        Ok(())
    }

    async fn agent_sock(&self) -> Result<String> {
        self.agent.agent_sock().await
    }

    async fn direct_volume_stats(&self, volume_guest_path: &str) -> Result<String> {
        let req: agent::VolumeStatsRequest = VolumeStatsRequest {
            volume_guest_path: volume_guest_path.to_string(),
        };
        let result = self
            .agent
            .get_volume_stats(req)
            .await
            .context("sandbox: failed to process direct volume stats query")?;
        Ok(result.data)
    }

    async fn direct_volume_resize(&self, resize_req: agent::ResizeVolumeRequest) -> Result<()> {
        self.agent
            .resize_volume(resize_req)
            .await
            .context("sandbox: failed to resize direct-volume")?;
        Ok(())
    }

    async fn set_iptables(&self, is_ipv6: bool, data: Vec<u8>) -> Result<Vec<u8>> {
        info!(sl!(), "sb: set_iptables invoked");
        let req = SetIPTablesRequest { is_ipv6, data };
        let resp = self
            .agent
            .set_ip_tables(req)
            .await
            .context("sandbox: failed to set iptables")?;
        Ok(resp.data)
    }

    async fn get_iptables(&self, is_ipv6: bool) -> Result<Vec<u8>> {
        info!(sl!(), "sb: get_iptables invoked");
        let req = GetIPTablesRequest { is_ipv6 };
        let resp = self
            .agent
            .get_ip_tables(req)
            .await
            .context("sandbox: failed to get iptables")?;
        Ok(resp.data)
    }

    async fn agent_metrics(&self) -> Result<String> {
        self.agent
            .get_metrics(agent::Empty::new())
            .await
            .map_err(|err| anyhow!("failed to get agent metrics {:?}", err))
            .map(|resp| resp.metrics)
    }

    async fn hypervisor_metrics(&self) -> Result<String> {
        self.hypervisor.get_hypervisor_metrics().await
    }

    async fn set_policy(&self, policy: &str) -> Result<()> {
        if policy.is_empty() {
            debug!(sl!(), "sb: set_policy skipped without policy");
            return Ok(());
        }

        info!(sl!(), "sb: set_policy invoked");
        let policy_req = SetPolicyRequest {
            policy: policy.to_string(),
        };
        self.agent
            .set_policy(policy_req)
            .await
            .context("sandbox: failed to set policy")?;

        Ok(())
    }
}

#[async_trait]
impl Persist for VirtSandbox {
    type State = crate::sandbox_persist::SandboxState;
    type ConstructorArgs = SandboxRestoreArgs;

    /// Save a state of Sandbox
    async fn save(&self) -> Result<Self::State> {
        let hypervisor_state = self.hypervisor.save_state().await?;
        let sandbox_state = crate::sandbox_persist::SandboxState {
            sandbox_type: VIRTCONTAINER.to_string(),
            resource: Some(self.resource_manager.save().await?),
            hypervisor: match hypervisor_state.hypervisor_type.as_str() {
                #[cfg(all(
                    feature = "dragonball",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                HYPERVISOR_DRAGONBALL => Ok(Some(hypervisor_state)),
                #[cfg(all(
                    feature = "cloud-hypervisor",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                HYPERVISOR_NAME_CH => Ok(Some(hypervisor_state)),
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                HYPERVISOR_FIRECRACKER => Ok(Some(hypervisor_state)),
                HYPERVISOR_QEMU => Ok(Some(hypervisor_state)),
                HYPERVISOR_REMOTE => Ok(Some(hypervisor_state)),
                _ => Err(anyhow!(
                    "Unsupported hypervisor {}",
                    hypervisor_state.hypervisor_type
                )),
            }?,
        };
        // FIXME: properly handle jailed case
        // eg: Determine if we are running jailed:
        // let h = sandbox_state.hypervisor.clone().unwrap_or_default();
        // Figure out the jailed path:
        // jailed_path = h.<>
        // and somehow store the sandbox state into the jail:
        // persist::to_disk(&sandbox_state, &self.sid, jailed_path)?;
        // Issue is, how to handle restore.
        let h = sandbox_state.hypervisor.as_ref().unwrap();
        let vmpath = match h.jailed {
            true => h.vm_path.clone(),
            false => "".to_string(),
        };
        persist::to_disk(&sandbox_state, &self.sid, vmpath.as_str())?;
        Ok(sandbox_state)
    }
    /// Restore Sandbox
    async fn restore(
        sandbox_args: Self::ConstructorArgs,
        sandbox_state: Self::State,
    ) -> Result<Self> {
        let config = sandbox_args.toml_config;
        let r = sandbox_state.resource.unwrap_or_default();
        let h = sandbox_state.hypervisor.unwrap_or_default();
        let hypervisor = match h.hypervisor_type.as_str() {
            #[cfg(all(
                feature = "dragonball",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            HYPERVISOR_DRAGONBALL => {
                let hypervisor = Arc::new(Dragonball::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            #[cfg(all(
                feature = "cloud-hypervisor",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            HYPERVISOR_NAME_CH => {
                let hypervisor =
                    Arc::new(CloudHypervisor::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            HYPERVISOR_FIRECRACKER => {
                let hypervisor =
                    Arc::new(Firecracker::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            HYPERVISOR_QEMU => {
                let hypervisor = Arc::new(Qemu::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            HYPERVISOR_REMOTE => {
                let hypervisor = Arc::new(Remote::restore((), h).await?) as Arc<dyn Hypervisor>;
                Ok(hypervisor)
            }
            _ => Err(anyhow!("Unsupported hypervisor {}", &h.hypervisor_type)),
        }?;
        let agent = Arc::new(KataAgent::new(kata_types::config::Agent::default()));
        let sid = sandbox_args.sid;
        let keep_abnormal = config.runtime.keep_abnormal;
        let args = ManagerArgs {
            sid: sid.clone(),
            agent: agent.clone(),
            hypervisor: hypervisor.clone(),
            config,
        };
        let resource_manager = Arc::new(ResourceManager::restore(args, r).await?);
        Ok(Self {
            sid: sid.to_string(),
            msg_sender: Arc::new(Mutex::new(sandbox_args.sender)),
            inner: Arc::new(RwLock::new(SandboxInner::new())),
            agent,
            hypervisor,
            resource_manager,
            monitor: Arc::new(HealthCheck::new(true, keep_abnormal)),
            exit_notify_tx: watch::channel(false).0,
            sandbox_config: None,
            shm_size: DEFAULT_SHM_SIZE,
            factory: None,
            cancel_token: CancellationToken::default(),
            members: Arc::new(RwLock::new(SandboxMembers::legacy(sid))),
        })
    }
}

#[cfg(test)]
mod pod_set_tests {
    use super::*;

    fn sandbox_config(sandbox_id: &str, pod_set_uid: Option<&str>) -> SandboxConfig {
        let mut annotations = HashMap::new();
        if let Some(uid) = pod_set_uid {
            annotations.insert(POD_SET_UID_ANNOTATION.to_string(), uid.to_string());
        }
        SandboxConfig {
            sandbox_id: sandbox_id.to_string(),
            hostname: sandbox_id.to_string(),
            dns: Vec::new(),
            network_env: SandboxNetworkEnv::default(),
            annotations,
            hooks: None,
            state: spec::State {
                version: Default::default(),
                id: sandbox_id.to_string(),
                status: spec::ContainerState::Creating,
                pid: 0,
                bundle: String::new(),
                annotations: HashMap::new(),
            },
            shm_size: 0,
        }
    }

    #[test]
    fn pod_set_members_are_symmetric() {
        let mut members = SandboxMembers::new(sandbox_config("sandbox-1", Some("set-1")));
        members
            .add(sandbox_config("sandbox-2", Some("set-1")))
            .unwrap();

        assert_eq!(
            members.deactivate("sandbox-1"),
            MemberDeactivation::Removed { last: false }
        );
        assert!(members.is_active("sandbox-2"));
        assert_eq!(
            members.deactivate("sandbox-2"),
            MemberDeactivation::Removed { last: true }
        );
    }

    #[test]
    fn pod_set_members_can_stop_in_reverse_order() {
        let mut members = SandboxMembers::new(sandbox_config("sandbox-1", Some("set-1")));
        members
            .add(sandbox_config("sandbox-2", Some("set-1")))
            .unwrap();

        assert_eq!(
            members.deactivate("sandbox-2"),
            MemberDeactivation::Removed { last: false }
        );
        assert!(members.is_active("sandbox-1"));
        assert_eq!(
            members.deactivate("sandbox-1"),
            MemberDeactivation::Removed { last: true }
        );
    }

    #[test]
    fn repeated_pod_set_stop_is_idempotent() {
        let mut members = SandboxMembers::new(sandbox_config("sandbox-1", Some("set-1")));
        members
            .add(sandbox_config("sandbox-2", Some("set-1")))
            .unwrap();

        assert_eq!(
            members.deactivate("sandbox-1"),
            MemberDeactivation::Removed { last: false }
        );
        assert_eq!(
            members.deactivate("sandbox-1"),
            MemberDeactivation::AlreadyInactive
        );
        assert!(members.is_active("sandbox-2"));
    }

    #[test]
    fn pod_set_rejects_member_from_another_set() {
        let mut members = SandboxMembers::new(sandbox_config("sandbox-1", Some("set-1")));

        let error = members
            .add(sandbox_config("sandbox-2", Some("set-2")))
            .unwrap_err()
            .to_string();

        assert!(error.contains("does not belong"));
    }

    #[test]
    fn repeated_pod_set_registration_keeps_original_config() {
        let mut members = SandboxMembers::new(sandbox_config("sandbox-1", Some("set-1")));
        let original = sandbox_config("sandbox-2", Some("set-1"));
        members.add(original).unwrap();

        let mut duplicate = sandbox_config("sandbox-2", Some("set-1"));
        duplicate.hostname = "replacement".to_string();
        members.add(duplicate).unwrap();

        assert_eq!(members.configs["sandbox-2"].hostname, "sandbox-2");
    }

    #[test]
    fn non_pod_set_keeps_legacy_lifecycle() {
        let mut members = SandboxMembers::new(sandbox_config("sandbox-1", None));

        assert_eq!(members.deactivate("sandbox-1"), MemberDeactivation::Legacy);
    }
}
