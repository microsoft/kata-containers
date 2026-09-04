// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use common::types::CompletedContainerSnapshot;
use oci_spec::runtime as oci;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use tokio::sync::{Mutex, MutexGuard};

pub(crate) const OCI_IDENTITY_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) enum RestoreActivation {
    Cold,
    RestoringPaused,
    PreparedPaused,
    Activating,
    Active,
    Failed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct RestoreIdentity {
    pub(crate) oci_identity_version: u32,
    pub(crate) oci_identity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct RestoreGuestMount {
    pub(crate) destination: String,
    pub(crate) guest_source: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RestoreLiveSlot {
    pub(crate) cri_name: String,
    pub(crate) guest_id: String,
    pub(crate) identity: RestoreIdentity,
    pub(crate) node_local_mounts: Vec<RestoreGuestMount>,
}

#[derive(Clone, Debug)]
pub(crate) struct RestoreCompletedSlot {
    pub(crate) cri_name: String,
    pub(crate) exit_code: i32,
    pub(crate) identity: RestoreIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RestoreCreateAction {
    Cold,
    AdoptLive { guest_id: String, is_pause: bool },
    SyntheticCompleted { exit_code: i32 },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LiveSlotState {
    guest_id: String,
    identity: RestoreIdentity,
    claimed_host_id: Option<String>,
    node_local_mounts: Vec<RestoreGuestMount>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CompletedSlotState {
    exit_code: i32,
    identity: RestoreIdentity,
    claimed_host_id: Option<String>,
    completion_pending: bool,
    restore_available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RestoreState {
    activation: RestoreActivation,
    source_sandbox_id: Option<String>,
    live_slots: HashMap<String, LiveSlotState>,
    completed_slots: HashMap<String, CompletedSlotState>,
    // Outbound agent RPC routing for target host IDs.
    host_to_guest: HashMap<String, String>,
    // Inbound guest event routing back to containerd IDs.
    guest_to_host: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RestorePersistState {
    version: u32,
    state: RestoreState,
}

#[derive(Debug)]
pub(crate) struct RestoreContext {
    target_sandbox_id: String,
    state: Mutex<RestoreState>,
    activation_lock: Mutex<()>,
}

impl RestoreContext {
    pub(crate) fn new(target_sandbox_id: &str) -> Self {
        Self {
            target_sandbox_id: target_sandbox_id.to_string(),
            state: Mutex::new(RestoreState {
                activation: RestoreActivation::Cold,
                source_sandbox_id: None,
                live_slots: HashMap::new(),
                completed_slots: HashMap::new(),
                host_to_guest: HashMap::new(),
                guest_to_host: HashMap::new(),
            }),
            activation_lock: Mutex::new(()),
        }
    }

    pub(crate) async fn begin(
        &self,
        source_sandbox_id: &str,
        live_slots: Vec<RestoreLiveSlot>,
        completed_slots: Vec<RestoreCompletedSlot>,
    ) -> Result<()> {
        if source_sandbox_id.is_empty() {
            return Err(anyhow!("snapshot restore identity is incomplete"));
        }
        let mut state = self.state.lock().await;
        if state.activation != RestoreActivation::Cold {
            return Err(anyhow!("restore is already initialized"));
        }
        let mut live_by_name = HashMap::new();
        for slot in live_slots {
            if slot.cri_name.is_empty()
                || slot.guest_id.is_empty()
                || live_by_name
                    .insert(
                        slot.cri_name,
                        LiveSlotState {
                            guest_id: slot.guest_id,
                            identity: slot.identity,
                            claimed_host_id: None,
                            node_local_mounts: slot.node_local_mounts,
                        },
                    )
                    .is_some()
            {
                return Err(anyhow!("snapshot live slot inventory is invalid"));
            }
        }
        if !live_by_name.contains_key("POD") {
            return Err(anyhow!("snapshot has no live pause slot"));
        }
        let mut completed_by_name = HashMap::new();
        for slot in completed_slots {
            if slot.cri_name.is_empty()
                || live_by_name.contains_key(&slot.cri_name)
                || completed_by_name
                    .insert(
                        slot.cri_name,
                        CompletedSlotState {
                            exit_code: slot.exit_code,
                            identity: slot.identity,
                            claimed_host_id: None,
                            completion_pending: true,
                            restore_available: true,
                        },
                    )
                    .is_some()
            {
                return Err(anyhow!("snapshot completed slot inventory is invalid"));
            }
        }
        state.activation = RestoreActivation::RestoringPaused;
        state.source_sandbox_id = Some(source_sandbox_id.to_string());
        state.live_slots = live_by_name;
        state.completed_slots = completed_by_name;
        Ok(())
    }

    pub(crate) async fn prepared_paused(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.activation != RestoreActivation::RestoringPaused {
            return Err(anyhow!("invalid prepared-paused restore transition"));
        }
        state.activation = RestoreActivation::PreparedPaused;
        Ok(())
    }

    pub(crate) async fn is_restore(&self) -> bool {
        self.state.lock().await.activation != RestoreActivation::Cold
    }

    pub(crate) async fn classify_create(
        &self,
        target_id: &str,
        cri_name: &str,
        is_pause: bool,
        identity: &RestoreIdentity,
    ) -> Result<RestoreCreateAction> {
        let mut state = self.state.lock().await;
        if state.activation == RestoreActivation::Cold {
            return Ok(RestoreCreateAction::Cold);
        }
        if state.activation == RestoreActivation::Failed {
            return Err(anyhow!("restore attempt has failed"));
        }
        if target_id.is_empty() || cri_name.is_empty() {
            return Err(anyhow!("incoming restore container identity is incomplete"));
        }
        // Pause may be adopted while CLH is still prepared-paused. Workloads
        // must wait until guest network identity is replaced and verified.
        if !is_pause && state.activation != RestoreActivation::Active {
            return Err(anyhow!("restored sandbox is not active"));
        }
        if let Some(slot) = state.completed_slots.get_mut(cri_name) {
            // Once kubelet consumed and deleted the synthetic task, a restart
            // policy creates a real replacement through the cold path.
            if !slot.restore_available {
                return Ok(RestoreCreateAction::Cold);
            }
            if is_pause || &slot.identity != identity {
                return Err(anyhow!(
                    "completed container identity mismatch for {cri_name}"
                ));
            }
            match slot.claimed_host_id.as_deref() {
                None => slot.claimed_host_id = Some(target_id.to_string()),
                Some(existing) if existing == target_id => {}
                Some(_) => {
                    return Err(anyhow!("completed container {cri_name} is already claimed"))
                }
            }
            return Ok(RestoreCreateAction::SyntheticCompleted {
                exit_code: slot.exit_code,
            });
        }
        if is_pause && (target_id != self.target_sandbox_id || cri_name != "POD") {
            return Err(anyhow!("invalid restored pause task identity"));
        }
        let Some(slot) = state.live_slots.get_mut(cri_name) else {
            let has_pending_slots = state
                .live_slots
                .values()
                .any(|slot| slot.claimed_host_id.is_none())
                || state
                    .completed_slots
                    .values()
                    .any(|slot| slot.restore_available && slot.claimed_host_id.is_none());
            if has_pending_slots {
                return Err(anyhow!(
                    "snapshot has no unclaimed container named {cri_name}"
                ));
            }
            return Ok(RestoreCreateAction::Cold);
        };
        if &slot.identity != identity {
            return Err(anyhow!("live container identity mismatch for {cri_name}"));
        }
        // Claim the slot and install both identity directions while holding the
        // same lock; no observer can see a claimed slot without its mappings.
        match slot.claimed_host_id.as_deref() {
            None => slot.claimed_host_id = Some(target_id.to_string()),
            Some(existing) if existing == target_id => {}
            Some(_) => return Err(anyhow!("live container {cri_name} is already claimed")),
        }
        let guest_id = slot.guest_id.clone();
        if let Some(existing) = state
            .host_to_guest
            .insert(target_id.to_string(), guest_id.clone())
        {
            if existing != guest_id {
                return Err(anyhow!("target host ID is already mapped"));
            }
        }
        if let Some(existing) = state
            .guest_to_host
            .insert(guest_id.clone(), target_id.to_string())
        {
            if existing != target_id {
                return Err(anyhow!("snapshot guest ID is already mapped"));
            }
        }
        Ok(RestoreCreateAction::AdoptLive { guest_id, is_pause })
    }

    pub(crate) async fn activation_guard(&self) -> MutexGuard<'_, ()> {
        self.activation_lock.lock().await
    }

    pub(crate) async fn begin_activation(&self, target_id: &str) -> Result<bool> {
        // Only the target sandbox ID owns paused-VM activation. Once Active,
        // workload IDs return false and continue into per-container Start.
        let mut state = self.state.lock().await;
        match state.activation {
            RestoreActivation::Cold => Ok(false),
            RestoreActivation::PreparedPaused if target_id == self.target_sandbox_id => {
                state.activation = RestoreActivation::Activating;
                Ok(true)
            }
            RestoreActivation::Active if target_id == self.target_sandbox_id => Ok(true),
            RestoreActivation::Active => Ok(false),
            RestoreActivation::Failed => Err(anyhow!("restore attempt has failed")),
            _ => Err(anyhow!("invalid restored sandbox activation transition")),
        }
    }

    pub(crate) async fn needs_activation(&self) -> bool {
        self.state.lock().await.activation == RestoreActivation::Activating
    }

    pub(crate) async fn activate(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.activation != RestoreActivation::Activating {
            return Err(anyhow!("invalid active restore transition"));
        }
        state.activation = RestoreActivation::Active;
        Ok(())
    }

    pub(crate) async fn source_pause_guest_id(&self) -> Result<String> {
        self.state
            .lock()
            .await
            .live_slots
            .get("POD")
            .map(|slot| slot.guest_id.clone())
            .ok_or_else(|| anyhow!("snapshot pause guest ID is unavailable"))
    }

    pub(crate) async fn target_pause_id(&self) -> Option<String> {
        self.state
            .lock()
            .await
            .live_slots
            .get("POD")
            .and_then(|slot| slot.claimed_host_id.clone())
    }

    pub(crate) async fn pause_guest_id_for_target(&self, target_id: &str) -> Option<String> {
        self.resolve_guest_id(target_id).await
    }

    pub(crate) async fn resolve_guest_id(&self, host_id: &str) -> Option<String> {
        self.state.lock().await.host_to_guest.get(host_id).cloned()
    }

    pub(crate) async fn resolve_host_id(&self, guest_id: &str) -> Option<String> {
        self.state.lock().await.guest_to_host.get(guest_id).cloned()
    }

    pub(crate) async fn guest_mounts_for_target(
        &self,
        host_id: &str,
    ) -> Option<Vec<RestoreGuestMount>> {
        // Some(empty) still means an adopted restore slot; None means callers
        // should use cold-container Volume state instead.
        self.state
            .lock()
            .await
            .live_slots
            .values()
            .find(|slot| slot.claimed_host_id.as_deref() == Some(host_id))
            .map(|slot| slot.node_local_mounts.clone())
    }

    pub(crate) async fn is_synthetic_completed(&self, host_id: &str) -> bool {
        self.state
            .lock()
            .await
            .completed_slots
            .values()
            .any(|slot| slot.claimed_host_id.as_deref() == Some(host_id))
    }

    pub(crate) async fn take_synthetic_exit_code(&self, host_id: &str) -> Option<i32> {
        // Consuming the pending bit closes the synthetic task exactly once;
        // dropping its process watcher later produces the single TaskExit.
        let mut state = self.state.lock().await;
        let slot = state.completed_slots.values_mut().find(|slot| {
            slot.claimed_host_id.as_deref() == Some(host_id) && slot.completion_pending
        })?;
        slot.completion_pending = false;
        Some(slot.exit_code)
    }

    pub(crate) async fn retire_synthetic_completed(&self, host_id: &str) {
        if let Some(slot) = self
            .state
            .lock()
            .await
            .completed_slots
            .values_mut()
            .find(|slot| slot.claimed_host_id.as_deref() == Some(host_id))
        {
            slot.claimed_host_id = None;
            slot.completion_pending = false;
            slot.restore_available = false;
        }
    }

    pub(crate) async fn record_completed(&self, record: CompletedContainerSnapshot) {
        self.state.lock().await.completed_slots.insert(
            record.cri_name,
            CompletedSlotState {
                exit_code: record.exit_code,
                identity: RestoreIdentity {
                    oci_identity_version: record.oci_identity_version,
                    oci_identity_sha256: record.oci_identity_sha256,
                },
                claimed_host_id: None,
                completion_pending: false,
                restore_available: false,
            },
        );
    }

    pub(crate) async fn remove_completed(&self, cri_name: &str) {
        self.state.lock().await.completed_slots.remove(cri_name);
    }

    pub(crate) async fn completed_containers(&self) -> Vec<CompletedContainerSnapshot> {
        self.state
            .lock()
            .await
            .completed_slots
            .iter()
            .map(|(cri_name, slot)| CompletedContainerSnapshot {
                cri_name: cri_name.clone(),
                exit_code: slot.exit_code,
                oci_identity_version: slot.identity.oci_identity_version,
                oci_identity_sha256: slot.identity.oci_identity_sha256.clone(),
            })
            .collect()
    }

    pub(crate) async fn persist_state(&self) -> RestorePersistState {
        RestorePersistState {
            version: 1,
            state: self.state.lock().await.clone(),
        }
    }

    pub(crate) fn from_persist(
        target_sandbox_id: &str,
        persisted: Option<RestorePersistState>,
    ) -> Result<Self> {
        let Some(persisted) = persisted else {
            return Ok(Self::new(target_sandbox_id));
        };
        // In-flight preparation/activation owns live VMM and network work that
        // cannot be reconstructed safely from state.json alone.
        if persisted.version != 1
            || matches!(
                persisted.state.activation,
                RestoreActivation::RestoringPaused | RestoreActivation::Activating
            )
        {
            return Err(anyhow!("unsupported persisted restore state"));
        }
        for (host_id, guest_id) in &persisted.state.host_to_guest {
            if persisted.state.guest_to_host.get(guest_id) != Some(host_id) {
                return Err(anyhow!("persisted restore ID maps are inconsistent"));
            }
        }
        for (guest_id, host_id) in &persisted.state.guest_to_host {
            if persisted.state.host_to_guest.get(host_id) != Some(guest_id) {
                return Err(anyhow!(
                    "persisted restore reverse ID maps are inconsistent"
                ));
            }
        }
        Ok(Self {
            target_sandbox_id: target_sandbox_id.to_string(),
            state: Mutex::new(persisted.state),
            activation_lock: Mutex::new(()),
        })
    }

    pub(crate) async fn fail(&self) {
        self.state.lock().await.activation = RestoreActivation::Failed;
    }

    #[cfg(test)]
    async fn activation(&self) -> RestoreActivation {
        self.state.lock().await.activation
    }
}

#[derive(Serialize)]
struct CanonicalMount<'a> {
    destination: &'a PathBuf,
    #[serde(rename = "type")]
    typ: &'a Option<String>,
    options: &'a Option<Vec<String>>,
}

#[derive(Serialize)]
struct CanonicalNamespace {
    #[serde(rename = "type")]
    typ: oci::LinuxNamespaceType,
    joins_existing: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalCapabilities {
    bounding: Option<BTreeSet<String>>,
    effective: Option<BTreeSet<String>>,
    inheritable: Option<BTreeSet<String>>,
    permitted: Option<BTreeSet<String>>,
    ambient: Option<BTreeSet<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalProcess<'a> {
    terminal: Option<bool>,
    console_size: Option<oci::Box>,
    user: &'a oci::User,
    args: &'a Option<Vec<String>>,
    command_line: &'a Option<String>,
    env: Option<BTreeMap<String, String>>,
    cwd: &'a PathBuf,
    capabilities: Option<CanonicalCapabilities>,
    rlimits: &'a Option<Vec<oci::PosixRlimit>>,
    no_new_privileges: Option<bool>,
    apparmor_profile: &'a Option<String>,
    oom_score_adj: Option<i32>,
    selinux_label: &'a Option<String>,
    io_priority: &'a Option<oci::LinuxIOPriority>,
    scheduler: &'a Option<oci::Scheduler>,
    #[serde(rename = "execCPUAffinity")]
    exec_cpu_affinity: &'a Option<oci::ExecCPUAffinity>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalLinuxResources<'a> {
    devices: &'a Option<Vec<oci::LinuxDeviceCgroup>>,
    memory: &'a Option<oci::LinuxMemory>,
    cpu: &'a Option<oci::LinuxCpu>,
    pids: &'a Option<oci::LinuxPids>,
    #[serde(rename = "blockIO")]
    block_io: &'a Option<oci::LinuxBlockIo>,
    hugepage_limits: &'a Option<Vec<oci::LinuxHugepageLimit>>,
    network: &'a Option<oci::LinuxNetwork>,
    rdma: Option<BTreeMap<String, oci::LinuxRdma>>,
    unified: Option<BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct CanonicalLinux<'a> {
    net_devices: Option<BTreeMap<String, oci::LinuxNetDevice>>,
    uid_mappings: &'a Option<Vec<oci::LinuxIdMapping>>,
    gid_mappings: &'a Option<Vec<oci::LinuxIdMapping>>,
    sysctl: Option<BTreeMap<String, String>>,
    resources: Option<CanonicalLinuxResources<'a>>,
    namespaces: Option<Vec<CanonicalNamespace>>,
    devices: &'a Option<Vec<oci::LinuxDevice>>,
    seccomp: &'a Option<oci::LinuxSeccomp>,
    rootfs_propagation: &'a Option<String>,
    masked_paths: &'a Option<Vec<String>>,
    readonly_paths: &'a Option<Vec<String>>,
    mount_label: &'a Option<String>,
    intel_rdt: &'a Option<oci::LinuxIntelRdt>,
    memory_policy: &'a Option<oci::LinuxMemoryPolicy>,
    personality: &'a Option<oci::LinuxPersonality>,
    time_offsets: Option<BTreeMap<String, oci::LinuxTimeOffset>>,
}

#[derive(Serialize)]
struct CanonicalOciIdentity<'a> {
    version: u32,
    oci_version: &'a str,
    process: Option<CanonicalProcess<'a>>,
    root_readonly: Option<bool>,
    mounts: Vec<CanonicalMount<'a>>,
    linux: Option<CanonicalLinux<'a>>,
}

fn canonical_capability_set(capabilities: &Option<oci::Capabilities>) -> Option<BTreeSet<String>> {
    capabilities
        .as_ref()
        .map(|capabilities| capabilities.iter().map(ToString::to_string).collect())
}

fn canonical_capabilities(capabilities: &oci::LinuxCapabilities) -> CanonicalCapabilities {
    CanonicalCapabilities {
        bounding: canonical_capability_set(capabilities.bounding()),
        effective: canonical_capability_set(capabilities.effective()),
        inheritable: canonical_capability_set(capabilities.inheritable()),
        permitted: canonical_capability_set(capabilities.permitted()),
        ambient: canonical_capability_set(capabilities.ambient()),
    }
}

fn canonical_environment(
    environment: &Option<Vec<String>>,
) -> Result<Option<BTreeMap<String, String>>> {
    environment
        .as_ref()
        .map(|environment| {
            let mut canonical = BTreeMap::new();
            for variable in environment {
                let (name, value) = variable
                    .split_once('=')
                    .filter(|(name, _)| !name.is_empty())
                    .ok_or_else(|| anyhow!("OCI environment entry is invalid"))?;
                if name == "HOSTNAME" {
                    continue;
                }
                if canonical
                    .insert(name.to_string(), value.to_string())
                    .is_some()
                {
                    return Err(anyhow!(
                        "OCI environment contains duplicate variable {name}"
                    ));
                }
            }
            Ok(canonical)
        })
        .transpose()
}

fn canonical_process(process: &oci::Process) -> Result<CanonicalProcess<'_>> {
    Ok(CanonicalProcess {
        terminal: process.terminal(),
        console_size: process.console_size(),
        user: process.user(),
        args: process.args(),
        command_line: process.command_line(),
        env: canonical_environment(process.env())?,
        cwd: process.cwd(),
        capabilities: process.capabilities().as_ref().map(canonical_capabilities),
        rlimits: process.rlimits(),
        no_new_privileges: process.no_new_privileges(),
        apparmor_profile: process.apparmor_profile(),
        oom_score_adj: process.oom_score_adj(),
        selinux_label: process.selinux_label(),
        io_priority: process.io_priority(),
        scheduler: process.scheduler(),
        exec_cpu_affinity: process.exec_cpu_affinity(),
    })
}

fn canonical_linux_resources(resources: &oci::LinuxResources) -> CanonicalLinuxResources<'_> {
    CanonicalLinuxResources {
        devices: resources.devices(),
        memory: resources.memory(),
        cpu: resources.cpu(),
        pids: resources.pids(),
        block_io: resources.block_io(),
        hugepage_limits: resources.hugepage_limits(),
        network: resources.network(),
        rdma: resources
            .rdma()
            .as_ref()
            .map(|values| values.clone().into_iter().collect()),
        unified: resources
            .unified()
            .as_ref()
            .map(|values| values.clone().into_iter().collect()),
    }
}

pub(crate) fn canonical_oci_identity(spec: &oci::Spec) -> Result<String> {
    // Compare guest-visible OCI semantics, not node-local rootfs or mount
    // sources. Packaged snapshot storage supplies the restored bytes.
    if spec.hooks().is_some() {
        return Err(anyhow!("OCI hooks are not supported by snapshot restore"));
    }
    let mounts = spec
        .mounts()
        .as_ref()
        .map(|mounts| {
            mounts
                .iter()
                .map(|mount| CanonicalMount {
                    destination: mount.destination(),
                    typ: mount.typ(),
                    options: mount.options(),
                })
                .collect()
        })
        .unwrap_or_default();
    let linux = spec.linux().as_ref().map(|linux| CanonicalLinux {
        net_devices: linux
            .net_devices()
            .as_ref()
            .map(|values| values.clone().into_iter().collect()),
        uid_mappings: linux.uid_mappings(),
        gid_mappings: linux.gid_mappings(),
        sysctl: linux
            .sysctl()
            .as_ref()
            .map(|values| values.clone().into_iter().collect()),
        resources: linux.resources().as_ref().map(canonical_linux_resources),
        namespaces: linux.namespaces().as_ref().map(|namespaces| {
            namespaces
                .iter()
                .map(|namespace| CanonicalNamespace {
                    typ: namespace.typ(),
                    joins_existing: namespace.path().is_some(),
                })
                .collect()
        }),
        devices: linux.devices(),
        seccomp: linux.seccomp(),
        rootfs_propagation: linux.rootfs_propagation(),
        masked_paths: linux.masked_paths(),
        readonly_paths: linux.readonly_paths(),
        mount_label: linux.mount_label(),
        intel_rdt: linux.intel_rdt(),
        memory_policy: linux.memory_policy(),
        personality: linux.personality(),
        time_offsets: linux
            .time_offsets()
            .as_ref()
            .map(|values| values.clone().into_iter().collect()),
    });
    let identity = CanonicalOciIdentity {
        version: OCI_IDENTITY_VERSION,
        oci_version: spec.version(),
        process: spec.process().as_ref().map(canonical_process).transpose()?,
        root_readonly: spec.root().as_ref().and_then(|root| root.readonly()),
        mounts,
        linux,
    };
    let encoded = serde_json::to_vec(&identity)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn identity(value: &str) -> RestoreIdentity {
        RestoreIdentity {
            oci_identity_version: OCI_IDENTITY_VERSION,
            oci_identity_sha256: value.to_string(),
        }
    }

    fn live_slot(name: &str, guest_id: &str, value: &str) -> RestoreLiveSlot {
        RestoreLiveSlot {
            cri_name: name.to_string(),
            guest_id: guest_id.to_string(),
            identity: identity(value),
            node_local_mounts: Vec::new(),
        }
    }

    fn identity_spec(root: &str, mount_source: &str, args: &[&str]) -> oci::Spec {
        serde_json::from_value(serde_json::json!({
            "ociVersion": "1.0.2",
            "root": {"path": root, "readonly": true},
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": args,
                "env": ["A=B"],
                "cwd": "/"
            },
            "mounts": [{
                "destination": "/data",
                "type": "bind",
                "source": mount_source,
                "options": ["rbind", "ro"]
            }],
            "linux": {
                "resources": {"memory": {"limit": 1048576}},
                "namespaces": [{"type": "mount"}],
                "maskedPaths": ["/proc/kcore"],
                "readonlyPaths": ["/proc/sys"]
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn activates_only_the_target_sandbox() {
        let context = RestoreContext::new("target");
        context
            .begin(
                "source",
                vec![live_slot("POD", "source-pause", "pause")],
                Vec::new(),
            )
            .await
            .unwrap();
        context.prepared_paused().await.unwrap();
        assert_eq!(
            context
                .classify_create("target", "POD", true, &identity("pause"))
                .await
                .unwrap(),
            RestoreCreateAction::AdoptLive {
                guest_id: "source-pause".to_string(),
                is_pause: true,
            }
        );
        assert!(context.begin_activation("target").await.unwrap());
        assert!(context.needs_activation().await);
        context.activate().await.unwrap();
        assert_eq!(context.activation().await, RestoreActivation::Active);
        assert!(!context.begin_activation("workload").await.unwrap());
    }

    #[tokio::test]
    async fn rejects_workload_adoption_before_sandbox_activation() {
        let context = RestoreContext::new("target");
        context
            .begin(
                "source",
                vec![
                    live_slot("POD", "source-pause", "pause"),
                    live_slot("app", "source-app", "app"),
                ],
                Vec::new(),
            )
            .await
            .unwrap();
        context.prepared_paused().await.unwrap();
        assert!(context
            .classify_create("target-app", "app", false, &identity("app"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn live_claim_maps_host_and_guest_ids_once() {
        let context = RestoreContext::new("target");
        context
            .begin(
                "source",
                vec![
                    live_slot("POD", "source-pause", "pause"),
                    live_slot("app", "source-app", "app"),
                ],
                Vec::new(),
            )
            .await
            .unwrap();
        context.prepared_paused().await.unwrap();
        context
            .classify_create("target", "POD", true, &identity("pause"))
            .await
            .unwrap();
        context.begin_activation("target").await.unwrap();
        context.activate().await.unwrap();

        assert_eq!(
            context
                .classify_create("target-app", "app", false, &identity("app"))
                .await
                .unwrap(),
            RestoreCreateAction::AdoptLive {
                guest_id: "source-app".to_string(),
                is_pause: false,
            }
        );
        assert_eq!(
            context.resolve_guest_id("target-app").await.as_deref(),
            Some("source-app")
        );
        assert_eq!(
            context.resolve_host_id("source-app").await.as_deref(),
            Some("target-app")
        );
        assert_eq!(
            context.guest_mounts_for_target("target-app").await,
            Some(Vec::new())
        );
        assert_eq!(context.guest_mounts_for_target("cold-app").await, None);
        assert!(context
            .classify_create("other-app", "app", false, &identity("app"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn allows_cold_container_after_snapshot_slots_are_consumed() {
        let context = RestoreContext::new("target");
        context
            .begin(
                "source",
                vec![
                    live_slot("POD", "source-pause", "pause"),
                    live_slot("app", "source-app", "app"),
                ],
                vec![RestoreCompletedSlot {
                    cri_name: "setup".to_string(),
                    exit_code: 0,
                    identity: identity("setup"),
                }],
            )
            .await
            .unwrap();
        context.prepared_paused().await.unwrap();
        context
            .classify_create("target", "POD", true, &identity("pause"))
            .await
            .unwrap();
        context.begin_activation("target").await.unwrap();
        context.activate().await.unwrap();

        assert!(context
            .classify_create(
                "debugger",
                "snapshot-debugger",
                false,
                &identity("debugger")
            )
            .await
            .is_err());
        context
            .classify_create("target-app", "app", false, &identity("app"))
            .await
            .unwrap();
        assert!(context
            .classify_create(
                "debugger",
                "snapshot-debugger",
                false,
                &identity("debugger")
            )
            .await
            .is_err());
        context
            .classify_create("target-setup", "setup", false, &identity("setup"))
            .await
            .unwrap();
        assert_eq!(
            context.take_synthetic_exit_code("target-setup").await,
            Some(0)
        );
        context.retire_synthetic_completed("target-setup").await;
        assert_eq!(
            context
                .classify_create(
                    "debugger",
                    "snapshot-debugger",
                    false,
                    &identity("debugger")
                )
                .await
                .unwrap(),
            RestoreCreateAction::Cold
        );
    }

    #[tokio::test]
    async fn completed_slot_finishes_once_then_allows_cold_replacement() {
        let context = RestoreContext::new("target");
        context
            .begin(
                "source",
                vec![live_slot("POD", "source-pause", "pause")],
                vec![RestoreCompletedSlot {
                    cri_name: "setup".to_string(),
                    exit_code: 42,
                    identity: identity("setup"),
                }],
            )
            .await
            .unwrap();
        context.prepared_paused().await.unwrap();
        context
            .classify_create("target", "POD", true, &identity("pause"))
            .await
            .unwrap();
        context.begin_activation("target").await.unwrap();
        context.activate().await.unwrap();

        assert_eq!(
            context
                .classify_create("target-setup", "setup", false, &identity("setup"))
                .await
                .unwrap(),
            RestoreCreateAction::SyntheticCompleted { exit_code: 42 }
        );
        assert_eq!(
            context.take_synthetic_exit_code("target-setup").await,
            Some(42)
        );
        assert_eq!(context.take_synthetic_exit_code("target-setup").await, None);
        context
            .record_completed(CompletedContainerSnapshot {
                cri_name: "setup".to_string(),
                exit_code: 42,
                oci_identity_version: OCI_IDENTITY_VERSION,
                oci_identity_sha256: "setup".to_string(),
            })
            .await;
        assert_eq!(
            context
                .classify_create("replacement", "setup", false, &identity("setup"))
                .await
                .unwrap(),
            RestoreCreateAction::Cold
        );
    }

    #[tokio::test]
    async fn persisted_state_preserves_activation_claims_and_stable_ids() {
        let context = RestoreContext::new("target");
        context
            .begin(
                "source",
                vec![live_slot("POD", "source-pause", "pause")],
                Vec::new(),
            )
            .await
            .unwrap();
        context.prepared_paused().await.unwrap();
        context
            .classify_create("target", "POD", true, &identity("pause"))
            .await
            .unwrap();
        context.begin_activation("target").await.unwrap();
        context.activate().await.unwrap();

        let encoded = serde_json::to_vec(&context.persist_state().await).unwrap();
        let persisted = serde_json::from_slice(&encoded).unwrap();
        let restored = RestoreContext::from_persist("target", Some(persisted)).unwrap();

        assert_eq!(restored.activation().await, RestoreActivation::Active);
        assert_eq!(
            restored.resolve_guest_id("target").await.as_deref(),
            Some("source-pause")
        );
        assert_eq!(
            restored.resolve_host_id("source-pause").await.as_deref(),
            Some("target")
        );
    }

    #[test]
    fn canonical_identity_normalizes_host_paths() {
        let source = identity_spec("/source/rootfs", "/source/config", &["sleep", "10"]);
        let target = identity_spec("/target/rootfs", "/target/config", &["sleep", "10"]);
        assert_eq!(
            canonical_oci_identity(&source).unwrap(),
            canonical_oci_identity(&target).unwrap()
        );
    }

    #[test]
    fn canonical_identity_detects_process_change() {
        let source = identity_spec("/rootfs", "/config", &["sleep", "10"]);
        let target = identity_spec("/rootfs", "/config", &["sleep", "20"]);
        assert_ne!(
            canonical_oci_identity(&source).unwrap(),
            canonical_oci_identity(&target).unwrap()
        );
    }

    #[test]
    fn canonical_identity_sorts_linux_maps() {
        let mut left = identity_spec("/rootfs", "/config", &["true"]);
        let mut right = left.clone();
        left.linux_mut()
            .as_mut()
            .unwrap()
            .set_sysctl(Some(HashMap::from([
                ("kernel.domainname".to_string(), "left".to_string()),
                ("net.ipv4.ip_forward".to_string(), "1".to_string()),
            ])));
        right
            .linux_mut()
            .as_mut()
            .unwrap()
            .set_sysctl(Some(HashMap::from([
                ("net.ipv4.ip_forward".to_string(), "1".to_string()),
                ("kernel.domainname".to_string(), "left".to_string()),
            ])));
        assert_eq!(
            canonical_oci_identity(&left).unwrap(),
            canonical_oci_identity(&right).unwrap()
        );
    }

    #[test]
    fn canonical_identity_rejects_hooks() {
        let mut spec = identity_spec("/rootfs", "/config", &["true"]);
        spec.set_hooks(Some(oci::Hooks::default()));
        assert!(canonical_oci_identity(&spec).is_err());
    }
}
