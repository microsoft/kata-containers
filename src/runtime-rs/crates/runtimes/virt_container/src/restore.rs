// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use oci_spec::runtime as oci;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use tokio::sync::Mutex;

pub(crate) const OCI_IDENTITY_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RestoreIdentity {
    pub(crate) resolved_image_manifest_digest: String,
    pub(crate) oci_identity_version: u32,
    pub(crate) oci_identity_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestoreContainerKind {
    Sandbox,
    Workload,
}

#[derive(Clone, Debug)]
pub(crate) struct RestoreContainerSlot {
    pub(crate) kind: RestoreContainerKind,
    pub(crate) cri_name: String,
    pub(crate) snapshot_guest_id: String,
    pub(crate) identity: RestoreIdentity,
    pub(crate) guest_mounts: Vec<RestoreGuestMount>,
}

#[derive(Clone, Debug)]
pub(crate) struct RestoreGuestMount {
    pub(crate) destination: String,
    pub(crate) guest_source: String,
}

#[derive(Clone, Debug)]
pub(crate) struct RestoreCompletedInit {
    pub(crate) name: String,
    pub(crate) order: u32,
    pub(crate) exit_code: i32,
    pub(crate) identity: RestoreIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CreateAction {
    ColdCreate,
    AdoptPause { snapshot_guest_id: String },
    AdoptWorkload { snapshot_guest_id: String },
    SyntheticInit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartAction {
    ColdStart,
    Stage,
    CompleteSyntheticInit,
    Finalize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestorePhase {
    Cold,
    RestoringPaused,
    AdoptingPause,
    Adopting,
    StartsStaged,
    Rebinding,
    Finalizing,
    Active,
    Failed,
}

#[derive(Debug)]
struct RestoreState {
    phase: RestorePhase,
    source_sandbox_id: Option<String>,
    slots: HashMap<String, RestoreContainerSlot>,
    completed_inits: Vec<RestoreCompletedInit>,
    target_digests: HashMap<String, String>,
    target_pause_id: Option<String>,
    adopted_workloads: HashMap<String, String>,
    target_to_guest: HashMap<String, String>,
    start_requested: HashSet<String>,
    completed_init_names: HashSet<String>,
    synthetic_init_ids: HashMap<String, Option<i32>>,
}

#[derive(Debug)]
pub(crate) struct RestoreCoordinator {
    state: Mutex<RestoreState>,
}

impl RestoreCoordinator {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RestoreState {
                phase: RestorePhase::Cold,
                source_sandbox_id: None,
                slots: HashMap::new(),
                completed_inits: Vec::new(),
                target_digests: HashMap::new(),
                target_pause_id: None,
                adopted_workloads: HashMap::new(),
                target_to_guest: HashMap::new(),
                start_requested: HashSet::new(),
                completed_init_names: HashSet::new(),
                synthetic_init_ids: HashMap::new(),
            }),
        }
    }

    pub(crate) async fn begin(
        &self,
        source_sandbox_id: &str,
        slots: Vec<RestoreContainerSlot>,
        completed_inits: Vec<RestoreCompletedInit>,
        target_digests: HashMap<String, String>,
    ) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.phase != RestorePhase::Cold || source_sandbox_id.is_empty() {
            return Err(anyhow!("invalid restore begin transition"));
        }
        let mut slots_by_name = HashMap::new();
        for slot in slots {
            if slots_by_name.insert(slot.cri_name.clone(), slot).is_some() {
                return Err(anyhow!("duplicate restore container name"));
            }
        }
        let expected_names = slots_by_name
            .keys()
            .chain(completed_inits.iter().map(|init| &init.name))
            .collect::<HashSet<_>>();
        if expected_names.len() != target_digests.len()
            || expected_names
                .iter()
                .any(|name| !target_digests.contains_key(*name))
        {
            return Err(anyhow!(
                "target image digest inventory does not match snapshot"
            ));
        }
        if completed_inits
            .iter()
            .enumerate()
            .any(|(index, init)| init.order != index as u32)
        {
            return Err(anyhow!("completed init order is invalid"));
        }
        state.phase = RestorePhase::RestoringPaused;
        state.source_sandbox_id = Some(source_sandbox_id.to_string());
        state.slots = slots_by_name;
        state.completed_inits = completed_inits;
        state.target_digests = target_digests;
        Ok(())
    }

    pub(crate) async fn restored_paused(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.phase != RestorePhase::RestoringPaused {
            return Err(anyhow!("invalid restored-paused transition"));
        }
        state.phase = RestorePhase::AdoptingPause;
        Ok(())
    }

    pub(crate) async fn classify_create(
        &self,
        target_id: &str,
        cri_name: &str,
        is_pause: bool,
        oci_identity_sha256: &str,
    ) -> Result<CreateAction> {
        let mut state = self.state.lock().await;
        if matches!(state.phase, RestorePhase::Cold | RestorePhase::Active) {
            return Ok(CreateAction::ColdCreate);
        }
        if state.phase == RestorePhase::Failed {
            return Err(anyhow!("restore attempt has failed"));
        }
        if matches!(
            state.phase,
            RestorePhase::Rebinding | RestorePhase::Finalizing
        ) {
            return Err(anyhow!("restore finalization is in progress"));
        }
        if target_id.is_empty() || cri_name.is_empty() {
            state.phase = RestorePhase::Failed;
            return Err(anyhow!("incoming restore container identity is incomplete"));
        }
        let target_digest = state
            .target_digests
            .get(cri_name)
            .cloned()
            .ok_or_else(|| anyhow!("unexpected restore container {cri_name}"))?;
        let identity = RestoreIdentity {
            resolved_image_manifest_digest: target_digest,
            oci_identity_version: OCI_IDENTITY_VERSION,
            oci_identity_sha256: oci_identity_sha256.to_string(),
        };

        if let Some(init) = state
            .completed_inits
            .iter()
            .find(|init| init.name == cri_name)
            .cloned()
        {
            if is_pause || init.identity != identity {
                state.phase = RestorePhase::Failed;
                return Err(anyhow!("completed init identity mismatch for {cri_name}"));
            }
            if init.order as usize != state.completed_init_names.len() {
                state.phase = RestorePhase::Failed;
                return Err(anyhow!("completed init {cri_name} arrived out of order"));
            }
            if !state.completed_init_names.insert(cri_name.to_string()) {
                state.phase = RestorePhase::Failed;
                return Err(anyhow!("completed init {cri_name} is already claimed"));
            }
            state
                .synthetic_init_ids
                .insert(target_id.to_string(), Some(init.exit_code));
            return Ok(CreateAction::SyntheticInit);
        }

        let slot = state
            .slots
            .get(cri_name)
            .cloned()
            .ok_or_else(|| anyhow!("snapshot has no container named {cri_name}"))?;
        if slot.identity != identity || (slot.kind == RestoreContainerKind::Sandbox) != is_pause {
            state.phase = RestorePhase::Failed;
            return Err(anyhow!(
                "snapshot identity mismatch for {cri_name}: expected {:?} kind {:?}, got {:?} is_pause {is_pause}",
                slot.identity,
                slot.kind,
                identity
            ));
        }
        if slot.kind == RestoreContainerKind::Sandbox {
            if state.phase != RestorePhase::AdoptingPause || state.target_pause_id.is_some() {
                return Err(anyhow!("invalid pause adoption transition"));
            }
            state.target_pause_id = Some(target_id.to_string());
            state
                .target_to_guest
                .insert(target_id.to_string(), slot.snapshot_guest_id.clone());
            state.phase = RestorePhase::Adopting;
            return Ok(CreateAction::AdoptPause {
                snapshot_guest_id: slot.snapshot_guest_id,
            });
        }
        if !matches!(
            state.phase,
            RestorePhase::Adopting | RestorePhase::StartsStaged
        ) {
            return Err(anyhow!("invalid workload adoption transition"));
        }
        if state.completed_init_names.len() != state.completed_inits.len() {
            state.phase = RestorePhase::Failed;
            return Err(anyhow!(
                "regular workload arrived before completed init inventory"
            ));
        }
        if state.adopted_workloads.contains_key(cri_name)
            || state.target_to_guest.contains_key(target_id)
        {
            state.phase = RestorePhase::Failed;
            return Err(anyhow!("workload {cri_name} is already adopted"));
        }
        state
            .adopted_workloads
            .insert(cri_name.to_string(), target_id.to_string());
        state
            .target_to_guest
            .insert(target_id.to_string(), slot.snapshot_guest_id.clone());
        Ok(CreateAction::AdoptWorkload {
            snapshot_guest_id: slot.snapshot_guest_id,
        })
    }

    pub(crate) async fn classify_start(&self, target_id: &str) -> Result<StartAction> {
        let mut state = self.state.lock().await;
        if matches!(state.phase, RestorePhase::Cold | RestorePhase::Active) {
            return Ok(StartAction::ColdStart);
        }
        if state.phase == RestorePhase::Failed {
            return Err(anyhow!("restore attempt has failed"));
        }
        if matches!(
            state.phase,
            RestorePhase::Rebinding | RestorePhase::Finalizing
        ) {
            return Err(anyhow!("restore finalization is in progress"));
        }
        if let Some(exit_code) = state.synthetic_init_ids.get(target_id) {
            return if exit_code.is_some() {
                Ok(StartAction::CompleteSyntheticInit)
            } else {
                Err(anyhow!("completed init {target_id} is already started"))
            };
        }
        if state.target_pause_id.as_deref() == Some(target_id) {
            return Ok(StartAction::Stage);
        }
        if !state.target_to_guest.contains_key(target_id) {
            return Err(anyhow!("restore start for unknown container {target_id}"));
        }
        if !state.start_requested.insert(target_id.to_string()) {
            return Ok(StartAction::Stage);
        }
        state.phase = RestorePhase::StartsStaged;
        let expected_workloads = state
            .slots
            .values()
            .filter(|slot| slot.kind == RestoreContainerKind::Workload)
            .count();
        if state.adopted_workloads.len() == expected_workloads
            && state.start_requested.len() == expected_workloads
        {
            state.phase = RestorePhase::Rebinding;
            return Ok(StartAction::Finalize);
        }
        Ok(StartAction::Stage)
    }

    pub(crate) async fn take_synthetic_init_exit_code(&self, target_id: &str) -> Option<i32> {
        self.state
            .lock()
            .await
            .synthetic_init_ids
            .get_mut(target_id)
            .and_then(Option::take)
    }

    pub(crate) async fn is_synthetic_init(&self, target_id: &str) -> bool {
        self.state
            .lock()
            .await
            .synthetic_init_ids
            .contains_key(target_id)
    }

    pub(crate) async fn forget_synthetic_init(&self, target_id: &str) {
        self.state.lock().await.synthetic_init_ids.remove(target_id);
    }

    pub(crate) async fn is_adopted_pause(&self, target_id: &str) -> bool {
        self.state.lock().await.target_pause_id.as_deref() == Some(target_id)
    }

    pub(crate) async fn target_to_guest(&self) -> HashMap<String, String> {
        self.state.lock().await.target_to_guest.clone()
    }

    pub(crate) async fn target_names(&self) -> Result<HashMap<String, String>> {
        let state = self.state.lock().await;
        let mut targets = state
            .adopted_workloads
            .iter()
            .map(|(name, target_id)| (name.clone(), target_id.clone()))
            .collect::<HashMap<_, _>>();
        let pause_name = state
            .slots
            .values()
            .find(|slot| slot.kind == RestoreContainerKind::Sandbox)
            .map(|slot| slot.cri_name.clone())
            .ok_or_else(|| anyhow!("snapshot has no sandbox container"))?;
        let pause_id = state
            .target_pause_id
            .clone()
            .ok_or_else(|| anyhow!("target sandbox container is unavailable"))?;
        if targets.insert(pause_name, pause_id).is_some() {
            return Err(anyhow!("duplicate target sandbox container name"));
        }
        Ok(targets)
    }

    pub(crate) async fn guest_mounts_by_target(&self) -> HashMap<String, Vec<RestoreGuestMount>> {
        let state = self.state.lock().await;
        state
            .adopted_workloads
            .iter()
            .filter_map(|(name, target_id)| {
                state
                    .slots
                    .get(name)
                    .map(|slot| (target_id.clone(), slot.guest_mounts.clone()))
            })
            .collect()
    }

    pub(crate) async fn source_sandbox_id(&self) -> Result<String> {
        self.state
            .lock()
            .await
            .source_sandbox_id
            .clone()
            .ok_or_else(|| anyhow!("restore source sandbox ID is unavailable"))
    }

    pub(crate) async fn needs_finalization(&self) -> bool {
        self.state.lock().await.phase == RestorePhase::Rebinding
    }

    pub(crate) async fn begin_finalizing(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.phase != RestorePhase::Rebinding {
            return Err(anyhow!("invalid finalizing transition"));
        }
        state.phase = RestorePhase::Finalizing;
        Ok(())
    }

    pub(crate) async fn activate(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.phase != RestorePhase::Finalizing {
            return Err(anyhow!("invalid active transition"));
        }
        state.phase = RestorePhase::Active;
        Ok(())
    }

    pub(crate) async fn fail(&self) {
        self.state.lock().await.phase = RestorePhase::Failed;
    }

    #[cfg(test)]
    async fn phase(&self) -> RestorePhase {
        self.state.lock().await.phase
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

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn identity(byte: char) -> RestoreIdentity {
        RestoreIdentity {
            resolved_image_manifest_digest: digest('1'),
            oci_identity_version: OCI_IDENTITY_VERSION,
            oci_identity_sha256: digest(byte),
        }
    }

    async fn begin_test_restore(coordinator: &RestoreCoordinator) {
        let pause = RestoreContainerSlot {
            kind: RestoreContainerKind::Sandbox,
            cri_name: "POD".to_string(),
            snapshot_guest_id: "source".to_string(),
            identity: identity('a'),
            guest_mounts: Vec::new(),
        };
        let workload = RestoreContainerSlot {
            kind: RestoreContainerKind::Workload,
            cri_name: "app".to_string(),
            snapshot_guest_id: "old-app".to_string(),
            identity: identity('b'),
            guest_mounts: Vec::new(),
        };
        let target_digests = HashMap::from([
            (
                "POD".to_string(),
                pause.identity.resolved_image_manifest_digest.clone(),
            ),
            (
                "app".to_string(),
                workload.identity.resolved_image_manifest_digest.clone(),
            ),
        ]);
        coordinator
            .begin("source", vec![pause, workload], Vec::new(), target_digests)
            .await
            .unwrap();
        coordinator.restored_paused().await.unwrap();
    }

    #[tokio::test]
    async fn stages_until_last_expected_workload_start() {
        let coordinator = RestoreCoordinator::new();
        begin_test_restore(&coordinator).await;
        assert!(matches!(
            coordinator
                .classify_create("target", "POD", true, &identity('a').oci_identity_sha256,)
                .await
                .unwrap(),
            CreateAction::AdoptPause { .. }
        ));
        assert_eq!(
            coordinator.classify_start("target").await.unwrap(),
            StartAction::Stage
        );
        assert!(matches!(
            coordinator
                .classify_create(
                    "target-app",
                    "app",
                    false,
                    &identity('b').oci_identity_sha256,
                )
                .await
                .unwrap(),
            CreateAction::AdoptWorkload { .. }
        ));
        assert_eq!(
            coordinator.classify_start("target-app").await.unwrap(),
            StartAction::Finalize
        );
        assert_eq!(coordinator.phase().await, RestorePhase::Rebinding);
    }

    #[tokio::test]
    async fn last_of_multiple_starts_owns_finalization_then_returns_to_cold_path() {
        let coordinator = RestoreCoordinator::new();
        let slots = vec![
            RestoreContainerSlot {
                kind: RestoreContainerKind::Sandbox,
                cri_name: "POD".to_string(),
                snapshot_guest_id: "source".to_string(),
                identity: identity('a'),
                guest_mounts: Vec::new(),
            },
            RestoreContainerSlot {
                kind: RestoreContainerKind::Workload,
                cri_name: "app-a".to_string(),
                snapshot_guest_id: "old-a".to_string(),
                identity: identity('b'),
                guest_mounts: Vec::new(),
            },
            RestoreContainerSlot {
                kind: RestoreContainerKind::Workload,
                cri_name: "app-b".to_string(),
                snapshot_guest_id: "old-b".to_string(),
                identity: identity('c'),
                guest_mounts: Vec::new(),
            },
        ];
        let digests = slots
            .iter()
            .map(|slot| {
                (
                    slot.cri_name.clone(),
                    slot.identity.resolved_image_manifest_digest.clone(),
                )
            })
            .collect();
        coordinator
            .begin("source", slots, Vec::new(), digests)
            .await
            .unwrap();
        coordinator.restored_paused().await.unwrap();
        coordinator
            .classify_create("target", "POD", true, &identity('a').oci_identity_sha256)
            .await
            .unwrap();
        coordinator
            .classify_create(
                "target-b",
                "app-b",
                false,
                &identity('c').oci_identity_sha256,
            )
            .await
            .unwrap();
        coordinator
            .classify_create(
                "target-a",
                "app-a",
                false,
                &identity('b').oci_identity_sha256,
            )
            .await
            .unwrap();
        assert_eq!(
            coordinator.classify_start("target-b").await.unwrap(),
            StartAction::Stage
        );
        assert_eq!(
            coordinator.classify_start("target-a").await.unwrap(),
            StartAction::Finalize
        );
        assert!(coordinator.classify_start("target-b").await.is_err());
        coordinator.begin_finalizing().await.unwrap();
        assert!(coordinator
            .classify_create("late", "debug", false, "digest")
            .await
            .is_err());
        coordinator.activate().await.unwrap();
        assert_eq!(
            coordinator
                .classify_create("late", "debug", false, "digest")
                .await
                .unwrap(),
            CreateAction::ColdCreate
        );
        assert_eq!(
            coordinator.classify_start("late").await.unwrap(),
            StartAction::ColdStart
        );
    }

    #[tokio::test]
    async fn rejects_identity_mismatch_terminally() {
        let coordinator = RestoreCoordinator::new();
        begin_test_restore(&coordinator).await;
        assert!(coordinator
            .classify_create("target", "POD", true, &identity('f').oci_identity_sha256,)
            .await
            .is_err());
        assert_eq!(coordinator.phase().await, RestorePhase::Failed);
    }

    #[tokio::test]
    async fn synthetic_init_exit_code_is_consumed_once() {
        let coordinator = RestoreCoordinator::new();
        let pause = RestoreContainerSlot {
            kind: RestoreContainerKind::Sandbox,
            cri_name: "POD".to_string(),
            snapshot_guest_id: "source".to_string(),
            identity: identity('a'),
            guest_mounts: Vec::new(),
        };
        let init = RestoreCompletedInit {
            name: "setup".to_string(),
            order: 0,
            exit_code: 42,
            identity: identity('b'),
        };
        coordinator
            .begin(
                "source",
                vec![pause],
                vec![init],
                HashMap::from([
                    (
                        "POD".to_string(),
                        identity('a').resolved_image_manifest_digest,
                    ),
                    (
                        "setup".to_string(),
                        identity('b').resolved_image_manifest_digest,
                    ),
                ]),
            )
            .await
            .unwrap();
        coordinator.restored_paused().await.unwrap();
        coordinator
            .classify_create("target", "POD", true, &identity('a').oci_identity_sha256)
            .await
            .unwrap();
        assert_eq!(
            coordinator
                .classify_create(
                    "target-init",
                    "setup",
                    false,
                    &identity('b').oci_identity_sha256,
                )
                .await
                .unwrap(),
            CreateAction::SyntheticInit
        );
        assert_eq!(
            coordinator.classify_start("target-init").await.unwrap(),
            StartAction::CompleteSyntheticInit
        );
        assert_eq!(
            coordinator
                .take_synthetic_init_exit_code("target-init")
                .await,
            Some(42)
        );
        assert_eq!(
            coordinator
                .take_synthetic_init_exit_code("target-init")
                .await,
            None
        );
        assert!(coordinator.is_synthetic_init("target-init").await);
        assert!(coordinator.classify_start("target-init").await.is_err());
        coordinator.forget_synthetic_init("target-init").await;
        assert!(!coordinator.is_synthetic_init("target-init").await);
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

    #[test]
    fn canonical_identity_normalizes_only_host_paths() {
        let source = identity_spec("/source/rootfs", "/source/config", &["sleep", "10"]);
        let target = identity_spec("/target/rootfs", "/target/config", &["sleep", "10"]);
        assert_eq!(
            canonical_oci_identity(&source).unwrap(),
            canonical_oci_identity(&target).unwrap()
        );
    }

    #[test]
    fn canonical_identity_normalizes_namespace_paths_and_hostname() {
        let source = serde_json::from_value::<oci::Spec>(serde_json::json!({
            "ociVersion": "1.0.2",
            "hostname": "source-host",
            "root": {"path": "/source/rootfs", "readonly": true},
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["sleep", "10"],
                "cwd": "/"
            },
            "linux": {
                "namespaces": [{"type": "network", "path": "/run/netns/source"}]
            }
        }))
        .unwrap();
        let target = serde_json::from_value::<oci::Spec>(serde_json::json!({
            "ociVersion": "1.0.2",
            "hostname": "target-host",
            "root": {"path": "/target/rootfs", "readonly": true},
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["sleep", "10"],
                "cwd": "/"
            },
            "linux": {
                "namespaces": [{"type": "network", "path": "/run/netns/target"}]
            }
        }))
        .unwrap();
        assert_eq!(
            canonical_oci_identity(&source).unwrap(),
            canonical_oci_identity(&target).unwrap()
        );
    }

    #[test]
    fn canonical_identity_preserves_namespace_join_semantics() {
        let created = identity_spec("/rootfs", "/config", &["true"]);
        let mut joined_value = serde_json::to_value(&created).unwrap();
        joined_value["linux"]["namespaces"][0]["path"] =
            serde_json::Value::String("/run/ns/existing".to_string());
        let joined = serde_json::from_value(joined_value).unwrap();
        assert_ne!(
            canonical_oci_identity(&created).unwrap(),
            canonical_oci_identity(&joined).unwrap()
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
        left.linux_mut()
            .as_mut()
            .unwrap()
            .resources_mut()
            .as_mut()
            .unwrap()
            .set_unified(Some(HashMap::from([
                ("memory.high".to_string(), "1048576".to_string()),
                ("pids.max".to_string(), "64".to_string()),
            ])));
        right
            .linux_mut()
            .as_mut()
            .unwrap()
            .resources_mut()
            .as_mut()
            .unwrap()
            .set_unified(Some(HashMap::from([
                ("pids.max".to_string(), "64".to_string()),
                ("memory.high".to_string(), "1048576".to_string()),
            ])));

        assert_eq!(
            canonical_oci_identity(&left).unwrap(),
            canonical_oci_identity(&right).unwrap()
        );
    }

    #[test]
    fn canonical_identity_sorts_capability_sets() {
        let mut left = identity_spec("/rootfs", "/config", &["true"]);
        let mut right = left.clone();
        left.process_mut().as_mut().unwrap().set_capabilities(Some(
            serde_json::from_value(serde_json::json!({
                "bounding": ["CAP_SYS_ADMIN", "CAP_CHOWN"],
                "effective": ["CAP_SYS_ADMIN", "CAP_CHOWN"]
            }))
            .unwrap(),
        ));
        right.process_mut().as_mut().unwrap().set_capabilities(Some(
            serde_json::from_value(serde_json::json!({
                "bounding": ["CAP_CHOWN", "CAP_SYS_ADMIN"],
                "effective": ["CAP_CHOWN", "CAP_SYS_ADMIN"]
            }))
            .unwrap(),
        ));

        assert_eq!(
            canonical_oci_identity(&left).unwrap(),
            canonical_oci_identity(&right).unwrap()
        );
    }

    #[test]
    fn canonical_identity_orders_environment_and_ignores_hostname() {
        let mut source = identity_spec("/rootfs", "/config", &["true"]);
        let mut target = source.clone();
        source.process_mut().as_mut().unwrap().set_env(Some(vec![
            "HOSTNAME=source".to_string(),
            "B=2".to_string(),
            "A=1".to_string(),
        ]));
        target.process_mut().as_mut().unwrap().set_env(Some(vec![
            "A=1".to_string(),
            "HOSTNAME=target".to_string(),
            "B=2".to_string(),
        ]));

        assert_eq!(
            canonical_oci_identity(&source).unwrap(),
            canonical_oci_identity(&target).unwrap()
        );
    }

    #[test]
    fn canonical_identity_rejects_duplicate_environment_names() {
        let mut spec = identity_spec("/rootfs", "/config", &["true"]);
        spec.process_mut()
            .as_mut()
            .unwrap()
            .set_env(Some(vec!["A=first".to_string(), "A=second".to_string()]));

        assert!(canonical_oci_identity(&spec).is_err());
    }

    #[test]
    fn canonical_identity_detects_process_semantic_change() {
        let source = identity_spec("/rootfs", "/config", &["sleep", "10"]);
        let target = identity_spec("/rootfs", "/config", &["sleep", "20"]);
        assert_ne!(
            canonical_oci_identity(&source).unwrap(),
            canonical_oci_identity(&target).unwrap()
        );
    }

    #[test]
    fn canonical_identity_rejects_hooks() {
        let mut spec = identity_spec("/rootfs", "/config", &["true"]);
        spec.set_hooks(Some(oci::Hooks::default()));
        assert!(canonical_oci_identity(&spec).is_err());
    }
}
