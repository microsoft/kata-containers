// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow K8s YAML field names.
#![allow(non_snake_case)]

use crate::config_map;
use crate::obj_meta;
use crate::policy;
use crate::registry;
use crate::secret;
use crate::settings;
use crate::utils::Config;
use crate::volume;
use crate::yaml;

use async_trait::async_trait;
use log::{debug, warn};
use protocols::agent;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pod {
    apiVersion: String,
    kind: String,
    pub metadata: obj_meta::ObjectMeta,
    pub spec: PodSpec,

    #[serde(skip)]
    doc_mapping: serde_yaml::Value,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PodSpec {
    pub containers: Vec<Container>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nodeSelector: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    restartPolicy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtimeClassName: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub initContainers: Option<Vec<Container>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    imagePullSecrets: Option<Vec<LocalObjectReference>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    affinity: Option<Affinity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<volume::Volume>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nodeName: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    serviceAccountName: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    serviceAccount: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    terminationGracePeriodSeconds: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tolerations: Option<Vec<Toleration>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostNetwork: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub shareProcessNamespace: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    dnsConfig: Option<PodDNSConfig>,

    #[serde(skip_serializing_if = "Option::is_none")]
    dnsPolicy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    topologySpreadConstraints: Option<Vec<TopologySpreadConstraint>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub securityContext: Option<PodSecurityContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    priorityClassName: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    preemptionPolicy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    schedulerName: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<ResourceRequirements>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Container {
    /// Container image registry information.
    #[serde(skip)]
    pub registry: registry::Container,

    pub name: String,
    pub image: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    imagePullPolicy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    securityContext: Option<SecurityContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    workingDir: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumeMounts: Option<Vec<VolumeMount>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumeDevices: Option<Vec<VolumeDevice>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<Vec<EnvVar>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    envFrom: Option<Vec<EnvFromSource>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<ResourceRequirements>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ports: Option<Vec<ContainerPort>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle: Option<Lifecycle>,

    #[serde(skip_serializing_if = "Option::is_none")]
    livenessProbe: Option<Probe>,

    #[serde(skip_serializing_if = "Option::is_none")]
    readinessProbe: Option<Probe>,

    #[serde(skip_serializing_if = "Option::is_none")]
    startupProbe: Option<Probe>,

    #[serde(skip_serializing_if = "Option::is_none")]
    restartPolicy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub serviceAccountName: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    stdin: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminationMessagePath: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminationMessagePolicy: Option<String>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Affinity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodeAffinity: Option<NodeAffinity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub podAntiAffinity: Option<PodAntiAffinity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub podAffinity: Option<PodAffinity>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeAffinity {
    #[serde(skip_serializing_if = "Option::is_none")]
    requiredDuringSchedulingIgnoredDuringExecution: Option<NodeSelector>,

    #[serde(skip_serializing_if = "Option::is_none")]
    preferredDuringSchedulingIgnoredDuringExecution: Option<Vec<PreferredSchedulingTerm>>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PreferredSchedulingTerm {
    weight: i32,
    preference: NodeSelectorTerm,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeSelector {
    nodeSelectorTerms: Vec<NodeSelectorTerm>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeSelectorTerm {
    #[serde(skip_serializing_if = "Option::is_none")]
    matchExpressions: Option<Vec<NodeSelectorRequirement>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    matchFields: Option<Vec<NodeSelectorRequirement>>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeSelectorRequirement {
    key: String,
    operator: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    values: Option<Vec<String>>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PodAffinity {
    #[serde(skip_serializing_if = "Option::is_none")]
    preferredDuringSchedulingIgnoredDuringExecution: Option<Vec<WeightedPodAffinityTerm>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    requiredDuringSchedulingIgnoredDuringExecution: Option<Vec<PodAffinityTerm>>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PodAntiAffinity {
    #[serde(skip_serializing_if = "Option::is_none")]
    preferredDuringSchedulingIgnoredDuringExecution: Option<Vec<WeightedPodAffinityTerm>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    requiredDuringSchedulingIgnoredDuringExecution: Option<Vec<PodAffinityTerm>>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WeightedPodAffinityTerm {
    weight: i32,
    podAffinityTerm: PodAffinityTerm,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PodAffinityTerm {
    topologyKey: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    labelSelector: Option<yaml::LabelSelector>,

    #[serde(skip_serializing_if = "Option::is_none")]
    matchLabelKeys: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    mismatchLabelKeys: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    namespaceSelector: Option<yaml::LabelSelector>,

    #[serde(skip_serializing_if = "Option::is_none")]
    namespaces: Option<Vec<String>>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Probe {
    #[serde(skip_serializing_if = "Option::is_none")]
    exec: Option<ExecAction>,

    #[serde(skip_serializing_if = "Option::is_none")]
    initialDelaySeconds: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    timeoutSeconds: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    periodSeconds: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    terminationGracePeriodSeconds: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    failureThreshold: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    successThreshold: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    httpGet: Option<HTTPGetAction>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tcpSocket: Option<TCPSocketAction>,

    #[serde(skip_serializing_if = "Option::is_none")]
    grpc: Option<GRPCAction>,
    // TODO: additional fields.
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TCPSocketAction {
    port: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct GRPCAction {
    port: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct HTTPGetAction {
    port: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    scheme: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    httpHeaders: Option<Vec<HTTPHeader>>,
    // TODO: additional fields.
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct HTTPHeader {
    name: String,
    value: String,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SecurityContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    readOnlyRootFilesystem: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    allowPrivilegeEscalation: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    privileged: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<Capabilities>,

    #[serde(skip_serializing_if = "Option::is_none")]
    runAsUser: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    runAsGroup: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    seccompProfile: Option<SeccompProfile>,

    #[serde(skip_serializing_if = "Option::is_none")]
    appArmorProfile: Option<AppArmorProfile>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod (AppArmorProfile).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppArmorProfile {
    #[serde(rename = "type")]
    pub profile_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub localhostProfile: Option<String>,
}

/// Derive the OCI ApparmorProfile that containerd would forward for a given k8s
/// appArmorProfile, overriding the settings-derived default only when the pod
/// spec pins an explicit profile:
/// - Localhost -> Some(localhostProfile) (containerd forwards the name verbatim).
/// - Unconfined -> Some("") (containerd applies no profile).
/// - RuntimeDefault / unspecified -> keep the settings-derived value (which may
///   be None, i.e. left unconstrained, when no expected default is configured).
pub fn apply_apparmor_profile(
    process: &mut policy::KataProcess,
    profile: &Option<AppArmorProfile>,
) {
    if let Some(p) = profile {
        match p.profile_type.as_str() {
            "Localhost" => {
                process.ApparmorProfile = Some(p.localhostProfile.clone().unwrap_or_default());
            }
            "Unconfined" => {
                process.ApparmorProfile = Some(String::new());
            }
            _ => {}
        }
    }
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeccompProfile {
    #[serde(rename = "type")]
    pub profile_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub localhostProfile: Option<String>,
}

/// A security control the workload asked for that the confidential guest will not apply.
///
/// The k8s API accepts `seccompProfile` and `appArmorProfile` on every pod and container,
/// and a policy generated from such a spec looks entirely normal. Neither control is
/// actually in force in the guest, for reasons that differ per control:
///
/// - **seccomp**: the guest kernel and the agent both support it (`CONFIG_SECCOMP_FILTER`,
///   `rustjail::seccomp::init_seccomp`), but the profile would have to reach the guest as
///   host-supplied data. `rules.rego` refuses it (`is_null(i_linux.Seccomp)`) and the
///   runtime strips it anyway (`disable_guest_seccomp` defaults to true), so the container
///   runs with an unfiltered syscall surface.
/// - **apparmor**: the guest kernel is built without the AppArmor LSM and the rootfs has
///   no `apparmor_parser`, so no profile can be applied regardless of what is requested.
///   The policy still pins the field, which keeps the host from varying it, but pinning an
///   inert field confines nothing.
///
/// Reporting this at policy-generation time is the point: a silently dropped security
/// control is worse than a refused one, because the operator is left believing a boundary
/// exists where none does. This is the same class of defect as RM-97 -- the system stating
/// something untrue about its own enforcement.
///
/// `Unconfined` is never reported: asking for no confinement and receiving none is not a
/// surprise.
pub fn unenforced_security_controls(
    resource_kind: &str,
    resource_name: &str,
    seccomp: &Option<SeccompProfile>,
    apparmor: &Option<AppArmorProfile>,
) -> Vec<String> {
    let mut notices = Vec::new();

    if let Some(p) = seccomp {
        if p.profile_type != "Unconfined" {
            notices.push(format!(
                "{resource_kind} {resource_name} requests seccompProfile type {}, but the \
                 confidential guest applies no seccomp profile: the container will run with \
                 an unfiltered syscall surface.",
                p.profile_type
            ));
        }
    }

    if let Some(p) = apparmor {
        if p.profile_type != "Unconfined" {
            notices.push(format!(
                "{resource_kind} {resource_name} requests appArmorProfile type {}, but the \
                 confidential guest kernel is built without AppArmor: no profile is applied \
                 and the container is unconfined by AppArmor.",
                p.profile_type
            ));
        }
    }

    notices
}

/// Print the notices from `unenforced_security_controls` to stderr, at most once each.
///
/// Deliberately not `warn!`: `main()` calls `env_logger::init()` with no default filter, so
/// with `RUST_LOG` unset -- which is the normal case in CI and in the tooling that shells
/// out to genpolicy -- the default `error` level would discard a `warn!` entirely. A
/// security control that is silently not applied must not be announced through a channel
/// that is itself silent by default.
///
/// The deduplication is what makes a pod-level request readable: the pod's security context
/// is applied once per container, so without it a three-container pod would print the same
/// line four times (once more for the pause container). Each notice names the resource it
/// refers to, so identical strings really are the same fact.
pub fn report_unenforced_security_controls(notices: &[String]) {
    static REPORTED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    let reported = REPORTED.get_or_init(|| Mutex::new(BTreeSet::new()));

    for notice in notices {
        let is_new = reported
            .lock()
            .expect("unenforced-control notice set is never held across a panic")
            .insert(notice.clone());
        if is_new {
            eprintln!("genpolicy: warning: {notice}");
        }
    }
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PodSecurityContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runAsUser: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysctls: Option<Vec<Sysctl>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub runAsGroup: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fsGroup: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplementalGroups: Option<Vec<u32>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowPrivilegeEscalation: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub appArmorProfile: Option<AppArmorProfile>,

    /// Not consumed when building the policy -- the guest applies no seccomp filtering, so
    /// there is nothing to constrain. It is parsed anyway so that
    /// `unenforced_security_controls` can see a pod-level request and report it; before
    /// this field existed the request was dropped by serde and could not be reported at
    /// all (RM-102).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccompProfile: Option<SeccompProfile>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sysctl {
    pub name: String,
    pub value: String,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Lifecycle {
    #[serde(skip_serializing_if = "Option::is_none")]
    postStart: Option<LifecycleHandler>,

    #[serde(skip_serializing_if = "Option::is_none")]
    preStop: Option<LifecycleHandler>,

    /// K8s 1.33 `lifecycle.stopSignal`: the signal the kubelet sends to stop this
    /// container. When present it is the container's own declaration of which signal
    /// it expects, so the policy narrows the per-container signal set to it (F-76).
    #[serde(skip_serializing_if = "Option::is_none")]
    stopSignal: Option<String>,
}

/// Signal name -> number, for the Linux architectures kata supports (x86_64, aarch64,
/// s390x and ppc64le share these numbers; only mips/alpha differ, and neither is a kata
/// target). Used to translate `lifecycle.stopSignal` into the numeric set `rules.rego`
/// compares against `SignalProcessRequest.signal`.
fn signal_number(name: &str) -> Option<u32> {
    let n = match name.trim().to_ascii_uppercase().as_str() {
        "SIGHUP" => 1,
        "SIGINT" => 2,
        "SIGQUIT" => 3,
        "SIGILL" => 4,
        "SIGTRAP" => 5,
        "SIGABRT" | "SIGIOT" => 6,
        "SIGBUS" => 7,
        "SIGFPE" => 8,
        "SIGKILL" => 9,
        "SIGUSR1" => 10,
        "SIGSEGV" => 11,
        "SIGUSR2" => 12,
        "SIGPIPE" => 13,
        "SIGALRM" => 14,
        "SIGTERM" => 15,
        "SIGSTKFLT" => 16,
        "SIGCHLD" => 17,
        "SIGCONT" => 18,
        "SIGSTOP" => 19,
        "SIGTSTP" => 20,
        "SIGTTIN" => 21,
        "SIGTTOU" => 22,
        "SIGURG" => 23,
        "SIGXCPU" => 24,
        "SIGXFSZ" => 25,
        "SIGVTALRM" => 26,
        "SIGPROF" => 27,
        "SIGWINCH" => 28,
        "SIGIO" | "SIGPOLL" => 29,
        "SIGPWR" => 30,
        "SIGSYS" => 31,
        _ => return None,
    };
    Some(n)
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LifecycleHandler {
    #[serde(skip_serializing_if = "Option::is_none")]
    exec: Option<ExecAction>,
    // TODO: additional fields.
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ExecAction {
    command: Vec<String>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Capabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    add: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    drop: Option<Vec<String>>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ContainerPort {
    containerPort: i32,

    #[serde(skip_serializing_if = "Option::is_none")]
    hostIP: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hostPort: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct EnvVar {
    name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    valueFrom: Option<EnvVarSource>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvVarSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configMapKeyRef: Option<ConfigMapKeySelector>,

    #[serde(skip_serializing_if = "Option::is_none")]
    fieldRef: Option<ObjectFieldSelector>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub secretKeyRef: Option<SecretKeySelector>,

    #[serde(skip_serializing_if = "Option::is_none")]
    resourceFieldRef: Option<ResourceFieldSelector>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKeySelector {
    pub key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigMapKeySelector {
    pub key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvFromSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configMapRef: Option<ConfigMapEnvSource>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub secretRef: Option<SecretEnvSource>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretEnvSource {
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigMapEnvSource {
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,
}

/// See Reference / Kubernetes API / Common Definitions / ResourceFieldSelector.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResourceFieldSelector {
    resource: String,
    // TODO: additional fields.
}

/// See Reference / Kubernetes API / Common Definitions / ObjectFieldSelector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObjectFieldSelector {
    fieldPath: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    apiVersion: Option<String>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VolumeMount {
    pub mountPath: String,
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mountPropagation: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subPathExpr: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub readOnly: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subPath: Option<String>,
    // TODO: additional fields.
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VolumeDevice {
    pub devicePath: String,
    pub name: String,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResourceRequirements {
    #[serde(skip_serializing_if = "Option::is_none")]
    requests: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    limits: Option<BTreeMap<String, String>>,
    // TODO: claims field.
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Toleration {
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    operator: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    effect: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    tolerationSeconds: Option<i64>,
}

/// See Reference / Kubernetes API / Common Definitions / LocalObjectReference.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalObjectReference {
    name: String,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PodDNSConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    nameservers: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<Vec<PodDNSConfigOption>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    searches: Option<Vec<String>>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PodDNSConfigOption {
    name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

/// See Reference / Kubernetes API / Workload Resources / Pod.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TopologySpreadConstraint {
    maxSkew: i32,
    topologyKey: String,
    whenUnsatisfiable: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    labelSelector: Option<yaml::LabelSelector>,

    #[serde(skip_serializing_if = "Option::is_none")]
    matchLabelKeys: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    minDomains: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nodeAffinityPolicy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nodeTaintsPolicy: Option<String>,
}

impl Container {
    pub async fn init(&mut self, config: &Config, is_pause_container: bool) {
        // Load container image properties from the registry.
        self.registry = registry::get_container(config, &self.image, is_pause_container)
            .await
            .unwrap();
    }

    pub fn get_env_variables(
        &self,
        dest_env: &mut Vec<String>,
        config_maps: &Vec<config_map::ConfigMap>,
        secrets: &Vec<secret::Secret>,
        namespace: &str,
        resource: &dyn yaml::K8sResource,
        service_account_name: &str,
    ) {
        if let Some(source_env) = &self.env {
            for env_variable in source_env {
                let value = env_variable.get_value(
                    config_maps,
                    secrets,
                    namespace,
                    resource,
                    service_account_name,
                );
                let src_string = format!("{}={value}", &env_variable.name);

                if !dest_env.contains(&src_string) {
                    dest_env.push(src_string.clone());
                }
            }
        }

        if let Some(env_from_sources) = &self.envFrom {
            for env_from_source in env_from_sources {
                let env_from_source_values = env_from_source.get_values(config_maps, secrets);

                for value in env_from_source_values {
                    if !dest_env.contains(&value) {
                        dest_env.push(value.clone());
                    }
                }
            }
        }
    }

    pub fn is_privileged(&self) -> bool {
        if let Some(context) = &self.securityContext {
            if let Some(privileged) = context.privileged {
                return privileged;
            }
        }
        false
    }

    pub fn read_only_root_filesystem(&self) -> bool {
        if let Some(context) = &self.securityContext {
            if let Some(read_only) = context.readOnlyRootFilesystem {
                return read_only;
            }
        }
        false
    }

    pub fn get_process_args(&self, policy_args: &mut Vec<String>) -> (bool, bool) {
        let mut yaml_has_command = true;
        let mut yaml_has_args = true;

        if let Some(commands) = &self.command {
            for command in commands {
                policy_args.push(command.clone());
            }
        } else {
            yaml_has_command = false;
        }

        if let Some(args) = &self.args {
            for arg in args {
                policy_args.push(arg.clone());
            }
        } else {
            yaml_has_args = false;
        }

        (yaml_has_command, yaml_has_args)
    }

    /// F-76: the container's own stop signal, if the pod spec declares one
    /// (`lifecycle.stopSignal`, K8s 1.33+). Returns `None` when unset or when the name is
    /// not a signal this policy knows, in which case the caller falls back to the
    /// settings-wide default set.
    pub fn get_stop_signal(&self) -> Option<u32> {
        self.lifecycle
            .as_ref()
            .and_then(|l| l.stopSignal.as_deref())
            .and_then(signal_number)
    }

    pub fn get_exec_commands(&self) -> Vec<Vec<String>> {
        let mut commands = Vec::new();

        if let Some(probe) = &self.livenessProbe {
            if let Some(exec) = &probe.exec {
                commands.push(exec.command.clone());
            }
        }

        if let Some(probe) = &self.readinessProbe {
            if let Some(exec) = &probe.exec {
                commands.push(exec.command.clone());
            }
        }

        if let Some(probe) = &self.startupProbe {
            if let Some(exec) = &probe.exec {
                commands.push(exec.command.clone());
            }
        }

        if let Some(lifecycle) = &self.lifecycle {
            if let Some(postStart) = &lifecycle.postStart {
                if let Some(exec) = &postStart.exec {
                    commands.push(exec.command.clone());
                }
            }
            if let Some(preStop) = &lifecycle.preStop {
                if let Some(exec) = &preStop.exec {
                    commands.push(exec.command.clone());
                }
            }
        }

        commands
    }
}

impl EnvFromSource {
    pub fn get_values(
        &self,
        config_maps: &Vec<config_map::ConfigMap>,
        secrets: &Vec<secret::Secret>,
    ) -> Vec<String> {
        if let Some(config_map_env_source) = &self.configMapRef {
            if let Some(value) = config_map::get_values(&config_map_env_source.name, config_maps) {
                return value.clone();
            } else {
                panic!(
                    "Couldn't get values from configmap ref: {}",
                    &config_map_env_source.name
                );
            }
        }

        if let Some(secret_env_source) = &self.secretRef {
            if let Some(value) = secret::get_values(&secret_env_source.name, secrets) {
                return value.clone();
            } else {
                panic!(
                    "Couldn't get values from secret ref: {}",
                    &secret_env_source.name
                );
            }
        }
        panic!("envFrom: no configmap or secret source found!");
    }
}

impl EnvVar {
    pub fn get_value(
        &self,
        config_maps: &Vec<config_map::ConfigMap>,
        secrets: &Vec<secret::Secret>,
        namespace: &str,
        resource: &dyn yaml::K8sResource,
        service_account_name: &str,
    ) -> String {
        // When neither `value` nor `valueFrom` were specified, the default value is an empty string:
        // https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#environment-variables
        if let Some(value) = &self.value {
            value.clone()
        } else {
            self.get_value_from(
                config_maps,
                secrets,
                namespace,
                resource,
                service_account_name,
            )
            .unwrap_or_default()
        }
    }

    fn get_value_from(
        &self,
        config_maps: &Vec<config_map::ConfigMap>,
        secrets: &Vec<secret::Secret>,
        namespace: &str,
        resource: &dyn yaml::K8sResource,
        service_account_name: &str,
    ) -> Option<String> {
        if let Some(value_from) = &self.valueFrom {
            if let Some(value) = config_map::get_value(value_from, config_maps) {
                return Some(value);
            }

            if let Some(value) = secret::get_value(value_from, secrets) {
                return Some(value);
            }

            if let Some(value) =
                self.get_value_from_field_ref(value_from, namespace, resource, service_account_name)
            {
                return Some(value);
            }

            if value_from.resourceFieldRef.is_some() {
                // TODO: should resource fields such as "limits.cpu" or "limits.memory"
                // be handled in a different way?
                return Some("$(resource-field)".to_string());
            }

            panic!("Couldn't get the value of env var: {}", &self.name);
        }

        None
    }

    fn get_value_from_field_ref(
        &self,
        value_from: &EnvVarSource,
        namespace: &str,
        resource: &dyn yaml::K8sResource,
        service_account_name: &str,
    ) -> Option<String> {
        if let Some(field_ref) = &value_from.fieldRef {
            let path: &str = &field_ref.fieldPath;
            let v = match path {
                "metadata.name" => "$(sandbox-name)",
                "metadata.namespace" => {
                    if namespace.is_empty() {
                        "$(sandbox-namespace)"
                    } else {
                        namespace
                    }
                }
                "metadata.uid" => "$(pod-uid)",
                "status.hostIP" => "$(host-ip)",
                "status.podIP" => "$(pod-ip)",
                "spec.nodeName" => "$(node-name)",
                "spec.serviceAccountName" => service_account_name,
                _ => {
                    if let Some(value) = self.get_annotation_value(path, resource) {
                        &value.to_string()
                    } else if let Some(value) = self.get_label_value(path, resource) {
                        &value.to_string()
                    } else {
                        panic!(
                            "Env var: unsupported field reference: {}",
                            &field_ref.fieldPath
                        )
                    }
                }
            };
            Some(v.to_string())
        } else {
            None
        }
    }

    fn get_annotation_value(
        &self,
        reference: &str,
        resource: &dyn yaml::K8sResource,
    ) -> Option<String> {
        let prefix = "metadata.annotations['";
        let suffix = "']";
        if reference.starts_with(prefix) && reference.ends_with(suffix) {
            if let Some(annotations) = resource.get_annotations() {
                let start = prefix.len();
                let end = reference.len() - 2;
                let annotation = reference[start..end].to_string();

                if let Some(value) = annotations.get(&annotation) {
                    return Some(value.clone());
                } else {
                    warn!(
                        "Can't find the value of annotation {}. Allowing any value.",
                        &annotation
                    );
                }
            }

            // TODO: should missing annotations be handled differently?
            return Some("$(todo-annotation)".to_string());
        }
        None
    }

    fn get_label_value(&self, reference: &str, resource: &dyn yaml::K8sResource) -> Option<String> {
        let prefix = "metadata.labels['";
        let suffix = "']";
        if reference.starts_with(prefix) && reference.ends_with(suffix) {
            if let Some(labels) = resource.get_labels() {
                let start = prefix.len();
                let end = reference.len() - 2;
                let label = reference[start..end].to_string();

                if let Some(value) = labels.get(&label) {
                    return Some(value.clone());
                } else {
                    panic!("Can't find the value of label {}.", &label);
                }
            }
        }
        None
    }
}

#[async_trait]
impl yaml::K8sResource for Pod {
    async fn init(&mut self, config: &Config, doc_mapping: &serde_yaml::Value, _silent: bool) {
        yaml::k8s_resource_init(&mut self.spec, config).await;
        self.doc_mapping = doc_mapping.clone();
    }

    fn get_sandbox_name(&self) -> Option<String> {
        yaml::name_regex_from_meta(&self.metadata)
    }

    fn get_namespace(&self) -> Option<String> {
        self.metadata.get_namespace()
    }

    fn get_container_mounts_and_storages(
        &self,
        policy_mounts: &mut Vec<policy::KataMount>,
        storages: &mut Vec<agent::Storage>,
        container: &Container,
        settings: &settings::Settings,
    ) {
        yaml::get_container_mounts_and_storages(
            policy_mounts,
            storages,
            container,
            settings,
            &self.spec,
        );
    }

    fn generate_initdata_anno(&self, agent_policy: &policy::AgentPolicy) -> String {
        agent_policy.generate_initdata_anno(self)
    }

    fn serialize(&mut self, policy: &str) -> String {
        yaml::add_policy_annotation(&mut self.doc_mapping, "", policy);
        serde_yaml::to_string(&self.doc_mapping).unwrap()
    }

    fn get_containers(&self) -> &Vec<Container> {
        &self.spec.containers
    }

    fn get_annotations(&self) -> &Option<BTreeMap<String, String>> {
        &self.metadata.annotations
    }

    fn use_host_network(&self) -> bool {
        if let Some(host_network) = self.spec.hostNetwork {
            return host_network;
        }
        false
    }

    fn use_sandbox_pidns(&self) -> bool {
        if let Some(shared) = self.spec.shareProcessNamespace {
            return shared;
        }
        false
    }

    fn get_runtime_class_name(&self) -> Option<String> {
        self.spec
            .runtimeClassName
            .clone()
            .or_else(|| Some(String::new()))
    }

    fn get_process_fields(
        &self,
        process: &mut policy::KataProcess,
        must_check_passwd: &mut bool,
        is_pause_container: bool,
    ) {
        yaml::get_process_fields(
            process,
            must_check_passwd,
            is_pause_container,
            &self.spec.securityContext,
        );
    }

    fn get_sysctls(&self) -> Vec<Sysctl> {
        yaml::get_sysctls(&self.spec.securityContext)
    }

    fn get_pod_security_context(&self) -> Option<&PodSecurityContext> {
        self.spec.securityContext.as_ref()
    }

    fn get_labels(&self) -> &Option<BTreeMap<String, String>> {
        &self.metadata.labels
    }
}

impl Container {
    pub fn apply_capabilities(
        &self,
        capabilities: &mut policy::KataLinuxCapabilities,
        defaults: &policy::CommonData,
    ) {
        assert!(capabilities.Ambient.is_empty());
        assert!(capabilities.Inheritable.is_empty());

        if let Some(securityContext) = &self.securityContext {
            if let Some(yaml_capabilities) = &securityContext.capabilities {
                if let Some(drop) = &yaml_capabilities.drop {
                    for c in drop {
                        if c == "ALL" {
                            capabilities.Bounding.clear();
                            capabilities.Permitted.clear();
                            capabilities.Effective.clear();
                        } else {
                            let cap = "CAP_".to_string() + c;

                            capabilities.Bounding.retain(|x| !x.eq(&cap));
                            capabilities.Permitted.retain(|x| !x.eq(&cap));
                            capabilities.Effective.retain(|x| !x.eq(&cap));
                        }
                    }
                }
                if let Some(add) = &yaml_capabilities.add {
                    for c in add {
                        let cap = "CAP_".to_string() + c;

                        if !capabilities.Bounding.contains(&cap) {
                            capabilities.Bounding.push(cap.clone());
                        }
                        if !capabilities.Permitted.contains(&cap) {
                            capabilities.Permitted.push(cap.clone());
                        }
                        if !capabilities.Effective.contains(&cap) {
                            capabilities.Effective.push(cap.clone());
                        }
                    }
                }
            }
        }
        compress_default_capabilities(capabilities, defaults);
    }

    pub fn get_process_fields(&self, process: &mut policy::KataProcess) {
        debug!(
            "get_process_fields: container image = {:?}",
            self.registry.image
        );

        // A k8s container.workingDir overrides the image's WorkingDir. When unset,
        // the value derived from the container image (registry) is retained.
        if let Some(working_dir) = &self.workingDir {
            if !working_dir.is_empty() {
                process.Cwd = working_dir.clone();
                debug!("get_process_fields: set Cwd from workingDir = {working_dir}");
            }
        }

        if let Some(context) = &self.securityContext {
            debug!("get_process_fields: securityContext = {:?}", context);

            report_unenforced_security_controls(&unenforced_security_controls(
                "container",
                &self.name,
                &context.seccompProfile,
                &context.appArmorProfile,
            ));

            // Container-level appArmorProfile overrides any pod-level default.
            apply_apparmor_profile(process, &context.appArmorProfile);

            if let Some(uid) = context.runAsUser {
                debug!("get_process_fields: runAsUser uid = {uid}");

                let new_uid = uid.try_into().unwrap();
                process.User.UID = new_uid;
                // Changing the UID can break the GID mapping
                // if a /etc/passwd file is present.
                // The proper GID is determined, in order of preference:
                // 1. the securityContext runAsGroup field (applied last in code)
                // 2. lacking an explicit runAsGroup, /etc/passwd (get_gid_from_passwd_uid)
                // 3. fall back to pod-level GID if there is one (unwrap_or)
                //
                // This behavior comes from the containerd runtime implementation:
                // WithUser https://github.com/containerd/containerd/blob/main/pkg/oci/spec_opts.go#L592
                let new_gid = match self.registry.get_gid_from_passwd_uid(new_uid) {
                    Ok(gid) => gid,
                    Err(e) => {
                        debug!(
                            "get_process_fields: no GID for UID = {new_uid} in container image, error {e}"
                        );
                        process.User.GID
                    }
                };
                process.User.GID = new_gid;
                debug!(
                    "get_process_fields: set GID = {new_gid}, User = {:?}",
                    &process.User
                );

                process.User.AdditionalGids.insert(new_gid);
                debug!(
                    "get_process_fields: inserted GID = {new_gid} into AdditionalGids, User = {:?}",
                    &process.User
                );
            }

            if let Some(gid) = context.runAsGroup {
                debug!("get_process_fields: runAsGroup = {:?}", gid);

                let new_gid = gid.try_into().unwrap();
                process.User.GID = new_gid;

                process.User.AdditionalGids.insert(new_gid);
                debug!(
                    "get_process_fields: inserted GID = {new_gid} into AdditionalGids, User = {:?}",
                    &process.User
                );
            }

            if let Some(allow) = context.allowPrivilegeEscalation {
                process.NoNewPrivileges = !allow
            }
        }

        // Handle AdditionalGids here as this is the last time the UID can be updated.
        for gid in self
            .registry
            .get_additional_groups_from_uid(process.User.UID)
            .unwrap_or_default()
        {
            debug!(
                "get_process_fields: adding additional group = {gid} for UID = {}",
                process.User.UID
            );
            process.User.AdditionalGids.insert(gid);
        }
    }

    pub fn run_as_user(&self) -> Option<i64> {
        self.securityContext
            .as_ref()
            .and_then(|context| context.runAsUser)
    }

    pub fn run_as_group(&self) -> Option<i64> {
        self.securityContext
            .as_ref()
            .and_then(|context| context.runAsGroup)
    }

    // Count NVIDIA passthrough GPU requests using an explicit allowlist of resource keys.
    pub fn get_nvidia_pgpu_count(&self, pgpu_resource_keys: &[String]) -> Option<usize> {
        let limits = self.resources.as_ref()?.limits.as_ref()?;
        sum_limits_by_keys(limits, pgpu_resource_keys)
    }
}

fn compress_default_capabilities(
    capabilities: &mut policy::KataLinuxCapabilities,
    defaults: &policy::CommonData,
) {
    assert!(capabilities.Ambient.is_empty());
    assert!(capabilities.Inheritable.is_empty());

    compress_capabilities(&mut capabilities.Bounding, defaults);
    compress_capabilities(&mut capabilities.Permitted, defaults);
    compress_capabilities(&mut capabilities.Effective, defaults);
}

fn compress_capabilities(capabilities: &mut Vec<String>, defaults: &policy::CommonData) {
    let default_caps = if capabilities == &defaults.default_caps {
        "$(default_caps)"
    } else if capabilities == &defaults.privileged_caps {
        "$(privileged_caps)"
    } else {
        ""
    };

    if !default_caps.is_empty() {
        capabilities.clear();
        capabilities.push(default_caps.to_string());
    }
}

pub async fn add_pause_container(containers: &mut Vec<Container>, config: &Config) {
    debug!("Adding pause container...");
    let mut pause_container = Container {
        image: config.settings.cluster_config.pause_container_image.clone(),
        name: String::new(),
        imagePullPolicy: None,
        securityContext: Some(SecurityContext {
            readOnlyRootFilesystem: Some(true),
            allowPrivilegeEscalation: Some(false),
            privileged: None,
            capabilities: None,
            runAsUser: None,
            runAsGroup: None,
            seccompProfile: None,
            appArmorProfile: None,
        }),
        ..Default::default()
    };
    let is_pause_container = true;
    pause_container.init(config, is_pause_container).await;
    containers.insert(0, pause_container);
    debug!("pause container added.");
}

fn sum_limits_by_keys(limits: &BTreeMap<String, String>, keys: &[String]) -> Option<usize> {
    if keys.is_empty() {
        return None;
    }

    let mut total: usize = 0;
    let mut matched_any = false;

    for key in keys {
        if let Some(v) = limits.get(key) {
            matched_any = true;
            let n = v.parse::<usize>().ok()?;
            total = total.saturating_add(n);
        }
    }

    // Preserve historical semantics:
    // - if at least one key matched and all matched values parsed, return Some(total)
    // - if no key matched, return None
    matched_any.then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_limits(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn sum_limits_none_when_keys_empty() {
        let limits = make_limits(&[("nvidia.com/pgpu", "2")]);
        assert_eq!(sum_limits_by_keys(&limits, &[]), None);
    }

    #[test]
    fn sum_limits_none_when_no_match() {
        let limits = make_limits(&[("nvidia.com/pgpu", "2")]);
        let keys = vec!["vendor.com/gpu".to_string()];
        assert_eq!(sum_limits_by_keys(&limits, &keys), None);
    }

    #[test]
    fn sum_limits_sums_matching_keys() {
        let limits = make_limits(&[("nvidia.com/pgpu", "2"), ("nvidia.com/gpu_model", "1")]);
        let keys = vec![
            "nvidia.com/pgpu".to_string(),
            "nvidia.com/gpu_model".to_string(),
        ];
        assert_eq!(sum_limits_by_keys(&limits, &keys), Some(3));
    }

    #[test]
    fn sum_limits_none_on_parse_failure() {
        let limits = make_limits(&[("nvidia.com/pgpu", "two")]);
        let keys = vec!["nvidia.com/pgpu".to_string()];
        assert_eq!(sum_limits_by_keys(&limits, &keys), None);
    }

    #[test]
    fn get_nvidia_pgpu_count_uses_allowlist_keys() {
        let limits = make_limits(&[("nvidia.com/pgpu", "1"), ("nvidia.com/GH100", "2")]);
        let keys = vec![
            "nvidia.com/pgpu".to_string(),
            "nvidia.com/GH100".to_string(),
        ];
        let c = Container {
            resources: Some(ResourceRequirements {
                requests: None,
                limits: Some(limits),
            }),
            ..Default::default()
        };

        assert_eq!(c.get_nvidia_pgpu_count(&keys), Some(3));
    }

    /// RM-102: a requested-but-unapplied security control must be reported.
    ///
    /// Before this, `seccompProfile` was parsed into a field nothing ever read, so a pod
    /// asking for `RuntimeDefault` produced a policy that looked correct while the
    /// container ran with an unfiltered syscall surface and nothing said so anywhere.
    #[test]
    fn a_requested_seccomp_profile_is_reported_as_unenforced() {
        let seccomp = Some(SeccompProfile {
            profile_type: "RuntimeDefault".to_string(),
            localhostProfile: None,
        });
        let notices = unenforced_security_controls("container", "web", &seccomp, &None);

        assert_eq!(notices.len(), 1, "expected exactly one notice: {notices:?}");
        assert!(
            notices[0].contains("web") && notices[0].contains("RuntimeDefault"),
            "the notice must name the container and the profile it asked for: {notices:?}"
        );
        assert!(
            notices[0].contains("seccomp"),
            "the notice must name the control that is not applied: {notices:?}"
        );
    }

    /// AppArmor is reported for a different reason than seccomp -- the guest kernel is
    /// built without the LSM -- but the operator-visible consequence is the same.
    #[test]
    fn a_requested_apparmor_profile_is_reported_as_unenforced() {
        let apparmor = Some(AppArmorProfile {
            profile_type: "Localhost".to_string(),
            localhostProfile: Some("k8s-apparmor-example-deny-write".to_string()),
        });
        let notices = unenforced_security_controls("pod", "my-pod", &None, &apparmor);

        assert_eq!(notices.len(), 1, "expected exactly one notice: {notices:?}");
        assert!(
            notices[0].contains("AppArmor"),
            "the notice must name the control that is not applied: {notices:?}"
        );
    }

    /// Asking for no confinement and receiving none is not a surprise, so it must not be
    /// reported. Without this the notice would fire on every PSS-`baseline` pod that pins
    /// `Unconfined`, and a warning that is always present is one nobody reads.
    #[test]
    fn unconfined_requests_are_not_reported() {
        let seccomp = Some(SeccompProfile {
            profile_type: "Unconfined".to_string(),
            localhostProfile: None,
        });
        let apparmor = Some(AppArmorProfile {
            profile_type: "Unconfined".to_string(),
            localhostProfile: None,
        });

        assert!(unenforced_security_controls("pod", "p", &seccomp, &apparmor).is_empty());
    }

    /// A pod that requests neither control must stay silent.
    #[test]
    fn absent_requests_are_not_reported() {
        assert!(unenforced_security_controls("pod", "p", &None, &None).is_empty());
    }

    /// A pod-level `seccompProfile` must survive deserialization. It has no effect on the
    /// generated policy, but if serde drops it the request cannot be reported at all --
    /// which is exactly the state this change fixes.
    #[test]
    fn pod_level_seccomp_profile_is_parsed() {
        let ctx: PodSecurityContext =
            serde_yaml::from_str("seccompProfile:\n  type: RuntimeDefault\nrunAsUser: 1000\n")
                .expect("pod security context parses");

        let seccomp = ctx.seccompProfile.expect("seccompProfile is retained");
        assert_eq!(seccomp.profile_type, "RuntimeDefault");
    }
}
