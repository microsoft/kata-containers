// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow OCI spec field names.
#![allow(non_snake_case)]

use crate::config_map;
use crate::containerd;
use crate::mount_and_storage;
use crate::no_policy;
use crate::pod;
use crate::policy;
use crate::secret;
use crate::utils;
use crate::yaml;

use anyhow::Result;
use log::{debug, warn};
use oci_spec::runtime as oci;
use protocols::agent;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::boxed;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::read_to_string;
use std::io::Write;
use std::process::exit;

/// Intermediary format of policy data.
pub struct AgentPolicy {
    /// K8s resources described by the input YAML file.
    pub resources: Vec<boxed::Box<dyn yaml::K8sResource + Send + Sync>>,

    /// K8s ConfigMap resources described by an additional input YAML file
    /// or by the "main" input YAML file, containing additional pod settings.
    config_maps: Vec<config_map::ConfigMap>,

    /// K8s Secret resources, containing additional pod settings.
    secrets: Vec<secret::Secret>,

    /// Rego rules read from a file (rules.rego).
    pub rules: String,

    /// Policy settings.
    pub config: utils::Config,
}

/// A trusted policy fragment reference: composed fragments are gated by
/// issuer, feed and a minimum acceptable security version number (SVN).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FragmentSpec {
    pub issuer: String,
    pub feed: String,
    pub minimum_svn: i64,

    /// BL-8: whether the guest must refuse to create containers until this fragment has
    /// been delivered and verified. Optional in the settings and defaulting to false, which
    /// is C-ACI/hcsshim behaviour — the declaration authorizes the fragment and fixes the
    /// terms it must meet, but its absence is tolerated because an undelivered fragment
    /// simply grants nothing. Set it only for fragments whose absence is not fail-safe.
    #[serde(default)]
    pub required: bool,

    /// BL-8: whether this fragment may itself declare further fragments, and whose. Passed
    /// through verbatim so the agent validates it — genpolicy has no trust context with
    /// which to judge an issuer scope, and a settings-time check here would only be a
    /// second place to keep the accepted forms in sync. Omitted from the emitted policy
    /// when unset, so existing settings produce byte-identical output.
    ///
    /// Accepted forms: `false`, `"none"`, `"same-issuer"`, `"any-authorized"`, or a list of
    /// issuer strings. Bare `true` is rejected by the agent, because it enables delegation
    /// without saying to whom.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_nested: Option<serde_json::Value>,

    /// FR-1c (F-62): policy namespaces under `agent_policy.fragments.` this fragment may
    /// contribute a module to. The fragment's own signed `includes` cannot widen this — the
    /// effective scope is the intersection — so the measured policy stays in control of
    /// which issuer may populate which namespace. Omitted when unset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<String>,

    /// FR-1n: name patterns bounding which environment variables this fragment may
    /// contribute `env_rules` for. Empty (the default) delegates nothing, so existing
    /// settings produce byte-identical output and cannot acquire the capability by upgrade.
    /// Passed through verbatim; `rules.rego` enforces the ceiling, anchoring every pattern
    /// to the whole name so a missing `^`/`$` cannot widen the grant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_env_rules: Vec<String>,

    /// FR-1o: destination patterns whose mounts a fragment for this feed may contribute.
    ///
    /// The mount half of the delegation `allow_env_rules` provides for environment
    /// variables. Same handling: `skip_serializing_if` so settings that do not use it
    /// produce byte-identical output, passed through verbatim, and the ceiling enforced in
    /// `rules.rego` with every pattern anchored to the whole destination.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_mount_rules: Vec<String>,

    /// FR-1c: whether the fragment's Rego module may be applied at all. Defaults to true;
    /// `false` accepts the fragment for its SVN/receipt/ordering record while contributing
    /// no rules. Emitted only when explicitly disabled, so existing settings produce
    /// byte-identical output.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub allow_module: bool,

    /// FR-1k: values to instantiate a parameterised fragment with, passed through verbatim.
    /// The fragment reads them via `parameter("name")`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

/// Representation of the policy_data field from the output policy text.
#[derive(Debug, Serialize)]
pub struct PolicyData {
    /// Policy properties for each container allowed to be executed in a pod.
    pub containers: Vec<ContainerPolicy>,

    /// Trusted policy fragments (issuer/feed/minimum_svn) composed into this
    /// policy's allowed container set. Empty ⇒ behaviour identical to a
    /// monolithic policy (no fragment composition).
    pub fragments: Vec<FragmentSpec>,

    /// Settings read from genpolicy-settings.json.
    pub common: CommonData,

    /// Sandbox settings read from genpolicy-settings.json.
    pub sandbox: SandboxData,

    /// Settings read from genpolicy-settings.json, related directly to each
    /// kata agent endpoint, that get added to the output policy.
    pub request_defaults: RequestDefaults,

    /// Device settings read from genpolicy-settings.json.
    pub devices: Devices,

    /// Cluster-level settings read from genpolicy-settings.json.
    pub cluster_config: ClusterConfig,
}

/// OCI Container spec. This struct is very similar to the Spec struct from
/// Kata Containers. The main difference is that the Annotations field below
/// is ordered, thus resulting in the same output policy contents every time
/// when this apps runs with the same inputs. Also, it preserves the upper
/// case field names, for consistency with the structs used by agent's rpc.rs.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KataSpec {
    /// Version of the Open Container Initiative Runtime Specification with which the bundle complies.
    #[serde(default)]
    pub Version: String,

    /// Process configures the container process.
    #[serde(default)]
    pub Process: KataProcess,

    /// Root configures the container's root filesystem.
    pub Root: KataRoot,

    /// Mounts configures additional mounts (on top of Root).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub Mounts: Vec<KataMount>,

    /// Hooks configures callbacks for container lifecycle events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Hooks: Option<oci::Hooks>,

    /// Annotations contains arbitrary metadata for the container.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub Annotations: BTreeMap<String, String>,

    /// Linux is platform-specific configuration for Linux based containers.
    #[serde(default)]
    pub Linux: KataLinux,
}

/// OCI container Process struct. This struct is very similar to the Process
/// struct generated from oci.proto. The main difference is that it preserves
/// the upper case field names from oci.proto, for consistency with the structs
/// used by agent's rpc.rs.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct KataProcess {
    /// Terminal creates an interactive terminal for the container.
    #[serde(default)]
    pub Terminal: bool,

    /// User specifies user information for the process.
    #[serde(default)]
    pub User: KataUser,

    /// Args specifies the binary and arguments for the application to execute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Args: Vec<String>,

    /// Env populates the process environment for the process.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Env: Vec<String>,

    /// Cwd is the current working directory for the process and must be
    /// relative to the container's root.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Cwd: String,

    /// Capabilities are Linux capabilities that are kept for the process.
    #[serde(default)]
    pub Capabilities: KataLinuxCapabilities,

    /// NoNewPrivileges controls whether additional privileges could be gained by processes in the container.
    #[serde(default)]
    pub NoNewPrivileges: bool,

    /// Rlimits specifies rlimit options to apply to the process. Modeled so the
    /// policy can exact-match the rlimits forwarded by the host, instead of
    /// leaving them unconstrained.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Rlimits: Vec<KataPosixRlimit>,

    /// ApparmorProfile is the expected apparmor profile for the container.
    /// Modeled as an Option so the policy can exact-match a profile the pod spec
    /// pins (or that an operator configures via settings), while leaving it
    /// unconstrained (None -> field omitted) when no expected value is known -
    /// the emitted profile for the RuntimeDefault case depends on whether
    /// apparmor is enabled on the host, which is not derivable from the pod spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ApparmorProfile: Option<String>,
}

/// OCI POSIXRlimit struct, mirroring the POSIXRlimit message from oci.proto,
/// preserving the upper case field names for consistency with agent's rpc.rs.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KataPosixRlimit {
    /// Type of the rlimit to set.
    #[serde(default)]
    pub Type: String,

    /// Hard is the hard limit for the specified type.
    #[serde(default)]
    pub Hard: u64,

    /// Soft is the soft limit for the specified type.
    #[serde(default)]
    pub Soft: u64,
}

/// OCI container User struct. This struct is very similar to the User
/// struct generated from oci.proto. The main difference is that it preserves
/// the upper case field names from oci.proto, for consistency with the structs
/// used by agent's rpc.rs.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct KataUser {
    /// UID is the user id.
    pub UID: u32,

    /// GID is the group id.
    pub GID: u32,

    /// AdditionalGids are additional group ids set for the container's process.
    pub AdditionalGids: BTreeSet<u32>,

    /// Username is the user name.
    pub Username: String,
}

/// OCI container Root struct. This struct is very similar to the Root
/// struct generated from oci.proto. The main difference is that it preserves the
/// upper case field names from oci.proto, for consistency with the structs used
/// by agent's rpc.rs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KataRoot {
    /// Path is the absolute path to the container's root filesystem.
    pub Path: String,

    /// Readonly makes the root filesystem for the container readonly before the process is executed.
    #[serde(default)]
    pub Readonly: bool,
}

/// OCI container Linux struct. This struct is similar to the Linux struct
/// generated from oci.proto, but includes just the fields that are currently
/// relevant for automatic generation of policy.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct KataLinux {
    /// Namespaces contains the namespaces that are created and/or joined by the container
    #[serde(default)]
    pub Namespaces: Vec<KataLinuxNamespace>,

    /// MaskedPaths masks over the provided paths inside the container.
    #[serde(default)]
    pub MaskedPaths: Vec<String>,

    /// ReadonlyPaths sets the provided paths as RO inside the container.
    #[serde(default)]
    pub ReadonlyPaths: Vec<String>,

    /// Devices contains devices to be created inside the container.
    #[serde(default)]
    pub Devices: Vec<KataLinuxDevice>,

    /// Sysctls contains sysctls to be applied inside the container.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub Sysctl: BTreeMap<String, String>,
}

/// OCI container LinuxNamespace struct. This struct is similar to the LinuxNamespace
/// struct generated from oci.proto, but includes just the fields that are currently
/// relevant for automatic generation of policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KataLinuxNamespace {
    /// Type is the type of namespace
    pub Type: String,

    /// Path is a path to an existing namespace persisted on disk that can be joined
    /// and is of the same type
    pub Path: String,
}

/// OCI container LinuxDevice struct. This struct is similar to the LinuxDevice
/// struct generated from oci.proto, but includes just the fields that are currently
/// relevant for automatic generation of policy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KataLinuxDevice {
    /// Type is the type of device.
    pub Type: String,

    /// Path is the path where the device should be created.
    pub Path: String,
}

/// OCI container LinuxCapabilities struct. This struct is very similar to the
/// LinuxCapabilities struct generated from oci.proto. The main difference is
/// that it preserves the upper case field names from oci.proto, for consistency
/// with the structs used by agent's rpc.rs.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct KataLinuxCapabilities {
    // Ambient is the ambient set of capabilities that are kept.
    pub Ambient: Vec<String>,

    /// Bounding is the set of capabilities checked by the kernel.
    pub Bounding: Vec<String>,

    /// Effective is the set of capabilities checked by the kernel.
    pub Effective: Vec<String>,

    /// Inheritable is the capabilities preserved across execve.
    pub Inheritable: Vec<String>,

    /// Permitted is the limiting superset for effective capabilities.
    pub Permitted: Vec<String>,
}

/// OCI container Mount struct. This struct is very similar to the Mount
/// struct generated from oci.proto. The main difference is that it preserves
/// the field names from oci.proto, for consistency with the structs used by
/// agent's rpc.rs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KataMount {
    /// destination is the path inside the container expect when it starts with "tmp:/"
    pub destination: String,

    /// source is the path inside the container expect when it starts with "vm:/dev/" or "tmp:/"
    /// the path which starts with "vm:/dev/" refers the guest vm's "/dev",
    /// especially, "vm:/dev/hostfs/" refers to the shared filesystem.
    /// "tmp:/" is a temporary directory which is used for temporary mounts.
    #[serde(default)]
    pub source: String,

    pub type_: String,
    pub options: Vec<String>,
}

/// Policy data for a container, included in the output of this app.
#[derive(Debug, Serialize)]
pub struct ContainerPolicy {
    /// Data compared with req.OCI for CreateContainerRequest calls.
    pub OCI: KataSpec,

    /// Data compared with req.storages for CreateContainerRequest calls.
    storages: Vec<agent::Storage>,

    /// Data compared with req.devices for CreateContainerRequest calls.
    devices: Vec<agent::Device>,

    /// Data compared with req.sandbox_pidns for CreateContainerRequest calls.
    sandbox_pidns: bool,

    /// Allow list of command lines that are allowed to be executed using
    /// ExecProcessRequest. By default, all ExecProcessRequest calls are blocked
    /// by the policy.
    exec_commands: Vec<Vec<String>>,

    /// Runtime-assigned annotation key-value pairs for validation of input annotations.
    runtime_anno_patterns: BTreeMap<String, String>,

    /// F-76: signal numbers `SignalProcessRequest` may deliver to *this* container,
    /// mirroring hcsshim's per-container `securityPolicyContainer.Signals`. Enforced in
    /// addition to the sandbox-wide `request_defaults.SignalProcessRequest.allowed_signals`
    /// ceiling, so a container (including one carried by a policy fragment) is signalable
    /// only with what its own declaration admits.
    allowed_signals: Vec<u32>,
}

/// See Reference / Kubernetes API / Config and Storage Resources / Volume.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Volumes {
    /// K8s EmptyDir Volume.
    pub emptyDir: Option<EmptyDirVolume>,

    /// K8s PersistentVolumeClaim Volume.
    pub persistentVolumeClaim: Option<PersistentVolumeClaimVolume>,
}

/// See Reference / Kubernetes API / Config and Storage Resources / Volume.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct EmptyDirVolume {
    pub mount_type: String,
    pub mount_point: String,
    pub mount_source: String,
    pub driver: String,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
}

/// See Reference / Kubernetes API / Config and Storage Resources / Volume.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PersistentVolumeClaimVolume {
    pub mount_type: String,
    pub mount_source: String,
}

/// CreateContainerRequest settings from genpolicy-settings.json.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateContainerRequestDefaults {
    /// Allow env variables that match any of these regexes.
    allow_env_regex: Vec<String>,
}

/// ExecProcessRequest settings from genpolicy-settings.json.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecProcessRequestDefaults {
    /// Allow these commands to be executed. This field has been deprecated - use allowed_commands instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<String>>,

    /// Allow these commands to be executed.
    pub allowed_commands: Vec<Vec<String>>,

    /// Allow commands matching these regexes to be executed.
    regex: Vec<String>,
}

/// UpdateRoutesRequest settings from genpolicy-settings.json.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateRoutesRequestDefaults {
    /// Forbid adding routes to devices of these names.
    forbidden_device_names: Vec<String>,

    /// Forbid adding routes originating from these addresses.
    forbidden_source_regex: Vec<String>,

    /// Allow routes whose destination matches any of these regexes. FR-14 asks for an
    /// allowlist on route destinations; the guest cannot know a deployment's topology, so
    /// the default is permissive and operators who do know it can narrow this.
    #[serde(default = "allow_any_regex")]
    allowed_dest_regex: Vec<String>,

    /// Allow routes whose gateway matches any of these regexes. A default route ("" dest)
    /// is redirected by its gateway, not its destination, so both are constrained.
    #[serde(default = "allow_any_regex")]
    allowed_gateway_regex: Vec<String>,
}

/// Default for the FR-14 route/address allowlists: match anything. Settings files written
/// before these fields existed keep their previous behaviour.
fn allow_any_regex() -> Vec<String> {
    vec![".*".to_string()]
}

/// UpdateInterfaceRequest settings from genpolicy-settings.json.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateInterfaceRequestDefaults {
    /// Raw flag bitmask explicitly allowed to configure
    allow_raw_flags: u32,

    /// Explicitly blocked interface names. Intent is to block changes to loopback interface.
    forbidden_names: Vec<String>,

    /// Explicitly blocked mac addresses. Intent is to block changes to loopback interface.
    forbidden_hw_addrs: Vec<String>,

    /// Allow interface addresses matching any of these regexes. Assigning an address
    /// creates a connected route for its prefix, so leaving this unconstrained would let a
    /// host obtain a covering route without calling UpdateRoutes at all.
    #[serde(default = "allow_any_regex")]
    allowed_ip_regex: Vec<String>,
}

/// UpdateInterfaceRequest settings from genpolicy-settings.json.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddARPNeighborsRequestDefaults {
    /// Explicitly blocked interface names. Intent is to block changes to loopback interface.
    forbidden_device_names: Vec<String>,
    /// Explicitly blocked IP address ranges.
    /// Should include loopback addresses and other CIDRs that should not be routed outside the VM.
    forbidden_cidrs_regex: Vec<String>,

    /// Allowed neighbor states. See https://www.man7.org/linux/man-pages/man8/ip-neighbour.8.html
    allowed_states: Vec<u32>,
}

/// SignalProcessRequest settings from genpolicy-settings.json.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignalProcessRequestDefaults {
    /// Signal numbers the Host is allowed to send to Guest container processes.
    /// Any signal not in this list is rejected, and signals targeting a container
    /// that was not created under this policy are rejected regardless of the signal.
    ///
    /// This is the sandbox-wide *ceiling*: `rules.rego` requires a signal to be in this
    /// list **and** in the target container's own `allowed_signals` (F-76), so a policy
    /// fragment can never widen the set beyond what the measured base policy admits.
    pub allowed_signals: Vec<u32>,

    /// Optional narrower set for the pause (sandbox) container, whose only lifecycle
    /// signals are stop and kill. Absent means "same as `allowed_signals`".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_container_allowed_signals: Option<Vec<u32>>,
}

impl SignalProcessRequestDefaults {
    /// Per-container signal set emitted into the generated policy (F-76 / hcsshim
    /// `securityPolicyContainer.Signals` parity). Precedence:
    ///
    /// 1. the container's own `lifecycle.stopSignal`, plus SIGKILL, which the kubelet
    ///    always retains as the ungraceful fallback after the termination grace period;
    /// 2. `pause_container_allowed_signals` for the pause container;
    /// 3. the sandbox-wide `allowed_signals`.
    ///
    /// The result is always intersected with `allowed_signals` by `rules.rego`, so no
    /// path here can widen the sandbox ceiling.
    pub fn signals_for_container(
        &self,
        is_pause_container: bool,
        stop_signal: Option<u32>,
    ) -> Vec<u32> {
        if let Some(signal) = stop_signal {
            let mut signals = vec![signal];
            if signal != SIGKILL {
                signals.push(SIGKILL);
            }
            signals.sort_unstable();
            return signals;
        }

        if is_pause_container {
            if let Some(signals) = &self.pause_container_allowed_signals {
                return signals.clone();
            }
        }

        self.allowed_signals.clone()
    }
}

const SIGKILL: u32 = 9;

/// Default signal allowlist used when `SignalProcessRequest` is absent from
/// genpolicy-settings.json. Covers the standard container-lifecycle signals
/// (SIGHUP/INT/QUIT/KILL/USR1/USR2/TERM/WINCH) while rejecting less common signals that
/// a malicious Host could otherwise inject into a workload.
///
/// SIGSTOP(19) and SIGCONT(18) are deliberately **not** here (F-77): nothing in the CRI
/// lifecycle sends them -- `docker pause` and the CRI equivalents use the cgroup freezer,
/// not signals -- while admitting them lets a malicious Host freeze any workload process
/// indefinitely (an availability attack) and single-step it for timing observation.
fn default_signal_process_request() -> SignalProcessRequestDefaults {
    SignalProcessRequestDefaults {
        allowed_signals: vec![1, 2, 3, 9, 10, 12, 15, 28],
        pause_container_allowed_signals: None,
    }
}

/// Settings for CopySingleFileRequest.
#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopySingleFileRequestDefaults {
    /// Upper bound on the size of a single file supplied by the Host.
    pub max_file_size: i64,
}

/// Settings for PutVolumeFileRevisionRequest.
#[allow(non_snake_case)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutVolumeFileRevisionRequestDefaults {
    /// Upper bound on the size of a file written into a watchable volume. Kubernetes caps
    /// ConfigMaps and Secrets at 1 MiB, so anything larger is not a legitimate projection.
    pub max_file_size: i64,
}

fn default_copy_single_file_request() -> CopySingleFileRequestDefaults {
    CopySingleFileRequestDefaults {
        max_file_size: 1024 * 1024,
    }
}

fn default_put_volume_file_request() -> PutVolumeFileRevisionRequestDefaults {
    PutVolumeFileRevisionRequestDefaults {
        max_file_size: 1024 * 1024,
    }
}

/// Settings specific to each kata agent endpoint, loaded from
/// genpolicy-settings.json.
///
/// `deny_unknown_fields` is load-bearing, not hygiene (RM-21). These settings are
/// deserialized here and then *re-serialized* into the generated policy, so a key this
/// binary does not know would be dropped silently -- and `rules.rego` reads several of
/// them by path. When `SignalProcessRequest.allowed_signals` went missing that way, the
/// signal rule became undefined, every signal was denied fail-closed, and no pod on the
/// cluster could be killed. Failing at generation time turns a version skew between the
/// binary, `rules.rego` and `genpolicy-settings.json` into an error a human reads.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestDefaults {
    /// Settings for CreateContainerRequest.
    pub CreateContainerRequest: CreateContainerRequestDefaults,

    /// Guest file paths matching these regular expressions can be copied by the Host.
    pub CopyFileRequest: Vec<String>,

    /// Commands allowed to be executed by the Host in all Guest containers.
    pub ExecProcessRequest: ExecProcessRequestDefaults,

    /// Allow the host to update routes for devices other than the loopback.
    pub UpdateRoutesRequest: UpdateRoutesRequestDefaults,

    /// Allow the host to configure only used raw_flags and reject names/mac addresses of the loopback.
    pub UpdateInterfaceRequest: UpdateInterfaceRequestDefaults,

    /// Allow the host to configure only used raw_flags and reject names/mac addresses of the loopback.
    pub AddARPNeighborsRequest: AddARPNeighborsRequestDefaults,

    /// Signals the Host is allowed to send to Guest container processes via SignalProcess.
    #[serde(default = "default_signal_process_request")]
    pub SignalProcessRequest: SignalProcessRequestDefaults,

    /// Allow the Host to close stdin for a container. Typically used with WriteStreamRequest.
    pub CloseStdinRequest: bool,

    /// Allow Host reading from Guest containers stdout and stderr.
    pub ReadStreamRequest: bool,

    /// Allow Host to update Guest mounts.
    pub UpdateEphemeralMountsRequest: bool,

    /// Allow Host writing to Guest containers stdin.
    pub WriteStreamRequest: bool,

    /// Allow Host to retrieve diagnostic data from the Guest.
    pub GetDiagnosticDataRequest: bool,

    /// Which well-known guest files the Host may supply, and how large they may be.
    ///
    /// Defaulted rather than required so that a settings file predating the
    /// host->guest content channel still generates a working policy. See the
    /// `deny_unknown_fields` note above for why the reverse (an unknown key) is fatal.
    #[serde(default = "default_copy_single_file_request")]
    pub CopySingleFileRequest: CopySingleFileRequestDefaults,

    /// Allow the Host to create a watchable volume. The request carries no field the
    /// guest acts on -- it mints its own volume id -- so this is a plain on/off switch
    /// for workloads that project no ConfigMaps, Secrets or downward-API volumes.
    #[serde(default = "default_true")]
    pub InitVolumeRequest: bool,

    /// Bounds on the files the Host may write into a watchable volume.
    #[serde(default = "default_put_volume_file_request")]
    pub PutVolumeFileRevisionRequest: PutVolumeFileRevisionRequestDefaults,

    /// Allow the Host to publish a staged watchable-volume revision.
    #[serde(default = "default_true")]
    pub CommitVolumeRevisionRequest: bool,
}

/// Struct used to read data from the settings file and copy that data into the policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonData {
    /// Path to the shared container files - e.g., "/run/kata-containers/shared/containers".
    pub cpath: String,

    /// Path to the container root - e.g., "/run/kata-containers/$(bundle-id)/rootfs".
    pub root_path: String,

    /// Regex prefix for shared file paths - e.g., "^$(cpath)/$(bundle-id)-[a-z0-9]{16}-".
    pub sfprefix: String,

    /// Path to the shared sandbox storage - e.g., "/run/kata-containers/sandbox/storage".
    pub spath: String,

    /// Regex for an IPv4 address.
    pub ipv4_a: String,

    /// Regex for an IP port number.
    pub ip_p: String,

    /// Regex for a K8s service name (RFC 1035), after downward API transformation.
    pub svc_name_downward_env: String,

    // Regex for a DNS label (e.g., host name).
    pub dns_label: String,

    /// Default capabilities for a non-privileged container.
    pub default_caps: Vec<String>,

    /// Default capabilities for a privileged container.
    pub privileged_caps: Vec<String>,

    /// RM-38: how the guest's read-only image layers are expected to be verified.
    ///
    /// * `"none"` (default) — emit no layer declarations. The guest's only trust root
    ///   for layer content is whatever the initdata supplies.
    /// * `"host-erofs-dm-verity"` — the host presents each image layer as its own
    ///   dm-verity backed EROFS lower layer (containerd's erofs snapshotter in
    ///   *unmerged* mode). Declare one storage per layer so the policy pins how many
    ///   lower layers a container may present and requires every one of them to be
    ///   verity backed.
    ///
    /// The name and the "none" default are inherited from the upstream setting that
    /// once selected the tarfs equivalent; the key survived the removal of that code
    /// with no field behind it, so until now any value here was silently ignored.
    #[serde(default = "default_image_layer_verification")]
    pub image_layer_verification: String,

    /// RM-119: admit guest-pulled images at all.
    ///
    /// Guest pull is the one storage path with no policy declaration behind it: genpolicy
    /// emits no `p_storage` for it, which is why `allow_storages` subtracts it from the
    /// declared/presented cardinality check. A host can therefore present an
    /// `image_guest_pull` storage *in addition to* a container's declared dm-verity layers
    /// — the layer declarations are all satisfied, nothing is missing, and the extra
    /// storage is exempt from the count. Where the image reference is unpinned that admits
    /// host-chosen content at the container root in a deployment whose layers are
    /// otherwise verity-bound, so the guest-pull path can be used to sidestep the
    /// host-pull integrity guarantee without ever failing a verity check.
    ///
    /// Content verification for a guest pull happens in image-rs inside CDH, which returns
    /// no proof to the agent (`ImagePullResponse` is empty), so the policy has no way to
    /// confirm what was actually pulled. Defaults to `false`: guest pull is refused, and
    /// `#[serde(default)]` is correct here because `false` *is* the safe value — an absent
    /// key denies.
    ///
    /// This gates the sandbox pause sentinel too, so the setting refuses *every*
    /// `image_guest_pull` storage rather than all but one. That is safe because the
    /// sentinel is only ever produced by the guest-pull path itself: runtime-rs reaches
    /// `get_image_reference` — the function that returns the literal `"pause"` for a
    /// `PodSandbox` — from `handle_virtual_volume_storage` alone, and only for a volume the
    /// snapshotter typed `image_guest_pull`. A host-pull deployment's sandbox rootfs is an
    /// overlay or EROFS volume, so no sentinel is presented. Under
    /// `host-erofs-dm-verity` the pause container's layers are declared and verity-bound
    /// like any other image, because `get_erofs_layer_storages` is called without an
    /// `is_pause_container` gate and `add_pause_container` pulls `pause_container_image`
    /// from the registry to obtain them — the sandbox rootfs comes from the host and needs
    /// no exemption. Deployments that do rely on the inboxed pause bundle are guest-pull
    /// deployments, and set this.
    #[serde(default)]
    pub allow_guest_pull_images: bool,

    /// RM-51: require every guest-pull image reference to be pinned by a manifest digest.
    ///
    /// Only reachable where `allow_guest_pull_images` is set: with guest pull refused
    /// outright this control has nothing to gate. It remains the second layer for a
    /// deployment that re-enables the path.
    ///
    /// Guest pull (`image_guest_pull`) unpacks into the guest's own filesystem, so there
    /// is no read-only block device and no dm-verity root hash to bind — the manifest
    /// digest is the *only* thing that identifies the content, and pinning it transitively
    /// pins every layer digest the manifest lists. A tag names whatever the host chooses to
    /// serve.
    ///
    /// The guest used to catch unpinned references separately, in
    /// `VerifiedImageStore::authorize`; that store has been removed in favour of the policy
    /// carrying the binding, so this is where the requirement lives now.
    ///
    /// Defaults to `true`, including when the key is absent from a settings file.
    /// `#[serde(default)]` would have yielded `false` there, which fails *open* on a
    /// control whose whole purpose is to pin content: guest pull has no dm-verity root
    /// hash to fall back on, so an unpinned reference is bound by nothing. A deployment
    /// that wants tag-based pod specs has to say so explicitly.
    #[serde(default = "default_true")]
    pub require_pinned_image_digests: bool,

    /// Expected apparmor profile for containers whose pod spec does not pin a
    /// specific (Localhost/Unconfined) profile. Defaults to empty, meaning the
    /// apparmor profile is left unconstrained for such containers, because the
    /// profile emitted for the RuntimeDefault case depends on whether apparmor
    /// is enabled on the host (not derivable from the pod spec). Set this to the
    /// host's runtime-default profile name (e.g. "cri-containerd.apparmor.d") to
    /// exact-match it cluster-wide.
    #[serde(default)]
    pub default_apparmor_profile: String,

    /// Expected rlimits forwarded by the host. Defaults to empty (enforce that no
    /// rlimits are set). Populate for environments that inject default rlimits.
    #[serde(default)]
    pub default_rlimits: Vec<KataPosixRlimit>,
}

/// Configuration from "kubectl config".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Pause container image reference.
    pub pause_container_image: String,

    /// Whether or not the cluster uses the guest pull mechanism.
    pub guest_pull: bool,

    /// Supported values:
    ///
    /// "v1" - Pause container UID/GID/AdditionalGids handled as in AKS pre-October 2025:
    ///         - Example container image reference: mcr.microsoft.com/oss/kubernetes/pause:3.6
    ///         - Defaults: UID=65535, GID=65535, AdditionalGids=[65535].
    ///         - When changing the GID via runAsUser or runAsGroup, the new GID value *replaces*
    ///           the default value from AdditionalGids.
    /// "v2" - Pause container UID/GID/AdditionalGids handled as in AKS post-October 2025:
    ///         - Example container image reference: mcr.microsoft.com/oss/v2/kubernetes/pause:3.6
    ///         - Defaults: UID=0, GID=0, AdditionalGids=[].
    ///         - When changing the GID via runAsUser or runAsGroup, the new GID value *gets added
    ///           as the only value* in AdditionalGids.
    pub pause_container_id_policy: String,

    /// How emptyDirs are represented in the policy.
    /// Supported values are "shared-fs", "block-encrypted", and "block-plain".
    pub emptydir_type: String,

    /// Cgroup v2 mount options that may appear beyond what genpolicy embeds
    /// (e.g. "nsdelegate", "memory_recursiveprot" on newer kernels).
    #[serde(default)]
    pub cgroup_mount_extras_allowed: Vec<String>,
}

/// Describes patterns for supported VFIO devices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VfioDevices {
    /// Device path prefix for VFIO devices (without device number suffix).
    pub device_path: String,

    /// Regex pattern for VFIO CDI annotation keys.
    #[serde(skip_serializing)]
    pub anno_key_regex: String,

    /// NVIDIA-specific VFIO settings.
    pub nvidia: VfioNvidiaDevices,
}

/// Device-related settings for policy generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Devices {
    pub vfio: VfioDevices,
}

/// Struct used to read data from the settings file and copy that data into the policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxData {
    /// Expected value of the CreateSandboxRequest storages field.
    pub storages: Vec<agent::Storage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VfioNvidiaDevices {
    /// Regex pattern for NVIDIA GPU CDI annotation values.
    #[serde(skip_serializing)]
    pub gpu_anno_value_regex: String,

    /// Device type for NVIDIA GPU VFIO devices (gk variant).
    #[serde(skip_serializing)]
    pub gpu_gk_device_type: String,

    /// Allowlist of K8s extended resource names that should be treated as NVIDIA
    /// passthrough GPU (pGPU) requests when generating policy.
    ///
    /// This is generation-time configuration; policy enforcement does not need it.
    /// We therefore skip serializing it into `policy_data`.
    #[serde(skip_serializing)]
    pub pgpu_resource_keys: Vec<String>,
}

enum K8sEnvFromSource {
    ConfigMap(config_map::ConfigMap),
    Secret(secret::Secret),
}

impl AgentPolicy {
    pub async fn from_files(config: &utils::Config) -> Result<AgentPolicy> {
        let mut config_maps = Vec::new();
        let mut secrets = Vec::new();
        let mut resources = Vec::new();
        let yaml_contents = yaml::get_input_yaml(&config.yaml_file)?;

        for document in serde_yaml::Deserializer::from_str(&yaml_contents) {
            let doc_mapping = Value::deserialize(document)?;
            if doc_mapping != Value::Null {
                let yaml_string = serde_yaml::to_string(&doc_mapping)?;
                let silent = config.silent_unsupported_fields;
                let (mut resource, kind) = yaml::new_k8s_resource(&yaml_string, silent)?;

                // Filter out resources that don't match the runtime class name.
                if let Some(resource_runtime_name) = resource.get_runtime_class_name() {
                    if !config.runtime_class_names.is_empty()
                        && !config
                            .runtime_class_names
                            .iter()
                            .any(|prefix| resource_runtime_name.starts_with(prefix))
                    {
                        resource =
                            boxed::Box::new(no_policy::NoPolicyResource { yaml: yaml_string });
                        resources.push(resource);
                        continue;
                    }
                }

                resource.init(config, &doc_mapping, silent).await;

                // ConfigMap and Secret documents contain additional input for policy generation.
                if kind.eq("ConfigMap") {
                    let config_map: config_map::ConfigMap = serde_yaml::from_str(&yaml_string)?;
                    debug!("{:#?}", &config_map);
                    config_maps.push(config_map);
                } else if kind.eq("Secret") {
                    let secret: secret::Secret = serde_yaml::from_str(&yaml_string)?;
                    debug!("{:#?}", &secret);
                    secrets.push(secret);
                }

                // Although copies of ConfigMap and Secret resources get created above,
                // those resources still have to be present in the resources vector, because
                // the elements of this vector will eventually be used to create the output
                // YAML file.
                resources.push(resource);
            }
        }

        if let Some(config_files) = &config.config_files {
            for resource_file in config_files {
                for config_resource in parse_config_file(resource_file.to_string(), config).await? {
                    match config_resource {
                        K8sEnvFromSource::ConfigMap(config_map) => {
                            config_maps.push(config_map);
                        }
                        K8sEnvFromSource::Secret(secret) => {
                            secrets.push(secret);
                        }
                    }
                }
            }
        }

        if let Ok(rules) = read_to_string(&config.rego_rules_path) {
            Ok(AgentPolicy {
                resources,
                rules,
                config_maps,
                secrets,
                config: config.clone(),
            })
        } else {
            panic!("Cannot open file {}. Please copy it to the current directory or specify the path to it using the -p parameter.",
                &config.rego_rules_path);
        }
    }

    pub fn export_policy(&mut self) {
        let mut yaml_string = String::new();
        for i in 0..self.resources.len() {
            let annotation = self.resources[i].generate_initdata_anno(self);
            yaml_string += &self.resources[i].serialize(&annotation);
        }

        if let Some(yaml_file) = &self.config.yaml_file {
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(yaml_file)
                .unwrap()
                .write_all(yaml_string.as_bytes())
                .unwrap();
        } else if !self.config.base64_out && !self.config.raw_out {
            std::io::stdout().write_all(yaml_string.as_bytes()).unwrap();
        }
    }

    pub fn generate_initdata_anno(&self, resource: &dyn yaml::K8sResource) -> String {
        let yaml_containers = resource.get_containers();
        let mut policy_containers = Vec::new();

        for (i, yaml_container) in yaml_containers.iter().enumerate() {
            debug!("generate_initdata_anno: ========================= Container {i}");
            policy_containers.push(self.get_container_policy(resource, yaml_container, i == 0));
        }

        let policy_data = policy::PolicyData {
            containers: policy_containers,
            fragments: self.config.settings.fragments.clone(),
            request_defaults: self.config.settings.request_defaults.clone(),
            common: self.config.settings.common.clone(),
            sandbox: self.config.settings.sandbox.clone(),
            devices: self.config.settings.devices.clone(),
            cluster_config: self.config.settings.cluster_config.clone(),
        };

        let json_data = serde_json::to_string_pretty(&policy_data).unwrap();
        // FR-1l: state the enforcement framework this policy was generated against, so the
        // agent's `check_framework_version` floor refuses to enforce it on an older build
        // that lacks gates the policy names. Absent is legal (legacy), which is what every
        // policy generated before this emitted, so the only thing that changes is that ours
        // are no longer legacy.
        let policy = format!(
            "{}\nframework_version := \"{}\"\npolicy_data := {json_data}",
            &self.rules, POLICY_FRAMEWORK_VERSION,
        );
        let mut initdata = self.config.initdata.clone();
        initdata.insert_data("policy.rego", policy.clone());
        let encoded = kata_types::initdata::encode_initdata(&initdata);

        if self.config.raw_out {
            std::io::stdout().write_all(policy.as_bytes()).unwrap();
        }
        if self.config.base64_out {
            std::io::stdout().write_all(encoded.as_bytes()).unwrap();
        }

        encoded
    }

    pub fn get_container_policy(
        &self,
        resource: &dyn yaml::K8sResource,
        yaml_container: &pod::Container,
        is_pause_container: bool,
    ) -> ContainerPolicy {
        let c_settings = self
            .config
            .settings
            .get_container_settings(is_pause_container);
        let mut root = c_settings.Root.clone();
        // The pause container is not described by any Kubernetes container spec, so it has no
        // securityContext to read `readOnlyRootFilesystem` from. Applying the app container's
        // flag to it produces a policy the runtime can never satisfy when the sandbox rootfs is
        // a read-only block device (host-pulled EROFS layers), so keep the settings value.
        if !is_pause_container {
            root.Readonly = yaml_container.read_only_root_filesystem();
        }

        let namespace = resource.get_namespace().unwrap_or_default();

        let use_host_network = resource.use_host_network();
        let annotations = get_container_annotations(
            resource,
            yaml_container,
            is_pause_container,
            &namespace,
            c_settings,
            use_host_network,
        );

        let is_privileged = yaml_container.is_privileged();
        let needs_privileged_mounts = is_privileged
            || (is_pause_container && resource.get_containers().iter().any(|c| c.is_privileged()));

        let process = self.get_container_process(
            resource,
            yaml_container,
            is_pause_container,
            &namespace,
            c_settings,
            is_privileged,
        );

        let mut mounts = containerd::get_mounts(is_pause_container, needs_privileged_mounts);
        mount_and_storage::get_policy_mounts(
            &self.config.settings,
            &mut mounts,
            yaml_container,
            is_pause_container,
        );

        let mut storages = Default::default();
        get_erofs_layer_storages(
            &mut storages,
            &self.config.settings.common.image_layer_verification,
            yaml_container.registry.get_image_layers(),
        );
        resource.get_container_mounts_and_storages(
            &mut mounts,
            &mut storages,
            yaml_container,
            &self.config.settings,
        );

        let mut linux = containerd::get_linux(is_privileged);
        linux.Namespaces = get_kata_namespaces(is_pause_container, use_host_network);

        if !c_settings.Linux.MaskedPaths.is_empty() {
            linux.MaskedPaths.clone_from(&c_settings.Linux.MaskedPaths);
        }
        if !c_settings.Linux.ReadonlyPaths.is_empty() {
            linux
                .ReadonlyPaths
                .clone_from(&c_settings.Linux.ReadonlyPaths);
        }

        let sandbox_pidns = if is_pause_container {
            false
        } else {
            resource.use_sandbox_pidns()
        };
        let exec_commands = yaml_container.get_exec_commands();
        let allowed_signals = self
            .config
            .settings
            .request_defaults
            .SignalProcessRequest
            .signals_for_container(is_pause_container, yaml_container.get_stop_signal());

        let mut devices: Vec<agent::Device> = vec![];
        if let Some(volumeDevices) = &yaml_container.volumeDevices {
            for volumeDevice in volumeDevices {
                if volumeDevice
                    .devicePath
                    .starts_with(&self.config.settings.devices.vfio.device_path)
                {
                    panic!(
                        "Requested volume device file path '{}' conflicts with the file path reserved for VFIO device passthrough '{}'. \
                         Note: for VFIO device passthrough, use resource limits (e.g., nvidia.com/gpu).",
                        volumeDevice.devicePath,
                        self.config.settings.devices.vfio.device_path
                    );
                }

                let mut device = agent::Device::new();
                device.set_container_path(volumeDevice.devicePath.clone());
                devices.push(device);

                linux.Devices.push(KataLinuxDevice {
                    Type: "".to_string(),
                    Path: volumeDevice.devicePath.clone(),
                })
            }
        }

        // Generate expected device entries and annotation key-value pairs for VFIO devices
        let mut runtime_anno_patterns = BTreeMap::new();
        if let Some(nvidia_pgpu_count) = yaml_container
            .get_nvidia_pgpu_count(&self.config.settings.devices.vfio.nvidia.pgpu_resource_keys)
        {
            if nvidia_pgpu_count > 0 {
                for _ in 0..nvidia_pgpu_count {
                    let mut device = agent::Device::new();
                    // The actual device number <device_path><device_number> is assigned at
                    // runtime by the device plugin. Here at policy generation time, we set
                    // the device path prefix <device_path>. When enforcing the policy, we
                    // we validate against this prefix and compare the observed device
                    // number with the number from the provided CDI annotations.
                    device
                        .set_container_path(self.config.settings.devices.vfio.device_path.clone());
                    device.set_type(
                        self.config
                            .settings
                            .devices
                            .vfio
                            .nvidia
                            .gpu_gk_device_type
                            .clone(),
                    );
                    device.set_vm_path("".to_string());
                    devices.push(device);
                }

                runtime_anno_patterns.insert(
                    self.config.settings.devices.vfio.anno_key_regex.clone(),
                    self.config
                        .settings
                        .devices
                        .vfio
                        .nvidia
                        .gpu_anno_value_regex
                        .clone(),
                );
            }
        }

        // Whether these appear on the OCI spec depends on the container runtime configuration
        // (e.g. containerd `container_annotations` allowlisting `io.kubernetes.container.*`).
        // When allowed, the kubelet passes path/policy (defaults: /dev/termination-log, File).
        // Do not put them in OCI.Annotations — that would require every CreateContainer input to
        // carry the same keys. Optional keys are allowed via runtime_anno_patterns instead.
        if !is_pause_container {
            runtime_anno_patterns.insert(
                "^io\\.kubernetes\\.container\\.terminationMessagePath$".to_string(),
                "^/.*$".to_string(),
            );
            runtime_anno_patterns.insert(
                "^io\\.kubernetes\\.container\\.terminationMessagePolicy$".to_string(),
                "^(File|FallbackToLogsOnError)$".to_string(),
            );
        }

        for default_device in &c_settings.Linux.Devices {
            linux.Devices.push(default_device.clone())
        }

        linux.Sysctl.extend(c_settings.Linux.Sysctl.clone());
        for sysctl in resource.get_sysctls() {
            linux.Sysctl.insert(sysctl.name, sysctl.value);
        }

        ContainerPolicy {
            OCI: KataSpec {
                Version: self.config.settings.kata_config.oci_version.clone(),
                Process: process,
                Root: root,
                Mounts: mounts,
                Hooks: None,
                Annotations: annotations,
                Linux: linux,
            },
            storages,
            devices,
            sandbox_pidns,
            exec_commands,
            runtime_anno_patterns,
            allowed_signals,
        }
    }

    /// Refuse to generate a policy that no container could satisfy.
    ///
    /// Where the rootfs is not otherwise declared — `image_layer_verification` is `none`,
    /// so `get_erofs_layer_storages` declares nothing — a container's rootfs arrives at
    /// runtime as an `image_guest_pull` storage, and `allow_image_guest_pull_source` is
    /// the only rule that can admit one. If `guest_pull` says that is how this cluster
    /// works and guest pull is also refused, the generated policy denies every
    /// `CreateContainerRequest` in the pod — the sandbox included, since RM-119 gates the
    /// pause sentinel too — so those settings together describe a policy with no
    /// satisfying request.
    ///
    /// Under `host-erofs-dm-verity` the rootfs *is* declared, for the pause container as
    /// much as for a workload, so the policy remains satisfiable with guest pull refused
    /// and there is nothing to report even if `guest_pull` is still set.
    ///
    /// Surface this at generation time rather than as a mystifying container-start denial
    /// much later, following the precedent of
    /// `exit_if_guest_pull_needs_security_context` above. The pause container returns
    /// early only to keep the diagnostic from being printed twice; the first workload
    /// container reports the same condition.
    fn exit_if_guest_pull_is_refused(
        &self,
        yaml_container: &pod::Container,
        is_pause_container: bool,
    ) {
        let common = &self.config.settings.common;
        if is_pause_container
            || !self.config.settings.cluster_config.guest_pull
            || common.allow_guest_pull_images
            || common.image_layer_verification != IMAGE_LAYER_VERIFICATION_NONE
        {
            return;
        }

        eprintln!(
            "ERROR: guest_pull is enabled for container '{}' using image '{}', but \
             allow_guest_pull_images is not set, so the generated policy would deny every \
             container in this pod at startup, the pause sandbox included. Guest pull is \
             refused by default because an image_guest_pull storage carries no policy \
             declaration: it is exempt from the declared-vs-presented storage count, so a \
             host can present one *in addition to* a container's declared dm-verity layers \
             and mount undeclared content at the container root without failing a verity \
             check. Either use host pull with image_layer_verification set to \
             'host-erofs-dm-verity', which declares and verity-binds the pause image's \
             layers along with every other image, or, if this cluster requires guest pull, \
             opt in explicitly by setting:\n\
             \x20   \"allow_guest_pull_images\": true\n\
             in the \"common\" section of genpolicy-settings.json. Note that guest pull \
             verifies image content in the Confidential Data Hub and reports no result back \
             to the policy, so the policy can bind the image reference but cannot confirm \
             the bytes it authorized were the bytes that were pulled.",
            yaml_container.name, yaml_container.image,
        );
        exit(1);
    }

    fn exit_if_guest_pull_needs_security_context(
        &self,
        resource: &dyn yaml::K8sResource,
        yaml_container: &pod::Container,
        is_pause_container: bool,
        process: &KataProcess,
    ) {
        if is_pause_container || !self.config.settings.cluster_config.guest_pull {
            return;
        }

        let pod_security_context = resource.get_pod_security_context();
        let uid = i64::from(process.User.UID);
        let gid = i64::from(process.User.GID);

        let effective_run_as_user = yaml_container
            .run_as_user()
            .or_else(|| pod_security_context.and_then(|context| context.runAsUser));
        let explicit_uid = effective_run_as_user == Some(uid);

        let effective_run_as_group = yaml_container
            .run_as_group()
            .or_else(|| pod_security_context.and_then(|context| context.runAsGroup));
        let explicit_gid = effective_run_as_group == Some(gid);

        let mut explicitly_added_gids = BTreeSet::new();
        if let Some(context) = pod_security_context {
            if let Some(fs_group) = context.fsGroup {
                explicitly_added_gids.insert(u32::try_from(fs_group).unwrap());
            }
            if let Some(supplemental_groups) = &context.supplementalGroups {
                explicitly_added_gids.extend(supplemental_groups.iter().copied());
            }
        }

        let missing_uid = process.User.UID != 0 && !explicit_uid;
        let missing_gid = process.User.GID != 0 && !explicit_gid;

        let missing_supplemental_groups: Vec<u32> = process
            .User
            .AdditionalGids
            .iter()
            .copied()
            .filter(|additional_gid| {
                *additional_gid != process.User.GID
                    && !explicitly_added_gids.contains(additional_gid)
            })
            .collect();

        if !missing_uid && !missing_gid && missing_supplemental_groups.is_empty() {
            return;
        }

        let mut recommendations = Vec::new();
        if missing_uid || missing_gid {
            let mut container_recommendation = format!(
                "containers:\n  - name: {}\n    securityContext:",
                yaml_container.name
            );
            if process.User.UID != 0 {
                container_recommendation
                    .push_str(&format!("\n      runAsUser: {}", process.User.UID));
            }
            if process.User.GID != 0 {
                container_recommendation
                    .push_str(&format!("\n      runAsGroup: {}", process.User.GID));
            }
            recommendations.push(container_recommendation);
        }
        if !missing_supplemental_groups.is_empty() {
            let supplemental_groups = missing_supplemental_groups
                .iter()
                .map(|gid| gid.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            recommendations.push(format!(
                "securityContext:\n  supplementalGroups: [{supplemental_groups}]"
            ));
        }
        let recommendation = recommendations.join("\n");

        eprintln!(
            "ERROR: guest_pull is enabled for container '{}' using image '{}'. \
             The generated policy expects UID={}, GID={}, AdditionalGids={:?}; \
             containerd may not reproduce image-derived user/group values when image layers are pulled in the guest. \
             Set explicit Kubernetes securityContext values, for example:\n{}\n\
             See docs/Limitations.md#guest-pulled-container-images.",
            yaml_container.name,
            yaml_container.image,
            process.User.UID,
            process.User.GID,
            process.User.AdditionalGids,
            recommendation
        );
        exit(1);
    }

    fn get_container_process(
        &self,
        resource: &dyn yaml::K8sResource,
        yaml_container: &pod::Container,
        is_pause_container: bool,
        namespace: &str,
        c_settings: &KataSpec,
        is_privileged: bool,
    ) -> KataProcess {
        ///////////////////////////////////////////////////////////////////////////////////////
        // Start with the Default Unix Spec from
        // https://github.com/containerd/containerd/blob/release/1.6/oci/spec.go#L132
        let mut process = containerd::get_process(is_privileged, &self.config.settings.common);
        debug!(
            "get_container_process: after containerd::get_process: process = {:?}",
            &process
        );

        ///////////////////////////////////////////////////////////////////////////////////////
        // Container-level settings from user's YAML.
        yaml_container.apply_capabilities(&mut process.Capabilities, &self.config.settings.common);
        debug!(
            "get_container_process: after apply_capabilities: process = {:?}",
            &process
        );

        let (yaml_has_command, yaml_has_args) = yaml_container.get_process_args(&mut process.Args);

        ///////////////////////////////////////////////////////////////////////////////////////
        // Container image settings.
        yaml_container
            .registry
            .get_process(&mut process, yaml_has_command, yaml_has_args);
        debug!(
            "get_container_process: after registry.get_processs: process = {:?}",
            &process
        );

        if let Some(tty) = yaml_container.tty {
            process.Terminal = tty;
            if tty && !is_pause_container {
                process.Env.push("TERM=xterm".to_string());
            }
        }

        if !is_pause_container {
            process.Env.push("HOSTNAME=$(host-name)".to_string());
        }

        let service_account_name = if let Some(s) = &yaml_container.serviceAccountName {
            s
        } else {
            "default"
        };

        yaml_container.get_env_variables(
            &mut process.Env,
            &self.config_maps,
            &self.secrets,
            namespace,
            resource,
            service_account_name,
        );
        debug!(
            "get_container_process: after get_env_variables: User = {:?}",
            &process.User
        );

        substitute_env_variables(&mut process.Env);
        debug!(
            "get_container_process: after substitute_env_variables: User = {:?}",
            &process.User
        );

        substitute_args_env_variables(&mut process.Args, &process.Env);
        debug!(
            "get_container_process: after substitute_args_env_variables: User = {:?}",
            &process.User
        );

        ///////////////////////////////////////////////////////////////////////////////////////
        // genpolicy-settings.json information.
        let v1_policy = self
            .config
            .settings
            .cluster_config
            .pause_container_id_policy
            == "v1";
        if !v1_policy {
            let v2_policy = self
                .config
                .settings
                .cluster_config
                .pause_container_id_policy
                == "v2";
            if !v2_policy {
                panic!(
                    "Unsupported pause_container_id_policy = {} - must be v1 or v2 in the settings file",
                    self.config.settings.cluster_config.pause_container_id_policy
                );
            }
        }
        let update_additional_gids = !is_pause_container || v1_policy;
        c_settings.get_process_fields(&mut process, update_additional_gids);
        debug!(
            "get_container_process: after c_settings.get_process_fields: User = {:?}",
            &process.User
        );

        ///////////////////////////////////////////////////////////////////////////////////////
        // Resource-level settings from user's YAML - e.g., pod-level or deployment-level.
        let mut must_check_passwd = false;
        resource.get_process_fields(&mut process, &mut must_check_passwd, is_pause_container);

        // RM-102: report a pod-level seccomp or apparmor request that the guest will not
        // apply. Reported here rather than in `yaml::get_process_fields` because this is
        // the only place that has both the security context and a name to attribute it to.
        // `report_unenforced_security_controls` deduplicates, so a pod-level request is
        // announced once rather than once per container in the pod.
        if let Some(context) = resource.get_pod_security_context() {
            pod::report_unenforced_security_controls(&pod::unenforced_security_controls(
                "pod",
                &resource.get_sandbox_name().unwrap_or_default(),
                &context.seccompProfile,
                &context.appArmorProfile,
            ));
        }

        debug!(
            "get_container_process: after resource.get_process_fields: must_check_passwd = {must_check_passwd}, User = {:?}",
            &process.User
        );

        if must_check_passwd {
            ///////////////////////////////////////////////////////////////////////////////////
            // Settings based on container image.
            let uid = process.User.UID;
            let gid = match yaml_container.registry.get_gid_from_passwd_uid(uid) {
                Ok(g) => g,
                Err(e) => {
                    debug!("get_container_process: no GID for UID = {uid} in container image, error {e}");
                    0
                }
            };
            process.User.GID = gid;
            debug!(
                "get_container_process: after registry.get_gid_from_passwd_uid: User = {:?}",
                &process.User
            );

            process.User.AdditionalGids.clear();
            debug!(
                "get_container_process: cleared AdditionalGids due to runAsUser = {}, User = {:?}",
                process.User.UID, &process.User
            );

            process.User.AdditionalGids.insert(gid);
            debug!(
                "get_container_process: inserted GID = {gid} into AdditionalGids: User = {:?}",
                &process.User
            );
        }

        yaml::apply_pod_fs_group_and_supplemental_groups(
            &mut process,
            resource.get_pod_security_context(),
            is_pause_container,
        );
        debug!(
            "get_container_process: after apply_pod_fs_group_and_supplemental_groups: User = {:?}",
            &process.User
        );

        ///////////////////////////////////////////////////////////////////////////////////////
        // Container-level settings from user's YAML.
        yaml_container.get_process_fields(&mut process);
        debug!(
            "get_container_process: after yaml_container.get_process_fields: User = {:?}",
            &process.User
        );

        debug!(
            "get_container_process: returning: User = {:?}",
            &process.User
        );
        self.exit_if_guest_pull_is_refused(yaml_container, is_pause_container);
        self.exit_if_guest_pull_needs_security_context(
            resource,
            yaml_container,
            is_pause_container,
            &process,
        );
        process
    }
}

impl KataSpec {
    fn add_annotations(&self, annotations: &mut BTreeMap<String, String>) {
        for a in &self.Annotations {
            annotations.entry(a.0.clone()).or_insert(a.1.clone());
        }
    }

    fn get_process_fields(&self, process: &mut KataProcess, update_additional_gids: bool) {
        if process.User.UID == 0 {
            process.User.UID = self.Process.User.UID;
            debug!(
                "get_process_fields: set UID = {}: User = {:?}",
                process.User.UID, &process.User
            );
        }
        if process.User.GID == 0 {
            process.User.GID = self.Process.User.GID;
            debug!(
                "get_process_fields: set GID = {}: User = {:?}",
                process.User.GID, &process.User
            );

            if update_additional_gids {
                process.User.AdditionalGids.insert(process.User.GID);
                debug!(
                    "get_process_fields: inserted process.User.GID = {} into AdditionalGids: User = {:?}",
                    process.User.GID, &process.User
                );
            }
        }

        process.User.Username = String::from(&self.Process.User.Username);
        add_missing_strings(&self.Process.Args, &mut process.Args);

        add_missing_strings(&self.Process.Env, &mut process.Env);
    }
}

async fn parse_config_file(
    yaml_file: String,
    config: &utils::Config,
) -> Result<Vec<K8sEnvFromSource>> {
    let mut k8sRes = Vec::new();
    let yaml_contents = yaml::get_input_yaml(&Some(yaml_file))?;
    for document in serde_yaml::Deserializer::from_str(&yaml_contents) {
        let doc_mapping = Value::deserialize(document)?;
        if doc_mapping != Value::Null {
            let yaml_string = serde_yaml::to_string(&doc_mapping)?;
            let silent = config.silent_unsupported_fields;
            let (mut resource, kind) = yaml::new_k8s_resource(&yaml_string, silent)?;

            resource.init(config, &doc_mapping, silent).await;

            // ConfigMap and Secret documents contain additional input for policy generation.
            if kind.eq("ConfigMap") {
                let config_map: config_map::ConfigMap = serde_yaml::from_str(&yaml_string)?;
                debug!("{:#?}", &config_map);
                k8sRes.push(K8sEnvFromSource::ConfigMap(config_map));
            } else if kind.eq("Secret") {
                let secret: secret::Secret = serde_yaml::from_str(&yaml_string)?;
                debug!("{:#?}", &secret);
                k8sRes.push(K8sEnvFromSource::Secret(secret));
            }
        }
    }

    Ok(k8sRes)
}

fn substitute_env_variables(env: &mut Vec<String>) {
    loop {
        let mut substituted = false;

        for i in 0..env.len() {
            let components: Vec<&str> = env[i].split('=').collect();
            if components.len() == 2 {
                if let Some((start, end)) = find_subst_target(components[1]) {
                    if let Some(new_value) = substitute_variable(components[1], start, end, env) {
                        let new_var = format!("{}={new_value}", &components[0]);
                        debug!("Replacing env variable <{}> with <{new_var}>", &env[i]);
                        env[i] = new_var;
                        substituted = true;
                    }
                }
            }
        }

        if !substituted {
            break;
        }
    }
}

fn find_subst_target(env_value: &str) -> Option<(usize, usize)> {
    if let Some(mut start) = env_value.find("$(") {
        start += 2;
        if env_value.len() > start {
            if let Some(end) = env_value[start..].find(')') {
                return Some((start, start + end));
            }
        }
    }

    None
}

fn substitute_variable(
    env_var: &str,
    name_start: usize,
    name_end: usize,
    env: &Vec<String>,
) -> Option<String> {
    // Variables generated by this application.
    let internal_vars = [
        "bundle-id",
        "host-ip",
        "node-name",
        "pod-ip",
        "pod-uid",
        "sandbox-id",
        "sandbox-name",
        "sandbox-namespace",
    ];

    assert!(name_start < name_end);
    assert!(name_end < env_var.len());
    let name = env_var[name_start..name_end].to_string();
    debug!("Searching for the value of <{}>", &name);

    for other_var in env {
        let components: Vec<&str> = other_var.split('=').collect();
        if components[0].eq(&name) {
            debug!("Found {} in <{}>", &name, &other_var);
            if components.len() == 2 {
                let mut replace = true;
                let value = &components[1];

                if let Some((start, end)) = find_subst_target(value) {
                    if internal_vars.contains(&&value[start..end]) {
                        // Variables used internally for Policy don't get expanded
                        // in the current design, so it's OK to use them as replacement
                        // in other env variables or command arguments.
                    } else {
                        // Don't substitute if the value includes variables to be
                        // substituted, to avoid circular substitutions.
                        replace = false;
                    }
                }

                if replace {
                    let from = format!("$({name})");
                    return Some(env_var.replace(&from, value));
                }
            }
        }
    }

    None
}

fn substitute_args_env_variables(args: &mut Vec<String>, env: &Vec<String>) {
    for arg in args {
        substitute_arg_env_variables(arg, env);
    }
}

fn substitute_arg_env_variables(arg: &mut String, env: &Vec<String>) {
    loop {
        let mut substituted = false;

        if let Some((start, end)) = find_subst_target(arg) {
            if let Some(new_value) = substitute_variable(arg, start, end, env) {
                debug!(
                    "substitute_arg_env_variables: replacing {} with {}",
                    &arg[start..end],
                    &new_value
                );
                *arg = new_value;
                substituted = true;
            }
        }

        if !substituted {
            break;
        }
    }
}

fn get_container_annotations(
    resource: &dyn yaml::K8sResource,
    yaml_container: &pod::Container,
    is_pause_container: bool,
    namespace: &str,
    c_settings: &KataSpec,
    use_host_network: bool,
) -> BTreeMap<String, String> {
    let mut annotations = if let Some(a) = resource.get_annotations() {
        let mut a_cloned = a.clone();
        yaml::remove_policy_annotation(&mut a_cloned);
        a_cloned
    } else {
        BTreeMap::new()
    };

    c_settings.add_annotations(&mut annotations);

    if let Some(name) = resource.get_sandbox_name() {
        annotations
            .entry("io.kubernetes.cri.sandbox-name".to_string())
            .or_insert(format!("^{name}$"));
    }

    if !is_pause_container {
        annotations
            .entry("io.kubernetes.cri.image-name".to_string())
            .or_insert(normalize_image_reference(&yaml_container.image));
    }

    annotations.insert(
        "io.kubernetes.cri.sandbox-namespace".to_string(),
        namespace.to_string(),
    );

    if !yaml_container.name.is_empty() {
        annotations
            .entry("io.kubernetes.cri.container-name".to_string())
            .or_insert(yaml_container.name.clone());
    }

    if is_pause_container {
        let mut network_namespace = "^/var/run/netns/cni".to_string();
        if use_host_network {
            network_namespace += "test";
        }
        network_namespace += "-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
        annotations
            .entry("nerdctl/network-namespace".to_string())
            .or_insert(network_namespace);
    }

    annotations
}

fn add_missing_strings(src: &Vec<String>, dest: &mut Vec<String>) {
    for src_string in src {
        if !dest.contains(src_string) {
            dest.push(src_string.clone());
        }
    }
    debug!("src = {:?}, dest = {:?}", src, dest)
}

fn default_image_layer_verification() -> String {
    IMAGE_LAYER_VERIFICATION_NONE.to_string()
}

pub const IMAGE_LAYER_VERIFICATION_NONE: &str = "none";
pub const IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY: &str = "host-erofs-dm-verity";

/// FR-1l: the enforcement framework version emitted into every generated policy.
///
/// Must equal `kata_agent_policy::policy::POLICY_FRAMEWORK_VERSION`; that crate is only a
/// dev-dependency here, because linking the agent's policy engine (and regorus with it)
/// into a host-side generator to read one string is not a trade worth making. The
/// equality is asserted instead by `framework_version_matches_the_agent` in
/// `tests/policy`, where both crates are in scope, so a drift fails the build rather than
/// producing policies that claim a floor the agent does not recognise.
pub const POLICY_FRAMEWORK_VERSION: &str = "1.0.0";

/// Marker driver for a declared EROFS lower layer.
///
/// The presented storage's real driver is a block driver chosen at runtime (`blk`,
/// `scsi`, `mmioblk`, ...), so the declaration cannot name it. This marker instead tells
/// `rules.rego` which matching rule applies, in the same spirit as the empty
/// driver/source that marks a host-chosen emptyDir device.
pub const EROFS_VERITY_LAYER_DRIVER: &str = "erofs-verity-layer";

/// dm-verity data and hash block size for containerd's EROFS differ in its default
/// (`--tar=f`) mode. Must track `kata_types::gpt_disk::DEFAULT_DMVERITY_BLOCK_SIZE`;
/// a mismatch shows up immediately as a policy denial rather than silently.
pub const EROFS_VERITY_BLOCK_SIZE: u32 = 4096;

/// RM-38/RM-42: declare one dm-verity backed EROFS lower layer per image layer.
///
/// In unmerged mode containerd gives each image layer its own `layer.erofs`, and
/// runtime-rs presents each as a GPT partition of a single VMDK block device, carrying
/// the layer's dm-verity parameters in `X-kata.dmverity.*` storage options. Nothing in
/// the generated policy described those storages, so a policy-enforcing guest could not
/// run an EROFS workload at all, and the layers a container mounted were constrained
/// only by the initdata trust store.
///
/// Two things are declared. The *shape*: how many lower layers there are, that each is
/// EROFS, that each must be dm-verity backed, and where they mount. The layer count
/// comes from the image manifest, so a host cannot add an extra lower layer to a
/// container's stack, nor drop one, without the count disagreeing. And, when the layer
/// carries a derived `verity_hash`, the *content*: the exact dm-verity root hash that
/// layer must present, which binds the mounted bytes to the image the policy was
/// generated for rather than merely requiring that some verity device be present.
///
/// The root hash is derived by rebuilding the layer's EROFS image locally with
/// containerd's own `mkfs.erofs` invocation (see `crate::erofs`), which is reproducible
/// for a fixed erofs-utils version. When derivation is unavailable or disabled the hash
/// is empty and only the shape is enforced, leaving the root hash's authenticity to the
/// initdata trust store as before.
fn get_erofs_layer_storages(
    storages: &mut Vec<agent::Storage>,
    image_layer_verification: &str,
    image_layers: &[crate::registry::ImageLayer],
) {
    if image_layer_verification != IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY {
        return;
    }

    debug!(
        "Declaring {} erofs dm-verity lower layers",
        image_layers.len()
    );

    // Number the partitions topmost layer first. `image_layers` is in OCI manifest order
    // (base first), but the runtime assigns GPT partitions in the order containerd's
    // snapshotter lists the erofs mounts, which is overlayfs lowerdir order -- topmost
    // first. Numbering base-first made the declared partition number disagree with the
    // presented one for every image with more than one layer, so the policy could never
    // be satisfied even when the root hashes matched exactly.
    for (index, layer) in image_layers.iter().rev().enumerate() {
        let partition_number = index + 1;
        let mut options = vec![
            "X-kata.overlay-lower".to_string(),
            "X-kata.multi-layer=true".to_string(),
            "X-kata.gpt-partitioned=true".to_string(),
            format!("X-kata.partition-number={partition_number}"),
            "X-kata.dmverity-enabled=true".to_string(),
            // Pin the verity geometry (RM-48). The agent derives
            // `blocknum = hashoffset / blocksize`, so an undeclared block size means a
            // host-chosen divisor feeding a security-relevant calculation. These are
            // static for containerd's default differ mode, so declaring them literally
            // requires an exact match.
            format!("X-kata.dmverity.blocksize={EROFS_VERITY_BLOCK_SIZE}"),
            format!("X-kata.dmverity.hashsize={EROFS_VERITY_BLOCK_SIZE}"),
        ];

        // Every declared layer must carry a derived root hash. Both registry paths
        // hard-fail if derivation is unavailable, so an empty hash here means an
        // invariant was broken rather than that the user opted out. Emitting the
        // declaration anyway would silently regress to the pre-RM-42 behaviour --
        // "some dm-verity device" rather than "this content" -- which is exactly
        // the gap this option closes, so fail loudly instead.
        assert!(
            !layer.verity_hash.is_empty(),
            "layer {} of the image has no derived dm-verity root hash, but \
             image_layer_verification is {IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY}; \
             refusing to generate a policy that would accept any verity device",
            layer.diff_id,
        );
        options.push(format!("X-kata.dmverity.roothash={}", layer.verity_hash));

        storages.push(agent::Storage {
            driver: EROFS_VERITY_LAYER_DRIVER.to_string(),
            driver_options: Vec::new(),
            // Assigned by the host at runtime: the guest device path for the VMDK that
            // spans every partition. Every layer of a container shares it.
            source: String::new(),
            fstype: "erofs".to_string(),
            options,
            mount_point: "^$(cpath)/$(bundle-id)/rootfs$".to_string(),
            fs_group: protobuf::MessageField::none(),
            shared: false,
            special_fields: ::protobuf::SpecialFields::new(),
        });
    }
}

pub fn get_kata_namespaces(
    is_pause_container: bool,
    use_host_network: bool,
) -> Vec<KataLinuxNamespace> {
    let mut namespaces: Vec<KataLinuxNamespace> = vec![KataLinuxNamespace {
        Type: "ipc".to_string(),
        Path: "".to_string(),
    }];

    if !is_pause_container || !use_host_network {
        namespaces.push(KataLinuxNamespace {
            Type: "uts".to_string(),
            Path: "".to_string(),
        });
    }

    namespaces.push(KataLinuxNamespace {
        Type: "mount".to_string(),
        Path: "".to_string(),
    });

    namespaces
}

/// Normalize a pod-spec image reference into the canonical form the container
/// runtime presents at CreateContainer time.
///
/// The runtime does not echo back the string from the pod spec. containerd
/// resolves the image and reports its canonical name, so a pod spec that says
/// `busybox:latest` arrives as `docker.io/library/busybox:latest`. Because the
/// guest-pull rules compare the declared image against the presented one, the
/// policy has to declare the same spelling or every unqualified Docker Hub
/// reference is denied.
fn normalize_image_reference(image: &str) -> String {
    match image.parse::<oci_client::Reference>() {
        Ok(reference) => reference.whole(),
        Err(e) => {
            warn!("Failed to parse image reference {image}: {e}. Using it verbatim.");
            let mut image_name = image.to_string();
            if image_name.find(':').is_none() {
                image_name += ":latest";
            }
            image_name
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_image_reference;
    use super::{
        get_erofs_layer_storages, IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY,
        IMAGE_LAYER_VERIFICATION_NONE,
    };
    use crate::registry::ImageLayer;

    /// `count` layers, each carrying a distinct derived root hash.
    fn layers_with_hashes(count: usize) -> Vec<ImageLayer> {
        (0..count)
            .map(|i| ImageLayer {
                diff_id: format!("sha256:diff{i}"),
                passwd: String::new(),
                group: String::new(),
                verity_hash: format!("{:02x}", i).repeat(32),
                verity_key: "test".to_string(),
            })
            .collect()
    }

    /// `count` layers with no derived hash, as when derivation is disabled.
    fn layers_without_hashes(count: usize) -> Vec<ImageLayer> {
        (0..count)
            .map(|i| ImageLayer {
                diff_id: format!("sha256:diff{i}"),
                passwd: String::new(),
                group: String::new(),
                verity_hash: String::new(),
                verity_key: String::new(),
            })
            .collect()
    }

    #[test]
    fn erofs_layers_not_declared_by_default() {
        // The default must stay inert: an existing deployment that has not opted into
        // erofs layer verification must generate exactly the policy it did before.
        let mut storages = Vec::new();
        get_erofs_layer_storages(
            &mut storages,
            IMAGE_LAYER_VERIFICATION_NONE,
            &layers_with_hashes(4),
        );
        assert!(storages.is_empty());

        let mut storages = Vec::new();
        get_erofs_layer_storages(&mut storages, "something-else", &layers_with_hashes(4));
        assert!(storages.is_empty());
    }

    #[test]
    fn erofs_layers_declared_one_per_image_layer() {
        let layers = layers_with_hashes(3);
        let mut storages = Vec::new();
        get_erofs_layer_storages(
            &mut storages,
            IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY,
            &layers,
        );
        assert_eq!(storages.len(), 3);

        for (i, storage) in storages.iter().enumerate() {
            assert_eq!(storage.driver, super::EROFS_VERITY_LAYER_DRIVER);
            assert_eq!(storage.fstype, "erofs");
            assert_eq!(storage.mount_point, "^$(cpath)/$(bundle-id)/rootfs$");
            assert!(storage.source.is_empty());
            assert!(storage.driver_options.is_empty());

            // Partition numbers are 1-based and must be distinct, so that the policy
            // pins the order of the layer stack rather than just its size. They count
            // the topmost layer first, matching the order the runtime assigns GPT
            // partitions (containerd's overlayfs lowerdir order), which is the reverse
            // of the OCI manifest order `image_layers` arrives in.
            assert!(storage
                .options
                .contains(&format!("X-kata.partition-number={}", i + 1)));

            // Every layer must be required to be verity backed. A layer declared
            // without this is a layer the guest would mount unverified.
            assert!(storage
                .options
                .contains(&"X-kata.dmverity-enabled=true".to_string()));

            // RM-42: the layer's derived root hash is declared, so the mounted bytes
            // are bound to this specific layer rather than to "some verity device".
            // Paired with the reversed numbering above: partition 1 carries the last
            // manifest layer's hash.
            assert!(storage.options.contains(&format!(
                "X-kata.dmverity.roothash={}",
                layers[layers.len() - 1 - i].verity_hash
            )));
        }
    }

    /// The partition a layer is declared under must be the one the runtime will present
    /// it on. `image_layers` is OCI manifest order (base first), while the runtime
    /// numbers partitions in containerd's overlayfs lowerdir order (topmost first), so
    /// the declaration counts backwards. Numbering the same direction as the manifest
    /// made every multi-layer image unsatisfiable even though its root hashes were
    /// correct, which reads like a verity mismatch and is not.
    #[test]
    fn erofs_layer_partitions_are_numbered_topmost_first() {
        let layers = layers_with_hashes(3);
        let mut storages = Vec::new();
        get_erofs_layer_storages(
            &mut storages,
            IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY,
            &layers,
        );

        let partition_of = |hash: &str| -> String {
            let s = storages
                .iter()
                .find(|s| {
                    s.options
                        .contains(&format!("X-kata.dmverity.roothash={hash}"))
                })
                .expect("every layer hash must be declared");
            s.options
                .iter()
                .find(|o| o.starts_with("X-kata.partition-number="))
                .expect("every declaration carries a partition number")
                .clone()
        };

        assert_eq!(
            partition_of(&layers[2].verity_hash),
            "X-kata.partition-number=1"
        );
        assert_eq!(
            partition_of(&layers[1].verity_hash),
            "X-kata.partition-number=2"
        );
        assert_eq!(
            partition_of(&layers[0].verity_hash),
            "X-kata.partition-number=3"
        );
    }

    /// Each layer must carry its own hash. Emitting a shared or copied value would
    /// let one layer of an image be substituted for another.
    #[test]
    fn erofs_layers_declare_distinct_root_hashes() {
        let mut storages = Vec::new();
        get_erofs_layer_storages(
            &mut storages,
            IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY,
            &layers_with_hashes(4),
        );
        let hashes: std::collections::BTreeSet<&String> = storages
            .iter()
            .map(|s| {
                s.options
                    .iter()
                    .find(|o| o.starts_with("X-kata.dmverity.roothash="))
                    .expect("every layer declares a root hash")
            })
            .collect();
        assert_eq!(hashes.len(), 4);
    }

    /// A layer with no derived hash must abort generation rather than fall back to
    /// the weaker "some dm-verity device" declaration. Silently degrading here would
    /// reintroduce the exact gap RM-42 closes, and it would do so invisibly: the
    /// policy would still look like it verified the layers.
    #[test]
    #[should_panic(expected = "no derived dm-verity root hash")]
    fn erofs_layers_refuse_to_declare_underived_layers() {
        let mut storages = Vec::new();
        get_erofs_layer_storages(
            &mut storages,
            IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY,
            &layers_without_hashes(2),
        );
    }

    #[test]
    fn erofs_single_layer_image_declares_one_storage() {
        let mut storages = Vec::new();
        get_erofs_layer_storages(
            &mut storages,
            IMAGE_LAYER_VERIFICATION_EROFS_DM_VERITY,
            &layers_with_hashes(1),
        );
        assert_eq!(storages.len(), 1);
        assert!(storages[0]
            .options
            .contains(&"X-kata.partition-number=1".to_string()));
    }

    #[test]
    fn normalizes_bare_docker_hub_names() {
        assert_eq!(
            normalize_image_reference("busybox"),
            "docker.io/library/busybox:latest"
        );
        assert_eq!(
            normalize_image_reference("busybox:latest"),
            "docker.io/library/busybox:latest"
        );
        assert_eq!(
            normalize_image_reference("redis:7"),
            "docker.io/library/redis:7"
        );
    }

    #[test]
    fn normalizes_namespaced_docker_hub_names() {
        assert_eq!(
            normalize_image_reference("bitnami/nginx:1.25"),
            "docker.io/bitnami/nginx:1.25"
        );
    }

    #[test]
    fn leaves_fully_qualified_references_alone() {
        for image in [
            "quay.io/prometheus/busybox:latest",
            "ghcr.io/burgerdev/weird-images/gid:latest",
            "registry.k8s.io/pause:3.9",
            "myregistry:5000/app:1",
        ] {
            assert_eq!(normalize_image_reference(image), image);
        }
    }

    #[test]
    fn preserves_digests() {
        let pinned = "ghcr.io/burgerdev/weird-images/gid:latest@sha256:bdbb485bb9e3baf381a2957b9369b6051c6113097a5f8dcee27faff17624a2c0";
        assert_eq!(normalize_image_reference(pinned), pinned);
        assert_eq!(
            normalize_image_reference("busybox@sha256:bdbb485bb9e3baf381a2957b9369b6051c6113097a5f8dcee27faff17624a2c0"),
            "docker.io/library/busybox@sha256:bdbb485bb9e3baf381a2957b9369b6051c6113097a5f8dcee27faff17624a2c0"
        );
    }

    #[test]
    fn falls_back_to_the_verbatim_reference_when_parsing_fails() {
        assert_eq!(
            normalize_image_reference("NOT A REFERENCE"),
            "NOT A REFERENCE:latest"
        );
    }
}
