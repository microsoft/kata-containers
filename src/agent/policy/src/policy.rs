// Copyright (c) 2023 Microsoft Corporation
// Copyright (c) 2024 Edgeless Systems GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Policy evaluation for the kata-agent.

use std::num::{NonZeroU32, NonZeroUsize};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

use anyhow::{bail, Error, Result};
use protocols::agent::CopyFileRequest;
use regorus::PolicyLengthConfig;
use slog::{debug, error, info, warn};
use tokio::io::AsyncWriteExt;

// Regorus' built-in policy length limits (1024 cols / 1 MiB / 20 000 lines)
// reject realistic policies emitted by `genpolicy`. In particular, container
// `Env` values such as NVIDIA_REQUIRE_CUDA on the upstream NVIDIA CUDA images
// can exceed 1 KiB on a single line. These constants raise the per-engine
// limits to values that comfortably fit any policy we expect to evaluate
// while still rejecting pathological/minified input.
//
// See microsoft/regorus#624 for the upstream API.
const POLICY_MAX_COL: u32 = 64 * 1024; // 64 KiB per line
const POLICY_MAX_FILE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB per file
const POLICY_MAX_LINES: usize = 200_000;

static POLICY_LOG_FILE: &str = "/tmp/policy.jsonl";
#[cfg(not(feature = "strict-policy"))]
static POLICY_DEFAULT_FILE: &str = "/etc/kata-opa/default-policy.rego";

/// Closed-door baseline used in strict builds. Every endpoint is left undefined, so policy
/// evaluation fails closed and every request is denied.
///
/// Unlike upstream this does not carve out `SetPolicyRequest`: strict builds deliver policy
/// exclusively through initdata, which is bound to the launch measurement, and the
/// `SetPolicy` RPC is compiled out. There is therefore no request the guest should accept
/// before an authorized policy is installed.
#[cfg(feature = "strict-policy")]
static STRICT_DEFAULT_POLICY: &str = "package agent_policy\n";

/// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

/// Singleton policy object.
#[derive(Debug, Default)]
pub struct AgentPolicy {
    /// When true policy errors are ignored, for debug purposes.
    allow_failures: bool,

    /// Strict builds: set once an authorized policy has been activated. After
    /// activation, any further call to `set_policy` is rejected (activation is one-shot;
    /// changing policy requires a new verifier-authorized epoch), so the host cannot swap
    /// the policy at runtime.
    #[cfg(feature = "strict-policy")]
    policy_activated: bool,

    /// "/tmp/policy.jsonl" log file for policy activity.
    log_file: Option<tokio::fs::File>,

    /// Regorus engine
    engine: regorus::Engine,
}

#[derive(serde::Deserialize, Debug)]
struct MetadataResponse {
    allowed: bool,
    ops: Option<json_patch::Patch>,
}

/// BL-8: a boot-time fragment declaration from the measured base policy
/// (`data.agent_policy.policy_fragments[]`). The agent pulls the COSE artifact at `feed`
/// and verifies it (issuer/SVN/receipt/ordering) through the SRM `FragmentStore`.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default, PartialEq)]
pub struct FragmentSpec {
    /// `did:x509` issuer the pulled fragment must be signed by.
    pub issuer: String,
    /// OCI reference (e.g. `contoso.azurecr.io/frag/infra:1`) to pull the COSE artifact from.
    pub feed: String,
    /// Minimum acceptable SVN (rollback floor) for this feed.
    #[serde(default)]
    pub minimum_svn: u64,
}

impl AgentPolicy {
    /// Create AgentPolicy object.
    pub fn new() -> Self {
        Self {
            allow_failures: false,
            engine: Self::new_engine(),
            ..Default::default()
        }
    }

    fn new_engine() -> regorus::Engine {
        let mut engine = regorus::Engine::new();
        engine.set_strict_builtin_errors(false);
        engine.set_gather_prints(true);
        engine.set_policy_length_config(PolicyLengthConfig {
            max_col: NonZeroU32::new(POLICY_MAX_COL).unwrap(),
            max_file_bytes: NonZeroUsize::new(POLICY_MAX_FILE_BYTES).unwrap(),
            max_lines: NonZeroUsize::new(POLICY_MAX_LINES).unwrap(),
        });
        // assign a slice of the engine data "pstate" to be used as policy state
        engine
            .add_data(
                regorus::Value::from_json_str(
                    r#"{
                        "pstate": {}
                    }"#,
                )
                .unwrap(),
            )
            .unwrap();
        engine
    }

    /// Initialize regorus.
    pub async fn initialize(
        &mut self,
        log_level: usize,
        default_policy_file: String,
        log_file: Option<String>,
    ) -> Result<()> {
        // log file path
        let log_file_path = match log_file {
            Some(path) => path,
            None => POLICY_LOG_FILE.to_string(),
        };
        let log_file_path = log_file_path.as_str();

        if log_level >= slog::Level::Debug.as_usize() {
            self.log_file = Some(
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(&log_file_path)
                    .await?,
            );
            debug!(sl!(), "policy: log file: {}", log_file_path);
        }

        self.load_initial_policy(default_policy_file).await
    }

    /// Strict builds never load a policy from the guest filesystem: the compiled-in
    /// closed-door baseline is installed unconditionally, so the guest denies all
    /// security-relevant requests until an authorized policy is delivered through initdata,
    /// which is bound to the launch measurement. (The `SetPolicy` RPC is not an alternative
    /// here -- it is compiled out of strict builds entirely.)
    ///
    /// `default_policy_file` is deliberately ignored. It is host-influenceable: it is
    /// populated from the `KATA_AGENT_POLICY_FILE` environment variable and from the agent
    /// config file, which the kernel command line can select via `agent.config_file=`.
    /// Honouring it would let a non-empty value skip the baseline and load a permissive
    /// policy from the image instead.
    #[cfg(feature = "strict-policy")]
    async fn load_initial_policy(&mut self, default_policy_file: String) -> Result<()> {
        if default_policy_file.is_empty() {
            info!(
                sl!(),
                "strict-policy: no explicit policy provided; loading closed-door baseline"
            );
        } else {
            warn!(
                sl!(),
                "strict-policy: ignoring configured policy file; the closed-door baseline is \
                 always used until an authorized policy is delivered";
                "ignored-policy-file" => &default_policy_file
            );
        }

        self.engine.add_policy(
            "strict-default.rego".to_string(),
            STRICT_DEFAULT_POLICY.to_string(),
        )?;
        self.update_allow_failures_flag().await?;
        Ok(())
    }

    /// Non-strict builds keep the historical behaviour: load the configured policy file, or
    /// fall back to the default policy shipped in the guest image.
    #[cfg(not(feature = "strict-policy"))]
    async fn load_initial_policy(&mut self, default_policy_file: String) -> Result<()> {
        let mut default_policy_file = default_policy_file;
        if default_policy_file.is_empty() {
            default_policy_file = POLICY_DEFAULT_FILE.to_string();
        }
        info!(sl!(), "default policy: {default_policy_file}");

        self.engine.add_policy_from_file(default_policy_file)?;
        self.update_allow_failures_flag().await?;
        Ok(())
    }

    async fn apply_patch_to_state(&mut self, patch: json_patch::Patch) -> Result<()> {
        // Convert the current engine data to a JSON value
        let mut state = serde_json::to_value(self.engine.get_data())?;

        // Apply the patch to the state
        json_patch::patch(&mut state, &patch)?;

        // Clear the existing data in the engine
        self.engine.clear_data();

        // Add the patched state back to the engine
        self.engine
            .add_data(regorus::Value::from_json_str(&state.to_string())?)?;

        Ok(())
    }

    /// FR-6: capture the current policy state (`pstate`) so a transaction can roll it back.
    /// The policy applies its state-mutating `ops` during authorization; snapshotting before
    /// authorization and restoring on abort ensures a failed operation leaves no committed
    /// enforcer state (equivalent to runhcs/OpenGCS `WithMetadataRollback`).
    #[cfg(feature = "strict-policy")]
    pub fn snapshot_state(&self) -> Result<String> {
        Ok(serde_json::to_value(self.engine.get_data())?.to_string())
    }

    /// FR-6: restore policy state captured by `snapshot_state` (transaction rollback).
    #[cfg(feature = "strict-policy")]
    pub fn restore_state(&mut self, snapshot: &str) -> Result<()> {
        self.engine.clear_data();
        self.engine
            .add_data(regorus::Value::from_json_str(snapshot)?)?;
        Ok(())
    }

    /// Ask regorus if an API call should be allowed or not.
    pub async fn allow_request(&mut self, ep: &str, ep_input: &str) -> Result<(bool, String)> {
        debug!(sl!(), "policy check: {ep}");
        self.log_eval_input(ep, ep_input).await;

        let query = format!("data.agent_policy.{ep}");
        self.engine.set_input_json(ep_input)?;

        let results = self.engine.eval_query(query, false)?;

        let prints = match self.engine.take_prints() {
            Ok(p) => p.join(" "),
            Err(e) => format!("Failed to get policy log: {e}"),
        };

        if results.result.len() != 1 {
            // Results are empty when AllowRequestsFailingPolicy is used to allow a Request that hasn't been defined in the policy
            if self.allow_failures {
                return Ok((true, prints));
            }
            bail!(
                "policy check: unexpected eval_query result len {:?}",
                results
            );
        }

        if results.result[0].expressions.len() != 1 {
            bail!(
                "policy check: unexpected eval_query result expressions {:?}",
                results
            );
        }

        let mut allow = match &results.result[0].expressions[0].value {
            regorus::Value::Bool(b) => *b,

            // Match against a specific variant that could be interpreted as MetadataResponse
            regorus::Value::Object(obj) => {
                let json_str = serde_json::to_string(obj)?;

                self.log_eval_input(ep, &json_str).await;

                let metadata_response: MetadataResponse = serde_json::from_str(&json_str)?;

                if metadata_response.allowed {
                    if let Some(ops) = metadata_response.ops {
                        self.apply_patch_to_state(ops).await?;
                    }
                }
                metadata_response.allowed
            }

            _ => {
                error!(sl!(), "allow_request: unexpected eval_query result type");
                bail!(
                    "policy check: unexpected eval_query result type {:?}",
                    results
                );
            }
        };

        if !allow && self.allow_failures {
            warn!(sl!(), "policy: ignoring error for {ep}");
            allow = true;
        }

        // FR-8: on denial, emit a structured, rule-attributable decision object. It
        // records the endpoint, the denied rule, and the request's top-level field names
        // (never values), so denials are auditable without leaking env values, sealed
        // secrets, or policy text.
        if !allow {
            let decision = crate::decision::DecisionObject::for_denial(ep, ep_input);
            self.log_decision(&decision).await;
        }

        Ok((allow, prints))
    }

    /// FR-8: append a structured decision object to the policy log. The object carries no
    /// request values, so this cannot leak workload data.
    async fn log_decision(&mut self, decision: &crate::decision::DecisionObject) {
        debug!(sl!(), "policy decision"; "endpoint" => &decision.endpoint, "decision" => decision.decision, "failed-rule" => &decision.failed_rule);
        if let Some(log_file) = &mut self.log_file {
            let line = format!("{}\n", decision.to_json());
            if let Err(e) = log_file.write_all(line.as_bytes()).await {
                warn!(sl!(), "policy: log_decision: write_all failed: {}", e);
            } else if let Err(e) = log_file.flush().await {
                warn!(sl!(), "policy: log_decision: flush failed: {}", e);
            }
        }
    }

    /// Replace the Policy in regorus.
    pub async fn set_policy(&mut self, policy: &str) -> Result<()> {
        // Strict builds: policy activation is one-shot. Once an authorized policy is
        // active, reject any attempt to replace it (changing policy requires a new
        // verifier-authorized epoch), so the host cannot weaken policy at runtime.
        //
        // Note this guards the *method*, not the `SetPolicy` RPC -- that RPC is compiled
        // out of strict builds entirely, so the only caller left is the initdata
        // activation in `main.rs`. The guard is the runtime invariant backing that
        // compile-time removal: if a second activation path is ever introduced, it fails
        // closed rather than silently replacing the active ruleset.
        #[cfg(feature = "strict-policy")]
        if self.policy_activated {
            bail!("strict-policy: policy already activated; activation is one-shot");
        }
        self.engine = Self::new_engine();
        self.engine
            .add_policy("agent_policy".to_string(), policy.to_string())?;
        self.update_allow_failures_flag().await?;
        #[cfg(feature = "strict-policy")]
        {
            self.policy_activated = true;
        }
        Ok(())
    }

    /// FR-1a: apply a verified policy fragment's Rego module to the live engine.
    ///
    /// This is the **only** sanctioned runtime extension of an active policy. Unlike
    /// `set_policy` it is **additive** — it adds a named module via `add_policy` and does
    /// NOT rebuild the engine, so it bypasses the FR-12 one-shot lock without weakening it
    /// (`set_policy` stays rejected after activation). The fragment module must declare a
    /// package inside the reserved fragment namespace (`agent_policy.fragments`, optionally
    /// scoped to one of the fragment's `includes`), so a fragment can only *add* rules in
    /// its own namespace and can never redefine or shadow a base `agent_policy` rule. The
    /// base policy is authored to consult `data.agent_policy.fragments.*`.
    pub fn apply_fragment_module(
        &mut self,
        name: &str,
        rego: &str,
        includes: &[String],
    ) -> Result<()> {
        let pkg = Self::rego_package(rego)
            .ok_or_else(|| anyhow::anyhow!("fragment module has no package declaration"))?;

        let mut allowed = vec!["agent_policy.fragments".to_string()];
        for ns in includes {
            allowed.push(format!("agent_policy.fragments.{ns}"));
        }
        if !allowed.iter().any(|a| a == &pkg) {
            bail!(
                "fragment module package {:?} is outside the permitted fragment namespaces {:?}",
                pkg,
                allowed
            );
        }

        // Additive merge; never resets the engine, never touches the one-shot lock.
        self.engine.add_policy(name.to_string(), rego.to_string())?;
        Ok(())
    }

    /// BL-8: read the boot-time fragment declarations the measured base policy exposes at
    /// `data.agent_policy.policy_fragments`. Each declaration names an `issuer`
    /// (`did:x509`), a `feed` (OCI reference to pull), and a `minimum_svn`. The agent's
    /// boot OCI-pull path fetches each declared fragment and verifies it through the SRM.
    ///
    /// Returns an empty vector when the base policy declares none (or the value is absent /
    /// not an array) — a base policy that declares no fragments boots with zero network
    /// calls and no behavioural change.
    pub fn fragment_specs(&mut self) -> Result<Vec<FragmentSpec>> {
        self.engine.set_input_json("{}")?;
        let results = self
            .engine
            .eval_query("data.agent_policy.policy_fragments".to_string(), false)?;
        let value = match results
            .result
            .first()
            .and_then(|r| r.expressions.first())
            .map(|e| &e.value)
        {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };
        let arr = match value {
            regorus::Value::Array(a) => a,
            regorus::Value::Undefined => return Ok(Vec::new()),
            _ => bail!("policy_fragments is not an array: {value:?}"),
        };
        let json = serde_json::to_string(arr)?;
        let specs: Vec<FragmentSpec> = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("malformed policy_fragments declaration: {e}"))?;
        Ok(specs)
    }

    /// Extract the top-level `package` path from a Rego module (e.g. "agent_policy.fragments").
    fn rego_package(rego: &str) -> Option<String> {
        for line in rego.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix("package ") {
                let pkg = rest.trim();
                if !pkg.is_empty() {
                    return Some(pkg.to_string());
                }
            }
        }
        None
    }

    async fn log_eval_input(&mut self, ep: &str, input: &str) {
        if let Some(log_file) = &mut self.log_file {
            match ep {
                "StatsContainerRequest" | "ReadStreamRequest" | "SetPolicyRequest" => {
                    // - StatsContainerRequest and ReadStreamRequest are called
                    //   relatively often, so we're not logging them, to avoid
                    //   growing this log file too much.
                    // - Confidential Containers Policy documents are relatively
                    //   large, so we're not logging them here, for SetPolicyRequest.
                    //   The Policy text can be obtained directly from the pod YAML.
                }
                _ => {
                    let log_entry = format!("{{\"kind\":\"{ep}\",\"request\":{input}}}\n");

                    if let Err(e) = log_file.write_all(log_entry.as_bytes()).await {
                        warn!(sl!(), "policy: log_eval_input: write_all failed: {}", e);
                    } else if let Err(e) = log_file.flush().await {
                        warn!(sl!(), "policy: log_eval_input: flush failed: {}", e);
                    }
                }
            }
        }
    }

    async fn update_allow_failures_flag(&mut self) -> Result<()> {
        // In strict builds the "ignore requests failing policy" escape hatch is
        // compiled out: requests that fail policy evaluation are always denied,
        // regardless of any AllowRequestsFailingPolicy value in the policy.
        #[cfg(feature = "strict-policy")]
        {
            self.allow_failures = false;
            return Ok(());
        }
        #[cfg(not(feature = "strict-policy"))]
        {
            self.allow_failures = match self.allow_request("AllowRequestsFailingPolicy", "{}").await
            {
                Ok((allowed, _prints)) => {
                    if allowed {
                        warn!(
                            sl!(),
                            "policy: AllowRequestsFailingPolicy is enabled - will ignore errors"
                        );
                    }
                    allowed
                }
                Err(_) => false,
            };
            Ok(())
        }
    }
}

/// FileType represents the S_IFMT part of the POSIX file mode such that it's easier to check in
/// Rego.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default, PartialEq)]
pub enum FileType {
    #[default]
    Unknown,
    Regular,
    Directory,
    Symlink,
}

impl From<u32> for FileType {
    // libc::S_IF* are mode_t, which is u16 on Darwin/BSD and u32 on Linux. The
    // `as u32` cast is required for Darwin but a no-op on Linux, which trips
    // clippy::unnecessary_cast. This is the documented libc-portability case
    // from https://github.com/rust-lang/rust-clippy/issues/6466.
    #[allow(clippy::unnecessary_cast)]
    fn from(raw_mode: u32) -> Self {
        const S_IFMT: u32 = libc::S_IFMT as u32;
        const S_IFREG: u32 = libc::S_IFREG as u32;
        const S_IFDIR: u32 = libc::S_IFDIR as u32;
        const S_IFLNK: u32 = libc::S_IFLNK as u32;
        match raw_mode & S_IFMT {
            S_IFREG => Self::Regular,
            S_IFDIR => Self::Directory,
            S_IFLNK => Self::Symlink,
            _ => Self::Unknown,
        }
    }
}

/// PolicyCopyFileRequest is a pre-processed variant of the CopyFileRequest that avoids byte
/// manipulation in Rego rules.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct PolicyCopyFileRequest {
    pub path: String,
    pub file_type: FileType,
    pub symlink_target: Option<String>,

    // Below fields are copied from the original request. They are not used by the genpolicy rules,
    // but might be relevant for alternative rule sets. The data field is intentionally omitted to
    // reduce serde overhead and protect the rules engine.
    pub file_size: i64,
    pub file_mode: u32,
    pub dir_mode: u32,
    pub uid: i32,
    pub gid: i32,
    pub offset: i64,
}

impl std::convert::TryFrom<&CopyFileRequest> for PolicyCopyFileRequest {
    type Error = Error;

    fn try_from(req: &CopyFileRequest) -> Result<Self> {
        let file_type = req.file_mode.into();
        let symlink_target: Option<String> = match file_type {
            FileType::Symlink => {
                if let Some(s) = OsStr::from_bytes(&req.data).to_str() {
                    Some(s.to_owned())
                } else {
                    bail!("invalid symlink content")
                }
            }
            _ => None,
        };

        Ok(PolicyCopyFileRequest {
            path: req.path.clone(),
            file_type,
            symlink_target,
            file_size: req.file_size,
            file_mode: req.file_mode,
            dir_mode: req.dir_mode,
            uid: req.uid,
            gid: req.gid,
            offset: req.offset,
        })
    }
}

#[cfg(test)]
// libc::S_IF* constants are u16 on Darwin/BSD and u32 on Linux, and the test
// cases below cast them to u32 to match the file_mode field type. The cast is
// a no-op on Linux (see https://github.com/rust-lang/rust-clippy/issues/6466).
#[allow(clippy::unnecessary_cast)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    use protocols::agent::CopyFileRequest;

    // FR-1a helper: evaluate `data.agent_policy.<ep>` on a policy's engine and return
    // whether it is boolean-true. Synchronous (no async runtime needed).
    fn eval_bool(p: &mut AgentPolicy, ep: &str) -> bool {
        p.engine.set_input_json("{}").unwrap();
        let r = p
            .engine
            .eval_query(format!("data.agent_policy.{ep}"), false)
            .unwrap();
        matches!(
            r.result
                .first()
                .and_then(|x| x.expressions.first())
                .map(|e| &e.value),
            Some(regorus::Value::Bool(true))
        )
    }

    /// Endpoints a closed-door baseline must refuse. `SetPolicyRequest` is deliberately in
    /// this list: strict builds deliver policy through initdata only.
    #[cfg(feature = "strict-policy")]
    const CLOSED_DOOR_ENDPOINTS: &[&str] = &[
        "CreateContainerRequest",
        "StartContainerRequest",
        "ExecProcessRequest",
        "ReadStreamRequest",
        "WriteStreamRequest",
        "CopyFileRequest",
        "CreateSandboxRequest",
        "GetOOMEventRequest",
        "SetPolicyRequest",
    ];

    const POLICY_ALLOW_CREATE: &str =
        "package agent_policy\ndefault CreateContainerRequest := true\n";
    const POLICY_ALLOW_EXEC: &str = "package agent_policy\ndefault ExecProcessRequest := true\n";

    /// A request is refused either by evaluating to `false` or by failing to evaluate at
    /// all (an undefined rule yields an empty result, which `allow_request` turns into an
    /// error). Both are denials; the agent maps `Err` to a refused request.
    #[cfg(feature = "strict-policy")]
    fn is_denied(outcome: Result<(bool, String)>) -> bool {
        !matches!(outcome, Ok((true, _)))
    }

    /// A3: the compiled-in baseline denies every endpoint, including `SetPolicyRequest`.
    /// Guards against reintroducing a carve-out.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn strict_baseline_denies_every_endpoint() {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "strict-default.rego".to_string(),
                STRICT_DEFAULT_POLICY.to_string(),
            )
            .unwrap();

        for ep in CLOSED_DOOR_ENDPOINTS {
            assert!(
                is_denied(p.allow_request(ep, "{}").await),
                "closed-door baseline allowed {}",
                ep
            );
        }
    }

    /// A1: in a strict build a configured policy file is ignored and the closed-door
    /// baseline is installed anyway. This is the regression test for the rootfs
    /// policy-file override: on the pre-fix agent the permissive file below is loaded and
    /// `CreateContainerRequest` is allowed.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn strict_initialize_ignores_configured_policy_file() {
        let dir = tempfile::tempdir().unwrap();
        let permissive = dir.path().join("allow-all.rego");
        std::fs::write(
            &permissive,
            "package agent_policy\ndefault CreateContainerRequest := true\n",
        )
        .unwrap();

        let mut p = AgentPolicy::new();
        p.initialize(0, permissive.to_string_lossy().into_owned(), None)
            .await
            .unwrap();

        assert!(
            is_denied(p.allow_request("CreateContainerRequest", "{}").await),
            "a policy file on the guest filesystem overrode the closed-door baseline"
        );
    }

    /// A1b: the same holds when no policy file is configured at all.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn strict_initialize_without_policy_file_is_closed() {
        let mut p = AgentPolicy::new();
        p.initialize(0, String::new(), None).await.unwrap();

        assert!(is_denied(
            p.allow_request("CreateContainerRequest", "{}").await
        ));
    }

    /// A2: non-strict builds keep the historical behaviour -- the configured policy file
    /// wins. Ensures the strict hardening did not change the default build.
    #[cfg(not(feature = "strict-policy"))]
    #[tokio::test]
    async fn non_strict_initialize_loads_configured_policy_file() {
        let dir = tempfile::tempdir().unwrap();
        let permissive = dir.path().join("allow-all.rego");
        std::fs::write(
            &permissive,
            "package agent_policy\ndefault CreateContainerRequest := true\n",
        )
        .unwrap();

        let mut p = AgentPolicy::new();
        p.initialize(0, permissive.to_string_lossy().into_owned(), None)
            .await
            .unwrap();

        let (allowed, _) = p
            .allow_request("CreateContainerRequest", "{}")
            .await
            .unwrap();
        assert!(
            allowed,
            "non-strict build should honour the configured policy file"
        );
    }

    /// FR-12 / F-7: policy activation is one-shot in strict builds. The first activation
    /// succeeds; every subsequent one is refused.
    ///
    /// This guards `AgentPolicy::set_policy()`, which is distinct from the `SetPolicy`
    /// RPC -- the RPC is compiled out of strict builds, leaving the initdata activation in
    /// `main.rs` as the only caller. That caller runs once per boot, so no live path
    /// exercises the guard today: it exists so that a future second activation path fails
    /// closed instead of silently replacing the active ruleset, and so that re-enabling
    /// the RPC does not by itself reintroduce runtime policy mutation. Without this test a
    /// regression that deleted the guard would therefore be entirely silent.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn strict_policy_activation_is_one_shot() {
        let mut p = AgentPolicy::new();
        p.set_policy(POLICY_ALLOW_CREATE).await.unwrap();

        let err = p
            .set_policy(POLICY_ALLOW_CREATE)
            .await
            .expect_err("second activation must be refused");
        assert!(
            err.to_string().contains("one-shot"),
            "unexpected rejection reason: {}",
            err
        );
    }

    /// FR-12 / F-7: a *refused* second activation must not disturb the policy already in
    /// force. The guard returns before `new_engine()`, so a rejected call cannot wipe the
    /// active ruleset -- this is the property that makes the one-shot lock safe rather than
    /// merely noisy.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn strict_rejected_activation_leaves_active_policy_intact() {
        let mut p = AgentPolicy::new();
        p.set_policy(POLICY_ALLOW_CREATE).await.unwrap();

        assert!(p.set_policy(POLICY_ALLOW_EXEC).await.is_err());

        let (allowed, _) = p
            .allow_request("CreateContainerRequest", "{}")
            .await
            .unwrap();
        assert!(allowed, "rejected activation wiped the active policy");
        assert!(
            is_denied(p.allow_request("ExecProcessRequest", "{}").await),
            "rejected activation leaked rules from the refused policy"
        );
    }

    /// FR-12 / F-5: `apply_fragment_module` is deliberately *not* covered by the one-shot
    /// lock -- it is additive and namespace-confined, so it extends the ruleset without
    /// rebuilding the engine. Pinning both halves here makes any future change to that
    /// asymmetry a conscious decision rather than an accident.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn strict_fragments_still_apply_after_activation() {
        let mut p = AgentPolicy::new();
        p.set_policy(POLICY_ALLOW_CREATE).await.unwrap();

        p.apply_fragment_module(
            "frag",
            "package agent_policy.fragments\ndefault allowed := true\n",
            &[],
        )
        .expect("an additive fragment must still apply after activation");

        assert!(
            p.set_policy(POLICY_ALLOW_CREATE).await.is_err(),
            "set_policy must stay rejected regardless of fragment activity"
        );
    }

    /// FR-12: the one-shot lock is strict-only. Default builds must keep the historical
    /// replaceable-policy behaviour, so the hardening cannot regress upstream users.
    #[cfg(not(feature = "strict-policy"))]
    #[tokio::test]
    async fn non_strict_set_policy_can_be_replaced() {
        let mut p = AgentPolicy::new();
        p.set_policy(POLICY_ALLOW_CREATE).await.unwrap();
        p.set_policy(POLICY_ALLOW_EXEC)
            .await
            .expect("non-strict builds must allow policy replacement");

        let (allowed, _) = p.allow_request("ExecProcessRequest", "{}").await.unwrap();
        assert!(allowed, "the replacement policy did not take effect");
    }

    /// BL-8: the boot-time fragment declarations are read from
    /// `data.agent_policy.policy_fragments[]`. A base policy declaring them yields the
    /// parsed specs; a base policy declaring none yields an empty list (no boot pull).
    #[test]
    fn test_fragment_specs_read_from_base_policy() {
        let mut p = AgentPolicy::new();
        // No declaration → empty (default: boot unchanged, zero network calls).
        let base_none = "package agent_policy\ndefault SetPolicyRequest := true\n";
        p.engine
            .add_policy("agent_policy".to_string(), base_none.to_string())
            .unwrap();
        assert!(p.fragment_specs().unwrap().is_empty());

        // Declared fragments → parsed into FragmentSpec entries in policy order.
        let mut p2 = AgentPolicy::new();
        let base = "package agent_policy\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:signer\", \"feed\": \"reg/frag/infra:1\", \"minimum_svn\": 2},\n\
            {\"issuer\": \"did:x509:0:sha256:BBB::CN:other\", \"feed\": \"reg/frag/net:3\"}\n\
            ]\n";
        p2.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        let specs = p2.fragment_specs().unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].issuer, "did:x509:0:sha256:AAA::CN:signer");
        assert_eq!(specs[0].feed, "reg/frag/infra:1");
        assert_eq!(specs[0].minimum_svn, 2);
        assert_eq!(specs[1].feed, "reg/frag/net:3");
        // minimum_svn defaults to 0 when omitted.
        assert_eq!(specs[1].minimum_svn, 0);
    }

    /// TC-F1.1: a verified fragment module flips a specific decision from deny→allow, and
    /// base rules are otherwise unaffected.
    #[test]
    fn test_fragment_module_flips_deny_to_allow() {
        let mut p = AgentPolicy::new();
        // Base policy: exec denied unless a fragment fact grants it.
        let base = "package agent_policy\n\
            default ExecProcessRequest := false\n\
            ExecProcessRequest := data.agent_policy.fragments.exec_allowed\n";
        p.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        assert!(
            !eval_bool(&mut p, "ExecProcessRequest"),
            "denied before fragment"
        );

        // Apply a verified fragment module in the reserved namespace.
        let module = "package agent_policy.fragments\nexec_allowed := true\n";
        p.apply_fragment_module("frag:issuerA:1", module, &[])
            .unwrap();
        assert!(
            eval_bool(&mut p, "ExecProcessRequest"),
            "allowed after fragment"
        );
    }

    /// TC-F1.2: a fragment module outside the permitted fragment namespaces is rejected —
    /// it can never redefine/shadow a base rule or contribute outside its `includes`.
    #[test]
    fn test_fragment_module_namespace_is_enforced() {
        let mut p = AgentPolicy::new();
        // A module trying to live in the base package is refused.
        let base_ns = "package agent_policy\ndefault ExecProcessRequest := true\n";
        assert!(p.apply_fragment_module("evil", base_ns, &[]).is_err());

        // A sub-namespace not in `includes` is refused; one that is, is accepted.
        let mount_ns = "package agent_policy.fragments.mount\nallowed := true\n";
        assert!(p
            .apply_fragment_module("m", mount_ns, &["exec".to_string()])
            .is_err());
        assert!(p
            .apply_fragment_module("m", mount_ns, &["mount".to_string()])
            .is_ok());
    }

    struct TestCase {
        name: String,
        input: CopyFileRequest,
        output: Option<PolicyCopyFileRequest>,
    }

    #[test]
    fn test_copyfile_translation() {
        let test_cases = [
            TestCase {
                name: "regular".to_owned(),
                input: CopyFileRequest {
                    file_mode: libc::S_IFREG as u32,
                    path: "/foo/bar".to_owned(),
                    ..Default::default()
                },
                output: Some(PolicyCopyFileRequest {
                    file_mode: libc::S_IFREG as u32,
                    file_type: FileType::Regular,
                    path: "/foo/bar".to_owned(),
                    ..Default::default()
                }),
            },
            TestCase {
                name: "directory".to_owned(),
                input: CopyFileRequest {
                    file_mode: libc::S_IFDIR as u32,
                    path: "/foo".to_owned(),
                    ..Default::default()
                },
                output: Some(PolicyCopyFileRequest {
                    file_mode: libc::S_IFDIR as u32,
                    file_type: FileType::Directory,
                    path: "/foo".to_owned(),
                    ..Default::default()
                }),
            },
            TestCase {
                name: "socket".to_owned(),
                input: CopyFileRequest {
                    file_mode: libc::S_IFSOCK as u32,
                    path: "/foo/sock".to_owned(),
                    ..Default::default()
                },
                output: Some(PolicyCopyFileRequest {
                    file_mode: libc::S_IFSOCK as u32,
                    file_type: FileType::Unknown,
                    path: "/foo/sock".to_owned(),
                    ..Default::default()
                }),
            },
            TestCase {
                name: "mixed".to_owned(),
                input: CopyFileRequest {
                    file_mode: libc::S_IFDIR as u32 | libc::S_IFREG as u32,
                    path: "/foo/dunno".to_owned(),
                    ..Default::default()
                },
                output: Some(PolicyCopyFileRequest {
                    file_mode: libc::S_IFDIR as u32 | libc::S_IFREG as u32,
                    file_type: FileType::Unknown,
                    path: "/foo/dunno".to_owned(),
                    ..Default::default()
                }),
            },
            TestCase {
                name: "all".to_owned(),
                input: CopyFileRequest {
                    file_mode: libc::S_IFMT as u32,
                    path: "/wat".to_owned(),
                    ..Default::default()
                },
                output: Some(PolicyCopyFileRequest {
                    file_mode: libc::S_IFMT as u32,
                    file_type: FileType::Unknown,
                    path: "/wat".to_owned(),
                    ..Default::default()
                }),
            },
            TestCase {
                name: "none".to_owned(),
                input: CopyFileRequest {
                    file_mode: 0,
                    path: "/0".to_owned(),
                    ..Default::default()
                },
                output: Some(PolicyCopyFileRequest {
                    file_mode: 0,
                    file_type: FileType::Unknown,
                    path: "/0".to_owned(),
                    ..Default::default()
                }),
            },
            TestCase {
                name: "link/valid".to_owned(),
                input: CopyFileRequest {
                    data: b"..data/foo".to_vec(),
                    file_mode: libc::S_IFLNK as u32,
                    path: "/foo/lnk".to_owned(),
                    ..Default::default()
                },
                output: Some(PolicyCopyFileRequest {
                    file_mode: libc::S_IFLNK as u32,
                    file_type: FileType::Symlink,
                    symlink_target: Some("..data/foo".to_owned()),
                    path: "/foo/lnk".to_owned(),
                    ..Default::default()
                }),
            },
            TestCase {
                name: "link/invalid".to_owned(),
                input: CopyFileRequest {
                    file_mode: libc::S_IFLNK as u32,
                    data: vec![0x00, 0xFF, 0xFF, 0x00],
                    ..Default::default()
                },
                output: None,
            },
        ];

        for test_case in test_cases {
            let output_res: Result<PolicyCopyFileRequest> = (&test_case.input).try_into();
            if let Some(expected) = test_case.output {
                let output = output_res.expect(&format!("test case {}", &test_case.name));
                assert_eq!(expected, output, "test case {}", &test_case.name)
            } else {
                assert!(
                    output_res.is_err(),
                    "test case {}\nunexpected success: {:?}",
                    &test_case.name,
                    output_res
                )
            }
        }
    }
}
