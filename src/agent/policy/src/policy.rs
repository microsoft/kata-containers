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

/// BL-8: whether a delivered fragment may itself declare further fragments, and whose.
///
/// One attribute carries both the switch and the scope, so the two cannot drift apart —
/// there is no way to enable delegation without saying how far it reaches.
///
/// Authored in rego as the `allow_nested` field of a declaration:
///
/// ```text
/// (omitted) | false        no delegation                              (default)
/// "same-issuer"           nested declarations may name only the delivering
///                         fragment's own issuer
/// "any-authorized"        any issuer the measured trust root authorizes
/// ["did:x509:a", ...]     only these issuers
/// ```
///
/// `true` is deliberately **not** accepted: it enables delegation without saying whose, and
/// picking a scope on the author's behalf is exactly the kind of silent assumption this
/// gate exists to prevent. It is rejected with a message naming the valid forms.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum AllowNested {
    /// `false` — no delegation. `true` is parsed here so it can be rejected by name.
    Flag(bool),
    /// `"same-issuer"` / `"any-authorized"` / `"none"`.
    Mode(String),
    /// An explicit issuer allow-list.
    Issuers(Vec<String>),
}

impl Default for AllowNested {
    fn default() -> Self {
        AllowNested::Flag(false)
    }
}

/// The resolved, validated form of [`AllowNested`].
#[derive(Clone, Debug, PartialEq)]
pub enum NestedScope {
    /// The fragment may not declare further fragments.
    None,
    /// Nested declarations must name the delivering fragment's own issuer.
    SameIssuer,
    /// Nested declarations may name any issuer the measured trust root authorizes.
    AnyAuthorized,
    /// Nested declarations may name only these issuers.
    Issuers(Vec<String>),
}

impl NestedScope {
    /// Whether `issuer` may appear in a nested declaration carried by a fragment signed by
    /// `parent_issuer`.
    ///
    /// Note this is a *scope* check only. It never widens trust on its own: the nested
    /// fragment must still be signed by an issuer the measured trust root authorizes, or
    /// `verify_cose` rejects it as `UnauthorizedIssuer` regardless of what any declaration
    /// says. `AnyAuthorized` therefore means "anyone the trust root already trusts", not
    /// "anyone".
    pub fn permits(&self, parent_issuer: &str, issuer: &str) -> bool {
        match self {
            NestedScope::None => false,
            NestedScope::SameIssuer => issuer == parent_issuer,
            NestedScope::AnyAuthorized => true,
            NestedScope::Issuers(list) => list.iter().any(|i| i == issuer),
        }
    }

    /// Whether delegation is enabled at all.
    pub fn is_enabled(&self) -> bool {
        !matches!(self, NestedScope::None)
    }
}

/// BL-8: a boot-time fragment declaration from the measured base policy
/// (`data.agent_policy.policy_fragments[]`). The host fetches the COSE artifact for `feed`
/// and pushes it in; the guest verifies it (issuer/SVN/receipt/ordering) through the SRM
/// `FragmentStore`.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default, PartialEq)]
pub struct FragmentSpec {
    /// `did:x509` issuer the fragment must be signed by.
    pub issuer: String,
    /// OCI reference (e.g. `contoso.azurecr.io/frag/infra:1`) the fragment is published at.
    pub feed: String,
    /// Minimum acceptable SVN (rollback floor) for this feed.
    #[serde(default)]
    pub minimum_svn: u64,
    /// Whether this fragment must be present before any container may be created.
    ///
    /// Defaults to `false`, which is C-ACI/hcsshim behaviour: a declaration authorizes a
    /// fragment and states the terms it must meet, but delivery is lazy and a fragment that
    /// never arrives simply contributes nothing. That is already safe, because a container
    /// only the fragment would have permitted still does not match the base policy and is
    /// refused on its own merits. hcsshim has no equivalent of this flag at all.
    ///
    /// Setting it to `true` is *stricter* than C-ACI: it converts the declaration from a
    /// permission into an obligation, so a host that withholds the fragment cannot run the
    /// workload under a policy that is missing grants it was measured to include. Use it
    /// when the fragment carries something whose absence is not fail-safe — a deny rule, an
    /// audit obligation, or a constraint the base policy assumes has been composed in.
    ///
    /// `false` never means "unchecked". An optional fragment that *is* delivered is
    /// verified exactly as a required one: same issuer binding, same SVN floor, same
    /// receipt and ordering gates. The flag governs only whether absence is tolerated.
    #[serde(default)]
    pub required: bool,
    /// Whether this fragment may itself declare further fragments, and whose. Defaults to
    /// no delegation. See [`AllowNested`].
    #[serde(default)]
    pub allow_nested: AllowNested,
}

impl FragmentSpec {
    /// Resolve and validate [`Self::allow_nested`].
    ///
    /// Fails closed on anything unrecognised rather than defaulting to permissive *or* to
    /// silently disabled: a policy author who mistypes `"same_issuer"` must find out at
    /// boot, not discover months later that delegation was quietly off (or, worse, on).
    pub fn nested_scope(&self) -> Result<NestedScope> {
        match &self.allow_nested {
            AllowNested::Flag(false) => Ok(NestedScope::None),
            AllowNested::Flag(true) => bail!(
                "fragment declaration for feed {:?}: allow_nested = true does not say which \
                 issuers may be delegated to; use \"same-issuer\", \"any-authorized\", or an \
                 explicit list of issuer strings",
                self.feed
            ),
            AllowNested::Mode(m) => match m.as_str() {
                "none" => Ok(NestedScope::None),
                "same-issuer" => Ok(NestedScope::SameIssuer),
                "any-authorized" => Ok(NestedScope::AnyAuthorized),
                other => bail!(
                    "fragment declaration for feed {:?}: unknown allow_nested value {other:?}; \
                     expected \"none\", \"same-issuer\", \"any-authorized\", false, or a list \
                     of issuer strings",
                    self.feed
                ),
            },
            AllowNested::Issuers(list) => {
                if list.is_empty() {
                    bail!(
                        "fragment declaration for feed {:?}: allow_nested is an empty issuer \
                         list, which permits nothing; use false to disable delegation",
                        self.feed
                    );
                }
                Ok(NestedScope::Issuers(list.clone()))
            }
        }
    }
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
    ///
    /// Replaces the whole data document, so it is only safe when no other request can have
    /// mutated policy state in the meantime. Prefer [`AgentPolicy::revert_state_delta`] on
    /// any path that awaits between the snapshot and the rollback.
    #[cfg(feature = "strict-policy")]
    pub fn restore_state(&mut self, snapshot: &str) -> Result<()> {
        self.engine.clear_data();
        self.engine
            .add_data(regorus::Value::from_json_str(snapshot)?)?;
        Ok(())
    }

    /// FR-6: undo only the state mutations made by one request, leaving concurrent ones
    /// intact.
    ///
    /// Restoring a whole-document snapshot rolls back *every* change made since it was
    /// taken, not just this request's. ttrpc dispatches each request on its own task and
    /// the policy lock is released while the runtime operation runs, so the interleaving
    /// is reachable: `remove(A)` snapshots, `create(B)` commits `B` into `pstate`, then
    /// `remove(A)` fails and restores a snapshot that predates `B`. Container `B` is now
    /// running but absent from the enforcer's state — it can never be authorized for
    /// removal, which is the divergence FR-6 exists to prevent.
    ///
    /// `before` and `after` bracket this request's own authorization, so their difference
    /// is exactly the set of keys it touched. Reverting only those keys, against whatever
    /// the current state happens to be, leaves everyone else's changes alone.
    #[cfg(feature = "strict-policy")]
    pub fn revert_state_delta(&mut self, before: &str, after: &str) -> Result<()> {
        let before: serde_json::Value = serde_json::from_str(before)?;
        let after: serde_json::Value = serde_json::from_str(after)?;
        let mut current: serde_json::Value = serde_json::to_value(self.engine.get_data())?;

        revert_delta(&mut current, &before, &after);

        self.engine.clear_data();
        self.engine
            .add_data(regorus::Value::from_json_str(&current.to_string())?)?;
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
    /// Returns the rego package the module was applied under, so the caller can find what
    /// the fragment itself declares (see [`Self::nested_fragment_specs`]).
    pub fn apply_fragment_module(
        &mut self,
        name: &str,
        rego: &str,
        includes: &[String],
    ) -> Result<String> {
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
        Ok(pkg)
    }

    /// BL-8: read the fragment declarations a *delivered* fragment carries in its own
    /// module, at `data.<package>.policy_fragments`.
    ///
    /// These are signed: `policy_module` is covered by the fragment statement's
    /// `signing_bytes()`, so the declarations a fragment makes are bound to the same COSE
    /// signature as everything else it carries. The host cannot add, remove or edit one.
    ///
    /// Reading them is only *permitted* when the declaration that authorized this fragment
    /// enabled delegation, and what they may name is bounded by that declaration's scope —
    /// see `NestedScope`. This function performs no authorization itself; it only reads.
    pub fn nested_fragment_specs(&mut self, package: &str) -> Result<Vec<FragmentSpec>> {
        self.query_fragment_specs(&format!("data.{package}.policy_fragments"))
    }

    /// BL-8: read the boot-time fragment declarations the measured base policy exposes at
    /// `data.agent_policy.policy_fragments`. Each declaration names an `issuer`
    /// (`did:x509`), a `feed` (OCI reference), a `minimum_svn`, and optionally `required`
    /// and `allow_nested`. The host delivers each fragment over `LoadPolicyFragment` and the
    /// guest verifies it through the SRM.
    ///
    /// Returns an empty vector when the base policy declares none (or the value is absent /
    /// not an array) — a base policy that declares no fragments is unaffected by any of
    /// this.
    pub fn fragment_specs(&mut self) -> Result<Vec<FragmentSpec>> {
        self.query_fragment_specs("data.agent_policy.policy_fragments")
    }

    /// Shared parse for a `policy_fragments[]` array at an arbitrary rego path.
    fn query_fragment_specs(&mut self, query: &str) -> Result<Vec<FragmentSpec>> {
        self.engine.set_input_json("{}")?;
        let results = self.engine.eval_query(query.to_string(), false)?;
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
        }
        Ok(())
    }
}

/// Undo, in `current`, exactly the differences between `before` and `after`.
///
/// A key whose value is identical in `before` and `after` was not touched by the request
/// being rolled back, so whatever `current` holds for it — including a change another
/// request made in the meantime — is left alone. Only keys the request actually added,
/// removed or modified are put back the way it found them, recursing into nested objects
/// so that two requests touching sibling entries of the same map do not clobber each
/// other.
#[cfg(feature = "strict-policy")]
fn revert_delta(
    current: &mut serde_json::Value,
    before: &serde_json::Value,
    after: &serde_json::Value,
) {
    use serde_json::Value;

    if before == after {
        return;
    }

    let (Value::Object(before_map), Value::Object(after_map)) = (before, after) else {
        // Not a map on at least one side, so there is no finer granularity to exploit.
        *current = before.clone();
        return;
    };
    let Value::Object(current_map) = current else {
        // The shape changed underneath us; the request's own view is the best we have.
        *current = before.clone();
        return;
    };

    let keys: std::collections::BTreeSet<&String> =
        before_map.keys().chain(after_map.keys()).collect();
    for key in keys {
        match (before_map.get(key), after_map.get(key)) {
            // Untouched by this request.
            (Some(b), Some(a)) if b == a => {}
            (Some(b), Some(a)) => match current_map.get_mut(key) {
                Some(c) => revert_delta(c, b, a),
                None => {
                    current_map.insert(key.clone(), b.clone());
                }
            },
            // The request removed it; put it back.
            (Some(b), None) => {
                current_map.insert(key.clone(), b.clone());
            }
            // The request added it; take it away.
            (None, Some(_)) => {
                current_map.remove(key);
            }
            (None, None) => unreachable!("key came from one of the two maps"),
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

    /// FR-6: a rollback must undo only its own request's mutations.
    ///
    /// The interleaving this guards against: `remove(A)` snapshots `{A}`, `create(B)`
    /// commits `{A, B}`, then `remove(A)` fails. A whole-document restore would write back
    /// `{A}` and lose `B` — leaving `B` running but invisible to the enforcer, hence
    /// unremovable. Reverting the delta must leave `B` in place.
    #[cfg(feature = "strict-policy")]
    #[test]
    fn reverting_a_delta_keeps_concurrent_changes() {
        let before = serde_json::json!({"pstate": {"A": {"running": true}}});
        // This request removed A.
        let after = serde_json::json!({"pstate": {}});
        // Meanwhile another request added B and committed it.
        let mut current = serde_json::json!({"pstate": {"B": {"running": true}}});

        revert_delta(&mut current, &before, &after);

        assert_eq!(
            current,
            serde_json::json!({"pstate": {"A": {"running": true}, "B": {"running": true}}}),
            "rollback must restore A without erasing the concurrently created B"
        );
    }

    /// The mirror case: a request that *added* state has that addition taken away again,
    /// and nothing else is disturbed.
    #[cfg(feature = "strict-policy")]
    #[test]
    fn reverting_a_delta_removes_only_what_the_request_added() {
        let before = serde_json::json!({"pstate": {"A": {"running": true}}});
        let after = serde_json::json!({"pstate": {"A": {"running": true}, "B": {"n": 1}}});
        let mut current =
            serde_json::json!({"pstate": {"A": {"running": true}, "B": {"n": 1}, "C": {"n": 2}}});

        revert_delta(&mut current, &before, &after);

        assert_eq!(
            current,
            serde_json::json!({"pstate": {"A": {"running": true}, "C": {"n": 2}}})
        );
    }

    /// A key the request never touched must survive even when another request changed its
    /// value after the snapshot was taken.
    #[cfg(feature = "strict-policy")]
    #[test]
    fn reverting_a_delta_leaves_untouched_keys_alone() {
        let before = serde_json::json!({"pstate": {"A": 1}, "other": "old"});
        let after = serde_json::json!({"pstate": {"A": 2}, "other": "old"});
        let mut current =
            serde_json::json!({"pstate": {"A": 2}, "other": "changed-by-someone-else"});

        revert_delta(&mut current, &before, &after);

        assert_eq!(
            current,
            serde_json::json!({"pstate": {"A": 1}, "other": "changed-by-someone-else"})
        );
    }

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
        // `required` defaults to false when omitted: a declaration is a permission, not an
        // obligation, unless the policy explicitly says otherwise (C-ACI parity).
        assert!(!specs[0].required);
        assert!(!specs[1].required);
    }

    /// BL-8: `required: true` is parsed off the declaration, so a policy can demand that a
    /// specific fragment be present while leaving others optional.
    #[test]
    fn test_fragment_specs_parse_required_flag() {
        let mut p = AgentPolicy::new();
        let base = "package agent_policy\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:signer\", \"feed\": \"reg/must:1\", \"minimum_svn\": 2, \"required\": true},\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:signer\", \"feed\": \"reg/may:1\", \"required\": false}\n\
            ]\n";
        p.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        let specs = p.fragment_specs().unwrap();
        assert_eq!(specs.len(), 2);
        assert!(specs[0].required, "explicit required:true must be honoured");
        assert!(!specs[1].required);
    }

    /// BL-8: `allow_nested` defaults to no delegation, so a policy written before the
    /// attribute existed cannot have acquired the capability by upgrade.
    #[test]
    fn test_fragment_specs_default_to_no_delegation() {
        let mut p = AgentPolicy::new();
        let base = "package agent_policy\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:signer\", \"feed\": \"reg/frag:1\"}\n\
            ]\n";
        p.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        let specs = p.fragment_specs().unwrap();
        let scope = specs[0].nested_scope().unwrap();
        assert_eq!(scope, NestedScope::None);
        assert!(!scope.is_enabled());
        assert!(
            !scope.permits("did:x509:0:sha256:AAA::CN:signer", "did:x509:0:sha256:AAA::CN:signer"),
            "no delegation means not even the fragment's own issuer"
        );
    }

    /// BL-8: each accepted `allow_nested` form resolves to the scope it names, and the scope
    /// admits exactly the issuers it should.
    #[test]
    fn test_allow_nested_scopes_resolve_and_bound_issuers() {
        let parent = "did:x509:0:sha256:AAA::CN:parent";
        let other = "did:x509:0:sha256:BBB::CN:other";
        let third = "did:x509:0:sha256:CCC::CN:third";

        let mut p = AgentPolicy::new();
        let base = format!(
            "package agent_policy\n\
            policy_fragments := [\n\
            {{\"issuer\": \"{parent}\", \"feed\": \"reg/a:1\", \"allow_nested\": \"same-issuer\"}},\n\
            {{\"issuer\": \"{parent}\", \"feed\": \"reg/b:1\", \"allow_nested\": \"any-authorized\"}},\n\
            {{\"issuer\": \"{parent}\", \"feed\": \"reg/c:1\", \"allow_nested\": [\"{other}\"]}},\n\
            {{\"issuer\": \"{parent}\", \"feed\": \"reg/d:1\", \"allow_nested\": false}},\n\
            {{\"issuer\": \"{parent}\", \"feed\": \"reg/e:1\", \"allow_nested\": \"none\"}}\n\
            ]\n"
        );
        p.engine.add_policy("agent_policy".to_string(), base).unwrap();
        let specs = p.fragment_specs().unwrap();
        assert_eq!(specs.len(), 5);

        // same-issuer: the delivering fragment's issuer only.
        let same = specs[0].nested_scope().unwrap();
        assert_eq!(same, NestedScope::SameIssuer);
        assert!(same.permits(parent, parent));
        assert!(!same.permits(parent, other));

        // any-authorized: bounded by the trust root, not by the declaration.
        let any = specs[1].nested_scope().unwrap();
        assert_eq!(any, NestedScope::AnyAuthorized);
        assert!(any.permits(parent, other));

        // explicit list: exactly the issuers named, and notably not the parent's own unless
        // it is listed — an explicit list is the whole answer, not an addition to a default.
        let list = specs[2].nested_scope().unwrap();
        assert_eq!(list, NestedScope::Issuers(vec![other.to_string()]));
        assert!(list.permits(parent, other));
        assert!(!list.permits(parent, third));
        assert!(!list.permits(parent, parent));

        // Both spellings of "off".
        assert_eq!(specs[3].nested_scope().unwrap(), NestedScope::None);
        assert_eq!(specs[4].nested_scope().unwrap(), NestedScope::None);
    }

    /// BL-8: `allow_nested: true` names no scope, so it is rejected rather than guessed at.
    /// Guessing either way would be wrong — permissive silently widens delegation, and
    /// silently disabling it leaves the author believing a control is on when it is not.
    #[test]
    fn test_allow_nested_true_is_rejected() {
        let mut p = AgentPolicy::new();
        let base = "package agent_policy\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:signer\", \"feed\": \"reg/frag:1\", \"allow_nested\": true}\n\
            ]\n";
        p.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        let specs = p.fragment_specs().unwrap();
        let err = specs[0].nested_scope().unwrap_err().to_string();
        assert!(
            err.contains("does not say which issuers"),
            "error must tell the author what is missing, got: {}", err
        );
        assert!(err.contains("same-issuer"), "error must name a valid form");
    }

    /// BL-8: an unrecognised mode string fails closed instead of being treated as "off".
    /// A typo like `same_issuer` must surface at boot, not silently disable delegation.
    #[test]
    fn test_allow_nested_unknown_mode_is_rejected() {
        let mut p = AgentPolicy::new();
        let base = "package agent_policy\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:signer\", \"feed\": \"reg/frag:1\", \"allow_nested\": \"same_issuer\"}\n\
            ]\n";
        p.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        let err = specs_err(&mut p);
        assert!(err.contains("same_issuer"), "error must quote the bad value: {}", err);
    }

    /// BL-8: an empty issuer list permits nothing, which is almost certainly an authoring
    /// mistake rather than an intent. Reject so it cannot be confused with `false`.
    #[test]
    fn test_allow_nested_empty_list_is_rejected() {
        let mut p = AgentPolicy::new();
        let base = "package agent_policy\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:signer\", \"feed\": \"reg/frag:1\", \"allow_nested\": []}\n\
            ]\n";
        p.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        let err = specs_err(&mut p);
        assert!(err.contains("empty issuer list"), "got: {}", err);
    }

    fn specs_err(p: &mut AgentPolicy) -> String {
        let specs = p.fragment_specs().unwrap();
        specs[0].nested_scope().unwrap_err().to_string()
    }

    /// BL-8: a delivered fragment's own declarations are read from its module's package, so
    /// two fragments in different namespaces cannot see or overwrite each other's.
    #[test]
    fn test_nested_fragment_specs_are_read_per_package() {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "agent_policy".to_string(),
                "package agent_policy\ndefault SetPolicyRequest := false\n".to_string(),
            )
            .unwrap();

        let module = "package agent_policy.fragments.infra\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:BBB::CN:child\", \"feed\": \"reg/child:1\", \"minimum_svn\": 5, \"required\": true}\n\
            ]\n";
        let pkg = p
            .apply_fragment_module("fragment:test", module, &["infra".to_string()])
            .unwrap();
        assert_eq!(pkg, "agent_policy.fragments.infra");

        let nested = p.nested_fragment_specs(&pkg).unwrap();
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].feed, "reg/child:1");
        assert_eq!(nested[0].minimum_svn, 5);
        assert!(nested[0].required);
        // A fragment that declares none, and a namespace nobody wrote to, both read empty
        // rather than erroring — declaring nothing is the overwhelmingly common case.
        assert!(p
            .nested_fragment_specs("agent_policy.fragments.absent")
            .unwrap()
            .is_empty());
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

    /// A miniature policy that reproduces the `pstate` mechanics of the generated
    /// `rules.rego`: the helper functions verbatim, a `RemoveContainerRequest` rule that
    /// deletes the container from `pstate` as its authorization `ops`, and a
    /// `SignalProcessRequest` rule that is undefined for a container missing from
    /// `pstate`. It is deliberately self-contained so the test does not depend on a
    /// generated policy_data blob.
    #[cfg(feature = "strict-policy")]
    const POLICY_PSTATE_LIFECYCLE: &str = r#"package agent_policy

import future.keywords.if

default RemoveContainerRequest := false
default SignalProcessRequest := false
default CreateContainerRequest := false

get_state() = state if { state := data["pstate"] }
get_state_val(key) = value if { state := get_state(); value := state[key] }
get_state_path(key) = path if { path := concat("/", ["/pstate", key]) }

state_del_key(key) = action if {
  get_state()
  path := get_state_path(key)
  action := {"op": "remove", "path": path}
}

state_add_key(key) = action if {
  get_state()
  path := get_state_path(key)
  action := {"op": "add", "path": path, "value": 0}
}

concat_op_if_not_null(ops, op) = result if { op == null; result := ops }
concat_op_if_not_null(ops, op) = result if { op != null; result := array.concat(ops, [op]) }

CreateContainerRequest := {"ops": ops, "allowed": true} if {
  not get_state_val(input.container_id)
  ops := concat_op_if_not_null([], state_add_key(input.container_id))
}

RemoveContainerRequest := {"ops": ops, "allowed": true} if {
  get_state_val(input.container_id)
  ops := concat_op_if_not_null([], state_del_key(input.container_id))
}

SignalProcessRequest if {
  get_state_val(input.container_id)
}
"#;

    /// Build a policy with the lifecycle rules above and one container already recorded in
    /// `pstate`, as a successful `CreateContainerRequest` would have left it.
    #[cfg(feature = "strict-policy")]
    fn pstate_policy_with_container(cid: &str) -> AgentPolicy {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "pstate-lifecycle.rego".to_string(),
                POLICY_PSTATE_LIFECYCLE.to_string(),
            )
            .unwrap();
        // AgentPolicy::new() already seeds an empty `pstate`, so replace the data wholesale
        // rather than adding a second binding for the same key.
        p.restore_state(&format!(r#"{{"pstate": {{"{cid}": 0}}}}"#))
            .unwrap();
        p
    }

    /// F-19: authorizing a `RemoveContainerRequest` deletes the container from `pstate`
    /// before the teardown runs. If the teardown then fails and that mutation is not rolled
    /// back, the container is still running but the policy no longer knows about it, so
    /// every later signal and every retried removal is denied by the fail-closed default.
    ///
    /// This asserts the damage exists, which is what makes the rollback in
    /// `remove_container` load-bearing rather than defensive.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn remove_authorization_alone_strands_the_container() {
        let cid = "ctr1";
        let req = format!(r#"{{"container_id": "{cid}"}}"#);
        let mut p = pstate_policy_with_container(cid);

        assert!(
            matches!(
                p.allow_request("SignalProcessRequest", &req).await,
                Ok((true, _))
            ),
            "a container in pstate must be signallable to begin with"
        );

        // Authorization applies the pstate deletion. Imagine do_remove_container failing here.
        assert!(matches!(
            p.allow_request("RemoveContainerRequest", &req).await,
            Ok((true, _))
        ));

        assert!(
            is_denied(p.allow_request("SignalProcessRequest", &req).await),
            "container is unreachable by signal once removed from pstate"
        );
        assert!(
            is_denied(p.allow_request("RemoveContainerRequest", &req).await),
            "and the removal cannot be retried either -- the container is stranded"
        );
    }

    /// F-19: reverting this request's own `pstate` delta undoes the removal's deletion, so
    /// a container whose teardown failed stays signallable and the removal stays retryable.
    /// This is the regression test for the rollback that `remove_container` performs on the
    /// failure path -- it exercises `revert_state_delta`, which is what the handler calls.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn rollback_after_failed_remove_keeps_the_container_reachable() {
        let cid = "ctr1";
        let req = format!(r#"{{"container_id": "{cid}"}}"#);
        let mut p = pstate_policy_with_container(cid);

        // What remove_container does: bracket authorization with before/after, then
        // revert only this request's delta on failure.
        let before = p.snapshot_state().unwrap();
        assert!(matches!(
            p.allow_request("RemoveContainerRequest", &req).await,
            Ok((true, _))
        ));
        let after = p.snapshot_state().unwrap();
        p.revert_state_delta(&before, &after).unwrap();

        assert!(
            matches!(
                p.allow_request("SignalProcessRequest", &req).await,
                Ok((true, _))
            ),
            "after rollback the still-running container must remain signallable"
        );
        assert!(
            matches!(
                p.allow_request("RemoveContainerRequest", &req).await,
                Ok((true, _))
            ),
            "after rollback the failed removal must be retryable"
        );
    }

    /// F-19: the reason the rollback is a *delta* revert and not a snapshot restore.
    /// A concurrent request commits its own `pstate` change while the failing removal is
    /// awaiting the runtime; the rollback must not take that change with it.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn rollback_preserves_concurrent_state_changes() {
        let (a, b) = ("ctr1", "ctr2");
        let req_a = format!(r#"{{"container_id": "{a}"}}"#);
        let req_b = format!(r#"{{"container_id": "{b}"}}"#);
        let mut p = pstate_policy_with_container(a);

        // remove(A) brackets its own authorization...
        let before = p.snapshot_state().unwrap();
        assert!(matches!(
            p.allow_request("RemoveContainerRequest", &req_a).await,
            Ok((true, _))
        ));
        let after = p.snapshot_state().unwrap();

        // ...then B is created and committed while remove(A) awaits the runtime.
        assert!(matches!(
            p.allow_request("CreateContainerRequest", &req_b).await,
            Ok((true, _))
        ));

        // remove(A) fails and rolls back. A whole-document restore of `before` would
        // erase B; reverting only A's delta must not.
        p.revert_state_delta(&before, &after).unwrap();

        assert!(
            matches!(
                p.allow_request("RemoveContainerRequest", &req_b).await,
                Ok((true, _))
            ),
            "a concurrently created container must survive another request's rollback"
        );
        assert!(
            matches!(
                p.allow_request("SignalProcessRequest", &req_a).await,
                Ok((true, _))
            ),
            "the rolled-back container must still be reachable"
        );
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
