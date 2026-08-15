// Copyright (c) 2023 Microsoft Corporation
// Copyright (c) 2024 Edgeless Systems GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Policy evaluation for the kata-agent.

use std::num::{NonZeroU32, NonZeroUsize};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};

use anyhow::{bail, Error, Result};
use protocols::agent::{CopyFileRequest, CopySingleFileRequest, PutVolumeFileRevisionRequest};
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
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, PartialEq)]
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
    /// FR-1c: the policy namespaces under `agent_policy.fragments.` this fragment may
    /// contribute a module to. Empty (the default) grants only the shared
    /// `agent_policy.fragments` package.
    ///
    /// The fragment statement carries an `includes` list of its own, but that is signed by
    /// the fragment's issuer and so states only what *that issuer* intended. Left as the
    /// sole authority it would let any trust-root-authorized issuer claim any namespace,
    /// including one the base policy meant a different issuer to fill. This field is the
    /// measured policy's grant; the effective scope is the intersection of the two, so
    /// neither side can widen the other. hcsshim does the same, taking `includes` from the
    /// matched candidate declaration rather than from the delivered fragment.
    #[serde(default)]
    pub includes: Vec<String>,
    /// FR-1n: regexes bounding the environment-variable *names* this fragment may
    /// contribute `env_rules` for. Empty (the default) delegates nothing.
    ///
    /// hcsshim lets a fragment carry `platform_rules`, which contribute environment rules
    /// applied across *all* containers, so a deployment pipeline that injects a variable
    /// (a feature flag, a fabric-injected setting) can be authorized by shipping a signed,
    /// SVN-versioned fragment instead of regenerating and re-measuring the base policy.
    /// There is no way for the base policy to say *which* variables a fragment may speak
    /// for: including the fragment grants it the whole namespace.
    ///
    /// This is the same capability with the grant made explicit. The base policy names the
    /// variables it is willing to let a feed decide — `["^FEATURE_FLAG_[A-Z0-9_]+$"]` — and
    /// the fragment supplies the concrete rules within that ceiling. An operator who wants
    /// hcsshim's all-or-nothing behaviour writes `["^.+$"]`; one who wants the list locked
    /// down at measurement time omits the field and keeps every variable in the measured
    /// base policy. Both ends of that range are expressible, and the default end is closed.
    ///
    /// Bounding by *name* rather than by rule is deliberate. Deciding whether one regex
    /// admits a subset of another is undecidable in general, so a ceiling expressed over
    /// whole rules could not be checked; a ceiling over names can, because the fragment's
    /// rule names a literal variable (see `env_rules` handling in `rules.rego`).
    ///
    /// Patterns are matched fully anchored regardless of how they are written, so a
    /// ceiling of `FEATURE_FLAG` cannot be widened into `EVIL_FEATURE_FLAG_X` by an author
    /// who forgot the anchors.
    #[serde(default)]
    pub allow_env_rules: Vec<String>,
    /// FR-1o: destination patterns whose mounts a fragment delivered for this feed may
    /// contribute. Empty — the default — delegates nothing.
    ///
    /// The mount half of the same delegation `allow_env_rules` provides for environment
    /// variables, and the counterpart to the mount side of hcsshim's `platform_rules`. The
    /// drift it answers is a deployment pipeline attaching a mount the policy author never
    /// wrote down: a projected service-account token path a newer kubelet uses, a CSI
    /// driver's directory, a socket injected by a cluster-wide admission webhook.
    ///
    /// Two bounds beyond the ceiling itself, both enforced in `rules.rego`:
    ///
    /// * A fragment may only *add* a destination. Restating one the base policy already
    ///   declares is refused, so a fragment cannot shadow a measured mount with a laxer
    ///   one — the weakening would otherwise be invisible, since the base declaration
    ///   would still read `ro` while the container got `rw`.
    /// * Mount options must match the fragment's rule exactly rather than by subset. The
    ///   options are the security-relevant part of a mount (`ro`, `nosuid`, `nodev`,
    ///   `noexec`), so an approximate match is the wrong default.
    ///
    /// As for `allow_env_rules`, patterns are matched fully anchored however they are
    /// written, and the ceiling is checked against the fragment rule's *literal*
    /// destination, which is what makes it an exact test rather than an undecidable
    /// regex-subset question.
    #[serde(default)]
    pub allow_mount_rules: Vec<String>,
    /// FR-1c: whether this fragment's Rego module may be applied at all. Defaults to true.
    ///
    /// Setting it to false accepts the fragment for its SVN, receipt and ordering record
    /// while contributing no rules — hcsshim's `add_module` behaviour. Useful to pin a
    /// version, or to require that an artifact exist and be countersigned, without granting
    /// it any policy surface.
    #[serde(default = "default_true")]
    pub allow_module: bool,
    /// FR-1k: values to instantiate a parameterised fragment's Rego with.
    ///
    /// A fragment can read these via `parameter("name")` rather than hard-coding a value,
    /// so one signed artefact serves several deployments without being re-signed per value.
    /// Mirrors hcsshim's fragment `parameters`.
    ///
    /// These are authority-bearing — a parameter may decide which env var value or command
    /// a rule admits — which is why they live on the *declaration*, in measured policy,
    /// rather than arriving with the fragment or from the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

fn default_true() -> bool {
    true
}

/// FR-1l: the enforcement framework version this agent implements.
///
/// Bumped when a gate is added that a policy could reasonably depend on, so a policy can
/// state a floor and be refused rather than under-enforced by an older agent. Deliberately
/// not tied to the agent version: two agents may differ in ways policy cannot observe.
pub const POLICY_FRAMEWORK_VERSION: &str = "1.0.0";

/// Parse a strict `major.minor.patch`. Returns `None` on anything else, including the
/// pre-release and build-metadata suffixes semver allows — accepting them would mean
/// deciding how they order, and there is no version here that needs them.
fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let mut it = s.trim().split('.');
    let out = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    it.next().is_none().then_some(out)
}

impl Default for FragmentSpec {
    /// Hand-written rather than derived so it cannot drift from the serde defaults: a
    /// derived impl would give `allow_module: false`, which is the opposite of what an
    /// omitted field means when the declaration is parsed.
    fn default() -> Self {
        Self {
            issuer: String::new(),
            feed: String::new(),
            minimum_svn: 0,
            required: false,
            allow_nested: AllowNested::default(),
            includes: Vec::new(),
            allow_env_rules: Vec::new(),
            allow_mount_rules: Vec::new(),
            allow_module: true,
            parameters: None,
        }
    }
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

    /// Validate [`Self::allow_env_rules`] and [`Self::allow_mount_rules`].
    ///
    /// An empty list is the closed default and is fine — it delegates nothing. What is not
    /// fine is a *present* list containing an empty pattern: anchored, an empty pattern
    /// matches only the empty name, so it grants nothing while looking like it grants
    /// something. That is the failure mode worth catching at boot, because the symptom (a
    /// fragment's rules silently never applying) is otherwise identical to the fragment not
    /// being delivered at all.
    ///
    /// Both grants are checked here rather than in a method each, so that adding a third
    /// delegation later cannot leave a caller validating two of three.
    pub fn validate_rule_grants(&self) -> Result<()> {
        for (field, patterns) in [
            ("allow_env_rules", &self.allow_env_rules),
            ("allow_mount_rules", &self.allow_mount_rules),
        ] {
            for pattern in patterns {
                if pattern.trim().is_empty() {
                    bail!(
                        "fragment declaration for feed {:?}: {} contains an empty pattern, \
                         which permits nothing; remove it, or omit {} entirely to delegate \
                         nothing",
                        self.feed,
                        field,
                        field
                    );
                }
            }
        }
        Ok(())
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

    /// Explain why the policy produced no result for `ep`.
    ///
    /// The raw regorus failure is `unexpected eval_query result len QueryResults { result: [] }`,
    /// which names neither the cause nor the fix. It surfaces to the operator as a sandbox
    /// creation failure on whatever RPC happened to be first (typically
    /// `UpdateInterfaceRequest`), which points at networking rather than policy.
    ///
    /// Under `strict-policy` the overwhelmingly common cause is that no policy was ever
    /// supplied: unlike the permissive build, a strict guest deliberately ships no
    /// `/etc/kata-opa/default-policy.rego` allow-all fallback, so *every* request is refused
    /// until an authorized policy is activated.
    #[cfg(feature = "strict-policy")]
    fn describe_missing_result(&self, ep: &str) -> String {
        if !self.policy_activated {
            return format!(
                "no policy has been activated, so \"{ep}\" cannot be allowed. A strict-policy \
                 guest ships no default policy and has no allow-all fallback, so every request \
                 is refused until an authorized policy is provided. Generate one with genpolicy \
                 and attach it to the workload."
            );
        }
        Self::describe_undefined_rule(ep)
    }

    #[cfg(not(feature = "strict-policy"))]
    fn describe_missing_result(&self, ep: &str) -> String {
        Self::describe_undefined_rule(ep)
    }

    fn describe_undefined_rule(ep: &str) -> String {
        format!(
            "the active policy defines no rule \"{ep}\", so the request cannot be allowed. \
             Regenerate the policy with a genpolicy build that knows about \"{ep}\"."
        )
    }

    /// Ask the policy why it refused `ep`.
    ///
    /// The endpoint rule only ever fails to produce a value, so the refusal itself carries
    /// no detail. `rules.rego` therefore defines a companion `reason` rule that re-derives
    /// which checks no policy container satisfied; this evaluates it with `rule` set to the
    /// endpoint name, exactly as the C-ACI baseline queries `data.policy.reason` after a
    /// denial.
    ///
    /// Strictly diagnostic. It runs only after the request has already been refused, so a
    /// failure here costs a good error message and nothing else — which is also why
    /// injecting `rule` into the input is safe even if a request ever carried that field:
    /// the allow decision has already been made from the unmodified input.
    async fn denial_reasons(&mut self, ep: &str, ep_input: &str) -> Vec<String> {
        let mut input: serde_json::Value = match serde_json::from_str(ep_input) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let Some(obj) = input.as_object_mut() else {
            return Vec::new();
        };
        obj.insert(
            "rule".to_string(),
            serde_json::Value::String(ep.to_string()),
        );

        if self.engine.set_input_json(&input.to_string()).is_err() {
            return Vec::new();
        }
        // Discard the prints this evaluation generates so they cannot bleed into the next
        // request's trace.
        let results = self
            .engine
            .eval_query("data.agent_policy.reason".to_string(), false);
        let _ = self.engine.take_prints();

        let Ok(results) = results else {
            return Vec::new();
        };
        // An older policy defines no `reason` rule at all; that is not an error, it just
        // means no attribution is available.
        let Some(first) = results.result.first() else {
            return Vec::new();
        };
        let Some(expr) = first.expressions.first() else {
            return Vec::new();
        };
        let Ok(json) = serde_json::to_value(&expr.value) else {
            return Vec::new();
        };
        // `errors` is a Rego *set*. regorus serializes a set as a JSON object whose keys
        // are the members (`{"some error": true}`), not as an array — so read the keys.
        // Arrays are accepted too, so this keeps working if that representation ever
        // changes or a policy defines `errors` as a list.
        let mut reasons: Vec<String> = match json.get("errors") {
            Some(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        // Rego sets have no inherent order; sort so the same denial always reads the same
        // way and two runs can be diffed.
        reasons.sort();
        reasons
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
            bail!("policy check: {}", self.describe_missing_result(ep));
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
        // records the endpoint, the checks that failed, and the request's top-level field
        // names (never values), so denials are auditable without leaking env values,
        // sealed secrets, or policy text.
        //
        // RM-64: the same explanation is returned to the caller, and the `print()` trace no
        // longer is. Returning the trace was both useless and unsafe. Useless because it is
        // unstructured and far larger than the message budget, so containerd truncated away
        // whatever mattered. Unsafe because it embeds the evaluated input verbatim --
        // `allow_create_container_input: input = {...}` carries every environment variable
        // *value* and the full command line -- and the denial crosses the guest/host
        // boundary on its way to the shim, so a refused request handed the host exactly the
        // workload data a confidential guest exists to keep from it. The baseline redacts
        // env values before a decision leaves the UVM; this reports names only.
        //
        // The trace is still available to whoever holds the guest, at debug level, via
        // `log_eval_input`.
        if !allow {
            let reasons = self.denial_reasons(ep, ep_input).await;
            let decision =
                crate::decision::DecisionObject::for_denial_with_reasons(ep, ep_input, reasons);
            self.log_decision(&decision).await;
            // RM-66: the structured object goes out on the error, not only into the
            // guest-local log file. That file is opened only at Debug and a strict guest
            // pins itself to Info, so `log_decision` above is a no-op in exactly the
            // configuration FR-8 exists for -- and a file inside a confidential guest
            // could never have been an audit trail anyway.
            return Ok((false, decision.to_host_error()));
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
        self.check_framework_version()?;
        self.update_allow_failures_flag().await?;
        #[cfg(feature = "strict-policy")]
        {
            self.policy_activated = true;
        }
        Ok(())
    }

    /// FR-1l: refuse a policy that expects a newer enforcement framework than this agent
    /// implements.
    ///
    /// A policy declares `framework_version` (semver) if it wants to be sure of what it is
    /// running on. Absent, it is treated as legacy and allowed — that is every policy
    /// written before this check existed, and refusing them would be a compatibility break
    /// with no security benefit, since such a policy by definition expects nothing newer.
    ///
    /// The asymmetry is the point. A policy **older** than the agent is fine: the agent
    /// implements every gate it names, and any gate the policy does not name is simply not
    /// requested. A policy **newer** than the agent is not: it was authored expecting checks
    /// this binary has never heard of, and an unknown rule name in Rego is not an error but
    /// an undefined value, so those checks would not fail loudly — they would silently not
    /// happen, and the policy would appear to be enforced while the gates it was written for
    /// were absent. Downgrading the enforcer is exactly the move an adversary would want, so
    /// this fails closed. Mirrors hcsshim, whose `apply_defaults` has cases for equal and
    /// older framework versions and deliberately none for newer.
    fn check_framework_version(&mut self) -> Result<()> {
        let declared = match self
            .engine
            .eval_rule("data.agent_policy.framework_version".into())
        {
            Ok(v) => match v.as_string() {
                Ok(s) => s.to_string(),
                Err(_) => return Ok(()),
            },
            Err(_) => return Ok(()),
        };
        let policy = parse_semver(&declared).ok_or_else(|| {
            anyhow::anyhow!("policy framework_version {declared:?} is not a semver x.y.z")
        })?;
        let ours = parse_semver(POLICY_FRAMEWORK_VERSION)
            .expect("POLICY_FRAMEWORK_VERSION is a compile-time constant");
        if policy > ours {
            bail!(
                "policy declares framework_version {declared}, but this agent implements \
                 {POLICY_FRAMEWORK_VERSION}; refusing to enforce a policy written for gates \
                 this build does not have"
            );
        }
        Ok(())
    }

    /// FR-1a: apply a verified policy fragment's Rego module to the live engine.    ///
    /// This is the **only** sanctioned runtime extension of an active policy. Unlike
    /// `set_policy` it is **additive** — it adds a named module via `add_policy` and does
    /// NOT rebuild the engine, so it bypasses the FR-12 one-shot lock without weakening it
    /// (`set_policy` stays rejected after activation). The fragment module must declare a
    /// package inside the reserved fragment namespace (`agent_policy.fragments`, optionally
    /// scoped to one of the fragment's `includes`), so a fragment can only *add* rules in
    /// its own namespace and can never redefine or shadow a base `agent_policy` rule. The
    /// base policy is authored to consult `data.agent_policy.fragments.*`.
    ///
    /// One further form is permitted: `agent_policy.fragments["<feed>"]`, quoted, naming
    /// **this fragment's own verified feed and nothing else**. It exists because the
    /// generated `rules.rego` looks a fragment's contribution up by feed
    /// (`data.agent_policy.fragments[spec.feed]`, the container-contribution contract), and
    /// a feed is an OCI reference — `localhost:5000/coco-e2e/fragment` — which is not a
    /// Rego identifier and therefore cannot be a rule name. Without this form that whole
    /// contract is unreachable: a fragment can never contribute a container. The feed comes
    /// from the COSE envelope the SRM already verified, not from the module, so the key a
    /// fragment writes under is pinned to the identity it was signed with; it cannot squat
    /// the namespace of another feed.
    ///
    /// Returns the rego package the module was applied under, so the caller can find what
    /// the fragment itself declares (see [`Self::nested_fragment_specs`]).
    ///
    /// `issuer` and `svn` are the values the SRM verified off the COSE envelope. They are
    /// not used to authorize anything here — that already happened — but the module is
    /// refused if it *describes itself* as anything else; see
    /// [`Self::assert_self_description`].
    // Every parameter is a distinct, verified input; folding them into a struct would only
    // move the arity somewhere else and churn ~35 call sites in the fragment tests.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_fragment_module(
        &mut self,
        name: &str,
        rego: &str,
        feed: &str,
        includes: &[String],
        parameters: Option<&str>,
        issuer: &str,
        svn: u64,
    ) -> Result<String> {
        const FRAGMENTS: &str = "agent_policy.fragments";
        let canonical = Self::rego_package(rego)?;

        // The shared package needs no grant; anything deeper must be named either by this
        // fragment's `includes` or by its own verified feed. Exactly one level is
        // permitted, so a granted namespace cannot be used as a springboard into a
        // sibling's subtree.
        let segment = if canonical == FRAGMENTS {
            None
        } else {
            match canonical.strip_prefix("agent_policy.fragments.") {
                Some(s) if includes.iter().any(|ns| ns.as_str() == s) => Some(s),
                Some(s) if !feed.is_empty() && s == feed => Some(s),
                _ => bail!(
                    "fragment module package {canonical:?} is outside the permitted fragment \
                     namespaces: {FRAGMENTS}, {FRAGMENTS}.<ns> for ns in {includes:?}, or this \
                     fragment's own feed {feed:?}"
                ),
            }
        };

        // regorus reports the path dot-joined, which is not a usable rego reference when a
        // segment holds an OCI feed (`reg/name:1`). Re-quote the segment that was just
        // authorized so callers can build queries against it.
        let pkg = match segment {
            None => FRAGMENTS.to_string(),
            Some(s) => format!("{FRAGMENTS}[{}]", serde_json::to_string(s)?),
        };

        let rego = match parameters {
            Some(p) => Self::instantiate_parameters(rego, &pkg, p)?,
            None => rego.to_string(),
        };

        // Belt and braces: what is handed to the engine must still be the module that was
        // authorized. Appending parameter bindings cannot move a module, so a disagreement
        // here would mean the two parses differ — fail closed rather than load it.
        let applied = Self::rego_package(&rego)?;
        if applied != canonical {
            bail!("fragment module would land in {applied:?}, not the authorized {canonical:?}");
        }

        // F-160: the generated base policy resolves a fragment's contribution through the
        // module's *own* `issuer` and `svn` rules. Pin them to the envelope before the
        // module can be consulted, so those are re-checks and not restatements.
        Self::assert_self_description(&rego, &pkg, issuer, svn)?;

        // Additive merge; never resets the engine, never touches the one-shot lock.
        self.engine.add_policy(name.to_string(), rego)?;
        Ok(pkg)
    }

    /// F-160: refuse a fragment whose module describes itself as a different fragment than
    /// the envelope the SRM verified.
    ///
    /// `rules.rego` admits a fragment's containers via
    /// `mod := data.agent_policy.fragments[spec.feed]`, then `mod.issuer == spec.issuer` and
    /// `to_number(mod.svn) >= spec.minimum_svn` — and both of those come from rules the
    /// fragment author wrote into the module body. The feed is already pinned (it is the
    /// package name, taken from the verified envelope), but nothing bound the other two, so
    /// the base policy's independent re-check was a check against the fragment's own
    /// account of itself. That is the shape retired in F-158: a gate over a self-asserted
    /// field looks protective and decides nothing.
    ///
    /// No exploit followed from it today — the SRM's own gates use the envelope values, and
    /// only one module can occupy a given feed — but it could not have caught a divergence,
    /// and it would mislead the next reader. hcsshim treats the same question as
    /// first-class: `svn_ok_if_defined` requires the CWT header SVN and the Rego-declared
    /// SVN to *match* when both are present.
    ///
    /// A module that declares neither is left alone: it is not lying, it simply contributes
    /// no containers, because `to_number(mod.svn)` is then undefined and the base policy's
    /// comprehension yields nothing. Fail-closed already covers that case.
    ///
    /// Evaluation happens in a throwaway engine on the *final* module text — after parameter
    /// instantiation, so a parameterised self-description is judged as it will actually
    /// evaluate — and before the live engine has seen it, so a module that fails this check
    /// never lands anywhere. That ordering matters: regorus has no remove-policy, so a
    /// check performed after `add_policy` could not undo itself. hcsshim has to call
    /// `RemoveModule` on exactly this path because it adds first.
    fn assert_self_description(rego: &str, pkg: &str, issuer: &str, svn: u64) -> Result<()> {
        let mut scratch = regorus::Engine::new();
        scratch
            .add_policy("fragment.rego".to_string(), rego.to_string())
            .map_err(|e| anyhow::anyhow!("fragment module does not parse: {e}"))?;
        scratch.set_input_json("{}")?;

        if let Some(v) = Self::eval_scalar(&mut scratch, format!("data.{pkg}.issuer"))? {
            let declared = v.as_str().ok_or_else(|| {
                anyhow::anyhow!("fragment module declares a non-string issuer: {v}")
            })?;
            if declared != issuer {
                bail!(
                    "fragment module declares issuer {declared:?}, but the envelope it arrived \
                     in was signed by {issuer:?}"
                );
            }
        }

        if let Some(v) = Self::eval_scalar(&mut scratch, format!("data.{pkg}.svn"))? {
            // The base policy reads this through `to_number`, so a string is the expected
            // form; accept a bare number too rather than make the check depend on which one
            // the author chose.
            let declared = match &v {
                serde_json::Value::Number(n) => n.as_u64(),
                serde_json::Value::String(s) => s.parse::<u64>().ok(),
                _ => None,
            }
            .ok_or_else(|| {
                anyhow::anyhow!("fragment module declares an svn that is not a whole number: {v}")
            })?;
            if declared != svn {
                bail!(
                    "fragment module declares svn {declared}, but the envelope it arrived in \
                     carries svn {svn}"
                );
            }
        }

        if let Some(v) = Self::eval_scalar(&mut scratch, format!("data.{pkg}.framework_version"))? {
            // FR-1l applied to fragments, which `check_framework_version` does not reach: it
            // runs from `set_policy` and reads `data.agent_policy.framework_version`, while a
            // fragment's module lands under `data.agent_policy.fragments.<feed>`. Without this
            // a version a fragment declares is read by nothing.
            //
            // A fragment is the only policy input that is neither measured nor default-denied
            // — third-party signed, delivered at runtime by an untrusted host — so its author
            // has no other way to say what it needs to be enforced by. The failure mode is the
            // one FR-1l exists for: an unknown rule name in Rego is an undefined value rather
            // than an error, so a fragment written for gates this build lacks does not fail
            // loudly, it silently does not get them.
            //
            // Absent stays legal, matching FR-1l — that is every fragment signed before this
            // check existed, and such a fragment by definition expects nothing newer. An
            // explicit but malformed one is an error, so a typo cannot pass as "unversioned".
            // hcsshim checks the same thing as step 5 of `load_fragment`
            // (`fragment_framework_version`).
            let declared = v.as_str().ok_or_else(|| {
                anyhow::anyhow!("fragment module declares a non-string framework_version: {v}")
            })?;
            let wanted = parse_semver(declared).ok_or_else(|| {
                anyhow::anyhow!(
                    "fragment module declares framework_version {declared:?}, which is not a \
                     semver x.y.z"
                )
            })?;
            let ours = parse_semver(POLICY_FRAMEWORK_VERSION)
                .expect("POLICY_FRAMEWORK_VERSION is a compile-time constant");
            if wanted > ours {
                bail!(
                    "fragment module declares framework_version {declared}, but this agent \
                     implements {POLICY_FRAMEWORK_VERSION}; refusing a fragment written for \
                     gates this build does not have"
                );
            }
        }

        Ok(())
    }

    /// Evaluate a single rego path, returning `None` when it is undefined.
    fn eval_scalar(
        engine: &mut regorus::Engine,
        query: String,
    ) -> Result<Option<serde_json::Value>> {
        let results = engine.eval_query(query, false)?;
        let value = match results
            .result
            .first()
            .and_then(|r| r.expressions.first())
            .map(|e| &e.value)
        {
            None | Some(regorus::Value::Undefined) => return Ok(None),
            Some(v) => v,
        };
        Ok(Some(serde_json::from_str(&serde_json::to_string(value)?)?))
    }

    /// FR-1k: bind a parameterised fragment's `parameter("name")` calls to concrete values.
    ///
    /// The values are appended to the module as a constant, plus a total `parameter`
    /// function that falls back to the `default` the fragment declares in its own
    /// `parameters_api`, and `null` when neither supplies one. This is hcsshim's mechanism
    /// (`getRegoWithParameterDefinitions` + `fragment_definition.rego`) and, like it,
    /// happens *after* the fragment's signature has been verified over the original bytes —
    /// the appended text is generated by the guest from measured state, so instantiating a
    /// fragment neither requires nor grants the ability to alter what was signed.
    ///
    /// `parameters` must be a JSON **object**. Anything else is rejected rather than
    /// coerced: `parameter(name)` is a lookup, and a non-object would make every lookup
    /// silently fall through to its default, turning a mis-specified policy into a quietly
    /// permissive one.
    fn instantiate_parameters(rego: &str, pkg: &str, parameters: &str) -> Result<String> {
        let parsed: serde_json::Value = serde_json::from_str(parameters)
            .map_err(|e| anyhow::anyhow!("fragment parameters are not valid JSON: {e}"))?;
        if !parsed.is_object() {
            bail!("fragment parameters must be a JSON object, got {parsed}");
        }
        // Re-serialize from the parsed form so the text spliced into the module is known to
        // be a single well-formed JSON value and cannot carry trailing Rego.
        let json = serde_json::to_string(&parsed)?;

        Ok(format!(
            "{rego}\n\
             # ---- appended by the agent (FR-1k): fragment parameter bindings ----\n\
             __fragment_parameters := {json}\n\
             default __fragment_parameters_api := {{}}\n\
             __fragment_parameters_api := data.{pkg}.parameters_api\n\
             parameter(__name) := object.get(\n\
             \x20   __fragment_parameters,\n\
             \x20   __name,\n\
             \x20   object.get(object.get(__fragment_parameters_api, __name, {{}}), \"default\", null),\n\
             )\n"
        ))
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

    /// Extract the top-level `package` path from a Rego module (e.g. "agent_policy.fragments"),
    /// dot-joined and with the leading `data.` removed.
    ///
    /// The path comes from the same parser that will execute the module, never from a scan
    /// of the source text. Scanning is a confusion attack waiting to happen: regorus accepts
    /// any whitespace — including a tab or a newline — between `package` and the path, so a
    /// scan keyed on the literal `"package "` walks straight past the real declaration and
    /// can then be steered onto a decoy in a comment or a raw string. That was F-143. A
    /// module whose real package was `package<TAB>agent_policy` passed the namespace check
    /// on the strength of a `package agent_policy.fragments` line hidden in a backtick
    /// string, loaded into the base package, and redefined base rules — a total policy
    /// bypass. hcsshim avoids this by pinning the declaration to line 0 and matching a
    /// literal space; taking the answer from the parser is stronger still, because it cannot
    /// drift from the parser no matter what the grammar goes on to accept.
    ///
    /// Parsing happens in a throwaway engine, so a module that is malformed or unauthorized
    /// never reaches the live one.
    fn rego_package(rego: &str) -> Result<String> {
        let mut scratch = regorus::Engine::new();
        let path = scratch
            .add_policy("fragment.rego".to_string(), rego.to_string())
            .map_err(|e| anyhow::anyhow!("fragment module does not parse: {e}"))?;
        path.strip_prefix("data.")
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("unexpected rego package path {path:?}"))
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
        let symlink_target = symlink_target_of(&file_type, &req.data)?;

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

/// Decode the symlink target carried in a request's `data` field.
///
/// `do_copy_file` interprets `data` as the link target whenever `file_mode` has `S_IFLNK`
/// set, so the target has to be visible to the policy for it to be constrainable.
fn symlink_target_of(file_type: &FileType, data: &[u8]) -> Result<Option<String>> {
    match file_type {
        FileType::Symlink => match OsStr::from_bytes(data).to_str() {
            Some(s) => Ok(Some(s.to_owned())),
            None => bail!("invalid symlink content"),
        },
        _ => Ok(None),
    }
}

/// PolicyCopySingleFileRequest is a pre-processed variant of the CopySingleFileRequest.
///
/// `data` is the entire file payload. Serializing it into the policy input would cost a
/// JSON array element per byte on every request and give the host a cheap way to load the
/// rules engine, so it is deliberately omitted.
///
/// The S_IFMT bits of `file_mode` are not decoded here: `copy_single_file` refuses any
/// request whose mode is not `S_IFREG` before policy ever sees it, so there is no
/// non-regular file for a rule to distinguish. The permission bits *are* still forwarded,
/// because that guard does not look at them and `do_copy_file` preserves `file_mode &
/// 0o7777` -- setuid, setgid and the sticky bit included.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct PolicyCopySingleFileRequest {
    pub sandbox_id: String,

    pub uid: i32,
    pub gid: i32,
    pub data_size: i64,
    pub file_mode: u32,
}

impl From<&CopySingleFileRequest> for PolicyCopySingleFileRequest {
    fn from(req: &CopySingleFileRequest) -> Self {
        PolicyCopySingleFileRequest {
            sandbox_id: req.sandbox_id.clone(),
            uid: req.uid,
            gid: req.gid,
            data_size: req.data_size,
            file_mode: req.file_mode,
        }
    }
}

/// PolicyPutVolumeFileRevisionRequest is a pre-processed variant of the
/// PutVolumeFileRevisionRequest, for the reasons documented on `PolicyCopySingleFileRequest`.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct PolicyPutVolumeFileRevisionRequest {
    pub agent_volume_id: String,
    pub file_name: String,
    pub revision: String,

    pub file_size: i64,
    pub file_mode: u32,
    pub dir_mode: u32,
    pub uid: i32,
    pub gid: i32,
    pub offset: i64,
}

impl From<&PutVolumeFileRevisionRequest> for PolicyPutVolumeFileRevisionRequest {
    fn from(req: &PutVolumeFileRevisionRequest) -> Self {
        Self {
            agent_volume_id: req.agent_volume_id.clone(),
            file_name: req.file_name.clone(),
            revision: req.revision.clone(),
            file_size: req.file_size,
            file_mode: req.file_mode,
            dir_mode: req.dir_mode,
            uid: req.uid,
            gid: req.gid,
            offset: req.offset,
        }
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
            "reg/a",
            &[],
            None,
            "",
            0,
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
            !scope.permits(
                "did:x509:0:sha256:AAA::CN:signer",
                "did:x509:0:sha256:AAA::CN:signer"
            ),
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
        p.engine
            .add_policy("agent_policy".to_string(), base)
            .unwrap();
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
            "error must tell the author what is missing, got: {}",
            err
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
        assert!(
            err.contains("same_issuer"),
            "error must quote the bad value: {}",
            err
        );
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

    /// FR-1n: the env-rule grant parses, defaults to empty (delegating nothing), and an
    /// empty *pattern* inside a present grant is rejected at boot rather than silently
    /// granting nothing — the symptom of which is indistinguishable from the fragment never
    /// having been delivered.
    #[test]
    fn test_fragment_specs_parse_env_rule_grant() {
        let mut p = AgentPolicy::new();
        let base = "package agent_policy\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:s\", \"feed\": \"reg/a:1\", \
             \"allow_env_rules\": [\"^FEATURE_FLAG_.+$\"]},\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:s\", \"feed\": \"reg/b:1\"},\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:s\", \"feed\": \"reg/c:1\", \
             \"allow_env_rules\": [\"\"]}\n\
            ]\n";
        p.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        let specs = p.fragment_specs().unwrap();

        assert_eq!(
            specs[0].allow_env_rules,
            vec!["^FEATURE_FLAG_.+$".to_string()]
        );
        specs[0].validate_rule_grants().unwrap();

        assert!(
            specs[1].allow_env_rules.is_empty(),
            "an omitted grant must delegate nothing"
        );
        specs[1]
            .validate_rule_grants()
            .expect("an omitted grant is the closed default, not an error");

        let err = specs[2].validate_rule_grants().unwrap_err().to_string();
        assert!(err.contains("empty pattern"), "got: {}", err);
    }

    /// F-62: the declaration carries the namespace grant and the module switch, and both
    /// default safely — no named namespaces, module allowed.
    #[test]
    fn test_fragment_specs_parse_module_grant() {
        let mut p = AgentPolicy::new();
        let base = "package agent_policy\n\
            policy_fragments := [\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:s\", \"feed\": \"reg/a:1\", \"includes\": [\"infra\", \"net\"]},\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:s\", \"feed\": \"reg/b:1\", \"allow_module\": false},\n\
            {\"issuer\": \"did:x509:0:sha256:AAA::CN:s\", \"feed\": \"reg/c:1\"}\n\
            ]\n";
        p.engine
            .add_policy("agent_policy".to_string(), base.to_string())
            .unwrap();
        let specs = p.fragment_specs().unwrap();

        assert_eq!(
            specs[0].includes,
            vec!["infra".to_string(), "net".to_string()]
        );
        assert!(
            specs[0].allow_module,
            "allow_module must default to true, or every existing declaration silently \
             stops contributing rules"
        );

        // Metadata-only: accepted for its SVN/receipt record, contributes no rules.
        assert!(!specs[1].allow_module);

        // Omitting both grants no named namespace but still applies the module — the
        // shared package remains available.
        assert!(specs[2].includes.is_empty());
        assert!(specs[2].allow_module);
    }

    /// F-62: `FragmentSpec::default()` must agree with what serde produces for an empty
    /// declaration. A derived Default would give `allow_module: false` and quietly disable
    /// module injection anywhere the struct is built from defaults.
    #[test]
    fn test_fragment_spec_default_matches_serde_default() {
        let from_serde: FragmentSpec =
            serde_json::from_str(r#"{"issuer":"i","feed":"f"}"#).unwrap();
        let from_default = FragmentSpec {
            issuer: "i".to_string(),
            feed: "f".to_string(),
            ..Default::default()
        };
        assert_eq!(from_serde, from_default);
        assert!(from_default.allow_module);
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
            .apply_fragment_module(
                "fragment:test",
                module,
                "reg/parent",
                &["infra".to_string()],
                None,
                "",
                0,
            )
            .unwrap();
        assert_eq!(pkg, "agent_policy.fragments[\"infra\"]");

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
        p.apply_fragment_module("frag:issuerA:1", module, "reg/a", &[], None, "", 0)
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
        assert!(p
            .apply_fragment_module("evil", base_ns, "reg/a", &[], None, "", 0)
            .is_err());

        // A sub-namespace not in `includes` is refused; one that is, is accepted.
        let mount_ns = "package agent_policy.fragments.mount\nallowed := true\n";
        assert!(p
            .apply_fragment_module("m", mount_ns, "reg/a", &["exec".to_string()], None, "", 0)
            .is_err());
        assert!(p
            .apply_fragment_module("m", mount_ns, "reg/a", &["mount".to_string()], None, "", 0)
            .is_ok());
    }

    /// F-69: a fragment may declare `agent_policy.fragments["<feed>"]` for its own verified
    /// feed — that is the only way to satisfy the container-contribution contract, because a
    /// feed is an OCI reference and cannot be a Rego identifier. Any *other* feed is refused,
    /// so the quoted form cannot be used to squat another publisher's namespace.
    #[test]
    fn test_fragment_may_only_claim_its_own_feed_namespace() {
        let feed = "localhost:5000/coco-e2e/fragment";
        let own = format!(
            "package agent_policy.fragments[\"{feed}\"]\n\
             issuer := \"did:example:e2e\"\nsvn := \"1\"\ncontainers := []\n"
        );

        let mut p = AgentPolicy::new();
        assert!(
            p.apply_fragment_module("own", &own, feed, &[], None, "did:example:e2e", 1)
                .is_ok(),
            "a fragment must be able to write under its own verified feed"
        );

        // Same module, delivered under a different verified feed: refused.
        let mut q = AgentPolicy::new();
        assert!(
            q.apply_fragment_module(
                "other",
                &own,
                "localhost:5000/someone-else",
                &[],
                None,
                "did:example:e2e",
                1
            )
            .is_err(),
            "a fragment must not be able to claim another feed's namespace"
        );

        // Whitespace inside the brackets is tolerated; the decoded feed is what is compared.
        let spaced = format!("package agent_policy.fragments[ \"{feed}\" ]\ncontainers := []\n");
        let mut r = AgentPolicy::new();
        assert!(r
            .apply_fragment_module("spaced", &spaced, feed, &[], None, "", 0)
            .is_ok());

        // A trailing segment after the bracket is not the sanctioned form.
        let suffixed =
            format!("package agent_policy.fragments[\"{feed}\"].extra\ncontainers := []\n");
        let mut s = AgentPolicy::new();
        assert!(s
            .apply_fragment_module("suffixed", &suffixed, feed, &[], None, "", 0)
            .is_err());
    }

    /// F-160: a fragment's module describes itself with `issuer` and `svn` rules, and the
    /// generated base policy resolves its containers through exactly those. They must
    /// therefore agree with the envelope the SRM verified, or the re-check in `rules.rego`
    /// is only the fragment restating its own claim.
    #[test]
    fn test_fragment_self_description_must_match_the_verified_envelope() {
        let feed = "localhost:5000/coco-e2e/fragment";
        let module = |issuer: &str, svn: &str| {
            format!(
                "package agent_policy.fragments[\"{feed}\"]\n\
                 issuer := \"{issuer}\"\nsvn := \"{svn}\"\ncontainers := []\n"
            )
        };
        let truth = "did:x509:0:sha256:AAA::CN:signer";

        // Agreement loads.
        let mut p = AgentPolicy::new();
        p.apply_fragment_module("ok", &module(truth, "4"), feed, &[], None, truth, 4)
            .expect("a module that describes itself accurately must load");

        // A module claiming a different issuer than the one that signed the envelope.
        let mut q = AgentPolicy::new();
        let err = q
            .apply_fragment_module(
                "wrong-issuer",
                &module("did:x509:0:sha256:BBB::CN:other", "4"),
                feed,
                &[],
                None,
                truth,
                4,
            )
            .expect_err("a module must not claim an issuer that did not sign it");
        assert!(err.to_string().contains("declares issuer"), "{}", err);

        // A module inflating its SVN past the envelope's, which is what would let it clear a
        // `minimum_svn` floor the envelope itself does not meet.
        let mut r = AgentPolicy::new();
        let err = r
            .apply_fragment_module("wrong-svn", &module(truth, "99"), feed, &[], None, truth, 4)
            .expect_err("a module must not claim an svn its envelope does not carry");
        assert!(err.to_string().contains("declares svn 99"), "{}", err);

        // Declaring neither is not a lie: such a fragment simply contributes no containers,
        // because the base policy's `to_number(mod.svn)` is undefined. Fail-closed already.
        let mut s = AgentPolicy::new();
        s.apply_fragment_module(
            "silent",
            &format!("package agent_policy.fragments[\"{feed}\"]\ncontainers := []\n"),
            feed,
            &[],
            None,
            truth,
            4,
        )
        .expect("a module that describes nothing must still load");

        // The check runs on the module as it will evaluate, so a self-description built from
        // measured parameters is judged after instantiation, not before.
        let mut t = AgentPolicy::new();
        let parameterised = format!(
            "package agent_policy.fragments[\"{feed}\"]\n\
             issuer := parameter(\"iss\")\nsvn := \"4\"\ncontainers := []\n"
        );
        t.apply_fragment_module(
            "param-ok",
            &parameterised,
            feed,
            &[],
            Some(&format!("{{\"iss\": \"{truth}\"}}")),
            truth,
            4,
        )
        .expect("a parameterised self-description that resolves correctly must load");

        let mut u = AgentPolicy::new();
        assert!(
            u.apply_fragment_module(
                "param-bad",
                &parameterised,
                feed,
                &[],
                Some("{\"iss\": \"did:x509:0:sha256:BBB::CN:other\"}"),
                truth,
                4,
            )
            .is_err(),
            "a parameterised self-description that resolves to the wrong issuer must not load"
        );
    }

    /// F-161 gap 2: `check_framework_version` runs from `set_policy` and reads
    /// `data.agent_policy.framework_version`, so it never sees a fragment — whose module
    /// lands under `data.agent_policy.fragments.<feed>`. A fragment is the only policy input
    /// that is neither measured nor default-denied, so without this its author has no way to
    /// state what it needs to be enforced by. hcsshim checks the same thing as step 5 of
    /// `load_fragment`.
    #[test]
    fn test_a_fragment_may_not_require_a_newer_framework_than_this_agent() {
        let feed = "localhost:5000/coco-e2e/fragment";
        let truth = "did:x509:0:sha256:AAA::CN:signer";
        let module = |fv: &str| {
            format!(
                "package agent_policy.fragments[\"{feed}\"]\n\
                 issuer := \"{truth}\"\nsvn := \"4\"\n\
                 framework_version := \"{fv}\"\ncontainers := []\n"
            )
        };
        let (maj, min, patch) = parse_semver(POLICY_FRAMEWORK_VERSION).unwrap();

        // Exactly what this agent implements is fine.
        let mut p = AgentPolicy::new();
        p.apply_fragment_module(
            "same",
            &module(POLICY_FRAMEWORK_VERSION),
            feed,
            &[],
            None,
            truth,
            4,
        )
        .expect("a fragment asking for the version we implement must load");

        // Older is fine: every gate it names exists, and one it does not name is not asked for.
        let mut q = AgentPolicy::new();
        q.apply_fragment_module(
            "older",
            &module(&format!("{}.0.0", maj.saturating_sub(1))),
            feed,
            &[],
            None,
            truth,
            4,
        )
        .expect("a fragment older than the agent must load");

        // Newer in any component is refused — the asymmetry FR-1l exists for.
        for ahead in [
            format!("{}.{}.{}", maj + 1, min, patch),
            format!("{}.{}.{}", maj, min + 1, patch),
            format!("{}.{}.{}", maj, min, patch + 1),
        ] {
            let mut r = AgentPolicy::new();
            let err = r
                .apply_fragment_module("ahead", &module(&ahead), feed, &[], None, truth, 4)
                .expect_err("a fragment ahead of the agent must be refused");
            assert!(
                err.to_string().contains("refusing a fragment written for"),
                "{}",
                err
            );
        }

        // Absent is legacy and allowed, matching FR-1l: that is every fragment signed before
        // this check existed, and such a fragment by definition expects nothing newer.
        let mut s = AgentPolicy::new();
        s.apply_fragment_module(
            "silent",
            &format!(
                "package agent_policy.fragments[\"{feed}\"]\n\
                 issuer := \"{truth}\"\nsvn := \"4\"\ncontainers := []\n"
            ),
            feed,
            &[],
            None,
            truth,
            4,
        )
        .expect("a fragment that declares no framework_version must load");

        // Explicit but malformed is an error, so a typo cannot pass as "unversioned" — which
        // is the whole value of treating absent as legacy.
        let mut t = AgentPolicy::new();
        let err = t
            .apply_fragment_module("typo", &module("1.0"), feed, &[], None, truth, 4)
            .expect_err("a malformed framework_version must not be read as absent");
        assert!(err.to_string().contains("not a semver"), "{}", err);
    }

    /// F-160: a module that fails the self-description check must not have reached the live
    /// engine. regorus has no remove-policy, so the check has to run before `add_policy`
    /// rather than undo itself afterwards — hcsshim, which adds first, has to call
    /// `RemoveModule` on this path.
    #[test]
    fn test_a_rejected_self_description_leaves_the_engine_untouched() {
        let feed = "localhost:5000/coco-e2e/fragment";
        let mut p = AgentPolicy::new();
        let module = format!(
            "package agent_policy.fragments[\"{feed}\"]\n\
             issuer := \"did:x509:0:sha256:BBB::CN:other\"\nsvn := \"4\"\n\
             containers := [\"smuggled\"]\n"
        );
        assert!(p
            .apply_fragment_module(
                "rejected",
                &module,
                feed,
                &[],
                None,
                "did:x509:0:sha256:AAA::CN:signer",
                4
            )
            .is_err());

        // Nothing from the refused module is visible to the engine.
        let found = Self_eval(&mut p, &format!("data.agent_policy.fragments[\"{feed}\"]"));
        assert!(
            found.is_none(),
            "a refused fragment module must not be queryable: {:?}",
            found
        );
    }

    /// Helper: evaluate a rego path in a policy under test, `None` when undefined.
    #[allow(non_snake_case)]
    fn Self_eval(p: &mut AgentPolicy, query: &str) -> Option<serde_json::Value> {
        p.engine.set_input_json("{}").unwrap();
        AgentPolicy::eval_scalar(&mut p.engine, query.to_string()).unwrap()
    }

    /// F-143: the package a fragment is *authorized* under must be the package it actually
    /// loads into. The namespace check used to read the source text with a scan for the
    /// literal `"package "`, which regorus does not require — it accepts any whitespace
    /// after the keyword. A module could therefore declare `package<TAB>agent_policy`, which
    /// the scan skipped, and park a decoy `package agent_policy.fragments` inside a raw
    /// string for the scan to find instead. The result was a module in the base package,
    /// free to redefine base rules.
    #[test]
    fn test_fragment_package_is_taken_from_the_parser_not_the_source_text() {
        let decoy = "\ndecoy := `\npackage agent_policy.fragments\n`\n";

        // Every separator regorus accepts after `package` must be read as the real
        // declaration, so none of these reach the base package.
        for (label, header) in [
            ("tab", "package\tagent_policy"),
            ("newline", "package\n agent_policy"),
            ("crlf", "package\r\n agent_policy"),
            ("many-spaces", "package   agent_policy"),
        ] {
            let mut p = AgentPolicy::new();
            let module = format!("{header}{decoy}");
            let err = p
                .apply_fragment_module(
                    "evil",
                    &module,
                    "reg/a",
                    &["infra".to_string()],
                    None,
                    "",
                    0,
                )
                .expect_err(&format!("{label}: base package must be refused"));
            assert!(
                format!("{err}").contains("outside the permitted fragment namespaces"),
                "{}: unexpected error {}",
                label,
                err
            );
        }

        // The same decoy alongside a genuinely permitted package is still fine: the decoy
        // is inert, because nothing reads it.
        let mut p = AgentPolicy::new();
        assert!(p
            .apply_fragment_module(
                "honest",
                &format!("package agent_policy.fragments.infra{decoy}"),
                "reg/a",
                &["infra".to_string()],
                None,
                "",
                0,
            )
            .is_ok());
    }

    /// F-143: the end-to-end consequence — a fragment that escapes into the base package can
    /// add a satisfying definition beside `default X := false` and flip every decision.
    #[tokio::test]
    async fn test_fragment_cannot_escape_its_namespace_to_flip_a_denial() {
        let containers = r#"[{
            "sandbox_pidns": false, "storages": [],
            "OCI": {"Version":"1.1.0","Root":{"Readonly":true},
                    "Process":{"Args":["/bin/sh"],"Cwd":"/","Env":["PATH=/usr/bin"]},
                    "Mounts":[],"Annotations":{}}
        }]"#;
        let request = r#"{"container_id":"c1","sandbox_pidns":false,"storages":[],
            "OCI":{"Version":"1.1.0","Root":{"Readonly":true},
                   "Process":{"Args":["/bin/evil"],"Cwd":"/","Env":["PATH=/usr/bin"]},
                   "Mounts":[],"Annotations":{}}}"#;

        let mut p = policy_with_containers(containers);
        let (before, _) = p
            .allow_request("CreateContainerRequest", request)
            .await
            .unwrap();
        assert!(!before, "the request must be denied to begin with");

        let evil = "package\tagent_policy\n\ndecoy := `\npackage agent_policy.fragments\n`\n\n\
                    CreateContainerRequest if { true }\n";
        assert!(p
            .apply_fragment_module(
                "evil",
                evil,
                "somefeed",
                &["infra".to_string()],
                None,
                "",
                0
            )
            .is_err());

        let (after, _) = p
            .allow_request("CreateContainerRequest", request)
            .await
            .unwrap();
        assert!(
            !after,
            "a refused fragment must not have changed the verdict"
        );
    }

    /// F-143: a module that does not parse is refused before it can touch the live engine,
    /// so a malformed fragment cannot leave the policy half-loaded.
    #[test]
    fn test_unparseable_fragment_never_reaches_the_engine() {
        let mut p = AgentPolicy::new();
        assert!(p
            .apply_fragment_module(
                "broken",
                "package agent_policy.fragments\nx := (",
                "reg/a",
                &[],
                None,
                "",
                0
            )
            .is_err());
        assert!(p
            .apply_fragment_module("no-package", "x := 1\n", "reg/a", &[], None, "", 0)
            .is_err());
        // The engine is still usable afterwards.
        assert!(p
            .apply_fragment_module(
                "good",
                "package agent_policy.fragments\nx := 1\n",
                "reg/a",
                &[],
                None,
                "",
                0
            )
            .is_ok());
    }

    /// FR-1k: a parameterised fragment reads its values through `parameter(name)`, falls
    /// back to the default it declares itself, and yields `null` when neither supplies one.
    #[test]
    fn test_fragment_parameters_are_bound_and_defaulted() {
        let mut p = AgentPolicy::new();
        let module = "package agent_policy.fragments\n\
            parameters_api := {\"host\": {\"default\": \"fallback\"}, \"other\": {}}\n\
            bound := parameter(\"host\")\n\
            defaulted := parameter(\"missing_here\")\n\
            unknown := parameter(\"other\")\n";
        p.apply_fragment_module(
            "frag",
            module,
            "reg/a",
            &[],
            Some("{\"host\": \"supplied\"}"),
            "",
            0,
        )
        .unwrap();

        let get = |p: &mut AgentPolicy, rule: &str| {
            p.engine
                .eval_rule(format!("data.agent_policy.fragments.{rule}"))
                .unwrap()
                .to_string()
        };
        assert_eq!(get(&mut p, "bound"), "\"supplied\"");
        // Neither supplied nor declared -> null rather than an evaluation failure.
        assert_eq!(get(&mut p, "defaulted"), "null");
        // Declared in `parameters_api` but with no default and no value -> null.
        assert_eq!(get(&mut p, "unknown"), "null");

        // The same module with the parameter left out falls back to the declared default,
        // proving `parameters_api` is consulted rather than the value being required.
        let mut q = AgentPolicy::new();
        q.apply_fragment_module("frag", module, "reg/a", &[], Some("{}"), "", 0)
            .unwrap();
        assert_eq!(get(&mut q, "bound"), "\"fallback\"");
    }

    /// FR-1k: parameters must be a JSON object. A scalar or array is rejected rather than
    /// coerced — every `parameter()` lookup would otherwise fall silently through to its
    /// default, turning a mis-specified policy into a quietly permissive one.
    #[test]
    fn test_fragment_parameters_must_be_an_object() {
        let mut p = AgentPolicy::new();
        let module = "package agent_policy.fragments\nx := 1\n";
        assert!(p
            .apply_fragment_module("a", module, "reg/a", &[], Some("[1, 2]"), "", 0)
            .is_err());
        assert!(p
            .apply_fragment_module("b", module, "reg/a", &[], Some("\"scalar\""), "", 0)
            .is_err());
        assert!(p
            .apply_fragment_module("c", module, "reg/a", &[], Some("{ not json"), "", 0)
            .is_err());
        // A fragment that is not parameterised is unaffected.
        assert!(p
            .apply_fragment_module("d", module, "reg/a", &[], None, "", 0)
            .is_ok());
    }

    /// FR-1l: a policy may state the enforcement framework it was written against. Equal or
    /// older is enforced; newer is refused, because gates this build lacks would silently
    /// not run rather than fail. An absent or unparseable declaration is legacy, not an
    /// error — only a malformed *explicit* one is.
    #[tokio::test]
    async fn test_framework_version_floor_is_enforced() {
        let base = "package agent_policy\ndefault SetPolicyRequest := false\n";
        let with = |v: &str| format!("{base}framework_version := \"{v}\"\n");

        // No declaration at all: every policy written before this check existed.
        assert!(AgentPolicy::new().set_policy(base).await.is_ok());
        // Older and equal are fine.
        assert!(AgentPolicy::new().set_policy(&with("0.9.0")).await.is_ok());
        assert!(AgentPolicy::new()
            .set_policy(&with(POLICY_FRAMEWORK_VERSION))
            .await
            .is_ok());
        // Newer in any component is refused.
        for v in ["1.0.1", "1.1.0", "2.0.0"] {
            assert!(
                AgentPolicy::new().set_policy(&with(v)).await.is_err(),
                "expected {} to be refused",
                v
            );
        }
        // An explicit but malformed version is an error, not a silent legacy fallback.
        assert!(AgentPolicy::new().set_policy(&with("1.0")).await.is_err());
        assert!(AgentPolicy::new()
            .set_policy(&with("v1.0.0"))
            .await
            .is_err());
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

    /// RM-64: build an `AgentPolicy` over the real `rules.rego` plus a `policy_data`
    /// declaring `containers`, so the denial-reason rules can be evaluated against the
    /// shipped policy rather than a model of it.
    fn policy_with_containers(containers_json: &str) -> AgentPolicy {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "rules.rego".to_string(),
                include_str!("../../../tools/genpolicy/rules.rego").to_string(),
            )
            .unwrap();
        p.engine
            .add_policy(
                "policy_data.rego".to_string(),
                format!(
                    "package agent_policy\npolicy_data := {{\"containers\": {containers_json}, \
                     \"fragments\": []}}\n"
                ),
            )
            .unwrap();
        p
    }

    /// RM-93: when the same `(issuer, feed)` is declared twice with different SVN floors,
    /// the *higher* floor must win.
    ///
    /// A policy can declare a fragment in two measured places — `policy_data.fragments`
    /// (BL-7, from `genpolicy-settings.json`) and `policy_fragments` (BL-8, appended to the
    /// generated policy text) — and `all_fragment_specs` concatenates them. Both are
    /// measured, so neither is attacker-controlled; the risk is not injection but an
    /// operator raising a floor in one place while a stale declaration survives in the
    /// other.
    ///
    /// `fragment_container_entries` selects with `some spec in all_fragment_specs`, which
    /// is an existential: a container is admitted if *any* spec accepts it. That makes the
    /// weakest floor win. The SRM does the opposite — `declare_feed` keeps the stricter
    /// floor when a feed is declared twice (RM-87) — so the two layers disagreed about what
    /// a duplicate declaration means, and the Rego layer was the permissive one.
    #[tokio::test]
    async fn duplicate_fragment_declarations_keep_the_strictest_svn_floor() {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "rules.rego".to_string(),
                include_str!("../../../tools/genpolicy/rules.rego").to_string(),
            )
            .unwrap();
        // Two declarations for one feed: a floor of 5, and a stale floor of 1.
        p.engine
            .add_policy(
                "policy_data.rego".to_string(),
                r#"package agent_policy
policy_data := {"containers": [], "fragments": [
  {"issuer": "did:x509:iss", "feed": "feed-a", "minimum_svn": 5},
  {"issuer": "did:x509:iss", "feed": "feed-a", "minimum_svn": 1}
]}
"#
                .to_string(),
            )
            .unwrap();
        // A delivered fragment at SVN 2: above the stale floor, below the real one.
        p.engine
            .add_policy(
                "frag.rego".to_string(),
                r#"package agent_policy.fragments["feed-a"]
issuer := "did:x509:iss"
svn := "2"
containers := [{"name": "smuggled"}]
"#
                .to_string(),
            )
            .unwrap();

        let entries = p
            .engine
            .eval_rule("data.agent_policy.fragment_container_entries".to_string())
            .expect("fragment_container_entries must evaluate");

        assert_eq!(
            entries.as_array().map(|a| a.len()).unwrap_or(0),
            0,
            "a fragment at SVN 2 is below the declared floor of 5, so it must contribute no \
             containers; admitting it means the weaker duplicate declaration won, which is \
             the opposite of what the SRM's declare_feed does. Got: {:?}",
            entries
        );
    }

    /// RM-93 positive control: the strict-floor rule must still admit a fragment that
    /// actually meets the highest declared floor, and must admit it exactly once even
    /// though two declarations name it. Without this, the test above would also pass if
    /// fragment composition were simply broken.
    #[tokio::test]
    async fn duplicate_declarations_admit_a_conforming_fragment_exactly_once() {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "rules.rego".to_string(),
                include_str!("../../../tools/genpolicy/rules.rego").to_string(),
            )
            .unwrap();
        p.engine
            .add_policy(
                "policy_data.rego".to_string(),
                r#"package agent_policy
policy_data := {"containers": [], "fragments": [
  {"issuer": "did:x509:iss", "feed": "feed-a", "minimum_svn": 5},
  {"issuer": "did:x509:iss", "feed": "feed-a", "minimum_svn": 1}
]}
"#
                .to_string(),
            )
            .unwrap();
        // At the strictest declared floor exactly.
        p.engine
            .add_policy(
                "frag.rego".to_string(),
                r#"package agent_policy.fragments["feed-a"]
issuer := "did:x509:iss"
svn := "5"
containers := [{"name": "legit"}]
"#
                .to_string(),
            )
            .unwrap();

        let entries = p
            .engine
            .eval_rule("data.agent_policy.fragment_container_entries".to_string())
            .expect("fragment_container_entries must evaluate");

        assert_eq!(
            entries.as_array().map(|a| a.len()).unwrap_or(0),
            1,
            "a fragment at the declared floor must contribute its container, once -- two \
             declarations of the same feed must not double it. Got: {:?}",
            entries
        );
    }

    /// FR-1n: evaluate the fragment-contributed env-rule arm of `allow_var` against the
    /// real `rules.rego`.
    ///
    /// The probe rule calls `allow_var` with an empty policy process, so no other arm can
    /// match and a `true` here can only have come from the fragment arm.
    fn env_probe(policy_data: &str, fragment: &str, var: &str) -> bool {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "rules.rego".to_string(),
                include_str!("../../../tools/genpolicy/rules.rego").to_string(),
            )
            .unwrap();
        p.engine
            .add_policy("policy_data.rego".to_string(), policy_data.to_string())
            .unwrap();
        p.engine
            .add_policy("frag.rego".to_string(), fragment.to_string())
            .unwrap();
        p.engine
            .add_policy(
                "probe.rego".to_string(),
                "package agent_policy\n\
                 default env_probe := false\n\
                 env_probe if {\n\
                 \x20   allow_var({\"Env\": []}, {\"Env\": []}, input.var, \"sandbox\", \"ns\")\n\
                 }\n"
                .to_string(),
            )
            .unwrap();
        p.engine
            .set_input_json(&serde_json::json!({ "var": var }).to_string())
            .unwrap();
        p.engine
            .eval_rule("data.agent_policy.env_probe".to_string())
            .unwrap()
            .to_string()
            == "true"
    }

    /// A declaration granting a name pattern, at SVN 5.
    fn env_policy_data(grant: &str) -> String {
        format!(
            r#"package agent_policy
policy_data := {{"containers": [], "fragments": [
  {{"issuer": "did:x509:iss", "feed": "prod/mut", "minimum_svn": 5{grant}}}
]}}
"#
        )
    }

    /// A delivered fragment carrying `env_rules`.
    fn env_fragment(svn: &str, rules: &str) -> String {
        format!(
            r#"package agent_policy.fragments["prod/mut"]
issuer := "did:x509:iss"
svn := "{svn}"
env_rules := {rules}
"#
        )
    }

    /// FR-1n: the whole point — a variable the deployment pipeline injects, which no
    /// measured container spec mentions, is admitted because a signed fragment says so and
    /// the base policy delegated that variable's name to it.
    #[tokio::test]
    async fn a_fragment_may_admit_an_env_var_the_base_policy_delegated() {
        assert!(
            env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^FEATURE_FLAG_[A-Z0-9_]+$"]"#),
                &env_fragment("5", r#"[{"name": "FEATURE_FLAG_X", "value": "true"}]"#),
                "FEATURE_FLAG_X=true",
            ),
            "a fragment rule inside the declared ceiling must admit the variable; this is \
             the capability hcsshim provides through platform_rules"
        );
    }

    /// The default is closed: a declaration that says nothing about env rules delegates
    /// nothing, so a policy written before this attribute existed cannot acquire the
    /// capability merely by running on a newer agent.
    #[tokio::test]
    async fn a_fragment_admits_nothing_when_the_base_policy_granted_nothing() {
        assert!(
            !env_probe(
                &env_policy_data(""),
                &env_fragment("5", r#"[{"name": "FEATURE_FLAG_X", "value": "true"}]"#),
                "FEATURE_FLAG_X=true",
            ),
            "without allow_env_rules the fragment has no env-rule authority at all, however \
             well-formed its rules are"
        );
    }

    /// The ceiling binds: a fragment cannot speak for a name outside the grant.
    #[tokio::test]
    async fn a_fragment_cannot_admit_a_name_outside_the_ceiling() {
        assert!(
            !env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^FEATURE_FLAG_[A-Z0-9_]+$"]"#),
                &env_fragment("5", r#"[{"name": "AZURE_CLIENT_SECRET", "value": "s"}]"#),
                "AZURE_CLIENT_SECRET=s",
            ),
            "a fragment that is trusted for feature flags must not thereby be trusted for \
             credentials"
        );
    }

    /// The ceiling is anchored by the enforcement, not by the author's discipline. An
    /// unanchored grant is the mistake a reader is most likely to make and the one whose
    /// consequence is worst: `regex.match` is a search, so "FEATURE_FLAG" would otherwise
    /// match anywhere in the name and hand the fragment a far wider grant than it reads as.
    #[tokio::test]
    async fn an_unanchored_ceiling_is_still_matched_whole() {
        assert!(
            !env_probe(
                &env_policy_data(r#", "allow_env_rules": ["FEATURE_FLAG"]"#),
                &env_fragment("5", r#"[{"name": "EVIL_FEATURE_FLAG_X", "value": "1"}]"#),
                "EVIL_FEATURE_FLAG_X=1",
            ),
            "an unanchored ceiling must not admit a name that merely contains it"
        );
        assert!(
            env_probe(
                &env_policy_data(r#", "allow_env_rules": ["FEATURE_FLAG"]"#),
                &env_fragment("5", r#"[{"name": "FEATURE_FLAG", "value": "1"}]"#),
                "FEATURE_FLAG=1",
            ),
            "positive control: anchoring must not break the exact name the author meant"
        );
    }

    /// Duplicate declarations intersect rather than union, matching the strictest-wins rule
    /// `svn_floor` applies to rollback floors. An operator who tightens one declaration must
    /// not be silently overridden by a stale copy of the other.
    #[tokio::test]
    async fn duplicate_declarations_intersect_the_env_ceiling() {
        let data = r#"package agent_policy
policy_data := {"containers": [], "fragments": [
  {"issuer": "did:x509:iss", "feed": "prod/mut", "minimum_svn": 5,
   "allow_env_rules": ["^FEATURE_FLAG_[A-Z0-9_]+$"]},
  {"issuer": "did:x509:iss", "feed": "prod/mut", "minimum_svn": 5}
]}
"#;
        assert!(
            !env_probe(
                data,
                &env_fragment("5", r#"[{"name": "FEATURE_FLAG_X", "value": "true"}]"#),
                "FEATURE_FLAG_X=true",
            ),
            "a second declaration that grants nothing must close the door for the feed; \
             taking the union would let the weakest declaration win, which is the opposite \
             of what the SRM's declare_feed does with duplicate SVN floors"
        );
    }

    /// The SVN floor governs env rules exactly as it governs containers: a rolled-back
    /// fragment cannot reintroduce a grant a newer version withdrew.
    #[tokio::test]
    async fn a_fragment_below_the_svn_floor_contributes_no_env_rules() {
        assert!(
            !env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^FEATURE_FLAG_[A-Z0-9_]+$"]"#),
                &env_fragment("2", r#"[{"name": "FEATURE_FLAG_X", "value": "true"}]"#),
                "FEATURE_FLAG_X=true",
            ),
            "SVN 2 is below the declared floor of 5, so the fragment contributes nothing"
        );
    }

    /// A rule's value is a literal unless the author asks for a regex. This is the exact
    /// mistake hcsshim's `strategy` field invites and that was raised against this design:
    /// `strategy = "string"` with `^FEATURE_FLAG_X=true$` reads like a regex and is not one.
    /// Here the quiet outcome is the safe one — the rule simply does not match.
    #[tokio::test]
    async fn a_value_is_literal_unless_re2_is_requested() {
        // A regex written where a literal is expected matches nothing, rather than being
        // silently reinterpreted.
        assert!(
            !env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^FEATURE_FLAG_X$"]"#),
                &env_fragment("5", r#"[{"name": "FEATURE_FLAG_X", "value": "^true$"}]"#),
                "FEATURE_FLAG_X=true",
            ),
            "the default strategy is literal equality, so a regex-looking value must not be \
             evaluated as a regex"
        );
        // Asking for re2 explicitly does work, and is anchored.
        assert!(
            env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^FEATURE_FLAG_X$"]"#),
                &env_fragment(
                    "5",
                    r#"[{"name": "FEATURE_FLAG_X", "value": "true|false", "value_strategy": "re2"}]"#
                ),
                "FEATURE_FLAG_X=false",
            ),
            "value_strategy re2 must evaluate the value as a regex"
        );
        assert!(
            !env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^FEATURE_FLAG_X$"]"#),
                &env_fragment(
                    "5",
                    r#"[{"name": "FEATURE_FLAG_X", "value": "true", "value_strategy": "re2"}]"#
                ),
                "FEATURE_FLAG_X=untrue",
            ),
            "an re2 value must be anchored, or \"true\" admits \"untrue\""
        );
        // An unrecognised strategy is not a synonym for the default.
        assert!(
            !env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^FEATURE_FLAG_X$"]"#),
                &env_fragment(
                    "5",
                    r#"[{"name": "FEATURE_FLAG_X", "value": "true", "value_strategy": "regex"}]"#
                ),
                "FEATURE_FLAG_X=true",
            ),
            "a misspelled strategy must fail closed rather than fall back to literal"
        );
    }

    /// The name ends at the *first* `=`. The `split`/`count == 2` idiom the older arms use
    /// silently refuses every value containing an `=` — base64, connection strings, JWTs —
    /// which is a common shape for exactly the pipeline-injected variables this feature
    /// exists to admit.
    #[tokio::test]
    async fn a_value_may_contain_an_equals_sign() {
        assert!(
            env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^PIPELINE_TOKEN$"]"#),
                &env_fragment("5", r#"[{"name": "PIPELINE_TOKEN", "value": "YWJj=="}]"#),
                "PIPELINE_TOKEN=YWJj==",
            ),
            "a base64 value must survive name/value splitting"
        );
    }

    /// A leading `=` gives an empty name, which is not a variable. Rejecting it keeps a
    /// ceiling of "^.*$" — the hcsshim-equivalent full delegation — from matching a
    /// malformed entry.
    #[tokio::test]
    async fn a_var_with_an_empty_name_is_refused() {
        assert!(
            !env_probe(
                &env_policy_data(r#", "allow_env_rules": ["^.*$"]"#),
                &env_fragment("5", r#"[{"name": "", "value": "x"}]"#),
                "=x",
            ),
            "an entry with no name is malformed and must not be admitted even under a \
             wide-open ceiling"
        );
    }

    /// FR-1o: evaluate the fragment-contributed mount arm against the real `rules.rego`.
    ///
    /// `fragment_mount_permitted` is probed directly rather than through
    /// `allow_by_bundle_or_sandbox_id`, because that rule needs a whole matching container,
    /// annotations and a resolvable bundle id before it ever reaches the mount check. The
    /// probe keeps each assertion about the thing it is named for.
    fn mount_probe(policy_data: &str, fragment: &str, p_mounts: &str, i_mount: &str) -> bool {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "rules.rego".to_string(),
                include_str!("../../../tools/genpolicy/rules.rego").to_string(),
            )
            .unwrap();
        p.engine
            .add_policy("policy_data.rego".to_string(), policy_data.to_string())
            .unwrap();
        p.engine
            .add_policy("frag.rego".to_string(), fragment.to_string())
            .unwrap();
        p.engine
            .add_policy(
                "probe.rego".to_string(),
                "package agent_policy\n\
                 default mount_probe := false\n\
                 mount_probe if {\n\
                 \x20   fragment_mount_permitted({\"Mounts\": input.p_mounts}, input.i_mount)\n\
                 }\n"
                .to_string(),
            )
            .unwrap();
        p.engine
            .set_input_json(&format!(
                r#"{{"p_mounts": {p_mounts}, "i_mount": {i_mount}}}"#
            ))
            .unwrap();
        p.engine
            .eval_rule("data.agent_policy.mount_probe".to_string())
            .unwrap()
            .to_string()
            == "true"
    }

    /// A declaration granting a mount-destination pattern, at SVN 5.
    ///
    /// `common` is present because `allow_by_bundle_or_sandbox_id` dereferences
    /// `policy_data.common.root_path` while substituting the bundle-id pattern; without it
    /// the rule is undefined long before it reaches any mount.
    fn mount_policy_data(grant: &str) -> String {
        format!(
            r#"package agent_policy
policy_data := {{"containers": [], "common": {{
  "root_path": "/run/kata/shared", "sfprefix": "^/run/kata/shared/", "cpath": "/run/kata/shared"
}}, "fragments": [
  {{"issuer": "did:x509:iss", "feed": "prod/mut", "minimum_svn": 5{grant}}}
]}}
"#
        )
    }

    /// A delivered fragment carrying `mount_rules`.
    fn mount_fragment(svn: &str, rules: &str) -> String {
        format!(
            r#"package agent_policy.fragments["prod/mut"]
issuer := "did:x509:iss"
svn := "{svn}"
mount_rules := {rules}
"#
        )
    }

    /// The mount a pipeline attaches, in the shape `rules.rego` sees it.
    const PIPELINE_MOUNT: &str = r#"{
        "destination": "/var/run/pipeline",
        "source": "/run/kata/pipeline",
        "type_": "bind",
        "options": ["rbind", "ro"]
    }"#;

    /// FR-1o: the point of the feature — a mount the deployment pipeline attaches, which
    /// no measured container spec declares, is admitted because a signed fragment says so
    /// and the base policy delegated that destination to it.
    #[tokio::test]
    async fn a_fragment_may_admit_a_mount_the_base_policy_delegated() {
        assert!(
            mount_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                PIPELINE_MOUNT,
            ),
            "a delegated destination, a fragment at the floor and an exactly matching rule \
             must admit the mount"
        );
    }

    /// The closed default: a base policy that never delegated a destination grants nothing,
    /// however well-formed the fragment's rule is.
    #[tokio::test]
    async fn without_allow_mount_rules_a_fragment_contributes_no_mount() {
        assert!(
            !mount_probe(
                &mount_policy_data(""),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                PIPELINE_MOUNT,
            ),
            "omitting allow_mount_rules must delegate nothing, so including a fragment \
             cannot by itself hand it the mount namespace"
        );
    }

    /// The ceiling is anchored however it is written, so an unanchored pattern cannot be
    /// widened by prefixing or suffixing the destination.
    #[tokio::test]
    async fn a_mount_ceiling_is_anchored_even_when_written_unanchored() {
        let grant = r#", "allow_mount_rules": ["/var/run/pipeline"]"#;
        let rule = r#"[{"destination": "/evil/var/run/pipeline", "source": "/run/kata/pipeline",
                        "type_": "bind", "options": ["rbind", "ro"]}]"#;
        let evil = r#"{
            "destination": "/evil/var/run/pipeline",
            "source": "/run/kata/pipeline",
            "type_": "bind",
            "options": ["rbind", "ro"]
        }"#;
        assert!(
            !mount_probe(
                &mount_policy_data(grant),
                &mount_fragment("5", rule),
                "[]",
                evil,
            ),
            "regex.match is an unanchored search, so without the anchoring a ceiling of \
             /var/run/pipeline would admit /evil/var/run/pipeline"
        );
    }

    /// A fragment may add a destination but never restate one the base policy declares.
    /// Without this a measured `ro` mount could be silently re-admitted as `rw`, and the
    /// base declaration would still read `ro` while the container got `rw`.
    #[tokio::test]
    async fn a_fragment_may_not_shadow_a_base_declared_destination() {
        let base = r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/x",
                        "type_": "bind", "options": ["rbind", "ro"]}]"#;
        assert!(
            !mount_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "rw"]}]"#
                ),
                base,
                r#"{
                    "destination": "/var/run/pipeline",
                    "source": "/run/kata/pipeline",
                    "type_": "bind",
                    "options": ["rbind", "rw"]
                }"#,
            ),
            "the base policy already speaks for this destination, so a fragment must not be \
             able to re-admit it on laxer terms"
        );
    }

    /// Options are the security-relevant part of a mount, so they match exactly rather
    /// than by subset: a presented mount carrying an option the rule does not name is
    /// refused even though every option the rule *does* name is present.
    #[tokio::test]
    async fn mount_options_must_match_exactly_not_by_subset() {
        assert!(
            !mount_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                r#"{
                    "destination": "/var/run/pipeline",
                    "source": "/run/kata/pipeline",
                    "type_": "bind",
                    "options": ["rbind", "ro", "rw"]
                }"#,
            ),
            "an option the rule never granted -- here rw alongside ro -- must not ride in \
             on a superset match"
        );
    }

    /// A rule that omits `options` admits only a mount that carries none, rather than any
    /// mount whose options it happens not to constrain.
    #[tokio::test]
    async fn a_mount_rule_without_options_does_not_admit_arbitrary_options() {
        assert!(
            !mount_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind"}]"#
                ),
                "[]",
                PIPELINE_MOUNT,
            ),
            "omitting options must mean 'no options', not 'any options'"
        );
    }

    /// The source is a literal unless the rule asks for a regex by name, so a pattern
    /// written without declaring `re2` is compared as text and does not match.
    #[tokio::test]
    async fn a_mount_source_is_literal_unless_re2_is_requested() {
        let grant = r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#;
        assert!(
            !mount_probe(
                &mount_policy_data(grant),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "^/run/kata/.+$",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                PIPELINE_MOUNT,
            ),
            "a pattern with no strategy is literal, so it must not quietly behave as a regex"
        );
        assert!(
            mount_probe(
                &mount_policy_data(grant),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/.+",
                         "source_strategy": "re2",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                PIPELINE_MOUNT,
            ),
            "asking for re2 by name must work"
        );
    }

    /// A mount rule cannot outrun the rollback floor: a fragment below the declared
    /// minimum SVN contributes nothing, mount rules included.
    #[tokio::test]
    async fn a_mount_rule_below_the_svn_floor_is_refused() {
        assert!(
            !mount_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#),
                &mount_fragment(
                    "4",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                PIPELINE_MOUNT,
            ),
            "a fragment below the floor must contribute no mount, or the rollback \
             protection would not cover this surface"
        );
    }

    /// The ceiling is the intersection over declarations, not the union: a second,
    /// narrower declaration of the same feed tightens the grant rather than being
    /// outvoted by the wider one. `some spec` here would let a stale, laxer duplicate win.
    #[tokio::test]
    async fn two_declarations_intersect_rather_than_union_the_mount_ceiling() {
        let policy_data = r#"package agent_policy
policy_data := {"containers": [], "fragments": [
  {"issuer": "did:x509:iss", "feed": "prod/mut", "minimum_svn": 5,
   "allow_mount_rules": ["^/var/run/.+$"]},
  {"issuer": "did:x509:iss", "feed": "prod/mut", "minimum_svn": 5,
   "allow_mount_rules": ["^/var/run/telemetry$"]}
]}
"#;
        assert!(
            !mount_probe(
                policy_data,
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                PIPELINE_MOUNT,
            ),
            "the narrower declaration must bind, so a destination only the wider one \
             permits is refused"
        );
    }

    /// A rule binds to the destination it names. Without the literal comparison a rule
    /// written for one destination would admit a mount at any *other* destination the
    /// ceiling happens to permit, which is the difference between delegating a named path
    /// and delegating the whole pattern the ceiling describes.
    #[tokio::test]
    async fn a_mount_rule_admits_only_the_destination_it_names() {
        assert!(
            !mount_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/.+$"]"#),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/telemetry", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                PIPELINE_MOUNT,
            ),
            "the rule names /var/run/telemetry, so it must not admit a mount at \
             /var/run/pipeline merely because the ceiling would allow that destination too"
        );
    }

    /// FR-1o integration: the arithmetic in `allow_by_bundle_or_sandbox_id`.
    ///
    /// The probes above cover `fragment_mount_permitted` in isolation. This one covers the
    /// part that actually changes the decision: a permitted mount is set aside, and the
    /// bijection is then required of what remains. That is where an off-by-one would live,
    /// and no amount of testing the predicate alone would find it.
    fn mounts_probe(policy_data: &str, fragment: &str, p_mounts: &str, i_mounts: &str) -> bool {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "rules.rego".to_string(),
                include_str!("../../../tools/genpolicy/rules.rego").to_string(),
            )
            .unwrap();
        p.engine
            .add_policy("policy_data.rego".to_string(), policy_data.to_string())
            .unwrap();
        p.engine
            .add_policy("frag.rego".to_string(), fragment.to_string())
            .unwrap();
        p.engine
            .add_policy(
                "probe.rego".to_string(),
                "package agent_policy\n\
                 default mounts_probe := false\n\
                 mounts_probe if {\n\
                 \x20   allow_by_bundle_or_sandbox_id(input.p_oci, input.i_oci, [], [])\n\
                 }\n"
                .to_string(),
            )
            .unwrap();
        let key = "io.kubernetes.cri.sandbox-id";
        let sandbox = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111";
        p.engine
            .set_input_json(
                &serde_json::json!({
                    "p_oci": {
                        "Annotations": { key: format!("^{sandbox}$") },
                        "Root": { "Path": "/run/kata/shared/$(bundle-id)/rootfs" },
                        "Mounts": serde_json::from_str::<serde_json::Value>(p_mounts).unwrap(),
                    },
                    "i_oci": {
                        "Annotations": { key: sandbox },
                        "Root": { "Path": format!("/run/kata/shared/{sandbox}/rootfs") },
                        "Mounts": serde_json::from_str::<serde_json::Value>(i_mounts).unwrap(),
                    },
                })
                .to_string(),
            )
            .unwrap();
        p.engine
            .eval_rule("data.agent_policy.mounts_probe".to_string())
            .unwrap()
            .to_string()
            == "true"
    }

    /// The base mount set is unchanged by the feature: with no fragment in play, a mount
    /// the policy does not declare is still refused. This is the guard that the excusing
    /// logic did not quietly widen the ordinary path.
    #[tokio::test]
    async fn an_undeclared_mount_is_still_refused_without_a_fragment() {
        let base = r#"[{"destination": "/etc/hosts", "source": "/run/kata/shared/x",
                        "type_": "bind", "options": ["rbind"]}]"#;
        let declared_only = r#"[{"destination": "/etc/hosts", "source": "/run/kata/shared/x",
                                 "type_": "bind", "options": ["rbind"]}]"#;
        assert!(
            mounts_probe(
                &mount_policy_data(""),
                &mount_fragment("5", "[]"),
                base,
                declared_only
            ),
            "the declared mount alone must still be accepted"
        );

        let with_extra = format!(
            r#"[{{"destination": "/etc/hosts", "source": "/run/kata/shared/x",
                                       "type_": "bind", "options": ["rbind"]}}, {PIPELINE_MOUNT}]"#
        );
        assert!(
            !mounts_probe(
                &mount_policy_data(""),
                &mount_fragment("5", "[]"),
                base,
                &with_extra
            ),
            "an extra mount no declaration covers must still be refused when nothing \
             delegated it"
        );
    }

    /// The feature end to end: the same extra mount is accepted once a signed fragment
    /// speaks for it and the base policy delegated that destination.
    #[tokio::test]
    async fn a_delegated_mount_is_excused_from_the_base_bijection() {
        let base = r#"[{"destination": "/etc/hosts", "source": "/run/kata/shared/x",
                        "type_": "bind", "options": ["rbind"]}]"#;
        let with_extra = format!(
            r#"[{{"destination": "/etc/hosts", "source": "/run/kata/shared/x",
                                       "type_": "bind", "options": ["rbind"]}}, {PIPELINE_MOUNT}]"#
        );
        assert!(
            mounts_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                base,
                &with_extra,
            ),
            "the pipeline mount is delegated and signed for, so the request must be \
             accepted with the declared mount still matched exactly once"
        );
    }

    /// Excusing must not become a way to drop a mount from scrutiny: a second *undeclared*
    /// mount that no fragment speaks for still fails the bijection even while the first is
    /// excused. This is the case an off-by-one in the count would let through.
    #[tokio::test]
    async fn excusing_one_mount_does_not_excuse_another() {
        let base = r#"[{"destination": "/etc/hosts", "source": "/run/kata/shared/x",
                        "type_": "bind", "options": ["rbind"]}]"#;
        let two_extra = format!(
            r#"[{{"destination": "/etc/hosts", "source": "/run/kata/shared/x",
                  "type_": "bind", "options": ["rbind"]}},
                {PIPELINE_MOUNT},
                {{"destination": "/var/run/smuggled", "source": "/run/kata/smuggled",
                  "type_": "bind", "options": ["rbind", "rw"]}}]"#
        );
        assert!(
            !mounts_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                base,
                &two_extra,
            ),
            "only the delegated mount may be set aside; a second undeclared mount must \
             still be counted and refused"
        );
    }

    /// The mount type is compared exactly, so a delegated destination cannot be reached
    /// with a different kind of filesystem than the rule names.
    #[tokio::test]
    async fn a_mount_type_must_match_the_rule() {
        assert!(
            !mount_probe(
                &mount_policy_data(r#", "allow_mount_rules": ["^/var/run/pipeline$"]"#),
                &mount_fragment(
                    "5",
                    r#"[{"destination": "/var/run/pipeline", "source": "/run/kata/pipeline",
                         "type_": "bind", "options": ["rbind", "ro"]}]"#
                ),
                "[]",
                r#"{
                    "destination": "/var/run/pipeline",
                    "source": "/run/kata/pipeline",
                    "type_": "tmpfs",
                    "options": ["rbind", "ro"]
                }"#,
            ),
            "a rule for a bind mount must not admit a tmpfs at the same destination"
        );
    }

    /// RM-93: a fragment whose issuer no declaration names contributes nothing, so the
    /// issuer check survived the move from iterating specs to iterating delivered modules.
    #[tokio::test]
    async fn a_fragment_from_an_undeclared_issuer_contributes_nothing() {
        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "rules.rego".to_string(),
                include_str!("../../../tools/genpolicy/rules.rego").to_string(),
            )
            .unwrap();
        p.engine
            .add_policy(
                "policy_data.rego".to_string(),
                r#"package agent_policy
policy_data := {"containers": [], "fragments": [
  {"issuer": "did:x509:iss", "feed": "feed-a", "minimum_svn": 1}
]}
"#
                .to_string(),
            )
            .unwrap();
        p.engine
            .add_policy(
                "frag.rego".to_string(),
                r#"package agent_policy.fragments["feed-a"]
issuer := "did:x509:someone-else"
svn := "9"
containers := [{"name": "wrong-issuer"}]
"#
                .to_string(),
            )
            .unwrap();

        let entries = p
            .engine
            .eval_rule("data.agent_policy.fragment_container_entries".to_string())
            .expect("fragment_container_entries must evaluate");

        assert_eq!(
            entries.as_array().map(|a| a.len()).unwrap_or(0),
            0,
            "no declaration names this issuer, so svn_floor is undefined and the fragment \
             must contribute nothing however high its SVN. Got: {:?}",
            entries
        );
    }

    /// RM-64: a denial says which check failed, not merely that one did.
    ///
    /// This reproduces RM-63 -- a workload with `readOnlyRootFilesystem: false` makes
    /// genpolicy declare `Readonly = false` for the pause container while the runtime
    /// presents `true`. Before this, the operator got the endpoint name and a `print()`
    /// trace that containerd truncated away; there was nothing to distinguish it from any
    /// other create-container denial.
    #[tokio::test]
    async fn a_denial_names_the_field_that_did_not_match() {
        let containers = r#"[{
            "sandbox_pidns": false,
            "storages": [],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": true},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": ["PATH=/usr/bin"]},
                "Mounts": [],
                "Annotations": {}
            }
        }]"#;
        let request = r#"{
            "container_id": "c1",
            "sandbox_pidns": false,
            "storages": [],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": false},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": ["PATH=/usr/bin"]},
                "Mounts": [],
                "Annotations": {}
            }
        }"#;

        let mut p = policy_with_containers(containers);
        let (allowed, explanation) = p
            .allow_request("CreateContainerRequest", request)
            .await
            .unwrap();

        assert!(!allowed, "the request must still be refused");
        assert!(
            explanation.contains("Root.Readonly"),
            "the denial does not name the field that failed: {}",
            explanation
        );
        // The point of the change is that this survives truncation, so it must lead.
        let head: String = explanation.chars().take(200).collect();
        assert!(
            head.contains("Root.Readonly"),
            "the reason must precede the trace, or containerd truncates it away: {}",
            head
        );
    }

    /// RM-110: an error must not report a field the request never carried.
    ///
    /// `not is_null(x)` holds when `x` is *undefined* as well as when it is a value, so
    /// reading `input.OCI.Linux.Seccomp` through an absent `Linux` section made the
    /// seccomp error fire on requests that carried no seccomp profile at all. Because
    /// the errors are joined in rule order that reason then led the denial, displacing
    /// the field that actually failed -- the precise defect RM-64 exists to prevent,
    /// reintroduced by a spurious reason rather than a missing one.
    #[tokio::test]
    async fn an_absent_linux_section_does_not_report_a_seccomp_profile() {
        let containers = r#"[{
            "sandbox_pidns": false,
            "storages": [],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": true},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": ["PATH=/usr/bin"]},
                "Mounts": [],
                "Annotations": {}
            }
        }]"#;
        // No `Linux` key at all, so `input.OCI.Linux.Seccomp` is undefined rather than null.
        let request = r#"{
            "container_id": "c1",
            "sandbox_pidns": false,
            "storages": [],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": false},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": ["PATH=/usr/bin"]},
                "Mounts": [],
                "Annotations": {}
            }
        }"#;

        let mut p = policy_with_containers(containers);
        let (allowed, explanation) = p
            .allow_request("CreateContainerRequest", request)
            .await
            .unwrap();

        assert!(!allowed, "the request must still be refused");
        assert!(
            !explanation.contains("Linux.Seccomp"),
            "the request carries no seccomp profile, so nothing may claim it does: {}",
            explanation
        );
    }

    /// RM-110: the guard above must not silence the error it guards.
    ///
    /// The failure mode of over-tightening the check is an error that never fires, which
    /// no negative test would catch, so pin the case the error exists for.
    #[tokio::test]
    async fn a_real_seccomp_profile_is_still_reported() {
        let containers = r#"[{
            "sandbox_pidns": false,
            "storages": [],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": true},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": ["PATH=/usr/bin"]},
                "Mounts": [],
                "Annotations": {}
            }
        }]"#;
        let request = r#"{
            "container_id": "c1",
            "sandbox_pidns": false,
            "storages": [],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": true},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": ["PATH=/usr/bin"]},
                "Mounts": [],
                "Annotations": {},
                "Linux": {"Seccomp": {"defaultAction": "SCMP_ACT_ERRNO"}}
            }
        }"#;

        let mut p = policy_with_containers(containers);
        let (allowed, explanation) = p
            .allow_request("CreateContainerRequest", request)
            .await
            .unwrap();

        assert!(!allowed, "a host seccomp profile must still be refused");
        assert!(
            explanation.contains("Linux.Seccomp"),
            "the denial must still name the seccomp profile it refused: {}",
            explanation
        );
    }

    /// RM-64 for the case that motivated it: RM-62, where the declared and presented
    /// dm-verity root hashes are identical and only the partition numbers are swapped.
    ///
    /// This is the failure worth calling out explicitly, because it *looks* like image
    /// corruption -- a verity mismatch -- and is actually a layer-ordering disagreement.
    /// Diagnosing it originally took a hand-built `rules.rego` with the largest `print()`
    /// calls stubbed out just to fit the trace under containerd's limit.
    #[tokio::test]
    async fn a_verity_ordering_mismatch_is_distinguishable_from_a_content_mismatch() {
        let containers = r#"[{
            "sandbox_pidns": false,
            "storages": [
                {"driver": "erofs-verity-layer",
                 "options": ["X-kata.dmverity.roothash=aaa", "X-kata.partition-number=1"]},
                {"driver": "erofs-verity-layer",
                 "options": ["X-kata.dmverity.roothash=bbb", "X-kata.partition-number=2"]}
            ],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": true},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": []},
                "Mounts": [],
                "Annotations": {}
            }
        }]"#;
        // Same two hashes, swapped onto each other's partitions.
        let request = r#"{
            "container_id": "c1",
            "sandbox_pidns": false,
            "storages": [
                {"fstype": "erofs",
                 "options": ["X-kata.dmverity.roothash=bbb", "X-kata.partition-number=1"]},
                {"fstype": "erofs",
                 "options": ["X-kata.dmverity.roothash=aaa", "X-kata.partition-number=2"]}
            ],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": true},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": []},
                "Mounts": [],
                "Annotations": {}
            }
        }"#;

        let mut p = policy_with_containers(containers);
        let (allowed, explanation) = p
            .allow_request("CreateContainerRequest", request)
            .await
            .unwrap();

        assert!(!allowed);
        assert!(
            explanation.contains("dm-verity layers"),
            "the denial does not mention the verity layers: {}",
            explanation
        );
        // Both hashes are present on both sides; the message has to show the pairing so
        // the reader can see the positions are what differ.
        assert!(
            explanation.contains("partition 1 = bbb") && explanation.contains("partition 1 = aaa"),
            "the message must show both pairings so an ordering fault is visible as one: {}",
            explanation
        );
    }

    /// The reasons must not leak workload data, and neither must anything else in the
    /// denial. The message crosses the guest/host boundary, so an environment variable
    /// value or a command line in it is data a confidential guest has handed to the host
    /// it is meant to be protected from. Variables are reported by name only and command
    /// arguments are not reported at all -- the same posture the C-ACI baseline takes when
    /// it redacts env values before a decision leaves the UVM.
    #[tokio::test]
    async fn a_denial_reports_env_names_but_never_values() {
        let containers = r#"[{
            "sandbox_pidns": false,
            "storages": [],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": true},
                "Process": {"Args": ["/bin/sh"], "Cwd": "/", "Env": ["PATH=/usr/bin"]},
                "Mounts": [],
                "Annotations": {}
            }
        }]"#;
        let request = r#"{
            "container_id": "c1",
            "sandbox_pidns": false,
            "storages": [],
            "OCI": {
                "Version": "1.1.0",
                "Root": {"Readonly": true},
                "Process": {
                    "Args": ["/bin/sh", "-c", "launch --token hunter2"],
                    "Cwd": "/",
                    "Env": ["PATH=/usr/bin", "API_KEY=supersecretvalue"]
                },
                "Mounts": [],
                "Annotations": {}
            }
        }"#;

        let mut p = policy_with_containers(containers);
        let (allowed, explanation) = p
            .allow_request("CreateContainerRequest", request)
            .await
            .unwrap();

        assert!(!allowed);
        assert!(
            explanation.contains("API_KEY"),
            "the undeclared variable's name must be reported: {}",
            explanation
        );
        // RM-66: the message now carries a base64 decision object, which would hide a leak
        // from a substring check on the message alone. Assert on the decoded payload too.
        let decoded = crate::decision::extract_decision_json(&explanation)
            .expect("the denial carried no decision object");
        for surface in [explanation.as_str(), decoded.as_str()] {
            for leaked in ["supersecretvalue", "hunter2", "launch --token"] {
                assert!(
                    !surface.contains(leaked),
                    "the denial leaked a value ({}) across the guest/host boundary: {}",
                    leaked,
                    surface
                );
            }
        }
    }

    /// RM-26: a removal for a container id the policy never admitted is allowed exactly
    /// once, and the tombstone it writes keeps it single-shot.
    ///
    /// Unlike the tests above, this one evaluates the **real** `rules.rego` rather than a
    /// model of it. The property is a two-rule interaction — the strict rule must stay
    /// undefined for a tombstoned id while the new no-op rule admits an untouched one — and
    /// a hand-written miniature would prove the model, not the shipped policy.
    ///
    /// Why the no-op exists: when a `CreateContainerRequest` is denied, the shim's cleanup
    /// path still issues `RemoveContainerRequest` for the same id. With only the strict
    /// rule, no state key was ever written for that id, so the removal was denied too, the
    /// shim retried forever and the pod sat in `Terminating` until it was force-deleted.
    #[cfg(feature = "strict-policy")]
    #[tokio::test]
    async fn removing_a_never_created_container_is_a_single_shot_no_op() {
        let cid = "ctr-never-created";
        let req = format!(r#"{{"container_id": "{cid}"}}"#);

        let mut p = AgentPolicy::new();
        p.engine
            .add_policy(
                "rules.rego".to_string(),
                include_str!("../../../tools/genpolicy/rules.rego").to_string(),
            )
            .unwrap();
        // `rules.rego` is only half a policy: genpolicy appends the `policy_data` document
        // when it generates one, and without it regorus refuses to compile the module at
        // all ("use of undefined variable `policy_data` is unsafe"). Supply an empty one.
        // The rules under test never read it -- they work purely off `pstate` -- so an
        // empty document is enough to make the real rules compile without modelling them.
        p.engine
            .add_policy(
                "policy_data.rego".to_string(),
                "package agent_policy\npolicy_data := {}\n".to_string(),
            )
            .unwrap();
        p.restore_state(r#"{"pstate": {}}"#).unwrap();

        let first = p.allow_request("RemoveContainerRequest", &req).await;
        assert!(
            matches!(first, Ok((true, _))),
            "removing an id with no container behind it must succeed, or a denied create \
             leaves the pod with no way to finish terminating; got {:?}",
            first
        );

        assert!(
            p.snapshot_state()
                .unwrap()
                .contains(&format!("retired:{cid}")),
            "the no-op path must still burn the id (RM-20), so removal is single-shot \
             however it was admitted"
        );

        assert!(
            is_denied(p.allow_request("RemoveContainerRequest", &req).await),
            "the second removal must be denied: an id carrying a tombstone is exactly the \
             replay the strict rule exists to refuse"
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
            let name = test_case.name.clone();
            let output_res: Result<PolicyCopyFileRequest> = (&test_case.input).try_into();
            if let Some(expected) = test_case.output {
                let output = output_res.unwrap_or_else(|e| panic!("test case {}: {:?}", name, e));
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

    /// The payload is dropped on both content-channel translations: neither policy input
    /// has a `data` field for the host to inflate. The permission bits survive, because
    /// the S_IFREG guard in the agent does not look at them and `do_copy_file` preserves
    /// `file_mode & 0o7777`.
    #[test]
    fn content_channel_translations_drop_the_payload() {
        let single = protocols::agent::CopySingleFileRequest {
            sandbox_id: "sbx".to_owned(),
            file_type: protobuf::EnumOrUnknown::new(
                protocols::agent::SingleFileType::SINGLE_FILE_TYPE_RESOLV_CONF,
            ),
            file_mode: libc::S_IFREG as u32 | 0o4644,
            data: b"nameserver 1.1.1.1\n".to_vec(),
            data_size: 19,
            ..Default::default()
        };

        let out = PolicyCopySingleFileRequest::from(&single);

        assert_eq!(out.sandbox_id, "sbx");
        assert_eq!(out.file_mode, libc::S_IFREG as u32 | 0o4644);
        assert_eq!(out.data_size, 19);
        assert_eq!(
            serde_json::to_value(&out).unwrap().get("data"),
            None,
            "the file payload must not reach the rules engine"
        );

        let volume = protocols::agent::PutVolumeFileRevisionRequest {
            agent_volume_id: "watchable-1".to_owned(),
            file_name: "config.json".to_owned(),
            revision: "..2026_02_11".to_owned(),
            file_mode: libc::S_IFREG as u32 | 0o2600,
            dir_mode: 0o750,
            data: b"{}".to_vec(),
            file_size: 2,
            ..Default::default()
        };

        let out = PolicyPutVolumeFileRevisionRequest::from(&volume);

        assert_eq!(out.agent_volume_id, "watchable-1");
        assert_eq!(out.file_name, "config.json");
        assert_eq!(out.revision, "..2026_02_11");
        assert_eq!(out.file_mode, libc::S_IFREG as u32 | 0o2600);
        assert_eq!(out.dir_mode, 0o750);
        assert_eq!(
            serde_json::to_value(&out).unwrap().get("data"),
            None,
            "the file payload must not reach the rules engine"
        );
    }
}
