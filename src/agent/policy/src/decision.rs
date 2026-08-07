// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-8 — structured, rule-attributable decision objects.
//!
//! When the policy denies a request, the agent must be able to explain *why* in a way
//! that is auditable but leaks nothing sensitive. A [`DecisionObject`] records:
//!
//!  - the **endpoint** that was evaluated (e.g. `CreateContainerRequest`);
//!  - the **decision** (`deny`);
//!  - the **failed rule** that produced the denial (the Rego query path that evaluated to
//!    false), giving rule attribution;
//!  - the **bound state keys**: the *names* of the top-level fields present in the request
//!    that were bound during evaluation.
//!
//! Crucially, the decision object never contains request **values**: no environment
//! variable values, no sealed secrets, no policy text — only field names and rule names.
//! This lets an operator see which request shape hit which rule without exposing the
//! workload's data or the policy's contents.
//!
//! The object is delivered on the **host-bound denial error** ([`DecisionObject::to_host_error`]),
//! not written to a guest-local file. A confidential guest's filesystem is not an audit
//! sink: nothing outside can read it and it does not outlive the VM. See RM-66.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;

/// Sentinel wrapping the encoded decision on the host-bound error. Deliberately the same
/// marker the C-ACI baseline uses, so a consumer that already knows how to pull a decision
/// out of a containerd log needs no changes to read one from this stack.
pub const DECISION_SENTINEL: &str = "policyDecision";

/// Byte budget for the whole denial message.
///
/// The message travels as a ttrpc status string and is then logged by containerd, neither
/// of which promises to carry an arbitrarily large payload. A denial that is dropped or
/// mangled for being oversized is worse than a smaller one, so the object is shed to fit
/// (see [`DecisionObject::to_host_error`]) rather than emitted whole and hoped for. The
/// baseline applies the same idea with its own limit; this is not an attempt to match its
/// exact value.
pub const MAX_HOST_ERROR_LEN: usize = 4096;

/// A structured, redaction-safe record of a policy decision (emitted on denial).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DecisionObject {
    /// The policy endpoint / request kind that was evaluated.
    pub endpoint: String,
    /// The decision. Always `deny` for objects produced on denial.
    pub decision: &'static str,
    /// The Rego query path that was evaluated. This identifies the *endpoint*, not the
    /// check that failed inside it — every denial of a given RPC produces the same value,
    /// so it carries no attribution on its own. [`Self::reasons`] is what discriminates.
    pub failed_rule: String,
    /// Names of the top-level request fields bound during evaluation. Field *names* only,
    /// never their values.
    pub bound_state_keys: Vec<String>,
    /// Which checks no policy container satisfied, from the policy's own `reason` rule.
    ///
    /// This is the attribution: it distinguishes a root-hash mismatch from a mount
    /// mismatch from a `Root.Readonly` mismatch, all of which are otherwise the same
    /// bare "denied". Empty when the policy predates the `reason` rule, so an older
    /// policy still produces a valid (if less specific) record rather than an error.
    pub reasons: Vec<String>,
    /// Fields shed to fit [`MAX_HOST_ERROR_LEN`], so a consumer can tell a deliberately
    /// trimmed record from a complete one and does not read an absent field as an empty
    /// one. Omitted entirely when nothing was dropped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dropped: Vec<String>,
}

impl DecisionObject {
    /// Build a denial decision object for `endpoint`, extracting only the top-level field
    /// names from the (JSON) request input. Values are deliberately discarded so no
    /// request data can leak into the audit record.
    pub fn for_denial(endpoint: &str, request_input_json: &str) -> Self {
        Self::for_denial_with_reasons(endpoint, request_input_json, Vec::new())
    }

    /// As [`Self::for_denial`], but carrying the policy's own account of which checks
    /// failed. `reasons` comes from the `reason` rule in `rules.rego` and is already
    /// redaction-safe by construction: it reports environment variables by name only and
    /// omits command arguments entirely.
    pub fn for_denial_with_reasons(
        endpoint: &str,
        request_input_json: &str,
        reasons: Vec<String>,
    ) -> Self {
        let mut bound_state_keys = extract_top_level_keys(request_input_json);
        // Deterministic ordering for stable, comparable audit records.
        bound_state_keys.sort();
        DecisionObject {
            endpoint: endpoint.to_string(),
            decision: "deny",
            // The endpoint's query path. See the field's doc comment: this is not
            // attribution, `reasons` is.
            failed_rule: format!("data.agent_policy.{endpoint}"),
            bound_state_keys,
            reasons,
            dropped: Vec::new(),
        }
    }

    /// The operator-facing explanation, ordered so the most useful part survives
    /// truncation.
    ///
    /// The denial message passes through containerd, which truncates it. Whatever is
    /// printed first is therefore what the operator actually gets, so the specific
    /// reasons lead and everything bulkier follows. This is the same ordering the C-ACI
    /// baseline applies when it trims a decision to fit: shed the large context first and
    /// keep the human-readable strings longest.
    pub fn explain(&self) -> String {
        if self.reasons.is_empty() {
            return format!(
                "{} was refused and the active policy provides no reason rule, so the \
                 specific check that failed is not recoverable. Regenerate the policy with \
                 a current genpolicy to get attributable denials.",
                self.endpoint
            );
        }
        format!(
            "{} was refused because no policy container satisfied: {}",
            self.endpoint,
            self.reasons.join("; ")
        )
    }

    /// Serialize to a single-line JSON audit record. Serialization only ever includes the
    /// (redaction-safe) fields of this struct.
    pub fn to_json(&self) -> String {
        // The struct contains no values, so this cannot leak request data.
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                "{{\"endpoint\":\"{}\",\"decision\":\"deny\"}}",
                self.endpoint
            )
        })
    }

    /// The message that crosses to the host on a denial: the human-readable explanation
    /// followed by the machine-readable decision object.
    ///
    /// RM-66. The structured object previously had exactly one sink — a JSON file at
    /// `/tmp/policy.jsonl` *inside the guest* — which made FR-8's "denials are auditable"
    /// guarantee unreachable in the configuration it was written for. That file is only
    /// opened when the log level is Debug or finer, and a strict guest pins itself to Info
    /// and refuses to let the host raise it, so the object was built on every denial and
    /// then discarded. Even with debug forced on it could not have served as an audit
    /// trail: nothing outside a confidential guest can read the guest's `/tmp`, and the
    /// record dies with the VM.
    ///
    /// So the object rides out on the error instead, which is the one channel that
    /// demonstrably reaches an operator — and which the C-ACI baseline picked deliberately
    /// for the same reason. Prose first, because containerd truncates and the reasons are
    /// what a human needs; the encoded object second, for anything parsing the log.
    ///
    /// This widens what crosses the trust boundary, so the redaction guarantee stops being
    /// a nicety: everything encoded here is field *names* and policy-authored reason
    /// strings, never request values. `no_request_values_survive_the_round_trip` holds the
    /// line by decoding the payload and asserting on it.
    pub fn to_host_error(&self) -> String {
        self.to_host_error_within(MAX_HOST_ERROR_LEN)
    }

    /// [`Self::to_host_error`] against an explicit budget, so the shedding order is
    /// testable without constructing multi-kilobyte denials.
    fn to_host_error_within(&self, budget: usize) -> String {
        let prose = self.explain();

        // Shed in increasing order of usefulness, mirroring the baseline's "drop the bulky
        // context first, keep the human-readable strings longest". `bound_state_keys` goes
        // first: it is the bulkiest part and the least informative, being the field names
        // of a fixed protobuf schema. `reasons` goes second, and only from the *payload* —
        // they are already in the prose, so this deduplicates rather than loses.
        for stage in 0..3 {
            let mut shed = self.clone();
            match stage {
                0 => {}
                1 => {
                    shed.bound_state_keys = Vec::new();
                    shed.dropped = vec!["bound_state_keys".to_string()];
                }
                _ => {
                    shed.bound_state_keys = Vec::new();
                    shed.reasons = Vec::new();
                    shed.dropped = vec!["bound_state_keys".to_string(), "reasons".to_string()];
                }
            }
            let encoded = STANDARD.encode(shed.to_json());
            let msg = format!("{prose} {DECISION_SENTINEL}<{encoded}>{DECISION_SENTINEL}");
            if msg.len() <= budget {
                return msg;
            }
        }

        // The object cannot be made to fit at all. Drop it entirely and keep the prose,
        // which is what an operator acts on. Say so, rather than leaving a consumer to
        // wonder whether the policy simply predates structured decisions.
        let note = " [decision object omitted: over size budget]";
        if prose.len() + note.len() <= budget {
            return format!("{prose}{note}");
        }
        // Even the prose is over budget: keep its head, because the reasons lead.
        let keep = budget.saturating_sub(3);
        let mut end = keep.min(prose.len());
        while end > 0 && !prose.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &prose[..end])
    }
}

/// Recover a [`DecisionObject`]'s JSON from a message produced by
/// [`DecisionObject::to_host_error`]. Returns `None` when the message carries no decision
/// — an older guest, or one whose object was shed to fit — so a caller can degrade to the
/// prose rather than treating it as an error.
pub fn extract_decision_json(message: &str) -> Option<String> {
    let open = format!("{DECISION_SENTINEL}<");
    let start = message.find(&open)? + open.len();
    let rest = &message[start..];
    let end = rest.find(&format!(">{DECISION_SENTINEL}"))?;
    let decoded = STANDARD.decode(&rest[..end]).ok()?;
    String::from_utf8(decoded).ok()
}

/// Extract the names of the top-level object fields of a JSON document. Nested values are
/// never traversed and never included; a non-object document yields no keys.
fn extract_top_level_keys(json: &str) -> Vec<String> {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC6.5: a denial emits a structured object with endpoint, failed rule, and the
    /// bound state keys (field names).
    #[test]
    fn denial_object_has_attribution_and_keys() {
        let input = r#"{"container_id":"c1","OCI":{"process":{}},"storages":[]}"#;
        let d = DecisionObject::for_denial("CreateContainerRequest", input);
        assert_eq!(d.endpoint, "CreateContainerRequest");
        assert_eq!(d.decision, "deny");
        assert_eq!(d.failed_rule, "data.agent_policy.CreateContainerRequest");
        assert_eq!(
            d.bound_state_keys,
            vec![
                "OCI".to_string(),
                "container_id".to_string(),
                "storages".to_string()
            ]
        );
    }

    /// TC6.6: the decision object (and its serialization) contains no request values —
    /// no env values, no sealed secrets, no policy text.
    #[test]
    fn decision_object_leaks_no_values() {
        // A request laden with sensitive values.
        let input = r#"{
            "container_id":"c1",
            "OCI":{"process":{"env":["API_KEY=supersecretvalue","DB_PASSWORD=hunter2"]}},
            "sealed_secret":"SEALED.eyJz.aGVsbG8",
            "policy":"package agent_policy\ndefault CreateContainerRequest := true"
        }"#;
        let d = DecisionObject::for_denial("CreateContainerRequest", input);
        let json = d.to_json();

        // Field names may appear; values must not.
        for leaked in [
            "supersecretvalue",
            "hunter2",
            "API_KEY=supersecretvalue",
            "SEALED.eyJz.aGVsbG8",
            "package agent_policy",
            "default CreateContainerRequest := true",
        ] {
            assert!(
                !json.contains(leaked),
                "decision object leaked a sensitive value: {}\nobject: {}",
                leaked,
                json
            );
        }
        // The bound keys are names only (no values attached).
        assert!(d.bound_state_keys.contains(&"sealed_secret".to_string()));
        assert!(d.bound_state_keys.contains(&"policy".to_string()));
        assert!(!json.contains("supersecret"));
    }

    #[test]
    fn non_object_input_yields_no_keys() {
        let d = DecisionObject::for_denial("SomeRequest", "\"not-an-object\"");
        assert!(d.bound_state_keys.is_empty());
        assert_eq!(d.decision, "deny");
    }

    /// RM-64: the explanation leads with the specific failed checks. containerd truncates
    /// the denial message, so anything after the first few hundred bytes is lost — if the
    /// reasons did not come first they would not reach an operator at all.
    #[test]
    fn explanation_leads_with_the_specific_reasons() {
        let d = DecisionObject::for_denial_with_reasons(
            "CreateContainerRequest",
            r#"{"container_id":"c1"}"#,
            vec![
                "Root.Readonly: request has false, policy accepts {true}".to_string(),
                "mount destinations no policy container declares: {\"/tmp\"}".to_string(),
            ],
        );
        let explanation = d.explain();
        assert!(
            explanation.contains("Root.Readonly: request has false"),
            "explanation dropped a reason: {}",
            explanation
        );
        assert!(
            explanation.contains("/tmp"),
            "explanation dropped a reason: {}",
            explanation
        );

        // The discriminating detail must survive an aggressive truncation.
        let truncated: String = explanation.chars().take(120).collect();
        assert!(
            truncated.contains("Root.Readonly"),
            "the first reason did not survive truncation: {}",
            truncated
        );
    }

    /// A policy generated before the `reason` rule existed yields no reasons. That must
    /// produce an actionable message rather than an empty one, because the operator's fix
    /// (regenerate the policy) is not otherwise discoverable.
    #[test]
    fn missing_reasons_still_explain_what_to_do() {
        let d = DecisionObject::for_denial("CreateContainerRequest", r#"{"container_id":"c1"}"#);
        let explanation = d.explain();
        assert!(explanation.contains("CreateContainerRequest"));
        assert!(
            explanation.contains("genpolicy"),
            "explanation names no remedy: {}",
            explanation
        );
    }

    /// The reasons are carried into the audit record too, not just the returned error.
    #[test]
    fn reasons_are_serialized_into_the_audit_record() {
        let d = DecisionObject::for_denial_with_reasons(
            "CreateContainerRequest",
            r#"{"container_id":"c1"}"#,
            vec!["storage count: request presents 3 storages, policy declares {2}".to_string()],
        );
        let json = d.to_json();
        assert!(
            json.contains("storage count"),
            "audit record dropped the reasons: {}",
            json
        );
    }

    /// RM-66: the object actually leaves the guest. This is the whole point of the change —
    /// previously it was built on every denial and then dropped on the floor in strict.
    #[test]
    fn the_host_bound_error_carries_the_structured_object() {
        let d = DecisionObject::for_denial_with_reasons(
            "CreateContainerRequest",
            r#"{"container_id":"c1","OCI":{}}"#,
            vec!["Root.Readonly: request has false, policy accepts {true}".to_string()],
        );
        let msg = d.to_host_error();

        // Prose first: containerd truncates, and this is what a human acts on.
        assert!(
            msg.starts_with("CreateContainerRequest was refused"),
            "prose did not lead: {}",
            msg
        );

        let recovered = extract_decision_json(&msg).expect("no decision in the message");
        let v: serde_json::Value = serde_json::from_str(&recovered).unwrap();
        assert_eq!(v["endpoint"], "CreateContainerRequest");
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["failed_rule"], "data.agent_policy.CreateContainerRequest");
        assert_eq!(v["bound_state_keys"][0], "OCI");
        assert!(v["reasons"][0]
            .as_str()
            .unwrap()
            .contains("Root.Readonly"));
        // Nothing was shed, so the marker must be absent rather than empty.
        assert!(v.get("dropped").is_none(), "unexpected dropped: {}", v);
    }

    /// The redaction guarantee now has to hold on a payload that crosses the trust
    /// boundary, so assert it on the *decoded* object rather than on the struct we built.
    /// This is the test that has to fail if anyone ever puts a value in here.
    #[test]
    fn no_request_values_survive_the_round_trip() {
        let input = r#"{
            "container_id":"c1",
            "OCI":{"process":{"env":["API_KEY=supersecretvalue","DB_PASSWORD=hunter2"],
                              "args":["launch","--token","hunter2"]}},
            "sealed_secret":"SEALED.eyJz.aGVsbG8",
            "policy":"package agent_policy\ndefault CreateContainerRequest := true"
        }"#;
        let d = DecisionObject::for_denial_with_reasons(
            "CreateContainerRequest",
            input,
            // Reasons come from rules.rego, which reports env vars by name only.
            vec!["env vars no policy container declares: {\"API_KEY\"}".to_string()],
        );
        let msg = d.to_host_error();
        let decoded = extract_decision_json(&msg).expect("no decision in the message");

        // Check the encoded payload *and* the surrounding message: base64 would hide a
        // leak from a naive substring check on `msg` alone.
        for surface in [msg.as_str(), decoded.as_str()] {
            for leaked in [
                "supersecretvalue",
                "hunter2",
                "SEALED.eyJz.aGVsbG8",
                "package agent_policy",
                "default CreateContainerRequest := true",
                "launch",
                "--token",
            ] {
                assert!(
                    !surface.contains(leaked),
                    "a request value crossed to the host: {}\nin: {}",
                    leaked,
                    surface
                );
            }
        }
        // Names are still reported, or the record would be useless.
        assert!(decoded.contains("API_KEY"));
        assert!(decoded.contains("sealed_secret"));
    }

    /// Over budget, the bulky-but-dull field goes first and the reasons stay. A denial
    /// that gets dropped or mangled for being oversized is worse than a trimmed one.
    #[test]
    fn an_oversized_decision_sheds_the_dullest_field_first() {
        let keys: String = (0..200)
            .map(|i| format!("\"field_number_{i}\":1"))
            .collect::<Vec<_>>()
            .join(",");
        let d = DecisionObject::for_denial_with_reasons(
            "CreateContainerRequest",
            &format!("{{{keys}}}"),
            vec!["Root.Readonly: request has false, policy accepts {true}".to_string()],
        );

        let msg = d.to_host_error_within(1024);
        assert!(msg.len() <= 1024, "budget exceeded: {} bytes", msg.len());

        let v: serde_json::Value =
            serde_json::from_str(&extract_decision_json(&msg).expect("decision shed entirely"))
                .unwrap();
        assert_eq!(
            v["dropped"][0], "bound_state_keys",
            "shed the wrong field first: {}",
            v
        );
        assert!(
            v["reasons"][0].as_str().unwrap().contains("Root.Readonly"),
            "shedding lost the attribution: {}",
            v
        );
        // The prose keeps the reason regardless of what the payload had to drop.
        assert!(msg.contains("Root.Readonly: request has false"));
    }

    /// When nothing fits, the operator still gets the reason — and is told the object was
    /// dropped, so its absence is not mistaken for a policy that predates FR-8.
    #[test]
    fn a_hopeless_budget_still_delivers_the_reason() {
        let d = DecisionObject::for_denial_with_reasons(
            "CreateContainerRequest",
            r#"{"container_id":"c1"}"#,
            vec!["Root.Readonly: request has false, policy accepts {true}".to_string()],
        );
        let msg = d.to_host_error_within(200);
        assert!(msg.len() <= 200, "budget exceeded: {} bytes", msg.len());
        assert!(msg.contains("Root.Readonly"), "lost the reason: {}", msg);
        assert!(
            msg.contains("decision object omitted"),
            "silently dropped the object: {}",
            msg
        );
        assert!(extract_decision_json(&msg).is_none());
    }

    /// A truncated or absent payload must read as "no decision", not as a parse failure —
    /// callers degrade to the prose.
    #[test]
    fn a_message_without_a_decision_extracts_nothing() {
        assert!(extract_decision_json("plain denial, no sentinel").is_none());
        assert!(extract_decision_json("policyDecision<truncated-mid-way").is_none());
        assert!(extract_decision_json("policyDecision<!!!not-base64!!!>policyDecision").is_none());
    }

    /// The default budget has to be big enough for a realistic denial, or the shedding
    /// path becomes the normal path and the object never actually arrives intact.
    #[test]
    fn a_realistic_denial_fits_the_default_budget_intact() {
        let input = r#"{"container_id":"c1","OCI":{"process":{}},"storages":[],
                        "sandbox_pidns":false,"string_user":null,"shared_mounts":[]}"#;
        let d = DecisionObject::for_denial_with_reasons(
            "CreateContainerRequest",
            input,
            vec![
                "Root.Readonly: request has false, policy accepts {true}".to_string(),
                "mount destinations no policy container declares: {\"/var/run/secrets\"}"
                    .to_string(),
                "dm-verity: no policy container declares root hash \
                 a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
                    .to_string(),
            ],
        );
        let msg = d.to_host_error();
        assert!(msg.len() <= MAX_HOST_ERROR_LEN);
        let v: serde_json::Value =
            serde_json::from_str(&extract_decision_json(&msg).unwrap()).unwrap();
        assert!(
            v.get("dropped").is_none(),
            "a routine denial should not need shedding: {}",
            v
        );
    }
}
