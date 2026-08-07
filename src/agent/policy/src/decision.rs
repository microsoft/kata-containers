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

use serde::Serialize;

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
}
