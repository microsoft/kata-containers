// Copyright (c) 2025 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! BL-8: host-side delivery of signed policy fragments.
//!
//! The guest cannot fetch these itself. At the point fragments must be loaded, the agent
//! has not yet served `update_interface`/`update_routes`, so the guest has only `lo` — no
//! route, no DNS, no egress. An in-guest pull can therefore never succeed, and a guest that
//! blocks on one never boots.
//!
//! So the host pulls the artifact and pushes the bytes in over the existing vsock ttRPC
//! channel, which is what hcsshim does: its `SecurityPolicyFragment` resource carries a
//! base64 COSE blob and a media type, never a URL, and there is no guest-side fetch path in
//! it at all.
//!
//! Nothing here is trusted. The host chooses only *which bytes to offer*; the guest decides
//! whether to accept them, verifying the COSE signature against the issuers and per-feed SVN
//! floors carried in its *measured* base policy, and refusing to create any container while a
//! declared fragment remains unsatisfied. A host that substitutes, downgrades, reorders or
//! withholds a fragment can cause a visible failure — never a silent bypass. That is why the
//! fetch is allowed to live out here in untrusted code.

use anyhow::{anyhow, bail, Context, Result};
use agent::{Agent, LoadPolicyFragmentRequest};
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use std::collections::HashMap;
use std::sync::Arc;

/// Pod annotation naming the fragments to deliver, as a comma-separated list of OCI
/// references (e.g. `contoso.azurecr.io/frag/infra:3,contoso.azurecr.io/frag/net:1`).
///
/// This is a *delivery hint only*. The trust anchors — which issuers are authorized, which
/// feeds are accepted, and the SVN floor for each — live in the measured base policy and are
/// never taken from here. Naming a fragment the policy does not accept gets it rejected;
/// omitting one the policy declares leaves the requirement outstanding and blocks container
/// creation.
pub const POLICY_FRAGMENTS_ANNOTATION: &str = "io.katacontainers.config.agent.policy_fragments";

/// OCI layer media type carrying the COSE_Sign1(rego) fragment envelope.
const COSE_LAYER_MEDIA_TYPE: &str = "application/cose-x509+rego";
/// Expected OCI artifactType for a kata policy fragment.
const FRAGMENT_ARTIFACT_TYPE: &str = "application/x-ms-ccepolicy-frag";

macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

/// Parse the delivery hint into an ordered, de-duplicated list of OCI references.
///
/// Order is preserved because the guest enforces an append-only ordering chain (FR-1j):
/// fragments must be presented in the order the issuer chained them, so this must not sort
/// or otherwise reshuffle the list.
fn parse_refs(annotation: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in annotation.split(',') {
        let item = item.trim();
        if item.is_empty() || out.iter().any(|e| e == item) {
            continue;
        }
        out.push(item.to_string());
    }
    out
}

/// Fetch every fragment named by the annotation and push it to the agent.
///
/// Must run after the agent is serving and before the first container is created. Any
/// failure is propagated: a fragment that was asked for but could not be delivered has to
/// surface here, where the error still says which reference failed and why, rather than
/// later as an opaque "declared fragment not satisfied" at container creation.
pub async fn deliver_declared_fragments(
    agent: &Arc<dyn Agent>,
    annotations: &HashMap<String, String>,
) -> Result<usize> {
    let Some(raw) = annotations.get(POLICY_FRAGMENTS_ANNOTATION) else {
        return Ok(0);
    };
    let refs = parse_refs(raw);
    if refs.is_empty() {
        return Ok(0);
    }

    slog::info!(
        sl!(),
        "policy-fragments: delivering {} declared fragment(s)",
        refs.len()
    );

    for reference in &refs {
        let cose_sign1 = fetch_fragment(reference)
            .await
            .with_context(|| format!("failed to fetch policy fragment {reference}"))?;

        // Only the envelope goes over the wire. The guest reconstructs issuer/feed/SVN from
        // the bytes it verifies, so the host never gets to describe the fragment.
        agent
            .load_policy_fragment(LoadPolicyFragmentRequest {
                cose_sign1,
                ..Default::default()
            })
            .await
            .with_context(|| format!("guest rejected policy fragment {reference}"))?;

        slog::info!(sl!(), "policy-fragments: delivered {}", reference);
    }

    Ok(refs.len())
}

/// Pull the raw COSE_Sign1 bytes for a fragment from its OCI registry.
///
/// No verification happens here, and none is possible: the host has no trust anchors. The
/// returned bytes are untrusted until the guest verifies them.
async fn fetch_fragment(reference: &str) -> Result<Vec<u8>> {
    let reference: Reference = reference
        .parse()
        .with_context(|| format!("invalid OCI reference: {reference}"))?;

    // Registries are HTTPS by default; only fall back to plain HTTP for an explicit
    // localhost/loopback dev registry.
    let protocol = if is_plain_http_registry(&reference) {
        ClientProtocol::Http
    } else {
        ClientProtocol::Https
    };
    let client = Client::new(ClientConfig {
        protocol,
        ..Default::default()
    });

    // Fragments are public, signed artifacts pinned by digest/tag; anonymous pull.
    let auth = RegistryAuth::Anonymous;

    let (manifest, _digest) = client
        .pull_image_manifest(&reference, &auth)
        .await
        .with_context(|| format!("failed to pull manifest for {reference}"))?;

    if let Some(at) = &manifest.artifact_type {
        if at != FRAGMENT_ARTIFACT_TYPE {
            slog::info!(
                sl!(),
                "policy-fragments: unexpected artifactType {} (want {}) for {} - continuing",
                at,
                FRAGMENT_ARTIFACT_TYPE,
                reference
            );
        }
    }

    let layer = manifest
        .layers
        .iter()
        .find(|l| l.media_type == COSE_LAYER_MEDIA_TYPE)
        .ok_or_else(|| {
            anyhow!(
                "no {COSE_LAYER_MEDIA_TYPE} layer in manifest for {reference} (have: {})",
                manifest
                    .layers
                    .iter()
                    .map(|l| l.media_type.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

    let mut buf: Vec<u8> = Vec::with_capacity(layer.size.max(0) as usize);
    client
        .pull_blob(&reference, layer, &mut buf)
        .await
        .with_context(|| format!("failed to download fragment layer {}", layer.digest))?;

    if buf.is_empty() {
        bail!("downloaded fragment layer is empty for {reference}");
    }
    Ok(buf)
}

/// Only treat an explicit localhost/loopback registry as plain-HTTP; all other registries
/// must use TLS.
///
/// Matches the host exactly rather than by prefix. A prefix test would accept
/// `localhost.evil.com`, letting an attacker-chosen hostname downgrade the pull to cleartext.
fn is_plain_http_registry(reference: &Reference) -> bool {
    is_loopback_registry(reference.registry())
}

/// Split out from [`is_plain_http_registry`] so the host-matching rule can be tested
/// directly, without depending on what the OCI reference parser happens to accept.
fn is_loopback_registry(registry: &str) -> bool {
    // Strip the optional :port. IPv6 literals are bracketed, so keep everything up to the
    // closing bracket when one is present.
    let host = match registry.rfind(']') {
        Some(close) => &registry[..=close],
        None => registry.split(':').next().unwrap_or(registry),
    };
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_dedups_preserving_order() {
        // Order matters: the guest enforces an append-only chain over these.
        assert_eq!(
            parse_refs(" r.io/b:2 , r.io/a:1,r.io/b:2 ,, r.io/c:3 "),
            vec!["r.io/b:2", "r.io/a:1", "r.io/c:3"]
        );
    }

    #[test]
    fn empty_annotation_yields_nothing() {
        assert!(parse_refs("").is_empty());
        assert!(parse_refs("  ,  , ").is_empty());
    }

    #[test]
    fn plain_http_only_for_loopback() {
        for r in ["localhost", "localhost:5000", "127.0.0.1:5000", "[::1]:5000"] {
            assert!(is_loopback_registry(r), "{}", r);
        }
        // A prefix match would downgrade all of these to cleartext.
        for r in [
            "contoso.azurecr.io",
            "localhost.example.com",
            "127.0.0.1.evil.com",
            "localhost-evil.com:443",
        ] {
            assert!(!is_loopback_registry(r), "{}", r);
        }
    }

    #[test]
    fn parsed_references_route_by_registry() {
        assert!(is_plain_http_registry(
            &"localhost:5000/f:1".parse().unwrap()
        ));
        assert!(!is_plain_http_registry(
            &"contoso.azurecr.io/f:1".parse().unwrap()
        ));
    }
}
