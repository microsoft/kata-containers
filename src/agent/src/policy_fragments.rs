// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0
//

//! BL-8 — the measured base policy's declared policy-fragment requirements.
//!
//! The measured base policy may declare `data.agent_policy.policy_fragments[]` entries —
//! each naming an `issuer` (`did:x509`), a `feed` (OCI reference), a `minimum_svn`, and
//! optionally `required`. A declaration always states the *terms* a fragment for that feed
//! must meet. Whether its **absence** is tolerated is the policy's choice, via `required`.
//!
//! # Why the guest does not fetch
//!
//! This module used to pull each declared fragment from its OCI registry at boot. That
//! could never work. `load_declared_fragments()` ran inside `start_sandbox()` *before*
//! `rpc::start()`, but the guest's interfaces and routes are configured only by the
//! `update_interface` / `update_routes` ttRPC handlers, which cannot run until that server
//! is serving. The guest kernel cmdline also masks `systemd-networkd`. At that point the
//! guest has only `lo`, so DNS could not resolve and every non-loopback feed failed —
//! meaning any pod that declared a fragment failed to boot.
//!
//! Delivery is therefore the host's job, which is also what C-ACI/hcsshim does: the host
//! pulls the artifact and passes the bytes in (`ResourceTypePolicyFragment` ->
//! `InjectFragment`), and the guest verifies the COSE signature against a *measured* trust
//! root. Untrusted delivery, trusted verification — the guest needing no network is the
//! point, not a limitation. Here the bytes arrive through `rpc::load_policy_fragment`.
//!
//! # What still makes this fail-closed
//!
//! Moving the fetch out means the host now chooses *when* — and whether — to deliver. Two
//! separate things keep that safe, and it is worth being clear about which does what.
//!
//! The first applies always and needs no opt-in: a fragment that never arrives contributes
//! no grants, so a container only that fragment would have permitted does not match the
//! composed policy and is refused on its own merits. Withholding a fragment can therefore
//! only ever *reduce* what runs. This is exactly C-ACI/hcsshim's position, where fragments
//! are injected lazily and nothing obliges the host to send any of them.
//!
//! The second is opt-in, because it is stricter than C-ACI. A fragment may carry something
//! whose absence is *not* fail-safe — a deny rule, an audit obligation, a constraint the
//! base policy was written assuming had been composed in. For those, silence is not a safe
//! default, and the policy says so by setting `required: true`. Such a declaration is
//! recorded at boot as an outstanding obligation and container creation is refused while it
//! is unsatisfied (see [`assert_all_declared_satisfied`]). A host that pushes nothing,
//! pushes late, or pushes a fragment for the wrong feed cannot get a container started.
//!
//! `required: false` is not `unchecked`. Every delivered fragment — optional or not — is
//! verified identically and cross-checked against its declaration, so a fragment that
//! arrives with the wrong issuer or an SVN below the measured floor is rejected either way.
//! The flag decides only whether *absence* is an error.
//!
//! Verification itself happens entirely in the guest, through the SRM `FragmentStore`, so
//! FR-1d (did:x509), FR-1f (receipts), FR-1i (rollback floor) and FR-1j (ordering) apply
//! regardless of `required`.

use anyhow::{bail, Result};
use slog::{info, warn};
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::AGENT_POLICY;

pub use kata_agent_policy::policy::{FragmentSpec, NestedScope};

macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

/// How many levels of delegated declaration are followed before the chain is cut.
///
/// Each level must already opt in through its own `allow_nested`, so a chain cannot extend
/// itself silently — this is a backstop against a cycle (A declares B, B declares A) rather
/// than the primary control. Kept small because no legitimate composition needs depth: an
/// issuer that wants five fragments declares five, it does not build a linked list.
const MAX_NESTING_DEPTH: u8 = 4;

lazy_static! {
    /// Fragment declarations from the measured base policy that have not yet been satisfied
    /// by a verified delivery. Emptied entry by entry as fragments arrive.
    ///
    /// Optional (`required: false`) declarations are tracked here too, even though their
    /// absence never blocks anything: they still have to be cross-checked against the
    /// delivery that claims to satisfy them, so a fragment arriving for a declared feed with
    /// the wrong issuer or too low an SVN is rejected whether or not it was mandatory.
    static ref PENDING: Mutex<Vec<FragmentSpec>> = Mutex::new(Vec::new());

    /// Every `(issuer, feed)` that has been declared, with the delegation scope its
    /// declaration granted and how deep in a delegation chain it sits.
    ///
    /// Separate from `PENDING` because a declaration is *removed* from there once
    /// satisfied, and the scope has to outlive that: a fragment's own nested declarations
    /// are read at delivery time, which is precisely the moment it stops being pending.
    static ref DELEGATION: Mutex<HashMap<(String, String), (NestedScope, u8)>> =
        Mutex::new(HashMap::new());
}

/// Record every fragment requirement the measured base policy declares.
///
/// Called from the boot path once the base policy is set from initdata. Performs no I/O:
/// it only reads the already-measured policy, so it cannot fail for environmental reasons.
/// Returns the number of outstanding requirements.
///
/// A failure to *read* the declarations is still fatal to the boot path — an unreadable
/// requirement list must not be silently treated as "no requirements".
pub async fn record_declared_fragments() -> Result<usize> {
    let specs = {
        let mut policy = AGENT_POLICY.lock().await;
        policy.fragment_specs()?
    };

    if specs.is_empty() {
        info!(sl!(), "policy-fragments: base policy declares no fragments");
        return Ok(0);
    }

    for spec in &specs {
        info!(
            sl!(),
            "policy-fragments: expecting feed {} (issuer {}, minimum_svn {}, {})",
            spec.feed,
            spec.issuer,
            spec.minimum_svn,
            if spec.required {
                "required — containers blocked until delivered"
            } else {
                "optional — absence contributes no grants"
            }
        );
    }

    // FR-1e: a declaration in the measured base policy authorizes its own (issuer, feed)
    // pair. Without this the SRM's feed allow-list is populated only from the trust root's
    // [[issuer.feed]] blocks, so a declared named feed was rejected as UndeclaredFeed no
    // matter what the host delivered -- the requirement could be stated but never
    // satisfied, and the sandbox stayed blocked forever. C-ACI/hcsshim likewise treats the
    // security policy's fragment declaration as the authorization.
    //
    // This grants no trust the policy did not already carry: the base policy is measured
    // alongside the trust root, the fragment must still be signed by an issuer the trust
    // root authorized, and min_required() keeps the issuer-wide floor in force, so a
    // declaration can raise the SVN bar but never lower it.
    //
    // Delegation scopes are resolved here rather than at use, so a malformed `allow_nested`
    // aborts the boot (the caller treats an Err as fatal) instead of surfacing much later
    // as a fragment that mysteriously cannot delegate.
    {
        let mut store = crate::FRAGMENTS.lock().await;
        let mut delegation = DELEGATION.lock().await;
        for spec in &specs {
            let scope = spec.nested_scope()?;
            store.declare_feed(spec.issuer.clone(), spec.feed.clone(), spec.minimum_svn);
            // FR-1c: the declaration, not the fragment, decides which policy namespaces
            // this feed may contribute to and whether its module is applied at all.
            // FR-1k: and, for a parameterised fragment, with what values.
            store.grant_module_scope(
                spec.issuer.clone(),
                spec.feed.clone(),
                &spec.includes,
                spec.allow_module,
                spec.parameters.as_ref().map(|p| p.to_string()),
            );
            delegation.insert((spec.issuer.clone(), spec.feed.clone()), (scope, 0));
        }
    }

    let n = specs.len();
    let required = specs.iter().filter(|s| s.required).count();
    *PENDING.lock().await = specs;
    if required == 0 {
        info!(
            sl!(),
            "policy-fragments: {} declared fragment(s), none required; delivery is lazy and \
             containers are not gated on it",
            n
        );
    } else {
        info!(
            sl!(),
            "policy-fragments: {} declared fragment(s), {} required; containers are blocked \
             until each required fragment is delivered and verified",
            n,
            required
        );
    }
    Ok(n)
}

/// Cross-check a *verified* fragment against the measured declarations and mark any it
/// satisfies as delivered.
///
/// Called from `rpc::load_policy_fragment` after the SRM has verified and committed the
/// fragment. Returns an error when the fragment names a declared feed but contradicts the
/// declaration — a valid signature over the wrong issuer, or an SVN below the measured
/// floor, must not satisfy the requirement. The declaration's `minimum_svn` is measured
/// and per-feed, so it binds independently of the trust root's per-issuer floor.
///
/// A fragment for a feed that was never declared is not an error: the runtime push path
/// predates BL-8 and stays open for fragments the base policy did not pre-declare. It
/// simply satisfies nothing.
pub async fn satisfy_declared_fragment(issuer: &str, feed: &str, svn: u64) -> Result<()> {
    let mut pending = PENDING.lock().await;
    let satisfied = satisfy_in(&mut pending, issuer, feed, svn)?;

    if satisfied > 0 {
        info!(
            sl!(),
            "policy-fragments: feed {} satisfied by svn {}; {} declaration(s) still outstanding",
            feed,
            svn,
            pending.len()
        );
    }
    Ok(())
}

/// The cross-check and removal itself, over an explicit requirement list.
///
/// Split out from the global so it can be tested directly: the tests would otherwise race
/// each other through `PENDING`, and a shared-state test that passes only when run alone is
/// worse than no test. Returns how many requirements this delivery satisfied.
fn satisfy_in(
    pending: &mut Vec<FragmentSpec>,
    issuer: &str,
    feed: &str,
    svn: u64,
) -> Result<usize> {
    for spec in pending.iter() {
        if spec.feed != feed {
            continue;
        }
        if spec.issuer != issuer {
            bail!(
                "fragment for declared feed {feed:?} is signed by issuer {issuer:?}, but the measured policy declares issuer {:?}",
                spec.issuer
            );
        }
        if svn < spec.minimum_svn {
            bail!(
                "fragment for declared feed {feed:?} has svn {svn}, below the measured minimum_svn {}",
                spec.minimum_svn
            );
        }
    }

    let before = pending.len();
    pending.retain(|spec| !(spec.feed == feed && spec.issuer == issuer && svn >= spec.minimum_svn));
    Ok(before - pending.len())
}

/// Fail unless every fragment the policy marked `required` has been delivered and verified.
///
/// This is the opt-in fail-closed gate. It exists because delivery is the host's
/// responsibility, so a requirement has to be enforced at the point the sandbox would
/// otherwise start doing work under an incompletely composed policy.
///
/// Declarations without `required: true` are ignored here by design — see the module docs.
/// Their absence is already fail-safe: an undelivered fragment grants nothing, so anything
/// it would have permitted is refused by the composed policy anyway. Blocking on them would
/// make every declaration an availability dependency on the host for no security gain, and
/// would diverge from C-ACI/hcsshim, where fragment injection is lazy and unobligated.
pub async fn assert_all_declared_satisfied() -> Result<()> {
    assert_satisfied_in(&PENDING.lock().await)
}

/// The gate itself, over an explicit declaration list. Split out for the same reason as
/// [`satisfy_in`] — so it can be tested without racing other tests through `PENDING`.
fn assert_satisfied_in(pending: &[FragmentSpec]) -> Result<()> {
    let outstanding: Vec<&FragmentSpec> = pending.iter().filter(|s| s.required).collect();
    if outstanding.is_empty() {
        return Ok(());
    }
    let detail = outstanding
        .iter()
        .map(|s| format!("{} (issuer {}, minimum_svn {})", s.feed, s.issuer, s.minimum_svn))
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "the measured base policy requires {} policy fragment(s) that have not been delivered and verified: {detail}",
        outstanding.len()
    )
}

/// FR-1c: the namespaces a fragment may actually contribute a module to.
///
/// The intersection of what the measured policy granted (`granted`) and what the fragment's
/// signed statement asked for (`requested`). Neither side can widen the other: the grant
/// bounds an issuer that would otherwise be able to claim any namespace, and the request
/// bounds a fragment to what its own author intended, so a mis-scoped grant does not hand a
/// fragment surface it never meant to take.
///
/// An empty result still permits the shared `agent_policy.fragments` package — that is
/// handled by `apply_fragment_module`, which always allows the shared package. The named
/// namespaces are what this gates.
pub fn effective_namespaces(granted: &[String], requested: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|ns| granted.iter().any(|g| g == *ns))
        .cloned()
        .collect()
}

/// BL-8: register the fragment declarations a just-delivered fragment carries in its own
/// signed module.
///
/// Called from `rpc::load_policy_fragment` after the fragment has been verified, injected
/// and committed. `parent_issuer`/`parent_feed` identify the fragment that carried them.
///
/// Delegation is off unless the declaration that authorized the *parent* said otherwise,
/// and even then it is bounded by that declaration's `allow_nested` scope. Everything that
/// does not clear the scope is dropped, loudly, rather than rejected: the parent fragment
/// is already verified and committed at this point, so failing the RPC would leave the
/// engine holding a module the host was told had failed. Dropping is fail-closed anyway —
/// an unregistered declaration authorizes no feed, so the fragment behind it can never be
/// accepted (`UndeclaredFeed`) and grants nothing.
///
/// Delegation cannot widen trust. A nested declaration only says "this feed is expected";
/// the fragment it names must still be signed by an issuer the *measured trust root*
/// authorizes or `verify_cose` rejects it as `UnauthorizedIssuer`, and `min_required()`
/// keeps the issuer-wide SVN floor binding, so a nested declaration can raise the bar but
/// never lower it. What delegation actually buys is composition: an issuer can publish a
/// fragment that pulls in its own dependencies without the base policy having to enumerate
/// them at build time.
///
/// Returns the number of declarations registered.
pub async fn register_nested_fragments(
    parent_issuer: &str,
    parent_feed: &str,
    nested: Vec<FragmentSpec>,
) -> Result<usize> {
    if nested.is_empty() {
        return Ok(0);
    }

    let (scope, depth) = match DELEGATION
        .lock()
        .await
        .get(&(parent_issuer.to_string(), parent_feed.to_string()))
        .cloned()
    {
        Some(entry) => entry,
        None => {
            // The runtime push path: a fragment nobody declared. Nothing granted it
            // delegation, so it has none.
            warn!(
                sl!(),
                "policy-fragments: fragment {} (issuer {}) declares {} nested fragment(s) but was \
                 not itself declared by the measured policy; ignoring them",
                parent_feed,
                parent_issuer,
                nested.len()
            );
            return Ok(0);
        }
    };

    if !scope.is_enabled() {
        warn!(
            sl!(),
            "policy-fragments: fragment {} declares {} nested fragment(s) but its declaration \
             does not set allow_nested; ignoring them",
            parent_feed,
            nested.len()
        );
        return Ok(0);
    }

    if depth + 1 > MAX_NESTING_DEPTH {
        warn!(
            sl!(),
            "policy-fragments: fragment {} is at delegation depth {} and its {} nested \
             declaration(s) would exceed the maximum of {}; ignoring them",
            parent_feed,
            depth,
            nested.len(),
            MAX_NESTING_DEPTH
        );
        return Ok(0);
    }

    let mut store = crate::FRAGMENTS.lock().await;
    let mut delegation = DELEGATION.lock().await;
    let mut pending = PENDING.lock().await;
    let mut registered = 0usize;

    for spec in nested {
        if !scope.permits(parent_issuer, &spec.issuer) {
            warn!(
                sl!(),
                "policy-fragments: fragment {} may not delegate to issuer {} (feed {}); the \
                 allow_nested scope of its declaration does not cover it",
                parent_feed,
                spec.issuer,
                spec.feed
            );
            continue;
        }

        // A declaration already registered stays as it is. Re-registering would reset a
        // cycle's depth counter and could also silently relax an SVN floor that a shallower
        // declaration set.
        let key = (spec.issuer.clone(), spec.feed.clone());
        if delegation.contains_key(&key) {
            info!(
                sl!(),
                "policy-fragments: nested declaration for feed {} (issuer {}) is already \
                 registered; keeping the existing terms",
                spec.feed,
                spec.issuer
            );
            continue;
        }

        let child_scope = match spec.nested_scope() {
            Ok(s) => s,
            Err(e) => {
                // Unlike the boot path this is not fatal: a malformed nested declaration
                // must not take down a sandbox that was running fine. It is dropped whole.
                warn!(
                    sl!(),
                    "policy-fragments: nested declaration for feed {} carried by {} is \
                     malformed and was ignored: {}",
                    spec.feed,
                    parent_feed,
                    e
                );
                continue;
            }
        };

        store.declare_feed(spec.issuer.clone(), spec.feed.clone(), spec.minimum_svn);
        store.grant_module_scope(
            spec.issuer.clone(),
            spec.feed.clone(),
            &spec.includes,
            spec.allow_module,
            spec.parameters.as_ref().map(|p| p.to_string()),
        );
        delegation.insert(key, (child_scope, depth + 1));
        info!(
            sl!(),
            "policy-fragments: fragment {} delegated to feed {} (issuer {}, minimum_svn {}, {}) \
             at depth {}",
            parent_feed,
            spec.feed,
            spec.issuer,
            spec.minimum_svn,
            if spec.required {
                "required"
            } else {
                "optional"
            },
            depth + 1
        );
        pending.push(spec);
        registered += 1;
    }

    Ok(registered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(issuer: &str, feed: &str, minimum_svn: u64) -> FragmentSpec {
        FragmentSpec {
            issuer: issuer.to_string(),
            feed: feed.to_string(),
            minimum_svn,
            required: false,
            ..Default::default()
        }
    }

    /// A declaration the policy marked `required: true` — the only kind that gates
    /// container creation.
    fn req(issuer: &str, feed: &str, minimum_svn: u64) -> FragmentSpec {
        FragmentSpec {
            required: true,
            ..spec(issuer, feed, minimum_svn)
        }
    }

    /// F-62: a fragment may only contribute to namespaces the measured policy granted it.
    /// Without the intersection, any trust-root-authorized issuer could claim any namespace
    /// — including one the base policy intended a different issuer to fill.
    #[test]
    fn a_fragment_cannot_claim_a_namespace_it_was_not_granted() {
        let granted = vec!["infra".to_string(), "net".to_string()];

        // Asking for a subset of the grant: allowed.
        assert_eq!(
            effective_namespaces(&granted, &["infra".to_string()]),
            vec!["infra".to_string()]
        );

        // Asking for something outside the grant: dropped, not silently honoured. This is
        // the squatting case — `secrets` belongs to somebody else.
        assert!(effective_namespaces(&granted, &["secrets".to_string()]).is_empty());

        // A mix keeps only the granted part.
        assert_eq!(
            effective_namespaces(&granted, &["net".to_string(), "secrets".to_string()]),
            vec!["net".to_string()]
        );
    }

    /// F-62: the grant cannot widen the fragment either. A policy that over-grants does not
    /// hand a fragment surface its own signed statement never asked for.
    #[test]
    fn a_grant_cannot_widen_what_the_fragment_asked_for() {
        let granted = vec!["infra".to_string(), "net".to_string(), "secrets".to_string()];
        assert_eq!(
            effective_namespaces(&granted, &["infra".to_string()]),
            vec!["infra".to_string()]
        );
        // Nothing requested → nothing named granted, regardless of how broad the grant is.
        assert!(effective_namespaces(&granted, &[]).is_empty());
    }

    /// F-62: no grant means no *named* namespaces. The shared `agent_policy.fragments`
    /// package stays available (enforced in `apply_fragment_module`), so a fragment that
    /// predates the grant keeps working; what it loses is the ability to self-assign a
    /// named namespace.
    #[test]
    fn an_ungranted_feed_gets_no_named_namespaces() {
        assert!(effective_namespaces(&[], &["infra".to_string()]).is_empty());
    }

    #[test]
    fn no_declarations_is_satisfied() {
        assert!(assert_satisfied_in(&[]).is_ok());
    }

    #[test]
    fn outstanding_declaration_blocks_until_delivered() {
        let mut pending = vec![req("did:x509:i", "reg.io/frag:1", 2)];
        let err = assert_satisfied_in(&pending).unwrap_err().to_string();
        assert!(err.contains("reg.io/frag:1"), "unhelpful error: {}", err);

        // A matching delivery clears it, and only then may containers start.
        assert_eq!(satisfy_in(&mut pending, "did:x509:i", "reg.io/frag:1", 2).unwrap(), 1);
        assert!(assert_satisfied_in(&pending).is_ok());
    }

    /// The enforcement is opt-in: a declaration the policy did not mark `required` states
    /// the terms a fragment must meet, but never blocks on its absence. This is C-ACI
    /// parity — an undelivered fragment simply contributes no grants.
    #[test]
    fn optional_declaration_does_not_block() {
        let pending = vec![spec("did:x509:i", "reg.io/frag:1", 2)];
        assert!(
            assert_satisfied_in(&pending).is_ok(),
            "an undelivered optional fragment must not gate container creation"
        );
    }

    /// Mixed policies are the point of a per-declaration flag: one mandatory baseline
    /// alongside optional add-ons. Only the mandatory one holds the gate, and the error
    /// names it rather than the optional ones.
    #[test]
    fn only_required_declarations_hold_the_gate() {
        let mut pending = vec![
            spec("did:x509:i", "reg.io/optional:1", 1),
            req("did:x509:i", "reg.io/mandatory:1", 1),
        ];
        let err = assert_satisfied_in(&pending).unwrap_err().to_string();
        assert!(err.contains("reg.io/mandatory:1"), "unhelpful error: {}", err);
        assert!(
            !err.contains("reg.io/optional:1"),
            "an optional declaration must not be reported as outstanding: {}",
            err
        );

        // Delivering only the required one opens the gate, even though the optional
        // declaration is still outstanding.
        satisfy_in(&mut pending, "did:x509:i", "reg.io/mandatory:1", 1).unwrap();
        assert!(assert_satisfied_in(&pending).is_ok());
        assert_eq!(pending.len(), 1, "the optional declaration is still tracked");
    }

    /// `required: false` is not `unchecked`. An optional fragment that is actually
    /// delivered must meet its declared terms exactly as a required one does.
    #[test]
    fn optional_declarations_are_still_cross_checked_on_delivery() {
        let mut pending = vec![spec("did:x509:good", "reg.io/frag:1", 5)];
        assert!(
            satisfy_in(&mut pending, "did:x509:evil", "reg.io/frag:1", 9).is_err(),
            "wrong issuer must be rejected even for an optional declaration"
        );
        assert!(
            satisfy_in(&mut pending, "did:x509:good", "reg.io/frag:1", 4).is_err(),
            "svn below the measured floor must be rejected even for an optional declaration"
        );
    }

    #[test]
    fn higher_svn_satisfies_the_floor() {
        let mut pending = vec![spec("did:x509:i", "reg.io/frag:1", 2)];
        satisfy_in(&mut pending, "did:x509:i", "reg.io/frag:1", 7).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn svn_below_the_measured_floor_is_rejected_and_does_not_satisfy() {
        let mut pending = vec![req("did:x509:i", "reg.io/frag:1", 5)];
        assert!(satisfy_in(&mut pending, "did:x509:i", "reg.io/frag:1", 4).is_err());
        // Still outstanding: a rejected delivery must not clear the requirement.
        assert_eq!(pending.len(), 1);
        assert!(assert_satisfied_in(&pending).is_err());
    }

    #[test]
    fn wrong_issuer_for_a_declared_feed_is_rejected() {
        let mut pending = vec![spec("did:x509:good", "reg.io/frag:1", 1)];
        assert!(satisfy_in(&mut pending, "did:x509:evil", "reg.io/frag:1", 9).is_err());
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn undeclared_feed_satisfies_nothing_but_is_allowed() {
        let mut pending = vec![spec("did:x509:i", "reg.io/frag:1", 1)];
        assert_eq!(
            satisfy_in(&mut pending, "did:x509:other", "reg.io/other:1", 3).unwrap(),
            0
        );
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn each_declaration_must_be_satisfied_individually() {
        let mut pending = vec![
            req("did:x509:i", "reg.io/a:1", 1),
            req("did:x509:i", "reg.io/b:1", 1),
        ];
        satisfy_in(&mut pending, "did:x509:i", "reg.io/a:1", 1).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(assert_satisfied_in(&pending).is_err());
    }
}