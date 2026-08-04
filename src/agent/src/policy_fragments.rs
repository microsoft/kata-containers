// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0
//

//! BL-8 — the measured base policy's declared policy-fragment requirements.
//!
//! The measured base policy may declare `data.agent_policy.policy_fragments[]` entries —
//! each naming an `issuer` (`did:x509`), a `feed` (OCI reference), and a `minimum_svn`.
//! A declaration is a *requirement*: the sandbox must not run containers until every
//! declared fragment has been delivered and verified.
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
//! Moving the fetch out means the host now chooses *when* — and whether — to deliver. So
//! the declaration is recorded at boot as an outstanding requirement and container
//! creation is refused while any requirement is unsatisfied (see
//! `assert_all_declared_satisfied`). A host that pushes nothing, pushes late, or pushes a
//! fragment for the wrong feed cannot get a container started. That is the fail-closed
//! guarantee the boot-time abort used to provide, enforced at the point where it is
//! actually observable.
//!
//! Verification itself is unchanged and still happens entirely in the guest, through the
//! same SRM `FragmentStore` as before, so FR-1d (did:x509), FR-1f (receipts), FR-1i
//! (rollback floor) and FR-1j (ordering) continue to apply.

use anyhow::{bail, Result};
use slog::info;
use tokio::sync::Mutex;

use crate::AGENT_POLICY;

pub use kata_agent_policy::policy::FragmentSpec;

macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

lazy_static! {
    /// Fragment requirements declared by the measured base policy that have not yet been
    /// satisfied by a verified delivery. Emptied entry by entry as fragments arrive.
    static ref PENDING: Mutex<Vec<FragmentSpec>> = Mutex::new(Vec::new());
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
            "policy-fragments: awaiting delivery of feed {} (issuer {}, minimum_svn {})",
            spec.feed,
            spec.issuer,
            spec.minimum_svn
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
    {
        let mut store = crate::FRAGMENTS.lock().await;
        for spec in &specs {
            store.declare_feed(spec.issuer.clone(), spec.feed.clone(), spec.minimum_svn);
        }
    }

    let n = specs.len();
    *PENDING.lock().await = specs;
    info!(
        sl!(),
        "policy-fragments: {} declared fragment(s) outstanding; containers are blocked until each is delivered and verified",
        n
    );
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

/// Fail unless every declared fragment has been delivered and verified.
///
/// This is the fail-closed gate. It replaces the boot-time `abort()`: because delivery is
/// now the host's responsibility, the requirement has to be enforced at the point the
/// sandbox would otherwise start doing work under an incompletely composed policy.
pub async fn assert_all_declared_satisfied() -> Result<()> {
    assert_satisfied_in(&PENDING.lock().await)
}

/// The gate itself, over an explicit requirement list. Split out for the same reason as
/// [`satisfy_in`] — so it can be tested without racing other tests through `PENDING`.
fn assert_satisfied_in(pending: &[FragmentSpec]) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let outstanding = pending
        .iter()
        .map(|s| format!("{} (issuer {}, minimum_svn {})", s.feed, s.issuer, s.minimum_svn))
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "the measured base policy declares {} policy fragment(s) that have not been delivered and verified: {outstanding}",
        pending.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(issuer: &str, feed: &str, minimum_svn: u64) -> FragmentSpec {
        FragmentSpec {
            issuer: issuer.to_string(),
            feed: feed.to_string(),
            minimum_svn,
        }
    }

    #[test]
    fn no_declarations_is_satisfied() {
        assert!(assert_satisfied_in(&[]).is_ok());
    }

    #[test]
    fn outstanding_declaration_blocks_until_delivered() {
        let mut pending = vec![spec("did:x509:i", "reg.io/frag:1", 2)];
        let err = assert_satisfied_in(&pending).unwrap_err().to_string();
        assert!(err.contains("reg.io/frag:1"), "unhelpful error: {}", err);

        // A matching delivery clears it, and only then may containers start.
        assert_eq!(satisfy_in(&mut pending, "did:x509:i", "reg.io/frag:1", 2).unwrap(), 1);
        assert!(assert_satisfied_in(&pending).is_ok());
    }

    #[test]
    fn higher_svn_satisfies_the_floor() {
        let mut pending = vec![spec("did:x509:i", "reg.io/frag:1", 2)];
        satisfy_in(&mut pending, "did:x509:i", "reg.io/frag:1", 7).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn svn_below_the_measured_floor_is_rejected_and_does_not_satisfy() {
        let mut pending = vec![spec("did:x509:i", "reg.io/frag:1", 5)];
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
            spec("did:x509:i", "reg.io/a:1", 1),
            spec("did:x509:i", "reg.io/b:1", 1),
        ];
        satisfy_in(&mut pending, "did:x509:i", "reg.io/a:1", 1).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(assert_satisfied_in(&pending).is_err());
    }
}