// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-1 — signed, add-only policy fragments.
//!
//! A base policy may be extended at runtime by *fragments* that grant additional,
//! narrowly-scoped capabilities (e.g. permitting a new container/process declaration).
//! To keep this safe, fragments are:
//!
//!  - **Signed** by an authorized issuer (Ed25519 over a canonical encoding); an unsigned
//!    or tampered fragment, or one from an unknown/unauthorized issuer, is rejected.
//!  - **Monotonic** per issuer: each accepted fragment must carry a strictly increasing
//!    security version number (SVN); a replayed or rolled-back SVN is rejected.
//!  - **Add-only and fail-closed**: a fragment may only *add* policy surface, and only
//!    within what measured state already permits it to contribute. The scope comes from the
//!    base policy's declaration for the `(issuer, feed)` — see [`ModuleScope`] — and is
//!    intersected with the fragment's own request, so a fragment can never widen its own
//!    reach; one that tries is rejected outright rather than partially applied.
//!  - **Transparency-backed** (optional, enabled in strict mode): a fragment must carry a
//!    transparency receipt so its issuance is auditable. (The receipt's cryptographic
//!    verification against a transparency service is a separate, environment-specific
//!    step; here its presence is required and its identifier is bound into the signature.)
//!
//! Verification is performed with a maintained pure-Rust Ed25519 verifier; no Go
//! dependency is introduced into the agent.

use crate::cose_keys::{CoseAlg, PublicKey};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// The ledger id used for a receipt that does not name one, and for the back-compat
/// single-anchor configuration (`set_transparency_anchor`).
pub const DEFAULT_LEDGER: &str = "default";

/// A policy fragment presented for loading.
#[derive(Debug, Clone, Default)]
pub struct PolicyFragment {
    /// Identifier of the issuer that signed the fragment.
    pub issuer: String,
    /// FR-1e: the logical feed (scope) under the issuer. The base policy declares which
    /// `(issuer, feed)` pairs it accepts and their SVN floor. Empty = the default feed.
    pub feed: String,
    /// Security version number; must strictly increase per `(issuer, feed)`.
    pub svn: u64,
    /// FR-1c: a signed Rego module (text) the fragment contributes to the policy engine
    /// (Model A). Must declare a package under the reserved fragment namespace.
    pub policy_module: Option<String>,
    /// FR-1c: the policy namespaces this fragment is scoped to contribute to. The applier
    /// refuses a module whose package is outside these.
    pub includes: Vec<String>,
    /// FR-1g: identifiers of fragments that must already be loaded before this one
    /// (composition). A fragment id is `"<issuer>/<feed>/<svn>"`.
    pub requires: Vec<String>,
    /// FR-1f: transparency receipt — a detached signature (hex) by a transparency ledger
    /// key over [`PolicyFragment::signed_bytes`]. Required when receipts are enforced;
    /// verified against a measured trust list when one is configured.
    pub receipt: Option<String>,
    /// FR-1f (trust list): the transparency ledger this receipt is claimed to originate
    /// from. Selects which ledger's key(s) the receipt is verified against and is subject to
    /// `allowed_ledgers`/`required_receipt_from` scoping. `None`/empty = the default ledger
    /// (back-compat with a single-anchor configuration). This is *untrusted* metadata: it
    /// only selects a key set; a receipt is accepted only if that ledger's key actually
    /// signed the statement, so a forged ledger id cannot bypass verification.
    ///
    /// F-167: on the Stage-1 and native Stage-2 paths that holds unconditionally, because
    /// the signed bytes are either the statement itself or `sth_signing_bytes(ledger, ..)`,
    /// which names the ledger. A CCF Stage-2 receipt signs only the bare Merkle root and so
    /// carries no ledger name of its own; that path additionally refuses a receipt that
    /// validates under more than one configured ledger (`FragmentStore::ledger_ambiguity`).
    pub receipt_ledger: Option<String>,
    /// FR-1j: the append-only log head this fragment asserts it is applied on top of.
    /// Carried in the **protected** header (`kata-prev-log-head`), so the issuer signs it
    /// and a host/orchestrator cannot forge an ordering. In ordered mode the store requires
    /// this to equal its current log head; on success the head advances by hashing this
    /// fragment in. `None` = not part of an ordered log (back-compat / opt-in).
    pub prev_log_head: Option<Vec<u8>>,
    /// FR-1f Stage 2: an optional transparency **inclusion + consistency** proof anchoring
    /// this fragment in an append-only transparency log (SCITT/CT). Text-encoded
    /// (`kata-ttl-proof/v1`): a signed tree head (size, root, ledger signature), the
    /// inclusion proof of this fragment's signed bytes, and an optional consistency proof
    /// from the previously-seen tree head. Verified against the transparency trust list;
    /// proves the fragment is recorded in — and the log has only grown since the last —
    /// tree head.
    pub receipt_proof: Option<String>,
    /// FR-1f (trust list): additional Stage-1 countersignatures, as `(ledger, signature)`
    /// pairs, each a detached signature over [`PolicyFragment::signed_bytes`].
    ///
    /// A scope's requirement list is a conjunction, so "countersigned by the vendor *and*
    /// logged publicly" needs more than one receipt to be satisfiable at all. Like the
    /// primary `receipt`, these are carried alongside the envelope rather than inside it —
    /// a receipt is a countersignature *over* the signed bytes and so cannot be one of them.
    pub extra_receipts: Vec<(String, String)>,
    /// The COSE `Sig_structure` (`Signature1`) these fields were parsed from: the exact
    /// bytes the issuer signed, and the bytes every receipt countersigns and the FR-1j
    /// ordering log chains.
    ///
    /// This is the fragment's identity. It is populated by
    /// [`from_cose_envelope`](Self::from_cose_envelope) and is empty for a
    /// hand-constructed fragment, which is why verification only ever happens through
    /// [`FragmentStore::verify_envelope`] — there is no way to present fields without the
    /// envelope that authenticates them.
    ///
    /// Using the `Sig_structure` rather than the whole COSE_Sign1 is deliberate. It is
    /// canonical *by construction* — the signer had to serialize exactly these bytes in
    /// order to sign at all — whereas the envelope additionally carries the signature and
    /// the unprotected header, neither of which is covered by the signature. Hashing the
    /// envelope would let a malleable signature encoding or an added unprotected header
    /// produce two different identities for one signed fragment, which would break the
    /// ordering log's "same fragment, same entry" property.
    pub tbs: Vec<u8>,
}

/// COSE content type (protected header label 3) of a signed policy fragment.
///
/// This is hcsshim's constant verbatim (`mediaTypeFragment` in
/// `pkg/securitypolicy/securitypolicy_options.go`). It is meaningful only because the
/// payload really is Rego: a media type is a parsing contract, and a consumer that trusts
/// the tag must get what the tag promises.
pub const FRAGMENT_CONTENT_TYPE: &str = "application/cose-x509+rego";

/// COSE protected header label 15 — CWT Claims (RFC 8392 / SCITT).
const HDR_CWT_CLAIMS: i64 = 15;
/// CWT claim 1 — issuer.
const CWT_ISSUER: i64 = 1;
/// CWT claim 2 — subject. hcsshim carries the *feed* here.
const CWT_SUBJECT: i64 = 2;
/// CWT claim key for the security version number. A string key, matching hcsshim's
/// `cwtClaims["svn"]` lookup — it is not a registered IANA claim.
const CWT_SVN: &str = "svn";

/// Protected header string keys for issuer and feed, as written by `sign1util create`
/// (`cosesign1go`'s `CreateCoseSign1` sets `headers.Protected["iss"]` / `["feed"]`).
/// Accepted as an alternative to the CWT claims form, exactly as hcsshim accepts both.
const HDR_ISS: &str = "iss";
const HDR_FEED: &str = "feed";

/// Kata-private protected header labels, for the requirements that have no hcsshim
/// counterpart. They are namespaced so they can never collide with a registered COSE label
/// or with anything C-ACI adds later, and they are **optional**: an envelope produced by
/// stock C-ACI tooling carries none of them and is still accepted.
///
/// They live in the *protected* header because every one of them is authority-relevant —
/// a dropped `requires` entry removes a dependency gate and a forged `kata-prev-log-head`
/// forges an ordering — so they must be inside what the issuer signed. This is the one
/// place kata deliberately diverges from hcsshim's placement choices: hcsshim puts receipts
/// in the *unprotected* header (label 394), where any intermediary can strip them.
const HDR_KATA_INCLUDES: &str = "kata-includes";
const HDR_KATA_REQUIRES: &str = "kata-requires";
const HDR_KATA_PREV_LOG_HEAD: &str = "kata-prev-log-head";

impl PolicyFragment {
    /// This fragment's composition identifier: `"<issuer>/<feed>/<svn>"`, with `/` and `%`
    /// percent-encoded in the issuer and feed. See [`make_id`](Self::make_id).
    pub fn id(&self) -> String {
        Self::make_id(&self.issuer, &self.feed, self.svn)
    }

    /// Build the composition identifier for an `(issuer, feed, svn)` triple — the value a
    /// dependent fragment puts in its `requires` list.
    ///
    /// F-145: the separator is escaped in the components rather than banned from them,
    /// because it cannot be banned: an issuer is a `did:x509` and a feed is an OCI
    /// reference, and both legitimately contain `/`. A plain join is therefore not
    /// injective — `(issuer "a/b", feed "c")` and `(issuer "a", feed "b/c")` produce the
    /// same id, so a fragment requiring one would be satisfied by the other. Escaping makes
    /// the two ids distinct (`a%2Fb/c/1` vs `a/b%2Fc/1`) while keeping the id a single
    /// readable string, so neither the statement format nor the `repeated string requires`
    /// wire type has to change. `%` is escaped first, so the encoding is reversible and no
    /// literal `%2F` in an issuer can impersonate a separator.
    ///
    /// A hand-written, unescaped requires entry simply matches nothing and fails closed as
    /// an unsatisfied requirement, so this cannot silently weaken a dependency.
    pub fn make_id(issuer: &str, feed: &str, svn: u64) -> String {
        fn esc(s: &str) -> String {
            s.replace('%', "%25").replace('/', "%2F")
        }
        format!("{}/{}/{}", esc(issuer), esc(feed), svn)
    }

    /// Build the COSE **protected header** that carries this fragment's metadata.
    ///
    /// This is the single definition of the fragment header format, used by the verifier's
    /// [`from_cose_envelope`](Self::from_cose_envelope) as its inverse and by every signer
    /// in-tree. Keeping one definition for both directions is the point: the previous format
    /// had an encoder and a decoder that had to be kept in agreement by hand, and the
    /// F-144/F-145 family all lived in that gap.
    ///
    /// Layout (see the constants above for provenance):
    ///
    /// | label | value |
    /// | --- | --- |
    /// | 3 (content type) | `application/cose-x509+rego` |
    /// | 15 (CWT claims) | `{1: issuer, 2: feed, "svn": svn}` |
    /// | `kata-includes` / `kata-requires` | arrays, omitted when empty |
    /// | `kata-prev-log-head` | byte string, omitted when absent |
    ///
    /// The caller supplies the algorithm and any `x5chain`, since those belong to the
    /// signing key rather than to the fragment.
    pub fn protected_header(&self) -> coset::Header {
        use ciborium::value::Value;
        use coset::{ContentType, Label};

        let mut rest: Vec<(Label, Value)> = Vec::new();

        // Issuer, feed and SVN go in the CWT claims map (protected label 15), which is the
        // form hcsshim prefers on read. The plain `iss`/`feed` string keys that
        // `sign1util create` writes are *accepted* by the parser but not emitted, because
        // there is nowhere in that older form to put the SVN.
        rest.push((
            Label::Int(HDR_CWT_CLAIMS),
            Value::Map(vec![
                (Value::Integer(CWT_ISSUER.into()), Value::Text(self.issuer.clone())),
                (Value::Integer(CWT_SUBJECT.into()), Value::Text(self.feed.clone())),
                (Value::Text(CWT_SVN.to_string()), Value::Integer(self.svn.into())),
            ]),
        ));

        // Sorted so that re-signing identical inputs produces identical bytes. Order is not
        // security-relevant — the signature covers whatever bytes were produced — but a
        // stable encoding makes fragments reproducible and diffable.
        let mut texts = |key: &str, v: &[String]| {
            if !v.is_empty() {
                let mut v = v.to_vec();
                v.sort();
                rest.push((
                    Label::Text(key.to_string()),
                    Value::Array(v.into_iter().map(Value::Text).collect()),
                ));
            }
        };
        texts(HDR_KATA_INCLUDES, &self.includes);
        texts(HDR_KATA_REQUIRES, &self.requires);

        if let Some(h) = &self.prev_log_head {
            rest.push((
                Label::Text(HDR_KATA_PREV_LOG_HEAD.to_string()),
                Value::Bytes(h.clone()),
            ));
        }

        coset::Header {
            content_type: Some(ContentType::Text(FRAGMENT_CONTENT_TYPE.to_string())),
            rest,
            ..Default::default()
        }
    }

    /// Build the unsigned COSE_Sign1 an issuer signs to produce this fragment: the protected
    /// header from [`protected_header`](Self::protected_header), the Rego module as payload,
    /// and no signature yet.
    ///
    /// This is the single definition of how a fragment becomes bytes, so the signer, the
    /// demo, the tests and any future tooling cannot drift from what the guest verifies. It
    /// also yields the bytes a receipt countersigns — `tbs_data` does not depend on the
    /// signature, so a transparency ledger can compute its Merkle leaf without the issuer
    /// key:
    ///
    /// ```ignore
    /// let leaf = fragment.to_unsigned_cose(alg).tbs_data(b"");
    /// ```
    pub fn to_unsigned_cose(&self, alg: coset::iana::Algorithm) -> coset::CoseSign1 {
        let mut hdr = self.protected_header();
        hdr.alg = Some(coset::Algorithm::Assigned(alg));
        let mut b = coset::CoseSign1Builder::new().protected(hdr);
        if let Some(m) = &self.policy_module {
            b = b.payload(m.clone().into_bytes());
        }
        b.build()
    }

    /// Parse a fragment out of a COSE_Sign1 envelope. This is the **only** way a
    /// `PolicyFragment` that can be verified comes into being.
    ///
    /// # Why the envelope is the format
    ///
    /// The fragment used to be described by a bespoke `kata-policy-fragment/vN` statement
    /// carried *as* the COSE payload. That statement existed for one reason: the load path
    /// once accepted a fragment with a **detached** signature and no envelope, and a
    /// detached signature needs some byte string to sign. Once that path was closed
    /// (F-151), the statement was serving nothing, while costing a hand-rolled canonical
    /// encoding whose ambiguities produced F-144, F-145 and F-146 in turn.
    ///
    /// This format is C-ACI/hcsshim's instead: the payload **is** the Rego module, and the
    /// metadata lives in the protected header. That is not merely tidier — it means a
    /// fragment produced by an existing C-ACI signing pipeline is one this guest can
    /// verify, and the OCI media type `application/cose-x509+rego` finally describes the
    /// bytes it labels (F-150).
    ///
    /// # What authenticates what
    ///
    /// Everything read here comes from the *protected* header or the payload, both of which
    /// are inside the COSE `Sig_structure` and therefore covered by the issuer's signature.
    /// Nothing is read from the unprotected header, which any intermediary can rewrite. The
    /// resulting [`tbs`](Self::tbs) is that `Sig_structure`, and it is what the signature,
    /// every receipt, and the FR-1j ordering log all bind to.
    ///
    /// Parsing does not authenticate: the signature is checked by
    /// [`FragmentStore::verify_envelope`], which is the only caller that matters.
    pub fn from_cose_envelope(cose_sign1: &[u8]) -> Result<Self, FragmentError> {
        use ciborium::value::Value;
        use coset::{CborSerializable, ContentType, Label};
        use std::convert::TryFrom;

        let bad = |reason: &str| FragmentError::MalformedEnvelope {
            reason: reason.to_string(),
        };

        let sign1 = coset::CoseSign1::from_slice(cose_sign1)
            .map_err(|_| bad("is not a well-formed COSE_Sign1"))?;
        let hdr = &sign1.protected.header;

        // `crit` names headers the signer requires the verifier to understand. This one
        // understands none that a fragment could carry, so an entry is refused rather than
        // ignored — ignoring it is exactly what `crit` exists to forbid.
        if !hdr.crit.is_empty() {
            return Err(bad(
                "marks protected headers critical, which this verifier does not implement",
            ));
        }

        // The content type is a parsing contract. Checking it here means a blob signed for
        // some other purpose by an authorized issuer — a trust list, a TCB reference — can
        // never be replayed as a policy fragment merely because the same key signed it.
        match &hdr.content_type {
            Some(ContentType::Text(t)) if t == FRAGMENT_CONTENT_TYPE => {}
            _ => {
                return Err(bad(
                    "does not declare content type application/cose-x509+rego",
                ))
            }
        }

        // A duplicate label is refused rather than resolved. CBOR maps admit duplicates and
        // decoders disagree about which one wins, so tolerating them would mean two
        // verifiers could read one signed envelope differently — the same class of defect
        // as F-144, arriving by a different route.
        for (i, (label, _)) in hdr.rest.iter().enumerate() {
            if hdr.rest[..i].iter().any(|(prev, _)| prev == label) {
                return Err(bad("carries a duplicate protected header label"));
            }
        }

        let by_text = |key: &str| -> Option<&Value> {
            hdr.rest
                .iter()
                .find(|(l, _)| matches!(l, Label::Text(t) if t == key))
                .map(|(_, v)| v)
        };
        let by_int = |key: i64| -> Option<&Value> {
            hdr.rest
                .iter()
                .find(|(l, _)| matches!(l, Label::Int(i) if *i == key))
                .map(|(_, v)| v)
        };
        fn as_text(v: &Value) -> Option<&String> {
            match v {
                Value::Text(s) => Some(s),
                _ => None,
            }
        }

        // CWT claims (label 15) are the SCITT-style form and the only one with a home for
        // the SVN. The plain `iss`/`feed` string keys are what `sign1util create` writes,
        // and hcsshim accepts either, so this does too.
        let cwt = match by_int(HDR_CWT_CLAIMS) {
            Some(Value::Map(m)) => Some(m),
            Some(_) => return Err(bad("carries a CWT claims header that is not a map")),
            None => None,
        };
        let cwt_claim = |k: Value| -> Option<&Value> {
            cwt.and_then(|m| m.iter().find(|(key, _)| *key == k).map(|(_, v)| v))
        };

        // When both forms are present they must agree. hcsshim simply prefers the CWT; this
        // refuses the disagreement, because an envelope that says two different things about
        // who signed it has no single correct reading and a verifier picking one silently is
        // how a signer's intent and a verifier's belief come apart.
        let pick = |field: &str, cwt_val: Option<&Value>, hdr_val: Option<&Value>| {
            let c = cwt_val.and_then(as_text);
            let h = hdr_val.and_then(as_text);
            match (c, h) {
                (Some(a), Some(b)) if a != b => Err(FragmentError::MalformedEnvelope {
                    reason: format!(
                        "declares two different values for {} (CWT claim vs. protected header)",
                        field
                    ),
                }),
                (Some(a), _) | (None, Some(a)) => Ok(Some(a.clone())),
                (None, None) => Ok(None),
            }
        };

        let issuer = pick(
            "the issuer",
            cwt_claim(Value::Integer(CWT_ISSUER.into())),
            by_text(HDR_ISS),
        )?
        .ok_or_else(|| bad("does not name an issuer"))?;

        // An absent feed is the default feed, which is a real configuration and not an
        // omission — the base policy declares `(issuer, "")` for it.
        let feed = pick(
            "the feed",
            cwt_claim(Value::Integer(CWT_SUBJECT.into())),
            by_text(HDR_FEED),
        )?
        .unwrap_or_default();

        // The SVN has no default. Defaulting it to zero would silently disarm rollback
        // protection for any fragment that forgot to set one, which is the opposite of what
        // an anti-rollback control should do when it is unsure.
        let svn = match cwt_claim(Value::Text(CWT_SVN.to_string())) {
            Some(Value::Integer(i)) => u64::try_from(*i)
                .map_err(|_| bad("declares an svn claim that is not a non-negative integer"))?,
            Some(_) => return Err(bad("declares an svn claim that is not an integer")),
            None => {
                return Err(bad(
                    "carries no svn claim, and a fragment without a security version cannot be \
                     checked for rollback",
                ))
            }
        };

        let texts = |key: &str| -> Result<Vec<String>, FragmentError> {
            match by_text(key) {
                None => Ok(Vec::new()),
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|v| {
                        as_text(v).cloned().ok_or_else(|| FragmentError::MalformedEnvelope {
                            reason: format!("has a non-string entry in {}", key),
                        })
                    })
                    .collect(),
                Some(_) => Err(FragmentError::MalformedEnvelope {
                    reason: format!("has a {} header that is not an array", key),
                }),
            }
        };
        let includes = texts(HDR_KATA_INCLUDES)?;
        let requires = texts(HDR_KATA_REQUIRES)?;

        let prev_log_head = match by_text(HDR_KATA_PREV_LOG_HEAD) {
            None => None,
            Some(Value::Bytes(b)) => Some(b.clone()),
            Some(_) => return Err(bad("has a kata-prev-log-head header that is not a byte string")),
        };

        // The payload is the Rego module. Absent (a detached payload) means the fragment
        // contributes no rules — it is being applied for its SVN, receipt or ordering record
        // alone, which is hcsshim's `add_module: false` case.
        let policy_module = match &sign1.payload {
            None => None,
            Some(p) => Some(
                String::from_utf8(p.clone())
                    .map_err(|_| bad("carries a payload that is not valid UTF-8 Rego"))?,
            ),
        };

        Ok(PolicyFragment {
            issuer,
            feed,
            svn,
            policy_module,
            includes,
            requires,
            receipt: None,
            receipt_ledger: None,
            prev_log_head,
            receipt_proof: None,
            extra_receipts: Vec::new(),
            tbs: sign1.tbs_data(b""),
        })
    }

    /// Reject fields that would be unsafe *downstream* of the statement encoding.
    ///
    /// # What this gate is, and is no longer, for
    ///
    /// Under v3 this gate carried the whole injectivity argument: the statement was a
    /// newline-delimited text format that escaped nothing, so it was injective only over
    /// the domain enforced here, and without it distinct fragments shared signing bytes
    /// (F-144). **v4 encodes the statement as CBOR** — every field length-prefixed and
    /// typed — so the encoding is now injective by construction and this gate is *not* what
    /// makes a signature commit to one reading. The delimiter-substring check went away with
    /// the delimiters.
    ///
    /// What remains is real, but it is about two *other* consumers that are still textual:
    ///
    /// - **The audit log (F-146).** [`export_fragment_log`](FragmentStore::export_fragment_log)
    ///   renders `index\tfragment-id\tstatement-sha256` per committed fragment. An issuer
    ///   containing a tab produces a four-field line, and an auditor's parser reads a
    ///   different id and digest than were committed — forging the record that is meant to
    ///   be the non-repudiable proof of what was applied. A newline forges a whole extra
    ///   record. The rest of the control range is banned on the same principle rather than
    ///   case by case, and because a control character in a `did:x509` or an OCI reference
    ///   is meaningless in the first place.
    /// - **The composition id.** [`make_id`](Self::make_id) escapes `/` and `%` but renders
    ///   the components verbatim otherwise, and that id is what a dependent names in
    ///   `requires` and what appears in the log.
    ///
    /// An empty list entry is refused because it is never meaningful: an empty `includes`
    /// entry names no namespace and an empty `requires` entry matches no id, so it is far
    /// more likely to be a bug in the signer than an intent. That is no longer an
    /// *ambiguity* — CBOR round-trips an empty string faithfully — so it is a hygiene
    /// check, and is documented as one.
    ///
    /// `policy_module` is deliberately not constrained: arbitrary Rego has to be
    /// expressible, and CBOR carries it whatever it contains. An empty-but-present module is
    /// still refused because it is a no-op no signer intends.
    pub fn validate_statement(&self) -> Result<(), FragmentError> {
        fn check(field: &str, value: &str) -> Result<(), FragmentError> {
            let bad = |reason: &str| FragmentError::MalformedStatement {
                field: field.to_string(),
                reason: reason.to_string(),
            };
            if let Some(c) = value.chars().find(|c| c.is_control()) {
                return Err(bad(&format!("contains the control character {:?}", c)));
            }
            Ok(())
        }
        fn check_entry(field: &str, value: &str) -> Result<(), FragmentError> {
            if value.is_empty() {
                return Err(FragmentError::MalformedStatement {
                    field: field.to_string(),
                    reason: "is empty, and an empty entry is never meaningful".to_string(),
                });
            }
            check(field, value)
        }

        check("issuer", &self.issuer)?;
        check("feed", &self.feed)?;
        for i in &self.includes {
            check_entry("includes", i)?;
        }
        for r in &self.requires {
            check_entry("requires", r)?;
        }
        if self.policy_module.as_deref() == Some("") {
            return Err(FragmentError::MalformedStatement {
                field: "policy_module".to_string(),
                reason: "is present but empty, which is indistinguishable from absent"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// The exact bytes the issuer signed: the COSE `Sig_structure` this fragment was
    /// parsed from.
    ///
    /// This is the fragment's identity for every downstream purpose — the transparency
    /// receipt countersigns it, the FR-1j ordering log chains it, and the audit log records
    /// its digest. Empty for a hand-constructed fragment that never came from an envelope,
    /// which is why such a fragment cannot be verified.
    ///
    /// It replaces the former `signing_bytes()`, which built a bespoke canonical encoding of
    /// the fields. There is nothing left to encode: the signer had to produce these bytes in
    /// order to sign at all, so they are canonical by construction rather than by a
    /// re-encoding check.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.tbs
    }
}

/// A fragment that has passed every verification gate but has not yet been committed to the
/// store. Returned by [`FragmentStore::verify`] so the caller can apply it to the policy
/// engine and only then [`FragmentStore::commit`] it — keeping verify+apply atomic.
#[derive(Debug, Clone)]
pub struct VerifiedFragment {
    pub issuer: String,
    pub feed: String,
    pub svn: u64,
    pub id: String,
    pub policy_module: Option<String>,
    pub includes: Vec<String>,
    /// FR-1j: SHA-256 of the fragment statement, used to advance the ordering log head on
    /// commit (so the head binds the exact applied sequence).
    pub stmt_sha256: [u8; 32],
    /// FR-1f Stage 2: the verified transparency tree head `(ledger, size, root)` this
    /// fragment advanced to, applied (raise-only) on commit. `None` when no proof was given.
    pub ttl_head: Option<(String, u64, [u8; 32])>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FragmentError {
    /// The fragment's issuer is not in the authorized-issuer set.
    UnauthorizedIssuer(String),
    /// The signature is malformed, or does not verify under the issuer's key (covers the
    /// unsigned case: an empty/garbage signature).
    InvalidSignature,
    /// The SVN is not strictly greater than the last accepted SVN for this issuer.
    RolledBackSvn {
        issuer: String,
        presented: u64,
        min_required: u64,
    },
    /// Receipts are enforced but the fragment carries none.
    MissingReceipt,
    /// FR-1f: the transparency receipt does not verify against the configured trust list.
    InvalidReceipt,
    /// FR-1f (trust list): the receipt's ledger is not in the `allowed_ledgers` scope for
    /// this `(issuer, feed)`.
    LedgerNotAllowed {
        issuer: String,
        feed: String,
        ledger: String,
    },
    /// FR-1f (trust list): a receipt is required from a specific ledger for this scope, but
    /// the presented receipt originates from a different (or unspecified) ledger.
    ReceiptFromDisallowedLedger { required: String, presented: String },
    /// FR-1f (trust list): a scope requirement entry (`*` or `TTL:<subject>`) was not met by
    /// any validated receipt. Ledger-name entries report as
    /// [`ReceiptFromDisallowedLedger`](FragmentError::ReceiptFromDisallowedLedger) instead,
    /// so existing single-ledger configurations keep the error they had.
    UnsatisfiedReceiptRequirement { requirement: String },
    /// FR-1e: the fragment's `(issuer, feed)` pair is not declared/accepted.
    UndeclaredFeed { issuer: String, feed: String },
    /// FR-1g: a required (dependency) fragment has not been loaded.
    UnsatisfiedRequirement { requires: String },
    /// FR-1d: the X.509 certificate chain (`x5chain`) is malformed, an unsupported
    /// algorithm, or a link signature does not verify.
    InvalidCertChain,
    /// FR-1d: no configured CA anchor is present in the presented certificate chain.
    UntrustedCa,
    /// FR-1d: the derived `did:x509` (chain CA + leaf policy) does not match an authorized
    /// anchor or the fragment's declared issuer.
    DidX509Mismatch,
    /// FR-1d: a configured `did:x509` anchor is not a canonical `did:x509` identifier, so the
    /// CA it names cannot be compared against the CA it anchors on.
    MalformedAnchorDid,
    /// FR-1d: a configured `did:x509` anchor advertises a CA fingerprint or a leaf constraint
    /// that is not the one it actually enforces.
    AnchorDidMismatch,
    /// FR-1d: a configured `did:x509` anchor declares a policy predicate this implementation
    /// cannot enforce. Refused rather than ignored, so a DID never reads as promising more
    /// than was checked.
    UnsupportedAnchorDidPolicy,
    /// FR-1d: a certificate in the chain is on the measured revocation list.
    RevokedCertificate,
    /// FR-1d: a certificate in the chain is outside its validity window.
    CertExpired,
    /// FR-1d: the presented `x5chain` holds more certificates than any legitimate chain
    /// needs. Bounded so an untrusted host cannot make the guest parse an arbitrarily long
    /// chain before it has authenticated anything.
    CertChainTooLong { len: usize, max: usize },
    /// FR-1j: the fragment asserts a predecessor log head that is not the store's current
    /// head — a reordering, omission, or insertion in the append-only application log.
    LogHeadMismatch { expected: String, presented: String },
    /// FR-1f Stage 2: the transparency inclusion proof does not recompute to the signed
    /// tree-head root (the fragment is not provably recorded in the log).
    InvalidInclusionProof,
    /// FR-1f Stage 2 (F-168): a CCF inclusion proof carries a longer path than any real
    /// ledger produces. Bounded because the fold runs on host-supplied, unsigned input
    /// before any signature is checked. Distinct from [`InvalidInclusionProof`] because it
    /// is the one case an operator can act on rather than an attack signature.
    ///
    /// [`InvalidInclusionProof`]: FragmentError::InvalidInclusionProof
    CcfProofPathTooLong { len: usize, max: usize },
    /// FR-1f Stage 2 (F-167): a CCF receipt validated under the ledger it claims *and* under
    /// at least one other configured ledger, so it does not attribute to a single ledger.
    ///
    /// Unlike the native `kata-ttl-proof/v1` path — where the ledger id is inside the bytes
    /// the ledger signs — a CCF receipt is a signature over the bare Merkle root, so the
    /// only thing binding it to a ledger is which trust-list entry the key sat in. When two
    /// entries share key material that binding is not a binding at all, and a receipt from
    /// one ledger would silently satisfy a scope naming the other.
    AmbiguousCcfLedger { claimed: String, also: String },
    /// FR-1f Stage 2: the presented signed tree head is not an append-only extension of the
    /// last-seen one for this ledger (the log was rewound or forked).
    LogRolledBack {
        ledger: String,
        last_size: u64,
        presented_size: u64,
    },
    /// F-146: a field would be unsafe downstream of the encoding — a control character in
    /// an issuer or feed forges a line in the exported audit log. See
    /// [`PolicyFragment::validate_statement`].
    MalformedStatement { field: String, reason: String },
    /// The COSE_Sign1 envelope is not a well-formed policy fragment: it does not decode, or
    /// it does not carry the metadata a fragment must declare. Distinct from
    /// [`InvalidSignature`](FragmentError::InvalidSignature), which means the envelope was
    /// well formed and did not verify — the two failures point at different culprits, and
    /// collapsing them would send an operator hunting a key problem for a signer bug.
    MalformedEnvelope { reason: String },
}

impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FragmentError::UnauthorizedIssuer(i) => write!(f, "unauthorized fragment issuer: {i}"),
            FragmentError::InvalidSignature => write!(f, "invalid fragment signature"),
            FragmentError::RolledBackSvn {
                issuer,
                presented,
                min_required,
            } => write!(
                f,
                "rolled-back SVN for issuer {issuer}: presented {presented}, require >= {min_required}"
            ),
            FragmentError::MissingReceipt => write!(f, "fragment is missing a transparency receipt"),
            FragmentError::InvalidReceipt => write!(f, "fragment transparency receipt is invalid"),
            FragmentError::LedgerNotAllowed { issuer, feed, ledger } => write!(
                f,
                "receipt ledger {ledger:?} not allowed for issuer {issuer}, feed {feed:?}"
            ),
            FragmentError::ReceiptFromDisallowedLedger { required, presented } => write!(
                f,
                "receipt required from ledger {required:?}, but presented from {presented:?}"
            ),
            FragmentError::UnsatisfiedReceiptRequirement { requirement } => write!(
                f,
                "no validated transparency receipt satisfies requirement {requirement:?}"
            ),
            FragmentError::UndeclaredFeed { issuer, feed } => {
                write!(f, "undeclared fragment feed: issuer {issuer}, feed {feed:?}")
            }
            FragmentError::UnsatisfiedRequirement { requires } => {
                write!(f, "required fragment not loaded: {requires}")
            }
            FragmentError::InvalidCertChain => write!(f, "invalid X.509 certificate chain"),
            FragmentError::UntrustedCa => write!(f, "no trusted CA anchor in certificate chain"),
            FragmentError::DidX509Mismatch => {
                write!(f, "did:x509 identity does not match an authorized anchor")
            }
            FragmentError::MalformedAnchorDid => {
                write!(f, "configured did:x509 anchor is not a canonical did:x509")
            }
            FragmentError::AnchorDidMismatch => write!(
                f,
                "configured did:x509 anchor advertises a CA or leaf constraint it does not enforce"
            ),
            FragmentError::UnsupportedAnchorDidPolicy => write!(
                f,
                "configured did:x509 anchor declares a policy predicate that cannot be enforced"
            ),
            FragmentError::RevokedCertificate => write!(f, "certificate in chain is revoked"),
            FragmentError::CertExpired => write!(f, "certificate in chain is outside validity"),
            FragmentError::CertChainTooLong { len, max } => write!(
                f,
                "certificate chain presents {len} certificates, more than the {max} permitted"
            ),
            FragmentError::LogHeadMismatch { expected, presented } => write!(
                f,
                "fragment ordering log-head mismatch: expected {expected}, presented {presented}"
            ),
            FragmentError::InvalidInclusionProof => {
                write!(f, "transparency inclusion proof does not verify")
            }
            FragmentError::CcfProofPathTooLong { len, max } => write!(
                f,
                "CCF inclusion proof presents a {len}-element path, more than the {max} permitted"
            ),
            FragmentError::AmbiguousCcfLedger { claimed, also } => write!(
                f,
                "CCF receipt claimed for ledger {claimed} also validates as ledger {also}: \
                 shared ledger key material makes the claimed ledger unverifiable"
            ),
            FragmentError::LogRolledBack { ledger, last_size, presented_size } => write!(
                f,
                "transparency log {ledger} rolled back: last size {last_size}, presented {presented_size}"
            ),
            FragmentError::MalformedStatement { field, reason } => write!(
                f,
                "fragment statement field {field} cannot be encoded unambiguously: {reason}"
            ),
            FragmentError::MalformedEnvelope { reason } => write!(
                f,
                "fragment envelope is malformed: it {reason}"
            ),
        }
    }
}

impl std::error::Error for FragmentError {}

/// Verifier and add-only accumulator for policy fragments.
#[derive(Default)]
pub struct FragmentStore {
    issuers: HashMap<String, VerifyingKey>,
    /// Monotonic SVN high-water mark keyed by (issuer, feed).
    last_svn: HashMap<(String, String), u64>,
    /// FR-1e: declared/accepted (issuer, feed) pairs and their SVN floor.
    feeds: HashMap<(String, String), u64>,
    require_receipt: bool,
    /// FR-1f (trust list): the Transparency Trust List — a map of ledger id to that
    /// ledger's current verification key(s). Multiple keys per ledger support rotation: a
    /// receipt verifies if *any* current key of the named ledger validates it. When
    /// non-empty, a fragment's receipt is cryptographically verified against the selected
    /// ledger's keys. BL-2: each key carries its algorithm (EdDSA/ES256/ES384/PS256/RS256),
    /// so a ledger may sign receipts/tree-heads with any supported scheme.
    transparency_trust_list: HashMap<String, Vec<TrustListKey>>,
    /// FR-1f (trust list): per-`(issuer, feed)` allow-list of ledger ids. A receipt whose
    /// ledger is not in this list (when the list is non-empty) is rejected.
    allowed_ledgers: HashMap<(String, String), Vec<String>>,
    /// FR-1f (trust list): per-`(issuer, feed)` policy-driven receipt requirement — the set
    /// of ledgers a receipt must originate from for this scope. Non-empty ⇒ a receipt from
    /// one of these ledgers is mandatory (overrides the global `require_receipt` default).
    required_receipt_from: HashMap<(String, String), Vec<String>>,
    /// FR-1g: identifiers of fragments that have been loaded (for composition).
    loaded_ids: HashSet<String>,
    /// FR-1d: authorized `did:x509` anchors (CA fingerprint + leaf policy), keyed by did.
    did_x509_anchors: HashMap<String, crate::did_x509::DidX509Anchor>,
    /// FR-1d: measured revocation list — SHA-256 fingerprints of revoked certificates.
    revoked_certs: HashSet<[u8; 32]>,
    /// FR-1d: when true, every fragment must present a valid `x5chain` (no raw-key path).
    require_x509: bool,
    /// FR-1j: the append-only application log head. Advances by hashing each committed
    /// fragment in. Equals the genesis until the first ordered fragment is committed.
    log_head: Vec<u8>,
    /// FR-1j: the log genesis; `Some` enables ordered mode (the log-head gate is enforced).
    log_genesis: Option<Vec<u8>>,
    /// FR-1j: the ordered, append-only record of committed fragments `(id, statement hash)`.
    ordered_log: Vec<(String, [u8; 32])>,
    /// FR-1j: number of fragments committed to the ordered log (persisted, raise-only, so a
    /// restart cannot rewind the log position).
    log_len: u64,
    /// FR-1f Stage 2: last-seen signed tree head `(size, root)` per transparency ledger.
    /// Monotonic (raise-only by size) and persisted, so the external log cannot be rewound
    /// across a restart.
    ttl_heads: HashMap<String, (u64, [u8; 32])>,
    /// FR-1c: per-`(issuer, feed)` grant of *which* policy namespaces a fragment may
    /// contribute a module to, and whether its module may be applied at all.
    ///
    /// The measured policy owns this, not the fragment. See [`ModuleScope`].
    module_scope: HashMap<(String, String), ModuleScope>,
}

/// FR-1f (trust list): a verification key for a transparency ledger, together with the
/// Trust List subject(s) that vouched for it.
///
/// The provenance matters because a policy may want to require not merely "a receipt from
/// ledger L" but "a receipt validated by a key that Trust List S vouched for". A ledger can
/// hold keys contributed by more than one Trust List, and the two requirements are not the
/// same: the ledger id is self-asserted metadata carried on the receipt, whereas the subject
/// is a property of the measured key material that actually validated it. Mirrors hcsshim's
/// `TTL:<subject>` receipt requirement form.
#[derive(Clone)]
pub struct TrustListKey {
    pub key: PublicKey,
    pub alg: CoseAlg,
    /// Trust List subjects that supplied this key. Empty when the key came from a plain
    /// ledger configuration with no Trust List provenance recorded.
    pub ttl_subjects: Vec<String>,
}

impl core::fmt::Debug for TrustListKey {
    /// Elides the key material itself — only its algorithm and provenance are of diagnostic
    /// interest, and log lines carrying key bytes are a needless disclosure.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrustListKey")
            .field("alg", &self.alg)
            .field("ttl_subjects", &self.ttl_subjects)
            .finish_non_exhaustive()
    }
}

/// FR-1f (trust list): one entry of a scope's receipt requirement list.
///
/// The grammar matches hcsshim's, and so does the conjunction: the list is satisfied only
/// when **every** entry is, though one receipt may satisfy several entries. Requiring all of
/// them is the point — a list is how a policy says "countersigned by the vendor *and* logged
/// publicly", which an any-of reading would silently downgrade to "either will do".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptRequirement {
    /// `*` — any validated receipt. Still requires a receipt to exist and to have verified.
    Any,
    /// `TTL:<subject>` — a receipt validated by a key the named Trust List vouched for.
    TrustList(String),
    /// A literal ledger id — a receipt presented under, and validated by, that ledger.
    Ledger(String),
}

impl ReceiptRequirement {
    /// Parse one entry. Anything without a recognised prefix is a ledger id, so existing
    /// single-ledger configurations read exactly as they did.
    pub fn parse(s: &str) -> Self {
        if s == "*" {
            ReceiptRequirement::Any
        } else if let Some(subject) = s.strip_prefix("TTL:") {
            ReceiptRequirement::TrustList(subject.to_string())
        } else {
            ReceiptRequirement::Ledger(s.to_string())
        }
    }

    fn satisfied_by(&self, validated: &[ValidatedReceipt]) -> bool {
        match self {
            ReceiptRequirement::Any => !validated.is_empty(),
            ReceiptRequirement::Ledger(l) => validated.iter().any(|r| &r.ledger == l),
            ReceiptRequirement::TrustList(s) => validated
                .iter()
                .any(|r| r.ttl_subjects.iter().any(|sub| sub == s)),
        }
    }
}

/// A receipt that has been cryptographically verified against the trust list, recorded so a
/// scope's requirements can be evaluated over the whole set rather than one at a time.
#[derive(Clone, Debug)]
struct ValidatedReceipt {
    ledger: String,
    ttl_subjects: Vec<String>,
}

/// Verify a detached signature against every key of a ledger, returning the union of the
/// Trust List subjects that vouched for the keys which accepted it, or `None` if none did.
///
/// The union, rather than the first match, is what makes `TTL:<subject>` mean what it says:
/// the same key material may be contributed by several Trust Lists, and a ledger may hold
/// both vouched and unvouched copies of a key. Stopping at the first acceptance would make
/// the outcome depend on insertion order.
fn validating_subjects(keys: &[TrustListKey], msg: &[u8], sig: &[u8]) -> Option<Vec<String>> {
    let mut subjects: Vec<String> = Vec::new();
    let mut any = false;
    for k in keys {
        if k.key.verify_cose(k.alg, msg, sig).is_ok() {
            any = true;
            for s in &k.ttl_subjects {
                if !subjects.contains(s) {
                    subjects.push(s.clone());
                }
            }
        }
    }
    any.then_some(subjects)
}

/// FR-1c: what a fragment for a given `(issuer, feed)` is permitted to contribute.
///
/// The fragment statement carries its own `includes` list, but that is the fragment
/// *asking*, not being granted: it is signed by the fragment's issuer, so it says only what
/// that issuer intended, and every authorized issuer would otherwise be able to claim any
/// namespace — including one the base policy meant a different issuer to fill. The grant
/// here comes from measured state (a `policy_fragments[]` declaration, or the trust root's
/// feed entry), which is the same authority that decided the issuer was trusted at all.
/// This mirrors hcsshim, where `load_fragment` passes `fragment.includes` from the matched
/// *candidate declaration* into `update_issuer`, never the delivered fragment's own.
///
/// The effective scope is the intersection of the grant and the fragment's own request, so
/// neither side can widen the other.
#[derive(Clone, Debug)]
pub struct ModuleScope {
    /// Namespaces under `agent_policy.fragments.` this feed may contribute to. Empty means
    /// only the shared `agent_policy.fragments` package is available.
    pub namespaces: Vec<String>,
    /// Whether the fragment's Rego module may be applied at all. `false` accepts the
    /// fragment for its SVN, receipt and ordering record while contributing no rules —
    /// hcsshim's `add_module` behaviour, useful for pinning a version or recording an
    /// attestation without granting policy surface.
    pub allow_module: bool,
    /// FR-1k: parameter values to instantiate the fragment's Rego with, as a JSON object.
    ///
    /// A parameterised fragment reads these via `parameter("name")` instead of hard-coding
    /// values, so one signed artefact can serve several deployments without being re-signed
    /// per value. They are authority-bearing — a parameter can decide which env var value or
    /// command a rule admits — so like the namespace grant they come from measured state,
    /// never from the host or from the fragment itself.
    pub parameters: Option<String>,
}

impl Default for ModuleScope {
    fn default() -> Self {
        Self {
            namespaces: Vec::new(),
            allow_module: true,
            parameters: None,
        }
    }
}

impl FragmentStore {
    /// Create a store. `require_receipt` should be true in strict mode.
    pub fn new(require_receipt: bool) -> Self {
        Self {
            require_receipt,
            ..Default::default()
        }
    }

    /// Authorize an issuer by its 32-byte Ed25519 public key. Returns an error if the key
    /// is not a valid Ed25519 public key.
    pub fn authorize_issuer(
        &mut self,
        issuer: impl Into<String>,
        public_key: &[u8; 32],
    ) -> Result<(), FragmentError> {
        let key =
            VerifyingKey::from_bytes(public_key).map_err(|_| FragmentError::InvalidSignature)?;
        let issuer = issuer.into();
        // Authorizing an issuer also declares its default feed ("") so simple fragments
        // (no explicit feed) are accepted; named feeds are added via `declare_feed`.
        self.feeds
            .entry((issuer.clone(), String::new()))
            .or_insert(0);
        self.issuers.insert(issuer, key);
        Ok(())
    }

    /// FR-1b: set a declarative minimum-SVN floor for an issuer's default feed (from
    /// measured state). A fragment is only accepted at `svn >= floor`.
    pub fn set_min_svn(&mut self, issuer: impl Into<String>, floor: u64) {
        self.feeds.insert((issuer.into(), String::new()), floor);
    }

    /// FR-1e: declare an accepted `(issuer, feed)` pair with its SVN floor (from measured
    /// state). A fragment whose `(issuer, feed)` is not declared is rejected.
    ///
    /// **Raise-only** (F-165). Two measured sources declare feeds into this map, in a fixed
    /// order: the trust root at boot (`seed_fragment_trust_root`, from the operator's
    /// attested issuer config) and then the base policy (`record_declared_fragments`, from
    /// the per-pod `policy_fragments[]`). Both use the same key, so a plain `insert` let the
    /// second silently discard the first — a per-pod declaration could drop the operator's
    /// anti-rollback floor for a feed and admit a genuinely signed but superseded fragment.
    ///
    /// Neither input is host-controlled, so this was not remotely exploitable; it is a
    /// weakening of the trust hierarchy between two *differently authored* measured
    /// artifacts, and the floor is exactly the control an operator raises to retire a
    /// vulnerable fragment version. Keeping the stricter value makes the invariant the code
    /// already claimed — "a per-feed floor may raise the bar, never lower it" — true of the
    /// declaration order as well as of the issuer/feed relationship, and makes it hold for
    /// any future third declarer without that caller having to remember.
    pub fn declare_feed(
        &mut self,
        issuer: impl Into<String>,
        feed: impl Into<String>,
        min_svn: u64,
    ) {
        self.feeds
            .entry((issuer.into(), feed.into()))
            .and_modify(|floor| *floor = (*floor).max(min_svn))
            .or_insert(min_svn);
    }

    /// FR-1c: grant the policy namespaces a `(issuer, feed)` may contribute a module to,
    /// and whether its module may be applied at all.
    ///
    /// Called from measured state only — the BL-8 declaration in the base policy, or the
    /// trust root's feed entry. See [`ModuleScope`] for why the fragment's own `includes`
    /// is not sufficient authority.
    pub fn grant_module_scope(
        &mut self,
        issuer: impl Into<String>,
        feed: impl Into<String>,
        namespaces: &[String],
        allow_module: bool,
        parameters: Option<String>,
    ) {
        self.module_scope.insert(
            (issuer.into(), feed.into()),
            ModuleScope {
                namespaces: namespaces.to_vec(),
                allow_module,
                parameters,
            },
        );
    }

    /// FR-1c: the module scope granted to a `(issuer, feed)`.
    ///
    /// Defaults to "shared namespace only, module allowed" when nothing was granted. That
    /// default is deliberate: it keeps a fragment that predates the grant working in the
    /// shared `agent_policy.fragments` package, while denying it the named namespaces it
    /// could previously have claimed for itself.
    pub fn module_scope(&self, issuer: &str, feed: &str) -> ModuleScope {
        self.module_scope
            .get(&(issuer.to_string(), feed.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// FR-1f (trust list): load the Transparency Trust List — a set of `(ledger_id, keys)`
    /// entries of Ed25519 keys from measured state. Each ledger may carry multiple keys to
    /// support rotation (a receipt verifies against any current key). Invalid keys are
    /// rejected. (BL-2: for non-Ed25519 ledger keys use [`add_ledger_key`].)
    pub fn load_transparency_trust_list(
        &mut self,
        entries: &[(String, Vec<[u8; 32]>)],
    ) -> Result<(), FragmentError> {
        for (id, keys) in entries {
            for k in keys {
                let pk = PublicKey::from_ed25519_bytes(k).ok_or(FragmentError::InvalidSignature)?;
                self.transparency_trust_list
                    .entry(id.clone())
                    .or_default()
                    .push(TrustListKey {
                        key: pk,
                        alg: CoseAlg::EdDsa,
                        ttl_subjects: Vec::new(),
                    });
            }
        }
        Ok(())
    }

    /// FR-1f Stage 2 (F-167): does a CCF receipt attribute to more than one configured
    /// ledger?
    ///
    /// Returns the id of some *other* ledger whose keys also validate `sig` over `root`, or
    /// `None` when the claim is unambiguous. Needed only for the CCF path: every other
    /// receipt form binds the ledger id into the bytes that were signed, so re-attribution
    /// is already impossible there.
    ///
    /// This tests the property directly rather than checking for duplicate key material, so
    /// it also covers the case where two entries hold *different* keys that both happen to
    /// verify (a key present in two encodings, say). Cost is one verification per key in the
    /// other ledgers, on a trust list that holds a handful of keys.
    fn ledger_ambiguity(&self, claimed: &str, root: &[u8; 32], sig: &[u8]) -> Option<String> {
        self.transparency_trust_list
            .iter()
            .filter(|(id, _)| id.as_str() != claimed)
            .find(|(_, keys)| validating_subjects(keys, root, sig).is_some())
            .map(|(id, _)| id.clone())
    }

    /// FR-1f (trust list): record which Trust List subject(s) vouched for a ledger key.
    ///
    /// Separate from [`load_transparency_trust_list`](Self::load_transparency_trust_list)
    /// so that a configuration with no Trust List provenance keeps working unchanged: keys
    /// loaded without subjects satisfy `*` and ledger-name requirements but never a
    /// `TTL:<subject>` one, which is the correct fail-closed reading — a requirement naming
    /// a subject nothing vouched for is unmet, not vacuously true.
    pub fn load_trust_list_with_subjects(
        &mut self,
        ledger: impl Into<String>,
        keys: &[[u8; 32]],
        ttl_subjects: &[String],
    ) -> Result<(), FragmentError> {
        let ledger = ledger.into();
        for k in keys {
            let pk = PublicKey::from_ed25519_bytes(k).ok_or(FragmentError::InvalidSignature)?;
            self.transparency_trust_list
                .entry(ledger.clone())
                .or_default()
                .push(TrustListKey {
                    key: pk,
                    alg: CoseAlg::EdDsa,
                    ttl_subjects: ttl_subjects.to_vec(),
                });
        }
        Ok(())
    }

    /// BL-2: add a single transparency ledger key of any supported algorithm (from a
    /// SubjectPublicKeyInfo DER for EC/RSA, or an Ed25519 key). Multiple keys per ledger
    /// support rotation and mixed algorithms.
    pub fn add_ledger_key(&mut self, ledger: impl Into<String>, key: PublicKey, alg: CoseAlg) {
        self.add_ledger_key_from_ttl(ledger, key, alg, &[]);
    }

    /// BL-2 + FR-1f: as [`add_ledger_key`](Self::add_ledger_key), recording the Trust List
    /// subject(s) that vouched for the key.
    pub fn add_ledger_key_from_ttl(
        &mut self,
        ledger: impl Into<String>,
        key: PublicKey,
        alg: CoseAlg,
        ttl_subjects: &[String],
    ) {
        self.transparency_trust_list
            .entry(ledger.into())
            .or_default()
            .push(TrustListKey {
                key,
                alg,
                ttl_subjects: ttl_subjects.to_vec(),
            });
    }

    /// FR-1f (trust list): scope the ledgers a receipt may originate from for a given
    /// `(issuer, feed)`. A non-empty list rejects receipts from any other ledger.
    pub fn set_allowed_ledgers(
        &mut self,
        issuer: impl Into<String>,
        feed: impl Into<String>,
        ledgers: &[String],
    ) {
        self.allowed_ledgers
            .insert((issuer.into(), feed.into()), ledgers.to_vec());
    }

    /// FR-1f (trust list): policy-driven `required_receipts` — require a receipt from one of
    /// `from_ledgers` for this `(issuer, feed)`. A non-empty list makes a receipt mandatory
    /// for the scope (overriding the global default) and constrains its ledger.
    pub fn require_receipt_for(
        &mut self,
        issuer: impl Into<String>,
        feed: impl Into<String>,
        from_ledgers: &[String],
    ) {
        self.required_receipt_from
            .insert((issuer.into(), feed.into()), from_ledgers.to_vec());
    }

    /// FR-1f: set a single transparency anchor public key. Back-compat shim over the trust
    /// list: registers the key under the default ledger. When set, a fragment's receipt is
    /// cryptographically verified against it (a detached signature over the fragment
    /// statement); without any trust-list entry, receipts are only checked for presence.
    pub fn set_transparency_anchor(&mut self, public_key: &[u8; 32]) -> Result<(), FragmentError> {
        self.load_transparency_trust_list(&[(DEFAULT_LEDGER.to_string(), vec![*public_key])])
    }

    /// FR-1d: authorize a `did:x509` issuer identity — a trusted CA (by fingerprint) plus a
    /// leaf policy. A fragment presenting an `x5chain` that path-validates to this CA and
    /// satisfies the policy is accepted as issued by `anchor.did`. Also declares the did's
    /// default feed so simple x509 fragments (no explicit feed) are accepted.
    ///
    /// The anchor must be self-consistent (see [`DidX509Anchor::validate`]): the CA named
    /// inside the DID must be the CA it anchors on. This is the only path into the trust
    /// store, so an inconsistent anchor cannot reach it.
    pub fn authorize_did_x509(
        &mut self,
        anchor: crate::did_x509::DidX509Anchor,
    ) -> Result<(), FragmentError> {
        anchor.validate()?;
        self.feeds
            .entry((anchor.did.clone(), String::new()))
            .or_insert(0);
        self.did_x509_anchors.insert(anchor.did.clone(), anchor);
        Ok(())
    }

    /// FR-1d: set the measured certificate revocation list (SHA-256 fingerprints). Any chain
    /// containing a revoked certificate is rejected.
    pub fn set_revoked_certs(&mut self, fingerprints: impl IntoIterator<Item = [u8; 32]>) {
        self.revoked_certs = fingerprints.into_iter().collect();
    }

    /// FR-1d: require every fragment to present a valid `x5chain` (disables the raw-key
    /// path). Fail-closed: with this set, a fragment lacking an x509 chain is rejected.
    pub fn set_require_x509(&mut self, required: bool) {
        self.require_x509 = required;
    }

    /// Whether the raw-key issuer path is disabled (FR-1d strict x509 mode).
    pub fn require_x509(&self) -> bool {
        self.require_x509
    }

    /// Whether any `did:x509` anchor is configured.
    pub fn has_did_x509_anchors(&self) -> bool {
        !self.did_x509_anchors.is_empty()
    }

    /// FR-1j: enable append-only ordering by setting the log genesis (a measured constant).
    /// Idempotent for a fresh store; does not rewind an already-advanced head. When set, the
    /// log-head gate is enforced on every fragment.
    pub fn set_log_genesis(&mut self, genesis: &[u8]) {
        let g = genesis.to_vec();
        if self.log_genesis.is_none() && self.log_len == 0 {
            self.log_head = g.clone();
        }
        self.log_genesis = Some(g);
    }

    /// FR-1j: whether ordered mode is enabled.
    pub fn is_ordered(&self) -> bool {
        self.log_genesis.is_some()
    }

    /// FR-1j: the current append-only log head (the value the next fragment must assert as
    /// its `prev_log_head`).
    pub fn log_head(&self) -> &[u8] {
        &self.log_head
    }

    /// FR-1j: export the ordered application log as a deterministic, customer-auditable
    /// record: one `index\tfragment-id\tstatement-sha256` line per committed fragment, then
    /// a final `head\t<hex>` line. This is the non-repudiable proof of the exact applied
    /// sequence (empty when not in ordered mode / nothing committed this session).
    ///
    /// F-146: this format is only unambiguous because `validate_statement` bans control
    /// characters — including tab — in the issuer and feed, and [`PolicyFragment::make_id`]
    /// escapes the `/` separator. Without the first, an issuer named `X\t<hash>` yields a
    /// four-field line that an auditor's parser splits into a different id and digest than
    /// were committed. Do not relax either without re-encoding this log.
    pub fn export_fragment_log(&self) -> String {
        let mut out = String::new();
        for (i, (id, hash)) in self.ordered_log.iter().enumerate() {
            out.push_str(&format!("{}\t{}\t{}\n", i, id, bytes_to_hex(hash)));
        }
        out.push_str(&format!("head\t{}", bytes_to_hex(&self.log_head)));
        out
    }

    /// F-147: true when a receipt is required — globally or by any scope — but no ledger
    /// key is loaded that could ever validate one, so every fragment will now be refused.
    /// The agent reports this at startup: the two are independent configuration options,
    /// and before the gate was fixed this combination silently accepted any receipt.
    pub fn receipt_gate_is_unsatisfiable(&self) -> bool {
        let required =
            self.require_receipt || self.required_receipt_from.values().any(|r| !r.is_empty());
        required && self.transparency_trust_list.is_empty()
    }

    /// Whether any issuer is authorized (fail-closed indicator).
    pub fn has_authorized_issuers(&self) -> bool {
        !self.issuers.is_empty()
    }

    /// The minimum SVN the next fragment for `(issuer, feed)` must carry (declarative floor
    /// combined with the monotonic high-water mark of accepted fragments).
    ///
    /// FR-1i: a named feed's floor never sinks below its issuer's. The issuer-wide floor
    /// from the measured trust root is held at `(issuer, "")`, and a named feed carries its
    /// own entry, so consulting only the named key let a per-feed `min_svn = 0` override a
    /// trust root demanding 5 — accepting a fragment the attested floor forbids. Take the
    /// stricter of the two: a per-feed floor may raise the bar, never lower it.
    fn min_required(&self, issuer: &str, feed: &str) -> u64 {
        let key = (issuer.to_string(), feed.to_string());
        let mut floor = self.feeds.get(&key).copied().unwrap_or(0);
        if !feed.is_empty() {
            let issuer_floor = self
                .feeds
                .get(&(issuer.to_string(), String::new()))
                .copied()
                .unwrap_or(0);
            floor = floor.max(issuer_floor);
        }
        match self.last_svn.get(&key) {
            Some(last) => (last + 1).max(floor),
            None => floor,
        }
    }

    /// Verify a fragment presented as a COSE_Sign1 envelope, against every gate, **without**
    /// mutating the store. Returns the verified fragment so the caller can apply it to the
    /// policy engine and only then [`commit`](Self::commit) it. On any failure the store is
    /// unchanged (fail-closed).
    ///
    /// # Why this is the only entry point
    ///
    /// Verification used to come in three flavours — a detached signature over a bespoke
    /// statement, an Ed25519 COSE envelope, and a `did:x509` COSE envelope — and the first
    /// two took the fragment's fields from the *caller*, alongside the bytes that were
    /// supposed to authenticate them. Keeping those in agreement was a check
    /// (`payload == statement`) rather than a property. Here the fields are parsed out of
    /// the envelope, so what is checked is by construction what the signature covers, and
    /// a caller cannot describe a fragment into being something it is not (F-151).
    ///
    /// # Routing
    ///
    /// FR-1d: deterministic, and offers no downgrade. An envelope carrying an `x5chain` is
    /// always verified as `did:x509`, and when x509 is required the raw-key path is not
    /// reachable at all — so an attacker cannot strip a chain to land on a weaker check.
    ///
    /// `attach` is the one hook for data that legitimately travels *outside* the envelope: a
    /// transparency receipt is a countersignature over the envelope and therefore cannot be
    /// inside it. Everything a receipt is verified *against* still comes from the envelope.
    pub fn verify_envelope_with(
        &self,
        cose_sign1: &[u8],
        attach: impl FnOnce(&mut PolicyFragment),
    ) -> Result<VerifiedFragment, FragmentError> {
        let mut fragment = PolicyFragment::from_cose_envelope(cose_sign1)?;
        attach(&mut fragment);

        if self.require_x509
            || (!self.did_x509_anchors.is_empty() && crate::did_x509::cose_has_x5chain(cose_sign1))
        {
            // FR-1d: the chain is path-validated to a trusted CA anchor, the leaf must
            // satisfy the anchor's `did:x509` policy, no chain certificate may be revoked,
            // and the leaf key must have signed this envelope.
            let did = crate::did_x509::verify_x509_cose(
                &self.did_x509_anchors,
                &self.revoked_certs,
                cose_sign1,
            )?;
            // The identity the chain proves must be the identity the envelope claims.
            if did != fragment.issuer {
                return Err(FragmentError::DidX509Mismatch);
            }
        } else {
            // The raw-key path: the issuer names a key the measured trust root authorized.
            let key = self
                .issuers
                .get(&fragment.issuer)
                .ok_or_else(|| FragmentError::UnauthorizedIssuer(fragment.issuer.clone()))?;
            use coset::CborSerializable;
            let sign1 = coset::CoseSign1::from_slice(cose_sign1)
                .map_err(|_| FragmentError::InvalidSignature)?;
            sign1
                .verify_signature(b"", |sig, tbs| {
                    let s = Signature::from_slice(sig).map_err(|_| ())?;
                    key.verify(tbs, &s).map_err(|_| ())
                })
                .map_err(|_| FragmentError::InvalidSignature)?;
        }

        let signed = fragment.tbs.clone();
        self.check_gates(&fragment, &signed)
    }

    /// [`verify_envelope_with`](Self::verify_envelope_with) for a fragment carrying no
    /// out-of-envelope receipts.
    pub fn verify_envelope(&self, cose_sign1: &[u8]) -> Result<VerifiedFragment, FragmentError> {
        self.verify_envelope_with(cose_sign1, |_| {})
    }
    fn check_gates(
        &self,
        fragment: &PolicyFragment,
        statement: &[u8],
    ) -> Result<VerifiedFragment, FragmentError> {
        // F-144: refuse a fragment whose fields the statement encoding cannot represent
        // unambiguously, so the bytes the issuer signed have exactly one reading. Enforced
        // here because it is the one point every verification path funnels through.
        fragment.validate_statement()?;

        // 3. FR-1e: the (issuer, feed) pair must be declared/accepted.
        let feed_key = (fragment.issuer.clone(), fragment.feed.clone());
        if !self.feeds.contains_key(&feed_key) {
            return Err(FragmentError::UndeclaredFeed {
                issuer: fragment.issuer.clone(),
                feed: fragment.feed.clone(),
            });
        }

        // 4. Monotonic SVN per (issuer, feed): >= the declared floor and strictly greater
        //    than the last accepted.
        let min_required = self.min_required(&fragment.issuer, &fragment.feed);
        if fragment.svn < min_required {
            return Err(FragmentError::RolledBackSvn {
                issuer: fragment.issuer.clone(),
                presented: fragment.svn,
                min_required,
            });
        }

        // 5. Transparency receipt (FR-1f): a receipt may be required globally or per-scope
        //    (`required_receipt_from`). Two forms are accepted and both are scoped by
        //    `allowed_ledgers`/`required_receipt_from`:
        //      Stage 1 — a detached signature by a trust-list ledger key over the statement;
        //      Stage 2 — an inclusion + consistency proof anchoring the statement in an
        //                append-only transparency log at a signed, monotonic tree head.
        let receipt = fragment.receipt.as_deref().unwrap_or("");
        let proof = fragment.receipt_proof.as_deref().unwrap_or("");
        let ledger = fragment
            .receipt_ledger
            .as_deref()
            .filter(|l| !l.is_empty())
            .unwrap_or(DEFAULT_LEDGER);
        let has_receipt = !receipt.is_empty() || !proof.is_empty();

        // Per-scope required ledgers (policy-driven `required_receipts`). A non-empty list
        // makes a receipt mandatory for this scope and constrains its ledger.
        let required = self.required_receipt_from.get(&feed_key);
        let scope_requires = required.map(|r| !r.is_empty()).unwrap_or(false);

        let mut ttl_head: Option<(String, u64, [u8; 32])> = None;
        // Every receipt that actually verified, with the provenance of the key that
        // validated it. The scope's requirement list is evaluated over this set at the end,
        // so a conjunction like ["vendor", "TTL:public-log"] can be satisfied by two
        // different receipts.
        let mut validated: Vec<ValidatedReceipt> = Vec::new();

        if !has_receipt {
            if scope_requires || self.require_receipt {
                return Err(FragmentError::MissingReceipt);
            }
        } else {
            // The presented ledger must be in the scope's allow-list (if one is set).
            if let Some(allowed) = self.allowed_ledgers.get(&feed_key) {
                if !allowed.is_empty() && !allowed.iter().any(|l| l == ledger) {
                    return Err(FragmentError::LedgerNotAllowed {
                        issuer: fragment.issuer.clone(),
                        feed: fragment.feed.clone(),
                        ledger: ledger.to_string(),
                    });
                }
            }
            // With a single receipt in play, a ledger requirement it cannot possibly satisfy
            // is reported as such up front, rather than surfacing as an `InvalidReceipt`
            // from verifying against keys of the wrong ledger. Purely diagnostic: the
            // conjunction below would reject these cases anyway.
            if fragment.extra_receipts.is_empty() {
                if let Some(req_ledgers) = required {
                    let named: Vec<&String> = req_ledgers
                        .iter()
                        .filter(|r| matches!(ReceiptRequirement::parse(r), ReceiptRequirement::Ledger(_)))
                        .collect();
                    if !named.is_empty() && !named.iter().any(|l| l.as_str() == ledger) {
                        return Err(FragmentError::ReceiptFromDisallowedLedger {
                            required: req_ledgers.join(","),
                            presented: ledger.to_string(),
                        });
                    }
                }
            }
            let keys = self
                .transparency_trust_list
                .get(ledger)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);

            // Stage 1: detached-signature receipt, verified against any current ledger key
            // (rotation) using that key's algorithm (BL-2 multi-alg).
            //
            // F-147: this is deliberately NOT guarded on the trust list being non-empty. It
            // was, and that made the gate fail *open*: with `require_receipt` on and no
            // ledger keys loaded, the presence check above was satisfied by any non-empty
            // string while verification was skipped entirely, so a garbage receipt was
            // accepted where presenting none was correctly refused. An empty key set makes
            // `validating_subjects` return `None`, which is the right answer — a receipt
            // nothing can validate is not a valid receipt.
            if !receipt.is_empty() {
                let bytes = hex_to_bytes(receipt).map_err(|_| FragmentError::InvalidReceipt)?;
                let subjects = validating_subjects(keys, statement, &bytes)
                    .ok_or(FragmentError::InvalidReceipt)?;
                validated.push(ValidatedReceipt {
                    ledger: ledger.to_string(),
                    ttl_subjects: subjects,
                });
            }

            // Stage 2: transparency inclusion + consistency proof.
            if !proof.is_empty() {
                // BL-6: external SCITT CCF-profile receipt. Recompute the CCF Merkle root
                // from the inclusion proof, require it binds SHA-256(statement), and verify
                // the ledger's signature over that root. CCF proofs carry no signed tree
                // head, so cross-fragment append-only ordering is left to FR-1j
                // (`prev_log_head`) rather than the external ledger — note that FR-1j is
                // opt-in (it only engages once the store has a `log_genesis`), so a
                // deployment that uses CCF receipts *without* ordered mode has neither the
                // native `ttl_heads` consistency gate nor a log-head chain. That is
                // acceptable only because `data_hash` binds the statement (hence the
                // issuer/feed/SVN) and SVN monotonicity refuses a replayed receipt.
                if proof.trim_start().starts_with("kata-ccf-proof/v1") {
                    let ccf = CcfReceipt::parse(proof).ok_or(FragmentError::InvalidReceipt)?;
                    let stmt_hash: [u8; 32] = Sha256::digest(statement).into();
                    let root = crate::ccf::verify_ccf_inclusion(&ccf.proof_cbor, &stmt_hash)
                        .map_err(|e| match e {
                            // F-168: surfaced distinctly so an over-long path reads as a
                            // bound being hit, not as an unverifiable proof.
                            crate::ccf::CcfError::PathTooLong { len, max } => {
                                FragmentError::CcfProofPathTooLong { len, max }
                            }
                            _ => FragmentError::InvalidInclusionProof,
                        })?;
                    let subjects = validating_subjects(keys, &root, &ccf.sig)
                        .ok_or(FragmentError::InvalidReceipt)?;
                    // F-167: the native path below has the ledger sign
                    // `sth_signing_bytes(ledger, size, root)`, so the ledger id is *inside*
                    // the signed bytes and a receipt cannot be re-attributed. A CCF receipt
                    // is a signature over the bare root — nothing in it names a ledger — so
                    // the claimed `receipt_ledger` is only as trustworthy as the assumption
                    // that one ledger's keys are that ledger's alone. Nothing enforces that
                    // assumption at load time (and it would be wrong to: sharing a key is
                    // harmless for Stage 1 and for the native path, both of which bind the
                    // ledger in the signed bytes). So test the property where it actually
                    // matters: if any *other* configured ledger also validates this receipt,
                    // the claim is unverifiable and the receipt is refused.
                    if let Some(also) = self.ledger_ambiguity(ledger, &root, &ccf.sig) {
                        return Err(FragmentError::AmbiguousCcfLedger {
                            claimed: ledger.to_string(),
                            also,
                        });
                    }
                    validated.push(ValidatedReceipt {
                        ledger: ledger.to_string(),
                        ttl_subjects: subjects,
                    });
                    // CCF receipts satisfy the transparency gate on their own; the native
                    // RFC 6962 tree-head/consistency checks below are skipped, and no native
                    // `ttl_head` is recorded (external ledger owns its own consistency).
                } else {
                    let tp = TransparencyProof::parse(proof)
                        .ok_or(FragmentError::InvalidInclusionProof)?;
                    // (a) the signed tree head must be signed by a current ledger key.
                    let sth = sth_signing_bytes(ledger, tp.size, &tp.root);
                    let subjects = validating_subjects(keys, &sth, &tp.sig)
                        .ok_or(FragmentError::InvalidReceipt)?;
                    validated.push(ValidatedReceipt {
                        ledger: ledger.to_string(),
                        ttl_subjects: subjects,
                    });
                    // (b) the statement must be included in the tree at that head.
                    let leaf = crate::merkle::leaf_hash(statement);
                    if !crate::merkle::verify_inclusion(tp.index, tp.size, leaf, &tp.incl, &tp.root)
                    {
                        return Err(FragmentError::InvalidInclusionProof);
                    }
                    // (c) the head must be an append-only extension of the last-seen head
                    //     (monotonic + consistency-proven) — this is the ordering guarantee.
                    if let Some((last_size, last_root)) = self.ttl_heads.get(ledger) {
                        if tp.size < *last_size {
                            return Err(FragmentError::LogRolledBack {
                                ledger: ledger.to_string(),
                                last_size: *last_size,
                                presented_size: tp.size,
                            });
                        } else if tp.size == *last_size {
                            if &tp.root != last_root {
                                return Err(FragmentError::LogRolledBack {
                                    ledger: ledger.to_string(),
                                    last_size: *last_size,
                                    presented_size: tp.size,
                                });
                            }
                        } else if !crate::merkle::verify_consistency(
                            *last_size, tp.size, last_root, &tp.root, &tp.cons,
                        ) {
                            return Err(FragmentError::LogRolledBack {
                                ledger: ledger.to_string(),
                                last_size: *last_size,
                                presented_size: tp.size,
                            });
                        }
                    }
                    ttl_head = Some((ledger.to_string(), tp.size, tp.root));
                }
            }
        }

        // 5b. FR-1f: additional Stage-1 countersignatures. Each must verify against a key of
        //     the ledger it names, and that ledger must satisfy the same allow-list as the
        //     primary receipt — an extra receipt is a receipt, not a way around the scope.
        for (extra_ledger, extra_sig) in &fragment.extra_receipts {
            if let Some(allowed) = self.allowed_ledgers.get(&feed_key) {
                if !allowed.is_empty() && !allowed.iter().any(|l| l == extra_ledger) {
                    return Err(FragmentError::LedgerNotAllowed {
                        issuer: fragment.issuer.clone(),
                        feed: fragment.feed.clone(),
                        ledger: extra_ledger.clone(),
                    });
                }
            }
            let bytes = hex_to_bytes(extra_sig).map_err(|_| FragmentError::InvalidReceipt)?;
            let keys = self
                .transparency_trust_list
                .get(extra_ledger)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let matched = validating_subjects(keys, statement, &bytes)
                .ok_or(FragmentError::InvalidReceipt)?;
            validated.push(ValidatedReceipt {
                ledger: extra_ledger.clone(),
                ttl_subjects: matched,
            });
        }

        // 5c. FR-1f: the scope's requirement list is a conjunction — *every* entry must be
        //     met by some validated receipt. Matches hcsshim's `fragment_receipts_ok`, which
        //     uses `every` over `required_receipts`. A bare ledger id keeps its old meaning,
        //     so single-entry configurations are unaffected.
        if let Some(reqs) = required {
            for r in reqs {
                let req = ReceiptRequirement::parse(r);
                if !req.satisfied_by(&validated) {
                    return match req {
                        ReceiptRequirement::Ledger(l) => {
                            Err(FragmentError::ReceiptFromDisallowedLedger {
                                required: l,
                                presented: validated
                                    .iter()
                                    .map(|v| v.ledger.clone())
                                    .collect::<Vec<_>>()
                                    .join(","),
                            })
                        }
                        _ => Err(FragmentError::UnsatisfiedReceiptRequirement {
                            requirement: r.clone(),
                        }),
                    };
                }
            }
        }

        // 6. FR-1g: every required (dependency) fragment must already be loaded.
        for req in &fragment.requires {
            if !self.loaded_ids.contains(req) {
                return Err(FragmentError::UnsatisfiedRequirement {
                    requires: req.clone(),
                });
            }
        }

        // 7. FR-1j: append-only ordering. In ordered mode the fragment's signed
        //    `prev_log_head` must equal the store's current head, so any reordering,
        //    omission, or insertion (which would present a different predecessor head) is
        //    rejected fail-closed. `prev_log_head` is bound into `signing_bytes`, so the
        //    untrusted delivery path cannot forge it.
        let stmt_sha256: [u8; 32] = Sha256::digest(statement).into();
        if self.log_genesis.is_some() {
            let presented = fragment.prev_log_head.as_deref().unwrap_or(&[]);
            if presented != self.log_head.as_slice() {
                return Err(FragmentError::LogHeadMismatch {
                    expected: bytes_to_hex(&self.log_head),
                    presented: bytes_to_hex(presented),
                });
            }
        }

        Ok(VerifiedFragment {
            issuer: fragment.issuer.clone(),
            feed: fragment.feed.clone(),
            svn: fragment.svn,
            id: fragment.id(),
            policy_module: fragment.policy_module.clone(),
            includes: fragment.includes.clone(),
            stmt_sha256,
            ttl_head,
        })
    }

    /// Commit a previously [`verify`](Self::verify)-ed fragment: advance the `(issuer, feed)`
    /// SVN high-water mark and record the fragment id (for composition).
    ///
    /// F-159: the mark is **raise-only**, like `ttl_heads` below. `verify` already refuses
    /// anything at or under the current mark, so in a serialized sequence this is a no-op —
    /// but an unconditional insert makes the anti-rollback invariant depend on the caller
    /// never committing two fragments out of order, and that is exactly what a concurrent
    /// pair of loads does. Keeping it local means a lost race can at worst fail to advance
    /// the mark; it can never move it backwards, and never write a lowered value through
    /// `export_svn_state` into the sealed store.
    pub fn commit(&mut self, verified: &VerifiedFragment) {
        let mark = self
            .last_svn
            .entry((verified.issuer.clone(), verified.feed.clone()))
            .or_insert(verified.svn);
        *mark = (*mark).max(verified.svn);
        self.loaded_ids.insert(verified.id.clone());
        // FR-1j: advance the append-only ordering log head (ordered mode only).
        if self.log_genesis.is_some() {
            let mut h = Sha256::new();
            h.update(&self.log_head);
            h.update(verified.stmt_sha256);
            self.log_head = h.finalize().to_vec();
            self.ordered_log
                .push((verified.id.clone(), verified.stmt_sha256));
            self.log_len += 1;
        }
        // FR-1f Stage 2: advance the per-ledger transparency tree head (raise-only by size).
        if let Some((ledger, size, root)) = &verified.ttl_head {
            let entry = self
                .ttl_heads
                .entry(ledger.clone())
                .or_insert((0, [0u8; 32]));
            if *size >= entry.0 {
                *entry = (*size, *root);
            }
        }
    }

    /// Verify and commit a fragment in one step. On any failure the store is left unchanged
    /// (fail-closed).
    ///
    /// Callers that must apply the fragment's Rego module to the policy engine cannot use
    /// this: they need [`verify_envelope`](Self::verify_envelope), then the apply, then
    /// [`commit`](Self::commit), so a failed apply leaves the store untouched.
    pub fn load_envelope(&mut self, cose_sign1: &[u8]) -> Result<(), FragmentError> {
        let verified = self.verify_envelope(cose_sign1)?;
        self.commit(&verified);
        Ok(())
    }

    /// FR-1i: export the per-`(issuer, feed)` SVN high-water marks as a stable text snapshot
    /// (`issuer\tfeed\tsvn` per line) for persistence to a sealed/measured store. Sorted
    /// for determinism.
    pub fn export_svn_state(&self) -> String {
        let mut lines: Vec<String> = self
            .last_svn
            .iter()
            .map(|((issuer, feed), svn)| format!("{issuer}\t{feed}\t{svn}"))
            .collect();
        lines.sort();
        // FR-1j: persist the ordering log head + length (raise-only on import) so a restart
        // cannot rewind the append-only log position. Uses a reserved sentinel key that can
        // never collide with an issuer id (issuers cannot contain a tab).
        if self.log_genesis.is_some() {
            lines.push(format!(
                "{LOG_STATE_KEY}\t{}\t{}",
                bytes_to_hex(&self.log_head),
                self.log_len
            ));
        }
        // FR-1f Stage 2: persist each ledger's last-seen transparency tree head (raise-only).
        let mut ttl: Vec<String> = self
            .ttl_heads
            .iter()
            .map(|(ledger, (size, root))| {
                format!("{TTL_STATE_KEY}\t{ledger}\t{size}\t{}", bytes_to_hex(root))
            })
            .collect();
        ttl.sort();
        lines.extend(ttl);
        lines.join("\n")
    }

    /// FR-1i: import a persisted SVN snapshot on boot. Each entry can only **raise** the
    /// high-water mark for its `(issuer, feed)`, never lower it — so an agent/VM restart can
    /// never reopen a rollback window (a fragment at or below a previously-accepted SVN
    /// stays rejected). Combined with the declarative floor (FR-1e), the effective minimum
    /// is `max(declared floor, persisted high-water + 1)`. FR-1j restores the ordering log
    /// head and FR-1f Stage 2 the per-ledger transparency tree head, both raise-only, so
    /// neither can be rewound across a restart.
    pub fn import_svn_state(&mut self, snapshot: &str) {
        for line in snapshot.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            match parts.as_slice() {
                [k, head, len] if *k == LOG_STATE_KEY => {
                    // FR-1j: ordering log head + length. Raise-only.
                    if let (Ok(head), Ok(len)) = (hex_to_bytes(head), len.trim().parse::<u64>()) {
                        if len >= self.log_len {
                            self.log_head = head;
                            self.log_len = len;
                        }
                    }
                }
                [k, ledger, size, root] if *k == TTL_STATE_KEY => {
                    // FR-1f Stage 2: transparency tree head. Raise-only by size.
                    if let (Ok(size), Ok(root)) = (size.trim().parse::<u64>(), hex_to_bytes(root)) {
                        if root.len() == 32 {
                            let mut r = [0u8; 32];
                            r.copy_from_slice(&root);
                            let entry = self
                                .ttl_heads
                                .entry(ledger.to_string())
                                .or_insert((0, [0u8; 32]));
                            if size >= entry.0 {
                                *entry = (size, r);
                            }
                        }
                    }
                }
                [issuer, feed, svn] => {
                    if let Ok(svn) = svn.trim().parse::<u64>() {
                        let entry = self
                            .last_svn
                            .entry((issuer.to_string(), feed.to_string()))
                            .or_insert(0);
                        *entry = (*entry).max(svn);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Reserved sentinel key for the FR-1j ordering-log state line in the SVN snapshot.
const LOG_STATE_KEY: &str = "--log-state--";
/// Reserved sentinel key for the FR-1f Stage 2 per-ledger tree-head state line.
const TTL_STATE_KEY: &str = "--ttl-head--";

/// FR-1f Stage 2: the bytes a transparency ledger signs to attest a tree head — binds the
/// ledger id, tree size, and Merkle root so a signed head cannot be replayed for a different
/// ledger or size. Public so ledger tooling/tests produce byte-identical signed heads.
pub fn sth_signing_bytes(ledger: &str, size: u64, root: &[u8; 32]) -> Vec<u8> {
    format!("kata-sth/v1\n{ledger}\n{size}\n{}", bytes_to_hex(root)).into_bytes()
}

/// FR-1f Stage 2: encode a `kata-ttl-proof/v1` transparency proof exactly as the verifier
/// parses it (signed tree head + inclusion proof + optional consistency proof). Used by the
/// mock-ledger dev tool, the demo, and tests so the wire format has a single source of truth.
pub fn encode_transparency_proof(
    size: u64,
    root: &[u8; 32],
    sig: &[u8],
    index: u64,
    incl: &[[u8; 32]],
    cons: &[[u8; 32]],
) -> String {
    let join = |v: &[[u8; 32]]| v.iter().map(bytes_to_hex_arr).collect::<Vec<_>>().join(",");
    format!(
        "kata-ttl-proof/v1\nsize={}\nroot={}\nsig={}\nindex={}\nincl={}\ncons={}\n",
        size,
        bytes_to_hex(root),
        bytes_to_hex(sig),
        index,
        join(incl),
        join(cons)
    )
}

fn bytes_to_hex_arr(b: &[u8; 32]) -> String {
    bytes_to_hex(b)
}

/// FR-1f Stage 2: a parsed `kata-ttl-proof/v1` transparency proof (signed tree head +
/// inclusion proof + optional consistency proof).
struct TransparencyProof {
    size: u64,
    root: [u8; 32],
    sig: Vec<u8>,
    index: u64,
    incl: Vec<[u8; 32]>,
    cons: Vec<[u8; 32]>,
}

impl TransparencyProof {
    fn parse(s: &str) -> Option<Self> {
        let mut size = None;
        let mut root = None;
        let mut sig = None;
        let mut index = None;
        let mut incl = Vec::new();
        let mut cons = Vec::new();
        let mut header_ok = false;
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line == "kata-ttl-proof/v1" {
                header_ok = true;
                continue;
            }
            let (k, v) = line.split_once('=')?;
            match k {
                "size" => size = v.trim().parse::<u64>().ok(),
                "root" => root = parse_hash32(v),
                "sig" => sig = hex_to_bytes(v).ok(),
                "index" => index = v.trim().parse::<u64>().ok(),
                "incl" => incl = parse_hash_list(v)?,
                "cons" => cons = parse_hash_list(v)?,
                _ => {}
            }
        }
        if !header_ok {
            return None;
        }
        Some(TransparencyProof {
            size: size?,
            root: root?,
            sig: sig?,
            index: index?,
            incl,
            cons,
        })
    }
}

/// BL-6: a parsed `kata-ccf-proof/v1` receipt — a SCITT CCF-profile inclusion proof
/// (`proof`, CBOR `ccf-inclusion-proof`) plus the ledger's signature (`sig`) over the
/// recomputed 32-byte Merkle root. Interoperates with external transparency ledgers
/// (Azure Confidential Ledger / CCF-based SCITT), unlike the native `kata-ttl-proof/v1`.
struct CcfReceipt {
    proof_cbor: Vec<u8>,
    sig: Vec<u8>,
}

impl CcfReceipt {
    fn parse(s: &str) -> Option<Self> {
        let mut proof_cbor = None;
        let mut sig = None;
        let mut header_ok = false;
        for line in s.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line == "kata-ccf-proof/v1" {
                header_ok = true;
                continue;
            }
            let (k, v) = line.split_once('=')?;
            match k {
                "proof" => proof_cbor = hex_to_bytes(v).ok(),
                "sig" => sig = hex_to_bytes(v).ok(),
                _ => {}
            }
        }
        if !header_ok {
            return None;
        }
        Some(CcfReceipt {
            proof_cbor: proof_cbor?,
            sig: sig?,
        })
    }
}

fn parse_hash32(v: &str) -> Option<[u8; 32]> {
    let b = hex_to_bytes(v).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&b);
    Some(h)
}

fn parse_hash_list(v: &str) -> Option<Vec<[u8; 32]>> {
    let v = v.trim();
    if v.is_empty() {
        return Some(Vec::new());
    }
    v.split(',').map(|e| parse_hash32(e.trim())).collect()
}

/// Lower-case hex encoding.
fn bytes_to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

/// Decode a hex string into bytes.
fn hex_to_bytes(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Build the COSE_Sign1 a signer would produce for `f`, without the signature. The
    /// `Sig_structure` does not depend on the signature, so this is also how a test computes
    /// the bytes a *receipt* has to countersign.
    fn unsigned(f: &PolicyFragment) -> coset::CoseSign1 {
        f.to_unsigned_cose(coset::iana::Algorithm::EdDSA)
    }

    /// The bytes the issuer signs and every receipt countersigns.
    fn tbs_of(f: &PolicyFragment) -> Vec<u8> {
        unsigned(f).tbs_data(b"")
    }

    /// Sign `f` into a COSE_Sign1 envelope with an Ed25519 issuer key.
    fn envelope(sk: &SigningKey, f: &PolicyFragment) -> Vec<u8> {
        use coset::CborSerializable;
        let mut s = unsigned(f);
        s.signature = sk.sign(&s.tbs_data(b"")).to_bytes().to_vec();
        s.to_vec().expect("serialize COSE_Sign1")
    }

    /// Verify `f` the way the guest does: hand the store **only** the envelope, plus the
    /// receipts that legitimately travel outside it.
    ///
    /// Tests describe a fragment and then check what the verifier makes of it, so this is
    /// where the two are deliberately separated — the store never sees the struct the test
    /// built, only the bytes that were signed.
    fn verify(
        store: &FragmentStore,
        sk: &SigningKey,
        f: &PolicyFragment,
    ) -> Result<VerifiedFragment, FragmentError> {
        store.verify_envelope_with(&envelope(sk, f), |g| {
            g.receipt = f.receipt.clone();
            g.receipt_ledger = f.receipt_ledger.clone();
            g.receipt_proof = f.receipt_proof.clone();
            g.extra_receipts = f.extra_receipts.clone();
        })
    }

    /// Verify and commit the way [`FragmentStore::load_envelope`] does, but with the
    /// out-of-envelope receipts attached — the test-side equivalent of what the RPC does.
    fn load(
        store: &mut FragmentStore,
        sk: &SigningKey,
        f: &PolicyFragment,
    ) -> Result<(), FragmentError> {
        let verified = verify(store, sk, f)?;
        store.commit(&verified);
        Ok(())
    }

    fn frag(issuer: &str, svn: u64, includes: &[&str]) -> PolicyFragment {
        PolicyFragment {
            issuer: issuer.to_string(),
            svn,
            includes: includes.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// BL-8: `from_cose_envelope` reconstructs exactly the fields the envelope commits to,
    /// so a boot-pulled envelope can be run through the SRM gates with nothing supplied
    /// alongside it. Round-trips issuer/feed/SVN/module/includes/requires and the
    /// FR-1j predecessor head, and the reconstruction must re-derive the identical
    /// `Sig_structure` — the bytes the signature is actually checked against.
    #[test]
    fn from_cose_envelope_roundtrips_every_signed_field() {
        let (sk, _pk) = keypair(1);
        let f = PolicyFragment {
            issuer: "did:x509:0:sha256:AAAA::CN:signer".into(),
            feed: "contoso.azurecr.io/frag/infra:1".into(),
            svn: 7,
            policy_module: Some(
                "package agent_policy.fragments\nallow := true\n# multi-line\nx := 1".into(),
            ),
            includes: vec!["exec".into(), "mount".into()],
            requires: vec!["did:x509:0:sha256:BBBB::CN:dep/feed/2".into()],
            prev_log_head: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            ..Default::default()
        };
        let cose = envelope(&sk, &f);
        let parsed = PolicyFragment::from_cose_envelope(&cose).expect("parse envelope");
        assert_eq!(parsed.issuer, f.issuer);
        assert_eq!(parsed.feed, f.feed);
        assert_eq!(parsed.svn, f.svn);
        assert_eq!(parsed.policy_module, f.policy_module);
        assert_eq!(parsed.includes, f.includes);
        assert_eq!(parsed.requires, f.requires);
        assert_eq!(parsed.prev_log_head, f.prev_log_head);
        assert_eq!(parsed.signed_bytes(), tbs_of(&f));

        // Minimal fragment (no module/includes/requires/prevhead) also round-trips,
        // and an absent payload means an absent module rather than an empty one.
        let bare = PolicyFragment {
            issuer: "iss".into(),
            feed: "feed".into(),
            svn: 1,
            ..Default::default()
        };
        let bp = PolicyFragment::from_cose_envelope(&envelope(&sk, &bare)).unwrap();
        assert_eq!(bp.signed_bytes(), tbs_of(&bare));
        assert!(bp.policy_module.is_none() && bp.prev_log_head.is_none());
    }

    /// TC-F1.5: a declarative minimum-SVN floor (from measured state) is enforced — a
    /// fragment below the floor is rejected, one at/above the floor is accepted.
    #[test]
    fn min_svn_floor_is_enforced() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store.set_min_svn("issuerA", 5);

        let mut below = frag("issuerA", 4, &["exec:x"]);
        assert!(matches!(
            load(&mut store, &sk, &below).unwrap_err(),
            FragmentError::RolledBackSvn {
                min_required: 5,
                ..
            }
        ));

        let mut at_floor = frag("issuerA", 5, &["exec:x"]);
        assert!(load(&mut store, &sk, &at_floor).is_ok());
    }

    /// TC-F1.6: with no authorized issuers (absent measured config), every fragment is
    /// rejected — fail-closed.
    #[test]
    fn no_authorized_issuers_is_fail_closed() {
        let (sk, _pk) = keypair(1);
        let mut store = FragmentStore::new(true);
        assert!(!store.has_authorized_issuers());
        let mut f = frag("issuerA", 1, &["exec:x"]);
        assert_eq!(
            load(&mut store, &sk, &f).unwrap_err(),
            FragmentError::UnauthorizedIssuer("issuerA".into())
        );
    }

    /// TC-F1.7 / TC-F1.8: the contributed Rego module and the `includes` scope are bound
    /// into the signature — mutating either invalidates it.
    #[test]
    fn module_and_includes_are_signature_bound() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();

        let mut f = PolicyFragment {
            issuer: "issuerA".into(),
            svn: 1,
            policy_module: Some("package agent_policy.fragments\nexec_allowed := true".into()),
            includes: vec!["exec".into()],
            ..Default::default()
        };
        let v = verify(&store, &sk, &f).unwrap();
        assert_eq!(v.includes, vec!["exec".to_string()]);
        assert!(v.policy_module.is_some());

        // Tamper the module (the payload) after signing.
        use coset::CborSerializable;
        let mut tampered = coset::CoseSign1::from_slice(&envelope(&sk, &f)).unwrap();
        tampered.payload =
            Some(b"package agent_policy.fragments\nexec_allowed := true # evil".to_vec());
        assert_eq!(
            store
                .verify_envelope(&tampered.to_vec().unwrap())
                .unwrap_err(),
            FragmentError::InvalidSignature
        );

        // Tamper `includes` (a protected header) after signing. The protected bytes are
        // inside the `Sig_structure`, so re-serializing the header is enough to break it.
        let mut swapped = f.clone();
        swapped.includes = vec!["mount".into()];
        let mut tampered2 = coset::CoseSign1::from_slice(&envelope(&sk, &f)).unwrap();
        tampered2.protected = coset::CoseSign1::from_slice(&envelope(&sk, &swapped))
            .unwrap()
            .protected;
        assert_eq!(
            store
                .verify_envelope(&tampered2.to_vec().unwrap())
                .unwrap_err(),
            FragmentError::InvalidSignature
        );
    }

    /// TC-F1.4 (store half): verify does not mutate; commit does — supporting atomic
    /// verify→apply→commit at the call site.
    #[test]
    fn verify_is_side_effect_free_until_commit() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        let mut f = frag("issuerA", 7, &["exec:x"]);

        let v = verify(&store, &sk, &f).unwrap();
        // Not committed yet: the SVN has not advanced, so a re-verify still succeeds.
        assert!(verify(&store, &sk, &f).is_ok());

        store.commit(&v);
        // After commit the same SVN is now a rollback.
        assert!(matches!(
            verify(&store, &sk, &f).unwrap_err(),
            FragmentError::RolledBackSvn { .. }
        ));
    }

    /// TC4.8: a valid signed fragment (with receipt) is accepted, and the commit takes —
    /// a replay of the same SVN is refused afterwards.
    #[test]
    fn valid_signed_fragment_is_accepted() {
        let (sk, pk) = keypair(1);
        let (ledger_sk, ledger_pk) = keypair(20);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store
            .load_transparency_trust_list(&[("ledgerA".into(), vec![ledger_pk])])
            .unwrap();
        let mut f = frag("issuerA", 1, &["exec:container-x"]);
        signed_with_receipt(&sk, &mut f, "ledgerA", &ledger_sk);
        load(&mut store, &sk, &f).expect("valid signed fragment must be accepted");
        assert!(matches!(
            verify(&store, &sk, &f).unwrap_err(),
            FragmentError::RolledBackSvn { .. }
        ));
    }

    /// TC4.4: an envelope carrying an empty or garbage signature is rejected.
    ///
    /// The envelope format makes this harder to reach by accident than v3 did — a fragment
    /// only exists as bytes once something has signed it — so the signature is emptied and
    /// then corrupted explicitly, which is the shape an attacker would submit.
    #[test]
    fn unsigned_fragment_is_rejected() {
        use coset::CborSerializable;

        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &pk).unwrap();
        let f = frag("issuerA", 1, &["exec:x"]);

        for (label, sig) in [
            ("empty signature", Vec::new()),
            ("garbage signature", vec![0u8; 64]),
        ] {
            let mut cose = coset::CoseSign1::from_slice(&envelope(&sk, &f)).unwrap();
            cose.signature = sig;
            assert_eq!(
                store.verify_envelope(&cose.to_vec().unwrap()).unwrap_err(),
                FragmentError::InvalidSignature,
                "{label}"
            );
        }
    }

    /// TC4.5: a fragment from an unauthorized issuer is rejected.
    #[test]
    fn unauthorized_issuer_is_rejected() {
        let (sk, _pk) = keypair(1);
        let store_pk = keypair(2).1; // a different, authorized key
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &store_pk).unwrap();
        // Fragment claims issuerA but is signed with the wrong key.
        let mut f = frag("issuerA", 1, &["exec:x"]);
        assert_eq!(load(&mut store, &sk, &f).unwrap_err(), FragmentError::InvalidSignature);

        // Fragment from a completely unknown issuer.
        let mut g = frag("issuerB", 1, &["exec:x"]);
        assert_eq!(
            load(&mut store, &sk, &g).unwrap_err(),
            FragmentError::UnauthorizedIssuer("issuerB".into())
        );
    }

    /// TC4.6: a rolled-back / replayed SVN is rejected (monotonic SVN).
    #[test]
    fn rolled_back_svn_is_rejected() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();

        let mut f5 = frag("issuerA", 5, &["exec:x"]);
        load(&mut store, &sk, &f5).unwrap();

        // Replay same SVN.
        let mut f5b = frag("issuerA", 5, &["exec:y"]);
        assert!(matches!(
            load(&mut store, &sk, &f5b).unwrap_err(),
            FragmentError::RolledBackSvn { .. }
        ));

        // Older SVN.
        let mut f3 = frag("issuerA", 3, &["exec:z"]);
        assert!(matches!(
            load(&mut store, &sk, &f3).unwrap_err(),
            FragmentError::RolledBackSvn { .. }
        ));

        // Strictly greater SVN is accepted.
        let mut f6 = frag("issuerA", 6, &["exec:w"]);
        assert!(load(&mut store, &sk, &f6).is_ok());
    }

    /// A fragment with no transparency receipt is rejected when receipts are enforced.
    #[test]
    fn missing_receipt_is_rejected_in_strict() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &pk).unwrap();
        let mut f = frag("issuerA", 1, &["exec:x"]);
        f.receipt = None;
        assert_eq!(load(&mut store, &sk, &f).unwrap_err(), FragmentError::MissingReceipt);
    }

    fn frag_feed(issuer: &str, feed: &str, svn: u64) -> PolicyFragment {
        PolicyFragment {
            issuer: issuer.to_string(),
            feed: feed.to_string(),
            svn,
            ..Default::default()
        }
    }

    /// Helper: build a ledger-signed receipt (hex) over a fragment's statement, tag its
    /// ledger id, and issuer-sign the fragment.
    fn signed_with_receipt(
        issuer_sk: &SigningKey,
        f: &mut PolicyFragment,
        ledger: &str,
        ledger_sk: &SigningKey,
    ) {
        let rsig = ledger_sk.sign(&tbs_of(&f));
        f.receipt = Some(
            rsig.to_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        );
        f.receipt_ledger = Some(ledger.to_string());
    }

    /// TC-F1.22 (FR-1f trust list): a multi-ledger trust list accepts a receipt from an
    /// allowed ledger whose key signed the statement.
    #[test]
    fn trust_list_accepts_allowed_ledger() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (ledger_a_sk, ledger_a_pk) = keypair(20);
        let (_ledger_b_sk, ledger_b_pk) = keypair(21);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[
                ("ledgerA".into(), vec![ledger_a_pk]),
                ("ledgerB".into(), vec![ledger_b_pk]),
            ])
            .unwrap();

        let mut f = frag_feed("issuerA", "", 1);
        signed_with_receipt(&issuer_sk, &mut f, "ledgerA", &ledger_a_sk);
        assert!(verify(&store, &issuer_sk, &f).is_ok());

        // A receipt tagged for ledgerB but signed by ledgerA's key does not verify against
        // ledgerB's key -> InvalidReceipt (a forged ledger id cannot bypass verification).
        f.receipt_ledger = Some("ledgerB".into());
        assert_eq!(verify(&store, &issuer_sk, &f).unwrap_err(), FragmentError::InvalidReceipt);
    }

    /// TC-F1.23 (FR-1f trust list): a receipt from a ledger outside the scope's
    /// `allowed_ledgers` is rejected even if its signature is otherwise valid.
    #[test]
    fn trust_list_rejects_disallowed_ledger() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (ledger_a_sk, ledger_a_pk) = keypair(20);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[("ledgerA".into(), vec![ledger_a_pk])])
            .unwrap();
        // Only ledgerB is allowed for the default feed, but the receipt is from ledgerA.
        store.set_allowed_ledgers("issuerA", "", &["ledgerB".to_string()]);

        let mut f = frag_feed("issuerA", "", 1);
        signed_with_receipt(&issuer_sk, &mut f, "ledgerA", &ledger_a_sk);
        assert_eq!(
            verify(&store, &issuer_sk, &f).unwrap_err(),
            FragmentError::LedgerNotAllowed {
                issuer: "issuerA".into(),
                feed: "".into(),
                ledger: "ledgerA".into(),
            }
        );
    }

    /// Helper: append an additional ledger-signed Stage-1 receipt, then re-sign as issuer.
    /// Order matters: `extra_receipts` is not part of `signing_bytes`, but the issuer
    /// signature is recomputed here so the helper is safe to call at any point.
    fn add_extra_receipt(
        issuer_sk: &SigningKey,
        f: &mut PolicyFragment,
        ledger: &str,
        ledger_sk: &SigningKey,
    ) {
        let sig = ledger_sk.sign(&tbs_of(&f));
        let hex: String = sig.to_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        f.extra_receipts.push((ledger.to_string(), hex));
    }

    /// FR-1f (trust list): `required_receipts` is a conjunction, matching hcsshim's `every`
    /// over the list. Two named ledgers need two validated receipts; one is not enough.
    #[test]
    fn required_receipts_are_conjunctive() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (ledger_a_sk, ledger_a_pk) = keypair(20);
        let (ledger_b_sk, ledger_b_pk) = keypair(21);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store.declare_feed("issuerA", "prod", 0);
        store
            .load_transparency_trust_list(&[
                ("ledgerA".into(), vec![ledger_a_pk]),
                ("ledgerB".into(), vec![ledger_b_pk]),
            ])
            .unwrap();
        store.require_receipt_for("issuerA", "prod", &["ledgerA".into(), "ledgerB".into()]);

        // Only ledgerA's receipt -> the ledgerB entry is unmet.
        let mut one = frag_feed("issuerA", "prod", 1);
        signed_with_receipt(&issuer_sk, &mut one, "ledgerA", &ledger_a_sk);
        assert!(matches!(
            verify(&store, &issuer_sk, &one).unwrap_err(),
            FragmentError::ReceiptFromDisallowedLedger { .. }
        ));

        // Both -> accepted.
        let mut both = frag_feed("issuerA", "prod", 1);
        signed_with_receipt(&issuer_sk, &mut both, "ledgerA", &ledger_a_sk);
        add_extra_receipt(&issuer_sk, &mut both, "ledgerB", &ledger_b_sk);
        assert!(verify(&store, &issuer_sk, &both).is_ok(), "{:?}", verify(&store, &issuer_sk, &both));
    }

    /// FR-1f (trust list): an extra receipt must itself verify — presenting a second ledger
    /// id signed by the wrong key does not launder the requirement.
    #[test]
    fn extra_receipt_must_verify() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (ledger_a_sk, ledger_a_pk) = keypair(20);
        let (_, ledger_b_pk) = keypair(21);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store.declare_feed("issuerA", "prod", 0);
        store
            .load_transparency_trust_list(&[
                ("ledgerA".into(), vec![ledger_a_pk]),
                ("ledgerB".into(), vec![ledger_b_pk]),
            ])
            .unwrap();
        store.require_receipt_for("issuerA", "prod", &["ledgerA".into(), "ledgerB".into()]);

        let mut f = frag_feed("issuerA", "prod", 1);
        signed_with_receipt(&issuer_sk, &mut f, "ledgerA", &ledger_a_sk);
        // ledgerB's slot is signed by ledgerA's key.
        add_extra_receipt(&issuer_sk, &mut f, "ledgerB", &ledger_a_sk);
        assert_eq!(verify(&store, &issuer_sk, &f).unwrap_err(), FragmentError::InvalidReceipt);
    }

    /// FR-1f (trust list): `"*"` requires *a* validated receipt without naming a ledger,
    /// and `"TTL:<subject>"` requires one validated by a key that Trust List subject
    /// vouched for — a key with no recorded provenance does not satisfy it.
    #[test]
    fn wildcard_and_ttl_receipt_requirements() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (ledger_a_sk, ledger_a_pk) = keypair(20);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store.declare_feed("issuerA", "prod", 0);
        store.declare_feed("issuerA", "ttl", 0);
        // ledgerA has no Trust List provenance recorded.
        store
            .load_transparency_trust_list(&[("ledgerA".into(), vec![ledger_a_pk])])
            .unwrap();
        store.require_receipt_for("issuerA", "prod", &["*".into()]);
        store.require_receipt_for("issuerA", "ttl", &["TTL:vendor".into()]);

        // "*" is met by any validated receipt, whatever its ledger.
        let mut any = frag_feed("issuerA", "prod", 1);
        signed_with_receipt(&issuer_sk, &mut any, "ledgerA", &ledger_a_sk);
        assert!(verify(&store, &issuer_sk, &any).is_ok());

        // "*" still requires a receipt to exist.
        let mut none = frag_feed("issuerA", "prod", 1);
        none.receipt = None;
        assert_eq!(
            verify(&store, &issuer_sk, &none).unwrap_err(),
            FragmentError::MissingReceipt
        );

        // "TTL:vendor" is unmet while no key claims that subject.
        let mut ttl = frag_feed("issuerA", "ttl", 1);
        signed_with_receipt(&issuer_sk, &mut ttl, "ledgerA", &ledger_a_sk);
        assert!(matches!(
            verify(&store, &issuer_sk, &ttl).unwrap_err(),
            FragmentError::UnsatisfiedReceiptRequirement { .. }
        ));

        // Record the provenance and the same fragment is accepted.
        let (_, ledger_a_pk2) = keypair(20);
        store
            .load_trust_list_with_subjects("ledgerA", &[ledger_a_pk2], &["vendor".to_string()])
            .unwrap();
        assert!(verify(&store, &issuer_sk, &ttl).is_ok(), "{:?}", verify(&store, &issuer_sk, &ttl));
    }

    /// TC-F1.24 (FR-1f trust list): policy-driven `required_receipts` per feed — feed
    /// "prod" requires a receipt from a specific ledger; feed "dev" requires none.
    #[test]
    fn per_feed_required_receipts_enforced() {        let (issuer_sk, issuer_pk) = keypair(1);
        let (ledger_a_sk, ledger_a_pk) = keypair(20);
        // Global receipt requirement off; requirement is expressed per-scope instead.
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store.declare_feed("issuerA", "prod", 0);
        store.declare_feed("issuerA", "dev", 0);
        store
            .load_transparency_trust_list(&[("ledgerA".into(), vec![ledger_a_pk])])
            .unwrap();
        store.require_receipt_for("issuerA", "prod", &["ledgerA".to_string()]);

        // prod without a receipt -> MissingReceipt.
        let mut prod_no = frag_feed("issuerA", "prod", 1);
        prod_no.receipt = None;
        assert_eq!(
            verify(&store, &issuer_sk, &prod_no).unwrap_err(),
            FragmentError::MissingReceipt
        );

        // prod with a receipt from a different ledger -> ReceiptFromDisallowedLedger.
        let mut prod_wrong = frag_feed("issuerA", "prod", 1);
        signed_with_receipt(&issuer_sk, &mut prod_wrong, "ledgerZ", &ledger_a_sk);
        assert!(matches!(
            verify(&store, &issuer_sk, &prod_wrong).unwrap_err(),
            FragmentError::ReceiptFromDisallowedLedger { .. }
        ));

        // prod with a valid receipt from the required ledger -> accepted.
        let mut prod_ok = frag_feed("issuerA", "prod", 1);
        signed_with_receipt(&issuer_sk, &mut prod_ok, "ledgerA", &ledger_a_sk);
        assert!(verify(&store, &issuer_sk, &prod_ok).is_ok());

        // dev with no receipt -> accepted (no per-scope requirement, global off).
        let mut dev_no = frag_feed("issuerA", "dev", 1);
        dev_no.receipt = None;
        assert!(verify(&store, &issuer_sk, &dev_no).is_ok());
    }

    /// TC-F1.25 (FR-1f trust list): ledger key rotation — receipts signed by either the old
    /// or the new key of a ledger both verify.
    #[test]
    fn ledger_key_rotation() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (old_sk, old_pk) = keypair(20);
        let (new_sk, new_pk) = keypair(22);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        // Both keys are current for the same ledger (rotation window).
        store
            .load_transparency_trust_list(&[("ledgerA".into(), vec![old_pk, new_pk])])
            .unwrap();

        let mut f_old = frag_feed("issuerA", "", 1);
        signed_with_receipt(&issuer_sk, &mut f_old, "ledgerA", &old_sk);
        assert!(verify(&store, &issuer_sk, &f_old).is_ok());

        let mut f_new = frag_feed("issuerA", "", 2);
        signed_with_receipt(&issuer_sk, &mut f_new, "ledgerA", &new_sk);
        assert!(verify(&store, &issuer_sk, &f_new).is_ok());
    }

    /// TC-F1.26 (FR-1f back-compat): a legacy single-anchor configuration (mapped to the
    /// default ledger) behaves exactly as before — a valid anchor signature over the
    /// statement is accepted; a bogus receipt is rejected. Preserves TC-F1.15/16 semantics.
    #[test]
    fn legacy_single_anchor_backcompat() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (anchor_sk, anchor_pk) = keypair(9);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store.set_transparency_anchor(&anchor_pk).unwrap(); // -> default ledger

        // Legacy fragment: no receipt_ledger set (defaults to the default ledger).
        let mut f = frag_feed("issuerA", "", 1);
        f.receipt = Some("deadbeef".into());
        f.receipt_ledger = None;
        assert_eq!(verify(&store, &issuer_sk, &f).unwrap_err(), FragmentError::InvalidReceipt);

        let rsig = anchor_sk.sign(&tbs_of(&f));
        f.receipt = Some(
            rsig.to_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        );
        assert!(verify(&store, &issuer_sk, &f).is_ok());
    }

    /// TC-F1.13 (FR-1e): a fragment for an undeclared (issuer, feed) is rejected.
    #[test]
    fn undeclared_feed_is_rejected() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap(); // declares default feed only
        let mut f = frag_feed("issuerA", "prod", 1);
        assert_eq!(
            load(&mut store, &sk, &f).unwrap_err(),
            FragmentError::UndeclaredFeed {
                issuer: "issuerA".into(),
                feed: "prod".into()
            }
        );
        // After declaring the feed, the same fragment is accepted.
        store.declare_feed("issuerA", "prod", 0);
        assert!(load(&mut store, &sk, &f).is_ok());
    }

    /// TC-F1.14 (FR-1e): the SVN floor is enforced per (issuer, feed) independently.
    #[test]
    fn svn_floor_is_per_feed() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store.declare_feed("issuerA", "prod", 10);
        store.declare_feed("issuerA", "test", 0);

        // prod floor is 10: svn 5 rejected.
        let mut low = frag_feed("issuerA", "prod", 5);
        assert!(matches!(
            load(&mut store, &sk, &low).unwrap_err(),
            FragmentError::RolledBackSvn {
                min_required: 10,
                ..
            }
        ));
        // test feed floor is 0: svn 1 accepted (independent of prod).
        let mut t = frag_feed("issuerA", "test", 1);
        assert!(load(&mut store, &sk, &t).is_ok());
        // prod at floor accepted.
        let mut p = frag_feed("issuerA", "prod", 10);
        assert!(load(&mut store, &sk, &p).is_ok());
    }

    /// TC-F1.24 (FR-1i): a per-feed floor may raise the issuer-wide floor but never lower
    /// it. `set_min_svn` records the trust root's issuer-wide floor under `(issuer, "")`,
    /// while a named feed carries its own entry; consulting only the named entry let a
    /// feed declared with `min_svn = 0` accept a fragment the attested floor forbids.
    #[test]
    fn per_feed_floor_cannot_sink_below_the_issuer_floor() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store.set_min_svn("issuerA", 5);
        // A laxer per-feed floor must not win.
        store.declare_feed("issuerA", "prod", 0);

        let mut below = frag_feed("issuerA", "prod", 4);
        assert!(matches!(
            load(&mut store, &sk, &below).unwrap_err(),
            FragmentError::RolledBackSvn { min_required: 5, .. }
        ));

        let mut at_floor = frag_feed("issuerA", "prod", 5);
        assert!(load(&mut store, &sk, &at_floor).is_ok());
    }

    /// F-165 (FR-1e/FR-1i): a later feed declaration may raise the floor, never lower it.
    ///
    /// Three sources declare feeds into this map. Two are measured, in a fixed order: the
    /// trust root at boot (`seed_fragment_trust_root`, from the operator's attested
    /// `fragment-issuers.toml`), then the base policy (`record_declared_fragments`, from
    /// the per-pod `policy_fragments[]`). The third is **not** measured:
    /// `register_nested_fragments` declares feeds carried in a delivered fragment's own
    /// signed module. All three used the same key, so a plain `insert` let a later one
    /// silently discard an earlier floor.
    ///
    /// The nested path is the sharper of the two. Its guard skips a feed already present in
    /// `DELEGATION`, but the trust root does not write there — so a feed the operator
    /// pinned and the base policy did not re-declare could have its floor lowered by a
    /// third-party fragment within the parent's `allow_nested` scope, admitting a genuinely
    /// signed but superseded fragment on a guest whose high-water mark for that feed is
    /// still below the floor (i.e. any fresh VM).
    ///
    /// The issuer-wide floor was never at risk (`min_required` maxes with `(issuer, "")`,
    /// TC-F1.24), which is why this survived: the invariant held for the case that was
    /// tested and not for the one that was not.
    #[test]
    fn a_later_feed_declaration_cannot_lower_an_earlier_floor() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        // Issuer-wide floor deliberately low, so the per-feed floor is the only thing
        // standing between an old fragment and acceptance.
        store.set_min_svn("issuerA", 0);

        // The operator's trust root pins this feed at 10.
        store.declare_feed("issuerA", "prod", 10);
        // The per-pod base policy then declares the same feed with a laxer floor.
        store.declare_feed("issuerA", "prod", 2);

        // A genuinely signed but superseded fragment must still be refused.
        let mut stale = frag_feed("issuerA", "prod", 3);
        assert!(
            matches!(
                load(&mut store, &sk, &stale).unwrap_err(),
                FragmentError::RolledBackSvn {
                    min_required: 10,
                    ..
                }
            ),
            "a later declaration lowered the operator's per-feed floor"
        );

        // Raising is still allowed, so this is a floor and not a pin.
        store.declare_feed("issuerA", "prod", 12);
        let mut below = frag_feed("issuerA", "prod", 11);
        assert!(load(&mut store, &sk, &below).is_err());
        let mut at_floor = frag_feed("issuerA", "prod", 12);
        assert!(load(&mut store, &sk, &at_floor).is_ok());
    }

    /// F-159: the SVN high-water mark is raise-only, so a `commit` that arrives out of order
    /// cannot move it backwards.
    ///
    /// `verify` refuses anything at or under the mark, so a *serialized* caller can never
    /// present this case — but `load_policy_fragment` verifies, applies and commits under
    /// separate locks, and two concurrent loads both clear the gate against the same
    /// pre-state before either commits. The losing commit then arrives with the lower SVN.
    /// An unconditional insert would write it, lowering the floor *and* persisting the
    /// lowered value through `export_svn_state` into the sealed store, so a restart would
    /// not recover. Keeping the invariant inside `commit` means the worst a lost race can do
    /// is fail to advance the mark.
    #[test]
    fn committing_out_of_order_cannot_lower_the_svn_high_water_mark() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store.declare_feed("issuerA", "prod", 0);

        // Verify both against the same pre-state, as two concurrent loads would.
        let newer = verify(&store, &sk, &frag_feed("issuerA", "prod", 9)).unwrap();
        let older = verify(&store, &sk, &frag_feed("issuerA", "prod", 5)).unwrap();

        // The newer one lands first; the older one's commit arrives afterwards.
        store.commit(&newer);
        assert_eq!(store.min_required("issuerA", "prod"), 10);
        store.commit(&older);

        assert_eq!(
            store.min_required("issuerA", "prod"),
            10,
            "a late commit must not reopen the rollback window"
        );
        assert!(
            !store.export_svn_state().contains("prod\t5"),
            "the lowered mark must never reach the sealed store: {}",
            store.export_svn_state()
        );
    }

    /// TC-F1.25 (FR-1i): a per-feed floor above the issuer-wide floor still binds, so the
    /// stricter-of-the-two rule does not weaken an explicitly raised bar.
    #[test]
    fn per_feed_floor_above_the_issuer_floor_still_binds() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store.set_min_svn("issuerA", 2);
        store.declare_feed("issuerA", "prod", 9);

        let mut below = frag_feed("issuerA", "prod", 8);
        assert!(matches!(
            load(&mut store, &sk, &below).unwrap_err(),
            FragmentError::RolledBackSvn { min_required: 9, .. }
        ));
    }

    /// TC-F1.15 / TC-F1.16 (FR-1f): with a transparency anchor configured, a fragment whose
    /// receipt is an invalid signature is rejected; a valid receipt (anchor signature over
    /// the statement) is accepted.
    #[test]
    fn transparency_receipt_is_cryptographically_verified() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (anchor_sk, anchor_pk) = keypair(9);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store.set_transparency_anchor(&anchor_pk).unwrap();

        // Build + issuer-sign a fragment.
        let mut f = frag_feed("issuerA", "", 1);

        // Bogus receipt -> rejected.
        f.receipt = Some("deadbeef".into());
        assert_eq!(verify(&store, &issuer_sk, &f).unwrap_err(), FragmentError::InvalidReceipt);

        // Valid receipt: anchor signs the same statement.
        let rsig = anchor_sk.sign(&tbs_of(&f));
        f.receipt = Some(
            rsig.to_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        );
        assert!(verify(&store, &issuer_sk, &f).is_ok());
    }

    /// TC-F1.17 / TC-F1.18 / TC-F1.19 (FR-1g): a chain of fragments applies in dependency
    /// order; a fragment requiring an unloaded dependency is rejected; because `requires`
    /// can only reference already-loaded fragments, cycles/unbounded depth are impossible.
    #[test]
    fn fragment_chaining_requires_loaded_dependencies() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();

        // Base fragment (svn 1), id "issuerA//1".
        let mut base = frag_feed("issuerA", "", 1);
        let base_id = base.id();

        // Dependent fragment (svn 2) requires the base.
        let mut dep = frag_feed("issuerA", "", 2);
        dep.requires = vec![base_id.clone()];

        // Loading the dependent before the base is rejected (broken link).
        assert_eq!(
            verify(&store, &sk, &dep).unwrap_err(),
            FragmentError::UnsatisfiedRequirement {
                requires: base_id.clone()
            }
        );

        // Load the base first, then the dependent applies.
        load(&mut store, &sk, &base).unwrap();
        assert!(load(&mut store, &sk, &dep).is_ok());

        // A fragment requiring a never-loaded id is rejected wholesale.
        let mut orphan = frag_feed("issuerA", "", 3);
        orphan.requires = vec!["issuerA//999".into()];
        assert!(matches!(
            verify(&store, &sk, &orphan).unwrap_err(),
            FragmentError::UnsatisfiedRequirement { .. }
        ));
    }

    /// TC-F1.21 (FR-1i): SVN high-water marks survive a restart via export/import, so a
    /// fragment at or below a previously-accepted SVN stays rejected after restart.
    #[test]
    fn svn_state_persists_across_restart() {
        let (sk, pk) = keypair(1);

        // First "boot": accept svn 5 on the default feed.
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        let mut f5 = frag_feed("issuerA", "", 5);
        load(&mut store, &sk, &f5).unwrap();
        let snapshot = store.export_svn_state();
        assert!(snapshot.contains("issuerA\t\t5"));

        // "Restart": a fresh store re-seeds issuers/floors, then imports the snapshot.
        let mut restarted = FragmentStore::new(false);
        restarted.authorize_issuer("issuerA", &pk).unwrap();
        restarted.import_svn_state(&snapshot);

        // A replay of svn 5 (or lower) is still rejected after restart.
        assert!(matches!(
            verify(&restarted, &sk, &f5).unwrap_err(),
            FragmentError::RolledBackSvn {
                min_required: 6,
                ..
            }
        ));
        // svn 6 is accepted.
        let mut f6 = frag_feed("issuerA", "", 6);
        assert!(load(&mut restarted, &sk, &f6).is_ok());

        // import can only raise, never lower: importing an older snapshot is a no-op.
        restarted.import_svn_state("issuerA\t\t2");
        assert!(matches!(
            verify(&restarted, &sk, &f6).unwrap_err(),
            FragmentError::RolledBackSvn {
                min_required: 7,
                ..
            }
        ));
    }

    /// TC-F1.20 (FR-1h): a fragment carried in a COSE_Sign1 envelope verifies, a tampered
    /// envelope does not, and — the property the format change is for — there is no way to
    /// present fields the envelope does not carry.
    #[test]
    fn cose_sign1_fragment_verifies() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();

        let fragment = PolicyFragment {
            issuer: "issuerA".into(),
            svn: 1,
            policy_module: Some("package agent_policy.fragments\nexec_allowed := true".into()),
            includes: vec!["exec".into()],
            ..Default::default()
        };
        let cose_bytes = envelope(&sk, &fragment);

        let v = store.verify_envelope(&cose_bytes).unwrap();
        assert_eq!(v.issuer, "issuerA");
        assert_eq!(v.svn, 1);
        assert_eq!(v.includes, vec!["exec".to_string()]);
        assert_eq!(
            v.policy_module.as_deref(),
            Some("package agent_policy.fragments\nexec_allowed := true")
        );

        // A tampered envelope (flip a signature byte) is rejected.
        let mut tampered = cose_bytes.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0xff;
        assert_eq!(
            store.verify_envelope(&tampered).unwrap_err(),
            FragmentError::InvalidSignature
        );

        // A different SVN is a different envelope, and one the issuer never signed. Under
        // the old format this was a `payload != statement` check between a caller-described
        // fragment and the bytes next to it; now the SVN *is* in the signed bytes, so
        // changing it invalidates the signature with nothing left to keep in agreement.
        let mut other = fragment.clone();
        other.svn = 2;
        let mut forged = envelope(&sk, &other);
        // Splice the honest signature onto the altered header, which is the closest a host
        // can get to "same signature, different fields".
        let sig_len = {
            use coset::CborSerializable;
            let honest = coset::CoseSign1::from_slice(&cose_bytes).unwrap();
            let mut f = coset::CoseSign1::from_slice(&forged).unwrap();
            f.signature = honest.signature.clone();
            forged = f.to_vec().unwrap();
            honest.signature.len()
        };
        assert_eq!(sig_len, 64);
        assert_eq!(
            store.verify_envelope(&forged).unwrap_err(),
            FragmentError::InvalidSignature
        );
    }

    /// The interop claim, made testable: an envelope carrying **only** the headers C-ACI's
    /// `sign1util` writes — content type, `iss`/`feed` as plain string keys, no kata-private
    /// labels — is accepted, with the Rego module as the payload.
    ///
    /// This is what "the same signing tool" means in practice. The one addition a stock
    /// `sign1util create` cannot make is the CWT claims map holding the SVN, which is why
    /// that is the single header this test adds by hand (hcsshim reads the SVN from the CWT
    /// claims too; its own `CreateCoseSign1` does not emit it either).
    #[test]
    fn an_hcsshim_shaped_envelope_is_accepted() {
        use ciborium::value::Value;
        use coset::{iana, CborSerializable, CoseSign1Builder, ContentType, Label};

        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("did:x509:0:sha256:AAAA::CN:signer", &pk).unwrap();
        store.declare_feed("did:x509:0:sha256:AAAA::CN:signer", "contoso.azurecr.io/frag:1", 0);

        let rego = b"package agent_policy.fragments.exec\nallow := true\n";
        let protected = coset::Header {
            alg: Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)),
            content_type: Some(ContentType::Text(FRAGMENT_CONTENT_TYPE.to_string())),
            rest: vec![
                (
                    Label::Text("iss".into()),
                    Value::Text("did:x509:0:sha256:AAAA::CN:signer".into()),
                ),
                (
                    Label::Text("feed".into()),
                    Value::Text("contoso.azurecr.io/frag:1".into()),
                ),
                (
                    Label::Int(15),
                    Value::Map(vec![(Value::Text("svn".into()), Value::Integer(3.into()))]),
                ),
            ],
            ..Default::default()
        };
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(rego.to_vec())
            .create_signature(b"", |tbs| sk.sign(tbs).to_bytes().to_vec())
            .build()
            .to_vec()
            .unwrap();

        let v = store.verify_envelope(&cose).expect("stock C-ACI envelope shape");
        assert_eq!(v.issuer, "did:x509:0:sha256:AAAA::CN:signer");
        assert_eq!(v.feed, "contoso.azurecr.io/frag:1");
        assert_eq!(v.svn, 3);
        assert_eq!(v.policy_module.as_deref(), Some(std::str::from_utf8(rego).unwrap()));
        // No kata-private headers were present, so the supersets are simply absent.
        assert!(v.includes.is_empty());
    }

    fn ordered_frag(issuer: &str, svn: u64, prev_head: &[u8]) -> PolicyFragment {
        PolicyFragment {
            issuer: issuer.to_string(),
            svn,
            prev_log_head: Some(prev_head.to_vec()),
            ..Default::default()
        }
    }

    /// TC-F1.28 (FR-1j): fragments applied in order are accepted and the append-only log
    /// head advances deterministically; the exported log records the exact sequence.
    #[test]
    fn ordering_in_order_accepted_and_head_advances() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store.set_log_genesis(b"kata-fragment-log/test-genesis");

        let h0 = store.log_head().to_vec();
        let mut a = ordered_frag("issuerA", 1, &h0);
        assert!(load(&mut store, &sk, &a).is_ok());
        let h1 = store.log_head().to_vec();
        assert_ne!(h0, h1, "head must advance");

        let mut b = ordered_frag("issuerA", 2, &h1);
        assert!(load(&mut store, &sk, &b).is_ok());
        let h2 = store.log_head().to_vec();
        assert_ne!(h1, h2);

        // The exported log is deterministic and ends with the current head.
        let log = store.export_fragment_log();
        assert!(log.contains("0\tissuerA//1\t"));
        assert!(log.contains("1\tissuerA//2\t"));
        assert!(log.trim_end().ends_with(&super::bytes_to_hex(&h2)));
    }

    /// TC-F1.29 (FR-1j): a fragment asserting a stale/wrong predecessor head (a reordering,
    /// omission, or insertion) is rejected fail-closed and the store is unchanged.
    #[test]
    fn ordering_out_of_order_rejected() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store.set_log_genesis(b"kata-fragment-log/test-genesis");

        let h0 = store.log_head().to_vec();
        let mut a = ordered_frag("issuerA", 1, &h0);
        load(&mut store, &sk, &a).unwrap();
        let h1 = store.log_head().to_vec();

        // A second fragment that still asserts the genesis head (out of order) is rejected.
        let mut stale = ordered_frag("issuerA", 2, &h0);
        assert!(matches!(
            load(&mut store, &sk, &stale).unwrap_err(),
            FragmentError::LogHeadMismatch { .. }
        ));
        // Head unchanged after the rejected fragment (fail-closed).
        assert_eq!(store.log_head(), h1.as_slice());

        // The correct next fragment (asserting h1) is accepted.
        let mut b = ordered_frag("issuerA", 2, &h1);
        assert!(load(&mut store, &sk, &b).is_ok());
    }

    /// TC-F1.30 (FR-1j): the ordering log head survives export/import (restart) and is
    /// raise-only — after a restart the next in-order fragment is accepted, a stale one is
    /// rejected, and importing an older (shorter) snapshot cannot rewind the head.
    #[test]
    fn ordering_head_persists_across_restart_raise_only() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        store.set_log_genesis(b"kata-fragment-log/test-genesis");

        let h0 = store.log_head().to_vec();
        let mut a = ordered_frag("issuerA", 1, &h0);
        load(&mut store, &sk, &a).unwrap();
        let snap_after_a = store.export_svn_state();
        let h1 = store.log_head().to_vec();

        let mut b = ordered_frag("issuerA", 2, &h1);
        load(&mut store, &sk, &b).unwrap();
        let snap_after_b = store.export_svn_state();
        let h2 = store.log_head().to_vec();

        // Restart: fresh store, re-seed genesis, import the persisted state.
        let mut restarted = FragmentStore::new(false);
        restarted.authorize_issuer("issuerA", &pk).unwrap();
        restarted.set_log_genesis(b"kata-fragment-log/test-genesis");
        restarted.import_svn_state(&snap_after_b);
        assert_eq!(
            restarted.log_head(),
            h2.as_slice(),
            "head restored across restart"
        );

        // The next in-order fragment (prev = h2) is accepted after restart.
        let mut c = ordered_frag("issuerA", 3, &h2);
        assert!(load(&mut restarted, &sk, &c).is_ok());

        // Raise-only: importing the older (shorter) snapshot must NOT rewind the head.
        let head_now = restarted.log_head().to_vec();
        restarted.import_svn_state(&snap_after_a);
        assert_eq!(
            restarted.log_head(),
            head_now.as_slice(),
            "older snapshot cannot rewind"
        );
    }

    /// TC-F1.30b (FR-1j): non-ordered mode is unchanged — with no genesis configured, a
    /// fragment carrying no prev_log_head is accepted (opt-in / back-compat).
    #[test]
    fn ordering_disabled_by_default() {
        let (sk, pk) = keypair(1);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &pk).unwrap();
        assert!(!store.is_ordered());
        let mut f = frag("issuerA", 1, &["exec:x"]);
        f.receipt = None;
        assert!(load(&mut store, &sk, &f).is_ok());
    }
    // ---- FR-1f Stage 2: transparency inclusion + consistency proofs ----
    use crate::merkle::MerkleTree;

    fn ttl_proof(
        tree: &MerkleTree,
        sk: &SigningKey,
        ledger: &str,
        index: usize,
        cons_from: Option<usize>,
    ) -> String {
        let size = tree.size();
        let root = tree.root();
        let sig = sk.sign(&sth_signing_bytes(ledger, size, &root)).to_bytes();
        let incl = tree.inclusion_proof(index);
        let cons = cons_from
            .map(|m| tree.consistency_proof(m))
            .unwrap_or_default();
        encode_transparency_proof(size, &root, &sig, index as u64, &incl, &cons)
    }

    fn ttl_frag(issuer_sk: &SigningKey, svn: u64, ledger: &str) -> PolicyFragment {
        let mut f = PolicyFragment {
            issuer: "issuerA".into(),
            svn,
            receipt_ledger: Some(ledger.into()),
            ..Default::default()
        };
        f
    }

    /// TC-F1.32 (Stage 2): a valid inclusion proof under a signed tree head is accepted; a
    /// tampered inclusion proof (wrong leaf position) is rejected.
    #[test]
    fn stage2_inclusion_proof_verified() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (led_sk, led_pk) = keypair(30);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[("ttl".into(), vec![led_pk])])
            .unwrap();

        let f = ttl_frag(&issuer_sk, 1, "ttl");
        let mut tree = MerkleTree::new();
        tree.push(tbs_of(&f));
        let mut ok = f.clone();
        ok.receipt_proof = Some(ttl_proof(&tree, &led_sk, "ttl", 0, None));
        assert!(verify(&store, &issuer_sk, &ok).is_ok());

        // Wrong index (leaf not at claimed position) -> inclusion fails.
        let mut bad = f.clone();
        tree.push(b"other".to_vec());
        bad.receipt_proof = Some(ttl_proof(&tree, &led_sk, "ttl", 1, None)); // claims index 1, but leaf 1 is "other"
        assert_eq!(
            verify(&store, &issuer_sk, &bad).unwrap_err(),
            FragmentError::InvalidInclusionProof
        );
    }

    /// TC-F1.33 (Stage 2): a signed tree head signed by a key NOT in the trust list is
    /// rejected (the ledger signature must chain to a trusted key).
    #[test]
    fn stage2_untrusted_sth_rejected() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (_led_sk, led_pk) = keypair(30);
        let (evil_sk, _evil_pk) = keypair(31);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[("ttl".into(), vec![led_pk])])
            .unwrap();

        let f = ttl_frag(&issuer_sk, 1, "ttl");
        let mut tree = MerkleTree::new();
        tree.push(tbs_of(&f));
        let mut bad = f.clone();
        bad.receipt_proof = Some(ttl_proof(&tree, &evil_sk, "ttl", 0, None)); // signed by untrusted key
        assert_eq!(
            verify(&store, &issuer_sk, &bad).unwrap_err(),
            FragmentError::InvalidReceipt
        );
    }

    /// BL-6 (Stage 2, CCF profile): a SCITT CCF-profile inclusion proof whose recomputed
    /// Merkle root is signed by a trusted ledger key and whose leaf `data-hash` binds the
    /// fragment statement is accepted; a proof for a different statement, or one whose root
    /// is signed by an untrusted key, is rejected.
    fn ccf_receipt(statement: &[u8], led_sk: &SigningKey, bind_stmt: &[u8]) -> String {
        let tx = [7u8; 32];
        let sib = [0x11u8; 32];
        let data_hash: [u8; 32] = Sha256::digest(bind_stmt).into();
        let leaf = crate::ccf::ccf_leaf_hash(&tx, b"ccf-evidence", &data_hash);
        // Single right sibling (left=false): root = SHA-256(leaf || sib).
        let mut h = Sha256::new();
        h.update(leaf);
        h.update(sib);
        let root: [u8; 32] = h.finalize().into();
        let proof = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1.into()),
                ciborium::value::Value::Array(vec![
                    ciborium::value::Value::Bytes(tx.to_vec()),
                    ciborium::value::Value::Text("ccf-evidence".into()),
                    ciborium::value::Value::Bytes(data_hash.to_vec()),
                ]),
            ),
            (
                ciborium::value::Value::Integer(2.into()),
                ciborium::value::Value::Array(vec![ciborium::value::Value::Array(vec![
                    ciborium::value::Value::Bool(false),
                    ciborium::value::Value::Bytes(sib.to_vec()),
                ])]),
            ),
        ]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&proof, &mut cbor).unwrap();
        let sig = led_sk.sign(&root).to_bytes();
        let _ = statement;
        format!(
            "kata-ccf-proof/v1\nproof={}\nsig={}\n",
            bytes_to_hex(&cbor),
            bytes_to_hex(&sig)
        )
    }

    #[test]
    fn stage2_ccf_receipt_verified() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (led_sk, led_pk) = keypair(30);
        let (evil_sk, _evil_pk) = keypair(31);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[("ttl".into(), vec![led_pk])])
            .unwrap();

        let f = ttl_frag(&issuer_sk, 1, "ttl");
        let stmt = tbs_of(&f);

        // Valid: CCF proof binds this statement, root signed by trusted ledger key.
        let mut ok = f.clone();
        ok.receipt_proof = Some(ccf_receipt(&stmt, &led_sk, &stmt));
        assert!(verify(&store, &issuer_sk, &ok).is_ok());

        // Wrong statement bound in the proof -> inclusion (data-hash) mismatch.
        let mut wrong = f.clone();
        wrong.receipt_proof = Some(ccf_receipt(&stmt, &led_sk, b"different-statement"));
        assert_eq!(
            verify(&store, &issuer_sk, &wrong).unwrap_err(),
            FragmentError::InvalidInclusionProof
        );

        // Root signed by an untrusted key -> receipt rejected.
        let mut untrusted = f.clone();
        untrusted.receipt_proof = Some(ccf_receipt(&stmt, &evil_sk, &stmt));
        assert_eq!(
            verify(&store, &issuer_sk, &untrusted).unwrap_err(),
            FragmentError::InvalidReceipt
        );
    }

    /// F-167: a CCF receipt signs only the bare Merkle root, so nothing in it names a
    /// ledger. If two configured ledgers share key material, the receipt validates as both
    /// and the `receipt_ledger` claim — which `allowed_ledgers` / `required_receipt_from`
    /// scoping is enforced against — means nothing. It must be refused rather than silently
    /// attributed to whichever ledger the host named.
    #[test]
    fn stage2_ccf_receipt_attributable_to_two_ledgers_is_refused() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (led_sk, led_pk) = keypair(30);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        // The same key registered under two ledger ids: a rename/migration, or one ledger
        // instance enrolled under both a generic and an environment-specific name.
        store
            .load_transparency_trust_list(&[
                ("ttl".into(), vec![led_pk]),
                ("other".into(), vec![led_pk]),
            ])
            .unwrap();

        let f = ttl_frag(&issuer_sk, 1, "ttl");
        let stmt = tbs_of(&f);

        let mut ccf = f.clone();
        ccf.receipt_proof = Some(ccf_receipt(&stmt, &led_sk, &stmt));
        assert_eq!(
            verify(&store, &issuer_sk, &ccf).unwrap_err(),
            FragmentError::AmbiguousCcfLedger {
                claimed: "ttl".into(),
                also: "other".into(),
            }
        );

        // Control: the native path carries the ledger id inside `sth_signing_bytes`, so the
        // very same ambiguous trust list is harmless there and must keep working. This is
        // why the check lives at the CCF branch and not in the trust-list loader.
        let mut tree = MerkleTree::new();
        tree.push(tbs_of(&f));
        let mut native = f.clone();
        native.receipt_proof = Some(ttl_proof(&tree, &led_sk, "ttl", 0, None));
        assert!(verify(&store, &issuer_sk, &native).is_ok());
    }

    /// F-167 control: with only the claimed ledger configured there is no ambiguity, so the
    /// receipt is accepted exactly as before. Guards against the check firing on the normal
    /// single-ledger configuration.
    #[test]
    fn stage2_ccf_receipt_unambiguous_when_ledgers_hold_distinct_keys() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (led_sk, led_pk) = keypair(30);
        let (_other_sk, other_pk) = keypair(32);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[
                ("ttl".into(), vec![led_pk]),
                ("other".into(), vec![other_pk]),
            ])
            .unwrap();

        let f = ttl_frag(&issuer_sk, 1, "ttl");
        let stmt = tbs_of(&f);
        let mut ok = f.clone();
        ok.receipt_proof = Some(ccf_receipt(&stmt, &led_sk, &stmt));
        assert!(verify(&store, &issuer_sk, &ok).is_ok());
    }

    /// F-168: the CCF path fold is host-supplied, unsigned input processed before any
    /// signature check, so its length is bounded — and the bound reports distinctly.
    #[test]
    fn stage2_ccf_proof_path_length_is_bounded() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (led_sk, led_pk) = keypair(30);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[("ttl".into(), vec![led_pk])])
            .unwrap();

        let f = ttl_frag(&issuer_sk, 1, "ttl");
        let stmt = tbs_of(&f);
        let over = crate::ccf::MAX_CCF_PATH_ELEMENTS + 1;

        let mut long = f.clone();
        long.receipt_proof = Some(ccf_receipt_with_path_len(&stmt, &led_sk, over));
        assert_eq!(
            verify(&store, &issuer_sk, &long).unwrap_err(),
            FragmentError::CcfProofPathTooLong {
                len: over,
                max: crate::ccf::MAX_CCF_PATH_ELEMENTS,
            }
        );

        // At the bound the proof is still processed normally: a correctly signed root at
        // exactly MAX elements verifies, so the cap is not off by one.
        let mut at_bound = f.clone();
        at_bound.receipt_proof = Some(ccf_receipt_with_path_len(
            &stmt,
            &led_sk,
            crate::ccf::MAX_CCF_PATH_ELEMENTS,
        ));
        assert!(verify(&store, &issuer_sk, &at_bound).is_ok());
    }

    /// F-168 helper: a CCF receipt binding `statement` with exactly `n` path elements, with
    /// the resulting root correctly signed — so the only reason it can be refused is length.
    fn ccf_receipt_with_path_len(statement: &[u8], led_sk: &SigningKey, n: usize) -> String {
        let tx = [7u8; 32];
        let data_hash: [u8; 32] = Sha256::digest(statement).into();
        let mut h = crate::ccf::ccf_leaf_hash(&tx, b"ccf-evidence", &data_hash);
        let mut path = Vec::with_capacity(n);
        for i in 0..n {
            let sib = [i as u8; 32];
            let mut d = Sha256::new();
            d.update(h);
            d.update(sib);
            h = d.finalize().into();
            path.push(ciborium::value::Value::Array(vec![
                ciborium::value::Value::Bool(false),
                ciborium::value::Value::Bytes(sib.to_vec()),
            ]));
        }
        let proof = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1.into()),
                ciborium::value::Value::Array(vec![
                    ciborium::value::Value::Bytes(tx.to_vec()),
                    ciborium::value::Value::Text("ccf-evidence".into()),
                    ciborium::value::Value::Bytes(data_hash.to_vec()),
                ]),
            ),
            (
                ciborium::value::Value::Integer(2.into()),
                ciborium::value::Value::Array(path),
            ),
        ]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&proof, &mut cbor).unwrap();
        let sig = led_sk.sign(&h).to_bytes();
        format!(
            "kata-ccf-proof/v1\nproof={}\nsig={}\n",
            bytes_to_hex(&cbor),
            bytes_to_hex(&sig)
        )
    }

    #[test]
    fn stage2_consistency_and_rollback() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (led_sk, led_pk) = keypair(30);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[("ttl".into(), vec![led_pk])])
            .unwrap();

        let fa = ttl_frag(&issuer_sk, 1, "ttl");
        let fb = ttl_frag(&issuer_sk, 2, "ttl");

        // Log state after A: size 1.
        let mut t1 = MerkleTree::new();
        t1.push(tbs_of(&fa));
        let mut a = fa.clone();
        a.receipt_proof = Some(ttl_proof(&t1, &led_sk, "ttl", 0, None));
        assert!(load(&mut store, &issuer_sk, &a).is_ok());

        // Log state after B: size 2, with a consistency proof from size 1.
        let mut t2 = MerkleTree::new();
        t2.push(tbs_of(&fa));
        t2.push(tbs_of(&fb));
        let mut b = fb.clone();
        b.receipt_proof = Some(ttl_proof(&t2, &led_sk, "ttl", 1, Some(1)));
        assert!(load(&mut store, &issuer_sk, &b).is_ok());

        // A fragment presenting an OLDER (size 1) head after the head advanced to 2 -> rollback.
        let fc = ttl_frag(&issuer_sk, 3, "ttl");
        let mut t1b = MerkleTree::new();
        t1b.push(tbs_of(&fc));
        let mut c = fc.clone();
        c.receipt_proof = Some(ttl_proof(&t1b, &led_sk, "ttl", 0, None));
        assert!(matches!(
            verify(&store, &issuer_sk, &c).unwrap_err(),
            FragmentError::LogRolledBack { .. }
        ));
    }

    /// TC-F1.35 (Stage 2): the transparency tree head survives export/import (restart) and
    /// is raise-only — after restart an older head is still rejected.
    #[test]
    fn stage2_tree_head_persists_across_restart() {
        let (issuer_sk, issuer_pk) = keypair(1);
        let (led_sk, led_pk) = keypair(30);
        let mut store = FragmentStore::new(false);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        store
            .load_transparency_trust_list(&[("ttl".into(), vec![led_pk])])
            .unwrap();

        let fa = ttl_frag(&issuer_sk, 1, "ttl");
        let fb = ttl_frag(&issuer_sk, 2, "ttl");
        let mut t2 = MerkleTree::new();
        t2.push(tbs_of(&fa));
        t2.push(tbs_of(&fb));
        // Jump straight to head size 2 (A already logged elsewhere): load B at size 2.
        let mut a = fa.clone();
        let mut t1 = MerkleTree::new();
        t1.push(tbs_of(&fa));
        a.receipt_proof = Some(ttl_proof(&t1, &led_sk, "ttl", 0, None));
        load(&mut store, &issuer_sk, &a).unwrap();
        let mut b = fb.clone();
        b.receipt_proof = Some(ttl_proof(&t2, &led_sk, "ttl", 1, Some(1)));
        load(&mut store, &issuer_sk, &b).unwrap();
        let snap = store.export_svn_state();
        assert!(snap.contains("--ttl-head--\tttl\t2\t"));

        // Restart: fresh store, same trust list, import the persisted tree head.
        let mut restarted = FragmentStore::new(false);
        restarted.authorize_issuer("issuerA", &issuer_pk).unwrap();
        restarted
            .load_transparency_trust_list(&[("ttl".into(), vec![led_pk])])
            .unwrap();
        restarted.import_svn_state(&snap);

        // An older (size 1) head is rejected after restart (raise-only tree head).
        let fc = ttl_frag(&issuer_sk, 3, "ttl");
        let mut t1c = MerkleTree::new();
        t1c.push(tbs_of(&fc));
        let mut c = fc.clone();
        c.receipt_proof = Some(ttl_proof(&t1c, &led_sk, "ttl", 0, None));
        assert!(matches!(
            verify(&restarted, &issuer_sk, &c).unwrap_err(),
            FragmentError::LogRolledBack { .. }
        ));
    }
    /// TC-F1.36 (BL-2): a transparency ledger key may be ES256 (not just Ed25519) — a receipt
    /// signed by that P-256 ledger key verifies; one signed by a different key is rejected.
    #[test]
    fn trust_list_accepts_es256_ledger_key() {
        use crate::cose_keys::{CoseAlg, PublicKey};
        use p256::ecdsa::{signature::Signer as _, Signature as P256Sig, SigningKey as P256Sk};
        use p256::pkcs8::EncodePublicKey as _;
        let (issuer_sk, issuer_pk) = keypair(1);
        let mut store = FragmentStore::new(true);
        store.authorize_issuer("issuerA", &issuer_pk).unwrap();
        let led = P256Sk::random(&mut rand_core::OsRng);
        let spki = led.verifying_key().to_public_key_der().unwrap();
        let pk = PublicKey::from_spki_der(spki.as_bytes()).unwrap();
        store.add_ledger_key("es256-ledger", pk, CoseAlg::Es256);

        let mut f = frag_feed("issuerA", "", 1);
        f.receipt_ledger = Some("es256-ledger".into());
        let sig: P256Sig = led.sign(&tbs_of(&f));
        f.receipt = Some(
            sig.to_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        );
        assert!(verify(&store, &issuer_sk, &f).is_ok());

        let other = P256Sk::random(&mut rand_core::OsRng);
        let bad: P256Sig = other.sign(&tbs_of(&f));
        f.receipt = Some(
            bad.to_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        );
        assert_eq!(verify(&store, &issuer_sk, &f).unwrap_err(), FragmentError::InvalidReceipt);
    }

    /// F-144 / F-145 / RM-71, closed structurally: the whole collision family is gone
    /// because there is no bespoke encoding left to collide in.
    ///
    /// Each pair below produced byte-identical signing input under the v3 text statement, so
    /// one signature had two readings and `validate_statement` had to refuse one member of
    /// each pair to keep the encoding injective. They are now separate COSE protected header
    /// entries, and the bytes that get signed are the ones the COSE encoder produced — so
    /// each member signs as itself and parses back as itself.
    #[test]
    fn the_v3_statement_collisions_do_not_exist_in_the_envelope_format() {
        let (sk, _pk) = keypair(1);

        // Two includes, or one include containing a newline.
        let split = PolicyFragment {
            issuer: "issuerA".into(),
            svn: 1,
            includes: vec!["alpha".into(), "beta".into()],
            ..Default::default()
        };
        let joined = PolicyFragment {
            includes: vec!["alpha\nbeta".into()],
            ..split.clone()
        };
        assert_ne!(
            tbs_of(&split),
            tbs_of(&joined),
            "a list of two is not a list of one"
        );
        assert_eq!(
            PolicyFragment::from_cose_envelope(&envelope(&sk, &split))
                .unwrap()
                .includes,
            vec!["alpha".to_string(), "beta".to_string()]
        );

        // A dependency declared in `requires`, or the same bytes with no dependency at all
        // and the old delimiter smuggled into the module. This was the dangerous member of
        // the family: the second reading silently has no composition dependency.
        let with_dep = PolicyFragment {
            issuer: "issuerA".into(),
            svn: 1,
            requires: vec!["--module--".into(), "r1".into()],
            policy_module: Some("M".into()),
            ..Default::default()
        };
        let without_dep = PolicyFragment {
            requires: vec![],
            policy_module: Some("r1\n--module--\nM".into()),
            ..with_dep.clone()
        };
        assert_ne!(
            tbs_of(&with_dep),
            tbs_of(&without_dep),
            "a signature must not bind both a dependency and its absence"
        );

        let a = PolicyFragment::from_cose_envelope(&envelope(&sk, &with_dep)).unwrap();
        assert_eq!(a.requires, vec!["--module--".to_string(), "r1".to_string()]);
        assert_eq!(a.policy_module.as_deref(), Some("M"));
        let b = PolicyFragment::from_cose_envelope(&envelope(&sk, &without_dep)).unwrap();
        assert!(b.requires.is_empty());
        assert_eq!(b.policy_module.as_deref(), Some("r1\n--module--\nM"));

        // The module is now literally the payload, so "smuggling a delimiter into the
        // module" cannot reach the metadata at all: the two live in different parts of the
        // envelope rather than in one flat byte string.
        use coset::CborSerializable;
        let parsed_env = coset::CoseSign1::from_slice(&envelope(&sk, &without_dep)).unwrap();
        assert_eq!(
            parsed_env.payload.as_deref(),
            Some("r1\n--module--\nM".as_bytes())
        );
    }

    /// RM-71: the delimiter-substring ban is deliberately gone — there are no delimiters —
    /// and values that v3 had to refuse are now accepted and round-trip. What survives is
    /// the control-character ban, which protects the still-textual audit log (F-146) and the
    /// composition id rather than any encoding.
    #[test]
    fn former_delimiter_values_are_now_safe_and_roundtrip() {
        let (sk, _pk) = keypair(1);
        let f = PolicyFragment {
            issuer: "did:x509:0:sha256:AAAA::CN:x--module--y".into(),
            feed: "reg/x--prevhead--y".into(),
            svn: 2,
            includes: vec!["x--includes--".into(), "--requires--".into()],
            ..Default::default()
        };
        assert!(
            f.validate_statement().is_ok(),
            "nothing splits on these any more"
        );
        let parsed = PolicyFragment::from_cose_envelope(&envelope(&sk, &f)).expect("parses");
        assert_eq!(parsed.issuer, f.issuer);
        assert_eq!(parsed.feed, f.feed);
        assert_eq!(parsed.includes, {
            let mut g = f.includes.clone();
            g.sort();
            g
        });
    }

    /// F-146: the control-character ban and the empty-entry check are what remain of
    /// `validate_statement`, and each has a live reason — the tab-delimited audit log and
    /// the composition id, not the statement encoding.
    #[test]
    fn statement_validation_covers_control_characters_and_empty_entries() {
        for (label, f) in [
            (
                "empty include",
                PolicyFragment {
                    includes: vec![String::new()],
                    ..Default::default()
                },
            ),
            (
                "issuer with a carriage return",
                PolicyFragment {
                    issuer: "did:x509:0:sha256:A\r".into(),
                    ..Default::default()
                },
            ),
            (
                "include with a newline",
                PolicyFragment {
                    includes: vec!["exec\nmount".into()],
                    ..Default::default()
                },
            ),
            (
                "feed with a tab",
                PolicyFragment {
                    feed: "reg/frag\tdeadbeef".into(),
                    ..Default::default()
                },
            ),
            (
                "present but empty module",
                PolicyFragment {
                    policy_module: Some(String::new()),
                    ..Default::default()
                },
            ),
        ] {
            assert!(
                matches!(
                    f.validate_statement(),
                    Err(FragmentError::MalformedStatement { .. })
                ),
                "{} must be refused",
                label
            );
        }
    }

    /// F-144: a module may contain what used to be the v3 delimiters — it has to, since it
    /// carries arbitrary Rego — and still round-trips exactly. Under v3 this worked only
    /// because the module was bounded by the first `--module--` and the *last*
    /// `--prevhead--`; now it works because the module is the payload and the delimiters
    /// are not syntax anywhere.
    #[test]
    fn a_module_containing_delimiters_is_still_accepted_and_roundtrips() {
        let (sk, _pk) = keypair(1);
        let f = PolicyFragment {
            issuer: "did:x509:0:sha256:AAAA::CN:signer".into(),
            feed: "reg/frag:1".into(),
            svn: 3,
            includes: vec!["exec".into()],
            policy_module: Some(
                "package agent_policy.fragments\n# --module--\n# --prevhead--\nallow := true"
                    .into(),
            ),
            prev_log_head: Some(vec![0xde, 0xad]),
            ..Default::default()
        };
        assert!(f.validate_statement().is_ok());
        let parsed = PolicyFragment::from_cose_envelope(&envelope(&sk, &f)).expect("parses");
        assert_eq!(parsed.policy_module, f.policy_module);
        assert_eq!(parsed.includes, f.includes);
        assert_eq!(parsed.prev_log_head, f.prev_log_head);
    }

    /// The envelope-format equivalent of the old canonicality test, and a smaller job.
    ///
    /// v4 had to *re-encode* the parsed statement and compare it byte for byte, because CBOR
    /// decoders accept indefinite-length items, non-minimal integers and trailing data, so
    /// "it parsed" said nothing about the bytes. None of that applies now: the signature
    /// covers the `Sig_structure`, which contains the protected header's original bytes, so
    /// there is exactly one reading of any envelope that verifies — no canonical form has to
    /// be reconstructed to check it against.
    ///
    /// What is left is refusing envelopes that are malformed *as fragments*, and each case
    /// here is refused for a reason rather than by a general parser rule.
    #[test]
    fn a_malformed_envelope_is_refused_with_its_reason() {
        use ciborium::value::Value;
        use coset::{iana, CborSerializable, CoseSign1Builder, ContentType, Label};

        let (sk, _pk) = keypair(1);
        let cwt = |entries: Vec<(Value, Value)>| (Label::Int(15), Value::Map(entries));
        let good_cwt = || {
            cwt(vec![
                (Value::Integer(1.into()), Value::Text("issuerA".into())),
                (Value::Text("svn".into()), Value::Integer(1.into())),
            ])
        };
        let good_cwt_value = || {
            (
                Value::Integer(15.into()),
                Value::Map(vec![
                    (Value::Integer(1.into()), Value::Text("issuerA".into())),
                    (Value::Text("svn".into()), Value::Integer(1.into())),
                ]),
            )
        };
        let build = |ct: Option<&str>, rest: Vec<(Label, Value)>, crit: bool| {
            let mut protected = coset::Header {
                alg: Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)),
                content_type: ct.map(|s| ContentType::Text(s.to_string())),
                rest,
                ..Default::default()
            };
            if crit {
                protected.crit = vec![coset::RegisteredLabel::Text("kata-unknown".into())];
            }
            CoseSign1Builder::new()
                .protected(protected)
                .payload(b"package agent_policy.fragments.x\n".to_vec())
                .create_signature(b"", |tbs| sk.sign(tbs).to_bytes().to_vec())
                .build()
                .to_vec()
                .unwrap()
        };

        let reason = |cose: Vec<u8>| match PolicyFragment::from_cose_envelope(&cose) {
            Err(FragmentError::MalformedEnvelope { reason }) => reason,
            other => panic!("expected MalformedEnvelope, got {:?}", other),
        };

        // Not a COSE_Sign1 at all.
        assert!(reason(b"garbage".to_vec()).contains("well-formed"));

        // No content type: an issuer's signature over some *other* kind of artefact — a
        // trust list, a TCB reference — must not be replayable as a policy fragment.
        assert!(reason(build(None, vec![good_cwt()], false)).contains("content type"));
        assert!(reason(build(
            Some("application/vnd.transparency-trust-list.v1+cose"),
            vec![good_cwt()],
            false
        ))
        .contains("content type"));

        // No SVN: defaulting it would silently disarm rollback protection.
        assert!(reason(build(
            Some(FRAGMENT_CONTENT_TYPE),
            vec![cwt(vec![(
                Value::Integer(1.into()),
                Value::Text("issuerA".into())
            )])],
            false
        ))
        .contains("no svn claim"));

        // No issuer.
        assert!(reason(build(
            Some(FRAGMENT_CONTENT_TYPE),
            vec![cwt(vec![(
                Value::Text("svn".into()),
                Value::Integer(1.into())
            )])],
            false
        ))
        .contains("does not name an issuer"));

        // The CWT claim and the `iss` string key disagree. hcsshim silently prefers the CWT;
        // refusing is stricter, because an envelope that says two things about who signed it
        // has no single correct reading.
        assert!(reason(build(
            Some(FRAGMENT_CONTENT_TYPE),
            vec![
                good_cwt(),
                (Label::Text("iss".into()), Value::Text("issuerB".into()))
            ],
            false
        ))
        .contains("two different values"));

        // A duplicate protected label: CBOR admits it and decoders disagree about which wins,
        // so two verifiers could read one signed envelope differently. coset will not *emit*
        // one, so the envelope is assembled by hand — which is what an attacker would do.
        let enc = |v: &Value| {
            let mut b = Vec::new();
            ciborium::ser::into_writer(v, &mut b).unwrap();
            b
        };
        let dup_protected = enc(&Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer((-8).into())),
            (
                Value::Integer(3.into()),
                Value::Text(FRAGMENT_CONTENT_TYPE.into()),
            ),
            good_cwt_value(),
            (
                Value::Text("kata-includes".into()),
                Value::Array(vec![Value::Text("a".into())]),
            ),
            (
                Value::Text("kata-includes".into()),
                Value::Array(vec![Value::Text("b".into())]),
            ),
        ]));
        let payload = b"package agent_policy.fragments.x\n".to_vec();
        let mut sig_structure = Vec::new();
        ciborium::ser::into_writer(
            &Value::Array(vec![
                Value::Text("Signature1".into()),
                Value::Bytes(dup_protected.clone()),
                Value::Bytes(Vec::new()),
                Value::Bytes(payload.clone()),
            ]),
            &mut sig_structure,
        )
        .unwrap();
        let handmade = enc(&Value::Array(vec![
            Value::Bytes(dup_protected),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(sk.sign(&sig_structure).to_bytes().to_vec()),
        ]));
        // Refused — in practice by coset's decoder, which rejects duplicate map keys before
        // the fragment parser sees the header. The parser's own duplicate check is therefore
        // defence in depth against that behaviour changing, and the property under test is
        // that the envelope does not verify, not which layer says so.
        let r = reason(handmade);
        assert!(
            r.contains("duplicate") || r.contains("well-formed"),
            "unexpected reason: {r}"
        );

        // `crit` names a header the verifier is required to understand. Ignoring it is
        // exactly what `crit` forbids, so an entry is refused rather than skipped.
        assert!(reason(build(Some(FRAGMENT_CONTENT_TYPE), vec![good_cwt()], true))
            .contains("critical"));

        // Wrong types for the kata-private headers.
        assert!(reason(build(
            Some(FRAGMENT_CONTENT_TYPE),
            vec![
                good_cwt(),
                (Label::Text("kata-requires".into()), Value::Text("not-an-array".into()))
            ],
            false
        ))
        .contains("not an array"));
        assert!(reason(build(
            Some(FRAGMENT_CONTENT_TYPE),
            vec![
                good_cwt(),
                (Label::Text("kata-prev-log-head".into()), Value::Text("hex?".into()))
            ],
            false
        ))
        .contains("not a byte string"));

        // The happy path through the same builder, so the negatives above are known to be
        // failing for the reason stated and not because the fixture never worked.
        assert!(PolicyFragment::from_cose_envelope(&build(
            Some(FRAGMENT_CONTENT_TYPE),
            vec![good_cwt()],
            false
        ))
        .is_ok());
    }
}
