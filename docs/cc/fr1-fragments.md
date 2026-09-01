# FR-1 — Signed, add-only policy fragments (detailed reference)

**What this is.** The full technical breakdown of the signed-policy-fragments feature, the
largest of the PARMA execution-integrity hardening features. The main guide
(`parma-hardening-features.md`) carries a summary; this document is the authoritative,
sub-requirement-by-sub-requirement reference with code locations, error variants, tests, and
the per-commit map. Reproducible dev walk-through: `docs/cc/fr1-fragment-e2e.md`.

All code lives in `src/agent/security-reference-monitor/src/` (the SRM crate) with agent
wiring in `src/agent/src/{main.rs,rpc.rs}` and tooling in
`src/agent/security-reference-monitor/examples/` + `src/tools/agent-ctl/`.

---

## 1. The guarantee

A base policy is one-shot/immutable within an attestation epoch (FR-12). Fragments let a
deployment **extend** what a workload may do at runtime **without weakening that guarantee**:
every extension is authenticated, monotonic, scope-limited, ordered, and incapable of relaxing
a base invariant. Concretely, only a signed, non-rolled-back, in-order, scope-limited policy
extension from an attested-trusted issuer can change what the workload may do — and every such
change is auditable after the fact.

**Threat model.** The host/orchestrator delivering fragments over the guest RPC is untrusted.
It may reorder, replay, omit, tamper, or forge fragments and their metadata. Every gate below
is fail-closed: on any doubt the fragment is rejected and neither the policy engine nor the
fragment store is mutated.

---

## 2. Sub-requirement map

| Sub-req | Guarantee it adds | Core code | Commits |
|---|---|---|---|
| **FR-1a** | verified fragment module is applied to the **live** policy engine (additive `add_policy`, never touches the one-shot `set_policy` lock) | `policy.rs::apply_fragment_module`; `rpc.rs::load_policy_fragment` | `dd2630053`, `294353a2a`, `11285337c`, `4ccd43f8a` |
| **FR-1b** | **authorized issuer** (measured trust root) + declarative **min-SVN floor**; atomic verify→apply→commit | `fragments.rs::{authorize_issuer,set_min_svn,verify,commit}`; `main.rs::seed_fragment_trust_root` | `bf602cb18`, `294353a2a` |
| **FR-1c** | **structured payload** — signed Rego module + `includes` namespace scoping | `fragments.rs` (`policy_module`, `includes`); applier namespace check | `bf602cb18` |
| **FR-1d** | **did:x509 issuer identity** — X.509 chain in COSE `x5chain`, CA-fingerprint + policy anchor, revocation, rotation, `basicConstraints CA:TRUE` on issuers; multi-algorithm (ES256/ES384/RS256/PS256) leaf + chain | `did_x509.rs`, `cose_keys.rs::{verify_cose,verify_cert_sig}` | `9cddd7f75`, `d6cdba49e`, `d01fabe13`, `bl2` |
| **FR-1e** | **feed scoping** — accepted `(issuer, feed)` pairs declared; undeclared feed rejected; per-feed SVN floor | `fragments.rs::declare_feed`; `UndeclaredFeed` | `ff8a4d5b9`, `c6b52c2ba` |
| **FR-1f** | **transparency receipts + Trust List** — multi-ledger, `allowed_ledgers` scoping, policy-driven `required_receipts`, ledger key rotation | `fragments.rs::{load_transparency_trust_list,set_allowed_ledgers,require_receipt_for}` | `ff8a4d5b9`, `c6b52c2ba`, `db24d40f5` |
| **FR-1f Stage 2** | **transparency-log inclusion + consistency** — RFC 6962 Merkle inclusion proof + monotonic, persisted signed tree head (append-only log) | `merkle.rs`; `fragments.rs` (`TransparencyProof`, `ttl_heads`) | `62fb8d45a` |
| **FR-1g** | **composition** — a fragment may `require` already-loaded fragments (no cycles/unbounded depth) | `fragments.rs` (`requires`); `UnsatisfiedRequirement` | `ff8a4d5b9`, `c6b52c2ba` |
| **FR-1h** | **COSE_Sign1 envelope** interop (pure-Rust `coset`, no Go) | `fragments.rs::verify_envelope` | `c0ea3cb25`, `f7ed23319`, `93e1ff6e5` |
| **FR-1i** | **SVN rollback protection across restart** — raise-only persisted high-water marks | `fragments.rs::{export_svn_state,import_svn_state}`; `main.rs` persist | `c0ea3cb25`, `f7ed23319` |
| **FR-1j** | **append-only application ordering** — signed rolling log head; reject reorder/omit/insert; exportable auditable log | `fragments.rs::{set_log_genesis,log_head,export_fragment_log}` (gate 8, `commit`) | `8efdaa65e` |
| **FR-1n** | **fragment-contributed environment rules within a measured ceiling** — a declaration may delegate named env vars to a feed; the fragment supplies concrete rules inside that grant (§4.19) | `policy.rs::FragmentSpec::allow_env_rules`; `rules.rego` (`allow_var` arm 9, `fragment_env_name_permitted`) | this PR |
| **FR-1o** | **fragment-contributed mounts within a measured ceiling** — a declaration may delegate named mount destinations to a feed; the fragment supplies concrete mount rules inside that grant (§4.20) | `policy.rs::FragmentSpec::allow_mount_rules`; `rules.rego` (`fragment_mount_permitted`, `fragment_mount_is_new`) | this PR |
| tools/demo | offline signer, agent-ctl command, mock ledger, self-contained capability demo | `examples/{sign-fragment,mock-ledger,fragment-demo}.rs`; `agent-ctl` | `392d890a8`, `69228f3b5`, `a63b9d5b3` |
| docs | in-tree guide + this reference | `docs/cc/{parma-hardening-features,fr1-fragment-e2e,fr1-fragments}.md`, `kata-opa/fragment-demo.rego` | `adaa7558b`, `d8149983e`, `b65ba9113`, `26d013c95`, `5dc0744f9` |

---

## 3. Verification pipeline (order of gates)

Every fragment is verified by a chain of fail-closed gates before it is committed. There is a
single entry point, `verify_envelope`, which takes the COSE_Sign1 bytes and nothing else; the
did:x509-versus-raw-key routing happens inside it, so no caller can select the weaker path.
Both routes converge on the shared `check_gates`:

1. **Issuer identity + signature.** Either (a) the issuer is in the measured authorized set and
   an Ed25519 signature verifies over the COSE `Sig_structure`, or (b) a did:x509 chain in the
   COSE `x5chain` path-validates to a measured CA (each issuer cert `CA:TRUE`, in-date),
   satisfies the did:x509 policy (subject CN / EKU / DNS SAN), is not revoked, and the leaf key
   signs the envelope — and the derived did equals the issuer the envelope claims. No
   downgrade: an x5chain-bearing envelope is always verified as did:x509.
2. **Feed declared** (FR-1e) — `(issuer, feed)` must be an accepted pair.
3. **Monotonic SVN** (FR-1b/1e/1i) — `svn ≥ max(declared floor, persisted high-water + 1)`.
4. **Transparency receipt** (FR-1f) — if required for the scope: a Stage-1 detached ledger
   signature and/or a Stage-2 inclusion+consistency proof, from an `allowed_ledgers` ledger,
   verified against a current trust-list key; Stage 2 also requires the signed tree head to be
   an append-only extension of the last-seen head (monotonic, consistency-proven).
5. **Composition** (FR-1g) — every `requires` id must already be loaded.
6. **Add-only** — a fragment may only add policy surface, and only within the scope measured
   state granted its `(issuer, feed)`; see `ModuleScope` and the delegation table below.
7. **Ordering** (FR-1j) — in ordered mode, the fragment's *signed* `prev_log_head` must equal
   the store's current rolling head; the head then advances by hashing the signed bytes in.

## Wire format: the C-ACI/hcsshim envelope

A fragment **is** a COSE_Sign1 envelope. The payload is the Rego module and the metadata lives
in the protected header:

| protected label | value |
| --- | --- |
| 1 | `alg` — EdDSA, ES256, ES384, PS256 or RS256 |
| 3 | content type `application/cose-x509+rego` |
| 15 | CWT claims: `1` = issuer, `2` = feed, `"svn"` = uint |
| `"iss"` / `"feed"` | string keys, accepted on read (this is what `sign1util create` writes) |
| `kata-includes` / `kata-requires` | arrays, omitted when empty |
| `kata-prev-log-head` | CBOR byte string, omitted when absent |

An absent payload means no module, which is hcsshim's `add_module: false`. `x5chain` (label
33) rides in the *unprotected* header, per RFC 9360 and `sign1util`; the chain is not the
identity, the leaf key having produced the signature is.

This is C-ACI's actual format, not a format inspired by it, so a fragment produced by an
existing C-ACI signing pipeline is one this guest verifies. Two divergences are deliberate,
and both are kata being stricter:

- **Receipts bind the `Sig_structure`.** hcsshim carries receipts in the *unprotected* header,
  where any intermediary can strip them.
- **`prev_log_head` is protected** and hcsshim has no ordering log at all (FR-1j is a kata
  superset).

Kata is also stricter on read: where an envelope carries both CWT claims and `iss`/`feed`
string keys that *disagree*, hcsshim silently prefers the CWT and kata refuses the envelope.
An envelope that says two things about who signed it has no single correct reading.

### What replaced the bespoke statement, and why

Until RM-75 the payload was a bespoke `kata-policy-fragment/vN` statement — v3 a flat
newline-delimited text format, v4 a fixed-arity CBOR array. That statement existed for exactly
one reason: the load path once accepted a fragment with a **detached** signature and no
envelope, and a detached signature needs some byte string to sign. Closing that path (F-151)
left the statement serving nothing while still costing a hand-rolled canonical encoding — the
encoding whose ambiguities produced F-144, F-145 and F-146 in turn.

v3 used literal `--includes--`, `--requires--`, `--module--` and `--prevhead--` marker lines
that escaped nothing, so it was injective only over a domain `validate_statement` had to
enforce as gate 0. Outside that domain distinct fragments shared signing bytes:
`includes = ["alpha", "beta"]` encoded identically to `includes = ["alpha\nbeta"]`, and
`requires = ["--module--", "r1"], module = "M"` collided with
`requires = [], module = "r1\n--module--\nM"` — the second of which silently has no dependency
at all. One signature, two readings (F-144).

Those collisions are now absent rather than fenced off, and the reasoning is shorter than v4's
was. The signature covers the COSE `Sig_structure`, which embeds the protected header's
*original bytes*; there is therefore exactly one reading of any envelope that verifies, and no
canonical form has to be reconstructed to check the bytes against. v4 needed a re-encode-and-
compare step precisely because it lacked that property. What remains is a duplicate-label
check, kept as defence in depth: CBOR maps admit duplicate keys and decoders disagree about
which wins, which would reintroduce F-144 at the key level. (In practice `coset` rejects them
first.)

The signed bytes are the `Sig_structure`, not the serialized envelope. That matters for the
FR-1j ordering log and for receipts: hashing the whole COSE_Sign1 would let a malleable
signature encoding, or an added unprotected header, give one signed fragment two identities.
`tbs_data` also does not depend on the signature, so a transparency ledger can compute its
Merkle leaf without the issuer key.

`validate_statement` survives the format change, with two live consumers that are still
textual: `export_fragment_log` renders a tab-delimited
`index<TAB>fragment-id<TAB>statement-sha256` record, so a control character in an issuer forges
the record meant to prove what was applied (F-146); and `make_id` renders its components
verbatim apart from the escaped `/` and `%`. The delimiter-substring ban went away with the
delimiters — an issuer containing `--module--` is now accepted and round-trips. The
empty-entry check is retained as hygiene: an empty `includes` entry names no namespace and an empty `requires`
entry matches no id, so it is likelier a signer bug than an intent.

A fragment's composition id — the value a dependent puts in its `requires` list — is
`<issuer>/<feed>/<svn>` with `/` and `%` percent-encoded in the first two components
(`PolicyFragment::make_id`). The separator is escaped rather than banned because it cannot be
banned: an issuer is a `did:x509` and a feed is an OCI reference, and both legitimately
contain `/`. A plain join is therefore not injective — `(issuer "a/b", feed "c")` and
`(issuer "a", feed "b/c")` collapse to the same id, so a fragment depending on one would be
satisfied by the other (F-145). Escaping keeps the id a single readable string, so neither
the envelope format nor the `repeated string requires` wire type changes, and it fixes the
audit log at the same time since that renders the same id. A hand-written, unescaped entry
matches nothing and fails closed as an unsatisfied requirement.

`requires` stayed a list of these id strings when the statement moved to CBOR (RM-71), rather
than becoming a structured `(issuer, feed, svn)` triple as earlier notes anticipated. The
triple was the right answer while the id was ambiguous, but escaping already made `make_id`
injective, so the triple would buy no security property — and it is not free: `requires` is
`repeated string requires = 9` on the ttRPC wire (`agent.proto`), so the triple means a
breaking protocol change. A wire break for a property already held is not a trade worth
making. The escaping remains load-bearing either way, since `id()` also backs
`VerifiedFragment.id` and the exported log.

---

## 4. Capability detail

### 4.1 Core: signed, authorized, add-only, monotonic (FR-1a/1b/1c)
`FragmentStore` (in `fragments.rs`) is the verifier and add-only accumulator. `authorize_issuer`
registers a measured Ed25519 key; `set_min_svn`/`declare_feed` set floors; `verify` runs the
gates without mutating; `commit` raises the SVN high-water mark and records the id; `load` = verify+commit. `apply_fragment_module`
(`policy.rs`) merges a verified module additively and refuses a package outside its `includes`
namespace. Fail-closed: with no authorized issuers, every fragment is rejected.

**The whole load is serialized** (`FRAGMENT_LOAD` in `main.rs`). `verify`→apply→`commit` spans
three separate store-lock acquisitions plus the policy-engine lock, and the agent's ttrpc server
dispatches concurrently, so without an outer guard two parallel loads both clear the SVN gate
against the same pre-state: the later apply wins the engine and the later commit sets the mark,
which let a host install a superseded fragment *and* lower the anti-rollback floor (persisted, so
a restart did not recover — F-159). The store guard itself cannot be widened, because nested
fragment registration re-enters it and the boot path takes the policy-engine lock first.
`commit` is additionally **raise-only**, so the invariant holds inside the store rather than
depending on callers committing in order. hcsshim closes the same window with
`WithMetadataRollback`'s transaction lock.

**A fragment cannot describe itself as another fragment.** The generated base policy resolves a
fragment's containers through the module's own `issuer` and `svn` rules
(`fragment_container_entries`, `container_by_ref`), so those must agree with the verified
envelope or the re-check is only the fragment restating its claim (F-160 — the shape retired in
F-158). `apply_fragment_module` refuses a divergent self-description, evaluated in a throwaway
engine on the final module text (after parameter instantiation, before the live engine sees it —
regorus has no remove-policy). A module declaring neither field still loads and simply
contributes no containers, since `to_number(mod.svn)` is then undefined. hcsshim's
`svn_ok_if_defined` likewise requires the COSE header SVN and the Rego SVN to match when both
are present.

### 4.2 did:x509 issuer identity (FR-1d)
`did_x509.rs` parses the COSE `x5chain` (header 33), path-validates leaf→CA with per-cert
signature verification and validity windows, **requires every issuer cert to assert
`basicConstraints CA:TRUE`** (so a non-CA leaf cannot mint sub-certs), enforces the did:x509
policy over the leaf, rejects revoked fingerprints, and verifies the COSE signature with the
leaf key. **Multi-algorithm (BL-2):** the leaf COSE signature dispatches on the envelope's
declared algorithm and chain-link signatures on each certificate's `signatureAlgorithm` OID —
**ES256 (P-256), ES384 (P-384), RS256 and PS256 (RSA)** are supported (shared `cose_keys.rs`
verifier), with no cross-algorithm confusion (the algorithm must match the key type). Trust is
anchored on **CA fingerprint + policy**, so leaf **rotation** — and choice of leaf algorithm —
needs no config change. Pure-Rust RustCrypto (`x509-cert`, `p256`, `p384`, `rsa`); no Go.
Errors: `InvalidCertChain`, `UntrustedCa`, `DidX509Mismatch`, `RevokedCertificate`,
`CertExpired`, `CertChainTooLong`.

The chain is **length-bounded to `MAX_X5CHAIN_CERTS` = 100** before any certificate is
touched. Every presented cert is fingerprinted and DER-parsed *before* a trust anchor has
matched, so without a bound the host — which is untrusted and chooses what to deliver —
decides how much work the guest does on a request it will refuse anyway. The check reads the
CBOR array length, so an over-long chain is rejected without allocating for it. 100 is
hcsshim's number (`cosesign1/check.go`) and is far above any real chain.

Routing is deliberately decided on **header presence, not chain validity**:
`cose_has_x5chain` selects the did:x509 path (`fragments.rs::verify_envelope_with`) by asking
only whether label 33 is there. Were it to ask whether the chain *parsed*, a host could steer
an envelope away from X.509 verification by presenting a malformed chain — the envelope
would fall through to the raw-key path instead of being refused. Presence is the question
being asked; anything wrong with the chain is then reported by `verify_x509_cose`.

### 4.3 Transparency receipts + Trust List (FR-1f)
Receipts prove a fragment's issuance is publicly auditable. The store holds a
`transparency_trust_list` (ledger id → current key set; multiple keys ⇒ rotation), per-scope
`allowed_ledgers`, and per-scope `required_receipt_from`. The receipt gate selects the ledger
(untrusted id, safe because verification only passes if that ledger's key actually signed),
enforces the allow-list and required ledger, and verifies against any current key.
**Multi-algorithm (BL-2):** each ledger key carries its algorithm, so receipts and signed
tree heads may be Ed25519, ES256, ES384, PS256, or RS256 (shared `cose_keys.rs` verifier).
Errors: `MissingReceipt`, `InvalidReceipt`, `LedgerNotAllowed`, `ReceiptFromDisallowedLedger`.
A single legacy anchor maps to a default ledger (back-compat).

### 4.4 Transparency-log inclusion + consistency — Stage 2 (FR-1f Stage 2)
`merkle.rs` implements RFC 6962 leaf/node hashing, inclusion-proof root recomputation, and
consistency-proof verification (property-tested across sizes 1..33 and every index/prefix). A
`kata-ttl-proof/v1` receipt carries a signed tree head (size, root, ledger signature), an
inclusion proof of the statement, and an optional consistency proof. The gate verifies the STH
signature against a trust-list key, verifies the statement's inclusion at that head, and
requires each head to be an **append-only extension** (consistency-proven) of the last-seen
head for that ledger. The per-ledger tree head is persisted **raise-only** so the log cannot be
rewound across restart. Errors: `InvalidInclusionProof`, `LogRolledBack`.

### 4.5 Feed scoping + composition (FR-1e / FR-1g)
Feeds partition an issuer's fragments; the base declares accepted `(issuer, feed)` pairs and
their SVN floor, and SVN is monotonic *per pair*. `requires` lets a fragment depend on
already-loaded fragments (identified by `issuer/feed/svn`), so composition is explicit and
cycle-free by construction.

### 4.6 COSE_Sign1 envelope (FR-1h)
`verify_envelope` accepts a COSE_Sign1 (CBOR) envelope and reads the fragment out of it, verified
via the pure-Rust `coset` crate — interop with standard COSE tooling with no Go dependency. The
did:x509 path (FR-1d) rides inside the same envelope via `x5chain`.

### 4.7 SVN persistence (FR-1i)
`export_svn_state`/`import_svn_state` persist the per-`(issuer,feed)` high-water marks (and the
FR-1j ordering head + FR-1f-Stage-2 tree heads) to sealed/encrypted-scratch storage. Import is
**raise-only**, so an agent/VM restart can never reopen a rollback window.

### 4.8 Append-only application ordering (FR-1j)
Each fragment's *signed* statement binds `prev_log_head`; in ordered mode the guest requires it
to equal its current rolling head, then advances `head = sha256(head ‖ sha256(statement))` on
commit. Because the predecessor head is signed by the issuer, the untrusted delivery path
cannot forge order — a reordered, omitted, or inserted fragment presents the wrong predecessor
and is rejected (`LogHeadMismatch`). `export_fragment_log` yields a deterministic,
customer-auditable record of the exact applied sequence; the head persists raise-only across
restart.

### 4.9 Declared fragments and optional enforcement (BL-8)
The measured base policy may declare the fragments it expects, in
`data.agent_policy.policy_fragments[]`:

```rego
policy_fragments := [
    {"issuer": "did:x509:0:sha256:AAA::CN:signer", "feed": "contoso.azurecr.io/frag/infra:1",
     "minimum_svn": 2, "required": true},
    {"issuer": "did:x509:0:sha256:AAA::CN:signer", "feed": "contoso.azurecr.io/frag/telemetry:1",
     "minimum_svn": 1},
]
```

**The guest does not fetch these.** At the point declarations are read the guest has only
`lo` — its interfaces and routes arrive via the `update_interface` / `update_routes` ttRPC
handlers, which cannot run until the server is serving. Delivery is the host's job, exactly
as in C-ACI/hcsshim (`ResourceTypePolicyFragment` → `InjectFragment` there;
`LoadPolicyFragment` here). The host is a **courier, not an authority**: it chooses which
bytes to offer and can withhold them, but the guest holds the trust anchors and does all
verification, so the host cannot forge, downgrade, or substitute a fragment. Withholding is
the one attack it retains.

A declaration always fixes the *terms* a fragment for that feed must meet — issuer, SVN
floor — and authorizes that `(issuer, feed)` pair (FR-1e). Whether its **absence** is
tolerated is the policy's choice:

| `required` | Behaviour | Equivalent in C-ACI/hcsshim |
| --- | --- | --- |
| `false` (default) | Delivery is lazy. An undelivered fragment contributes no rules. | Yes — hcsshim injection is lazy and carries no obligation |
| `true` | `CreateContainer` is refused until the fragment is delivered and verified. | **No equivalent** — this is stricter than C-ACI |

The default is `false` because absence is already fail-safe in the common case: a container
only the missing fragment would have permitted does not match the composed policy and is
refused on its own merits, so withholding can only ever *reduce* what runs. Making every
declaration blocking would turn it into an availability dependency on the host for no
security gain.

Set `required: true` when absence is **not** fail-safe — a fragment carrying a deny rule, an
audit obligation, or a constraint the base policy was written assuming had been composed in.
Silence is not a safe default for those. Because the flag is per-declaration, one policy can
demand a mandatory baseline while leaving optional add-ons optional.

`required: false` is **not** `unchecked`. A delivered fragment is verified identically either
way — same issuer binding, same SVN floor, same receipt and ordering gates — and is still
cross-checked against its declaration, so one arriving with the wrong issuer or an SVN below
the measured floor is rejected regardless. The flag governs only whether absence is an error.

Enforcement lives in `agent/src/policy_fragments.rs`
(`record_declared_fragments` / `assert_all_declared_satisfied`), called from
`rpc.rs::create_container` *before* `is_allowed()` — the point being that the active policy
is not yet the measured one, so its verdict is not the one to act on.

### 4.10 Delegated declarations — `allow_nested` (BL-8)

A base policy has to name every fragment it expects at build time. That is fine for a fixed
composition and awkward for a layered one: an infrastructure fragment that itself depends on
a networking fragment forces the dependency up into the base policy, where the author may not
know it exists and certainly cannot track its version.

`allow_nested` lets a declaration delegate that. A fragment may carry fragment declarations
of its own, in its Rego module at `policy_fragments` inside its own package, and the agent
registers them as though the base policy had declared them.

Nested declarations are **signed**. `policy_module` is covered by the fragment statement's
payload, so they ride the same COSE signature as everything else the fragment carries. The
host cannot add, remove, or edit one — which is why the declarations live in the module rather
than in a new header field: the module is already signed, where a new field would have been
one more thing for a verifier and a signer to agree about.

> Note: an earlier revision of this document justified that choice by saying a format change
> would "invalidate every artifact signed to date". That is not true and should not be cited.
> The bespoke statement went `v1` → `v2` → `v3` → `v4` within this branch as fields were
> added, and was then removed entirely (RM-75); no signed artifact exists in the tree (every
> test signs at runtime, and the only signers are in-tree tooling), and the branch is
> unreleased. Format changes are cheap here; weigh one on its own merits.

Delegation is off unless the *authorizing* declaration turns it on, and one attribute carries
both the switch and its reach, so the two cannot drift apart:

| `allow_nested` | nested declarations may name |
| --- | --- |
| omitted / `false` / `"none"` | *nothing* — no delegation (default) |
| `"same-issuer"` | the delivering fragment's own issuer only |
| `"any-authorized"` | any issuer the measured trust root authorizes |
| `["did:x509:…", …]` | exactly the issuers listed |

`true` is **rejected**, not interpreted. It enables delegation without saying to whom, and
both possible guesses are wrong: permissive silently widens the scope, and silently treating
it as off leaves the author believing a control is on when it is not. The error names the
valid forms. Unknown mode strings and empty issuer lists are rejected for the same reason — a
typo like `same_issuer` must surface at boot, not become a quiet no-op. At boot this is
fatal; a malformed declaration arriving later, inside a fragment, is dropped rather than
allowed to take down a running sandbox.

**Delegation cannot widen trust.** A declaration only says a feed is expected. The fragment
behind it must still be signed by an issuer the *measured trust root* authorizes, or
`verify_envelope` rejects it as `UnauthorizedIssuer` — so `"any-authorized"` means "anyone the
trust root already trusts", never "anyone". `min_required()` keeps the issuer-wide SVN floor
binding (F-55), and `declare_feed` is raise-only (F-165), so a nested declaration can raise
the rollback bar for a feed but never lower it. What delegation buys is composition, not
privilege.

Bounds and behaviours worth knowing:

- **Depth is capped at 4.** Each level must opt in through its own `allow_nested`, so a chain
  cannot extend itself silently; the cap is a backstop against a cycle (A declares B, B
  declares A) rather than the primary control. No legitimate composition needs depth — an
  issuer wanting five fragments declares five, it does not build a linked list.
- **First declaration wins.** A feed already declared keeps its original terms, so a
  re-declaration cannot reset a cycle's depth counter or relax an SVN floor a shallower
  declaration set. That guard is keyed on the delegation table, which the *trust root* does
  not write to — so it did not by itself protect a feed the operator pinned and the base
  policy never re-declared (F-165). The SVN floor is now raise-only in the store
  (`declare_feed`), so the property holds for every declarer regardless of which table
  remembers it.
- **Out-of-scope declarations are dropped, not fatal.** The delivering fragment is verified
  and committed by the time its declarations are read, so failing the RPC would leave the
  engine holding a module the host was told had failed. Dropping is fail-closed anyway: an
  unregistered declaration authorizes no feed, so the fragment behind it is refused as
  `UndeclaredFeed` and grants nothing. Each drop is logged with the reason.
- **A fragment nobody declared gets no delegation.** The runtime push path stays open, but
  nothing granted such a fragment a scope, so its nested declarations are ignored.
- **A nested declaration may set `required: true`**, which blocks *subsequent* container
  creation. It cannot retroactively stop containers already running. This is a denial-of-
  service vector, but only from a signer the trust root authorizes and a parent that
  explicitly delegated to it — which is the delegation working as asked, not a bypass.

Registration lives in `policy_fragments.rs::register_nested_fragments`, called from
`rpc.rs::load_policy_fragment` after verify, inject, and commit. Reading the declarations
uses `policy.rs::nested_fragment_specs`, scoped to the package the module was actually
accepted under, so two fragments in different namespaces cannot see or overwrite each
other's.

**Live coverage.** Delegation is proven on a real CVM cluster by stage 07 cases `07f`–`07k`,
not by unit tests alone. The oracle is pod phase: a nested declaration marked `required: true`
becomes an obligation the host never satisfies, so *registered* means `create_container` is
refused and the pod never runs, while *dropped* means it boots. That reads the scope decision
in both directions from outside the guest.

| Case | Grant on the parent declaration | Delivered | Pod | Reads |
| --- | --- | --- | --- | --- |
| `07f` | *(none)* | parent | Running | delegation is off unless granted |
| `07g` | `"same-issuer"` | parent | never Running | the nested declaration was registered |
| `07h` | `"same-issuer"` | parent + child | Running | the chain completes: child fetched, verified, obligation satisfied |
| `07i` | `"same-issuer"` | parent (declares a foreign issuer) | Running | out-of-scope declaration dropped |
| `07j` | `["<foreign did>"]` | parent (same) | never Running | an explicit list admits exactly what it names |
| `07k` | `"any-authorized"` | parent (same) | never Running | the permissive scope admits an issuer the parent does not share |

`07i` and `07j` deliver the *same* fragment and differ only in the grant, so a pass cannot be
a delivery failure wearing a scope check's clothes. The "foreign" issuer is a did:x509 string
that never signs anything, which is deliberately the stronger fixture: a scope check that
wrongly admitted it cannot then be rescued by a downstream signature failure and still look
correct.

C-ACI/hcsshim has the equivalent capability, and — usefully — puts the switch in the same
place we do. `candidate_fragments` is the union of the base policy's `fragments` array and
the declarations contributed by already-loaded fragments, and whether a given fragment's own
declarations are harvested is decided by `includes: ["fragments"]` on **the declaration that
authorized it**, not by anything the fragment itself asserts. So delegation is parent-granted
and opt-in there too.

The difference is the *scope*. hcsshim's switch is a bare boolean: once a declaration says
`includes: ["fragments"]`, the fragment behind it may name any `(issuer, feed)` pair it
likes, and `fragment_issuer_feed_ok` compares only the incoming fragment against the
candidate — never the candidate against the issuer that declared it. There is also no depth
cap and no cycle guard (`update_issuer` appends, so a re-load of the same feed simply stacks
another entry). `allow_nested` is that same parent-granted opt-in with the reach written
down, plus the depth cap and first-declaration-wins rule.

### 4.11 Gate parity with hcsshim on the load path

Every check hcsshim performs before accepting a fragment has an equivalent or stronger
counterpart here. Audited 2026-08-04 against `pkg/securitypolicy/framework.rego` and the
Go verification path.

| hcsshim gate | ours | verdict |
| --- | --- | --- |
| COSE_Sign1 signature + cert chain (`cosesign1.UnpackAndValidateCOSE1CertChain`) | `fragments.rs::verify_envelope` | parity |
| did:x509 → issuer identity (`didx509resolver.Resolve`) | `did_x509.rs:290-349`, derived DID must equal declared issuer | parity |
| issuer+feed must match a candidate (`fragment_issuer_feed_ok`) | `declare_feed` allow-list; otherwise `UndeclaredFeed` | parity |
| SVN ≥ `minimum_svn` (`header_svn_ok`, `svn_ok_if_defined`) | single signed `svn`, and `min_required()` takes the **max** with the trust root's issuer-wide floor | **stronger** — a declaration cannot sink below the issuer floor; hcsshim honours the per-declaration value alone |
| `required_receipts` (`fragment_receipts_ok`) | `require_receipt` (global) + `required_receipt_from` (per issuer/feed), conjunctive, with `*` / `TTL:<subject>` / ledger-name entries | parity, plus an `allowed_ledgers` allow-list on the *presented* ledger |
| module confined to a namespace (`add_module`, `input.namespace`) | `apply_fragment_module` package confinement | parity |
| metadata-only load (`add_module` false) | `allow_module` on the measured grant | parity |
| — | `required`: fragment must be present before containers start | **ours only** |
| — | `allow_nested` issuer scope, depth cap, first-declaration-wins | **ours only** (hcsshim opt-in is unscoped, uncapped, and stacks duplicates) |
| — | namespace grant comes from measured state, never the fragment's own `includes` | parity (hcsshim reads the declaration too); we additionally intersect with the request |
| — | SVN high-water marks persisted across agent restart (FR-1i) | **ours only** |
| — | Stage-2 transparency inclusion + consistency proofs (§4.4) | **ours only** |
| — | certificate revocation checked during chain validation | **ours only** (`cosesign1go` does no OCSP/CRL) |
| header SVN and Rego SVN must agree (`svn_ok_if_defined`) | module self-description pinned to the verified envelope (§4.1) | parity — ours also pins the issuer, not just the SVN |
| concurrent/nested loads rejected (`WithMetadataRollback` transaction lock) | whole load serialized behind `FRAGMENT_LOAD` (§4.1) | parity — we serialize where hcsshim fails closed |
| `framework_version` floor on the base policy (denied if ahead) | `check_framework_version` (§4.14, FR-1l) | parity |
| policy *must* declare `framework_version`; missing is an error | genpolicy stamps it into every generated policy (§4.14); absent stays legacy-allowed for policies already in the field | parity in effect — the floor is armed for everything we produce; we decline the hard requirement rather than break older policies, which by declaring nothing expect nothing newer |
| `fragment_framework_version` checked on load (step 5) | `assert_self_description` applies the same floor to the fragment's module (§4.14) | parity |
| `api_version` + per-endpoint `introducedVersion`/`default_results` | `default XRequest := false` + the FR-7 mediation manifest | parity by other means — same fail-closed outcome, no version to keep in sync |
| cert chain bounded to 1–100 certs | `did_x509.rs::extract_x5chain` (`MAX_X5CHAIN_CERTS`) | parity — DoS mitigation; same bound as `cosesign1/check.go` |

Deltas that are **not** gates — surface hcsshim has and we do not, none of which is a check we
skip:

- The richer `includes` vocabulary (`external_processes`, `platform_rules`,
  `transparency_trust_lists`), which names hcsshim policy sections we do not have. The two
  halves of `platform_rules` that deployment pipelines actually need are both covered — the
  environment half as of FR-1n (§4.19) and the mount half as of FR-1o (§4.20) — and each is
  bounded by the measured base policy rather than granted wholesale. `external_processes`
  remains hcsshim-only.
- Trying **several** parameter sets per fragment. hcsshim concatenates every `parameters`
  object declared for an `(issuer, feed)` and compiles the fragment once per set, because
  its loading is lazy and it cannot know which instantiation the host will want. Ours is one
  set per declaration: delivery is explicit and a feed is declared once, so there is exactly
  one intended instantiation. hcsshim itself forbids multiple sets when the fragment claims
  a namespace.
- Semver `framework_version` negotiation via `apply_defaults`, i.e. filling in fields an
  older policy could not have named. Ours is done in Rust with `#[serde(default)]` on every
  added field, so an older declaration parses under a newer agent with the same effect. The
  security-relevant half of that mechanism — refusing a policy *newer* than the enforcer —
  is implemented, see §4.14.

### 4.14 Framework version floor (FR-1l)

A policy may declare `framework_version` (semver) to state what it was written against. Equal
or older is enforced; **newer is refused**.

The asymmetry is the point. A policy older than the agent is safe: the agent implements every
gate it names, and a gate the policy does not name is simply not requested. A policy newer
than the agent is not, and the reason is a property of Rego: an unknown rule name is not an
error but an undefined value. A policy written for gates this binary has never heard of would
not fail loudly — those gates would silently not happen, while the policy looked enforced.
Downgrading the enforcer is exactly the move an adversary would want, so this fails closed.
hcsshim reaches the same conclusion structurally: `apply_defaults` has cases for equal and
older framework versions and deliberately none for newer, so a newer policy leaves the rule
undefined and denies.

An absent declaration is legacy and allowed — that is every policy written before the check
existed, and such a policy by definition expects nothing newer. An *explicit but malformed*
one is an error, so a typo cannot be mistaken for "unversioned". `POLICY_FRAMEWORK_VERSION`
is compiled into the agent and bumped when a gate is added that a policy could depend on; it
is deliberately not the agent version, since two agents may differ in ways policy cannot
observe.

**The floor has two arms**, both added under F-161.

First, it has a **producer**: `genpolicy` stamps `framework_version` into every policy it
generates, so the check is armed for the policies we actually ship rather than only for a
hand-written policy that opts in. The constant is duplicated in `genpolicy::policy` rather
than imported, because `kata-agent-policy` is a dev-dependency there and linking the policy
engine into a host-side generator to read one string is not a trade worth making; the two are
held equal by `framework_version_matches_the_agent` in genpolicy's `tests/policy`, where both
crates are in scope, and every generation case in that suite asserts the stamp is present. We
still treat an absent declaration as legacy rather than requiring it as hcsshim does: policies
generated before this change are in the field, and refusing them would break compatibility
without buying anything, since a policy that declares nothing expects nothing newer.

Second, it covers **fragments as well as the base policy**. `check_framework_version` runs
from `set_policy` and reads `data.agent_policy.framework_version`, while a fragment's module
lands under `data.agent_policy.fragments.<feed>` — so `assert_self_description` applies the
same rule to the fragment's own module at load time, mirroring hcsshim's
`fragment_framework_version` (step 5 of `load_fragment`). This matters because a fragment is
the only policy input that is neither measured nor default-denied, so its author has no other
way to state what it needs. Exposure was nil in practice — fragments contribute `containers`
and nothing else (§4.1), and an unread *permission* is a denial — but the gate is what keeps
that true if a fragment ever expresses a restriction.

### 4.13 Parameterised fragments (FR-1k)

A fragment may read values through `parameter("name")` instead of hard-coding them, so one
signed artefact serves several deployments without being re-signed per value — hcsshim's
fragment `parameters`. Values are supplied by the **declaration** (`policy_fragments[].parameters`,
or `[[issuer.feed]] parameters` in the trust root), never by the fragment or the host: a
parameter can decide which env var value or command a rule admits, so it is authority-bearing
and belongs with the measured state that authorized the fragment in the first place.

After the COSE signature has been verified over the fragment's original bytes, the agent
appends to the module a `__fragment_parameters` constant and a total `parameter` function
that resolves, in order: the supplied value, the `default` the fragment declares for that
name in its own `parameters_api`, then `null`. The appended text is generated by the guest
from measured data, so instantiating a fragment neither requires nor grants the ability to
alter what was signed. The value must be a JSON object; a scalar or array is rejected rather
than coerced, because every lookup would otherwise fall silently through to its default and a
mis-specified policy would read as configured while behaving as permissive.

```rego
# in the base policy
policy_fragments := [{
  "issuer": "did:x509:...", "feed": "reg/net:1", "minimum_svn": 3,
  "parameters": {"allowed_registry": "myregistry.azurecr.io"},
}]

# in the signed fragment module
parameters_api := {"allowed_registry": {"default": "mcr.microsoft.com"}}
registry_ok { input.image_registry == parameter("allowed_registry") }
```

### 4.19 Fragment-contributed environment rules (FR-1n)

A deployment pipeline is not static. A given version of the API server, kubelet or containerd
may inject an environment variable the policy author never wrote down, and a feature flag may
be turned on by a pipeline stage rather than by the workload manifest. Without a delegation
path the only way to admit such a variable is to regenerate and re-measure the base policy —
re-establishing the security boundary for a change that was never about security.

hcsshim answers this with `platform_rules`: an included fragment carries environment rules
that are applied across every container. Effective, but unbounded — including the fragment
hands it the whole environment namespace, and nothing in the base policy limits which
variables it may speak for.

Ours is the same capability with the grant made explicit. The **declaration** names the
variables it is willing to let a feed decide; the **fragment** supplies the concrete rules
inside that ceiling.

```rego
# in the measured base policy
policy_fragments := [{
  "issuer": "did:x509:...", "feed": "prod/mut:1", "minimum_svn": 5,
  "allow_env_rules": ["^FEATURE_FLAG_[A-Z0-9_]+$"],
}]

# in the signed fragment module, at agent_policy.fragments["prod/mut:1"]
env_rules := [
  {"name": "FEATURE_FLAG_X", "value": "true"},
  {"name": "FEATURE_FLAG_MODE", "value": "fast|slow", "value_strategy": "re2"},
]
```

Omitting `allow_env_rules` delegates nothing, so a policy written before the attribute existed
cannot acquire the capability by upgrade. Writing `["^.+$"]` reproduces hcsshim's behaviour
exactly. Both ends of that range are expressible and the default end is closed.

Four properties make the ceiling hold rather than merely look like it does:

- **The grant is over variable *names*, and the fragment's rule names a literal.** Deciding
  whether one regex admits a subset of another is undecidable in general, so a ceiling
  expressed over whole rules could not be checked. Over names it can be, exactly.
- **Every pattern is anchored by the enforcement, not by the author's discipline.** Rego's
  `regex.match` is an unanchored search, so a ceiling of `FEATURE_FLAG` would otherwise admit
  `EVIL_FEATURE_FLAG_X`, and an `re2` value of `true` would admit `untrue`.
  `fragment_anchored` wraps both sides unconditionally.
- **Duplicate declarations intersect.** The name must be permitted by *every* declaration
  naming that `(issuer, feed)`, and at least one must exist — mirroring the strictest-wins
  rule `svn_floor` applies to rollback floors (RM-93). An existential would let a stale, laxer
  duplicate win. A declaration that omits the attribute contributes an empty list, so one
  un-granted declaration closes the door for the whole feed.
- **Delegation cannot manufacture env-rule authority.** The ceiling is built only from
  declarations in the measured base policy, so a feed that exists solely because another
  fragment delegated to it (§4.10) matches no ceiling and contributes nothing.

The SVN floor governs env rules exactly as it governs containers, so a rolled-back fragment
cannot reintroduce a grant a newer version withdrew.

A rule's value is a **literal** unless `value_strategy: "re2"` is asked for. hcsshim's
equivalent field takes a strategy with no safe default, and reading `"string"` as though it
meant "regex" is an easy mistake and an invisible one — the rule simply never matches, or,
unanchored, matches far more than intended. Defaulting to literal equality makes the quiet
outcome the safe one; an unrecognised strategy fails closed rather than falling back.

The `name=value` split takes the **first** `=`, unlike the older `allow_var` arms, whose
`split`/`count == 2` idiom silently refuses every value containing an `=` — base64 payloads,
connection strings, JWTs — a common shape for exactly the pipeline-injected variables this
exists to admit.

Scope note: this covers the environment half of `platform_rules`. The mount half is FR-1o,
immediately below, which reuses this section's ceiling machinery — including `fragment_anchored`
and the intersect-duplicates rule — and adds the constraints a mount specifically needs.

### 4.20 Fragment-contributed mounts (FR-1o)

The drift argument of §4.19 applies to mounts as directly as it does to environment variables,
and often for the same release. A newer kubelet moves a projected service-account token; a CSI
driver attaches a directory under a name the workload manifest never mentions; a cluster-wide
admission webhook injects an observability socket. Each is a mount the policy author could not
have written down, and each otherwise forces a regeneration and re-measurement of the base
policy for a change that was never about security.

hcsshim's `platform_rules` carries mounts alongside environment rules, and concatenates them
onto every container's mount list. As with env, the capability is right and the bound is
missing: including the fragment hands it the entire mount namespace.

The shape mirrors FR-1n. The **declaration** names the destinations it will let a feed speak
for; the **fragment** supplies concrete mount rules inside that ceiling.

```rego
# in the measured base policy
policy_fragments := [{
  "issuer": "did:x509:...", "feed": "prod/mut:1", "minimum_svn": 5,
  "allow_mount_rules": ["^/var/run/platform/[a-z0-9/._-]+$"],
}]

# in the signed fragment module, at agent_policy.fragments["prod/mut:1"]
mount_rules := [{
  "destination": "/var/run/platform/telemetry.sock",
  "source": "/run/host/telemetry.sock",
  "source_strategy": "string",
  "type_": "bind",
  "options": ["rbind", "rprivate", "ro", "nosuid", "nodev", "noexec"],
}]
```

Omitting `allow_mount_rules` delegates nothing, so — as with env rules — a policy written
before the attribute existed cannot acquire the capability by upgrading the agent.

The ceiling reuses FR-1n's machinery wholesale: destinations are matched with the same
unconditional anchoring (`fragment_anchored`), duplicate declarations **intersect** rather than
union, at least one declaration must exist so a feed reachable only through delegation (§4.10)
contributes nothing, and the SVN floor governs mounts exactly as it governs containers. The
rule's `destination` is compared **literally**, which is what makes the ceiling an exact test
rather than an undecidable regex-subset question.

Three further constraints are specific to mounts, and each is tighter than hcsshim:

- **A fragment may only add a destination, never restate one the base policy declares**
  (`fragment_mount_is_new`). Without it a fragment could shadow a measured mount with a laxer
  one — declaring `/data` read-only in the base policy would count for nothing if a fragment
  could re-admit `/data` read-write — and the weakening would be invisible, because the base
  declaration would still be sitting there reading `ro`. Fragments extend the mount set; they
  cannot rewrite it.
- **Options must match exactly, not by subset**, and a rule that omits `options` therefore
  admits only a mount carrying none. Mount options *are* the security-relevant part of a mount
  — `ro`, `nosuid`, `nodev`, `noexec` — so a subset test would let the enforcement ignore
  precisely the fields worth enforcing.
- **`source` is a literal unless `source_strategy: "re2"` is asked for**, and `type_` is always
  literal. Same reasoning as the env rule's value strategy: the quiet outcome is the safe one,
  and an unrecognised strategy fails closed.

The enforcement point is worth noting because it is not where one would first reach for it.
`allow_by_bundle_or_sandbox_id` requires a **bijection** between presented mounts and policy
mounts, via `allow_mount`, which returns an *index into* `p_oci.Mounts`; the check is
`count(p_matches) == count(i_oci.Mounts)`. A fragment mount cannot simply be added to the
candidate set, because it has no such index — it would have to invent one that cannot collide
with a real one, or two presented mounts would silently collapse onto a single match and defeat
the bijection. Instead the permitted fragment mounts are **set aside first** and the bijection
is required of what remains. The base check is left byte-for-byte as it was, and the whole of
the new attack surface is confined to one predicate, `fragment_mount_permitted`.

### 4.12 Receipt requirement grammar (FR-1f)

`required_receipt_from` is a **conjunction**: a fragment is accepted only when *every* entry
is satisfied by some validated receipt. This matches hcsshim's `fragment_receipts_ok`, which
evaluates `every requirement in required_receipts`. Requiring all of them is the point — a
list is how a policy says "countersigned by the vendor *and* logged publicly", and an any-of
reading would silently downgrade that to "either will do". A single-entry list, which is what
every existing configuration uses, means exactly what it always did.

| entry | satisfied by |
| --- | --- |
| `*` | any receipt that validated. Still requires a receipt to be present. |
| `TTL:<subject>` | a receipt validated by a key that Trust List `<subject>` vouched for |
| anything else | a receipt presented under, and validated by, that ledger id |

`TTL:` resolves through *provenance* rather than the ledger id because the ledger id is
self-asserted metadata carried on the receipt, whereas the subject is a property of the
measured key material that actually validated it. Subjects are recorded per ledger key in the
measured trust root (`[[ledger]] ttl_subjects`); a key loaded without them satisfies `*` and
ledger-name entries but never a `TTL:` one — a requirement naming a subject nothing vouched
for is unmet, not vacuously true. When several keys of a ledger accept the same signature,
the union of their subjects is taken, so the outcome does not depend on key insertion order.

Satisfying a conjunction needs more than one receipt, so `LoadPolicyFragmentRequest` carries
`extra_receipts`, a list of `<ledger>=<hex signature>` entries, each an additional Stage-1
detached signature over the same signed bytes. Each must verify against a key of the
ledger it names and is subject to the same `allowed_ledgers` scope as the primary receipt —
an extra receipt is a receipt, not a way around the scope. Receipts are **not** covered by
the issuer signature (a receipt countersigns the statement and so cannot be inside it), which
is why carrying several needs no change to the envelope format.

**Compatibility.** This narrows what is accepted, so the change is fail-closed: the effect is
a fragment being refused, never one admitted. It reaches only the fragment verification path
in `FragmentStore`, which nothing but `rpc.rs::load_policy_fragment` calls -- a policy that
declares no fragments cannot be affected. Within that path it reaches only a scope naming
more than one requirement, whether that comes from `required_receipt_from` on a measured
issuer or feed, or from a declaration's own `requires`. Single-entry lists, which is what
every configuration in the tree uses, are unchanged.

---

### 4.15 Naming a fragment-contributed container in policy state (FR-1m)

`CreateContainerRequest` records, in `pstate`, which policy container authorized the
container it just admitted; later requests read it back (`ExecProcessRequest` through
`get_state_container`, and `RemoveContainer` / `SignalProcess` / the per-container lifecycle
gates for defined-ness). The set it has to name into is
`base_container_entries ++ fragment_container_entries`, and the fragment half is a
comprehension over the fragments **currently loaded**.

That set is therefore not stable. Delivering a fragment that the base policy declares
*earlier* in `policy_fragments[]` inserts its containers ahead of ones already recorded and
shifts every position after them. Recording a position would let the host re-bind a running
container to a different policy entry by choosing when to deliver a second, entirely
legitimate fragment:

```
base declares [A, B], B delivered first
  B only         : ["BASE0", "B0"]                 <- B0 recorded at index 1
  B then A loads : ["BASE0", "A0", "A1", "B0"]     <- index 1 is now A0
```

State therefore records a **reference**, not a position: `{"base": true, "idx": i}` into the
measured base array, or `{"feed": f, "svn": n, "idx": j}` into one specific version of one
fragment. `container_by_ref` resolves it and re-runs the declaration gates rather than
trusting the stored value -- the fragment must still be declared by the measured base policy,
from the issuer that declaration names, at or above its SVN floor -- and it pins the recorded
SVN **exactly**. A container admitted under one version of a fragment is consequently never
evaluated against the containers of another version of it. Both arms are undefined when any
of that fails, which makes the calling rule undefined and falls through to the fail-closed
default.

The exact-SVN pin has one cost, taken deliberately: an exec into a container whose
authorizing fragment has since been upgraded is denied rather than silently re-resolved. The
denial is fail-closed, it is host-triggered (the host chose to deliver the upgrade), and the
alternative -- accepting a newer version's container list for a container admitted under an
older one -- is the re-binding this section exists to prevent, in slower motion.

A content digest would remove the pin, but regorus is vendored here without the `crypto`
feature, so `crypto.sha256` is not available inside the policy.

hcsshim has no analogue of either the bug or the mechanism: it keeps no persisted
per-container policy state, so it has nothing to name and nothing to re-bind.

Re-verified live after the change: stage 07 is 11/11 green with the state value an
object rather than a number, so every rule that reads it -- the exec family through
`get_state_container`, and `RemoveContainer` / `SignalProcess` / the per-container
lifecycle gates for defined-ness -- still behaves as before.

---

### 4.16 The package a contributing fragment declares (FR-1m)

A fragment that contributes a container has to write the key `rules.rego` reads:

```rego
fragment_container_entries := [... |
    some spec in policy_data.fragments
    mod := data.agent_policy.fragments[spec.feed]
    ...
]
```

`spec.feed` is an OCI reference — `myregistry.io/fragments/sidecar` — and a Rego
rule name must be a bare identifier, so no module can define that key by rule
name. The only way to write it is a quoted package path segment:

```rego
package agent_policy.fragments["myregistry.io/fragments/sidecar"]

issuer := "did:x509:..."
svn := 3
containers := [ ... ]     # full container policy entries, layer root hashes and all
```

regorus accepts that package form. `apply_fragment_module` did not: it compared
the raw package text against exactly `agent_policy.fragments` and
`agent_policy.fragments.<include>`. So the contract documented in `rules.rego`
was unreachable — a fragment could be declared, delivered, verified, version-
floored, delegated and receipt-checked, and still never contribute a container.
Fail-closed, and therefore not a bypass, but it made the delivery machinery a
transport with nothing to transport. Every e2e fixture defined identifier-named
rules in the shared package, which is why eleven green cases never touched it.

The agent now also accepts exactly `agent_policy.fragments["<feed>"]`, where
`<feed>` is the feed **the SRM verified from the fragment's own COSE envelope** —
not anything the module says about itself. The comparison is on the decoded
string, so whitespace inside the brackets is tolerated while a different feed, or
a segment appended after the bracket, is not.

That is stricter than the shared package it sits beside. Two fragments writing
into `agent_policy.fragments` share one namespace and can collide; a fragment
writing under its own feed key cannot reach any other publisher's key, because
the key is the signed identity. hcsshim has no equivalent: its fragments are
namespaced by the fragment's declared `namespace` field, which the fragment
itself chooses.

Covered live by stage 07 cases 07l/07m, which build the C-ACI sidecar shape — a
base policy admitting one workload, and a separately signed fragment admitting a
second container that the base policy never contained. 07l withholds the fragment
and the sidecar must never run; 07m delivers it and both containers must become
ready. They differ in exactly one field.

How strongly the entry pins the image depends on how images reach the guest, and
it is worth stating exactly. Under **host-pull with dm-verity** the entry carries
the layer root hash, so the image is pinned by content. Under **guest-pull** —
what the e2e cluster runs — `storages` is empty and the entry pins the image
*reference* plus argv, env, mounts, user/gid and annotations; image integrity is
enforced separately, by the guest's own image-verification policy. In both cases
the fragment authorizes one specific container and nothing else, but the property
doing the pinning is not the same one, and claiming layer hashes under guest-pull
would overstate it.

**Known limitation — one version per feed per boot.** Two modules from the same
feed at different SVNs both declare the same package, so both define `containers`
and `svn` as complete rules and regorus reports a conflict when the second is
applied. That is fail-closed (the delivery is refused; nothing already applied
changes), and it is consistent with the exact-SVN pin in §4.15, which already
means a container authorized under one fragment version is not re-evaluated
against another's. It does mean a rolling fragment upgrade has to happen across a
sandbox boundary rather than inside a live sandbox. Fragments that use the shared
`agent_policy.fragments` package are unaffected only to the extent that they
declare distinct rule names, which is the same constraint stated differently.

### 4.17 Both declaration lists are read (FR-1m)

A policy can declare a trusted fragment in two places, and both of them are
measured:

* `policy_data.fragments` — BL-7. Serialized out of `genpolicy-settings.json` at
  generation time. Always present, possibly empty. This is what a settings-driven
  deployment uses.
* `policy_fragments` — BL-8. A rule in the generated policy text. **This is the
  list the agent reads to decide what the host must deliver**, and the one an
  annotation-driven deployment populates.

`fragment_container_entries` and `container_by_ref` originally read only the
first. The consequence was silent and total: a fragment declared for delivery was
fetched by the host, verified by the SRM, applied into the engine, and logged as
delivered — and then contributed no containers, because the rule that reads its
contribution was looking at a list the declaration never appears in. Nothing
errored. The only way to make it work was to declare the same fragment twice, in
two different files, with any divergence between them failing silently.

Both rules now read `all_fragment_specs := array.concat(policy_data.fragments,
policy_fragments)`. Duplicates across the two are harmless: they produce identical
container entries with identical references, and `container_by_ref` needs only one
matching declaration.

### 4.18 Authoring note — a fragment entry belongs to a pod shape

A fragment's container entry is compared against the real
`CreateContainerRequest`, and that request carries the pod's annotations: the
runtime stamps pod-level annotations onto every container's OCI spec, and
genpolicy stamps them onto every generated container entry. An entry lifted or
authored against a pod *without* the delivery annotation therefore never matches a
pod that has one — `allow_anno_key_value` refuses the unexpected
`io.katacontainers.config.agent.policy_fragments` key, and the container is denied
with no mention of the fragment.

This is not a gap; it is the annotation gate doing its job, and it is the same
constraint C-ACI fragment authors work under. It is recorded here because the
failure looks exactly like "the fragment did not load". A fragment author must
generate the entry against the pod shape the container will actually run in,
delivery annotation included. Stage 07 does this explicitly.

---

## 5. Measured configuration

Seeded at boot by `main.rs::seed_fragment_trust_root` from the **measured initdata section**
(well-known key `fragment-issuers.toml`), and only once FR-2 has bound that initdata to the
launch measurement. There is no other source: RM-89 removed the former
`/etc/kata/fragment-issuers.toml` rootfs fallback (and with it `KATA_FRAGMENT_ISSUERS`), so
absent, unbound or unusable config ⇒ no authorized issuer ⇒ fail-closed. Shape:

```toml
require_receipt = true                 # global default
```

> **`require_receipt` and `[[ledger]]` are independent options, and requiring receipts
> without configuring a ledger key is a misconfiguration, not a weaker setting.** The Stage-1
> receipt check used to be guarded on the trust list being non-empty, which made the gate
> fail *open*: the presence check was satisfied by any non-empty string while verification
> was skipped, so a garbage receipt was accepted where presenting none was correctly refused
> (F-147). The guard is gone — a receipt no key can validate is now `InvalidReceipt` — and
> `seed_fragment_trust_root` warns at startup when receipts are required but no ledger key is
> loaded, because the resulting state refuses every fragment and that is easier to diagnose
> from a log line than from a wall of rejections.

```toml
ordered = true                         # FR-1j append-only ordering
# log_genesis_hex = "<hex>"            # optional; default measured constant
require_x509 = false                   # FR-1d: when true, all fragments must carry a valid x5chain
# revoked = ["<sha256-hex>", ...]      # FR-1d revocation list

[[ledger]]                             # FR-1f transparency trust list
id = "acl"
pubkey_hex = ["<64 hex>", "<rotated>"] # Ed25519 keys; multiple ⇒ rotation
ttl_subjects = ["vendor"]              # FR-1f: Trust List subjects vouching for these keys
                                       #   (enables `TTL:vendor` requirements — see §4.12)
  [[ledger.key]]                       # BL-2: non-Ed25519 ledger key (ES256/ES384/PS256/RS256)
  alg = "es256"
  spki_hex = "<SubjectPublicKeyInfo DER, hex>"

[[ca_anchor]]                          # FR-1d did:x509 anchor
# Canonical form only: did:x509:0:sha256:<base64url(SHA-256 of the CA DER), unpadded>,
# optionally followed by "::<predicate>:<arg>..." sections. The fingerprint inside the
# DID must equal ca_fingerprint_hex below, and every predicate the DID declares must be
# one this anchor really enforces -- the agent refuses to start otherwise, so a DID can
# never advertise a trust root or a constraint that was not the one checked.
did = "did:x509:0:sha256:<base64url of the same fingerprint>::eku:1.3.6.1.5.5.7.3.3"
ca_fingerprint_hex = "<sha256 of CA DER>"
require_eku = ["1.3.6.1.5.5.7.3.3"]

[[issuer]]                             # FR-1b raw-Ed25519 issuer
id = "issuerA"
ed25519_pubkey_hex = "<64 hex>"
min_svn = 0
required_receipt_from = ["acl"]        # FR-1f per-issuer required receipts
  [[issuer.feed]]                      # FR-1e named feed
  name = "prod"
  min_svn = 0
  allowed_ledgers = ["acl"]
  required_receipt_from = ["acl", "TTL:vendor"]  # conjunctive — see §4.12
  # parameters = { allowed_registry = "myregistry.azurecr.io" }   # FR-1k, see §4.13
```

Runtime SVN/ordering/tree-head state is persisted to `/run/kata/fragment-svn.state`
and re-imported raise-only at boot. The path is fixed in a shipped build: `KATA_FRAGMENT_SVN_STATE` is honoured only under the test-only `test-path-override` feature, because the agent's environment is host-influenced (the kernel passes unrecognised `key=value` command line parameters to init as environment variables) and a redirected path would silently reset the rollback floor on every boot (F-86).

---

## 6. Tooling, tests, and proofs

**Tooling** (`src/agent/security-reference-monitor/examples/`, `src/tools/agent-ctl/`):
- `sign-fragment` — Ed25519 keygen + signer; emits the COSE_Sign1 envelope (always) and
  did:x509 ES256 envelopes (`--x509-key/--x509-chain`), ledger-tagged receipts (`--ledger`),
  ordering (`--prev-head`), signed bytes for a ledger (`--emit-statement`); `verify-x509`
  offline verifier.
- `mock-ledger` — RFC 6962 transparency-log stand-in emitting `kata-ttl-proof/v1` proofs.
- `agent-ctl LoadPolicyFragment` — key=value args (`cose= receipt= receipt_ledger= proof=
  extra_receipts=`). `cose=` is required and carries every signed field; the guest refuses a
  request that describes any of them (F-151).
- `fragment-demo` — offline, no-cluster/no-openssl demo asserting every capability.

**Unit tests** — fragment/identity tests (of 98 in the SRM crate): `fragments::tests::*`
(core, feed, receipt/trust-list/rotation incl. an ES256 ledger key, chaining, persistence,
COSE, ordering, Stage-2 inclusion/consistency), `did_x509::tests::*`
(valid/untrusted/broken/expired/revoked/rotated/policy-mismatch/intermediate-CA/
non-CA-intermediate + **ES384 and RSA-RS256 end-to-end**), `cose_keys::tests::*` (alg mapping,
cross-alg rejection), `merkle::tests::*` (inclusion + consistency across sizes).

**Live E2E** (strict agent build, over vsock) — `fr1-fragment-attack.sh` (deny→load→allow),
`fr1-cose-attack.sh` (COSE), `fr1-x509-attack.sh` (did:x509 valid/untrusted/revoked/rotated),
`fr1-ordering-attack.sh` (out-of-order rejected), `fr1-ttl-attack.sh` (inclusion+consistency
accepted, rewound-log + missing-proof rejected). Aggregated as `negative-matrix.sh` stages.

**Live E2E on a cluster** (`docs/cc/e2e/`, an Azure confidential VM with `kata-deploy`) —
stage 06 signs and publishes fixtures to a real registry; stage 07 runs **fourteen cases**
against pods on the dm-verity-pinned guest, using pod phase as the oracle:

| Case | Proves |
| --- | --- |
| `07a` | control — an empty `policy_fragments` list is inert |
| `07b` | a declared, `required`, undelivered fragment refuses `CreateContainer` |
| `07c` | good path — a delivered fragment is fetched, SRM-verified, injected, and the pod runs |
| `07d` | an SVN floor above the published fragment is refused |
| `07e` | an undelivered *optional* declaration still boots — enforcement is opt-in |
| `07f`–`07k` | the four `allow_nested` scopes and the full parent→child chain (see §4.10) |
| `07l`/`07m` | the C-ACI sidecar shape — a fragment contributing a container the base policy never held: withheld, the sidecar never runs; delivered, both containers run |
| `07n` | a module whose self-description claims an SVN its envelope does not carry is refused, and refused *for that reason* (F-160) |

Every negative is paired with a control differing in exactly one field, so a blocked pod
cannot be an environment failure and a running pod cannot be a gate that was never armed.
Verified green 2026-08-08 on `ccpolicy-snp` (`E2E_PLATFORM=clh-snp`, SEV-SNP/MSHV), 14/14.

Conjunctive receipt requirements (§4.12) and fragment parameters (§4.13) are unit-tested
only. A live case for the receipt conjunction needs a second mock ledger fixture; tracked in
`docs/cc/backlog.md`. The framework version floor (§4.14) is unit-tested for its refusal
paths and covered end-to-end for its *producer* — every genpolicy generation case asserts the
stamp is present, so stages 04 and 06 exercise it on every run.

---

## 7. Net guarantee

Unsigned, wrong-issuer, untrusted-CA, revoked, expired, non-CA-intermediate, rolled-back,
undeclared-feed, over-broad, missing/invalid/disallowed-receipt, out-of-order, or
unsatisfied-requirement fragments are all rejected fail-closed. Accepted fragments extend the
live policy additively, in a verifiable order, with an auditable record — never relaxing a base
invariant and never reopening a rollback window, even across a restart.
