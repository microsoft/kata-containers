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
| **FR-1h** | **COSE_Sign1 envelope** interop (pure-Rust `coset`, no Go) | `fragments.rs::verify_cose` | `c0ea3cb25`, `f7ed23319`, `93e1ff6e5` |
| **FR-1i** | **SVN rollback protection across restart** — raise-only persisted high-water marks | `fragments.rs::{export_svn_state,import_svn_state}`; `main.rs` persist | `c0ea3cb25`, `f7ed23319` |
| **FR-1j** | **append-only application ordering** — signed rolling log head; reject reorder/omit/insert; exportable auditable log | `fragments.rs::{set_log_genesis,log_head,export_fragment_log}` (gate 8, `commit`) | `8efdaa65e` |
| tools/demo | offline signer, agent-ctl command, mock ledger, self-contained capability demo | `examples/{sign-fragment,mock-ledger,fragment-demo}.rs`; `agent-ctl` | `392d890a8`, `69228f3b5`, `a63b9d5b3` |
| docs | in-tree guide + this reference | `docs/cc/{parma-hardening-features,fr1-fragment-e2e,fr1-fragments}.md`, `kata-opa/fragment-demo.rego` | `adaa7558b`, `d8149983e`, `b65ba9113`, `26d013c95`, `5dc0744f9` |

---

## 3. Verification pipeline (order of gates)

Every fragment is verified by a chain of fail-closed gates before it is committed. Both the
native detached-signature path (`verify`), the COSE path (`verify_cose`), and the did:x509
path (`verify_cose_x509`) converge on the shared `check_gates`:

1. **Issuer identity + signature.** Either (a) the issuer is in the measured authorized set and
   an Ed25519 signature verifies over the canonical statement, or (b) a did:x509 chain in the
   COSE `x5chain` path-validates to a measured CA (each issuer cert `CA:TRUE`, in-date),
   satisfies the did:x509 policy (subject CN / EKU / DNS SAN), is not revoked, and the leaf key
   signs the statement — and the derived did equals the declared issuer. No downgrade: an
   x5chain-bearing envelope is always verified as did:x509.
2. **Feed declared** (FR-1e) — `(issuer, feed)` must be an accepted pair.
3. **Monotonic SVN** (FR-1b/1e/1i) — `svn ≥ max(declared floor, persisted high-water + 1)`.
4. **Transparency receipt** (FR-1f) — if required for the scope: a Stage-1 detached ledger
   signature and/or a Stage-2 inclusion+consistency proof, from an `allowed_ledgers` ledger,
   verified against a current trust-list key; Stage 2 also requires the signed tree head to be
   an append-only extension of the last-seen head (monotonic, consistency-proven).
5. **Composition** (FR-1g) — every `requires` id must already be loaded.
6. **Add-only** — a fragment may only add grants; it may never introduce a grant that relaxes
   a declared root constraint.
7. **Ordering** (FR-1j) — in ordered mode, the fragment's *signed* `prev_log_head` must equal
   the store's current rolling head; the head then advances by hashing the statement in.

The statement (`signing_bytes`, `kata-policy-fragment/v3`) binds issuer, feed, SVN, sorted
grants, module, sorted includes, sorted requires, **and** `prev_log_head` — so none of these,
including the asserted predecessor, can be altered without invalidating the signature. The
receipt/ledger id and the transparency proof are countersignatures/assertions *over* that
statement and are deliberately outside it.

---

## 4. Capability detail

### 4.1 Core: signed, authorized, add-only, monotonic (FR-1a/1b/1c)
`FragmentStore` (in `fragments.rs`) is the verifier and add-only accumulator. `authorize_issuer`
registers a measured Ed25519 key; `set_min_svn`/`declare_feed` set floors; `verify` runs the
gates without mutating; `commit` advances SVN/grants; `load` = verify+commit. `apply_fragment_module`
(`policy.rs`) merges a verified module additively and refuses a package outside its `includes`
namespace. Fail-closed: with no authorized issuers, every fragment is rejected.

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
`CertExpired`.

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
`verify_cose` accepts a COSE_Sign1 (CBOR) envelope whose payload equals the statement, verified
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
| `false` (default) | Delivery is lazy. An undelivered fragment contributes no grants. | Yes — hcsshim injection is lazy and unobligated |
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
`signing_bytes()`, so they ride the same COSE signature as everything else the fragment
carries. The host cannot add, remove, or edit one — which is why the declarations live in the
module and not in a new statement field: adding a signed field would bump the statement
format from `kata-policy-fragment/v3` to v4 and invalidate every artifact signed to date.

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
`verify_cose` rejects it as `UnauthorizedIssuer` — so `"any-authorized"` means "anyone the
trust root already trusts", never "anyone". `min_required()` keeps the issuer-wide SVN floor
binding (F-55), so a nested declaration can raise the rollback bar but never lower it. What
delegation buys is composition, not privilege.

Bounds and behaviours worth knowing:

- **Depth is capped at 4.** Each level must opt in through its own `allow_nested`, so a chain
  cannot extend itself silently; the cap is a backstop against a cycle (A declares B, B
  declares A) rather than the primary control. No legitimate composition needs depth — an
  issuer wanting five fragments declares five, it does not build a linked list.
- **First declaration wins.** A feed already declared keeps its original terms, so a
  re-declaration cannot reset a cycle's depth counter or relax an SVN floor a shallower
  declaration set.
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
| COSE_Sign1 signature + cert chain (`cosesign1.UnpackAndValidateCOSE1CertChain`) | `fragments.rs::verify_cose` / `verify_cose_x509` | parity |
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

Deltas that are **not** gates — surface hcsshim has and we do not, none of which is a check we
skip:

- The richer `includes` vocabulary (`external_processes`, `platform_rules`,
  `transparency_trust_lists`), which names hcsshim policy sections we do not have.
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

`TTL:` indirects through *provenance* rather than the ledger id because the ledger id is
self-asserted metadata carried on the receipt, whereas the subject is a property of the
measured key material that actually validated it. Subjects are recorded per ledger key in the
measured trust root (`[[ledger]] ttl_subjects`); a key loaded without them satisfies `*` and
ledger-name entries but never a `TTL:` one — a requirement naming a subject nothing vouched
for is unmet, not vacuously true. When several keys of a ledger accept the same signature,
the union of their subjects is taken, so the outcome does not depend on key insertion order.

Satisfying a conjunction needs more than one receipt, so `LoadPolicyFragmentRequest` carries
`extra_receipts`, a list of `<ledger>=<hex signature>` entries, each an additional Stage-1
detached signature over the same fragment statement. Each must verify against a key of the
ledger it names and is subject to the same `allowed_ledgers` scope as the primary receipt —
an extra receipt is a receipt, not a way around the scope. Receipts are **not** covered by
the issuer signature (a receipt countersigns the statement and so cannot be inside it), which
is why carrying several needs no `kata-policy-fragment` version bump.

**Compatibility.** This narrows what is accepted, so the change is fail-closed: the effect is
a fragment being refused, never one admitted. It reaches only the fragment verification path
in `FragmentStore`, which nothing but `rpc.rs::load_policy_fragment` calls -- a policy that
declares no fragments cannot be affected. Within that path it reaches only a scope naming
more than one requirement, whether that comes from `required_receipt_from` on a measured
issuer or feed, or from a declaration's own `requires`. Single-entry lists, which is what
every configuration in the tree uses, are unchanged.

---

## 5. Measured configuration

Seeded at boot by `main.rs::seed_fragment_trust_root` from a measured-rootfs file
(`/etc/kata/fragment-issuers.toml`, override `KATA_FRAGMENT_ISSUERS`); absent config ⇒ no
authorized issuer ⇒ fail-closed. Shape:

```toml
require_receipt = true                 # global default
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
did = "did:x509:0:demo-ca:issuerX"
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
(override `KATA_FRAGMENT_SVN_STATE`) and re-imported raise-only at boot.

---

## 6. Tooling, tests, and proofs

**Tooling** (`src/agent/security-reference-monitor/examples/`, `src/tools/agent-ctl/`):
- `sign-fragment` — Ed25519 keygen + signer; emits detached sig, COSE_Sign1 (`--cose`),
  did:x509 ES256 envelopes (`--x509-key/--x509-chain`), ledger-tagged receipts (`--ledger`),
  ordering (`--prev-head`), statements for a ledger (`--emit-statement`); `verify-x509`
  offline verifier.
- `mock-ledger` — RFC 6962 transparency-log stand-in emitting `kata-ttl-proof/v1` proofs.
- `agent-ctl LoadPolicyFragment` — key=value args (`issuer= svn= feed= includes= requires=
  receipt= receipt_ledger= prev_head= proof= module= sig= cose=`).
- `fragment-demo` — offline, no-cluster/no-openssl demo asserting every capability.

**Unit tests** — fragment/identity tests (of 98 in the SRM crate): `fragments::tests::*`
(core, feed, receipt/trust-list/rotation incl. an ES256 ledger key, chaining, persistence,
COSE, ordering, Stage-2 inclusion/consistency), `did_x509::tests::*`
(valid/untrusted/broken/expired/revoked/rotated/policy-mismatch/intermediate-CA/
non-CA-intermediate + **ES384 and RSA-RS256 end-to-end**), `cose_keys::tests::*` (alg mapping,
cross-alg rejection), `merkle::tests::*` (inclusion + consistency across sizes).

**Live E2E** (strict `kata-parma`, over vsock) — `fr1-fragment-attack.sh` (deny→load→allow),
`fr1-cose-attack.sh` (COSE), `fr1-x509-attack.sh` (did:x509 valid/untrusted/revoked/rotated),
`fr1-ordering-attack.sh` (out-of-order rejected), `fr1-ttl-attack.sh` (inclusion+consistency
accepted, rewound-log + missing-proof rejected). Aggregated as `negative-matrix.sh` stages.

**Live E2E on a cluster** (`docs/cc/e2e/`, an Azure confidential VM with `kata-deploy`) —
stage 06 signs and publishes fixtures to a real registry; stage 07 runs **eleven cases**
against pods on the dm-verity-pinned guest, using pod phase as the oracle:

| Case | Proves |
| --- | --- |
| `07a` | control — an empty `policy_fragments` list is inert |
| `07b` | a declared, `required`, undelivered fragment refuses `CreateContainer` |
| `07c` | good path — a delivered fragment is fetched, SRM-verified, injected, and the pod runs |
| `07d` | an SVN floor above the published fragment is refused |
| `07e` | an undelivered *optional* declaration still boots — enforcement is opt-in |
| `07f`–`07k` | the four `allow_nested` scopes and the full parent→child chain (see §4.10) |

Every negative is paired with a control differing in exactly one field, so a blocked pod
cannot be an environment failure and a running pod cannot be a gate that was never armed.
Verified green 2026-08-04 on `coco-dev-2`, 11/11.

Conjunctive receipt requirements (§4.12), fragment parameters (§4.13) and the framework
version floor (§4.14) are unit-tested only. A live case for the receipt conjunction needs a
second mock ledger fixture; tracked in `docs/cc/backlog.md`.

---

## 7. Net guarantee

Unsigned, wrong-issuer, untrusted-CA, revoked, expired, non-CA-intermediate, rolled-back,
undeclared-feed, over-broad, missing/invalid/disallowed-receipt, out-of-order, or
unsatisfied-requirement fragments are all rejected fail-closed. Accepted fragments extend the
live policy additively, in a verifiable order, with an auditable record — never relaxing a base
invariant and never reopening a rollback window, even across a restart.
