#!/usr/bin/env bash
# 06 — signed policy-fragment end-to-end (FR-1).
#
# Two halves, because the feature has two distinct boundaries:
#
#   A. Verification boundary — `fragment-demo` drives the real `FragmentStore`
#      (the same one the guest boot-pull and the runtime push path both use) and
#      asserts every positive and negative outcome internally: unsigned,
#      unauthorized issuer, SVN rollback, revoked cert, reordered log head,
#      missing/foreign receipt. Offline, no cluster.
#
#   B. Delivery boundary — sign a real fragment, package it as an OCI artifact,
#      push it, and assert the artifact contract the guest fetcher depends on
#      (artifactType + layer mediaType). Then emit the base-policy settings entry
#      and the measured trust root needed for a live boot-pull.
#
# Only B needs a registry; only the optional live check needs a cluster.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 06-policy-fragment-e2e

step "06 — signed policy-fragment e2e"
load_toolchain
need jq
need curl
cd "$E2E_REPO_DIR" || die "no repo at $E2E_REPO_DIR"

WORK="${E2E_FRAGMENT_WORK:-$E2E_STATE_DIR/fragments}"
# The issuer private key lands here. Restrict before anything is written: this
# directory persists, and a 0644 signing key would let any local account mint
# fragments that the trust root accepts.
(umask 077; mkdir -p "$WORK")
chmod 700 "$WORK" || die "could not restrict $WORK"

# Contract constants — these must match src/agent/src/policy_fragments.rs.
ARTIFACT_TYPE="application/x-ms-ccepolicy-frag"
COSE_MEDIA_TYPE="application/cose-x509+rego"

SIGN()    { cargo run -q --example sign-fragment -p kata-security-reference-monitor -- "$@"; }
FRAGGEN() { cargo run -q -p genpolicy-fragmentgen -- "$@"; }

# =============================================================== A. verification
step "06a — verification boundary (fragment-demo)"
# fragment-demo asserts on every outcome, so a non-zero exit here is a real
# security regression rather than a flaky environment.
if cargo run -q --example fragment-demo -p kata-security-reference-monitor \
     > "$WORK/fragment-demo.log" 2>&1; then
  ok "fragment-demo passed — all FR-1 positive and negative cases hold"
  tail -5 "$WORK/fragment-demo.log" | sed 's/^/    /'
else
  tail -40 "$WORK/fragment-demo.log" | sed 's/^/    /'
  die "fragment-demo FAILED — a fragment verification invariant regressed"
fi

# ================================================================== B. delivery
step "06b — issuer keypair and measured trust root"
(umask 077; SIGN gen-key > "$WORK/key.txt") || die "gen-key failed"
chmod 600 "$WORK/key.txt"
PRIV=$(grep '^private_key_hex=' "$WORK/key.txt" | cut -d= -f2)
PUB=$(grep  '^public_key_hex='  "$WORK/key.txt" | cut -d= -f2)
[ -n "$PRIV" ] && [ -n "$PUB" ] || die "could not parse the keypair"
# NOTE: sign-fragment only accepts the private key as a hex argv value, so it is
# briefly visible in /proc/<pid>/cmdline. Acceptable for a throwaway dev key on a
# single-user VM; do not reuse this key or this flow for anything real.
ok "issuer key generated (pub ${PUB:0:16}...)"

ISSUER="${E2E_FRAGMENT_ISSUER:-did:example:e2e-issuer}"
# The feed is baked into the COSE payload at signing time, and the guest fetches
# *that* — not whatever --push points at. So the registry has to be settled here,
# before 06c signs; mirroring the artifact afterwards would not repoint the guest.
if ensure_acr; then
  E2E_REGISTRY="$ACR_LOGIN_SERVER"
else
  ACR_LOGIN_SERVER=""; ACR_USERNAME=""; ACR_PASSWORD=""
  [ -n "${E2E_ACR:-}${E2E_ACR_LOGIN_SERVER:-}" ] &&
    warn "falling back to $E2E_REGISTRY — stage 07 will skip its guest-fetch cases"
fi
FEED="${E2E_FRAGMENT_FEED:-$E2E_REGISTRY/coco-e2e/fragment}"
SVN="${E2E_FRAGMENT_SVN:-2}"
MIN_SVN="${E2E_FRAGMENT_MIN_SVN:-1}"

# min_svn is the FR-1i rollback floor. require_receipt=false keeps this run
# self-contained; set it true (and add a [[ledger]]) to exercise FR-1f as well.
cat > "$WORK/fragment-issuers.toml" <<EOF
require_receipt = false

[[issuer]]
id = "$ISSUER"
ed25519_pubkey_hex = "$PUB"
min_svn = $MIN_SVN
EOF
ok "trust root written: $WORK/fragment-issuers.toml"

cat > "$WORK/fragment.rego" <<'EOF'
package agent_policy.fragments

# Minimal, observable fragment: a successful injection makes this visible to
# policy evaluation, so the live boot-pull check has something to assert on.
#
# The package is agent_policy.fragments, not agent_policy: the guest confines
# fragment modules to the fragment namespace so an injected module can never
# redefine or shadow a base rule (policy.rs apply_fragment_module, TC-F1.2).
# A fragment in the base package is refused at injection -- after a successful
# fetch and signature check -- so only a live boot-pull shows it up.
e2e_fragment_loaded := true
EOF

step "06c — sign the fragment"
# --cose is what makes the signer emit the COSE_Sign1 envelope (FR-1h); without it
# only the raw signature is printed and the OCI packaging step has nothing to push.
SIGN sign \
  --issuer "$ISSUER" \
  --feed   "$FEED" \
  --svn    "$SVN" \
  --module "$WORK/fragment.rego" \
  --key    "$PRIV" \
  --cose > "$WORK/sign.txt" || die "signing failed"

grep '^cose_sign1_hex=' "$WORK/sign.txt" | cut -d= -f2 > "$WORK/fragment.cose.hex"
[ -s "$WORK/fragment.cose.hex" ] || die "signer did not emit cose_sign1_hex"
ok "COSE_Sign1 envelope produced ($(wc -c < "$WORK/fragment.cose.hex") hex chars)"

step "06d — package and push the OCI artifact"
PLAIN_HTTP=""
REG_HOST="${E2E_REGISTRY%%:*}"
if [ "$REG_HOST" = "localhost" ] || [ "$REG_HOST" = "127.0.0.1" ]; then
  PLAIN_HTTP="--plain-http"
  if ! curl -fsS "http://$E2E_REGISTRY/v2/" >/dev/null 2>&1; then
    log "starting a local OCI registry at $E2E_REGISTRY"
    docker rm -f coco-e2e-registry >/dev/null 2>&1 || true
    # --restart and a named volume so a node reboot does not silently empty the
    # registry: fragment-ref.txt persists on disk and would keep asserting the
    # artifact exists, leaving stage 07 to fail at the fetch minutes later with
    # diagnostics pointing at delivery rather than at a registry that went away.
    docker run -d --name coco-e2e-registry --restart unless-stopped \
      -v coco-e2e-registry-data:/var/lib/registry \
      -p "${E2E_REGISTRY##*:}:5000" \
      registry:2 >/dev/null || die "could not start the local registry"
    wait_for 60 "registry $E2E_REGISTRY responding" curl -fsS "http://$E2E_REGISTRY/v2/"
  fi
fi

TAG="${E2E_FRAGMENT_TAG:-e2e}"
# Credentials go through the environment, never argv: /proc/<pid>/cmdline is
# world-readable, and this token can push to the registry the guest trusts.
if [ -n "${ACR_PASSWORD:-}" ]; then
  export FRAGMENTGEN_USERNAME="$ACR_USERNAME" FRAGMENTGEN_PASSWORD="$ACR_PASSWORD"
fi
FRAGGEN --cose "$WORK/fragment.cose.hex" --push "$FEED:$TAG" $PLAIN_HTTP \
  > "$WORK/entry.txt" || die "packaging/push failed"
unset FRAGMENTGEN_USERNAME FRAGMENTGEN_PASSWORD
ok "pushed $FEED:$TAG"

# Record the reference the artifact was pushed to, which is not the same thing as
# the feed. The feed is a trust identity: it is what the COSE envelope commits to
# and what the measured policy names, and it carries no tag. Fetching needs an OCI
# reference, tag included. Stage 07 needs both -- the feed for the declaration, the
# reference for the delivery annotation -- and inferring one from the other means
# guessing the tag, which silently resolves to :latest and fails as a missing
# manifest well away from the cause.
printf '%s\n' "$FEED:$TAG" > "$WORK/fragment-ref.txt"

# fragmentgen prints a human-readable header before the entry, so the raw capture
# is not valid JSON. Extract just the object so step 06f emits something that can
# be pasted straight into the base policy.
sed -n '/^  {$/,/^  }$/p' "$WORK/entry.txt" > "$WORK/fragment-entry.json"
jq -e . "$WORK/fragment-entry.json" >/dev/null \
  || { cat "$WORK/entry.txt"; die "could not extract a valid policy_fragments[] entry"; }

# The guest fetcher selects the layer by artifactType and mediaType. If either
# drifts, boot-pull finds nothing and the VM fails closed — so assert the
# published manifest, not just the exit code.
REPO="${FEED#*/}"
MAN=""
if [ -n "$PLAIN_HTTP" ]; then
  MAN=$(curl -fsS -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        "http://$E2E_REGISTRY/v2/$REPO/manifests/$TAG") \
    || die "could not read back the pushed manifest"
else
  # Read back *anonymously* over HTTPS — deliberately the same shape of request
  # the guest makes, so this doubles as a preflight that anonymous pull is really
  # on. A registry API GET needs a bearer token even when anonymous, so do the
  # WWW-Authenticate dance the guest's OCI client does internally.
  TOK=$(curl -fsS "https://$E2E_REGISTRY/oauth2/token?service=$E2E_REGISTRY&scope=repository:$REPO:pull" \
        | jq -r '.access_token // .token // empty') || TOK=""
  [ -n "$TOK" ] || die "could not get an anonymous pull token for $E2E_REGISTRY — is anonymous pull enabled?"
  MAN=$(curl -fsS -H "Authorization: Bearer $TOK" \
          -H "Accept: application/vnd.oci.image.manifest.v1+json" \
          "https://$E2E_REGISTRY/v2/$REPO/manifests/$TAG") \
    || die "could not read back the pushed manifest anonymously — the guest could not fetch it either"
  ok "anonymous pull verified against $E2E_REGISTRY"
fi
echo "$MAN" | jq -e --arg t "$ARTIFACT_TYPE" '.artifactType == $t' >/dev/null \
  || die "artifactType mismatch: expected $ARTIFACT_TYPE, got $(echo "$MAN" | jq -r .artifactType)"
echo "$MAN" | jq -e --arg m "$COSE_MEDIA_TYPE" '.layers[0].mediaType == $m' >/dev/null \
  || die "layer mediaType mismatch: expected $COSE_MEDIA_TYPE"
ok "OCI artifact contract verified (artifactType + layer mediaType)"

step "06e — negative: --plain-http must be refused for a remote registry"
if out=$(FRAGGEN --cose "$WORK/fragment.cose.hex" \
           --push "example.azurecr.io/coco-e2e/fragment:$TAG" --plain-http 2>&1); then
  die "plain-HTTP push to a remote registry SUCCEEDED — downgrade exposure"
fi
# Any non-zero exit would otherwise pass this test, including a compile error or a
# DNS failure. Require the specific guard message from genpolicy-fragmentgen.
echo "$out" | grep -q -- "--plain-http is only allowed for localhost/loopback registries" \
  || { echo "$out" | tail -10; die "push failed, but not via the plain-HTTP guard"; }
ok "plain-HTTP refused for a non-loopback registry (expected)"

# ---------------------------------------------------------------- wiring output
step "06f — wiring for a live boot-pull"
cat <<EOF

Stage 07 (07-fragment-bootpull.sh) does all of this for you against the cluster
from 03/04. The wiring below is what it applies, recorded here so the artifacts
are usable by hand too.

 1. Add this to the BASE policy's data.agent_policy.policy_fragments[]:

$(sed 's/^/      /' "$WORK/fragment-entry.json")

 2. Deliver the measured trust root through initdata under the key
    "fragment-issuers.toml":

$(sed 's/^/      /' "$WORK/fragment-issuers.toml")

 3. Boot a pod (see 05-smoke-test.sh) and confirm injection:

      journalctl -t kata -g 'FR-1' | tail -40

    Expect: config sourced from measured initdata, then the fragment fetched,
    verified and injected. Any failure aborts the VM — fail-closed is correct.

EOF

ok "policy-fragment e2e passed"
mark_done 06-policy-fragment-e2e
