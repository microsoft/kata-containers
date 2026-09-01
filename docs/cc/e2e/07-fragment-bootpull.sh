#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
# 07 — live delivery of a declared policy fragment (BL-8), on the cluster.
#
# Stage 06 stops at the delivery boundary: it signs a fragment, publishes it, and
# prints the wiring. Nothing there boots a VM, so nothing there proves the guest
# actually consumes a declaration. This stage closes that gap.
#
# Delivery is host-side. The guest cannot fetch its own fragments: at that point
# in boot it has no interfaces, because those arrive only via the ttRPC handlers
# it has not started serving yet. So the shim pulls the artifact and pushes the
# COSE bytes over LoadPolicyFragment, and the guest — which is the only party
# holding trust anchors — verifies them and refuses to create any container while
# a fragment its *measured* policy declares is still unsatisfied.
#
# That gate makes pod phase a sound oracle in both directions:
#
#   declaration absent                        -> Running       (control: wiring is inert)
#   declared required, never delivered        -> never Running (fail-closed)
#   declared required, delivered, valid       -> Running       => delivered AND verified AND injected
#   declared optional, never delivered        -> Running       (C-ACI parity: lazy delivery)
#
# 07f-07k extend the same oracle to *delegation* — declarations a delivered
# fragment carries in its own signed module. Because those are marked
# `required: true`, the pod-phase reading inverts cleanly: a nested declaration
# that gets registered becomes an obligation the host never satisfies and blocks,
# while one that is dropped blocks nothing. So:
#
#   delegation not granted                    -> Running       (off by default)
#   granted, child withheld                   -> never Running (it was registered)
#   granted, child delivered                  -> Running       (the chain completes)
#   granted same-issuer, foreign child        -> Running       (out of scope, dropped)
#   granted by explicit list / any-authorized -> never Running (in scope, registered)
#
# The third inference is only valid because of the second: had any step failed,
# the gate would still be shut. So "Running with a non-empty policy_fragments[]"
# is proof of a completed delivery, without reading anything out of the guest.
#
# The fourth is what shows the enforcement is opt-in rather than unconditional,
# and it differs from the second by exactly one field.
#
# The control is not optional decoration. Without it, a pod that fails to start
# for an unrelated reason (a bad rules.rego patch, a broken node) would read as a
# passing fail-closed test. 07a must go green using the identical mechanism, or
# 07b proves nothing.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 07-fragment-bootpull

step "07 — delivery of declared policy fragments (BL-8)"
load_toolchain
load_coco_env
need jq
need kubectl

# Same preflight as the smoke test: without the locally built guest this stage
# would exercise the CI nightly agent, which has no strict-policy build and
# therefore no fragment gate at all — and would report a green control plus a green
# "fail-closed" (the pod fails for a different reason entirely).
assert_local_guest_installed

NS="${E2E_NS:-coco-e2e}"
# Resolve the genpolicy inputs for whichever platform is in use: on the QEMU path
# stage 03 stages them into the installed defaults directory; on clh-snp nothing
# installs them, so they are staged straight from the branch.
ensure_genpolicy_defaults
SETTINGS="${GP_SETTINGS}"
RULES_SRC="${GP_RULES}"

# Stage 03 installs both genpolicy inputs from the branch and asserts they match.
# Re-assert it here, because 03 may have run many commits ago and these two files
# are a matched pair: rules.rego reads its thresholds and allow-lists out of
# genpolicy-settings.json, so a rules.rego that is newer than the settings beside
# it generates policies that deny things the branch means to allow. That failure
# does not look like a stale file -- it looks like a working pod that cannot be
# signalled, or a container that cannot be created -- and it is expensive to chase.
#
# Nothing rewrites the settings on the way in any more -- what this platform
# needs beyond the branch's defaults lives in a genpolicy-settings.d/ drop-in --
# so both files can be compared verbatim against the branch.
#
# On clh-snp the check is skipped: ensure_genpolicy_defaults stages both files
# from the branch at the point of use, so there is no staleness left to detect
# and the comparison would be a tautology.
#
# The comparison reads the *installed* files rather than GP_RULES/GP_SETTINGS.
# Those now name the suite's staged copies, and GP_SETTINGS names a directory so
# that a drop-in can sit beside the settings; checking them would ask whether the
# suite copied its own copy correctly. What is worth asserting is that stage 03's
# install is still the branch's, which is what these two paths hold.
if [[ "${E2E_PLATFORM}" = "qemu-coco-dev" ]]; then
  GP_SRC="${E2E_REPO_DIR}/src/tools/genpolicy"
  have_rules=$(sudo sha256sum "${E2E_KATA_DEFAULTS}/rules.rego" | cut -d' ' -f1)
  want_rules=$(sha256sum "${GP_SRC}/rules.rego" | cut -d' ' -f1)
  [[ "${have_rules}" = "${want_rules}" ]] \
    || die "staged rules.rego is not the branch copy — re-run 03-deploy-cluster.sh"

  have_set=$(sudo sha256sum "${E2E_KATA_DEFAULTS}/genpolicy-settings.json" | cut -d' ' -f1)
  want_set=$(sha256sum "${GP_SRC}/genpolicy-settings.json" | cut -d' ' -f1)
  [[ "${have_set}" = "${want_set}" ]] \
    || die "staged genpolicy-settings.json is not the branch copy — re-run 03-deploy-cluster.sh"
  ok "genpolicy inputs staged from this branch"
else
  ok "genpolicy inputs re-staged from this branch by ensure_genpolicy_defaults"
fi

# Artifacts from stage 06. The COSE envelope commits to its feed, so the entry and
# the trust root must be the ones 06 actually produced — regenerating them here
# would silently drift from what was published.
FRAG="${E2E_FRAGMENT_WORK:-${E2E_STATE_DIR}/fragments}"
ENTRY="${FRAG}/fragment-entry.json"
ISSUERS="${FRAG}/fragment-issuers.toml"
REF_FILE="${FRAG}/fragment-ref.txt"
[[ -s "${ENTRY}" ]]   || die "missing ${ENTRY} — run 06-policy-fragment-e2e.sh first"
[[ -s "${ISSUERS}" ]] || die "missing ${ISSUERS} — run 06-policy-fragment-e2e.sh first"
[[ -s "${REF_FILE}" ]] || die "missing ${REF_FILE} — re-run 06-policy-fragment-e2e.sh"

ISSUER=$(jq -r .issuer      "${ENTRY}") || die "could not read issuer from ${ENTRY}"
FEED=$(jq -r .feed          "${ENTRY}") || die "could not read feed from ${ENTRY}"
SVN=$(jq -r .minimum_svn    "${ENTRY}") || die "could not read minimum_svn from ${ENTRY}"
[[ -n "${ISSUER}" && -n "${FEED}" && -n "${SVN}" ]] || die "incomplete entry in ${ENTRY}"

# What the host is told to fetch, which is deliberately not $FEED. $FEED is the
# trust identity the policy declares and the envelope commits to; it has no tag.
# $REF is the OCI reference 06 actually pushed to. Keeping them separate here is
# the point of the test: the annotation only says which bytes to offer, and the
# guest still decides whether they satisfy the declaration.
REF=$(tr -d '[:space:]' < "${REF_FILE}")
[[ -n "${REF}" ]] || die "empty reference in ${REF_FILE}"

# BL-8 delegation fixtures (06g). Read here so a fixture set predating this stage
# fails immediately and says which stage to re-run, rather than surfacing as an
# empty annotation twenty minutes later.
NESTED_FIXTURES="${FRAG}/nested-fixtures.json"
[[ -s "${NESTED_FIXTURES}" ]] \
  || die "missing ${NESTED_FIXTURES} — re-run 06-policy-fragment-e2e.sh (E2E_FORCE=1) to publish the delegation fixtures"
OTHER_ISSUER=$(jq -r .other_issuer          "${NESTED_FIXTURES}")
CHILD_REF=$(jq -r .child.ref                "${NESTED_FIXTURES}")
PARENT_SAME_FEED=$(jq -r .parent_same.feed  "${NESTED_FIXTURES}")
PARENT_SAME_REF=$(jq -r .parent_same.ref    "${NESTED_FIXTURES}")
PARENT_FGN_FEED=$(jq -r .parent_foreign.feed "${NESTED_FIXTURES}")
PARENT_FGN_REF=$(jq -r .parent_foreign.ref  "${NESTED_FIXTURES}")
NESTED_SVN=$(jq -r .svn                     "${NESTED_FIXTURES}")
for v in "${OTHER_ISSUER}" "${CHILD_REF}" "${PARENT_SAME_FEED}" "${PARENT_SAME_REF}" \
         "${PARENT_FGN_FEED}" "${PARENT_FGN_REF}" "${NESTED_SVN}"; do
  [[ -n "${v}" && "${v}" != "null" ]] || die "incomplete delegation fixtures in ${NESTED_FIXTURES}"
done

# $REF_FILE persists on disk; the artifact it names does not necessarily still
# exist. Stage 06's registry survives a reboot on the docker path but not on the
# containerd one, and either way it can be removed by hand, so a node reboot can
# leave localhost:5000 refusing connections with the ref file still cheerfully
# asserting the fragment is there. Without this probe the first thing to notice
# is 07c timing out after five minutes, and the stage's own diagnostics then
# point at delivery/verification/injection rather than at a registry that is
# simply down. Resolve the manifest before creating any pod, so a stale fixture
# fails immediately and says so.
REF_PATH="${REF#*/}"                 # repo/name:tag
REF_HOST="${REF%%/*}"
REF_TAG="${REF_PATH##*:}"
REF_REPO="${REF_PATH%:*}"
# Only the loopback dev registry is probed directly. A real registry (ACR) speaks
# HTTPS and wants a token, so a bare GET proves nothing there; the reboot trap
# this guards against is specific to the throwaway container 06 starts anyway.
case "${REF_HOST%%:*}" in
  localhost | 127.0.0.1)
    if ! curl -fsS -o /dev/null \
         -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
         "http://${REF_HOST}/v2/${REF_REPO}/manifests/${REF_TAG}" 2>/dev/null; then
      warn "the node cannot resolve ${REF}"
      warn "stage 06 publishes it to a registry started without --restart or a volume,"
      warn "so a reboot empties it. Re-run: E2E_FORCE=1 ./run-all.sh 06 07"
      die "the fragment 06 published is not fetchable — nothing to deliver"
    fi
    ok "the published fragment is still fetchable from this node (${REF})"
    ;;
  *)
    log "registry ${REF_HOST} is not loopback — skipping the reachability probe"
    ;;
esac

# A declaration the host will never be able to satisfy, for the fail-closed case.
# It is never offered via the delivery annotation either, so this negative cannot
# go green for an environmental reason.
UNREACHABLE_FEED="${E2E_FRAGMENT_UNREACHABLE_FEED:-localhost:5000/coco-e2e/absent:e2e}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ------------------------------------------------------------------- genpolicy
# Always build genpolicy from the branch; see ensure_branch_genpolicy() in lib.sh
# for why an installed binary cannot stand in for one built from source.
#
# This used to be conditional on `--initdata-path` being absent, which looked
# like a currency check and was not one: the nightly already had that flag, so
# the probe passed and the stale tool ran. It then silently dropped every
# request_defaults key it did not know — including SignalProcessRequest, whose
# allowed_signals the branch's rules.rego reads. The generated policies denied
# SIGKILL, and pods that started could never be stopped or removed.
#
# The assertion below is a capability gate on the *branch* build, not a currency
# probe on an installed one — it must stay after the build, never replace it.
ensure_branch_genpolicy
"${GENPOLICY}" --help 2>&1 | grep -q -- '--initdata-path' \
  || die "branch genpolicy lacks --initdata-path — cannot deliver the trust root"

# -------------------------------------------------------------------- fixtures
# The trust root travels as a measured initdata key, which is the provenance the
# agent prefers (BL-5). A TOML literal block is used so the hex key and the DID
# pass through unescaped and the value is byte-identical to the file 06 wrote.
render_initdata() {
  printf 'version = "0.1.0"\nalgorithm = "sha256"\n\n[data]\n"fragment-issuers.toml" = %s\n%s\n%s\n' \
    "'''" "$(cat "${ISSUERS}")" "'''"
}
render_initdata > "${WORK}/initdata.toml"

# genpolicy concatenates the rules file verbatim into the generated policy, and
# `policy_fragments` is undefined upstream, so appending the declaration to a copy
# of the staged rules is the whole wiring. Append rather than edit in place: the
# staged copy is what stage 03 asserted, and mutating it would poison stage 05.
render_rules() {
  local out="$1" decl="$2"
  cat "${RULES_SRC}" > "${out}" || die "could not copy ${RULES_SRC}"
  printf '\n# BL-8 (e2e stage 07): boot-time fragment declarations.\npolicy_fragments := %s\n' \
    "${decl}" >> "${out}"
}

render_pod() {
  # Mirrors 05-smoke-test.sh: where the image is pulled in the guest, genpolicy
  # refuses images whose user/group would come from the layers, so the
  # securityContext must be explicit at pod level.
  #
  # $2, when set, is the fragment delivery hint. BL-8 delivery is host-side: the
  # shim fetches each reference and pushes the COSE envelope over the
  # LoadPolicyFragment RPC. The annotation only says *what to offer* — the
  # issuer, feed and SVN floor come from the measured policy, so a case that
  # omits it (or names the wrong thing) exercises the fail-closed path.
  local frag_anno=""
  if [[ -n "${2:-}" ]]; then
    frag_anno="
  annotations:
    io.katacontainers.config.agent.policy_fragments: \"$2\""
  fi
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: ${NS}${frag_anno}
spec:
  runtimeClassName: ${E2E_RUNTIMECLASS}
$(pod_pin)
  restartPolicy: Never
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    supplementalGroups: [10]
  containers:
    - name: busybox
      image: ${E2E_BUSYBOX_IMAGE}
      command: ["sleep", "600"]
EOF
}

# Generate a policy over the given rules + initdata and apply the pod.
apply_case() {
  # Separate statements on purpose: bash expands every word of a declaration
  # command before performing any of its assignments, so `yaml` could not refer
  # to `pod` on the same line.
  local pod="$1" rules="$2" deliver="${3:-}"
  local yaml="${WORK}/${pod}.yaml"
  render_pod "${pod}" "${deliver}" > "${yaml}"
  "${GENPOLICY}" -y "${yaml}" -p "${rules}" -j "${SETTINGS}" \
    --initdata-path="${WORK}/initdata.toml" >/dev/null \
    || die "genpolicy failed for ${pod}"
  # This build delivers the policy through initdata, not the legacy agent.policy
  # annotation, so a "did the policy land?" check must look for cc_init_data.
  grep -q 'cc_init_data' "${yaml}" || die "no cc_init_data annotation for ${pod}"
  assert_request_defaults_survived "${yaml}" "${pod}"
  kubectl delete pod "${pod}" -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl apply -f "${yaml}" >/dev/null || die "kubectl apply failed for ${pod}"
}

# genpolicy does not copy request_defaults through as opaque JSON: it
# deserializes the settings into a typed struct and re-serializes that struct
# into the policy. Any key the binary's struct does not declare is dropped
# without a word. rules.rego then reads an undefined value, the rule becomes
# undefined, and the fail-closed default denies the endpoint -- a denial that
# looks like a policy decision and is really a missing field.
#
# That is how SignalProcessRequest.allowed_signals vanished and left pods
# unstoppable. Compare the key sets rather than trusting the tool: what the
# settings declare is exactly what the generated policy must carry.
assert_request_defaults_survived() {
  local yaml="$1" pod="$2" missing
  missing=$(python3 - "${yaml}" "${SETTINGS}" <<'PY'
import base64, glob, gzip, json, os, re, sys

yaml_path, settings_path = sys.argv[1], sys.argv[2]
blob = re.search(r'cc_init_data:\s*"?([A-Za-z0-9+/=]+)"?', open(yaml_path).read())
if not blob:
    print("could not read the cc_init_data annotation")
    raise SystemExit(0)
policy = gzip.decompress(base64.b64decode(blob.group(1))).decode("utf-8", "replace")

# The policy is rego text with a JSON data block appended; pull just the
# request_defaults object out by brace matching.
i = policy.find('"request_defaults"')
if i < 0:
    print("the generated policy has no request_defaults block at all")
    raise SystemExit(0)
depth, start = 0, None
for k in range(i + len('"request_defaults"'), len(policy)):
    if policy[k] == "{":
        if depth == 0:
            start = k
        depth += 1
    elif policy[k] == "}":
        depth -= 1
        if depth == 0:
            break
got = set(json.loads(policy[start:k + 1]))


# genpolicy takes either a settings file or a directory; where it is a directory
# it reads genpolicy-settings.json plus every genpolicy-settings.d/*.json as an
# RFC 6902 patch, in lexical order. Both forms are in use here -- coco-dev and
# clh-snp carry a drop-in -- so resolve the same inputs genpolicy saw. Applying
# only the request_defaults ops keeps this from reimplementing a patch engine;
# anything else in a drop-in cannot change the key set being compared.
def load_request_defaults(path):
    if os.path.isdir(path):
        settings = json.load(open(os.path.join(path, "genpolicy-settings.json")))
        for name in sorted(glob.glob(os.path.join(path, "genpolicy-settings.d", "*.json"))):
            for op in json.load(open(name)):
                p = op.get("path", "")
                if not p.startswith("/request_defaults"):
                    continue
                parts = p.lstrip("/").split("/")
                if len(parts) != 2:
                    raise SystemExit(
                        "drop-in %s patches %s; this check only understands "
                        "whole request_defaults keys" % (name, p)
                    )
                if op["op"] == "remove":
                    settings["request_defaults"].pop(parts[1], None)
                elif op["op"] in ("add", "replace"):
                    settings["request_defaults"][parts[1]] = op["value"]
                else:
                    raise SystemExit("drop-in %s uses unsupported op %r" % (name, op["op"]))
        return settings["request_defaults"]
    return json.load(open(path))["request_defaults"]


want = set(load_request_defaults(settings_path))
print(" ".join(sorted(want - got)))
PY
  ) || die "could not inspect the generated policy for ${pod}"
  [[ -z "${missing}" ]] || die "genpolicy dropped request_defaults key(s) [${missing}] from ${pod}'s policy — the binary predates the settings; it must be built from this branch"
}

pod_phase() { kubectl get pod "$1" -n "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null; }

# Fail as soon as the pod reports Running, rather than only sampling at the end:
# a sandbox that comes up and is then torn down would otherwise slip through.
expect_never_running() {
  local pod="$1" secs="$2" deadline
  deadline=$(( $(date +%s) + secs ))
  log "watching ${pod} for ${secs}s — it must never reach Running"
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    [[ "$(pod_phase "${pod}")" = "Running" ]] && return 1
    sleep 5
  done
  return 0
}

diagnose() {
  local pod="$1"
  warn "diagnostics for ${pod}:"
  kubectl describe pod "${pod}" -n "${NS}" 2>&1 | tail -25 | sed 's/^/    /'
  # A strict guest discards its own log stream instead of forwarding it to the host
  # (FR-7 / F-79), so what follows is the shim's view, not the guest's. It was already
  # informational and never the assertion; it is now also expected to be thin.
  sudo journalctl -t kata --since '-10m' 2>/dev/null | grep -i 'FR-1\|fragment' \
    | tail -15 | sed 's/^/    /' || true
}

cleanup_pod() { kubectl delete pod "$1" -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true; }

ensure_ns "${NS}"

# ============================================================ 07a — the control
step "07a — control: an empty declaration must still boot"
render_rules "${WORK}/rules-none.rego" '[]'
apply_case e2e-frag-none "${WORK}/rules-none.rego"
if ! wait_for_soft 300 "pod e2e-frag-none Running" \
     bash -c "kubectl get pod e2e-frag-none -n ${NS} -o jsonpath='{.status.phase}' | grep -qx Running"; then
  diagnose e2e-frag-none
  die "the control pod did not boot — the patched base policy is broken, so no fail-closed result below would mean anything"
fi
ok "control booted — patching policy_fragments is inert when the list is empty"
cleanup_pod e2e-frag-none

# ====================================================== 07b — fail-closed (BL-8)
step "07b — a declared but undelivered fragment must not run containers"
render_rules "${WORK}/rules-bad.rego" \
  "[{\"issuer\": \"${ISSUER}\", \"feed\": \"${UNREACHABLE_FEED}\", \"minimum_svn\": 1, \"required\": true}]"
# No delivery annotation on purpose: the measured policy declares a fragment the
# host never offers. This is the case that matters, because delivery is now the
# host's job and the host is untrusted — a host that simply withholds a fragment
# must not get a container out of it.
#
# "required": true is what arms that gate. Without it the declaration is lazy,
# which is C-ACI/hcsshim behaviour, and this pod would legitimately boot — that
# is 07e below. Asserting both directions is the only way to show the flag is
# actually read rather than the gate being unconditional or dead.
apply_case e2e-frag-unfetchable "${WORK}/rules-bad.rego"
if expect_never_running e2e-frag-unfetchable "${E2E_FRAGMENT_NEG_WAIT:-180}"; then
  ok "pod never reached Running — the unsatisfied declaration held the gate (expected)"
  # Necessary but not sufficient on its own: a guest that never runs anything at
  # all would also pass this. 07c is what shows the gate opens for a fragment
  # that is actually delivered and verified.
  kubectl describe pod e2e-frag-unfetchable -n "${NS}" 2>/dev/null \
    | grep -i 'sandbox\|failed' | tail -3 | cut -c1-200 | sed 's/^/    /' || true
else
  diagnose e2e-frag-unfetchable
  cleanup_pod e2e-frag-unfetchable
  die "pod is Running despite an undelivered declared fragment — the fail-closed gate is not wired"
fi
cleanup_pod e2e-frag-unfetchable

# ================================================ 07c/07d — the delivered feed
# No reachability gate here any more. Delivery is host-side, so the shim fetches
# the artifact and pushes the bytes in — a loopback dev registry is as usable as
# an ACR, because it only has to be reachable from the node.
step "07c — good path: a delivered, valid fragment must let containers run"
render_rules "${WORK}/rules-good.rego" \
  "[{\"issuer\": \"${ISSUER}\", \"feed\": \"${FEED}\", \"minimum_svn\": ${SVN}, \"required\": true}]"
apply_case e2e-frag-good "${WORK}/rules-good.rego" "${REF}"
if ! wait_for_soft 300 "pod e2e-frag-good Running" \
     bash -c "kubectl get pod e2e-frag-good -n ${NS} -o jsonpath='{.status.phase}' | grep -qx Running"; then
  diagnose e2e-frag-good
  cleanup_pod e2e-frag-good
  warn "the host fetches ${REF} and pushes it over LoadPolicyFragment. Check, in order:"
  warn "  - can the node pull it?  crane manifest ${REF}  (or the 06 read-back)"
  warn "  - did the shim try?      journalctl -t kata | grep policy-fragments"
  warn "  - did the guest reject it? look for a FAILED_PRECONDITION from the RPC"
  die "the declared fragment did not let the pod run — delivery, verification, or injection failed"
fi
# Sound only because 07b established that an unsatisfied declaration blocks:
# had the fetch, the signature check, the SVN floor or the injection failed,
# this pod would have been held at create_container instead of reaching Running.
ok "pod ran with a declared fragment => it was delivered, SRM-verified and injected"
sudo journalctl -t kata --since '-10m' 2>/dev/null | grep -i 'FR-1\|policy-fragments' | tail -5 \
  | sed 's/^/    /' || true
cleanup_pod e2e-frag-good

step "07d — negative: an SVN floor above the published fragment must be refused"
# Same artifact, and it is offered — so the fetch succeeds and the rejection can
# only come from verification. This is what separates a working trust gate from
# a host that simply failed to deliver; 07b alone cannot tell those apart.
render_rules "${WORK}/rules-rollback.rego" \
  "[{\"issuer\": \"${ISSUER}\", \"feed\": \"${FEED}\", \"minimum_svn\": $((SVN + 1)), \"required\": true}]"
apply_case e2e-frag-rollback "${WORK}/rules-rollback.rego" "${REF}"
if expect_never_running e2e-frag-rollback "${E2E_FRAGMENT_NEG_WAIT:-180}"; then
  ok "pod never reached Running — the SVN rollback floor held (expected)"
else
  diagnose e2e-frag-rollback
  cleanup_pod e2e-frag-rollback
  die "pod is Running with minimum_svn above the fragment's SVN — the rollback floor is not enforced"
fi
cleanup_pod e2e-frag-rollback

# ============================================ 07e — enforcement is opt-in (BL-8)
step "07e — an undelivered *optional* declaration must still boot"
# Identical to 07b in every respect except the flag: same unreachable feed, same
# absent delivery annotation. Only "required" differs, so a difference in outcome
# can be attributed to nothing else.
#
# This is C-ACI/hcsshim parity. There, fragment injection is lazy and nothing
# obliges the host to send anything; an undelivered fragment simply contributes no
# rules, and a container only it would have permitted fails to match the composed
# policy on its own merits. Blocking unconditionally would make every declaration
# an availability dependency on the host for no security gain.
#
# Pairing this with 07b is what makes either meaningful: 07b alone is satisfied by
# a gate that is simply always shut, and 07e alone by one that is never armed.
render_rules "${WORK}/rules-optional.rego" \
  "[{\"issuer\": \"${ISSUER}\", \"feed\": \"${UNREACHABLE_FEED}\", \"minimum_svn\": 1, \"required\": false}]"
apply_case e2e-frag-optional "${WORK}/rules-optional.rego"
if ! wait_for_soft 300 "pod e2e-frag-optional Running" \
     bash -c "kubectl get pod e2e-frag-optional -n ${NS} -o jsonpath='{.status.phase}' | grep -qx Running"; then
  diagnose e2e-frag-optional
  cleanup_pod e2e-frag-optional
  die "an optional declaration blocked the pod — the BL-8 gate is enforcing declarations the policy did not mark required"
fi
ok "pod ran with an undelivered optional declaration — enforcement is opt-in (expected)"
cleanup_pod e2e-frag-optional

# ================================= 07f–07k — delegated (nested) declarations
# A delivered fragment may declare further fragments in its own signed module.
# Two separate properties have to hold, and each is tested against its own
# control rather than inferred from the other:
#
#   1. the declarations are read and registered when the measured policy granted
#      the parent delegation — and are *not* when it did not, which is the
#      default; and
#   2. what they may name is bounded by the scope that grant set.
#
# The oracle is pod phase, and it is decidable only because the declaration each
# parent carries is marked `required: true` (see 06g). Registered => an
# obligation the host never satisfies => create_container refused => the pod
# never runs. Dropped => no obligation => the pod runs. The parent fragment, its
# delivery and the base declaration are otherwise identical across a pair, so a
# difference in outcome has exactly one available explanation.
#
# Pairing is not decoration. A "blocked" case on its own is equally consistent
# with a parent that simply failed to deliver, and a "runs" case on its own with
# a gate that is never armed; only the pair distinguishes them. Every case below
# marks its parent `required: true` too, so a delivery failure turns the "runs"
# half of each pair red instead of quietly passing.
#
# Budget roughly ${E2E_FRAGMENT_NEG_WAIT:-180}s for each of the three negatives.

# A base-policy declaration for a parent fragment, with the delegation scope
# under test. $2 is raw JSON so every allow_nested form (string, list, absent)
# can be expressed without another quoting layer.
nested_decl() {
  local feed="$1" allow="$2"
  if [[ -n "${allow}" ]]; then
    printf '[{"issuer": "%s", "feed": "%s", "minimum_svn": %s, "required": true, "allow_nested": %s}]' \
      "${ISSUER}" "${feed}" "${NESTED_SVN}" "${allow}"
  else
    printf '[{"issuer": "%s", "feed": "%s", "minimum_svn": %s, "required": true}]' \
      "${ISSUER}" "${feed}" "${NESTED_SVN}"
  fi
}

# $1 pod, $2 rules file, $3 delivery annotation, $4 what a pass means.
expect_delegation_blocked() {
  local pod="$1"
  apply_case "${pod}" "$2" "$3"
  if expect_never_running "${pod}" "${E2E_FRAGMENT_NEG_WAIT:-180}"; then
    ok "${pod} never reached Running — $4 (expected)"
  else
    diagnose "${pod}"
    cleanup_pod "${pod}"
    die "${pod} is Running — $4 did not happen"
  fi
  cleanup_pod "${pod}"
}

expect_delegation_runs() {
  local pod="$1"
  apply_case "${pod}" "$2" "$3"
  if ! wait_for_soft 300 "pod ${pod} Running" \
       bash -c "kubectl get pod ${pod} -n ${NS} -o jsonpath='{.status.phase}' | grep -qx Running"; then
    diagnose "${pod}"
    cleanup_pod "${pod}"
    die "${pod} did not reach Running — $4 did not hold"
  fi
  ok "${pod} ran — $4 (expected)"
  cleanup_pod "${pod}"
}

step "07f — delegation is off unless the measured policy grants it"
# The control for 07g. Same fragment, same delivery, no allow_nested at all. The
# parent's signed module still declares a required child, and it must be ignored:
# a policy written before delegation existed must not acquire it by upgrade, and
# a fragment must not be able to bind the guest to obligations its declaration
# never authorized.
render_rules "${WORK}/rules-nest-off.rego" "$(nested_decl "${PARENT_SAME_FEED}" "")"
expect_delegation_runs e2e-frag-nest-off "${WORK}/rules-nest-off.rego" "${PARENT_SAME_REF}" \
  "an undeclared delegation was ignored"

step "07g — a granted delegation is registered and gates on its child"
# Differs from 07f in one field. The nested declaration is now in scope, so it is
# registered as an obligation — and the child is deliberately not delivered, so
# it stays outstanding and containers must be refused.
render_rules "${WORK}/rules-nest-on.rego" "$(nested_decl "${PARENT_SAME_FEED}" '"same-issuer"')"
expect_delegation_blocked e2e-frag-nest-on "${WORK}/rules-nest-on.rego" "${PARENT_SAME_REF}" \
  "the delegated declaration was registered and its undelivered child held the gate"

step "07h — good path: delivering the delegated child releases the gate"
# 07g with the child added to the delivery list. This is what shows the chain
# completes rather than merely blocking: the child is a fragment no *measured*
# declaration ever named, authorized solely by the parent's signed module, and it
# is still verified through the SRM before it can satisfy anything.
#
# Order matters and the runtime preserves it: the child's feed only becomes
# acceptable once the parent has been delivered and its declarations registered.
render_rules "${WORK}/rules-nest-good.rego" "$(nested_decl "${PARENT_SAME_FEED}" '"same-issuer"')"
expect_delegation_runs e2e-frag-nest-good "${WORK}/rules-nest-good.rego" \
  "${PARENT_SAME_REF},${CHILD_REF}" \
  "the delegated child was fetched, verified and satisfied the nested obligation"

step "07i — same-issuer must not admit a foreign issuer"
# The scope check itself. Identical grant to 07g, but the parent now names a
# *different* issuer in its nested declaration. It must be dropped, so no
# obligation is created and the pod runs — the same outcome as 07f, reached for a
# different reason, which 07j then separates.
render_rules "${WORK}/rules-nest-foreign.rego" "$(nested_decl "${PARENT_FGN_FEED}" '"same-issuer"')"
expect_delegation_runs e2e-frag-nest-foreign "${WORK}/rules-nest-foreign.rego" "${PARENT_FGN_REF}" \
  "a nested declaration outside the same-issuer scope was dropped"

step "07j — an explicit issuer list admits exactly what it names"
# 07i with the foreign issuer named in the grant. Same fragment, same delivery,
# only the scope changes — so the declaration is now in scope, registered, and
# never satisfiable. Together with 07i this shows the scope is actually consulted
# rather than the foreign case failing for some unrelated reason.
render_rules "${WORK}/rules-nest-list.rego" \
  "$(nested_decl "${PARENT_FGN_FEED}" "[\"${OTHER_ISSUER}\"]")"
expect_delegation_blocked e2e-frag-nest-list "${WORK}/rules-nest-list.rego" "${PARENT_FGN_REF}" \
  "the explicitly listed issuer was admitted and its undelivered child held the gate"

step "07k — any-authorized admits an issuer the parent does not share"
# The third scope form, and the most permissive one. Same fixture as 07i/07j; it
# must behave like 07j rather than 07i. Worth asserting separately because
# "permits everything" is the one mode a bug could produce by accident, and 07i
# alone would still pass if any-authorized had silently collapsed to same-issuer.
render_rules "${WORK}/rules-nest-any.rego" "$(nested_decl "${PARENT_FGN_FEED}" '"any-authorized"')"
expect_delegation_blocked e2e-frag-nest-any "${WORK}/rules-nest-any.rego" "${PARENT_FGN_REF}" \
  "any-authorized admitted the foreign issuer and its undelivered child held the gate"

# ================================ 07l/07m — a fragment that contributes a container
# Everything above proves the *delivery* path: declarations, scopes, SVN floors,
# delegation. None of it exercises what a fragment is ultimately for — adding a
# container the measured base policy does not contain. That is the C-ACI sidecar
# shape: the base policy admits one workload, and a separately signed fragment
# admits one further container that cannot run unless the fragment is loaded.
#
# It is worth asserting separately because it is the only case that reaches
# `fragment_container_entries`, and therefore the only one that would have caught
# F-69 (a feed is an OCI reference, so a fragment can only write its own key with
# a quoted package path — which the agent used to refuse, making this contract
# unreachable in practice while every delivery test still passed).
#
# Construction, in order:
#   1. generate a policy for the *two*-container pod and lift the sidecar's entry
#      out of it — that entry is the real generated entry for that container, so
#      the fragment admits exactly it and nothing else;
#   2. sign that entry into a fragment published under its own feed;
#   3. generate the base policy from the *one*-container pod, then append the
#      sidecar to the yaml after generation. The base policy therefore has no
#      entry that could match the sidecar, and only the fragment can authorize it.
# 07l withholds the fragment and the sidecar must never become ready; 07m delivers
# it and the sidecar must. They differ in exactly one field. Note that pod *phase*
# is not the oracle here: a pod is Running once every container has been created
# and one is up, so the sandbox and the base-policy container legitimately come up
# in both cases and only the sidecar's own status separates them.
step "07l/07m — a fragment contributes a container the base policy does not have"

SIDECAR_POD=e2e-frag-sidecar
SIDECAR_FEED="${FEED}-sidecar"
SIDECAR_TAG="${REF##*:}"
SIDECAR_REF="${SIDECAR_FEED}:${SIDECAR_TAG}"
# The sidecar is distinguished by its command, not by its name: the extractor has
# to find one entry inside a generated policy, and the container name appears in
# annotations that are easy to confuse with the pause container's.
SIDECAR_MARK="sleep-601-e2e-sidecar"

# An array, not a string: unquoted it would word-split, and quoted as a string it
# would pass FRAGGEN an empty argument when the registry is not plain-HTTP.
SIDECAR_PLAIN_HTTP=()
case "${FEED%%/*}" in
  localhost*|127.0.0.1*) SIDECAR_PLAIN_HTTP=(--plain-http) ;;
esac

FRAG_KEY="${FRAG}/key.txt"
SIDECAR_PRIV=""
[[ -s "${FRAG_KEY}" ]] && SIDECAR_PRIV=$(grep '^private_key_hex=' "${FRAG_KEY}" | cut -d= -f2)

if [[ -z "${SIDECAR_PRIV}" ]]; then
  warn "no issuer key at ${FRAG_KEY} — re-run 06-policy-fragment-e2e.sh to publish a fresh one"
  warn "skipping 07l/07m (fragment-contributed container)"
elif [[ ${#SIDECAR_PLAIN_HTTP[@]} -eq 0 ]] && [[ -z "${ACR_PASSWORD:-}" ]]; then
  # Signing needs only the key; pushing needs the registry. Say which half is
  # missing, because "skipped" otherwise looks like the case does not exist.
  warn "no push credentials for ${FEED%%/*} — export ACR_USERNAME/ACR_PASSWORD to run 07l/07m"
  warn "skipping 07l/07m (fragment-contributed container)"
else

SIGN()    { ( cd "${E2E_REPO_DIR}" && cargo run -q --example sign-fragment \
              -p kata-security-reference-monitor -- "$@" ); }
FRAGGEN() { ( cd "${E2E_REPO_DIR}" && cargo run -q -p genpolicy-fragmentgen -- "$@" ); }

# $1 pod name, $2 "one"|"two" (whether the sidecar is declared), $3 delivery hint.
render_sidecar_pod() {
  local frag_anno=""
  if [[ -n "${3:-}" ]]; then
    frag_anno="
  annotations:
    io.katacontainers.config.agent.policy_fragments: \"$3\""
  fi
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
  namespace: ${NS}${frag_anno}
spec:
  runtimeClassName: ${E2E_RUNTIMECLASS}
$(pod_pin)
  restartPolicy: Never
  securityContext:
    runAsUser: 0
    runAsGroup: 0
    supplementalGroups: [10]
  containers:
    - name: busybox
      image: ${E2E_BUSYBOX_IMAGE}
      command: ["sleep", "600"]
EOF
  [[ "$2" = "two" ]] && cat <<EOF
    - name: sidecar
      image: ${E2E_BUSYBOX_IMAGE}
      command: ["sh", "-c", "echo ${SIDECAR_MARK}; sleep 600"]
EOF
  return 0
}

# Lift one container entry out of a generated policy. The policy travels as a
# gzipped, base64'd initdata blob; policy_data is a JSON object embedded in the
# rego text, so it is decoded with a real JSON parser rather than brace matching —
# genpolicy emits regexes containing braces, which naive matching truncates.
extract_container_entry() {
  python3 - "$1" "${SIDECAR_MARK}" <<'PY'
import base64, gzip, json, re, sys

yaml_path, marker = sys.argv[1], sys.argv[2]
blob = re.search(r'cc_init_data:\s*"?([A-Za-z0-9+/=]+)"?', open(yaml_path).read())
if not blob:
    sys.exit("could not read the cc_init_data annotation")
policy = gzip.decompress(base64.b64decode(blob.group(1))).decode("utf-8", "replace")

i = policy.find("policy_data := {")
if i < 0:
    sys.exit("the generated policy has no policy_data block")
start = policy.index("{", i)
data, _ = json.JSONDecoder().raw_decode(policy, start)

hits = [c for c in data.get("containers", []) if marker in json.dumps(c)]
if len(hits) != 1:
    sys.exit(f"expected exactly one container matching {marker!r}, found {len(hits)}")
# Indented, not compact. The agent raises regorus' 1024-column source-line limit, so
# a single-line entry would parse, but a fragment is a human-reviewable artifact —
# it is signed, published and audited, and a several-kilobyte line is not reviewable.
print(json.dumps(hits[0], indent=2))
PY
}

log "generating the two-container reference policy to lift the sidecar entry from"
# The reference pod carries the same delivery annotation as the case that will run,
# because genpolicy stamps pod-level annotations onto *every* container entry and the
# runtime stamps them onto every container's OCI spec. An entry lifted from a pod
# without the annotation therefore never matches the real request: the input carries
# io.katacontainers.config.agent.policy_fragments and the entry does not, and
# allow_anno_key_value refuses it. A fragment author has to write the entry against
# the pod their container will actually run in.
render_sidecar_pod "${SIDECAR_POD}" two "${SIDECAR_REF}" > "${WORK}/sidecar-ref.yaml"
"${GENPOLICY}" -y "${WORK}/sidecar-ref.yaml" -p "${WORK}/rules-none.rego" -j "${SETTINGS}" \
  --initdata-path="${WORK}/initdata.toml" >/dev/null \
  || die "genpolicy failed for the two-container reference pod"
extract_container_entry "${WORK}/sidecar-ref.yaml" > "${WORK}/sidecar-entry.json" \
  || die "could not lift the sidecar entry out of the reference policy"
[[ -s "${WORK}/sidecar-entry.json" ]] || die "empty sidecar entry"
# How strongly the entry pins the image depends on the image path. Under host-pull
# with dm-verity it carries the layer root hash and the image is pinned by content.
# Under guest-pull — what this cluster runs — `storages` is empty and the entry
# pins the image reference plus argv, env, mounts and user, with image integrity
# enforced by the guest's own image-verification policy. Report which one is in
# force rather than asserting the stronger claim, so the case does not read as
# proving content pinning when it is not.
if grep -q 'root_hash\|dm-verity\|verity' "${WORK}/sidecar-entry.json"; then
  log "the sidecar entry carries a dm-verity root hash — the image is pinned by content"
else
  log "guest-pull: the sidecar entry pins the image reference and process shape,"
  log "and image integrity is enforced by the guest's image-verification policy"
fi
ok "lifted the sidecar container entry ($(wc -c < "${WORK}/sidecar-entry.json") bytes)"

# The package path is the fragment's own feed, quoted, because a feed is an OCI
# reference and not a Rego identifier. The agent accepts that form only when the
# quoted segment matches the feed its COSE envelope was signed for, so this key
# cannot be written by anyone but this feed's publisher.
{
  printf 'package agent_policy.fragments["%s"]\n\n' "${SIDECAR_FEED}"
  printf 'issuer := "%s"\n' "${ISSUER}"
  printf 'svn := %s\n' "${SVN}"
  printf 'containers := [%s]\n' "$(cat "${WORK}/sidecar-entry.json")"
} > "${WORK}/sidecar.rego"

log "signing and publishing the sidecar fragment to ${SIDECAR_REF}"
SIGN sign --issuer "${ISSUER}" --feed "${SIDECAR_FEED}" --svn "${SVN}" \
     --module "${WORK}/sidecar.rego" --key "${SIDECAR_PRIV}" > "${WORK}/sidecar.sign.txt" \
  || { tail -20 "${WORK}/sidecar.sign.txt"; die "signing the sidecar fragment failed"; }
grep '^cose_sign1_hex=' "${WORK}/sidecar.sign.txt" | cut -d= -f2 > "${WORK}/sidecar.cose.hex"
[[ -s "${WORK}/sidecar.cose.hex" ]] || die "the signer emitted no cose_sign1_hex for the sidecar fragment"
if [[ -n "${ACR_PASSWORD:-}" ]]; then
  export FRAGMENTGEN_USERNAME="${ACR_USERNAME}" FRAGMENTGEN_PASSWORD="${ACR_PASSWORD}"
fi
FRAGGEN --cose "${WORK}/sidecar.cose.hex" --push "${SIDECAR_REF}" "${SIDECAR_PLAIN_HTTP[@]}" \
  > "${WORK}/sidecar.push.txt" \
  || { tail -20 "${WORK}/sidecar.push.txt"; die "pushing the sidecar fragment failed"; }
unset FRAGMENTGEN_USERNAME FRAGMENTGEN_PASSWORD
ok "published the sidecar fragment -> ${SIDECAR_REF} (svn ${SVN})"

# required is deliberately absent (lazy, C-ACI behaviour). The gate under test is
# not the obligation gate — it is whether the sidecar has a matching container
# entry at all. Making the declaration required would block the sandbox for the
# wrong reason in 07l and prove nothing.
render_rules "${WORK}/rules-sidecar.rego" \
  "[{\"issuer\": \"${ISSUER}\", \"feed\": \"${SIDECAR_FEED}\", \"minimum_svn\": ${SVN}}]"

# $1 pod, $2 delivery annotation. The base policy is generated from the
# one-container pod; the sidecar is appended to the yaml afterwards, so it is
# present in the workload and absent from the measured policy.
apply_sidecar_case() {
  local yaml="${WORK}/$1.yaml"
  render_sidecar_pod "$1" one "${2:-}" > "${yaml}"
  "${GENPOLICY}" -y "${yaml}" -p "${WORK}/rules-sidecar.rego" -j "${SETTINGS}" \
    --initdata-path="${WORK}/initdata.toml" >/dev/null \
    || die "genpolicy failed for $1"
  grep -q 'cc_init_data' "${yaml}" || die "no cc_init_data annotation for $1"
  assert_request_defaults_survived "${yaml}" "$1"
  # Append after generation: this is the container the measured policy has never
  # seen. genpolicy would otherwise add an entry for it and the test would be
  # asserting nothing.
  cat >> "${yaml}" <<EOF
    - name: sidecar
      image: ${E2E_BUSYBOX_IMAGE}
      command: ["sh", "-c", "echo ${SIDECAR_MARK}; sleep 600"]
EOF
  kubectl delete pod "$1" -n "${NS}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl apply -f "${yaml}" >/dev/null || die "kubectl apply failed for $1"
}

log "07l — without the fragment, the extra container has no policy entry"
apply_sidecar_case "${SIDECAR_POD}" ""
# Pod *phase* is the wrong oracle here, and usefully so: a pod is Running once
# every container has been created and one of them is up, so the sandbox and the
# base-policy container come up exactly as they should while the sidecar is
# refused. The assertion has to be per-container.
sidecar_ready() {
  kubectl get pod "${SIDECAR_POD}" -n "${NS}" \
    -o jsonpath='{range .status.containerStatuses[?(@.name=="sidecar")]}{.ready}{end}' \
    2>/dev/null | grep -qx true
}
SIDECAR_DEADLINE=$(( $(date +%s) + ${E2E_FRAGMENT_NEG_WAIT:-180} ))
SIDECAR_LEAKED=0
log "watching ${SIDECAR_POD} for ${E2E_FRAGMENT_NEG_WAIT:-180}s — the sidecar must never become ready"
while [[ "$(date +%s)" -lt "${SIDECAR_DEADLINE}" ]]; do
  if sidecar_ready; then SIDECAR_LEAKED=1; break; fi
  sleep 5
done
if [[ "${SIDECAR_LEAKED}" = "1" ]]; then
  diagnose "${SIDECAR_POD}"
  cleanup_pod "${SIDECAR_POD}"
  die "the sidecar is running without the fragment — the base policy is matching it, so 07m would prove nothing"
fi
# Necessary but not sufficient: a sandbox that never started would also pass. The
# base-policy container must be up, so the only thing that failed is the one the
# measured policy has no entry for.
kubectl get pod "${SIDECAR_POD}" -n "${NS}" \
  -o jsonpath='{range .status.containerStatuses[?(@.name=="busybox")]}{.ready}{end}' 2>/dev/null \
  | grep -qx true \
  || { diagnose "${SIDECAR_POD}"; cleanup_pod "${SIDECAR_POD}"
       die "the base-policy container is not running either — the sandbox failed for some unrelated reason"; }
ok "busybox ran and the sidecar was refused — the base policy has no entry for it (expected)"
kubectl get events -n "${NS}" --field-selector "involvedObject.name=${SIDECAR_POD}" 2>/dev/null \
  | grep -i 'sidecar' | tail -3 | cut -c1-200 | sed 's/^/    /' || true
cleanup_pod "${SIDECAR_POD}"
# Deleting the pod is not enough: the next case reuses the name, and a sandbox
# still shutting down would make kubectl apply race the old one.
wait_for_soft 120 "${SIDECAR_POD} gone" \
  bash -c "! kubectl get pod ${SIDECAR_POD} -n ${NS} >/dev/null 2>&1" \
  || kubectl delete pod "${SIDECAR_POD}" -n "${NS}" --force --grace-period=0 >/dev/null 2>&1 || true

log "07m — delivering the fragment admits it"
apply_sidecar_case "${SIDECAR_POD}" "${SIDECAR_REF}"
if ! wait_for_soft 300 "${SIDECAR_POD} sidecar ready" bash -c "sidecar_ready() { kubectl get pod ${SIDECAR_POD} -n ${NS} -o jsonpath='{range .status.containerStatuses[?(@.name==\"sidecar\")]}{.ready}{end}' 2>/dev/null | grep -qx true; }; sidecar_ready"; then
  diagnose "${SIDECAR_POD}"
  cleanup_pod "${SIDECAR_POD}"
  warn "the fragment carries the sidecar's own policy entry, so check in order:"
  warn "  - was it applied?  no guest log to read: a strict guest discards its own log"
  warn "                     stream (FR-7 / F-79). Rebuild without strict-policy to watch it."
  warn "  - was the package refused? look for 'outside the permitted fragment namespaces'"
  warn "  - does the lifted entry still match? re-run with E2E_FORCE=1 after any rules.rego change"
  die "the sidecar did not run with its fragment delivered — the container contribution path is broken"
fi
ok "both containers running — the fragment authorized a container the measured policy never contained"
cleanup_pod "${SIDECAR_POD}"
wait_for_soft 120 "${SIDECAR_POD} gone" \
  bash -c "! kubectl get pod ${SIDECAR_POD} -n ${NS} >/dev/null 2>&1" \
  || kubectl delete pod "${SIDECAR_POD}" -n "${NS}" --force --grace-period=0 >/dev/null 2>&1 || true

# 07n (F-160) — the same sidecar fragment, but its module lies about its own SVN.
#
# The base policy resolves a fragment's containers through the module's *own*
# `issuer` and `svn` rules, so a module that inflates its SVN could clear a
# `minimum_svn` floor its signed envelope does not meet. The envelope here is
# signed at the honest SVN and the declaration asks for exactly that, so the SRM's
# own gates are all satisfied — nothing but the self-description check stands
# between this fragment and the engine. If that check regresses, the pod boots.
#
# 07m and 07n differ in one character of the module and nothing else: same issuer,
# same feed, same envelope SVN, same declaration, same container entry.
#
# The oracle is *not* 07l's per-container one. Boot delivery is mandatory: a
# fragment the guest refuses fails the whole sandbox, so the pod never reaches
# Running at all. That is the stronger outcome and it lets the case assert on the
# refusal reason, which is what makes it a test of this gate rather than of any
# refusal that happens to occur.
SIDECAR_LIE_SVN=$(( SVN + 7 ))
SIDECAR_LIAR_REF="${SIDECAR_FEED}:liar"
log "07n — a fragment whose module claims svn ${SIDECAR_LIE_SVN} while its envelope carries ${SVN}"
{
  printf 'package agent_policy.fragments["%s"]\n\n' "${SIDECAR_FEED}"
  printf 'issuer := "%s"\n' "${ISSUER}"
  printf 'svn := %s\n' "${SIDECAR_LIE_SVN}"
  printf 'containers := [%s]\n' "$(cat "${WORK}/sidecar-entry.json")"
} > "${WORK}/sidecar-liar.rego"

SIGN sign --issuer "${ISSUER}" --feed "${SIDECAR_FEED}" --svn "${SVN}" \
     --module "${WORK}/sidecar-liar.rego" --key "${SIDECAR_PRIV}" > "${WORK}/sidecar-liar.sign.txt" \
  || { tail -20 "${WORK}/sidecar-liar.sign.txt"; die "signing the lying sidecar fragment failed"; }
grep '^cose_sign1_hex=' "${WORK}/sidecar-liar.sign.txt" | cut -d= -f2 > "${WORK}/sidecar-liar.cose.hex"
[[ -s "${WORK}/sidecar-liar.cose.hex" ]] || die "the signer emitted no cose_sign1_hex for the lying fragment"
if [[ -n "${ACR_PASSWORD:-}" ]]; then
  export FRAGMENTGEN_USERNAME="${ACR_USERNAME}" FRAGMENTGEN_PASSWORD="${ACR_PASSWORD}"
fi
FRAGGEN --cose "${WORK}/sidecar-liar.cose.hex" --push "${SIDECAR_LIAR_REF}" "${SIDECAR_PLAIN_HTTP[@]}" \
  > "${WORK}/sidecar-liar.push.txt" \
  || { tail -20 "${WORK}/sidecar-liar.push.txt"; die "pushing the lying fragment failed"; }
unset FRAGMENTGEN_USERNAME FRAGMENTGEN_PASSWORD
ok "published the lying sidecar fragment -> ${SIDECAR_LIAR_REF} (envelope svn ${SVN}, module claims ${SIDECAR_LIE_SVN})"

apply_sidecar_case "${SIDECAR_POD}" "${SIDECAR_LIAR_REF}"
if ! expect_never_running "${SIDECAR_POD}" "${E2E_FRAGMENT_NEG_WAIT:-180}"; then
  diagnose "${SIDECAR_POD}"
  cleanup_pod "${SIDECAR_POD}"
  die "the pod booted from a fragment that misdescribed its own SVN — the F-160 binding has regressed"
fi
# Necessary but not sufficient: any broken sandbox never reaches Running either.
# The refusal has to name *this* gate, or the case is green for the wrong reason.
if ! kubectl describe pod "${SIDECAR_POD}" -n "${NS}" 2>/dev/null \
     | grep -q 'declares svn .* but the envelope it arrived in carries svn'; then
  diagnose "${SIDECAR_POD}"
  cleanup_pod "${SIDECAR_POD}"
  die "the sandbox failed, but not for the self-description mismatch — something else refused this fragment first, so the case proves nothing"
fi
ok "07n — the module was refused for describing itself as an SVN its envelope does not carry"
cleanup_pod "${SIDECAR_POD}"
wait_for_soft 120 "${SIDECAR_POD} gone" \
  bash -c "! kubectl get pod ${SIDECAR_POD} -n ${NS} >/dev/null 2>&1" \
  || kubectl delete pod "${SIDECAR_POD}" -n "${NS}" --force --grace-period=0 >/dev/null 2>&1 || true

fi   # sidecar fixtures available

ok "fragment delivery e2e passed"
mark_done 07-fragment-bootpull
