#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# FR-15: model-check the SRM lifecycle specification with TLC.
#
# Requires a Java runtime and tla2tools.jar. In CI this can run in any JRE image:
#   docker run --rm -v "$PWD:/w" -w /w eclipse-temurin:21-jre ./run-tlc.sh
#
# tla2tools.jar is fetched next to this script if absent, and verified against
# TLA2TOOLS_SHA256 below. Pinning the version is not enough once this check
# gates the security model in CI: the tool that certifies the model becomes a
# supply-chain input to the assurance argument, so it is pinned by content.
#
# Deadlock checking is disabled on purpose: the model legitimately terminates
# (all operations reach a terminal state, or the monitor quarantines), so a
# "deadlock" is an expected end state, not a bug. The checked properties are the
# TypeOK, VersionCountsAllCommits, CommittedIsPlanBound, QuarantineHasCause,
# DivergenceImpliesQuarantine and InFlightIsAuthorized invariants, plus the
# QuarantineSticky, QuarantineAdmitsOnlyTeardown, QuarantineGatesExecute,
# SupersedingIsConfined and VersionMonotone properties; see README.md. Run
# ./mutation-test.py afterwards to confirm none of them is vacuous.
#
# TLC runs with -coverage and this script FAILS if any action never fired. An
# action with zero generated states is a guard that contradicts itself: it
# contributes no behaviour, so every property is checked over a smaller state
# space than the module claims. That is the vacuity class mutation-test.py
# defends against, seen from the transition side rather than the property side,
# and it is how an earlier revision of CommitFails was wrong. An action that
# fires but adds no *distinct* state is reported as a warning; see below.
set -euo pipefail
cd "$(dirname "$0")"

# v1.8.0 is upstream's only *prerelease*, and it targets master rather than a
# fixed commit: the release object is deleted and recreated as master advances,
# republishing tla2tools.jar under this same URL. The pin below was correct when
# it landed on 2026-08-21 and stopped matching on 2026-09-01, when the release
# was recreated (its created_at moved forward, which a stable release's cannot).
# Expect to refresh this hash again. The durable fix is to pin the latest stable
# release instead -- v1.7.4, untouched since 2024-08-08 -- once the model has
# been confirmed to check cleanly, with the coverage gates below intact, there.
TLA2TOOLS_VERSION=v1.8.0
TLA2TOOLS_SHA256=dbcc75552f21978a4846688b8e23be1a6b6c0b3fcee35d78fec2df167958ec94

JAR=${TLA2TOOLS_JAR:-tla2tools.jar}
if [[ ! -f "${JAR}" ]]; then
  echo "fetching tla2tools.jar ${TLA2TOOLS_VERSION}..."
  curl -fsSL -o "${JAR}" \
    "https://github.com/tlaplus/tlaplus/releases/download/${TLA2TOOLS_VERSION}/tla2tools.jar"
fi

# The jar is executable supply-chain input, so a missing checksum tool is a
# reason to stop, not a reason to continue: "could not verify" and "verified"
# must never take the same branch. macOS ships `shasum` rather than
# `sha256sum`, so try both before giving up.
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "${JAR}" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "${JAR}" | cut -d' ' -f1)
else
  echo "ERROR: neither sha256sum nor shasum is available, so ${JAR} cannot be" >&2
  echo "       verified against its pin. Refusing to run an unverified jar." >&2
  exit 1
fi

if [[ "${actual}" != "${TLA2TOOLS_SHA256}" ]]; then
  echo "ERROR: ${JAR} does not match the pinned sha256." >&2
  echo "       expected ${TLA2TOOLS_SHA256}" >&2
  echo "       actual   ${actual}" >&2
  echo "       Delete it to re-fetch, or update TLA2TOOLS_SHA256 if the" >&2
  echo "       pinned version was changed deliberately." >&2
  exit 1
fi

# Keep the raw output: the coverage check parses it, and a failing run must
# still show TLC's own diagnostics.
out=$(mktemp)
trap 'rm -f "${out}"' EXIT

status=0
java -cp "${JAR}" tlc2.TLC -deadlock -coverage 1 -config SRM.cfg SRM.tla \
  2>&1 | tee "${out}" || status=$?

if [[ ${status} -ne 0 ]]; then
  exit "${status}"
fi

# Action coverage lines look like:
#   <Prepare line 181, col 1 to line 181, col 17 of module SRM>: 431:6336
# where the pair is DISTINCT:GENERATED — how many of the states this action
# generated were new, and how many it generated in all. (The order is easy to
# invert; the labels above are TLC's own, and the checks below depend on them.)
# The two mean different things:
#
#   generated == 0  the action never fired at all. That is a guard which
#                   contradicts itself, and it is a hard failure: every
#                   property is then checked over a smaller state space than
#                   the module claims.
#   distinct  == 0  the action fired, but reached nothing another action does
#                   not already reach — it is transition-equivalent to some
#                   other action. Reported as a warning, not a failure: an
#                   action may legitimately mirror a distinct *code* path whose
#                   effect coincides (AbandonPrepared vs Abort), which is worth
#                   keeping for traceability even though it adds no obligation.
parse='/^<[A-Za-z_][A-Za-z0-9_]* line [0-9]+, col [0-9]+ .* of module SRM>: [0-9]+:[0-9]+$/'

# A coverage check that only inspects the rows it finds cannot tell "every
# action fired" from "no rows were parsed": if TLC's output format changes, or
# -coverage stops being passed, every filter below matches nothing and the gate
# reports success while checking precisely nothing. So derive the actions the
# module *claims* from `Next`, and require a row for each. This also catches an
# action that is defined and never disjoined into `Next`, which TLC itself will
# not report -- the coverage output simply would not mention it.
expected=$(sed -n '/^Next ==/,/^$/p' SRM.tla |
  sed -n 's/.*[:/][[:space:]]*\([A-Za-z_][A-Za-z0-9_]*\)[[:space:]]*(\{0,1\}.*/\1/p' | sort -u)

if [[ -z "${expected}" ]]; then
  echo "ERROR: could not parse any action names out of SRM.tla's \`Next\`." >&2
  echo "       The coverage gate cannot verify anything without them, so this" >&2
  echo "       is a failure rather than a skip. Has \`Next\` been reformatted?" >&2
  exit 1
fi

missing=()
while IFS= read -r action; do
  if ! grep -qE "^<${action} line [0-9]+, col [0-9]+ .* of module SRM>:" "${out}"; then
    missing+=("${action}")
  fi
done <<<"${expected}"

if [[ ${#missing[@]} -gt 0 ]]; then
  echo >&2
  echo "ERROR: TLC reported no coverage at all for these actions of \`Next\`:" >&2
  for action in "${missing[@]}"; do echo "  - ${action}" >&2; done
  echo >&2
  echo "Either TLC's coverage output changed shape (in which case this gate was" >&2
  echo "silently passing and must be repaired), or these actions are named in" >&2
  echo "\`Next\` but not defined as actions of this module." >&2
  exit 1
fi

dead=$(awk "${parse}"'{ name = substr($1, 2); split($NF, c, ":"); if (c[2] == 0) print name }' \
  "${out}" | sort -u)
redundant=$(awk "${parse}"'{ name = substr($1, 2); split($NF, c, ":"); if (c[1] == 0 && c[2] != 0) print name }' \
  "${out}" | sort -u)

if [[ -n "${redundant}" ]]; then
  echo >&2
  echo "WARNING: these actions generated no state another action does not" >&2
  echo "         already reach (transition-equivalent, no added obligation):" >&2
  while IFS= read -r action; do echo "  - ${action}" >&2; done <<<"${redundant}"
fi

if [[ -n "${dead}" ]]; then
  echo >&2
  echo "ERROR: the following actions never fired (zero states generated):" >&2
  while IFS= read -r action; do echo "  - ${action}" >&2; done <<<"${dead}"
  echo >&2
  echo "An action that cannot fire is a guard that contradicts itself. Either" >&2
  echo "the guard is wrong, or SRM.cfg is too small to reach it. Both make the" >&2
  echo "checked properties weaker than they appear." >&2
  exit 1
fi

echo
echo "coverage: all $(wc -l <<<"${expected}") actions of \`Next\` fired at least once"
