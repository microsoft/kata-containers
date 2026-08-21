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

TLA2TOOLS_VERSION=v1.8.0
TLA2TOOLS_SHA256=eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a

JAR=${TLA2TOOLS_JAR:-tla2tools.jar}
if [[ ! -f "${JAR}" ]]; then
  echo "fetching tla2tools.jar ${TLA2TOOLS_VERSION}..."
  curl -fsSL -o "${JAR}" \
    "https://github.com/tlaplus/tlaplus/releases/download/${TLA2TOOLS_VERSION}/tla2tools.jar"
fi

if command -v sha256sum >/dev/null 2>&1; then
  if ! echo "${TLA2TOOLS_SHA256}  ${JAR}" | sha256sum -c - >/dev/null 2>&1; then
    echo "ERROR: ${JAR} does not match the pinned sha256." >&2
    echo "       Delete it to re-fetch, or update TLA2TOOLS_SHA256 if the" >&2
    echo "       pinned version was changed deliberately." >&2
    exit 1
  fi
else
  echo "WARNING: sha256sum not found; ${JAR} integrity NOT verified" >&2
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
# where the pair is DISTINCT:GENERATED — the states this action generated, and
# how many of those were new. The two mean different things:
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
echo "coverage: every action fired at least once"
