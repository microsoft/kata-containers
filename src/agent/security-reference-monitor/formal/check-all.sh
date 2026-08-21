#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# FR-15 aggregate check: the single command that decides whether the formal
# argument for the security reference monitor still holds.
#
# FR-15 does not claim "a TLA+ model exists". It claims that the model is
# checked, that the properties it checks are falsifiable, and that the model
# still describes the Rust code. Those are three separate obligations, and each
# is discharged by a different tool here. Running them one at a time by hand is
# how the first two came to be reported green while the third had never run at
# all, so they are bound together into one gate:
#
#   1. run-tlc.sh        the model satisfies its properties, and every action
#                        it declares can actually fire (coverage gate)
#   2. mutation-test.py  each property is falsifiable, is caught by the
#                        specific mutant that targets it, and no property in
#                        SRM.cfg lacks a mutant
#   3. cargo test        the Rust side still matches the model: model_drift
#                        cross-checks the quarantine causes, the call sites and
#                        the checked-property list against SRM.tla / SRM.cfg
#
# Steps 1 and 2 need a JRE; step 3 needs the agent's build dependencies. In CI
# they run in one container, but the split is honoured here so the script is
# still useful on a workstation that has only one of the two:
#
#   ./check-all.sh              everything
#   ./check-all.sh --model      steps 1 and 2 only (JRE, no Rust toolchain)
#   ./check-all.sh --drift      step 3 only (Rust toolchain, no JRE)
set -euo pipefail
cd "$(dirname "$0")"

run_model=yes
run_drift=yes
case "${1:---all}" in
  --all) ;;
  --model) run_drift=no ;;
  --drift) run_model=no ;;
  -h|--help) sed -n '7,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
esac

failed=()

step() {
  local name=$1; shift
  echo
  echo "=============================================================="
  echo "  ${name}"
  echo "=============================================================="
  if "$@"; then
    echo "-- ${name}: OK"
  else
    echo "-- ${name}: FAILED" >&2
    failed+=("${name}")
  fi
}

if [[ ${run_model} == yes ]]; then
  step "TLC model check (+ action coverage)" ./run-tlc.sh
  # mutation-test.py reuses the jar run-tlc.sh fetched and verified, so it must
  # run second; on its own it would only tell the user to run run-tlc.sh first.
  step "mutation test (property falsifiability)" ./mutation-test.py
fi

if [[ ${run_drift} == yes ]]; then
  # Run from the crate root so this works regardless of where the workspace
  # target directory is; -p keeps it to the monitor even though the agent
  # workspace is much larger.
  step "Rust model-drift lint" \
    cargo test --manifest-path ../Cargo.toml \
    -p kata-security-reference-monitor --test model_drift
fi

echo
if (( ${#failed[@]} )); then
  echo "FR-15 aggregate check FAILED (${#failed[@]}):" >&2
  printf '  - %s\n' "${failed[@]}" >&2
  exit 1
fi

echo "FR-15 aggregate check passed."
