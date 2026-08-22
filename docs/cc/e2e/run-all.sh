#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
# run-all.sh — orchestrate the end-to-end reproduction.
#
# Stages are resumable: each records a marker under ~/.coco-e2e and is skipped on
# re-run. Set E2E_FORCE=1 to re-run everything, or delete individual markers.
#
#   ./run-all.sh              # every stage
#   ./run-all.sh 04 05 06     # only these
#   E2E_FORCE=1 ./run-all.sh 06
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/lib.sh"

ALL=(00-adopt-node
     01-provision-vm 02-bootstrap-node 03-deploy-cluster
     04-build-guest-stack 05-smoke-test 06-policy-fragment-e2e
     07-fragment-bootpull 08-lifecycle-gates)

# 00 and 01-04 are alternatives, not a sequence: 00 adopts a prebuilt image and
# 01-04 build one. Running the wrong set is not a no-op — 04 on an AKS node would
# try to install a second guest stack over the one under test — so pick by
# platform rather than leaving it to the caller to remember.
#
# Narrow the list before arguments are matched against it, not after: an
# explicitly named stage has to be refused for the same reason a defaulted one
# does. `./run-all.sh 04` on AKS would otherwise overwrite the very image the
# run exists to validate.
if [[ "${E2E_PLATFORM}" = "aks" ]]; then
  ALL=(00-adopt-node 05-smoke-test 06-policy-fragment-e2e
       07-fragment-bootpull 08-lifecycle-gates)
else
  ALL=("${ALL[@]:1}")
fi

if [[ "$#" -gt 0 ]]; then
  SELECTED=()
  for want in "$@"; do
    found=""
    for s in "${ALL[@]}"; do
      case "${s}" in "${want}"|"${want}"-*) SELECTED+=("${s}"); found=1; break ;; esac
    done
    [[ -n "${found}" ]] || die "stage ${want} is not available on platform ${E2E_PLATFORM}
(have: ${ALL[*]})"
  done
else
  SELECTED=("${ALL[@]}")
fi

# 01 provisions the VM and must run from the workstation; the rest run on the node.
# On the node itself the Azure CLI is absent (stage 02 does not install it), so
# skip provisioning automatically rather than failing the whole run on `need az`.
if [[ "${E2E_SKIP_PROVISION:-auto}" = "1" ]] ||
   { [[ "${E2E_SKIP_PROVISION:-auto}" = "auto" ]] && ! command -v az >/dev/null 2>&1; }; then
  FILTERED=()
  for s in "${SELECTED[@]}"; do
    if [[ "${s}" = "01-provision-vm" ]]; then
      warn "skipping 01-provision-vm (no Azure CLI here; set E2E_SKIP_PROVISION=0 to force)"
    else
      FILTERED+=("${s}")
    fi
  done
  SELECTED=("${FILTERED[@]}")
fi
[[ "${#SELECTED[@]}" -gt 0 ]] || die "no stages left to run"

declare -A RESULT
start_all=$(date +%s)

for s in "${SELECTED[@]}"; do
  t0=$(date +%s)
  if bash "${HERE}/${s}.sh"; then
    RESULT[${s}]="PASS"
  else
    RESULT[${s}]="FAIL"
    printf '\n%s[FAIL]%s stage %s failed — stopping\n' "${_c_red}" "${_c_off}" "${s}" >&2
    # Later stages depend on earlier ones, so continuing would only produce noise.
    break
  fi
  log "${s} took $(( $(date +%s) - t0 ))s"
done

printf '\n%s================ summary ================%s\n' "${_c_blu}" "${_c_off}"
rc=0
for s in "${SELECTED[@]}"; do
  r="${RESULT[${s}]:-SKIPPED}"
  case "${r}" in
    PASS) printf '  %s%-24s PASS%s\n' "${_c_grn}" "${s}" "${_c_off}" ;;
    FAIL) printf '  %s%-24s FAIL%s\n' "${_c_red}" "${s}" "${_c_off}"; rc=1 ;;
    *)    printf '  %s%-24s %s%s\n'   "${_c_yel}" "${s}" "${r}" "${_c_off}"; rc=1 ;;
  esac
done
printf 'total: %ss\n' "$(( $(date +%s) - start_all ))"
exit "${rc}"
