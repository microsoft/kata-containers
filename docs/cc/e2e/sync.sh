#!/usr/bin/env bash
# sync.sh — push this suite to the node and (optionally) run stages there.
#
# Run from the workstation. The scripts are copied rather than git-pulled on the
# node so an in-progress local edit can be tested without committing it — the
# suite itself is not what stage 04's clean-tree gate is about.
#
#   ./sync.sh                       # copy only
#   ./sync.sh 04 05                 # copy, then run those stages on the node
#   E2E_SSH_HOST=coco-dev-2 ./sync.sh 02
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"

need ssh
need scp

ssh "$E2E_SSH_HOST" 'mkdir -p ~/coco-e2e' || die "cannot reach $E2E_SSH_HOST over ssh"
scp -q "$HERE"/*.sh "$HERE"/README.md "$E2E_SSH_HOST:~/coco-e2e/" || die "scp failed"
# Windows checkouts carry no executable bit, and scp preserves that, so the
# scripts arrive non-executable and every invocation fails with Permission denied.
ssh "$E2E_SSH_HOST" 'chmod +x ~/coco-e2e/*.sh' || die "chmod failed"
ok "suite synced to $E2E_SSH_HOST:~/coco-e2e"

[ "$#" -gt 0 ] || exit 0

# Forward the knobs that change what the run means, so a remote run is not
# silently different from what was asked for locally.
env_prefix=""
for v in E2E_FAST E2E_SKIP_BUILD E2E_FORCE E2E_NIGHTLY_SHA E2E_BRANCH \
         E2E_STRICT_POLICY E2E_AGENT_POLICY E2E_REGISTRY E2E_NS; do
  if [ -n "${!v:-}" ]; then
    env_prefix+="$v=$(printf '%q' "${!v}") "
  fi
done

log "running on $E2E_SSH_HOST: $*"
# -t so ^C reaches the remote side rather than orphaning a multi-hour build.
ssh -t "$E2E_SSH_HOST" "cd ~/coco-e2e && ${env_prefix}./run-all.sh $*"
