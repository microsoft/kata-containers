#!/usr/bin/env bash
# 01 — provision an Azure confidential VM to run the end-to-end suite on.
#
# Idempotent: if the VM already exists it is started (not recreated) and the
# script succeeds.
#
# Env: E2E_RG E2E_VM E2E_REGION E2E_VM_SIZE E2E_VM_IMAGE E2E_ADMIN E2E_SSH_KEY
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 01-provision-vm

step "01 — provision Azure CVM"
need az
need jq

az account show >/dev/null 2>&1 || die "not logged in: run 'az login'"
SUB=$(az account show --query name -o tsv)
log "subscription: $SUB"

# Availability and quota are independent — each one alone is a false green, so
# check both before blaming the deployment.
log "checking SKU availability for $E2E_VM_SIZE in $E2E_REGION"
avail=$(az vm list-skus --all --size "$E2E_VM_SIZE" --location "$E2E_REGION" \
          --query "[?name=='$E2E_VM_SIZE'] | [0]" -o json) \
  || die "az vm list-skus failed — check 'az login' and the active subscription"
if [ -z "$avail" ] || [ "$avail" = "null" ]; then
  die "$E2E_VM_SIZE is not offered in $E2E_REGION at all. Try westus/westeurope; see README."
fi
# Restrictions come in two flavours and they are not equivalent. A `Location`
# restriction means the SKU cannot be deployed in the region at all. A `Zone`
# restriction only blocks *zonal* deployments — a regional (no --zone) VM is
# still allowed, which is exactly how coco-dev-1 was created in eastus while all
# three of its zones were restricted. Failing on both would refuse the one
# configuration known to work, so only Location is fatal. az vm create below
# deliberately passes no --zone.
loc_block=$(echo "$avail" | jq -r '[.restrictions[]? | select(.type=="Location") | .reasonCode] | join(",")')
zone_block=$(echo "$avail" | jq -r '[.restrictions[]? | select(.type=="Zone") | .reasonCode] | join(",")')
if [ -n "$loc_block" ]; then
  die "$E2E_VM_SIZE restricted in $E2E_REGION ($loc_block). Try westus/westeurope; see README."
fi
if [ -n "$zone_block" ]; then
  warn "$E2E_VM_SIZE is zone-restricted in $E2E_REGION ($zone_block) — deploying regionally (no zone)"
else
  ok "SKU available in $E2E_REGION"
fi

if ! az group show -n "$E2E_RG" >/dev/null 2>&1; then
  log "creating resource group $E2E_RG"
  az group create -n "$E2E_RG" -l "$E2E_REGION" -o none || die "resource group create failed"
fi

if az vm show -g "$E2E_RG" -n "$E2E_VM" >/dev/null 2>&1; then
  ok "VM $E2E_VM already exists — starting it if deallocated"
  az vm start -g "$E2E_RG" -n "$E2E_VM" -o none 2>/dev/null || true
else
  [ -f "$E2E_SSH_KEY" ] || die "no ssh public key at $E2E_SSH_KEY (set E2E_SSH_KEY)"
  log "creating $E2E_VM ($E2E_VM_SIZE) in $E2E_REGION — this takes a few minutes"
  # The security type is deliberately Standard by default. The qemu-coco-dev
  # runtime class this suite exercises is the *non-attested* dev path: the guest
  # is a normal VM, so what the node needs is a confidential-capable host SKU for
  # nested virtualisation (the _cc_ in DC16as_cc_v5), not a confidential VM of its
  # own. Asking for ConfidentialVM here also fails outright against the plain
  # ubuntu 'server' image, which is the image this suite is built around.
  SEC_ARGS=()
  if [ "$E2E_VM_SECURITY_TYPE" = "ConfidentialVM" ]; then
    SEC_ARGS=(--security-type ConfidentialVM
              --os-disk-security-encryption-type VMGuestStateOnly
              --enable-vtpm true --enable-secure-boot true)
  elif [ "$E2E_VM_SECURITY_TYPE" != "Standard" ]; then
    # Silently dropping an unrecognised value would hand back a VM whose posture
    # is not the one that was asked for, with nothing to say so.
    die "unsupported E2E_VM_SECURITY_TYPE=$E2E_VM_SECURITY_TYPE (expected Standard or ConfidentialVM)"
  fi
  az vm create \
    -g "$E2E_RG" -n "$E2E_VM" -l "$E2E_REGION" \
    --size "$E2E_VM_SIZE" \
    --image "$E2E_VM_IMAGE" \
    --admin-username "$E2E_ADMIN" \
    --ssh-key-values "$E2E_SSH_KEY" \
    "${SEC_ARGS[@]+"${SEC_ARGS[@]}"}" \
    --os-disk-size-gb 256 \
    -o none || die "az vm create failed"
  ok "VM created"
fi

IP=$(az vm show -d -g "$E2E_RG" -n "$E2E_VM" --query publicIps -o tsv)
[ -n "$IP" ] || die "could not resolve public IP for $E2E_VM"
ok "VM $E2E_VM is up at $IP"

# Writing the ssh alias here is what makes a second, parallel environment
# practical: E2E_VM=coco-dev-2 E2E_SSH_HOST=coco-dev-2 gets its own entry and the
# original stays untouched. Only ever adds a missing entry — an existing one may
# have been hand-tuned, and a redeployed VM changes IP, so say so rather than
# silently rewriting it.
SSH_CFG="$HOME/.ssh/config"
if grep -qE "^[[:space:]]*Host[[:space:]]+$E2E_SSH_HOST([[:space:]]|$)" "$SSH_CFG" 2>/dev/null; then
  cur=$(ssh -G "$E2E_SSH_HOST" 2>/dev/null | awk '/^hostname /{print $2}')
  if [ "$cur" = "$IP" ]; then
    ok "ssh alias '$E2E_SSH_HOST' already points at $IP"
  else
    warn "ssh alias '$E2E_SSH_HOST' points at $cur but the VM is at $IP — update $SSH_CFG by hand"
  fi
else
  log "adding ssh alias '$E2E_SSH_HOST' to $SSH_CFG"
  mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
  cat >> "$SSH_CFG" <<EOF

Host $E2E_SSH_HOST
    HostName $IP
    User $E2E_ADMIN
    StrictHostKeyChecking accept-new
EOF
  chmod 600 "$SSH_CFG"
fi

HERE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cat <<EOF

Copy this directory to the VM and continue there:

  $HERE_DIR/sync.sh
  ssh $E2E_SSH_HOST 'bash ~/coco-e2e/02-bootstrap-node.sh'

Remember to deallocate when you are finished:

  az vm deallocate -g $E2E_RG -n $E2E_VM

EOF

echo "$IP" > "$E2E_STATE_DIR/vm-ip"
mark_done 01-provision-vm
