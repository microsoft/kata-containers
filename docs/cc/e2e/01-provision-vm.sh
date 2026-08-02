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
          --query "[?name=='$E2E_VM_SIZE'] | [0]" -o json 2>/dev/null || true)
if [ -z "$avail" ] || [ "$avail" = "null" ]; then
  die "$E2E_VM_SIZE is not offered in $E2E_REGION at all. Try westus/westeurope; see README."
fi
reason=$(echo "$avail" | jq -r '[.restrictions[]?.reasonCode] | join(",")')
case "$reason" in
  "") ok "SKU available in $E2E_REGION" ;;
  *) die "$E2E_VM_SIZE restricted in $E2E_REGION ($reason). Try westus/westeurope; see README." ;;
esac

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
  az vm create \
    -g "$E2E_RG" -n "$E2E_VM" -l "$E2E_REGION" \
    --size "$E2E_VM_SIZE" \
    --image "$E2E_VM_IMAGE" \
    --admin-username "$E2E_ADMIN" \
    --ssh-key-values "$E2E_SSH_KEY" \
    --security-type ConfidentialVM \
    --os-disk-security-encryption-type VMGuestStateOnly \
    --enable-vtpm true --enable-secure-boot true \
    --os-disk-size-gb 256 \
    -o none || die "az vm create failed"
  ok "VM created"
fi

IP=$(az vm show -d -g "$E2E_RG" -n "$E2E_VM" --query publicIps -o tsv)
[ -n "$IP" ] || die "could not resolve public IP for $E2E_VM"
ok "VM $E2E_VM is up at $IP"

cat <<EOF

Add this to ~/.ssh/config so the rest of the scripts can reach it as 'coco-dev':

  Host coco-dev
      HostName $IP
      User $E2E_ADMIN
      StrictHostKeyChecking accept-new

Then copy this directory to the VM and continue there:

  cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ssh coco-dev 'mkdir -p ~/coco-e2e'
  scp -r ./ coco-dev:~/coco-e2e/
  ssh coco-dev 'bash ~/coco-e2e/02-bootstrap-node.sh'

Remember to deallocate when you are finished:

  az vm deallocate -g $E2E_RG -n $E2E_VM

EOF

echo "$IP" > "$E2E_STATE_DIR/vm-ip"
mark_done 01-provision-vm
