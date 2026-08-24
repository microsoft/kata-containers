#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2154  # E2E_* are defined by lib.sh, which sources this file;
# it cannot be sourced back from here without a cycle.
# platform-aks.sh — helpers for validating a *prebuilt* node image on AKS.
#
# The clh-snp platform builds the guest stack on the node (stage 04) and then
# asserts against what it built. On AKS the node image is handed to us already
# assembled — by a pipeline, from a branch we did not drive — so stages 01-04 do
# not apply and the question changes from "did my build work" to "is the image I
# was given the one I think it is, and are the hardened bits actually in it".
#
# That is a different claim and it needs a different gate. Everything here exists
# to answer it without weakening the suite's central rule: no stage may report
# PASS while silently exercising a stack other than the one under test.
#
# Node access is by privileged pod rather than SSH: an AKS node has no inbound
# SSH by default, and the one mechanism guaranteed to exist on every AKS cluster
# is the API server. The pod is pinned to a single node, runs in the host PID
# namespace and mounts / at /host, which is enough to read the installed payload
# and to `nsenter` into the host for anything that needs the host's own binaries.

# --------------------------------------------------------------- discovery
# Resolve the node, RuntimeClass and install prefix we are validating.
#
# Nothing here is hardcoded to an AKS SKU name. AKS has shipped kata under at
# least `kata-mshv-vm-isolation` and `kata-cc-isolation`, the label that marks a
# kata-capable node has changed with it, and a BYOI image can carry a handler
# that matches neither. Guessing wrong does not fail loudly — it schedules the
# pod onto a runtime that is not the one under test — so derive each value from
# the cluster and say out loud which one was picked.
aks_discover() {
  need kubectl

  if [[ -z "${E2E_NODE:-}" ]]; then
    local sel
    for sel in \
        'kubernetes.azure.com/kata-mshv-vm-isolation=true' \
        'katacontainers.io/kata-runtime=true' \
        ''; do
      E2E_NODE=$(kubectl get nodes ${sel:+-l "${sel}"} \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null) || E2E_NODE=""
      if [[ -n "${E2E_NODE}" ]]; then
        log "node ${E2E_NODE} selected${sel:+ by ${sel}}"
        break
      fi
    done
  fi
  [[ -n "${E2E_NODE}" ]] || die "no node found — is KUBECONFIG pointing at the right cluster?"
  export E2E_NODE

  # The image version is what a human will quote in a bug report, so surface it
  # even though nothing branches on it. It comes from the node's own labels
  # rather than from the az aks create command line, which is the only copy that
  # cannot be stale.
  local nodeimg
  nodeimg=$(kubectl get node "${E2E_NODE}" \
    -o jsonpath='{.metadata.labels.kubernetes\.azure\.com/node-image-version}' 2>/dev/null)
  [[ -n "${nodeimg}" ]] && ok "node image version: ${nodeimg}"
  AKS_NODE_IMAGE_VERSION="${nodeimg:-unknown}"
  export AKS_NODE_IMAGE_VERSION

  # A RuntimeClass carries scheduling.nodeSelector, which the API server copies
  # onto every pod that uses it. If the node under test does not satisfy that
  # selector the pod is rejected by kubelet with an opaque "Predicate
  # NodeAffinity failed" long before anything kata-related runs.
  if [[ -z "${E2E_RUNTIMECLASS_EXPLICIT:-}" ]]; then
    local rcs rc pick=""
    rcs=$(kubectl get runtimeclass -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
      2>/dev/null | grep -i kata || true)
    [[ -n "${rcs}" ]] || die "no kata RuntimeClass in this cluster — the node image is not wired up
(kubectl get runtimeclass showed none matching /kata/)"
    # Pick a class the node can actually honour rather than the first one by name.
    for rc in ${rcs}; do
      if aks_node_satisfies_runtimeclass "${rc}"; then pick="${rc}"; break; fi
      warn "RuntimeClass ${rc} requires labels ${E2E_NODE} does not have — skipping"
    done
    [[ -n "${pick}" ]] || die "no kata RuntimeClass is schedulable onto ${E2E_NODE}
(every kata RuntimeClass carries a scheduling.nodeSelector the node does not satisfy;
on AKS those are system-managed labels that cannot be added by hand, so either the
nodepool was not provisioned as a kata pool or the BYOI override suppressed the
labelling. Create a RuntimeClass with no nodeSelector over the same handler to
test anyway.)"
    E2E_RUNTIMECLASS="${pick}"
    export E2E_RUNTIMECLASS
  fi

  # Check the class whether it was discovered or supplied. An explicit choice is
  # not a safer one: because AKS workloads are additionally pinned with nodeName,
  # a selector the node cannot meet fails the pod outright, which is precisely
  # the opaque failure this discovery code exists to prevent.
  aks_node_satisfies_runtimeclass "${E2E_RUNTIMECLASS}" \
    || die "RuntimeClass ${E2E_RUNTIMECLASS} cannot schedule onto ${E2E_NODE}

  its nodeSelector  $(kubectl get runtimeclass "${E2E_RUNTIMECLASS}" -o jsonpath='{.scheduling.nodeSelector}' 2>/dev/null)

The API server copies that selector onto every pod using the class, and because
the node under test is pinned by name the pod cannot land anywhere else — kubelet
rejects it with 'Predicate NodeAffinity failed' before any kata code runs. On AKS
these labels are system-managed and cannot be added by hand; use a RuntimeClass
with no nodeSelector over the same handler instead."
  ok "RuntimeClass under test: ${E2E_RUNTIMECLASS}"
}

# True when every scheduling.nodeSelector entry on the RuntimeClass is present
# on the node under test with the same value.
aks_node_satisfies_runtimeclass() {
  local rc="$1" sel need k v
  sel=$(kubectl get runtimeclass "${rc}" -o jsonpath='{.scheduling.nodeSelector}' 2>/dev/null)
  [[ -n "${sel}" && "${sel}" != "null" ]] || return 0
  need=$(jq -r 'to_entries[] | "\(.key)=\(.value)"' <<<"${sel}" 2>/dev/null) || return 0
  while IFS='=' read -r k v; do
    [[ -n "${k}" ]] || continue
    [[ "$(kubectl get node "${E2E_NODE}" -o jsonpath="{.metadata.labels['${k//./\\.}']}" 2>/dev/null)" = "${v}" ]] \
      || return 1
  done <<<"${need}"
  return 0
}

# ------------------------------------------------------------- node access
: "${E2E_NODE_NS:=coco-e2e-inspect}"
: "${E2E_NODE_POD:=coco-e2e-inspector}"
# Azure Linux base/core carries coreutils, util-linux and grep, and lives on MCR
# so an AKS node can always pull it. Override for an air-gapped cluster.
: "${E2E_NODE_POD_IMAGE:=mcr.microsoft.com/azurelinux/base/core:3.0}"

# Bring up (or adopt) the inspector pod. Idempotent.
aks_node_pod_up() {
  if kubectl get pod "${E2E_NODE_POD}" -n "${E2E_NODE_NS}" \
       -o jsonpath='{.status.phase}' 2>/dev/null | grep -qx Running; then
    return 0
  fi

  ensure_ns "${E2E_NODE_NS}"

  # The pod deliberately does NOT set a runtimeClassName: it must run on the
  # host runtime. Scheduling the inspector into a kata sandbox would show it the
  # guest's filesystem rather than the node's, and every assertion below would
  # then be about the wrong machine.
  #
  # nodeName pins it directly instead of using a nodeSelector: with a selector a
  # multi-node pool can land the pod on a different node than the workload
  # stages use, and the digests would describe an image nobody tested.
  kubectl delete pod "${E2E_NODE_POD}" -n "${E2E_NODE_NS}" --ignore-not-found >/dev/null 2>&1
  kubectl apply -f - >/dev/null <<EOF || die "could not create the inspector pod"
apiVersion: v1
kind: Pod
metadata:
  name: ${E2E_NODE_POD}
  namespace: ${E2E_NODE_NS}
spec:
  nodeName: ${E2E_NODE}
  hostPID: true
  hostNetwork: true
  restartPolicy: Never
  tolerations:
    - operator: Exists
  containers:
    - name: inspect
      image: ${E2E_NODE_POD_IMAGE}
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
        type: Directory
EOF

  wait_for 180 "inspector pod Running on ${E2E_NODE}" \
    bash -c "kubectl get pod ${E2E_NODE_POD} -n ${E2E_NODE_NS} -o jsonpath='{.status.phase}' | grep -qx Running"

  # The Azure Linux base/core image ships neither nsenter nor mount/losetup, so
  # every host-side step below would fail with a bare "command not found" that
  # reads like a missing node feature rather than a missing inspector package.
  # Pull util-linux in once, here, where the failure is attributable.
  if ! aks_node_exec "command -v nsenter >/dev/null"; then
    log "installing util-linux into the inspector (nsenter/mount/losetup)"
    aks_node_exec "tdnf install -y util-linux >/dev/null 2>&1" || true
    aks_node_exec "command -v nsenter >/dev/null" \
      || die "could not install util-linux into the inspector pod
Without nsenter there is no way to reach the node's own mount namespace."
  fi
}

aks_node_pod_down() {
  kubectl delete ns "${E2E_NODE_NS}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

# Run a shell snippet inside the inspector pod. The node's filesystem is at
# /host. Returns the command's own exit status.
aks_node_exec() {
  kubectl exec -n "${E2E_NODE_NS}" "${E2E_NODE_POD}" -- sh -c "$*" 2>/dev/null
}

# Run a shell snippet in the *host's* namespaces, for things that need the node's
# own binaries or a mount that must be visible to the host kernel's view.
aks_host_exec() {
  kubectl exec -n "${E2E_NODE_NS}" "${E2E_NODE_POD}" -- \
    nsenter -t 1 -m -u -i -n -p -- sh -c "$*" 2>/dev/null
}

# ------------------------------------------------------------ install layout
# Locate the installed kata payload on the node and export the paths the rest of
# the suite reads. Sets E2E_KATA_PREFIX / E2E_KATA_DEFAULTS / E2E_GUEST_IMAGE /
# E2E_GUEST_IGVM to *node-side* paths (they are never opened locally on this
# platform; aks_* helpers resolve them through the inspector pod).
aks_locate_payload() {
  local p found=""
  for p in /opt/confidential-containers /opt/kata; do
    if aks_node_exec "test -d /host${p}/share/kata-containers"; then found="${p}"; break; fi
  done
  [[ -n "${found}" ]] || die "no kata payload under /opt/confidential-containers or /opt/kata on ${E2E_NODE}
The image does not carry a kata guest stack where either layout puts it."
  E2E_KATA_PREFIX="${found}"
  E2E_KATA_DEFAULTS="${E2E_KATA_PREFIX}/share/defaults/kata-containers"
  E2E_GUEST_IMAGE="${E2E_KATA_PREFIX}/share/kata-containers/${E2E_GUEST_IMAGE_NAME}"
  E2E_GUEST_IGVM="${E2E_KATA_PREFIX}/share/kata-containers/${E2E_GUEST_IGVM_NAME}"
  export E2E_KATA_PREFIX E2E_KATA_DEFAULTS E2E_GUEST_IMAGE E2E_GUEST_IGVM
  ok "kata payload at ${E2E_KATA_PREFIX}"

  aks_node_exec "test -f /host${E2E_GUEST_IMAGE}" \
    || die "missing ${E2E_GUEST_IMAGE} on ${E2E_NODE}"
  if ! aks_node_exec "test -f /host${E2E_GUEST_IGVM}"; then
    warn "no IGVM at ${E2E_GUEST_IGVM} — this node boots the guest without one"
    E2E_GUEST_IGVM=""
    export E2E_GUEST_IGVM
  fi
}

# sha256 of a node-side file, or empty.
aks_node_sha256() {
  aks_node_exec "sha256sum /host$1 2>/dev/null | cut -d' ' -f1" | tr -d '\r\n'
}

# ------------------------------------------------- what is actually in the image
# Count occurrences of a marker string in the guest's kata-agent binary.
#
# `strings` is not on an Azure Linux node and binutils is not worth installing
# into the inspector just for this, so approximate it the way strings(1) does:
# split on non-printables and count the lines that match. The counts are then
# directly comparable with the thresholds platform-clh-snp.sh uses on the build
# output, which is the point — the same predicate, applied to the shipped image
# instead of to a freshly built one.
#
# Echoes "<srm> <devmapper_stub>" on success; returns non-zero if the rootfs
# could not be mounted or the agent could not be found inside it.
aks_probe_guest_agent() {
  local mnt=/run/coco-e2e-guest
  local out abin

  # Every step here runs in the *host's* namespaces rather than the container's,
  # and that is deliberate on both counts:
  #
  #  - The guest image is a whole disk image, not a bare filesystem: on the
  #    clh-snp layout it carries an MS-DOS table with the ext4 rootfs on p1 and
  #    the dm-verity hash tree on p2, so `mount -o loop` on the raw file fails
  #    with "wrong fs type". It has to be attached with -P and mounted per
  #    partition.
  #  - The partition device nodes that -P creates exist in the host's devtmpfs.
  #    A privileged container gets its own /dev, so mounting from inside it
  #    fails with "Can't lookup blockdev" even though the loop attach succeeded.
  #    Reading the bytes host-side as well avoids depending on mount propagation
  #    to carry the result back under /host.
  aks_host_exec "mkdir -p ${mnt}; mountpoint -q ${mnt} && exit 0
    LO=\$(losetup -j '${E2E_GUEST_IMAGE}' | cut -d: -f1 | head -1)
    [ -n \"\$LO\" ] || LO=\$(losetup -fP --show '${E2E_GUEST_IMAGE}')
    [ -n \"\$LO\" ] || exit 1
    for d in \${LO}p1 \${LO}p2 \$LO; do
      [ -b \$d ] || continue
      mount -o ro \$d ${mnt} 2>/dev/null && exit 0
    done
    exit 1" >/dev/null

  aks_host_exec "mountpoint -q ${mnt}" || { aks_guest_umount "${mnt}"; return 1; }

  abin=$(aks_host_exec "for c in /usr/bin/kata-agent /bin/kata-agent /sbin/init /usr/lib/systemd/kata-agent; do
      [ -s ${mnt}\$c ] && { echo \$c; exit 0; }
    done
    f=\$(find ${mnt} -maxdepth 4 -name kata-agent -type f 2>/dev/null | head -1)
    [ -n \"\$f\" ] && echo \"\${f#${mnt}}\"" | tr -d '\r\n')

  [[ -n "${abin}" ]] || { aks_guest_umount "${mnt}"; return 1; }

  # >&2 deliberately: this function's stdout is the caller's result value.
  log "guest agent binary: ${abin} (inside ${E2E_GUEST_IMAGE_NAME})" >&2
  # `strings` is not on an Azure Linux node, so split on non-printables the way
  # strings(1) does. Materialise that view once and grep it twice rather than
  # reading the binary twice: it is faster, and it guarantees both counts
  # describe the same bytes.
  #
  # Match both spellings of the SRM marker. A shipped (stripped) release binary
  # keeps no symbol names, so `security_reference_monitor` never appears; what
  # survives are the panic-location strings, which carry the *directory* name
  # `src/agent/security-reference-monitor/...`. An unstripped build has the
  # underscored form too. Counting either way keeps this predicate honest
  # against both, instead of failing a correct image for being stripped.
  out=$(aks_host_exec "tr -c '[:print:]' '\n' < ${mnt}${abin} > /tmp/ag.txt
    printf '%s %s' \"\$(grep -c -e security_reference_monitor -e security-reference-monitor /tmp/ag.txt)\" \
                   \"\$(grep -c 'dm-verity support not compiled in' /tmp/ag.txt)\"
    rm -f /tmp/ag.txt" | tr -d '\r')

  aks_guest_umount "${mnt}"
  [[ -n "${out}" ]] || return 1
  echo "${out}"
}

# Undo whatever aks_probe_guest_agent attached. Detaching the loop device
# matters as much as the umount: a leaked -fP attachment makes the *next* run
# find a stale device via `losetup -j` and silently inspect the wrong bytes.
aks_guest_umount() {
  local mnt="$1"
  aks_host_exec "umount ${mnt} 2>/dev/null
    for L in \$(losetup -j '${E2E_GUEST_IMAGE}' | cut -d: -f1); do losetup -d \$L 2>/dev/null; done" >/dev/null
}

# Assert the shipped agent carries the strict-policy build.
#
# This is a hard gate, not a warning, whenever the probe can run at all: an
# image built without STRICT_POLICY still boots pods and still passes anything
# that only checks liveness, which is precisely the false green stage 05 exists
# to rule out. If the probe cannot run (unmountable payload), say so loudly and
# leave stage 05's behavioural gate as the remaining evidence.
aks_assert_strict_image() {
  local counts srm dmv
  if ! counts=$(aks_probe_guest_agent); then
    warn "could not inspect the guest rootfs at ${E2E_GUEST_IMAGE}"
    warn "the static strict-bits check is UNPROVEN — stage 05's exec denial is the only remaining evidence"
    return 0
  fi
  srm=${counts%% *}; dmv=${counts##* }
  log "shipped agent: srm=${srm} devmapper_stub=${dmv}"
  [[ "${dmv}" -eq 0 ]] \
    || die "the image's kata-agent was built without --features devicemapper
(it carries the 'dm-verity support not compiled in' stub, so every CreateContainer
will fail inside the guest and surface only as an opaque sandbox timeout)"
  [[ "${srm}" -gt 0 ]] \
    || die "the image's kata-agent does not carry the security reference monitor
(no SRM markers at all — STRICT_POLICY did not reach this build)"
  ok "shipped image carries the strict-policy agent (${srm} SRM markers)"
}

# ------------------------------------------------------------ adopt / re-assert
# Record what the node is running, so later stages can prove they still describe
# the same thing.
aks_record_baseline() {
  local img_sha igvm_sha
  img_sha=$(aks_node_sha256 "${E2E_GUEST_IMAGE}")
  [[ -n "${img_sha}" ]] || die "could not hash ${E2E_GUEST_IMAGE} on ${E2E_NODE}"
  printf '%s\n' "${img_sha}" > "${E2E_STATE_DIR}/guest-image-sha256"

  if [[ -n "${E2E_GUEST_IGVM}" ]]; then
    igvm_sha=$(aks_node_sha256 "${E2E_GUEST_IGVM}")
    [[ -n "${igvm_sha}" ]] || die "could not hash ${E2E_GUEST_IGVM} on ${E2E_NODE}"
    printf '%s\n' "${igvm_sha}" > "${E2E_STATE_DIR}/guest-igvm-sha256"
  else
    rm -f "${E2E_STATE_DIR}/guest-igvm-sha256"
  fi

  printf '%s\n' "AKS node image ${AKS_NODE_IMAGE_VERSION} on ${E2E_NODE}" \
    > "${E2E_STATE_DIR}/guest-image-commit"
  {
    printf 'E2E_NODE=%s\n'            "${E2E_NODE}"
    printf 'E2E_RUNTIMECLASS=%s\n'    "${E2E_RUNTIMECLASS}"
    printf 'E2E_KATA_PREFIX=%s\n'     "${E2E_KATA_PREFIX}"
    printf 'E2E_GUEST_IMAGE=%s\n'     "${E2E_GUEST_IMAGE}"
    printf 'E2E_GUEST_IGVM=%s\n'      "${E2E_GUEST_IGVM}"
    printf 'AKS_NODE_IMAGE_VERSION=%s\n' "${AKS_NODE_IMAGE_VERSION}"
  } > "${E2E_STATE_DIR}/adopted-node"
  ok "baseline recorded for ${E2E_NODE} (${AKS_NODE_IMAGE_VERSION})"
}

# The adopted-node counterpart of assert_local_guest_installed().
#
# The claim is weaker than the built-it-ourselves one and it is worth being
# explicit about how: we cannot say "this is the image stage 04 produced",
# only "this is still the image stage 00 inspected, on the node stage 00
# inspected, and that image was verified to carry the strict agent". Anything
# that swaps the node image, or reschedules onto a second node in the pool
# running a different one, changes a digest here and fails.
aks_assert_adopted_guest() {
  local rec="${E2E_STATE_DIR}/adopted-node"
  [[ -f "${rec}" ]] || die "this node has not been adopted — run 00-adopt-node.sh first"
  # shellcheck disable=SC1090
  . "${rec}"
  export E2E_NODE E2E_RUNTIMECLASS E2E_KATA_PREFIX E2E_GUEST_IMAGE E2E_GUEST_IGVM
  E2E_KATA_DEFAULTS="${E2E_KATA_PREFIX}/share/defaults/kata-containers"
  export E2E_KATA_DEFAULTS

  aks_node_pod_up

  local want got
  want=$(cat "${E2E_STATE_DIR}/guest-image-sha256" 2>/dev/null)
  got=$(aks_node_sha256 "${E2E_GUEST_IMAGE}")
  [[ -n "${got}" ]] || die "could not re-hash ${E2E_GUEST_IMAGE} on ${E2E_NODE}"
  [[ "${got}" = "${want}" ]] \
    || die "${E2E_GUEST_IMAGE} on ${E2E_NODE} changed since adoption — re-run 00-adopt-node.sh"

  if [[ -n "${E2E_GUEST_IGVM}" ]]; then
    want=$(cat "${E2E_STATE_DIR}/guest-igvm-sha256" 2>/dev/null)
    got=$(aks_node_sha256 "${E2E_GUEST_IGVM}")
    [[ "${got}" = "${want}" ]] \
      || die "${E2E_GUEST_IGVM} on ${E2E_NODE} changed since adoption — re-run 00-adopt-node.sh"
    ok "guest pinned by IGVM measurement to the adopted image"
  else
    warn "no IGVM on this node — the guest is not measured, only digest-tracked"
  fi

  # A pod may only ever land on the node we inspected. With more than one node
  # in the pool the scheduler is free to pick another, whose image we have made
  # no claim about at all.
  local n
  n=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
  if [[ "${n}" -gt 1 ]]; then
    warn "${n} nodes in this cluster — pods are pinned to ${E2E_NODE} so the assertions stay about the image we inspected"
  fi
  ok "testing guest from $(cat "${E2E_STATE_DIR}/guest-image-commit" 2>/dev/null || echo unknown)"
}

# containerd's effective config, read from the node. `config dump` is the
# authoritative view (it includes imported drop-ins and applied defaults); the
# on-disk file is only a fallback for when the host binary cannot be reached.
aks_containerd_config_dump() {
  local out
  out=$(aks_host_exec 'containerd config dump 2>/dev/null || crictl info 2>/dev/null')
  [[ -n "${out}" ]] || out=$(aks_node_exec 'cat /host/etc/containerd/config.toml 2>/dev/null')
  printf '%s' "${out}"
}

# The per-handler assertions below read TOML tables. `crictl info` is a fine
# fallback for a flat lookup like the sandbox image, but it carries no table
# headers, so every scoped lookup against it returns empty — which the callers
# would then report as "this handler declares no ConfigPath/snapshotter". Say
# what actually happened instead of inventing a finding about the node.
aks_require_toml_dump() {
  local dump="$1"
  grep -q 'runtimes\.[A-Za-z0-9_-]*\]' <<<"${dump}" \
    || die "could not read containerd's TOML configuration from ${E2E_NODE}

'containerd config dump' produced nothing and only 'crictl info' was available.
Its JSON does not expose the per-handler tables this stage has to inspect, so
neither the RuntimeClass's kata stack nor its layer transport can be established
— and an unverified answer here is the one this stage exists to prevent."
}

# One key out of a containerd runtime handler's block. Handler blocks are TOML
# tables, so scope the search to the block that names the handler and stop at
# the next table header — a bare grep would return whichever handler happens to
# appear first in the file. The handler's own sub-tables (.options) stay in
# scope, because ConfigPath lives there while snapshotter sits directly in the
# handler table.
#
# TOML only. aks_containerd_config_dump falls back to `crictl info`, whose JSON
# has no table headers to scope by; aks_require_toml_dump refuses that input
# rather than letting every lookup come back empty and be read as "unset".
aks_handler_key() {
  local handler="$1" dump="$2" key="$3"
  awk -v h="${handler}" -v k="${key}" '
    $0 ~ ("runtimes\\." h "\\]")            { inblk = 1; next }
    $0 ~ ("runtimes\\." h "\\.options\\]")  { inblk = 1; next }
    /^[[:space:]]*\[/ {
      # Any other table header ends the block, except the handler own sub-tables.
      if (inblk && $0 !~ ("runtimes\\." h "\\.")) inblk = 0
    }
    inblk && $0 ~ ("^[[:space:]]*\"?" k "\"?[[:space:]]*[=:]") {
      # containerd 1.x dumps TOML with double quotes, 2.x with single quotes.
      # Strip the key, then whichever quoting style this containerd chose.
      sub(/^[^=:]*[=:][[:space:]]*/, "")
      sub(/,[[:space:]]*$/, "")
      gsub(/^["\047]|["\047][[:space:]]*$/, "")
      print; exit
    }
  ' <<<"${dump}"
}

# The ConfigPath declared for a containerd runtime handler.
aks_handler_config_path() {
  aks_handler_key "$1" "$2" ConfigPath
}

# Every handler with its ConfigPath, for error messages that tell the reader
# which handler they should have used instead.
aks_handler_table() {
  local dump="$1" h
  while read -r h; do
    [[ -n "${h}" ]] || continue
    printf '    %-12s -> %s\n' "${h}" "$(aks_handler_config_path "${h}" "${dump}")"
  done < <(grep -o 'runtimes\.[A-Za-z0-9_-]*\]' <<<"${dump}" \
             | sed 's/^runtimes\.//; s/\]$//' | sort -u)
}

# ------------------------------------------------------- image layer transport
# One key out of a top-level containerd plugin table, e.g. the EROFS differ's
# enable_dmverity. Same scoping problem as aks_handler_key: the key names are
# generic enough that an unscoped grep would read a neighbouring plugin's value.
aks_plugin_key() {
  local plugin="$1" dump="$2" key="$3"
  awk -v p="${plugin}" -v k="${key}" '
    $0 ~ ("^[[:space:]]*\\[plugins\\.[\"\047]?" p "[\"\047]?\\]") { inblk = 1; next }
    /^[[:space:]]*\[/ { inblk = 0 }
    inblk && $0 ~ ("^[[:space:]]*\"?" k "\"?[[:space:]]*[=:]") {
      sub(/^[^=:]*[=:][[:space:]]*/, "")
      sub(/,[[:space:]]*$/, "")
      gsub(/^["\047]|["\047][[:space:]]*$/, "")
      print; exit
    }
  ' <<<"${dump}"
}

# genpolicy is told to model image layers as host EROFS with dm-verity (see
# ensure_genpolicy_defaults in lib.sh), which is only true if the node actually
# transports layers that way. If it does not — if the handler pulls inside the
# guest instead — the policy declares a roothash per layer, the guest presents
# storages that carry none, allow_storages fails the match and every container
# is refused. That reads as a verity or policy defect and is neither: the two
# halves of the contract are simply describing different worlds.
#
# The reverse skew is quieter still and is why this is an assertion rather than
# a note. The mkfs options below are reproduced byte-for-byte by genpolicy to
# predict each layer's root hash (src/tools/genpolicy/src/erofs.rs). Let the
# node build layers with different options and the content is identical while
# the hash is not, so the policy declares a digest the host will never present.
aks_assert_erofs_layers() {
  local handler="$1" dump="$2"
  local snap verity opts want="--mkfs-time -T0 --sort=none" missing=""

  snap=$(aks_handler_key "${handler}" "${dump}" snapshotter)
  [[ -n "${snap}" ]] || die "handler '${handler}' declares no snapshotter

Without one containerd uses its default (overlayfs), so image layers never
become EROFS block devices and the host-erofs-dm-verity policy this suite
generates cannot match anything the guest presents."

  [[ "${snap}" = "erofs" ]] || die "handler '${handler}' does not use the EROFS snapshotter

  snapshotter   ${snap}
  expected      erofs

This suite validates the host-EROFS + dm-verity layer path: layers are built on
the node, hashed there, and attached to the guest as verified block devices. A
'nydus' snapshotter means the image is pulled inside the guest instead, where
there is no host-side root hash for genpolicy to declare — a different design
with a different policy, not a variant of this one. Point the RuntimeClass at a
handler configured with snapshotter = \"erofs\"."
  ok "handler '${handler}' transports layers through the EROFS snapshotter"

  verity=$(aks_plugin_key 'io.containerd.differ.v1.erofs' "${dump}" enable_dmverity)
  [[ "${verity}" = "true" ]] || die "the EROFS differ on ${E2E_NODE} has dm-verity disabled

  enable_dmverity   ${verity:-<unset>}

The differ is what computes each layer's hash tree and writes the .dmverity
metadata beside layer.erofs. Without it the snapshotter still produces perfectly
good layers, but no mount carries the verity annotation, so runtime-rs attaches
them bare. The policy asks for a roothash, the storage has none, and every
container is refused with no mention of verity anywhere in the error."
  ok "the EROFS differ writes dm-verity metadata"

  opts=$(aks_plugin_key 'io.containerd.differ.v1.erofs' "${dump}" mkfs_options)
  for o in ${want}; do
    grep -q -- "${o}" <<<"${opts}" || missing="${missing} ${o}"
  done
  [[ -z "${missing}" ]] || die "the EROFS differ's mkfs_options cannot produce reproducible layers

  mkfs_options   ${opts:-<unset>}
  missing       ${missing}

genpolicy reproduces this exact mkfs.erofs invocation to predict each layer's
root hash. -T0 and --mkfs-time pin the build timestamp, --sort=none removes tar
ordering variance; without them the same layer content yields a different image,
and therefore a different digest, on every unpack. The policy would declare a
hash this node will never present and stage 05 would fail as though the image
were wrong."
  ok "mkfs_options pin the layer build (${opts})"
}
