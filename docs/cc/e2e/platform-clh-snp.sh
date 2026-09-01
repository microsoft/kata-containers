#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# shellcheck source-path=SCRIPTDIR
# shellcheck disable=SC2154  # E2E_* are defined by lib.sh, which sources this file;
# it cannot be sourced back from here without a cycle.
# Platform module for E2E_PLATFORM=clh-snp — Cloud Hypervisor + MSHV + SEV-SNP on
# Azure Linux 3.
#
# Sourced by stages 02/03/04 when the platform is clh-snp. It exists as a separate
# file rather than as branches inside those stages because the two platforms share
# almost nothing below the Kubernetes layer: different package manager, different
# builder, different install prefix, and no kata-deploy at all. Keeping the new
# path out of the working QEMU path is also what stops this from regressing a
# suite that currently passes 8/8.
#
# The recipe follows tools/osbuilder/node-builder/azure-linux/README.md, with two
# deliberate departures, both of which are load-bearing:
#
#   1. The README's dev flow passes AGENT_POLICY_FILE=allow-all.rego. That would
#      make the guest agent accept every request unconditionally, which is exactly
#      what stages 05-08 exist to prove it does not. We keep the release default,
#      allow-set-policy.rego, so genpolicy-generated policy is what is enforced.
#   2. The README stops at `ctr`. This suite is Kubernetes-based, so we also
#      register a RuntimeClass and label the node.
#
# shellcheck shell=bash

# --------------------------------------------------------------------- packages
# Build dependencies from the node-builder README, with one deliberate omission:
# `rust` and `cargo`. The README lists them, but AzL3 packages a Rust that can be
# older than versions.yaml requires, and installing them is actively harmful here
# because load_toolchain() *appends* ~/.cargo/bin to PATH — so a distro
# /usr/bin/cargo would shadow the rustup toolchain and the build would fail deep
# inside a long compile with an error that names neither Rust nor its version.
# Stage 02 installs rustup for both platforms; that is the one we want.
CLH_HOST_PKGS=(
  git golang build-essential protobuf-compiler protobuf-devel
  expect openssl-devel clang-devel libseccomp-devel btrfs-progs-devel
  device-mapper-devel cmake fuse-devel kata-packages-uvm-build curl cpio
  jq unzip wget tar which python3-pip erofs-utils
)

need_azl3() {
  local v
  v=$(sed -n 's/^VERSION_ID="\?\([^"]*\)"\?/\1/p' /etc/os-release | head -1)
  [[ "${v}" = "3.0" ]] \
    || die "E2E_PLATFORM=clh-snp requires Azure Linux 3 (found VERSION_ID=${v:-unknown})"
}

# The whole point of this platform is that the guest is a real SNP CVM. If the
# host is not an MSHV Dom0 the stack will still build and will still deploy, and
# then every pod will fail to start for reasons that look like anything but "the
# node was never confidential". Fail here instead, where it is one line to read.
# AzL3 boots the plain kernel by default, not the MSHV Dom0 entry, so a freshly
# provisioned CC-SKU node has no /dev/mshv and nothing confidential is possible.
# /etc/grub.d/50_mariner_mshv_menuentry already emits a "Dom0" entry that
# chainloads HvLoader.efi with MSHV_ENABLE/MSHV_SEV_SNP; stock /etc/default/grub
# just never selects it (GRUB_TIMEOUT=0, no GRUB_DEFAULT).
#
# This does not reboot on its own: stage 02 is running *on* the node over ssh, so
# a reboot here would look like a stage failure. Configure, then say plainly what
# is needed.
enable_dom0() {
  if [[ -e /dev/mshv ]]; then
    ok "already running as MSHV Dom0 ($(uname -r))"
    return 0
  fi

  # The host kernel must have EROFS as well as MSHV: the erofs snapshotter mounts
  # layers on the *host* side.
  log "installing MSHV host kernel"
  sudo dnf -y install kernel-mshv kernel-mshv-devel \
    || die "could not install kernel-mshv.
If the EROFS-enabled build is still unpublished, install
kernel-mshv-6.6.137.mshv2-2.azl3 (+ -devel) by hand from the Azure Linux buddy
build artifact, then re-run this stage."

  log "selecting the Dom0 boot entry"
  sudo sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' /etc/default/grub
  if grep -q '^GRUB_DEFAULT=' /etc/default/grub; then
    sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT="Dom0"/' /etc/default/grub \
      || die "could not rewrite GRUB_DEFAULT"
  else
    echo 'GRUB_DEFAULT="Dom0"' | sudo tee -a /etc/default/grub >/dev/null \
      || die "could not append GRUB_DEFAULT"
  fi
  sudo grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 \
    || die "grub2-mkconfig failed"

  die "node configured to boot as MSHV Dom0, but it is still running the plain kernel.
Reboot it and re-run this stage:

    az vm restart -g \$E2E_RG -n \$E2E_VM      # or: sudo reboot

After the reboot, /dev/mshv must exist and 'modprobe erofs' must succeed.
Note /dev/sev does NOT appear on the host — MSHV owns the PSP, so /dev/mshv is
the indicator to check."
}

# Both modules have to be present *before* containerd starts, so this runs during
# bootstrap rather than at first use. containerd's erofs differ probes for
# dm-verity at plugin-load time, and if the probe fails it does not merely
# disable verity — it fails the differ, which cascades into the diff service,
# the CRI image service and finally the whole CRI plugin. The node then looks
# like containerd is up while kubelet cannot talk to it at all, and stage 03's
# 'kubeadm init' dies in preflight with an opaque "unknown service
# runtime.v1.RuntimeService".
load_storage_modules() {
  sudo modprobe erofs 2>/dev/null || true
  grep -qw erofs /proc/filesystems \
    || die "the running host kernel has no EROFS support — the erofs snapshotter cannot mount layers.
Install the EROFS-enabled kernel-mshv build and reboot."

  # When EROFS ships as a module rather than built in, make sure it is loaded on
  # every boot: containerd starts before anything would autoload it, and it then
  # falls back to overlayfs silently instead of failing loudly.
  if ! grep -qx erofs /etc/modules-load.d/erofs.conf 2>/dev/null; then
    echo erofs | sudo tee /etc/modules-load.d/erofs.conf >/dev/null
  fi

  sudo modprobe dm-verity 2>/dev/null || true
  # Probe the device-mapper target, not just the module list: with
  # CONFIG_DM_VERITY=y the target is available but nothing appears in
  # /proc/modules. (The EROFS check above is already builtin-safe because
  # /proc/filesystems lists built-in filesystems too.)
  if ! sudo dmsetup targets 2>/dev/null | grep -qw verity \
     && ! grep -qw dm_verity /proc/modules; then
    die "the running host kernel has no dm-verity support — containerd's erofs
differ cannot compute per-layer hash trees, so no layer will carry the
X-containerd.dmverity annotation and any policy asking for
image_layer_verification = host-erofs-dm-verity will refuse every container."
  fi
  # Only worth persisting when it is a loadable module; a built-in target needs
  # no modules-load.d entry.
  if grep -qw dm_verity /proc/modules \
     && ! grep -qx dm-verity /etc/modules-load.d/dm-verity.conf 2>/dev/null; then
    echo dm-verity | sudo tee /etc/modules-load.d/dm-verity.conf >/dev/null
  fi
}

assert_snp_host() {
  [[ -e /dev/mshv ]] \
    || die "no /dev/mshv — this node is not running as an MSHV Dom0. Re-run stage 02, then reboot."
  load_storage_modules
  ok "MSHV Dom0 with EROFS ($(uname -r))"
}

# ------------------------------------------------------------------- bootstrap
clh_bootstrap_node() {
  need_azl3

  log "installing host and build packages (dnf)"
  sudo dnf -y install "${CLH_HOST_PKGS[@]}" || die "dnf install of build packages failed"
  sudo dnf -y install kata-packages-host || die "dnf install kata-packages-host failed"

  # Belt and braces for the PATH-shadowing trap described above: if something
  # else on the node has pulled in a distro cargo, say so now rather than at
  # minute 40 of the guest build.
  if command -v cargo >/dev/null 2>&1 && [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    local resolved; resolved=$(command -v cargo)
    [[ "${resolved}" = "${HOME}/.cargo/bin/cargo" ]] \
      || warn "cargo resolves to ${resolved}, not the rustup toolchain — prepend \$HOME/.cargo/bin to PATH if the build fails on a version requirement"
  fi

  # Bring the node to Dom0 first. On the pre-reboot pass this deliberately dies
  # asking for a reboot, so the module checks and containerd land on the MSHV
  # kernel that will actually run the stack — not on the stock kernel, whose
  # EROFS support is not this suite's to guarantee.
  enable_dom0
  load_storage_modules
  install_containerd
  clh_configure_containerd
  ok "node bootstrapped for clh-snp"
}

# containerd 2.3.x is required for the EROFS flow: earlier releases have no EROFS
# differ, so the single-layer path silently falls back to the walking differ and
# nothing under test is exercised.
install_containerd() {
  local want="${E2E_CONTAINERD_VERSION:-2.3.3}" have=""
  have=$(containerd --version 2>/dev/null | awk '{print $3}' | sed 's/^v//')
  if [[ "${have}" = "${want}" ]]; then
    ok "containerd ${want} already installed"
    return 0
  fi
  log "installing containerd ${want} (found: ${have:-none})"
  local url="https://github.com/containerd/containerd/releases/download/v${want}/containerd-${want}-linux-amd64.tar.gz"
  curl -fsSLo /tmp/containerd.tgz "${url}" || die "containerd download failed"
  sudo systemctl stop containerd 2>/dev/null || true
  sudo tar -C /usr/local -xzf /tmp/containerd.tgz || die "containerd unpack failed"
  # The unit file ships in the source tree, not in the binary tarball.
  if [[ ! -f /etc/systemd/system/containerd.service ]]; then
    curl -fsSLo /tmp/containerd.service \
      https://raw.githubusercontent.com/containerd/containerd/main/containerd.service \
      || die "containerd unit download failed"
    sudo install -m 0644 /tmp/containerd.service /etc/systemd/system/containerd.service
  fi
  sudo systemctl daemon-reload
  sudo systemctl enable --now containerd || die "containerd failed to start"
  ok "containerd $(containerd --version | awk '{print $3}') installed"
}

# Register the kata and kata-cc handlers, and point the EROFS snapshotter at the
# differ. Written as a whole-file render rather than an append so that re-running
# the stage is idempotent — appending would stack duplicate TOML tables, and
# containerd fails to start on those.
clh_configure_containerd() {
  local cfg=/etc/containerd/config.toml
  log "writing ${cfg}"
  sudo mkdir -p /etc/containerd
  [[ -f "${cfg}" ]] && sudo cp -n "${cfg}" "${cfg}.pre-e2e"
  sudo tee "${cfg}" >/dev/null <<'EOF'
version = 3

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
    # kubelet defaults to the systemd cgroup driver. Leaving runc on cgroupfs
    # gives two writers for the same hierarchy, which shows up much later as
    # pods that start and then die under memory pressure.
    SystemdCgroup = true

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  snapshotter = "erofs"
  pod_annotations = ["io.katacontainers.*"]
  container_annotations = ["io.katacontainers.*"]

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata-cc]
  runtime_type = "io.containerd.kata-cc.v2"
  snapshotter = "erofs"
  # Without these passthrough lists containerd strips every io.katacontainers.*
  # annotation before it reaches the shim, so the genpolicy-generated policy
  # (delivered as cc_init_data) is silently dropped and the guest keeps running
  # the baked-in default policy.
  pod_annotations = ["io.katacontainers.*"]
  container_annotations = ["io.katacontainers.*"]
  [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata-cc.options]
    ConfigPath = "/opt/confidential-containers/share/defaults/kata-containers/runtime-rs/configuration.toml"

[plugins.'io.containerd.snapshotter.v1.erofs']
  # A non-zero default size would pad every layer to a fixed extent, which
  # defeats the single-layer EROFS path this stack exists to exercise.
  default_size = "0"

[plugins.'io.containerd.differ.v1.erofs']
  # The differ is what computes each layer's dm-verity hash tree and writes the
  # .dmverity metadata file next to layer.erofs. Without it the snapshotter
  # still produces perfectly good EROFS layers, but no mount ever carries the
  # X-containerd.dmverity annotation, so runtime-rs finds nothing to attach and
  # presents the layers with no verity options at all.
  #
  # That is invisible until the policy asks for verity. With
  # image_layer_verification = "host-erofs-dm-verity" genpolicy declares a
  # roothash per layer, the presented storages carry none, the pair fails to
  # match, and the request is refused. Leaving this false while the policy is
  # strict is the host half of a contract only one side was honouring.
  #
  # NOTE: the differ probes for the dm_verity kernel module at plugin-load time.
  # If it is missing, the probe does not merely disable verity -- it fails the
  # differ, the diff service, the CRI image service and finally the whole CRI
  # plugin, leaving a node where containerd is "active" but kubelet cannot talk
  # to it. load_storage_modules() loads and persists the module first.
  enable_dmverity = true
  # These three must match erofs_mkfs_options() in
  # tools/packaging/kata-deploy/binary/src/artifacts/snapshotters.rs, because
  # genpolicy reproduces containerd's mkfs.erofs invocation byte-for-byte to
  # predict each layer's root hash (see src/tools/genpolicy/src/erofs.rs).
  # -T0/--mkfs-time pin the build timestamp and --sort=none removes tar ordering
  # variance; without them the same layer content yields a different image, and
  # therefore a different root hash, on every unpack. The policy then declares a
  # hash the host will never present, and every container is refused.
  mkfs_options = ["-T0", "--mkfs-time", "--sort=none"]
  enable_tar_index = false

# NOTE: kata-deploy additionally sets use_local_image_pull = false and binds the
# transfer service's unpacker to the erofs differ (RM-50). On the containerd
# build used here that combination makes CRI pulls fail outright with "no unpack
# platforms defined", and it is not needed: diff-service `default` already puts
# the erofs differ first, so the local pull path produces dm-verity metadata too
# (verified by the .dmverity sidecar appearing after a local pull). Left out
# deliberately rather than forgotten.

[plugins.'io.containerd.service.v1.diff-service']
  default = ["erofs", "walking"]
EOF
  sudo systemctl restart containerd || die "containerd failed to restart with the new config"
  ok "containerd configured with kata / kata-cc handlers and the EROFS differ"
}

# ---------------------------------------------------------------- build inputs
# Cloud Hypervisor is pinned to an upstream commit rather than the Microsoft
# fork. Multi-layer EROFS attaches the layers as one multi-extent VMDK, and the
# fork's ImageType knows only FixedVhd/Qcow2/Raw/Vhdx -- it silently treats the
# VMDK descriptor (a ~1 KB text file) as a raw disk, so the guest sees a device
# with no GPT signature and no partition node ever appears. Upstream gained flat
# VMDK support at this commit; the compat patch restores MSHV/SNP behaviour that
# regressed after the fork point. See docs/design/erofs-cloud-hypervisor-investigation.md.
clh_build_cloud_hypervisor() {
  local dir="${E2E_CLH_DIR:-${HOME}/cloud-hypervisor-vmdk}"
  local patch="${E2E_REPO_DIR}/cloud-hypervisor-mshv-vmdk-compat.patch"
  CLH_SNP_BIN="${dir}/target/release/cloud-hypervisor"
  if [[ -x "${CLH_SNP_BIN}" ]] && [[ "${E2E_FORCE:-0}" != "1" ]]; then
    ok "cloud-hypervisor already built: ${CLH_SNP_BIN}"
    export CLH_SNP_BIN; return 0
  fi
  if [[ ! -d "${dir}/.git" ]]; then
    log "cloning ${E2E_CLH_REPO} at ${E2E_CLH_TAG}"
    git clone "${E2E_CLH_REPO}" "${dir}" || die "cloud-hypervisor clone failed"
  fi
  ( cd "${dir}" && git fetch --all --quiet && git checkout --quiet "${E2E_CLH_TAG}" ) \
    || die "cloud-hypervisor checkout of ${E2E_CLH_TAG} failed"
  # Re-appliable: reset first so E2E_FORCE=1 does not fail on an already-patched tree.
  [[ -f "${patch}" ]] || die "missing compat patch: ${patch}"
  ( cd "${dir}" && git checkout --quiet -- . && git apply "${patch}" ) \
    || die "cloud-hypervisor mshv/vmdk compat patch failed to apply"
  log "building cloud-hypervisor with the mshv,sev_snp features"
  # OPENSSL_NO_VENDOR=1 makes the build use the distro OpenSSL. Without it the
  # vendored build needs a perl/ssl toolchain AzL3 does not ship by default.
  ( cd "${dir}" && OPENSSL_NO_VENDOR=1 cargo build --release --no-default-features --features mshv,sev_snp ) \
    || die "cloud-hypervisor build failed"
  [[ -x "${CLH_SNP_BIN}" ]] || die "cloud-hypervisor built but ${CLH_SNP_BIN} is missing"
  export CLH_SNP_BIN
  ok "cloud-hypervisor: ${CLH_SNP_BIN}"
}

# The UVM kernel is pinned and rebuilt rather than taken from the distro: AzL's
# kernel-uvm 6.6.137.mshv1 triple-faults during IGVM boot, and the packaged
# 6.1.58 has no EROFS support, which the single-layer image flow requires.
clh_build_uvm_kernel() {
  local dir="${E2E_UVM_KERNEL_DIR:-${HOME}/kernel-uvm-6.1.58}"
  IGVM_KERNEL="${dir}/build/arch/x86/boot/bzImage"
  if [[ -f "${IGVM_KERNEL}" ]] && [[ "${E2E_FORCE:-0}" != "1" ]]; then
    ok "UVM kernel already built: ${IGVM_KERNEL}"
    export IGVM_KERNEL; return 0
  fi

  # Why build a kernel at all: AzL3's packaged kernel-uvm (6.6.137.mshv1)
  # triple-faults during IGVM boot, and the packaged 6.1.58 has EROFS off, which
  # the single-layer image flow requires. So the guest kernel is rebuilt from the
  # distro SRPM with exactly one config change.
  local ver="${E2E_UVM_KERNEL_VERSION}"           # e.g. 6.1.58.mshv8
  local srpm="kernel-uvm-${ver}-1.azl3.src.rpm"
  local url="https://packages.microsoft.com/azurelinux/3.0/prod/base/srpms/Packages/k/${srpm}"

  sudo dnf -y install bc bison flex dwarves ncurses-devel elfutils-libelf-devel \
    cpio rpm-build tar >/dev/null || die "UVM kernel build deps failed"

  mkdir -p "${dir}"/{srpm,source,build} || die "cannot create ${dir}"
  (
    set -e
    cd "${dir}"
    [[ -f "${srpm}" ]] || { log "downloading ${srpm}"; curl -fsSLO "${url}"; }
    rpm2cpio "${srpm}" | ( cd srpm && cpio -idm ) 2>/dev/null
    if [[ ! -f source/Makefile ]]; then
      tar --extract --file "srpm/kernel-uvm-${ver}.tar.gz" --directory source --strip-components=1
    fi
    cp srpm/config build/.config
    source/scripts/config --file build/.config --enable EROFS_FS
    make --directory source O="${PWD}/build" olddefconfig >/dev/null
    make --directory source O="${PWD}/build" --jobs "$(nproc)" bzImage
  ) || die "UVM kernel build failed (see above)"

  [[ -f "${IGVM_KERNEL}" ]] || die "UVM kernel built but ${IGVM_KERNEL} is missing"

  # EROFS has to actually be in the kernel that gets measured into the IGVM. A
  # kernel that merely built is not evidence of that: olddefconfig can silently
  # drop an option whose dependencies are unmet.
  grep -qE '^CONFIG_EROFS_FS=[ym]' "${dir}/build/.config" \
    || die "the UVM kernel was built without CONFIG_EROFS_FS — the single-layer image flow will not work"
  ok "UVM kernel has CONFIG_EROFS_FS"

  export IGVM_KERNEL
  ok "UVM kernel: ${IGVM_KERNEL}"
}

clh_install_igvm_tooling() {
  local sh="${E2E_REPO_DIR}/tools/osbuilder/igvm-builder/igvm_builder.sh"
  [[ -x "${sh}" ]] || die "missing ${sh}"
  log "installing IGVM build tooling"
  ( cd "$(dirname "${sh}")" && sudo ./igvm_builder.sh -i ) || die "igvm_builder.sh -i failed"

  # The installer skips the pip step whenever the extracted tooling folder is
  # already present, and on Azure Linux the plain `pip3 install` inside it is
  # refused because the site-packages tree is dnf-managed. Either way the igvm
  # module ends up missing, which only surfaces much later as a build failure.
  if ! python3 -c "import igvm" >/dev/null 2>&1; then
    local src
    src="$(dirname "${sh}")/igvm-tooling/src"
    [[ -d "${src}" ]] || die "igvm tooling sources missing at ${src}"
    log "installing the msigvm module explicitly"
    ( cd "${src}" && sudo pip3 install --no-deps --break-system-packages ./ ) \
      || die "pip3 install msigvm failed"
    python3 -c "import igvm" >/dev/null 2>&1 \
      || die "msigvm installed but 'import igvm' still fails"
  fi
  ok "IGVM tooling installed"
}

# ------------------------------------------------------- build + install kata
clh_build_and_deploy() {
  local nb="${E2E_REPO_DIR}/tools/osbuilder/node-builder/azure-linux"
  [[ -d "${nb}" ]] || die "missing ${nb} — is this branch the right one?"

  : "${CLH_SNP_BIN:?clh_build_cloud_hypervisor must run first}"
  : "${IGVM_KERNEL:?clh_build_uvm_kernel must run first}"

  # The Kata and Kata-CC flows share intermediate build state and will otherwise
  # install a mix of the two. The README is explicit that they must not be
  # interleaved without a clean.
  log "cleaning any previous confpods build"
  ( cd "${nb}" && make clean-confpods ) || warn "make clean-confpods returned non-zero (first run?)"

  # Note what is NOT passed: AGENT_POLICY_FILE. The release default is
  # allow-set-policy.rego, which permits SetPolicy and then enforces whatever
  # policy was set. The README's allow-all.rego is a dev convenience that would
  # make every gate in stages 05-08 pass vacuously.
  #
  # STRICT_POLICY/AGENT_POLICY match what the qemu stage 04 passes, so both
  # platforms exercise the same agent. STRICT_POLICY=yes also implies
  # USE_DEVMAPPER=yes, which the erofs dm-verity mount path requires.
  local mk=(make CLH_SNP_PATH="${CLH_SNP_BIN}" IGVM_KERNEL="${IGVM_KERNEL}"
            STRICT_POLICY="${E2E_STRICT_POLICY}" AGENT_POLICY="${E2E_AGENT_POLICY}")
  [[ "${E2E_BUILD_TARFS:-no}" = "yes" ]] && mk+=(BUILD_TARFS=yes)

  log "building kata-cc host and guest components (this takes a while)"
  ( cd "${nb}" && "${mk[@]}" all-confpods ) || die "make all-confpods failed"

  log "installing kata-cc components"
  ( cd "${nb}" && sudo "${mk[@]}" deploy-confpods ) || die "make deploy-confpods failed"

  # Verify the produced agent rather than trusting the flags. A node-builder
  # agent without the devicemapper feature stubs out dm-verity device creation,
  # and every CreateContainer then fails inside the guest with
  # "dm-verity support not compiled in" — which surfaces only as an opaque
  # sandbox timeout on the host.
  local abin="${nb}/agent-install/usr/bin/kata-agent"
  if [[ -f "${abin}" ]]; then
    local srm dmv
    srm=$(strings -a "${abin}" | grep -c security_reference_monitor || true)
    dmv=$(strings -a "${abin}" | grep -c 'dm-verity support not compiled in' || true)
    log "agent binary check: strict=${E2E_STRICT_POLICY} srm=${srm} devmapper_stub=${dmv}"
    [[ "${dmv}" -eq 0 ]] || die "agent built without --features devicemapper (USE_DEVMAPPER did not take)"
    # Assert in whichever direction was asked for, so a non-strict leg is
    # verified too rather than silently accepted (see 04-build-guest-stack.sh).
    if [[ "${E2E_STRICT_POLICY}" = "yes" ]]; then
      [[ "${srm}" -gt 100 ]] \
        || die "STRICT_POLICY did not take: only ${srm} SRM symbols (expected >100)"
    else
      [[ "${srm}" -le 100 ]] \
        || die "E2E_STRICT_POLICY=${E2E_STRICT_POLICY} but the agent carries ${srm} SRM symbols — the knob did not reach the build"
    fi
  else
    warn "no agent binary at ${abin} — skipping build verification"
  fi

  local cfg="${E2E_KATA_DEFAULTS}/runtime-rs/configuration.toml"
  [[ -f "${cfg}" ]] || die "expected shim config at ${cfg} after deploy-confpods"
  [[ -f "${E2E_GUEST_IMAGE}" ]] || die "expected guest IGVM at ${E2E_GUEST_IMAGE} after deploy-confpods"
  ok "kata-cc installed (shim config: ${cfg})"
}

# ------------------------------------------------------------------ kubernetes
# kata-deploy does not apply here — it installs a payload image built for the
# upstream layout, under /opt/kata, with handlers this node does not have. The
# node-builder has already installed everything, so all Kubernetes needs is a
# RuntimeClass pointing at the handler and a node that admits it.
register_runtimeclass() {
  local node
  node=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}') \
    || die "no Kubernetes node — bring the cluster up first"

  log "registering RuntimeClass ${E2E_RUNTIMECLASS}"
  kubectl apply -f - <<EOF || die "could not create RuntimeClass ${E2E_RUNTIMECLASS}"
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: ${E2E_RUNTIMECLASS}
handler: ${E2E_RUNTIMECLASS}
overhead:
  podFixed:
    memory: "600Mi"
scheduling:
  nodeSelector:
    katacontainers.io/kata-runtime: "true"
EOF

  kubectl label node "${node}" katacontainers.io/kata-runtime=true --overwrite \
    || die "could not label node ${node}"
  ok "RuntimeClass ${E2E_RUNTIMECLASS} registered; node ${node} labelled"
}

# ------------------------------------------------------------------ kubernetes
# gha-run.sh deploy-k8s and install-bats are apt-flavoured (they call apt-get and
# add-apt-repository), so on Azure Linux they fail before doing anything at all.
# Azure Linux ships kubeadm, kubelet and cri-tools in its own cloud-native repo,
# so the cluster is brought up natively here rather than borrowing upstream's
# Ubuntu path.
CLH_POD_CIDR="10.244.0.0/16"
CLH_FLANNEL_URL="https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml"

deploy_k8s() {
  if kubectl get nodes >/dev/null 2>&1; then
    ok "kubernetes already up"
    return 0
  fi

  log "installing kubeadm/kubelet/cri-tools from the Azure Linux cloud-native repo"
  sudo dnf -y install kubeadm kubelet kubectl cri-tools iproute-tc socat conntrack ethtool \
    || die "dnf install of the kubernetes packages failed"

  # Stage 02 drops a kubectl into /usr/local/bin, which precedes /usr/bin on
  # PATH. Leaving it there lets kubectl and the cluster drift apart
  # independently, so make the distro package the single source of truth.
  if [[ -f /usr/local/bin/kubectl ]] && [[ ! -L /usr/local/bin/kubectl ]]; then
    sudo ln -sf /usr/bin/kubectl /usr/local/bin/kubectl
  fi

  log "preparing the host for kubelet"
  sudo swapoff -a || true
  printf 'overlay\nbr_netfilter\n' | sudo tee /etc/modules-load.d/k8s.conf >/dev/null
  sudo modprobe overlay || true
  sudo modprobe br_netfilter || true
  sudo tee /etc/sysctl.d/99-k8s.conf >/dev/null <<'EOS'
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOS
  sudo sysctl --system >/dev/null 2>&1 || true
  sudo systemctl enable --now kubelet >/dev/null 2>&1 || true

  log "kubeadm init (a couple of minutes)"
  sudo kubeadm init \
    --pod-network-cidr="${CLH_POD_CIDR}" \
    --cri-socket=unix:///run/containerd/containerd.sock \
    --ignore-preflight-errors=Mem,NumCPU \
    || die "kubeadm init failed — see 'sudo journalctl -u kubelet'"

  mkdir -p "${HOME}/.kube"
  sudo install -o "$(id -u)" -g "$(id -g)" -m 0600 \
    /etc/kubernetes/admin.conf "${HOME}/.kube/config" \
    || die "could not install the kubeconfig"

  log "installing the flannel CNI"
  kubectl apply -f "${CLH_FLANNEL_URL}" || die "flannel apply failed"

  # Single node: nothing can ever schedule unless the control-plane taint goes.
  # A second run has nothing left to remove and kubectl exits non-zero on that.
  kubectl taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true

  wait_for 300 "node Ready" all_nodes_ready
  ok "kubernetes up"
}
