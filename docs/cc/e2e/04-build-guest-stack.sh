#!/usr/bin/env bash
# 04 — build the hardened guest stack (STRICT_POLICY agent + rootfs + coco extension)
#      and install it over the deployed cluster.
#
# This is where our changes actually enter the guest. Read the two traps below
# before editing anything here.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
skip_if_done 04-build-guest-stack

step "04 — build hardened guest stack"
load_toolchain
load_coco_env
cd "$E2E_REPO_DIR" || die "no repo at $E2E_REPO_DIR"

LB=tools/packaging/kata-deploy/local-build

# TRAP 1: the agent builds inside a container from a *git checkout*, so
# uncommitted working-tree changes are invisible to the build.
if ! git diff --quiet HEAD -- src/ tools/; then
  die "uncommitted changes in src/ or tools/ — commit them; the container build only sees committed state"
fi
ok "working tree clean at $(git rev-parse --short HEAD)"

# TRAP 2: kata-deploy-binaries.sh wraps each packaging step in
# [[ ! -f ${final_tarball_path} ]]. If a tarball already exists it recompiles the
# agent, throws the result away, and repackages the STALE tarball. USE_CACHE=no
# does not bypass this. Delete the tarballs first, every time.
log "removing stale tarballs and target dir"
rm -rf src/agent/target build/agent
rm -f build/kata-static-agent.tar.zst \
      build/kata-static-rootfs-image.tar.zst \
      build/kata-static-rootfs-image-coco-extension.tar.zst \
      "$LB/build/kata-static-agent.tar.zst"

# Group membership from stage 02 only takes effect on a new login session, so this
# script may still be outside the docker group. Fix ownership rather than granting
# world write, which would be a root-equivalent grant to every local account.
sudo chgrp docker /var/run/docker.sock 2>/dev/null || true
sudo chmod 660 /var/run/docker.sock 2>/dev/null || true
docker info >/dev/null 2>&1 \
  || die "cannot talk to docker as $USER — log out and back in so the 'docker' group applies"

# static-build/agent/Dockerfile does `COPY install_libseccomp.sh`, but that file
# is not in git at that path — the Makefile-only copy-scripts targets stage it in
# from ci/. We invoke kata-deploy-binaries.sh directly, so stage it by hand.
"$LB/kata-deploy-copy-libseccomp-installer.sh" agent || die "libseccomp stage (agent) failed"
"$LB/kata-deploy-copy-libseccomp-installer.sh" tools || die "libseccomp stage (tools) failed"

build_component() {
  log "building $1"
  USE_CACHE=no \
  AGENT_POLICY="$E2E_AGENT_POLICY" \
  STRICT_POLICY="$E2E_STRICT_POLICY" \
  INIT_DATA="$E2E_INIT_DATA" \
  DEBUG=1 \
    "$LB/kata-deploy-binaries.sh" --build="$1" || die "build $1 failed"
}

build_component agent

# Verify the produced binary rather than trusting the flags — silent staleness
# here would invalidate every strict-policy result downstream.
CHK=$(mktemp -d)
tar -xf build/kata-static-agent.tar.zst -C "$CHK" || die "cannot open agent tarball"
BIN="$CHK/usr/bin/kata-agent"
[ -f "$BIN" ] || die "no kata-agent in the tarball"

srm=$(strings -a "$BIN" | grep -c security_reference_monitor || true)
bypass=$(strings -a "$BIN" | grep -c AllowRequestsFailingPolicy || true)

log "binary check: srm=$srm bypass=$bypass"
[ "$srm"    -gt 100 ] || die "STRICT_POLICY did not take: only $srm SRM symbols (expected >100)"
[ "$bypass" -eq 0 ]   || die "policy-failure bypass symbol present ($bypass) — not a hardened build"
rm -rf "$CHK"

# The SetPolicy handler is *compiled out* under strict-policy, so there is no
# string to grep for -- its absence has to be proved against a non-strict control
# binary. src/agent/tests/test-setpolicy-absent.sh does exactly that (and fails if
# the probe itself stops working), so call it rather than reimplementing it.
log "running the differential SetPolicy-removal test"
src/agent/tests/test-setpolicy-absent.sh || die "SetPolicy removal test failed"
ok "hardened agent verified"

mkdir -p "$LB/build"
cp build/kata-static-agent.tar.zst "$LB/build/"

build_component rootfs-image
build_component rootfs-image-coco-extension

# Installing the tarballs is what actually puts our agent in the guest. Building
# them only primes the local cache: without this the cluster keeps booting the
# nightly image and every result downstream is a false green.
install_tarball() {
  local t="$1"
  [ -f "$t" ] || die "expected tarball missing: $t"
  log "installing $t into /"
  sudo tar --zstd -xf "$t" -C / || die "install of $t failed"
}

IMG=/opt/kata/share/kata-containers/kata-containers.img
before=$(sha256sum "$IMG" 2>/dev/null | cut -d' ' -f1 || echo none)

install_tarball build/kata-static-rootfs-image.tar.zst
install_tarball build/kata-static-rootfs-image-coco-extension.tar.zst

after=$(sha256sum "$IMG" | cut -d' ' -f1)
[ "$after" != "$before" ] || die "$IMG is byte-identical after install — the build did not replace the deployed image"
ok "guest image replaced (${before:0:12} -> ${after:0:12})"

# Record what stage 05 is entitled to assume it is testing.
echo "$after" > "$E2E_STATE_DIR/guest-image-sha256"
git rev-parse HEAD > "$E2E_STATE_DIR/guest-image-commit"

# The guest image is dm-verity protected; the runtime config must carry the root
# hashes produced by THIS build or the guest will not boot. The tarballs install
# the hash files alongside the images, and each file's contents are already the
# exact comma-separated parameter string the config expects.
BASE_HASH=/opt/kata/share/kata-containers/root_hash_base.txt
EXT_HASH=/opt/kata/share/kata-containers/root_hash_coco-extension.txt
[ -f "$BASE_HASH" ] || die "missing $BASE_HASH after install"
[ -f "$EXT_HASH" ]  || die "missing $EXT_HASH after install"

CFG_DIR=/opt/kata/share/defaults/kata-containers/runtime-rs
mapfile -t CFGS < <(find "$CFG_DIR" -name 'configuration-qemu-coco-dev-runtime-rs.toml')
[ "${#CFGS[@]}" -gt 0 ] || die "no coco-dev runtime-rs configuration found under $CFG_DIR"

for CFG in "${CFGS[@]}"; do
  log "re-pointing dm-verity parameters in $CFG"
  sudo cp "$CFG" "$CFG.bak.$(date +%s)"
  sudo sed -i \
    -e "s|^kernel_verity_params = .*|kernel_verity_params = \"$(tr -d '\n' < "$BASE_HASH")\"|" \
    -e "s|^verity_params = .*|verity_params = \"$(tr -d '\n' < "$EXT_HASH")\"|" \
    "$CFG"
  grep -q "^kernel_verity_params = \"root_hash=" "$CFG" \
    || die "kernel_verity_params not set in $CFG after patching"
done
ok "dm-verity re-pointed in ${#CFGS[@]} config(s)"

ok "guest stack built and installed"
mark_done 04-build-guest-stack
