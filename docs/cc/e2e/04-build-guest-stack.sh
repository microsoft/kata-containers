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
# A brand-new, never-committed source file is equally invisible to the container
# build, and `git diff` cannot see it — so check for it separately rather than
# relying on the diff alone.
#
# `helm dependency build` during stage 03 writes a Chart.lock and vendors its
# dependency charts into the kata-deploy chart, both untracked and both entirely
# normal. Excluding them keeps the gate about *source* the build would silently
# ignore, instead of failing every clean-room run on its own predecessor's
# byproducts.
untracked=$(git ls-files --others --exclude-standard -- src/ tools/ \
            ':!tools/packaging/kata-deploy/helm-chart/*/Chart.lock' \
            ':!tools/packaging/kata-deploy/helm-chart/*/charts/')
[ -z "$untracked" ] || die "untracked new files under src/ or tools/ — commit or remove them:
$untracked"
ok "working tree clean at $(git rev-parse --short HEAD)"

# TRAP 2: kata-deploy-binaries.sh wraps each packaging step in
# [[ ! -f ${final_tarball_path} ]]. If a tarball already exists it recompiles the
# agent, throws the result away, and repackages the STALE tarball. USE_CACHE=no
# does not bypass this. Delete the tarballs first, every time.
#
# The coco-extension image is keyed on the tools/ tree because that is where its
# only local input lives (the components.toml manifest emitted by
# kata-deploy-binaries.sh); its other inputs are prebuilt CoCo guest-component and
# pause artefacts. It contains no kata-agent, so an agent-only change cannot
# affect it. E2E_FAST reuses it when that key is unchanged.
EXT_TARBALL=build/kata-static-rootfs-image-coco-extension.tar.zst
EXT_KEY_FILE="$E2E_STATE_DIR/ext-build-key"
EXT_KEY=$(git rev-parse HEAD:tools)
REBUILD_EXT=1

if [ "$E2E_SKIP_BUILD" = "1" ]; then
  warn "E2E_SKIP_BUILD: installing the existing tarballs without rebuilding"
  for t in build/kata-static-rootfs-image.tar.zst "$EXT_TARBALL"; do
    [ -f "$t" ] || die "E2E_SKIP_BUILD set but $t does not exist — run without it once"
  done
else

if [ "$E2E_FAST" = "1" ] &&
   [ -f "$EXT_TARBALL" ] &&
   [ -f "/opt/kata/share/kata-containers/root_hash_coco-extension.txt" ] &&
   [ "$(cat "$EXT_KEY_FILE" 2>/dev/null || true)" = "$EXT_KEY" ]; then
  REBUILD_EXT=0
  warn "E2E_FAST: reusing the coco-extension image (tools/ tree unchanged at ${EXT_KEY:0:12})"
fi

log "removing stale tarballs"
rm -rf build/agent
rm -f build/kata-static-agent.tar.zst \
      build/kata-static-rootfs-image.tar.zst \
      "$LB/build/kata-static-agent.tar.zst"
[ "$REBUILD_EXT" = "1" ] && rm -f "$EXT_TARBALL"

# The stale-tarball trap is about tarballs, not about the cargo target dir, so the
# incremental cache can be kept for iteration. Cargo re-resolves feature flags on
# its own; the hardening assertions below still run either way.
if [ "$E2E_FAST" = "1" ]; then
  warn "E2E_FAST: keeping src/agent/target (incremental agent build)"
else
  rm -rf src/agent/target
fi

# `docker.io` already ships the socket as root:docker 0660, so the only thing the
# old `chmod a+rw` achieved was granting THIS login session access — `usermod -aG`
# does not apply until the next login. Re-exec under the docker group instead of
# widening the socket to every local account.
if ! docker info >/dev/null 2>&1; then
  if id -nG "$USER" | tr ' ' '\n' | grep -qx docker && [ -z "${E2E_SG_REEXEC:-}" ]; then
    log "not yet in an active 'docker' group session — re-executing under sg docker"
    export E2E_SG_REEXEC=1
    exec sg docker -c "$(printf '%q ' bash "$0" "$@")"
  fi
  die "cannot talk to docker as $USER — run 02-bootstrap-node.sh, then log out and back in"
fi

# static-build/agent/Dockerfile does `COPY install_libseccomp.sh`, but that file
# is not in git at that path — the Makefile-only copy-scripts targets stage it in
# from ci/. We invoke kata-deploy-binaries.sh directly, so stage it by hand.
"$LB/kata-deploy-copy-libseccomp-installer.sh" agent || die "libseccomp stage (agent) failed"
"$LB/kata-deploy-copy-libseccomp-installer.sh" tools || die "libseccomp stage (tools) failed"

# USE_CACHE=no is about the agent: with the cache on, the build downloads a
# published tarball, rebuilds the agent, throws the result away and repackages
# the STALE one. For components we do not modify that trap does not apply, and
# pulling the published artefact instead of building it from source saves the
# best part of an hour -- so those pass cache=yes.
build_component() {
  local comp="$1" cache="${2:-no}"
  log "building $comp (cache=$cache)"
  USE_CACHE="$cache" \
  AGENT_POLICY="$E2E_AGENT_POLICY" \
  STRICT_POLICY="$E2E_STRICT_POLICY" \
  INIT_DATA="$E2E_INIT_DATA" \
  DEBUG=1 \
    "$LB/kata-deploy-binaries.sh" --build="$comp" || die "build $comp failed"
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
#
# It costs two more debug builds of kata-agent, which dominates an iteration, so
# E2E_FAST drops it. That weakens the run: the strings check above is an
# artefact-level assertion, this is the only proof that the handler is gone.
if [ "$E2E_FAST" = "1" ]; then
  warn "E2E_FAST: SKIPPING the differential SetPolicy-removal test — re-run without E2E_FAST before trusting a result"
else
  log "running the differential SetPolicy-removal test"
  src/agent/tests/test-setpolicy-absent.sh || die "SetPolicy removal test failed"
fi
ok "hardened agent verified"

mkdir -p "$LB/build"
cp build/kata-static-agent.tar.zst "$LB/build/"

build_component rootfs-image
if [ "$REBUILD_EXT" = "1" ]; then
  # The extension image is assembled from prebuilt inputs rather than compiled:
  # install_image_coco_extension unpacks the CoCo guest components and the pause
  # bundle into a rootfs. Both must already exist as tarballs or it dies on a
  # bare `tar: Cannot open`. Nothing builds them implicitly, so build them here.
  # They contain no kata-agent, so our change cannot affect them -- take the
  # published artefact.
  build_component coco-guest-components yes
  build_component pause-image yes
  build_component rootfs-image-coco-extension
  echo "$EXT_KEY" > "$EXT_KEY_FILE"
fi

fi  # end of the build block skipped by E2E_SKIP_BUILD

# Installing the tarballs is what actually puts our agent in the guest. Building
# them only primes the local cache: without this the cluster keeps booting the
# nightly image and every result downstream is a false green.
install_tarball() {
  local t="$1"
  [ -f "$t" ] || die "expected tarball missing: $t"
  # Extracting into / trusts every path in the archive. Today these tarballs only
  # contain ./opt/kata/..., but a packaging change that widened them would silently
  # overwrite arbitrary root-owned files — including stage 03's genpolicy-settings
  # patch, which would re-break every pod at CreateContainerRequest.
  if tar --zstd -tf "$t" | grep -qv '^\./opt/kata/'; then
    die "$t contains paths outside ./opt/kata/ — refusing to extract into /"
  fi
  log "installing $t into /"
  sudo tar --zstd -xf "$t" -C / || die "install of $t failed"
}

IMG=/opt/kata/share/kata-containers/kata-containers.img
IMG_IN_TARBALL=./opt/kata/share/kata-containers/kata-containers.img

install_tarball build/kata-static-rootfs-image.tar.zst
install_tarball build/kata-static-rootfs-image-coco-extension.tar.zst

# Assert the deployed image IS the one we just built, not merely that it changed.
# "It changed" would fail a byte-identical rebuild at the same commit (a correct
# outcome reported as a failure) and would accept a change made by anything else.
want=$(tar --zstd -xOf build/kata-static-rootfs-image.tar.zst "$IMG_IN_TARBALL" \
        | sha256sum | cut -d' ' -f1)
[ -n "$want" ] || die "could not read $IMG_IN_TARBALL out of the rootfs tarball"
[ -f "$IMG" ] || die "no $IMG after install"
after=$(sha256sum "$IMG" | cut -d' ' -f1)
[ -n "$after" ] || die "could not hash $IMG after install"
[ "$after" = "$want" ] || die "installed $IMG is not the image just built (want ${want:0:12}, got ${after:0:12})"
ok "deployed guest image matches this build (${after:0:12})"

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
  grep -q "^verity_params = \"root_hash=" "$CFG" \
    || die "verity_params (coco-extension) not set in $CFG after patching"
done
ok "dm-verity re-pointed in ${#CFGS[@]} config(s)"

# Stage 05 must check the same files this stage actually patched, rather than
# guessing a path that a layout change would invalidate.
printf '%s\n' "${CFGS[@]}" > "$E2E_STATE_DIR/guest-config-paths"
tr -d '\n' < "$BASE_HASH" > "$E2E_STATE_DIR/guest-verity-params"

ok "guest stack built and installed"
mark_done 04-build-guest-stack
