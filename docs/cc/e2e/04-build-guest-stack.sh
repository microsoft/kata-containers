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
# The unpacked rootfs tree has to go with them. It is a build cache that the
# rootfs build reuses wholesale when it is present, and reusing it keeps
# whatever kata-agent was installed the first time it was populated -- so a
# freshly built, correctly verified agent tarball can sit in build/ while the
# image ships an agent that is days old. That is not hypothetical: it is exactly
# how stage 07 came to test a guest-side fetch that this branch had already
# replaced, and it cost a full debugging cycle because every artefact check
# upstream of the image passed. Cheaper to rebuild the tree than to trust it.
#
# sudo, and anchored to $E2E_REPO_DIR rather than a relative path: the tree is
# populated by a build container running as root, so an unprivileged rm deletes
# only what it can and leaves a half-gutted rootfs behind -- which the next build
# then fails on. Delete it completely or not at all.
sudo rm -rf "$E2E_REPO_DIR/build/rootfs-image"
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

  # Components are produced into build/ but consumed out of $LB/build/ -- the
  # extension image reads its inputs from there and dies on a bare
  # `tar: Cannot open` if they are missing. Stage every component we build, so
  # that adding one later cannot reintroduce this.
  local t="build/kata-static-$comp.tar.zst"
  if [ -f "$t" ]; then
    mkdir -p "$LB/build"
    cp "$t" "$LB/build/" || die "could not stage $t for later components"
  fi
}

build_component agent

# Verify the produced binary rather than trusting the flags — silent staleness
# here would invalidate every strict-policy result downstream.
CHK=$(mktemp -d)
trap 'rm -rf "$CHK"' EXIT
tar -xf build/kata-static-agent.tar.zst -C "$CHK" || die "cannot open agent tarball"
BIN="$CHK/usr/bin/kata-agent"
[ -f "$BIN" ] || die "no kata-agent in the tarball"

srm=$(strings -a "$BIN" | grep -c security_reference_monitor || true)
bypass=$(strings -a "$BIN" | grep -c AllowRequestsFailingPolicy || true)

log "binary check: srm=$srm bypass=$bypass"
[ "$srm"    -gt 100 ] || die "STRICT_POLICY did not take: only $srm SRM symbols (expected >100)"
[ "$bypass" -eq 0 ]   || die "policy-failure bypass symbol present ($bypass) — not a hardened build"

# Fingerprint the verified binary so the image build can be held to it below.
# rootfs.sh strips the agent on the way in, so neither a hash of the file nor its
# mtime survives the trip (it arrives by tar, which preserves the *build* mtime,
# and is then rewritten by strip). The string literals in the loaded sections do
# survive stripping untouched, so hash those: identical here and in the rootfs
# means the same binary, and any real agent change moves it.
AGENT_FP=$(strings -d "$BIN" | sha256sum | cut -d' ' -f1)
rm -rf "$CHK"; trap - EXIT

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

build_component rootfs-image

# Every check above proves the agent *tarball* is right. None of them prove the
# image contains it, and that is the gap that let stage 07 spend a run testing an
# agent from a previous day: the rootfs build reused a cached tree and quietly
# kept the agent already in it. Assert the agent that actually landed in the
# rootfs is the one just verified, so a stale image fails here -- naming the
# cause -- instead of surfacing later as an unexplained guest failure.
ROOTFS_AGENT=$(find build/rootfs-image/builddir -path '*/usr/bin/kata-agent' -type f 2>/dev/null | head -1)
[ -n "$ROOTFS_AGENT" ] \
  || die "no kata-agent under build/rootfs-image/builddir — the rootfs build installed no agent"
got_fp=$(strings -d "$ROOTFS_AGENT" | sha256sum | cut -d' ' -f1)
if [ "$got_fp" != "$AGENT_FP" ]; then
  warn "rootfs agent: $ROOTFS_AGENT ($(date -r "$ROOTFS_AGENT" '+%F %T'))"
  warn "expected fingerprint ${AGENT_FP:0:16}, got ${got_fp:0:16}"
  die "the image would ship an agent that is not the one built in this run — stale rootfs cache"
fi
ok "rootfs carries the agent built in this run (${AGENT_FP:0:12})"
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
  local t="$1" why
  [ -f "$t" ] || die "expected tarball missing: $t"
  # Extracting into / trusts every path in the archive; tarball_confined (lib.sh)
  # is what makes that trust conditional. A packaging change that widened these
  # tarballs would otherwise silently overwrite arbitrary root-owned files —
  # including stage 03's genpolicy-settings patch, which would re-break every pod
  # at CreateContainerRequest.
  why=$(tarball_confined "$t") || die "refusing to extract into /: $why"
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
#
# kata-containers.img is a symlink (to kata-ubuntu-noble.image) both in the
# tarball and once installed. `tar -xO` on a symlink member emits no bytes, so
# hashing its output digests the empty string -- which never matches, and which
# a `[ -n "$want" ]` check cannot catch because sha256sum always produces a
# hash. Unpack to a scratch dir instead and hash through the link, exactly as
# the comparison against the installed copy does.
REF=$(mktemp -d)
trap 'rm -rf "$REF"' EXIT
tar --zstd -xf build/kata-static-rootfs-image.tar.zst -C "$REF" \
  || die "could not unpack the rootfs tarball for verification"
REF_IMG="$REF/opt/kata/share/kata-containers/kata-containers.img"
[ -s "$REF_IMG" ] || die "$IMG_IN_TARBALL is missing or empty in the rootfs tarball"
want=$(sha256sum "$REF_IMG" | cut -d' ' -f1)
[ -f "$IMG" ] || die "no $IMG after install"
[ -s "$IMG" ] || die "$IMG is empty after install"
after=$(sha256sum "$IMG" | cut -d' ' -f1)
[ "$after" = "$want" ] || die "installed $IMG is not the image just built (want ${want:0:12}, got ${after:0:12})"
rm -rf "$REF"; trap - EXIT
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

# ------------------------------------------------------------------ the shim
# Everything above rebuilds the *guest*. The runtime-rs shim is host-side and is
# not in any of those tarballs — it arrives from the CI-nightly kata-tools build
# in stage 03 and is otherwise never replaced. So a change under src/runtime-rs
# would silently not be under test: the guest would be new, the host old, and a
# stage that depends on both (07's fragment delivery) would fail as though the
# guest change were wrong.
SHIM_DST=/opt/kata/runtime-rs/bin/containerd-shim-kata-v2
if [ -e "$SHIM_DST" ]; then
  log "building runtime-rs shim"
  # Build through make, not cargo: crates/shim/src/config.rs is generated from a
  # template by the Makefile and is not in git, so a direct cargo build fails on
  # a missing module. The Makefile targets musl, which the pinned toolchain
  # needs installed separately from the host target.
  RUST_CHANNEL=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml | head -1)
  [ -n "$RUST_CHANNEL" ] || die "could not read the pinned toolchain from rust-toolchain.toml"
  if ! rustup target list --toolchain "$RUST_CHANNEL" --installed 2>/dev/null \
       | grep -qx x86_64-unknown-linux-musl; then
    log "adding the musl target to toolchain $RUST_CHANNEL"
    rustup target add --toolchain "$RUST_CHANNEL" x86_64-unknown-linux-musl \
      || die "could not add the musl target"
  fi
  need musl-gcc
  # Force crates/shim/src/config.rs to be regenerated. It is produced from
  # config.rs.in by a plain timestamp rule in the Makefile, so once it exists it
  # is never rebuilt -- and it is where @COMMIT@ is substituted. The shim
  # therefore keeps reporting whatever commit was current the first time it was
  # generated, however many times it is rebuilt afterwards.
  #
  # That makes the currency check below compare against a frozen constant: it
  # fails spuriously the moment any shim input changes, and would keep passing
  # for a genuinely stale binary if the file happened to be regenerated. Deleting
  # it costs one sed and one relink, and is what makes the assertion mean
  # anything at all.
  rm -f src/runtime-rs/crates/shim/src/config.rs
  ( cd src/runtime-rs && make ) || die "could not build the runtime-rs shim"

  SHIM_SRC="$E2E_REPO_DIR/target/x86_64-unknown-linux-musl/release/containerd-shim-kata-v2"
  [ -x "$SHIM_SRC" ] || die "runtime-rs build produced no shim at $SHIM_SRC"

  sudo cp "$SHIM_DST" "$SHIM_DST.bak.$(date +%s)"
  sudo install -m 0755 "$SHIM_SRC" "$SHIM_DST"
  # The shim reports the commit it was built from. Do not require that to equal
  # HEAD: cargo rightly does not relink for a commit that touched only docs, so
  # the binary would be stale-but-correct and the stage would fail for no reason.
  # What matters is that nothing the shim is built *from* has changed since.
  SHIM_INPUTS=(src/runtime-rs src/libs src/dragonball Cargo.toml Cargo.lock)
  got=$("$SHIM_DST" --version 2>&1 | sed -n 's/.*commit: *\([0-9a-f]\{7,\}\).*/\1/p')
  [ -n "$got" ] || die "installed shim does not report a commit — is it the runtime-rs shim?"
  git merge-base --is-ancestor "$got" HEAD 2>/dev/null \
    || die "installed shim reports commit $got, which is not in this branch's history"
  stale=$(git log --oneline "$got..HEAD" -- "${SHIM_INPUTS[@]}")
  [ -z "$stale" ] || {
    printf '%s\n' "$stale" | sed 's/^/    /'
    die "shim was built at ${got:0:12} but the above commits changed ${SHIM_INPUTS[*]} since — the build did not pick them up"
  }
  ok "runtime-rs shim installed and current (built at ${got:0:12})"
  # containerd caches nothing about the shim binary, but any shim already
  # running for a live sandbox is the old one; stage 07 creates fresh pods.
else
  warn "no runtime-rs shim at $SHIM_DST — host-side changes are NOT under test"
fi

# Stage 05 must check the same files this stage actually patched, rather than
# guessing a path that a layout change would invalidate.
printf '%s\n' "${CFGS[@]}" > "$E2E_STATE_DIR/guest-config-paths"
tr -d '\n' < "$BASE_HASH" > "$E2E_STATE_DIR/guest-verity-params"

ok "guest stack built and installed"
mark_done 04-build-guest-stack
