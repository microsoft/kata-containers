#!/usr/bin/env bash
# Unit test for tarball_confined() in lib.sh — the predicate that decides whether
# 04-build-guest-stack.sh may extract a tarball as root into /. It is the only
# thing standing between a widened or hostile archive and arbitrary root-owned
# files on the node, so it is worth a test that does not need a VM.
#
# Every case builds a real tarball and runs the real predicate: no transcription
# of the guard lives here.
#
#   bash docs/cc/e2e/test-path-guard.sh
set -uo pipefail
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

need tar
need zstd

SRC=$(mktemp -d); OUT=$(mktemp -d)
trap 'rm -rf "$SRC" "$OUT"' EXIT
mkdir -p "$SRC/opt/kata/share"
echo payload > "$SRC/opt/kata/share/file"

mk() { (cd "$SRC" && tar --zstd -cf "$OUT/$1" "${@:2}"); }

# 1 payload only
mk ok.tar.zst ./opt/kata/share/file
# 2 ancestor dir entries — the shape the real extension tarball has
mk ancestors.tar.zst --no-recursion ./ ./opt ./opt/kata ./opt/kata/share/file
# 3 benign internal symlink — the shape the real rootfs tarball has
#   (kata-containers.img -> kata-ubuntu-noble.image). Rejecting symlinks by
#   member type rather than by target would break the install on this case.
ln -sf file "$SRC/opt/kata/share/link"
mk benign-link.tar.zst --no-recursion ./opt/kata/share/file ./opt/kata/share/link
# 4 symlink whose target escapes the payload
ln -sfn /etc "$SRC/opt/kata/share/esc"
mk escaping-link.tar.zst --no-recursion ./opt/kata/share/file ./opt/kata/share/esc
# 5 plain member outside the payload
mkdir -p "$SRC/etc"; echo x > "$SRC/etc/shadow"
mk stray.tar.zst --no-recursion ./opt/kata/share/file ./etc/shadow
# 6 corrupt archive — this is the case an earlier `|| true` on the listing
#   pipeline swallowed: tar failed, the empty stream read as a clean archive,
#   and the guard passed by failing.
head -c 64 /dev/urandom > "$OUT/corrupt.tar.zst"

fail=0
check() { # $1 = tarball, $2 = ACCEPT|REJECT
  local why verdict
  if why=$(tarball_confined "$OUT/$1"); then verdict=ACCEPT; else verdict=REJECT; fi
  if [ "$verdict" = "$2" ]; then
    printf 'PASS  %-22s %s\n' "$1" "$verdict"
  else
    printf 'FAIL  %-22s expected %s got %s %s\n' "$1" "$2" "$verdict" "$why"
    fail=1
  fi
}

check ok.tar.zst            ACCEPT
check ancestors.tar.zst     ACCEPT
check benign-link.tar.zst   ACCEPT
check escaping-link.tar.zst REJECT
check stray.tar.zst         REJECT
check corrupt.tar.zst       REJECT

[ "$fail" -eq 0 ] && ok "path guard: 6/6" || die "path guard: failures above"
