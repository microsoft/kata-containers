#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Build and install erofs-utils, which provides mkfs.erofs.
#
# genpolicy reproduces containerd's EROFS layer images byte for byte in order to
# compute their dm-verity root hashes, so it invokes mkfs.erofs with containerd's
# own option set. That set needs a version far newer than the distributions the
# CI runners use ship: Ubuntu 22.04 carries 1.4 and 24.04 carries 1.7.1, while
# --tar=f, -T0, --mkfs-time and --sort=none require >= 1.8.2. Building the pinned
# release from source keeps the version identical across every runner image and
# independent of what the distribution happens to carry.

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
source "${script_dir}/../tests/common.bash"

# These change the behaviour of the configure script and would make the build
# install somewhere other than the requested directory.
unset PREFIX DESTDIR

workdir="$(mktemp -d --tmpdir build-erofs-utils.XXXXX)"

erofs_utils_version="${EROFS_UTILS_VERSION:-""}"
if [[ -z "${erofs_utils_version}" ]]; then
	erofs_utils_version=$(get_from_kata_deps ".externals.erofs-utils.version")
fi
erofs_utils_url="${EROFS_UTILS_URL:-""}"
if [[ -z "${erofs_utils_url}" ]]; then
	erofs_utils_url=$(get_from_kata_deps ".externals.erofs-utils.url")
fi

erofs_utils_tarball="erofs-utils-${erofs_utils_version}.tar.gz"
erofs_utils_tarball_url="${erofs_utils_url}/snapshot/${erofs_utils_tarball}"

die() {
	msg="$*"
	echo "[Error] ${msg}" >&2
	exit 1
}

finish() {
	rm -rf "${workdir}"
}

trap finish EXIT

build_and_install_erofs_utils() {
	echo "Build and install erofs-utils version ${erofs_utils_version}"
	mkdir -p "${erofs_utils_install_dir}"

	curl -sLO "${erofs_utils_tarball_url}"
	tar -xf "${erofs_utils_tarball}"
	pushd "erofs-utils-${erofs_utils_version}"

	# The git snapshot ships no configure script.
	./autogen.sh

	# lz4 is what containerd's differ compresses with, so it has to be enabled
	# for the images genpolicy rebuilds to match byte for byte. libuuid is
	# likewise required rather than optional: the images carry the filesystem
	# UUID containerd derives per layer, which mkfs.erofs can only set with -U.
	# Fail loudly if either is missing rather than silently producing a
	# mkfs.erofs that cannot reproduce them.
	./configure --prefix="${erofs_utils_install_dir}" --enable-lz4

	make
	make install
	popd

	local installed
	installed="$("${erofs_utils_install_dir}/bin/mkfs.erofs" --version 2>&1 | head -1)"
	echo "erofs-utils installed successfully: ${installed}"
}

main() {
	local erofs_utils_install_dir="${1:-}"

	if [[ -z "${erofs_utils_install_dir}" ]]; then
		die "Usage: ${0} <erofs-utils-install-dir>"
	fi

	pushd "${workdir}"
	build_and_install_erofs_utils
	popd
}

main "$@"
