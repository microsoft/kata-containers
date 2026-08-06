# Vendored `pathrs` 0.2.4 (patched)

Upstream: https://github.com/cyphar/libpathrs (crates.io `pathrs` 0.2.4)
Licence: MPL-2.0 OR LGPL-3.0-or-later (unmodified LICENSE files retained)

## Why this is vendored

`pathrs` parses the `release` string from `uname(2)` to feature-gate kernel
capabilities (`is_gte!(5, 2)` in `procfs.rs`, `is_gte!(5, 14)` in
`utils/fdinfo.rs`, `is_lt!(5, 14)` in `utils/fd.rs`). Its parser strips the
vendor localversion by cutting the string at the first character that is
neither an ASCII digit nor a dot.

Every mainstream distro separates the localversion with a **dash**
(`5.15.0-89-generic` -> `5.15.0`), so the cut lands cleanly. MSHV kernels use a
**dot** (`6.6.137.mshv2-2.azl3`, `6.1.58.mshv8`), so the cut leaves a trailing
dot -> an empty final version component -> `parse_kernel_version` returns
`None` -> `host_kernel_version()` panics on its `.expect()`.

`host_kernel_version()` is a `once_cell::Lazy` forced by ordinary path
resolution, so on any MSHV kernel this panics on the first `CopyFile` RPC --
both on the AzL3 MSHV host and inside the SNP UVM guest.

## The patch

`0001-kernel_version-tolerate-dot-separated-localversion.patch` -- one line:
trim trailing dots after the localversion is stripped, so `6.6.137.mshv2-2.azl3`
parses as `6.6.137` instead of failing.

Upstream bug report pending; drop this vendored copy once a fixed release ships.

## Trimmed

Non-build content removed to keep the tree small: `go-pathrs/`, `e2e-tests/`,
`examples/`, `contrib/`, `hack/`, `Makefile`, `install.sh`, `codecov.yml`,
`libpathrs.keyring`, `MAINTAINERS`. Rust sources, `build.rs`, `include/`,
`cbindgen.toml`, `README.md` and all licence files are unmodified.
