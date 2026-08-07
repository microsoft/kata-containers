// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Reconstruction of the EROFS layer image that containerd's differ builds on
//! the host, so that genpolicy can predict its dm-verity root hash (RM-42).
//!
//! The host side is `plugins/diff/erofs` in containerd. For each image layer it
//! decompresses the registry blob and pipes the tar into `mkfs.erofs`, then
//! formats the result with dm-verity. Because every input to `mkfs.erofs` is
//! pinned -- build timestamp, tar ordering, and the filesystem UUID -- the
//! resulting image is a pure function of the layer content, and we can rebuild
//! it here and hash it (RM-47).
//!
//! This is deliberately an exact reproduction of containerd's command line
//! rather than an equivalent one: any divergence produces a different root hash
//! and therefore a policy that denies every pod, so the argv is treated as an
//! interface and asserted on in the tests below.

use anyhow::{anyhow, bail, Result};
use log::{debug, info};
use sha1::Digest;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Namespace UUID used by containerd when deriving a layer's filesystem UUID.
/// This is RFC 4122's standard URL namespace.
const UUID_NAMESPACE_URL: [u8; 16] = [
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
];

/// The fixed leading options containerd passes to `mkfs.erofs` in its default
/// (non tar-index) mode, before the operator's configured `mkfs_options`.
///
/// `--tar=f` fully converts the tar into an EROFS image, `--aufs` translates
/// aufs whiteouts, `--quiet` suppresses progress output, `-Enoinline_data`
/// keeps file data out of inodes so that the layout is stable, and `-b4096`
/// sets the block size.
const CONTAINERD_FIXED_OPTS: &[&str] = &["--tar=f", "--aufs", "--quiet", "-Enoinline_data", "-b4096"];

/// The `mkfs_options` kata-deploy writes into containerd's differ configuration.
/// Must stay in sync with `erofs_mkfs_options()` in
/// `tools/packaging/kata-deploy/binary/src/artifacts/snapshotters.rs`.
const KATA_MKFS_OPTS: &[&str] = &["-T0", "--mkfs-time", "--sort=none"];

/// Derive the filesystem UUID containerd assigns to a layer's EROFS image.
///
/// containerd computes `uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+desc.Digest))`,
/// a version 5 UUID over the layer's *compressed manifest digest*. Note this is
/// the manifest digest, not the diff_id: two images sharing an uncompressed
/// layer but compressed differently get different UUIDs and therefore different
/// root hashes.
pub fn layer_uuid(layer_digest: &str) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(UUID_NAMESPACE_URL);
    hasher.update(format!("erofs:blobs/{layer_digest}").as_bytes());
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122: set the version to 5 and the variant to RFC 4122.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let h: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    )
}

/// Build the exact `mkfs.erofs` argument list containerd uses for `layer_digest`,
/// excluding the program name.
///
/// The order matters: containerd appends its own `-U` *after* the configured
/// `mkfs_options`, and `mkfs.erofs` honours the last `-U` on the command line
/// (RM-46).
pub fn mkfs_args(image_path: &Path, layer_digest: &str) -> Vec<String> {
    let mut args: Vec<String> = CONTAINERD_FIXED_OPTS.iter().map(|s| s.to_string()).collect();
    args.extend(KATA_MKFS_OPTS.iter().map(|s| s.to_string()));
    args.push("-U".to_string());
    args.push(layer_uuid(layer_digest));
    args.push(image_path.to_string_lossy().into_owned());
    args
}

/// Build the EROFS image for a decompressed layer tarball and return its path.
///
/// `mkfs.erofs` reads the tar from stdin, exactly as containerd's differ feeds
/// it from the decompressing reader.
pub fn build_layer_image(
    decompressed_tar: &Path,
    layer_digest: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    let image_path = output_dir.join("layer.erofs");
    let args = mkfs_args(&image_path, layer_digest);
    debug!("build_layer_image: mkfs.erofs {}", args.join(" "));

    let tar = std::fs::File::open(decompressed_tar)
        .map_err(|e| anyhow!("failed to open {}: {e}", decompressed_tar.display()))?;

    let output = Command::new("mkfs.erofs")
        .args(&args)
        .stdin(tar)
        .output()
        .map_err(|e| {
            anyhow!(
                "failed to run mkfs.erofs (is erofs-utils installed?): {e}. \
                 Deriving EROFS layer root hashes requires the same erofs-utils \
                 version as the target nodes"
            )
        })?;

    if !output.status.success() {
        bail!(
            "mkfs.erofs failed for layer {layer_digest}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(image_path)
}

/// Derive the dm-verity root hash the host will compute for an image layer.
pub fn layer_root_hash(decompressed_tar: &Path, layer_digest: &str) -> Result<String> {
    let temp_dir = tempfile::tempdir()?;
    let image = build_layer_image(decompressed_tar, layer_digest, temp_dir.path())?;
    let hash = crate::verity::root_hash(
        &image,
        crate::verity::DEFAULT_BLOCK_SIZE,
        crate::verity::DEFAULT_BLOCK_SIZE,
        &crate::verity::CONTAINERD_DEFAULT_SALT,
    )?;
    info!("layer_root_hash: layer {layer_digest} -> {hash}");
    Ok(hash)
}

/// Report the installed `mkfs.erofs` version.
///
/// The derived root hash is only stable for a fixed erofs-utils version, so the
/// version is recorded to make a hash mismatch after a node image bump
/// diagnosable rather than mysterious (RM-47).
pub fn erofs_utils_version() -> Result<String> {
    let output = Command::new("mkfs.erofs")
        .arg("--version")
        .output()
        .map_err(|e| anyhow!("failed to run mkfs.erofs --version: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden UUID, cross-checked against Python's
    /// `uuid.uuid5(uuid.NAMESPACE_URL, "erofs:blobs/sha256:deadbeef")`, which is
    /// the same construction as Go's `uuid.NewSHA1(uuid.NameSpaceURL, ...)`.
    #[test]
    fn layer_uuid_matches_containerd() {
        assert_eq!(
            layer_uuid("sha256:deadbeef"),
            "ebc0b188-5b2a-52e0-b4a0-21a192556101"
        );
    }

    /// A version 5 UUID must carry the version nibble and the RFC 4122 variant
    /// bits; getting these wrong yields a UUID mkfs.erofs would still accept but
    /// that differs from containerd's, silently breaking every derived hash.
    #[test]
    fn layer_uuid_is_version_5() {
        let u = layer_uuid("sha256:abc123");
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "5", "version nibble in {u}");
        assert!(
            ["8", "9", "a", "b"].contains(&&u[19..20]),
            "variant nibble in {u}"
        );
    }

    /// Observed golden vector: containerd 2.3.3 (commit aad11006) pulling
    /// `docker.io/library/alpine:3.20` through the erofs differ produced an image
    /// whose `Filesystem UUID` was exactly this value for that layer digest.
    /// This pins the derivation to real, measured containerd behaviour rather
    /// than to our reading of its source.
    #[test]
    fn layer_uuid_matches_observed_containerd_artifact() {
        assert_eq!(
            layer_uuid("sha256:25f1d6b1951ac8eb3740558fe94cb83d377bdadf95fd9f98b50d2e1b96130471"),
            "bbd1bbf7-a4ab-554a-8c54-61915f102522"
        );
    }

    /// Different layers must get different UUIDs, otherwise two layers with the
    /// same content would be indistinguishable in the image.
    #[test]
    fn layer_uuid_is_per_layer() {
        assert_ne!(layer_uuid("sha256:aaa"), layer_uuid("sha256:bbb"));
    }

    /// The argv is an interface with containerd: it must reproduce the differ's
    /// command line exactly, including the trailing `-U` that overrides anything
    /// configured before it.
    #[test]
    fn mkfs_args_reproduce_containerd_command_line() {
        let args = mkfs_args(Path::new("/tmp/layer.erofs"), "sha256:deadbeef");
        assert_eq!(
            args,
            vec![
                "--tar=f",
                "--aufs",
                "--quiet",
                "-Enoinline_data",
                "-b4096",
                "-T0",
                "--mkfs-time",
                "--sort=none",
                "-U",
                "ebc0b188-5b2a-52e0-b4a0-21a192556101",
                "/tmp/layer.erofs",
            ]
        );
    }

    /// The UUID must be the last `-U` and must come after the kata-configured
    /// options, mirroring containerd appending it to `mkfsExtraOpts`.
    #[test]
    fn uuid_is_appended_after_configured_options() {
        let args = mkfs_args(Path::new("/tmp/x"), "sha256:deadbeef");
        let u = args.iter().position(|a| a == "-U").unwrap();
        let sort = args.iter().position(|a| a == "--sort=none").unwrap();
        assert!(u > sort, "-U must follow the configured mkfs_options");
        assert_eq!(args.iter().filter(|a| *a == "-U").count(), 1);
    }

    /// End-to-end verification against a real containerd artifact.
    ///
    /// Set `KATA_TEST_EROFS_TAR` to a decompressed layer tar, `KATA_TEST_EROFS_DIGEST`
    /// to that layer's manifest digest and `KATA_TEST_EROFS_ROOTHASH` to the
    /// `roothash` containerd wrote into the `.dmverity` sidecar for the same layer.
    /// The test then proves that genpolicy, on its own, arrives at the hash the
    /// host will present at runtime. Skipped when the variables are unset because
    /// it needs a live erofs-utils and a real image.
    #[test]
    fn layer_root_hash_matches_containerd_sidecar() {
        let (tar, digest, expected) = match (
            std::env::var("KATA_TEST_EROFS_TAR"),
            std::env::var("KATA_TEST_EROFS_DIGEST"),
            std::env::var("KATA_TEST_EROFS_ROOTHASH"),
        ) {
            (Ok(t), Ok(d), Ok(h)) => (t, d, h),
            _ => return,
        };
        let hash = layer_root_hash(Path::new(&tar), &digest).unwrap();
        assert_eq!(hash, expected);
    }
}
