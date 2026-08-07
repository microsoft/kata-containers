// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! dm-verity root hash computation.
//!
//! genpolicy needs to predict the dm-verity root hash that the host's EROFS
//! snapshotter will produce for an image layer, so that the generated policy can
//! bind each layer to its content rather than merely requiring that *some*
//! verity device be present (RM-42).
//!
//! This computes the hash tree exactly as `veritysetup format` and the kernel's
//! dm-verity target do, without writing it out -- only the root hash is needed.
//! The tree is built bottom-up: every data block is hashed as `salt || block`,
//! the resulting digests are packed into hash blocks (zero-padded to the hash
//! block size), each hash block is hashed the same way, and the process repeats
//! until a level fits in a single hash block. The root hash is that final
//! block's digest.
//!
//! Verified against `veritysetup format --no-superblock` (cryptsetup 2.7.x,
//! hash type 1, sha256) for both the 4096-byte layout containerd uses in its
//! default tar mode and the 512-byte layout it uses in tar-index mode; see the
//! golden vectors in the tests below.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Size of a sha256 digest, in bytes.
const DIGEST_SIZE: usize = 32;

/// dm-verity block size used by containerd's EROFS differ in its default
/// (`--tar=f`) mode, which is the mode kata-deploy configures.
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// The all-zero salt containerd's differ formats layers with. Mirrors
/// `CONTAINERD_DEFAULT_DMVERITY_SALT` in `kata-types::gpt_disk`, expressed here
/// as raw bytes because that constant is a hex string.
pub const CONTAINERD_DEFAULT_SALT: [u8; 32] = [0u8; 32];

/// Compute the dm-verity root hash of `path`, as lowercase hex.
///
/// `data_block_size` and `hash_block_size` must both be non-zero multiples of
/// the digest size; a short trailing data block is zero-padded, matching the
/// way containerd pre-allocates the hash area at a block-aligned offset.
pub fn root_hash(
    path: &Path,
    data_block_size: usize,
    hash_block_size: usize,
    salt: &[u8],
) -> Result<String> {
    if data_block_size == 0 || hash_block_size < DIGEST_SIZE {
        return Err(anyhow!(
            "invalid dm-verity geometry: data block {data_block_size}, hash block {hash_block_size}"
        ));
    }

    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow!("failed to open {} for hashing: {e}", path.display()))?;

    let mut digests: Vec<u8> = Vec::new();
    let mut block = vec![0u8; data_block_size];
    loop {
        let read = read_full(&mut file, &mut block)?;
        if read == 0 {
            break;
        }
        block[read..].fill(0);
        digests.extend_from_slice(&hash_block(salt, &block));
    }

    if digests.is_empty() {
        return Err(anyhow!("cannot compute a root hash over an empty file"));
    }

    // Digests per hash block; the remainder of a partially filled hash block is
    // zeroed so that its hash is well defined.
    let per_block = hash_block_size / DIGEST_SIZE;
    loop {
        let blocks = digests.len().div_ceil(per_block * DIGEST_SIZE);
        let mut next = Vec::with_capacity(blocks * DIGEST_SIZE);
        let mut padded = vec![0u8; hash_block_size];
        for chunk in digests.chunks(per_block * DIGEST_SIZE) {
            padded[..chunk.len()].copy_from_slice(chunk);
            padded[chunk.len()..].fill(0);
            if blocks == 1 {
                return Ok(hex(&hash_block(salt, &padded)));
            }
            next.extend_from_slice(&hash_block(salt, &padded));
        }
        digests = next;
    }
}

fn hash_block(salt: &[u8], block: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(block);
    hasher.finalize().into()
}

/// Read until `buf` is full or EOF, returning how many bytes were read.
///
/// `Read::read` is permitted to return short reads, so a single call cannot be
/// used to detect a partial final block.
fn read_full(file: &mut std::fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(anyhow!("failed to read layer image: {e}")),
        }
    }
    Ok(filled)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Writes a deterministic 3000-block file: block `i` is the little-endian
    /// u32 `i` repeated to fill 4096 bytes. The golden hashes below were taken
    /// from `veritysetup format` over this exact content.
    fn deterministic_image(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("det.img");
        let mut f = std::fs::File::create(&path).unwrap();
        for i in 0u32..3000 {
            let word = i.to_le_bytes();
            let block: Vec<u8> = word.iter().copied().cycle().take(4096).collect();
            f.write_all(&block).unwrap();
        }
        f.flush().unwrap();
        path
    }

    /// Golden vector for the layout containerd uses in its default tar mode.
    /// Produced by:
    ///   veritysetup format det.img det.hash --data-block-size=4096 \
    ///       --hash-block-size=4096 --salt=00..00 --no-superblock
    #[test]
    fn root_hash_matches_veritysetup_at_4096() {
        let dir = tempfile::tempdir().unwrap();
        let img = deterministic_image(dir.path());
        assert_eq!(
            root_hash(&img, 4096, 4096, &CONTAINERD_DEFAULT_SALT).unwrap(),
            "b66f087933ddbac8aca3c62359bbd9ff87372c30d86dbb6bfcd4b8ae369367eb"
        );
    }

    /// Same content under the 512-byte layout containerd forces in tar-index
    /// mode. We do not use that mode today (RM-49), but the geometry must stay
    /// correct so that enabling it later is a configuration change only.
    #[test]
    fn root_hash_matches_veritysetup_at_512() {
        let dir = tempfile::tempdir().unwrap();
        let img = deterministic_image(dir.path());
        assert_eq!(
            root_hash(&img, 512, 512, &CONTAINERD_DEFAULT_SALT).unwrap(),
            "94c67a2d2b46e669032d74bcdf3571cc128c306281e4ae6deb07ff62011c7dee"
        );
    }

    /// The salt is prefixed to every hashed block, so a different salt must
    /// yield a different root hash. Without this, a policy generated against
    /// containerd's default salt would silently match a device formatted with
    /// any other salt.
    #[test]
    fn salt_changes_the_root_hash() {
        let dir = tempfile::tempdir().unwrap();
        let img = deterministic_image(dir.path());
        let zero = root_hash(&img, 4096, 4096, &CONTAINERD_DEFAULT_SALT).unwrap();
        let other = root_hash(&img, 4096, 4096, &[0xabu8; 32]).unwrap();
        assert_ne!(zero, other);
    }

    /// A trailing partial block is zero-padded, exactly as dm-verity treats a
    /// device whose length is not a whole number of blocks. Appending the
    /// padding explicitly must therefore give the same answer.
    #[test]
    fn trailing_partial_block_is_zero_padded() {
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short.img");
        let padded = dir.path().join("padded.img");
        std::fs::write(&short, b"hello world").unwrap();
        let mut full = b"hello world".to_vec();
        full.resize(4096, 0);
        std::fs::write(&padded, &full).unwrap();
        assert_eq!(
            root_hash(&short, 4096, 4096, &CONTAINERD_DEFAULT_SALT).unwrap(),
            root_hash(&padded, 4096, 4096, &CONTAINERD_DEFAULT_SALT).unwrap()
        );
    }

    /// An empty file has no data blocks and therefore no root hash; returning
    /// some default would let a zero-length layer masquerade as verified.
    #[test]
    fn empty_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.img");
        std::fs::write(&empty, b"").unwrap();
        assert!(root_hash(&empty, 4096, 4096, &CONTAINERD_DEFAULT_SALT).is_err());
    }

    /// Guard the geometry validation: a zero data block size would divide by
    /// zero and a hash block smaller than a digest could never hold one.
    #[test]
    fn invalid_geometry_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("x.img");
        std::fs::write(&img, vec![0u8; 4096]).unwrap();
        assert!(root_hash(&img, 0, 4096, &CONTAINERD_DEFAULT_SALT).is_err());
        assert!(root_hash(&img, 4096, 16, &CONTAINERD_DEFAULT_SALT).is_err());
    }
}
