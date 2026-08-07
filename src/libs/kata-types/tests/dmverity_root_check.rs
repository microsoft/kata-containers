// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! RM-52 integration checks against a real dm-verity device.
//!
//! These exist because the unit tests cannot reach the parts that can actually be wrong:
//! whether `table_status` returns the *active* table, whether the kernel reports the verity
//! parameters in the layout the parser assumes, and whether the eager verification read
//! turns a bad hash tree into a mount-time failure instead of a later `EIO`.
//!
//! Requires root and a loop device, so they are `#[ignore]`d by default:
//!
//! ```text
//! sudo -E cargo test --features devicemapper --test dmverity_root_check -- --ignored --test-threads=1
//! ```

#![cfg(feature = "devicemapper")]

use kata_types::dmverity::{
    build_dmverity_device_name, create_dmverity_device, destroy_partition_dmverity_device,
};
use kata_types::mount::DmVerityInfo;
use std::path::{Path, PathBuf};
use std::process::Command;

const BLOCK: u64 = 4096;
const DATA_BLOCKS: u64 = 64;

fn sh(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {}", cmd, e));
    assert!(
        out.status.success(),
        "{} {:?} failed: {}{}",
        cmd,
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// A loop-backed image whose data area is followed by a verity hash tree, mirroring the
/// layout the agent receives (hash tree appended to the same device).
struct VerityFixture {
    img: PathBuf,
    loop_dev: String,
    root_hash: String,
    salt: String,
}

impl VerityFixture {
    fn new(tag: &str) -> Self {
        let img = PathBuf::from(format!("/tmp/rm52-{tag}-{}.img", std::process::id()));
        let _ = std::fs::remove_file(&img);

        // Data area of known content, then room for the hash tree.
        let data = vec![0xABu8; (BLOCK * DATA_BLOCKS) as usize];
        std::fs::write(&img, &data).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
        f.set_len(BLOCK * DATA_BLOCKS * 4).unwrap();
        drop(f);

        let hash_offset = (BLOCK * DATA_BLOCKS).to_string();
        let out = sh(
            "veritysetup",
            &[
                "format",
                img.to_str().unwrap(),
                img.to_str().unwrap(),
                "--data-block-size",
                &BLOCK.to_string(),
                "--hash-block-size",
                &BLOCK.to_string(),
                "--data-blocks",
                &DATA_BLOCKS.to_string(),
                "--hash-offset",
                &hash_offset,
            ],
        );

        let field = |name: &str| -> String {
            out.lines()
                .find(|l| l.starts_with(name))
                .unwrap_or_else(|| panic!("veritysetup output missing {}:\n{}", name, out))
                .split_whitespace()
                .last()
                .unwrap()
                .to_string()
        };
        let root_hash = field("Root hash");
        let salt = field("Salt");

        let loop_dev = sh("losetup", &["--find", "--show", img.to_str().unwrap()])
            .trim()
            .to_string();

        VerityFixture {
            img,
            loop_dev,
            root_hash,
            salt,
        }
    }

    fn info(&self, hash: &str) -> DmVerityInfo {
        DmVerityInfo {
            hashtype: "sha256".to_string(),
            hash: hash.to_string(),
            blocknum: DATA_BLOCKS,
            blocksize: BLOCK,
            hashsize: BLOCK,
            offset: BLOCK * DATA_BLOCKS,
            salt: Some(self.salt.clone()),
            hash_type: 1,
            no_superblock: false,
        }
    }
}

impl Drop for VerityFixture {
    fn drop(&mut self) {
        let _ = Command::new("losetup")
            .args(["-d", &self.loop_dev])
            .status();
        let _ = std::fs::remove_file(&self.img);
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The good case: a device whose hash tree really does root at the declared hash comes up,
/// which also proves the read-back parsed the *active* table rather than rejecting a
/// correctly-built device.
#[test]
#[ignore]
fn good_root_hash_activates() {
    let fx = VerityFixture::new("good");
    let info = fx.info(&fx.root_hash);

    let dev = rt()
        .block_on(create_dmverity_device(&info, Path::new(&fx.loop_dev)))
        .expect("device with the correct root hash must activate");
    assert!(Path::new(&dev).exists(), "{} should exist", dev);

    // Tear down through the same path production uses, and check it removes the node too --
    // `create_dmverity_device` always creates the node itself, so teardown always owns it.
    let logger = slog_scope::logger();
    destroy_partition_dmverity_device(&dev, &logger).expect("teardown must succeed");
    assert!(
        !Path::new(&dev).exists(),
        "{} should have been removed by teardown",
        dev
    );
}

/// The case RM-52 exists for: a hash that does not match the device's tree must fail
/// *while creating the device*, not later on first read. Without the eager verification
/// read this activates cleanly and only fails as an opaque EIO deep inside a container.
#[test]
#[ignore]
fn wrong_root_hash_fails_at_creation() {
    let fx = VerityFixture::new("bad");
    // Flip the first nibble: same length, same format, different tree.
    let mut wrong = fx.root_hash.clone();
    let first = if wrong.starts_with('0') { '1' } else { '0' };
    wrong.replace_range(0..1, &first.to_string());
    assert_ne!(wrong, fx.root_hash);

    let info = fx.info(&wrong);
    let err = rt()
        .block_on(create_dmverity_device(&info, Path::new(&fx.loop_dev)))
        .expect_err("a device whose tree does not root at the declared hash must not come up");

    let msg = format!("{err:#}");
    // Specifically the *eager read*, not the table read-back. That distinction is the
    // evidence RM-52 buys something: the table loaded fine and the read-back passed (the
    // kernel is enforcing exactly the hash we asked it to), so without the verification
    // read this device would have activated cleanly and only failed later, as an opaque
    // EIO somewhere inside a running container.
    assert!(
        msg.contains("verification read failed"),
        "expected the eager verification read to reject the device, got: {}",
        msg
    );
    assert!(
        msg.contains("hash tree does not match"),
        "error should explain what went wrong, got: {}",
        msg
    );

    // The failure path must not leave the rejected mapping live in the kernel. Before this
    // was fixed, every failed verification leaked an active dm device (observed directly:
    // `dmsetup ls` listing devices for images that had long since been deleted).
    let name = build_dmverity_device_name(Path::new(&fx.loop_dev), &info);
    let live = Command::new("dmsetup")
        .args(["ls"])
        .output()
        .expect("dmsetup ls");
    let live = String::from_utf8_lossy(&live.stdout);
    assert!(
        !live.contains(&name),
        "a device rejected by verification was left active: {} still in:\n{}",
        name,
        live
    );
}
