// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-4B — descriptor/handle-based operations (TOCTOU defense).
//!
//! A path checked at authorization time can be swapped — via a symlink flip or a rename of
//! a parent component — before it is used, so an operation that re-resolves the path *by
//! name* may act on a different object than the one that was checked.
//!
//! The defence is to stop naming the object twice. [`CheckedHandle::capture`] opens the
//! path once, at check time, and keeps an `O_PATH` descriptor. A descriptor refers to the
//! inode itself, not to the name it was reached through, so it cannot be redirected: after
//! any subsequent rename or symlink swap the descriptor still refers to the object that was
//! checked. The operation is then performed against [`CheckedHandle::bound_target`], the
//! `/proc/self/fd/N` magic link for that descriptor, which the kernel resolves straight to
//! the pinned inode without walking the original path a second time.
//!
//! [`CheckedHandle::verify_unchanged`] is retained as a *diagnostic*, not as the control:
//! it reports whether the original name still resolves to the pinned object, which turns a
//! swap attempt into an explicit error rather than a silently-ignored one. Even if it were
//! removed the binding would still hold, because the operation never uses the name again.

use std::fmt;
use std::fs::File;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

/// A filesystem object pinned at check time.
///
/// Holds an `O_PATH` descriptor to the object, so the identity captured here is the
/// identity any later operation acts on.
pub struct CheckedHandle {
    /// The path the object was reached through. Retained for diagnostics and error
    /// messages only — it is deliberately never re-resolved to perform the operation.
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    /// `O_PATH` descriptor pinning the object. Nothing the host does to the namespace can
    /// redirect it.
    handle: File,
}

impl fmt::Debug for CheckedHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedHandle")
            .field("path", &self.path)
            .field("dev", &self.dev)
            .field("ino", &self.ino)
            .field("fd", &self.handle.as_raw_fd())
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HandleError {
    /// The path no longer resolves to any object.
    Vanished { path: String },
    /// The path now resolves to a different object than the one checked (a swap).
    Swapped {
        path: String,
        expected: (u64, u64),
        found: (u64, u64),
    },
}

impl fmt::Display for HandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandleError::Vanished { path } => {
                write!(f, "checked path {path} vanished before use")
            }
            HandleError::Swapped {
                path,
                expected,
                found,
            } => write!(
                f,
                "path {path} was swapped between check and use: expected dev/ino {expected:?}, found {found:?}"
            ),
        }
    }
}

impl std::error::Error for HandleError {}

impl CheckedHandle {
    /// Pin `path` by opening it with `O_PATH` and recording the resulting object's identity.
    ///
    /// `O_PATH` opens the object without granting read or write access to its contents and
    /// without triggering any side effects of opening (no device is activated, no FIFO
    /// blocks), which is exactly what is wanted for something that will be mounted on or
    /// mounted from rather than read.
    ///
    /// Symlinks in the path are resolved normally, matching the resolution the authorized
    /// operation would itself have performed; the point is not to forbid symlinks but to
    /// resolve them exactly once, under our control, and then hold the result.
    pub fn capture(path: impl Into<String>) -> std::io::Result<Self> {
        let path = path.into();
        // `read(true)` is required by `OpenOptions`, but O_PATH overrides the access mode:
        // the descriptor confers no read permission on the object's contents.
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&path)?;
        let md = handle.metadata()?;
        Ok(CheckedHandle {
            dev: md.dev(),
            ino: md.ino(),
            path,
            handle,
        })
    }

    /// The path to hand to a syscall so it operates on the pinned object rather than
    /// re-resolving the original name.
    ///
    /// `/proc/self/fd/N` is a magic link: the kernel jumps straight to the inode the
    /// descriptor refers to, so no component of the original path is walked again and there
    /// is nothing left for the host to swap.
    pub fn bound_target(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd()))
    }

    /// Diagnostic: report whether the original name still resolves to the pinned object.
    ///
    /// A failure here means someone moved the target between the check and the use. The
    /// operation is refused so the attempt surfaces as an error, but note that the safety
    /// of the operation does not rest on this — [`Self::bound_target`] does not consult the
    /// name at all.
    pub fn verify_unchanged(&self) -> Result<(), HandleError> {
        let md = std::fs::metadata(&self.path).map_err(|_| HandleError::Vanished {
            path: self.path.clone(),
        })?;
        self.check_identity(md.dev(), md.ino())
    }

    /// Compare a currently-observed identity against the pinned one (unit-testable core).
    pub fn check_identity(&self, current_dev: u64, current_ino: u64) -> Result<(), HandleError> {
        if (current_dev, current_ino) == (self.dev, self.ino) {
            Ok(())
        } else {
            Err(HandleError::Swapped {
                path: self.path.clone(),
                expected: (self.dev, self.ino),
                found: (current_dev, current_ino),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scratch directory + a file to pin, so every test works against a real inode rather
    /// than a hand-built struct (the handle now owns a descriptor and cannot be faked).
    fn scratch(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fr4b-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("checked");
        std::fs::write(&target, b"original").unwrap();
        (dir, target)
    }

    /// Atomically replace `target` with a different inode, the way an attacker with write
    /// access to the parent directory would.
    fn swap_in_new_inode(dir: &PathBuf, target: &PathBuf) {
        let other = dir.join("attacker");
        std::fs::write(&other, b"attacker-controlled").unwrap();
        std::fs::rename(&other, target).unwrap();
    }

    #[test]
    fn identity_match_is_accepted() {
        let (dir, target) = scratch("id-ok");
        let h = CheckedHandle::capture(target.to_str().unwrap()).unwrap();
        assert!(h.check_identity(h.dev, h.ino).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn identity_mismatch_is_rejected() {
        let (dir, target) = scratch("id-bad");
        let h = CheckedHandle::capture(target.to_str().unwrap()).unwrap();
        assert_eq!(
            h.check_identity(h.dev, h.ino + 1).unwrap_err(),
            HandleError::Swapped {
                path: target.to_str().unwrap().to_string(),
                expected: (h.dev, h.ino),
                found: (h.dev, h.ino + 1),
            }
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The property FR-4B actually asks for: after the name is swapped, the *handle* still
    /// reaches the object that was checked. This is what makes the mount safe rather than
    /// merely racy-but-narrow — nothing the host does to the namespace redirects it.
    #[test]
    fn bound_target_still_reaches_the_checked_object_after_a_swap() {
        let (dir, target) = scratch("bind");
        let handle = CheckedHandle::capture(target.to_str().unwrap()).unwrap();

        swap_in_new_inode(&dir, &target);

        // Resolving the name now yields the attacker's inode ...
        let by_name = std::fs::metadata(&target).unwrap();
        assert_ne!(by_name.ino(), handle.ino);
        assert_eq!(std::fs::read(&target).unwrap(), b"attacker-controlled");

        // ... but the bound target still lands on the pinned one.
        let by_handle = std::fs::metadata(handle.bound_target()).unwrap();
        assert_eq!(by_handle.ino(), handle.ino);
        assert_eq!(by_handle.dev(), handle.dev);
        assert_eq!(std::fs::read(handle.bound_target()).unwrap(), b"original");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Even after the name is deleted outright, the handle remains valid — an unlinked
    /// inode is still reachable through its descriptor.
    #[test]
    fn bound_target_survives_deletion_of_the_name() {
        let (dir, target) = scratch("unlink");
        let handle = CheckedHandle::capture(target.to_str().unwrap()).unwrap();
        std::fs::remove_file(&target).unwrap();

        let md = std::fs::metadata(handle.bound_target()).unwrap();
        assert_eq!(md.ino(), handle.ino);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// TC5.4: a swap between check and use is still *reported*, so the attempt is visible
    /// rather than silently tolerated.
    #[test]
    fn real_file_swap_between_check_and_use_is_reported() {
        let (dir, target) = scratch("swap");
        let handle = CheckedHandle::capture(target.to_str().unwrap()).unwrap();
        assert!(handle.verify_unchanged().is_ok());

        swap_in_new_inode(&dir, &target);

        assert!(matches!(
            handle.verify_unchanged().unwrap_err(),
            HandleError::Swapped { .. }
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn vanished_path_is_reported() {
        let (dir, target) = scratch("van");
        let handle = CheckedHandle::capture(target.to_str().unwrap()).unwrap();
        std::fs::remove_file(&target).unwrap();
        assert!(matches!(
            handle.verify_unchanged().unwrap_err(),
            HandleError::Vanished { .. }
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Capturing a path that does not exist must fail, so a caller cannot end up with
    /// "no handle" and skip the binding silently.
    #[test]
    fn capturing_a_missing_path_fails() {
        assert!(CheckedHandle::capture("/definitely/not/here/fr4b").is_err());
    }
}
