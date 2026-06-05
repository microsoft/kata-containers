// Copyright (c) 2026 Microsoft
//
// SPDX-License-Identifier: Apache-2.0
//

//! Pre-slog fallback file logger and panic hook for the kata shim.
//!
//! The slog logger (see `logger::set_logger`) is initialised inside
//! `ShimExecutor::run` after argument parsing and several other steps.
//! Anything that panics or `eprintln!`s before that point is invisible
//! to `journalctl -t kata`, and containerd's `cmd.CombinedOutput()` may
//! surface it only as an opaque "ttrpc: unsupported protocol" error
//! against the unrelated transport.
//!
//! This module installs a tiny fallback that runs from the very first
//! line of `main()`. It:
//!
//!   * Opens an append-only file at
//!     `/var/log/kata-shim/early-<pid>.log` with mode 0600 (the
//!     directory is created if missing).
//!   * Records a single one-line breadcrumb identifying the
//!     invocation: pid, ppid, argv, cwd, and the kata-relevant
//!     environment variables.
//!   * Replaces the default panic handler with one that writes the
//!     panic message + backtrace to the same file before re-running
//!     the existing slog-based hook (see `panic_hook::set_panic_hook`).
//!
//! The fallback log is intentionally simple: it has no dependency on
//! slog, tokio, or any kata library, so a panic in those subsystems
//! still produces output. Once slog is up, a `early-logger handing
//! over to slog` line is written and the file logger goes quiet for
//! the rest of the run; the panic hook stays installed in case a
//! later panic occurs after slog drains have been torn down.

use std::{
    env, fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    panic,
    path::{Path, PathBuf},
    process,
    sync::{Mutex, OnceLock},
};

use backtrace::Backtrace;

/// Directory used by the shim for file-side logs. See also the slog
/// `run.log` and the `invocations.log` written by the
/// `54-patch-runtime-rs-shim-in-kata.sh` wrapper.
pub const SHIM_LOG_DIR: &str = "/var/log/kata-shim";

/// Whitelisted environment variables to dump in the breadcrumb. Kept
/// deliberately small to avoid leaking secrets that production
/// deployments often park in `*_TOKEN` or `*_KEY` env vars.
const ENV_ALLOWLIST: &[&str] = &[
    "RUST_LOG",
    "RUST_BACKTRACE",
    "KATA_CONF_FILE",
    "XDG_RUNTIME_DIR",
    "PATH",
    "TOKIO_RUNTIME_WORKER_THREADS",
];

static EARLY_FILE: OnceLock<Mutex<fs::File>> = OnceLock::new();

/// Initialise the early file logger. Idempotent. Best-effort: returns
/// quietly on any I/O failure (the rest of the shim still functions
/// without an early log; we just lose visibility into pre-slog
/// crashes).
pub fn init() {
    let _ = fs::create_dir_all(SHIM_LOG_DIR);

    let path = PathBuf::from(SHIM_LOG_DIR).join(format!("early-{}.log", process::id()));

    let file = match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return,
    };

    if EARLY_FILE.set(Mutex::new(file)).is_err() {
        return;
    }

    install_panic_hook();
    record_invocation();
}

/// Append a single line to the early log. No-op if `init()` did not
/// succeed.
pub fn record(line: &str) {
    if let Some(mu) = EARLY_FILE.get() {
        if let Ok(mut f) = mu.lock() {
            let _ = writeln!(f, "{}", line);
            let _ = f.flush();
        }
    }
}

/// Mark the hand-off from the early logger to slog. Called from
/// `ShimExecutor::run` once `logger::set_logger` has returned.
pub fn handoff_to_slog() {
    record("early-logger handing over to slog");
}

fn record_invocation() {
    let pid = process::id();
    let ppid = nix::unistd::getppid().as_raw();
    let argv = env::args().collect::<Vec<_>>().join(" ");
    let cwd = env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());

    let env_dump = ENV_ALLOWLIST
        .iter()
        .filter_map(|k| env::var(k).ok().map(|v| format!("{}={}", k, v)))
        .collect::<Vec<_>>()
        .join(" ");

    record(&format!(
        "invocation pid={} ppid={} cwd={} argv={:?} env=[{}]",
        pid, ppid, cwd, argv, env_dump
    ));
}

fn install_panic_hook() {
    // Preserve whatever hook is currently installed (typically the
    // default print-to-stderr hook; the slog-aware
    // `panic_hook::set_panic_hook` runs later and chains on top of
    // this one).
    let prev = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let (file, line) = info
            .location()
            .map(|l| (l.file().to_string(), l.line()))
            .unwrap_or_else(|| ("<unknown>".to_string(), 0));
        let payload = info.payload();
        let cause = payload
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("<cause unknown>");
        let bt = Backtrace::new();
        record(&format!(
            "PANIC at {}:{}: {} pid={} ppid={}",
            file,
            line,
            cause,
            process::id(),
            nix::unistd::getppid().as_raw()
        ));
        record(&format!("backtrace:\n{:?}", bt));
        // Re-invoke the previous hook so the existing slog/kmsg path
        // also runs once it is in place.
        prev(info);
    }));
}

/// Returns the early-log file path for the current process, useful
/// when the slog `invocation` line wants to point a human at the
/// fallback log.
pub fn current_log_path() -> Option<PathBuf> {
    EARLY_FILE.get().map(|_| {
        Path::new(SHIM_LOG_DIR)
            .join(format!("early-{}.log", process::id()))
    })
}
