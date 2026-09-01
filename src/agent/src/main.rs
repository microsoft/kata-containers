// Copyright (c) 2019 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate lazy_static;
extern crate capctl;
extern crate prometheus;
extern crate protocols;
extern crate regex;
extern crate scan_fmt;
extern crate serde_json;

#[macro_use]
extern crate scopeguard;

#[macro_use]
extern crate slog;

use anyhow::{anyhow, bail, Context, Result};
use cfg_if::cfg_if;
use clap::Parser;
use const_format::concatcp;
use initdata::{InitdataReturnValue, AA_CONFIG_PATH, CDH_CONFIG_PATH};
use nix::fcntl::OFlag;
use nix::sys::reboot::{reboot, RebootMode};
// Only the non-strict logger path binds a vsock listener; a strict build discards the log
// stream (FR-7 / F-79) and therefore never constructs one.
#[cfg(not(feature = "strict-policy"))]
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, VsockAddr};
use nix::unistd::{self, dup, sync, Pid};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::os::unix::fs::{self as unixfs, FileTypeExt};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::Path;
use std::process::exit;
use std::sync::Arc;
use tracing::{instrument, span};

mod confidential_data_hub;
mod config;
mod console;
mod device;
mod features;
mod guest_extension_image;
mod initdata;
mod linux_abi;
mod mediation;
mod metrics;
mod mount;
mod namespace;
mod netlink;
mod network;
mod passfd_io;
mod pci;
pub mod random;
mod sandbox;
mod signal;
mod storage;
mod uevent;
mod util;
mod version;
mod watcher;

use config::GuestComponentsProcs;
use mount::{cgroups_mount, general_mount};
use sandbox::Sandbox;
use signal::setup_signal_handler;
use slog::{debug, error, info, o, warn, Logger};
use uevent::watch_uevents;

use futures::future::join_all;
use rustjail::pipestream::PipeStream;
use tokio::{
    io::AsyncWrite,
    sync::{
        watch::{channel, Receiver},
        Mutex,
    },
    task::JoinHandle,
};

mod rpc;
mod tracer;

#[cfg(feature = "agent-policy")]
mod policy;

// BL-8: the measured base policy's declared policy-fragment requirements, and the
// fail-closed gate that keeps containers from starting until the host has delivered them.
// Only in strict confidential builds, where the SRM `FRAGMENTS` store exists.
#[cfg(feature = "strict-policy")]
mod policy_fragments;

// In-guest verification that the initdata the agent consumed is the initdata the VM was
// launched with (HOSTDATA / MRCONFIGID). Only in strict confidential builds.
#[cfg(feature = "strict-policy")]
mod hostdata;

// FR-3: bounds the divergence between the OCI spec the policy authorized and the spec the
// in-guest resolution chain actually executes. Only in strict confidential builds.
#[cfg(feature = "strict-policy")]
mod plan_binding;

cfg_if! {
    if #[cfg(target_arch = "s390x")] {
        mod ap;
        mod ccw;
    }
}

const NAME: &str = "kata-agent";

const UNIX_SOCKET_PREFIX: &str = "unix://";

// Legacy (non-extension) rootfs locations for the CoCo guest components. They are
// used to build the built-in launch plan when no CoCo extension image is mounted,
// keeping monolithic / non-confidential images working unchanged.
const AA_PATH: &str = "/usr/local/bin/attestation-agent";
const AA_ATTESTATION_SOCKET: &str =
    "/run/confidential-containers/attestation-agent/attestation-agent.sock";
const AA_ATTESTATION_URI: &str = concatcp!(UNIX_SOCKET_PREFIX, AA_ATTESTATION_SOCKET);

const CDH_PATH: &str = "/usr/local/bin/confidential-data-hub";
const CDH_SOCKET: &str = "/run/confidential-containers/cdh.sock";
const CDH_SOCKET_URI: &str = concatcp!(UNIX_SOCKET_PREFIX, CDH_SOCKET);

const API_SERVER_PATH: &str = "/usr/local/bin/api-server-rest";

const OCICRYPT_CONFIG_PATH: &str = "/etc/ocicrypt_config.json";

lazy_static! {
    static ref AGENT_CONFIG: AgentConfig =
        // Note: We can't do AgentOpts.parse() here to send through the processed arguments to AgentConfig
        // clap::Parser::parse() greedily process all command line input including cargo test parameters,
        // so should only be used inside main.
        AgentConfig::from_cmdline("/proc/cmdline", env::args().collect()).unwrap();
}

#[cfg(feature = "agent-policy")]
lazy_static! {
    static ref AGENT_POLICY: Mutex<AgentPolicy> = Mutex::new(AgentPolicy::new());
}

// FR-6: the Security Reference Monitor tracks each security-relevant, state-mutating
// operation as a two-phase transaction (prepare/execute/commit/abort) so policy and
// runtime state commit together or are rolled back/quarantined. Present only in strict
// builds; it is agent-internal and introduces no new shim<->agent API.
#[cfg(feature = "strict-policy")]
lazy_static! {
    static ref SRM: Mutex<kata_security_reference_monitor::ReferenceMonitor> =
        Mutex::new(kata_security_reference_monitor::ReferenceMonitor::new());
}

// FR-9: registry of container occurrences and their lifecycle states. The host
// container_id is an untrusted alias; the enforcer mints its own occurrence handle and
// gates every lifecycle-mutating RPC on the occurrence state. Strict builds only;
// agent-internal, no new shim<->agent API.
#[cfg(feature = "strict-policy")]
lazy_static! {
    static ref OCCURRENCES: Mutex<kata_security_reference_monitor::OccurrenceRegistry> =
        Mutex::new(kata_security_reference_monitor::OccurrenceRegistry::new());
}

// FR-1: verifier/accumulator for signed, add-only policy fragments. Receipts are enforced
// in strict builds. Authorized issuers and root constraints are configured from measured
// state; absent configuration, no issuer is trusted (fail-closed). Strict builds only.
#[cfg(feature = "strict-policy")]
lazy_static! {
    static ref FRAGMENTS: Mutex<kata_security_reference_monitor::FragmentStore> =
        Mutex::new(kata_security_reference_monitor::FragmentStore::new(true));
}

// F-159: serializes a whole LoadPolicyFragment, so verify -> apply -> commit really is the
// atomic step its callers assume. The store lock alone cannot do this: the apply runs under
// AGENT_POLICY, and register_nested_fragments re-enters FRAGMENTS, so holding the store
// guard across the sequence would both invert the boot path's AGENT_POLICY -> FRAGMENTS
// order and deadlock on the re-entry. This is the outermost lock and nothing beneath it
// takes it.
//
// Without it two concurrent loads each read the SVN floor before either commits, so both
// clear the monotonicity gate; whichever applies last wins the engine, and the losing
// fragment's commit then writes its own (lower) SVN as the high-water mark. A host that can
// issue two RPCs in parallel could therefore install a superseded fragment *and* lower the
// anti-rollback floor -- the guarantee FR-1 exists to provide. hcsshim closes the same
// window with regoEnforcer.WithMetadataRollback's transactionLock.
#[cfg(feature = "strict-policy")]
lazy_static! {
    static ref FRAGMENT_LOAD: Mutex<()> = Mutex::new(());
}

// FR-14: network phase state machine. Network-mutating RPCs are permitted only during
// sandbox setup; once a workload container starts the network surface is frozen. Strict
// builds only; agent-internal.
#[cfg(feature = "strict-policy")]
lazy_static! {
    static ref NET_PHASE: Mutex<kata_security_reference_monitor::NetworkPhaseMachine> =
        Mutex::new(kata_security_reference_monitor::NetworkPhaseMachine::new());
}

#[derive(Parser)]
// The default clap version info doesn't match our form, so we need to override it
#[clap(disable_version_flag = true)]
struct AgentOpts {
    /// Print the version information
    #[clap(short, long)]
    version: bool,
    #[clap(subcommand)]
    subcmd: Option<SubCommand>,
    /// Specify a custom agent config file
    #[clap(short, long)]
    config: Option<String>,
}

#[derive(Parser)]
enum SubCommand {
    Init {},
}

#[instrument]
fn announce(logger: &Logger, config: &AgentConfig) {
    let extra_features = features::get_build_features();

    info!(logger, "announce";
    "agent-commit" => version::VERSION_COMMIT,
    "agent-version" =>  version::AGENT_VERSION,
    "api-version" => version::API_VERSION,
    "config" => format!("{:?}", config),
    "extra-features" => format!("{extra_features:?}"),
    );
}

// Create a thread to handle reading from the logger pipe. The thread will
// output to the vsock port specified, or stdout.
async fn create_logger_task(rfd: RawFd, vsock_port: u32, shutdown: Receiver<bool>) -> Result<()> {
    let mut reader = PipeStream::from_fd(rfd);

    // FR-7 (F-79): a strict confidential build does not forward the agent's log stream to
    // the host at all — matching the baseline, where runtime logging defaults to off and the
    // GCS logger is wired to io.Discard. Both sinks below are host-visible (vsock directly,
    // stdout via the guest console), and both the verbosity and the port are chosen on the
    // kernel command line, which this build already treats as untrusted for the debug
    // console. The stream is still *drained* into a sink rather than left unread: the writer
    // end is a pipe shared by every logger in the process, so abandoning the reader would
    // block the agent as soon as the pipe filled.
    #[cfg(feature = "strict-policy")]
    let mut writer: Box<dyn AsyncWrite + Unpin + Send> = {
        let _ = vsock_port;
        Box::new(tokio::io::sink())
    };

    #[cfg(not(feature = "strict-policy"))]
    let mut writer: Box<dyn AsyncWrite + Unpin + Send> = if vsock_port > 0 {
        let listenfd = socket::socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )?;

        let addr = VsockAddr::new(libc::VMADDR_CID_ANY, vsock_port);
        socket::bind(listenfd.as_raw_fd(), &addr)?;
        socket::listen(&listenfd, nix::sys::socket::Backlog::new(1).unwrap())?;

        Box::new(util::get_vsock_stream(listenfd.into_raw_fd()).await?)
    } else {
        Box::new(tokio::io::stdout())
    };

    let _ = util::interruptable_io_copier(&mut reader, &mut writer, shutdown).await;

    Ok(())
}

async fn real_main(init_mode: bool) -> std::result::Result<(), Box<dyn std::error::Error>> {
    env::set_var("RUST_BACKTRACE", "full");

    // List of tasks that need to be stopped for a clean shutdown
    let mut tasks: Vec<JoinHandle<Result<()>>> = vec![];

    console::initialize();

    // support vsock log
    let (rfd, wfd) = unistd::pipe2(OFlag::O_CLOEXEC)?;

    let (shutdown_tx, shutdown_rx) = channel(true);

    if init_mode {
        // dup a new file descriptor for this temporary logger writer,
        // since this logger would be dropped and it's writer would
        // be closed out of this code block.
        let newwfd = dup(&wfd)?;
        let writer = unsafe { File::from_raw_fd(newwfd.into_raw_fd()) };

        // Init a temporary logger used by init agent as init process
        // since before do the base mount, it wouldn't access "/proc/cmdline"
        // to get the customzied debug level.
        let (logger, logger_async_guard) =
            logging::create_logger(NAME, "agent", slog::Level::Debug, writer);

        // Must mount proc fs before parsing kernel command line
        general_mount(&logger).map_err(|e| {
            error!(logger, "fail general mount: {}", e);
            e
        })?;

        lazy_static::initialize(&AGENT_CONFIG);
        let cgroup_v2 = AGENT_CONFIG.unified_cgroup_hierarchy || AGENT_CONFIG.cgroup_no_v1 == "all";

        init_agent_as_init(&logger, cgroup_v2)?;
        drop(logger_async_guard);
    } else {
        lazy_static::initialize(&AGENT_CONFIG);
    }

    let config = &AGENT_CONFIG;
    let log_vport = config.log_vport as u32;

    let log_handle = tokio::spawn(create_logger_task(
        rfd.into_raw_fd(),
        log_vport,
        shutdown_rx.clone(),
    ));

    tasks.push(log_handle);

    let writer = unsafe { File::from_raw_fd(wfd.into_raw_fd()) };

    // Recreate a logger with the log level get from "/proc/cmdline".
    let (logger, logger_async_guard) =
        logging::create_logger(NAME, "agent", config.log_level, writer);

    announce(&logger, config);

    // This variable is required as it enables the global (and crucially static) logger,
    // which is required to satisfy the the lifetime constraints of the auto-generated gRPC code.
    let global_logger = slog_scope::set_global_logger(logger.new(o!("subsystem" => "rpc")));

    // Allow the global logger to be modified later (for shutdown)
    global_logger.cancel_reset();

    let mut ttrpc_log_guard: Result<(), log::SetLoggerError> = Ok(());

    if config.log_level == slog::Level::Trace {
        // Redirect ttrpc log calls to slog iff full debug requested
        ttrpc_log_guard = Ok(slog_stdlog::init()?);
    }

    // FR-7 (F-80): the OpenTelemetry exporter is a vsock channel out of the guest that
    // carries decoded RPC requests — `trace_rpc_call!` records `req=?$req`, so an enabled
    // trace exports whole CreateContainer OCI specs, exec argument vectors and mount lists.
    // It is enabled by a plain kernel command line flag, so a strict build refuses it
    // outright; the baseline has no host-facing span exporter in its confidential path at
    // all. `config.tracing` is already forced false by the strict config allow-list — this
    // gate is here so that neither place can quietly become the only one.
    #[cfg(feature = "strict-policy")]
    let tracing_enabled = false;
    #[cfg(not(feature = "strict-policy"))]
    let tracing_enabled = config.tracing;

    if tracing_enabled {
        tracer::setup_tracing(NAME, &logger)?;
    }

    let root_span = span!(tracing::Level::TRACE, "root-span");

    // XXX: Start the root trace transaction.
    //
    // XXX: Note that *ALL* spans needs to start after this point!!
    let span_guard = root_span.enter();

    // Start the fd passthrough io listener
    let passfd_listener_port = config.passfd_listener_port as u32;
    if passfd_listener_port != 0 {
        passfd_io::start_listen(passfd_listener_port).await?;
    }

    // Start the sandbox and wait for its ttRPC server to end
    start_sandbox(&logger, config, init_mode, &mut tasks, shutdown_rx.clone()).await?;

    // Install a NOP logger for the remainder of the shutdown sequence
    // to ensure any log calls made by local crates using the scope logger
    // don't fail.
    let global_logger_guard2 =
        slog_scope::set_global_logger(slog::Logger::root(slog::Discard, o!()));
    global_logger_guard2.cancel_reset();

    drop(logger_async_guard);

    drop(ttrpc_log_guard);

    // Trigger a controlled shutdown
    shutdown_tx
        .send(true)
        .map_err(|e| anyhow!(e).context("failed to request shutdown"))?;

    // Wait for all threads to finish
    let results = join_all(tasks).await;

    // force flushing spans
    drop(span_guard);
    drop(root_span);

    if config.tracing {
        tracer::end_tracing();
    }

    eprintln!("{NAME} shutdown complete");

    let mut wait_errors: Vec<tokio::task::JoinError> = vec![];
    for result in results {
        if let Err(e) = result {
            eprintln!("wait task error: {e:#?}");
            wait_errors.push(e);
        }
    }

    if wait_errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("wait all tasks failed: {:#?}", wait_errors).into())
    }
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = AgentOpts::parse();

    if args.version {
        let extra_features = features::get_build_features();

        println!(
            "{} version {} (api version: {}, commit version: {}, type: rust, extra-features: {extra_features:?})",
            NAME,
            version::AGENT_VERSION,
            version::API_VERSION,
            version::VERSION_COMMIT,
        );
        exit(0);
    }

    if let Some(SubCommand::Init {}) = args.subcmd {
        reset_sigpipe();
        rustjail::container::init_child();
        exit(0);
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let init_mode = unistd::getpid() == Pid::from_raw(1);
    let result = rt.block_on(real_main(init_mode));

    if init_mode {
        sync();
        let _ = reboot(RebootMode::RB_POWER_OFF);
    }

    result
}

// FR-7 (F-79) fallout: a strict build routes the agent's log stream into a sink, so the
// `error!` that precedes each fatal startup abort below produces *no output at all* —
// and because `kata-agent.service` carries `FailureAction=poweroff`, the VM then shuts
// down silently. The observable symptom is a guest that powers off a few seconds into
// boot having said nothing, which is close to undebuggable: it took days to attribute one
// such abort to a missing kernel config option (RM-68).
//
// Emit a short reason straight to stderr as well, which reaches the guest console and
// bypasses the sink entirely. What is disclosed is a fixed `&'static str` chosen at the
// call site — never policy content, measurement values, or any formatted error — so this
// adds nothing a host cannot already infer from the fact that the VM aborted at all,
// while turning a silent poweroff into a one-line diagnosis.
#[cfg(any(feature = "agent-policy", feature = "strict-policy"))]
fn fatal_reason_line(reason: &'static str) -> String {
    format!("kata-agent: fatal: {}; aborting VM\n", reason)
}

#[cfg(any(feature = "agent-policy", feature = "strict-policy"))]
fn emit_fatal_reason(reason: &'static str) {
    // Deliberately a raw, unbuffered write rather than a logger: `abort()` raises SIGABRT,
    // which does not run destructors or flush buffered writers.
    use std::io::Write;
    let mut err = std::io::stderr();
    let _ = err.write_all(fatal_reason_line(reason).as_bytes());
    let _ = err.flush();
}

/// Abort the process (and so the VM) after a fatal startup failure.
///
/// The brief sleep gives a non-strict build's asynchronous logger a chance to drain before
/// SIGABRT; the console line is written synchronously beforehand, so it survives regardless.
#[cfg(any(feature = "agent-policy", feature = "strict-policy"))]
async fn fatal_abort(reason: &'static str) -> ! {
    emit_fatal_reason(reason);
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    std::process::abort();
}

#[instrument]
async fn start_sandbox(
    logger: &Logger,
    config: &AgentConfig,
    init_mode: bool,
    tasks: &mut Vec<JoinHandle<Result<()>>>,
    shutdown: Receiver<bool>,
) -> Result<()> {
    let debug_console_vport = config.debug_console_vport as u32;

    // FR-7: the interactive debug console is an un-mediated shell into the guest and is
    // never available in a strict confidential build, regardless of host configuration.
    #[cfg(feature = "strict-policy")]
    let debug_console_enabled = false;
    #[cfg(not(feature = "strict-policy"))]
    let debug_console_enabled = config.debug_console;

    if debug_console_enabled {
        let debug_console_task = tokio::task::spawn(console::debug_console_handler(
            logger.clone(),
            debug_console_vport,
            shutdown.clone(),
        ));

        tasks.push(debug_console_task);
    }

    // Initialize unique sandbox structure.
    let s = Sandbox::new(logger).context("Failed to create sandbox")?;
    if init_mode {
        s.rtnl.handle_localhost().await?;
    }

    #[cfg(feature = "agent-policy")]
    if let Err(e) = initialize_policy().await {
        error!(logger, "Failed to initialize agent policy: {:?}", e);
        // Continuing execution without a security policy could be dangerous.
        fatal_abort("agent policy failed to initialize").await;
    }

    let sandbox = Arc::new(Mutex::new(s));

    let signal_handler_task = tokio::spawn(setup_signal_handler(
        logger.clone(),
        sandbox.clone(),
        shutdown.clone(),
    ));

    tasks.push(signal_handler_task);

    let uevents_handler_task = tokio::spawn(watch_uevents(sandbox.clone(), shutdown.clone()));

    tasks.push(uevents_handler_task);

    let (tx, rx) = tokio::sync::oneshot::channel();
    sandbox.lock().await.sender = Some(tx);

    let initdata_return_value = initdata::initialize_initdata(logger).await?;

    // FR-2: bind the initdata the agent just parsed to the VM's launch measurement before
    // anything consumes it. The host stamps the initdata digest into HOSTDATA (SEV-SNP) or
    // MRCONFIGID (TDX); without this check the guest would take the host's word for it and
    // rely on a remote verifier to notice later -- which gates secret release but does not
    // stop the guest from running under host-chosen initdata (policy, SRM trust roots,
    // AA/CDH config) in the meantime. Equivalent to hcsshim's `ValidateHostData()`.
    //
    // Fail-closed: a mismatch, or a report we cannot read or parse, aborts the VM. A guest with
    // no TEE report provider at all cannot *prove* it is non-confidential, so F-166/R-2 makes
    // that fatal too in a strict build: hcsshim's gcs-sidecar keeps its deny policy when no
    // report is available, and F-6 showed the no-provider path is reachable on a genuinely
    // confidential VM (Azure paravisor SNP, where `detect_provider()` finds neither sysfs dir).
    // Treating it as "not a confidential VM" therefore hands the host an unmeasured initdata on
    // exactly the platform C-ACI ships. `allow-unattested-initdata` restores the old
    // warn-and-continue for non-confidential dev VMs; it is a *build-time* opt-out on purpose,
    // because the agent's environment and kernel command line are host-chosen, so a runtime
    // switch would hand the downgrade straight back.
    #[cfg(feature = "strict-policy")]
    let initdata_bound = if let Some(idrv) = initdata_return_value.as_ref() {
        match hostdata::verify_initdata_binding(logger, &idrv.digest) {
            Ok(true) => {
                info!(logger, "FR-2: initdata verified against launch measurement");
                true
            }
            Ok(false) => {
                #[cfg(not(feature = "allow-unattested-initdata"))]
                {
                    error!(
                        logger,
                        "FR-2: no TEE report provider, so the initdata cannot be bound to a \
                         launch measurement and the guest cannot prove it is non-confidential; \
                         aborting VM (F-166/R-2)"
                    );
                    fatal_abort("initdata is not bound to a launch measurement (FR-2/F-166)").await
                }
                #[cfg(feature = "allow-unattested-initdata")]
                {
                    warn!(
                        logger,
                        "FR-2: no TEE report provider; initdata is NOT bound to a launch \
                         measurement. The SRM trust roots it carries are host-chosen."
                    );
                    false
                }
            }
            Err(e) => {
                error!(
                    logger,
                    "FR-2: initdata does not match the launch measurement, aborting VM: {:?}", e
                );
                fatal_abort("initdata does not match the launch measurement (FR-2)").await
            }
        }
    } else {
        false
    };

    // FR-1b / FR-4C / BL-3 (BL-5): seed the SRM trust roots — the policy-fragment issuers,
    // the verified read-only-layer (dm-verity) allowlist, and the verified guest-pull image
    // allowlist — from measured guest state. FR-1's root comes from the attestation-bound
    // initdata section and nowhere else (RM-89; see `resolve_measured_config` for why the
    // rootfs alternative was removed). Seeded after initdata is parsed and before the ttRPC
    // server (and the BL-8 boot fragment pull) run.
    //
    // RM-36 (F-94): a seeding failure is **fatal**. It used to be `warn!`-and-continue, which
    // meant an unparseable measured trust root produced a booting, apparently-healthy,
    // unprotected pod — the fail-open direction, and the one an operator is least likely to
    // notice. Fifty lines above, an initdata measurement mismatch already aborts; a trust
    // root that exists but cannot be read is the same class of fault and now gets the same
    // treatment. Note this deliberately does not cover *absent* config: that is F-93, and the
    // three roots differ there (FR-1's store defaults closed, the two allowlists default to
    // not-required until something produces their files).
    #[cfg(feature = "strict-policy")]
    {
        let idrv = initdata_return_value.as_ref();
        let seeded = async {
            seed_fragment_trust_root(
                logger,
                idrv.and_then(|r| r._fragment_issuers.as_deref()),
                initdata_bound,
            )
            .await
            .context("FR-1: fragment trust root")
        }
        .await;
        if let Err(e) = seeded {
            error!(
                logger,
                "SRM trust root is present but unusable, aborting VM: {:?}", e
            );
            fatal_abort("SRM trust root is present but unusable (RM-36)").await;
        }
    }

    let gc_procs = config.guest_components_procs;
    let launch_plan = build_coco_launch_plan(config, &initdata_return_value, gc_procs)?;
    if !attestation_components_available(logger, &launch_plan) {
        warn!(
            logger,
            "attestation binaries requested for launch not available"
        );
    } else {
        init_attestation_components(logger, &launch_plan).await?;
    }

    // if policy is given via initdata, use it
    #[cfg(feature = "agent-policy")]
    if let Some(initdata_return_value) = initdata_return_value {
        if let Some(policy) = &initdata_return_value._policy {
            info!(logger, "using policy from initdata");
            AGENT_POLICY
                .lock()
                .await
                .set_policy(policy)
                .await
                .context("Failed to set policy from initdata")?;
        }
    }

    // BL-8: record the fragment requirements the measured base policy declares, after the
    // base policy is set from init-data and the fragment trust root is seeded.
    //
    // The guest does NOT fetch them. This runs before rpc::start() below, and the guest's
    // interfaces and routes are configured only by the update_interface/update_routes ttRPC
    // handlers — so at this point there is no network at all and a pull could never
    // succeed. Delivery is the host's job (as in C-ACI/hcsshim), arriving through
    // rpc::load_policy_fragment; verification stays here, against the measured trust root.
    //
    // Fail-closed is preserved by refusing container creation while any declaration marked
    // `required` is outstanding, not by aborting here — the bytes legitimately have not
    // arrived yet. Declarations without that flag are lazy, as in C-ACI/hcsshim: an
    // undelivered fragment grants nothing, so its absence cannot widen what runs. Failing to
    // *read* the declarations is still fatal: an unreadable list must not be mistaken for an
    // empty one.
    #[cfg(feature = "strict-policy")]
    match policy_fragments::record_declared_fragments().await {
        Ok(n) if n > 0 => info!(
            logger,
            "FR-1/BL-8: {} declared fragment(s) recorded; see policy-fragments logs for which \
             are required",
            n
        ),
        Ok(_) => {}
        Err(e) => {
            error!(
                logger,
                "FR-1/BL-8: could not read declared policy fragments, aborting VM: {:?}", e
            );
            fatal_abort("could not read declared policy fragments (FR-1/BL-8)").await;
        }
    }

    let mut oma = None;
    let mut _ort = None;
    if let Some(c) = &config.mem_agent {
        let (ma, rt) =
            mem_agent::agent::MemAgent::new(c.memcg_config.clone(), c.compact_config.clone())
                .map_err(|e| {
                    error!(logger, "MemAgent::new fail: {}", e);
                    e
                })
                .context("start mem-agent")?;
        oma = Some(ma);
        _ort = Some(rt);
    }

    // vsock:///dev/vsock, port
    let mut server =
        rpc::start(sandbox.clone(), config.server_addr.as_str(), init_mode, oma).await?;

    server.start().await?;

    rx.await?;
    server.shutdown().await?;

    Ok(())
}

// Map the requested guest-components level to the numeric gating level used by
// extension manifests. A process is launched only when its declared `level` is
// <= this value. The ordering mirrors the implications documented on
// `GuestComponentsProcs` (ApiServerRest implies CDH implies AttestationAgent).
fn guest_components_max_level(procs: GuestComponentsProcs) -> u32 {
    match procs {
        GuestComponentsProcs::None => 0,
        GuestComponentsProcs::AttestationAgent => 1,
        GuestComponentsProcs::ConfidentialDataHub => 2,
        GuestComponentsProcs::ApiServerRest => 3,
    }
}

// Build the substitution context exposed to extension manifests. New extension bundles
// can rely on these variables without requiring agent code changes; introducing
// a brand new variable is the only case that needs touching the agent.
fn build_substitution_ctx(
    config: &AgentConfig,
    initdata_return_value: &Option<InitdataReturnValue>,
) -> Result<std::collections::HashMap<String, String>> {
    let ocicrypt_config_path = guest_extension_image::resolve_component_path(
        guest_extension_image::COCO_EXTENSION_NAME,
        guest_extension_image::COCO_COMPONENT_OCICRYPT_CONFIG,
        OCICRYPT_CONFIG_PATH,
    )?;

    let initdata_toml_path = if initdata_return_value.is_some() {
        initdata::INITDATA_TOML_PATH.to_string()
    } else {
        String::new()
    };

    let extension_root =
        guest_extension_image::extension_mount_root(guest_extension_image::COCO_EXTENSION_NAME)?;

    let mut ctx = std::collections::HashMap::new();
    ctx.insert(
        "aa_attestation_uri".to_string(),
        AA_ATTESTATION_URI.to_string(),
    );
    ctx.insert(
        "aa_attestation_socket".to_string(),
        AA_ATTESTATION_SOCKET.to_string(),
    );
    ctx.insert("aa_config_path".to_string(), AA_CONFIG_PATH.to_string());
    ctx.insert("cdh_config_path".to_string(), CDH_CONFIG_PATH.to_string());
    ctx.insert("cdh_socket".to_string(), CDH_SOCKET.to_string());
    ctx.insert(
        "ocicrypt_config_path".to_string(),
        ocicrypt_config_path.to_string_lossy().into_owned(),
    );
    ctx.insert(
        "rest_api_features".to_string(),
        config.guest_components_rest_api.to_string(),
    );
    ctx.insert(
        "launch_process_timeout".to_string(),
        config.launch_process_timeout.as_secs().to_string(),
    );
    ctx.insert("initdata_toml_path".to_string(), initdata_toml_path);
    ctx.insert(
        "extension_root".to_string(),
        extension_root.to_string_lossy().into_owned(),
    );
    // The CoCo extension ships several attestation-agent flavours and selects one
    // via the manifest's "attester_variant". The guest init (NVRC) owns that
    // decision: with a GPU present it sets KATA_ATTESTER_VARIANT=nvidia so the
    // NVIDIA-attester build launches (it emits the GPU evidence a KBS GPU
    // policy requires). Absent that signal we fall back to the stock attester.
    // Cross-component contract: the env var name and "nvidia" value are set by
    // NVRC (src/kata_agent.rs, src/gpu.rs); keep them in sync.
    let attester_variant = env::var("KATA_ATTESTER_VARIANT")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "default".to_string());
    ctx.insert("attester_variant".to_string(), attester_variant);

    Ok(ctx)
}

// Built-in launch plan used when no CoCo extension image is mounted. It reproduces
// the legacy behaviour of launching the guest components from the rootfs
// (`/usr/local/bin/...`), so monolithic and non-confidential images are
// unaffected by the extension machinery.
fn builtin_coco_plan(
    config: &AgentConfig,
    initdata_return_value: &Option<InitdataReturnValue>,
    max_level: u32,
) -> Vec<guest_extension_image::LaunchSpec> {
    let mut plan = Vec::new();

    if max_level >= 1 {
        let mut args = vec![
            "--attestation_sock".to_string(),
            AA_ATTESTATION_URI.to_string(),
        ];
        if initdata_return_value.is_some() {
            args.push("--initdata-toml".to_string());
            args.push(initdata::INITDATA_TOML_PATH.to_string());
        }
        plan.push(guest_extension_image::LaunchSpec {
            id: "attestation-agent".to_string(),
            path: Path::new(AA_PATH).to_path_buf(),
            args,
            config: Some(AA_CONFIG_PATH.to_string()),
            env: vec![],
            wait_socket: Some(AA_ATTESTATION_SOCKET.to_string()),
            timeout_secs: config.launch_process_timeout.as_secs(),
        });
    }

    if max_level >= 2 {
        plan.push(guest_extension_image::LaunchSpec {
            id: "confidential-data-hub".to_string(),
            path: Path::new(CDH_PATH).to_path_buf(),
            args: vec![],
            config: Some(CDH_CONFIG_PATH.to_string()),
            env: vec![(
                "OCICRYPT_KEYPROVIDER_CONFIG".to_string(),
                OCICRYPT_CONFIG_PATH.to_string(),
            )],
            wait_socket: Some(CDH_SOCKET.to_string()),
            timeout_secs: config.launch_process_timeout.as_secs(),
        });
    }

    if max_level >= 3 {
        plan.push(guest_extension_image::LaunchSpec {
            id: "api-server-rest".to_string(),
            path: Path::new(API_SERVER_PATH).to_path_buf(),
            args: vec![
                "--features".to_string(),
                config.guest_components_rest_api.to_string(),
            ],
            config: None,
            env: vec![],
            wait_socket: None,
            timeout_secs: 0,
        });
    }

    plan
}

// Build the ordered launch plan for the guest components. When a CoCo extension
// image is mounted its manifest drives the plan (so new bundles need no agent
// changes); otherwise the built-in legacy plan is used.
fn build_coco_launch_plan(
    config: &AgentConfig,
    initdata_return_value: &Option<InitdataReturnValue>,
    procs: GuestComponentsProcs,
) -> Result<Vec<guest_extension_image::LaunchSpec>> {
    let max_level = guest_components_max_level(procs);
    let ctx = build_substitution_ctx(config, initdata_return_value)?;
    match guest_extension_image::launch_plan(
        guest_extension_image::COCO_EXTENSION_NAME,
        max_level,
        &ctx,
    )? {
        Some(plan) => Ok(plan),
        None => Ok(builtin_coco_plan(config, initdata_return_value, max_level)),
    }
}

// Check that every process in the launch plan is present on disk. A missing
// binary means the components were not provisioned (e.g. a non-confidential
// rootfs), in which case launching is skipped.
fn attestation_components_available(
    logger: &Logger,
    plan: &[guest_extension_image::LaunchSpec],
) -> bool {
    for spec in plan {
        let exists = spec
            .path
            .try_exists()
            .unwrap_or_else(|error| match error.kind() {
                ErrorKind::NotFound => false,
                _ => panic!(
                    "Path existence check failed for '{}': {}",
                    spec.path.display(),
                    error
                ),
            });

        if !exists {
            warn!(logger, "{} not found", spec.path.display());
            return false;
        }
    }
    true
}

async fn launch_guest_component_procs(
    logger: &Logger,
    plan: &[guest_extension_image::LaunchSpec],
) -> Result<()> {
    for spec in plan {
        let path = spec
            .path
            .to_str()
            .ok_or_else(|| anyhow!("non-utf8 component path {}", spec.path.display()))?;
        debug!(logger, "spawning extension component process {}", spec.id);

        let args: Vec<&str> = spec.args.iter().map(String::as_str).collect();
        let envs: Vec<(&str, &str)> = spec
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        launch_process(
            logger,
            path,
            args,
            spec.config.as_deref(),
            spec.wait_socket.as_deref().unwrap_or(""),
            spec.timeout_secs,
            &envs,
        )
        .await
        .map_err(|e| anyhow!("launch_process {} failed: {:?}", path, e))?;
    }

    Ok(())
}

// Start-up attestation-agent, CDH and api-server-rest if they are packaged in the rootfs
// and the corresponding procs are enabled in the agent configuration. the process will be
// launched in the background and the function will return immediately.
// If the CDH is started, a CDH client will be instantiated and returned.
async fn init_attestation_components(
    logger: &Logger,
    plan: &[guest_extension_image::LaunchSpec],
) -> Result<()> {
    launch_guest_component_procs(logger, plan).await?;

    // If a CDH socket exists, initialize the CDH client and enable ocicrypt
    match tokio::fs::metadata(CDH_SOCKET).await {
        Ok(md) => {
            if md.file_type().is_socket() {
                confidential_data_hub::init_cdh_client(CDH_SOCKET_URI).await?;
            } else {
                debug!(logger, "File {} is not a socket", CDH_SOCKET);
            }
        }
        Err(err) => warn!(
            logger,
            "Failed to probe CDH socket file {}: {:?}", CDH_SOCKET, err
        ),
    }

    Ok(())
}

async fn wait_for_path_to_exist(logger: &Logger, path: &str, timeout_secs: u64) -> Result<()> {
    let p = Path::new(path);
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if p.exists() {
            return Ok(());
        }
        if attempts >= timeout_secs {
            break;
        }
        attempts += 1;
        info!(
            logger,
            "waiting for {} to exist (attempts={})", path, attempts
        );
    }

    Err(anyhow!("wait for {} to exist timeout.", path))
}

async fn launch_process(
    logger: &Logger,
    path: &str,
    mut args: Vec<&str>,
    config: Option<&str>,
    unix_socket_path: &str,
    timeout_secs: u64,
    envs: &[(&str, &str)],
) -> Result<()> {
    if !Path::new(path).exists() {
        bail!("path {} does not exist.", path);
    }

    if let Some(config_path) = config {
        if Path::new(config_path).exists() {
            args.push("-c");
            args.push(config_path);
        }
    }

    if !unix_socket_path.is_empty() && Path::new(unix_socket_path).exists() {
        tokio::fs::remove_file(unix_socket_path).await?;
    }

    let mut process = tokio::process::Command::new(path);
    process.args(args);
    for (k, v) in envs {
        process.env(k, v);
    }
    process.spawn()?;
    if !unix_socket_path.is_empty() && timeout_secs > 0 {
        wait_for_path_to_exist(logger, unix_socket_path, timeout_secs).await?;
    }

    Ok(())
}

// init_agent_as_init will do the initializations such as setting up the rootfs
// when this agent has been run as the init process.
fn init_agent_as_init(logger: &Logger, unified_cgroup_hierarchy: bool) -> Result<()> {
    cgroups_mount(logger, unified_cgroup_hierarchy).map_err(|e| {
        error!(
            logger,
            "fail cgroups mount, unified_cgroup_hierarchy {}: {}", unified_cgroup_hierarchy, e
        );
        e
    })?;

    fs::remove_file(Path::new("/dev/ptmx"))?;
    unixfs::symlink(Path::new("/dev/pts/ptmx"), Path::new("/dev/ptmx"))?;

    unistd::setsid()?;

    unsafe {
        libc::ioctl(std::io::stdin().as_raw_fd(), libc::TIOCSCTTY, 1);
    }

    env::set_var("PATH", "/bin:/sbin/:/usr/bin/:/usr/sbin/");

    let contents =
        std::fs::read_to_string("/etc/hostname").unwrap_or_else(|_| String::from("localhost"));
    let contents_array: Vec<&str> = contents.split(' ').collect();
    let hostname = contents_array[0].trim();

    if unistd::sethostname(OsStr::new(hostname)).is_err() {
        warn!(logger, "failed to set hostname");
    }

    Ok(())
}

#[cfg(feature = "agent-policy")]
async fn initialize_policy() -> Result<()> {
    AGENT_POLICY
        .lock()
        .await
        .initialize(
            AGENT_CONFIG.log_level.as_usize(),
            AGENT_CONFIG.policy_file.clone(),
            None,
        )
        .await
}

// BL-5: resolve an SRM trust-root config from measured guest state — the **initdata**
// section, and only once FR-2 has bound it to the launch measurement. Returns None when the
// config is absent or unusable, so the caller fails closed (no authorized issuers).
//
// Single-source on purpose (RM-89). BL-5 originally specified a precedence: the initdata
// section first, else a `/etc/kata/fragment-issuers.toml` in the measured rootfs. Both
// carriers really are measured — the guest rootfs is a dm-verity device mounted read-only
// whose root hash is a kernel command line parameter in the IGVM, hence part of the launch
// measurement — so the two were never a difference in trust level, only in granularity
// (per-image vs per-deployment). What the choice between them did add was a precedence
// decision, and F-166 was precisely a bug in that decision: the higher-priority source was
// consumed without checking the property that made it trustworthy, overriding the lower one.
// Removing the second source removes that class of bug rather than fixing one instance, and
// it costs nothing in practice: nothing in the tree ever installs that file, and every e2e,
// demo and deployment path delivers the trust root through initdata. It is also the C-ACI
// shape — hcsshim has exactly one configurable path (the policy whose digest the guest checks
// against HOSTDATA via `ValidateHostData()`), and its only other source is a compiled-in
// closed-door default. Compare FR-2 GAP-3, where the analogous rootfs *policy* file was
// removed for the same reason. FR-4C's CDI allow-list keeps its rootfs file and stays
// single-source too, which is the property that matters here.
#[cfg(feature = "strict-policy")]
fn resolve_measured_config(
    logger: &Logger,
    label: &str,
    initdata_cfg: Option<&str>,
    initdata_bound: bool,
) -> Option<String> {
    let text = initdata_cfg?;
    if !initdata_bound {
        // F-166: initdata is measured state only once it is bound to the launch measurement;
        // unbound it is whatever the host handed us. A shipped strict build never reaches
        // here — `main` aborts on an unbound initdata — so this is the dev-build path, kept
        // as a defence in depth for the same reason the rule lives in the resolver at all.
        if !cfg!(feature = "allow-unattested-initdata") {
            warn!(
                logger,
                "{}: refusing the initdata trust-root config — it was not bound to a launch \
                 measurement, so it is not measured state; failing closed",
                label
            );
            return None;
        }
        warn!(
            logger,
            "{}: accepting an UNBOUND initdata trust-root config because the agent was built \
             with `allow-unattested-initdata`; the host chose this trust root and it is NOT \
             measured state. This build must never ship in a confidential image.",
            label
        );
        return Some(text.to_string());
    }
    info!(
        logger,
        "{}: trust-root config sourced from measured initdata", label
    );
    Some(text.to_string())
}

// FR-1i: runtime SVN high-water state, persisted so an agent restart cannot reopen a
// rollback window. Must live on sealed/encrypted-scratch storage (in a confidential guest
// the writable scratch is memory-/disk-encrypted).
#[cfg(feature = "strict-policy")]
const FRAGMENT_SVN_STATE_PATH: &str = "/run/kata/fragment-svn.state";

// FR-7 (F-86): the path is fixed in a shipped strict build. `KATA_FRAGMENT_SVN_STATE` only
// exists under `test-path-override`, which is deliberately not implied by `strict-policy`.
// The agent's environment is host-influenced — the kernel hands unrecognised `key=value`
// command line parameters to init as environment variables — so honouring the variable
// unconditionally would let the host name a path that is never populated. The import at boot
// is a silent no-op when the file cannot be read, so that would reset the SVN floor to zero
// on every boot and defeat exactly the rollback protection FR-1i exists to provide, leaving
// no trace. Same hazard, and same remedy, as `KATA_AGENT_TSM_ROOT` in hostdata.rs.
#[cfg(feature = "strict-policy")]
fn fragment_svn_state_path() -> String {
    #[cfg(feature = "test-path-override")]
    if let Ok(p) = std::env::var("KATA_FRAGMENT_SVN_STATE") {
        return p;
    }

    FRAGMENT_SVN_STATE_PATH.to_string()
}

// FR-1i: write the exported SVN snapshot to the persistence path (best-effort).
#[cfg(feature = "strict-policy")]
pub(crate) fn persist_fragment_svn_state(snapshot: &str) {
    let path = fragment_svn_state_path();
    if let Some(dir) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&path, snapshot);
}

#[cfg(feature = "strict-policy")]
#[derive(serde::Deserialize, Default)]
struct FragmentTrustConfig {
    #[serde(default)]
    require_receipt: Option<bool>,
    /// FR-1f: legacy single transparency anchor public key (hex); mapped to the default
    /// ledger. Prefer `[[ledger]]` for multi-ledger / rotation.
    #[serde(default)]
    transparency_anchor_hex: Option<String>,
    /// FR-1f (trust list): the Transparency Trust List — named ledgers with rotatable keys.
    #[serde(default)]
    ledger: Vec<FragmentLedgerConfig>,
    /// FR-1d: require every fragment to carry a valid did:x509 chain (no raw-key path).
    #[serde(default)]
    require_x509: Option<bool>,
    /// FR-1d: measured certificate revocation list (SHA-256 fingerprints, hex).
    #[serde(default)]
    revoked: Vec<String>,
    /// FR-1d: authorized did:x509 CA anchors.
    #[serde(default, rename = "ca_anchor")]
    ca_anchor: Vec<FragmentCaAnchorConfig>,
    /// FR-1j: enable append-only application ordering (the log-head gate). Opt-in.
    #[serde(default)]
    ordered: Option<bool>,
    /// FR-1j: the measured ordering-log genesis (hex). Defaults to a fixed constant when
    /// `ordered` is true and this is unset.
    #[serde(default)]
    log_genesis_hex: Option<String>,
    #[serde(default)]
    issuer: Vec<FragmentIssuerConfig>,
}

#[cfg(feature = "strict-policy")]
#[derive(serde::Deserialize)]
struct FragmentCaAnchorConfig {
    /// The did:x509 issuer id this anchor authorizes (must equal a fragment's issuer).
    did: String,
    /// SHA-256 fingerprint (hex) of the trusted CA certificate DER. One of this or
    /// `ca_cert_pem` must be set.
    #[serde(default)]
    ca_fingerprint_hex: Option<String>,
    /// PEM of the trusted CA certificate (its fingerprint is derived). Alternative to
    /// `ca_fingerprint_hex`.
    #[serde(default)]
    ca_cert_pem: Option<String>,
    /// did:x509 policy over the leaf: required subject Common Name.
    #[serde(default)]
    require_subject_cn: Option<String>,
    /// did:x509 policy: required leaf Extended Key Usage OIDs (dotted).
    #[serde(default)]
    require_eku: Vec<String>,
    /// did:x509 policy: required leaf DNS SubjectAltName entries.
    #[serde(default)]
    require_san_dns: Vec<String>,
}

#[cfg(feature = "strict-policy")]
#[derive(serde::Deserialize)]
struct FragmentLedgerConfig {
    id: String,
    /// One or more current Ed25519 verification keys for this ledger (multiple ⇒ rotation).
    #[serde(default)]
    pubkey_hex: Vec<String>,
    /// BL-2: additional non-Ed25519 keys (ES256/ES384/PS256/RS256), each a SubjectPublicKeyInfo
    /// DER in hex plus its COSE algorithm name.
    #[serde(default)]
    key: Vec<FragmentLedgerKeyConfig>,
    /// FR-1f (trust list): Trust List subject(s) that vouched for this ledger's keys.
    ///
    /// Recording provenance is what lets a scope require `TTL:<subject>` — "a receipt
    /// validated by a key subject S vouched for" — rather than only naming the ledger,
    /// which is self-asserted metadata on the receipt. Absent here, `TTL:` requirements
    /// against this ledger are unmet, which is the fail-closed reading.
    #[serde(default)]
    ttl_subjects: Vec<String>,
}

#[cfg(feature = "strict-policy")]
#[derive(serde::Deserialize)]
struct FragmentLedgerKeyConfig {
    /// COSE algorithm: "eddsa" | "es256" | "es384" | "ps256" | "rs256".
    alg: String,
    /// SubjectPublicKeyInfo DER (hex) for the ledger key.
    spki_hex: String,
}

#[cfg(feature = "strict-policy")]
#[derive(serde::Deserialize)]
struct FragmentIssuerConfig {
    id: String,
    ed25519_pubkey_hex: String,
    #[serde(default)]
    min_svn: u64,
    /// FR-1f (trust list): ledgers a receipt for this issuer's default feed must come from
    /// (policy-driven required_receipts). Non-empty ⇒ a receipt is mandatory.
    #[serde(default)]
    required_receipt_from: Vec<String>,
    /// FR-1f (trust list): ledgers allowed to back receipts for this issuer's default feed.
    #[serde(default)]
    allowed_ledgers: Vec<String>,
    /// FR-1e: named feeds this issuer may publish, with their SVN floor.
    #[serde(default)]
    feed: Vec<FragmentFeedConfig>,
}

#[cfg(feature = "strict-policy")]
#[derive(serde::Deserialize)]
struct FragmentFeedConfig {
    name: String,
    #[serde(default)]
    min_svn: u64,
    /// FR-1f (trust list): ledgers a receipt for this feed must come from.
    #[serde(default)]
    required_receipt_from: Vec<String>,
    /// FR-1f (trust list): ledgers allowed to back receipts for this feed.
    #[serde(default)]
    allowed_ledgers: Vec<String>,
    /// FR-1c: policy namespaces under `agent_policy.fragments.` a fragment on this feed may
    /// contribute a module to. Empty grants only the shared `agent_policy.fragments`
    /// package. The fragment's own `includes` cannot widen this.
    #[serde(default)]
    includes: Vec<String>,
    /// FR-1c: whether a fragment on this feed may apply its Rego module at all. False
    /// accepts the fragment for its SVN/receipt/ordering record but contributes no rules.
    #[serde(default = "default_true_cfg")]
    allow_module: bool,
    /// FR-1k: values to instantiate a parameterised fragment on this feed with, as a TOML
    /// table. The fragment reads them via `parameter("name")`; a name it does not supply
    /// falls back to the fragment's own declared default.
    #[serde(default)]
    parameters: Option<toml::Value>,
}

#[cfg(feature = "strict-policy")]
fn default_true_cfg() -> bool {
    true
}

#[cfg(feature = "strict-policy")]
fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        anyhow::bail!("ed25519 pubkey must be 64 hex chars, got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in pubkey: {e}"))?;
    }
    Ok(out)
}

// FR-1j: decode an arbitrary-length hex string (e.g. the ordering-log genesis).
#[cfg(feature = "strict-policy")]
fn decode_hex_vec(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length: {}", s.len());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("invalid hex: {e}"))
        })
        .collect()
}

// FR-1b: configure the global fragment store from measured state. Absent/empty config
// leaves the store with no authorized issuers (fail-closed).
#[cfg(feature = "strict-policy")]
async fn seed_fragment_trust_root(
    logger: &Logger,
    initdata_cfg: Option<&str>,
    initdata_bound: bool,
) -> Result<()> {
    let text = match resolve_measured_config(logger, "FR-1", initdata_cfg, initdata_bound) {
        Some(t) => t,
        None => {
            info!(
                logger,
                "FR-1: no fragment-issuer config; fragments fail-closed"
            );
            return Ok(());
        }
    };
    let cfg: FragmentTrustConfig = toml::from_str(&text).context("parse fragment-issuers.toml")?;

    let mut store = FRAGMENTS.lock().await;
    if let Some(rr) = cfg.require_receipt {
        // Rebuild with the configured receipt requirement, preserving fail-closed default.
        *store = kata_security_reference_monitor::FragmentStore::new(rr);
    }
    // FR-1f: configure the transparency anchor (receipts cryptographically verified).
    if let Some(anchor_hex) = &cfg.transparency_anchor_hex {
        let key = decode_hex32(anchor_hex).context("transparency anchor key")?;
        store
            .set_transparency_anchor(&key)
            .map_err(|e| anyhow::anyhow!("set transparency anchor: {}", e))?;
        info!(
            logger,
            "FR-1: transparency anchor configured (default ledger)"
        );
    }
    // FR-1f (trust list): load named ledgers with rotatable keys.
    if !cfg.ledger.is_empty() {
        for l in &cfg.ledger {
            let mut keys = Vec::with_capacity(l.pubkey_hex.len());
            for k in &l.pubkey_hex {
                keys.push(decode_hex32(k).with_context(|| format!("ledger {} key", l.id))?);
            }
            store
                .load_trust_list_with_subjects(l.id.clone(), &keys, &l.ttl_subjects)
                .map_err(|e| anyhow::anyhow!("load transparency trust list: {}", e))?;
        }
        // BL-2: additional non-Ed25519 ledger keys (ES256/ES384/PS256/RS256).
        for l in &cfg.ledger {
            for k in &l.key {
                let alg = match k.alg.trim().to_ascii_lowercase().as_str() {
                    "eddsa" | "ed25519" => {
                        kata_security_reference_monitor::cose_keys::CoseAlg::EdDsa
                    }
                    "es256" => kata_security_reference_monitor::cose_keys::CoseAlg::Es256,
                    "es384" => kata_security_reference_monitor::cose_keys::CoseAlg::Es384,
                    "ps256" => kata_security_reference_monitor::cose_keys::CoseAlg::Ps256,
                    "rs256" => kata_security_reference_monitor::cose_keys::CoseAlg::Rs256,
                    other => anyhow::bail!("ledger {} unsupported key alg {}", l.id, other),
                };
                let der = decode_hex_vec(&k.spki_hex)
                    .with_context(|| format!("ledger {} spki_hex", l.id))?;
                let pk = kata_security_reference_monitor::cose_keys::PublicKey::from_spki_der(&der)
                    .ok_or_else(|| anyhow::anyhow!("ledger {} invalid SPKI key", l.id))?;
                store.add_ledger_key_from_ttl(l.id.clone(), pk, alg, &l.ttl_subjects);
            }
        }
        info!(logger, "FR-1: transparency trust list loaded"; "ledgers" => cfg.ledger.len());
    }
    // FR-1d: did:x509 issuer identity — require_x509, revocation list, CA anchors.
    if let Some(rx) = cfg.require_x509 {
        store.set_require_x509(rx);
    }
    if !cfg.revoked.is_empty() {
        let mut fps = Vec::with_capacity(cfg.revoked.len());
        for hexfp in &cfg.revoked {
            fps.push(decode_hex32(hexfp).context("revoked cert fingerprint")?);
        }
        store.set_revoked_certs(fps);
        info!(logger, "FR-1: revocation list loaded"; "revoked" => cfg.revoked.len());
    }
    for ca in &cfg.ca_anchor {
        let ca_fingerprint = if let Some(hexfp) = &ca.ca_fingerprint_hex {
            decode_hex32(hexfp).with_context(|| format!("ca_anchor {} fingerprint", ca.did))?
        } else if let Some(pem) = &ca.ca_cert_pem {
            kata_security_reference_monitor::did_x509::ca_fingerprint_from_pem(pem)
                .map_err(|e| anyhow::anyhow!("ca_anchor {} pem: {}", ca.did, e))?
        } else {
            anyhow::bail!(
                "ca_anchor {} needs ca_fingerprint_hex or ca_cert_pem",
                ca.did
            );
        };
        store
            .authorize_did_x509(kata_security_reference_monitor::DidX509Anchor {
                did: ca.did.clone(),
                ca_fingerprint,
                policy: kata_security_reference_monitor::DidX509Policy {
                    require_subject_cn: ca.require_subject_cn.clone(),
                    require_eku: ca.require_eku.clone(),
                    require_san_dns: ca.require_san_dns.clone(),
                },
            })
            .map_err(|e| anyhow::anyhow!("ca_anchor {}: {}", ca.did, e))?;
        info!(logger, "FR-1: authorized did:x509 anchor"; "did" => &ca.did);
    }
    for issuer in &cfg.issuer {
        let key = decode_hex32(&issuer.ed25519_pubkey_hex)
            .with_context(|| format!("issuer {}", issuer.id))?;
        store
            .authorize_issuer(issuer.id.clone(), &key)
            .map_err(|e| anyhow::anyhow!("authorize issuer {}: {}", issuer.id, e))?;
        store.set_min_svn(issuer.id.clone(), issuer.min_svn);
        // FR-1f (trust list): default-feed receipt scoping for this issuer.
        if !issuer.allowed_ledgers.is_empty() {
            store.set_allowed_ledgers(issuer.id.clone(), "", &issuer.allowed_ledgers);
        }
        if !issuer.required_receipt_from.is_empty() {
            store.require_receipt_for(issuer.id.clone(), "", &issuer.required_receipt_from);
        }
        // FR-1e: declare named feeds for this issuer.
        for feed in &issuer.feed {
            store.declare_feed(issuer.id.clone(), feed.name.clone(), feed.min_svn);
            // FR-1f (trust list): per-feed receipt scoping.
            if !feed.allowed_ledgers.is_empty() {
                store.set_allowed_ledgers(
                    issuer.id.clone(),
                    feed.name.clone(),
                    &feed.allowed_ledgers,
                );
            }
            if !feed.required_receipt_from.is_empty() {
                store.require_receipt_for(
                    issuer.id.clone(),
                    feed.name.clone(),
                    &feed.required_receipt_from,
                );
            }
            // FR-1c: the trust root is measured state, so it is a valid authority for the
            // namespace grant on feeds the base policy does not separately declare.
            // FR-1k: same for parameter bindings.
            if !feed.includes.is_empty() || !feed.allow_module || feed.parameters.is_some() {
                // Re-serialized to JSON because the policy engine takes a JSON object; the
                // TOML table is only the authoring surface.
                let parameters = match &feed.parameters {
                    Some(p) => Some(serde_json::to_string(p).with_context(|| {
                        format!("issuer {} feed {} parameters", issuer.id, feed.name)
                    })?),
                    None => None,
                };
                store.grant_module_scope(
                    issuer.id.clone(),
                    feed.name.clone(),
                    &feed.includes,
                    feed.allow_module,
                    parameters,
                );
            }
        }
        info!(logger, "FR-1: authorized fragment issuer";
            "issuer" => &issuer.id, "min-svn" => issuer.min_svn, "feeds" => issuer.feed.len());
    }

    // FR-1j: enable append-only application ordering (before importing persisted state so
    // the restored head is not overwritten by the genesis).
    if cfg.ordered.unwrap_or(false) {
        let genesis = if let Some(hex) = &cfg.log_genesis_hex {
            decode_hex_vec(hex).context("log_genesis_hex")?
        } else {
            b"kata-fragment-log/v1".to_vec()
        };
        store.set_log_genesis(&genesis);
        info!(
            logger,
            "FR-1: append-only fragment ordering enabled (FR-1j)"
        );
    }

    // FR-1i: re-import any persisted SVN high-water marks so a restart keeps rollback
    // protection (import can only raise the floor, never lower it). FR-1j: this also
    // restores the ordering log head (raise-only) across restart.
    if let Ok(snapshot) = std::fs::read_to_string(fragment_svn_state_path()) {
        store.import_svn_state(&snapshot);
        info!(logger, "FR-1: imported persisted fragment SVN state");
    }

    // F-147: `require_receipt` and the ledger trust list are independent options, so a
    // config can demand receipts while loading no key able to validate one. That is now
    // fail-closed (every fragment is refused), but silently refusing everything is a poor
    // way to learn about a typo, and before the gate was fixed this same combination
    // silently accepted *any* receipt. Say so plainly at startup.
    if store.receipt_gate_is_unsatisfiable() {
        warn!(
            logger,
            "FR-1: transparency receipts are required but no ledger key is configured; \
             every fragment will be refused (add a [[ledger]] entry or transparency_anchor_hex)"
        );
    }
    Ok(())
}

// The Rust standard library had suppressed the default SIGPIPE behavior,
// see https://github.com/rust-lang/rust/pull/13158.
// Since the parent's signal handler would be inherited by it's child process,
// thus we should re-enable the standard SIGPIPE behavior as a workaround to
// fix the issue of https://github.com/kata-containers/kata-containers/issues/1887.
fn reset_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

use crate::config::AgentConfig;
use std::os::unix::io::RawFd;

#[cfg(feature = "agent-policy")]
use kata_agent_policy::policy::AgentPolicy;

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::TestUserType;
    use test_utils::{assert_result, skip_if_not_root, skip_if_root};

    // FR-7 (F-86): the path backing fragment SVN rollback protection must not be relocatable
    // by the host. It is read only in strict builds, so the environment override that used to
    // serve tests was reachable exactly where it must not be: the kernel hands unrecognised
    // `key=value` command line parameters to init as environment variables, and in a
    // confidential guest the command line is the host's. Redirecting the SVN state path is
    // silent and total -- the boot-time import is a no-op when the file cannot be read, so the
    // floor restarts at zero every boot -- which is why this is asserted rather than left to
    // review.
    //
    // The fragment issuer trust root used to be asserted here too, against
    // `KATA_FRAGMENT_ISSUERS`. RM-89 removed its file source outright, so there is no longer a
    // path for the host to redirect; the property is now structural rather than tested.
    //
    // Compiled out under `test-path-override`, which is what re-enables the redirection.
    #[cfg(all(feature = "strict-policy", not(feature = "test-path-override")))]
    #[test]
    fn measured_state_paths_are_not_relocatable_by_the_environment() {
        std::env::set_var("KATA_FRAGMENT_SVN_STATE", "/tmp/attacker-svn.state");
        let path = super::fragment_svn_state_path();
        std::env::remove_var("KATA_FRAGMENT_SVN_STATE");
        assert_eq!(
            path,
            super::FRAGMENT_SVN_STATE_PATH,
            "the host relocated the fragment SVN high-water file, resetting the rollback floor"
        );
    }

    // F-166: the initdata section is measured state only once FR-2 has bound it to the launch
    // measurement. Unbound, it is host-chosen -- and the failure mode is silent, because an
    // unbound initdata looks exactly like a bound one to this function. F-6 makes the unbound
    // case reachable on a genuinely confidential VM (Azure paravisor SNP), so this is asserted
    // rather than left to review.
    //
    // RM-89: with the rootfs source gone, "refused" now means fail-closed rather than "falls
    // back to the file", so the assertion is that no trust root is produced at all.
    #[cfg(all(feature = "strict-policy", not(feature = "allow-unattested-initdata")))]
    #[test]
    fn an_unbound_initdata_trust_root_is_refused_in_favour_of_measured_state() {
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        let host_supplied = "require_receipt = false\n";

        // Bound: the initdata section is measured state, so it is the trust root.
        let bound = super::resolve_measured_config(&logger, "FR-1", Some(host_supplied), true);
        assert_eq!(
            bound.as_deref(),
            Some(host_supplied),
            "a bound initdata trust root must be used"
        );

        // Unbound: it is not measured state, so it must not become the trust root. Fragments
        // then fail closed, which is the correct answer -- there is nothing else to trust.
        let unbound = super::resolve_measured_config(&logger, "FR-1", Some(host_supplied), false);
        assert!(
            unbound.is_none(),
            "an unbound, host-chosen initdata section was used as the FR-1 trust root"
        );

        // No initdata at all is likewise closed: RM-89 removed the rootfs alternative, so
        // absent config means no authorized issuers rather than a second source to consult.
        let absent = super::resolve_measured_config(&logger, "FR-1", None, true);
        assert!(absent.is_none(), "a trust root appeared from nowhere");
    }

    // FR-7 (F-79) leaves a strict build with no host-visible log stream, so the `error!`
    // preceding each fatal startup abort is swallowed and the VM just powers off. The
    // console line below is the only thing that survives that, so pin its shape: a stable,
    // greppable prefix, and nothing in it but the fixed reason handed in at the call site.
    #[cfg(any(feature = "agent-policy", feature = "strict-policy"))]
    #[test]
    fn test_fatal_reason_line() {
        let line = fatal_reason_line("initdata does not match the launch measurement (FR-2)");
        assert_eq!(
            line,
            "kata-agent: fatal: initdata does not match the launch measurement (FR-2); \
             aborting VM\n"
        );
        assert!(
            line.starts_with("kata-agent: fatal: "),
            "the prefix is what an operator greps a guest console for"
        );
        assert!(
            line.ends_with('\n'),
            "an unterminated line can be lost in console output interleaving"
        );
    }

    #[tokio::test]
    async fn test_create_logger_task() {
        #[derive(Debug)]
        struct TestData {
            vsock_port: u32,
            test_user: TestUserType,
            result: Result<()>,
        }

        // FR-7 (F-79): a strict build discards the agent log stream and never binds a vsock
        // listener, so the privileged-port case cannot fail on EACCES any more -- the port is
        // not used at all. That difference is itself the assertion: if a future change
        // reinstated the listener, this case would start returning EACCES again.
        #[cfg(feature = "strict-policy")]
        let privileged_port_result: Result<()> = Ok(());
        #[cfg(not(feature = "strict-policy"))]
        let privileged_port_result: Result<()> =
            Err(anyhow!(nix::errno::Errno::from_raw(libc::EACCES)));

        let tests = &[
            TestData {
                // non-root user cannot use privileged vsock port
                vsock_port: 1,
                test_user: TestUserType::NonRootOnly,
                result: privileged_port_result,
            },
            TestData {
                // passing vsock_port 0 causes logger task to write to stdout
                vsock_port: 0,
                test_user: TestUserType::Any,
                result: Ok(()),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            if d.test_user == TestUserType::RootOnly {
                skip_if_not_root!();
            } else if d.test_user == TestUserType::NonRootOnly {
                skip_if_root!();
            }

            let msg = format!("test[{i}]: {d:?}");
            let (rfd, wfd) = unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
            let rfd_raw = rfd.as_raw_fd();
            let wfd_raw = wfd.as_raw_fd();
            // Prevent OwnedFd from closing the fds when dropped
            std::mem::forget(rfd);
            std::mem::forget(wfd);
            defer!({
                // XXX: Never try to close rfd, because it will be closed by PipeStream in
                // create_logger_task() and it's not safe to close the same fd twice time.
                unistd::close(wfd_raw).unwrap();
            });

            let (shutdown_tx, shutdown_rx) = channel(true);

            shutdown_tx.send(true).unwrap();
            let result = create_logger_task(rfd_raw, d.vsock_port, shutdown_rx).await;

            let msg = format!("{msg}, result: {result:?}");
            assert_result!(d.result, result, msg);
        }
    }
}
