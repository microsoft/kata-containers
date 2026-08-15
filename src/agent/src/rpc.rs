// Copyright (c) 2019 Ant Financial
//
// SPDX-License-Identifier: Apache-2.0
//

use async_trait::async_trait;
#[cfg(feature = "agent-policy")]
use kata_agent_policy::policy::{
    PolicyCopySingleFileRequest, PolicyPutVolumeFileRevisionRequest,
};
// The generic CopyFile gate exists only in non-strict builds; strict builds refuse the RPC
// before any policy round trip.
#[cfg(all(feature = "agent-policy", not(feature = "strict-policy")))]
use kata_agent_policy::policy::PolicyCopyFileRequest;
use rustjail::{pipestream::PipeStream, process::StreamType};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

use std::collections::HashMap;
use std::convert::TryFrom;
#[cfg(all(feature = "agent-policy", not(feature = "strict-policy")))]
use std::convert::TryInto as _;
use std::ffi::{CString, OsStr};
use std::fmt::Debug;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Component;
use std::path::Path;
#[cfg(target_arch = "s390x")]
use std::str::FromStr;
use std::sync::Arc;
use ttrpc::{
    self,
    error::get_rpc_status,
    r#async::{Server as TtrpcServer, TtrpcContext},
};

use anyhow::{anyhow, Context, Result};
use cgroups::freezer::FreezerState;
use oci::{Hooks, LinuxNamespace, Spec};
use oci_spec::runtime as oci;
use pathrs::flags::OpenFlags;
#[cfg(feature = "agent-policy")]
use protobuf::MessageDyn;
use protobuf::MessageField;
use protocols::agent::{
    AddSwapPathRequest, AddSwapRequest, AgentDetails, CommitVolumeRevisionRequest, CopyFileRequest,
    CopySingleFileRequest, GetIPTablesRequest, GetIPTablesResponse, GuestDetailsResponse,
    InitVolumeRequest, InitVolumeResponse, Interfaces, Metrics, OOMEvent,
    PutVolumeFileRevisionRequest, ReadStreamResponse, ResizeVolumeRequest, Routes, SetIPTablesRequest,
    SetIPTablesResponse, SingleFileType, StatsContainerResponse, VolumeStatsRequest,
    WaitProcessResponse, WriteStreamResponse,
};
use protocols::csi::{
    volume_usage::Unit as VolumeUsage_Unit, VolumeCondition, VolumeStatsResponse, VolumeUsage,
};
use protocols::empty::Empty;
use protocols::health::{
    health_check_response::ServingStatus as HealthCheckResponse_ServingStatus, HealthCheckResponse,
    VersionCheckResponse,
};
use protocols::types::Interface;
use protocols::{agent_ttrpc_async as agent_ttrpc, health_ttrpc_async as health_ttrpc};
use rustjail::cgroups::notifier;
use rustjail::container::{BaseContainer, Container, LinuxContainer, SYSTEMD_CGROUP_PATH_FORMAT};
use rustjail::mount::parse_mount_table;
use rustjail::process::Process;
use rustjail::specconv::CreateOpts;

use nix::errno::Errno;
use nix::mount::MsFlags;
use nix::sys::{stat, statfs};
use nix::unistd::{self, Pid};
use rustjail::process::ProcessOperations;
#[cfg(all(test, not(target_arch = "powerpc64")))]
use std::os::fd::AsRawFd;

#[cfg(target_arch = "s390x")]
use crate::ccw;
use crate::confidential_data_hub::image::KATA_IMAGE_WORK_DIR;
use crate::device::block_device_handler::get_virtio_blk_pci_device_name;
#[cfg(target_arch = "s390x")]
use crate::device::network_device_handler::wait_for_ccw_net_interface;
#[cfg(not(target_arch = "s390x"))]
use crate::device::network_device_handler::wait_for_pci_net_interface;
use crate::device::{
    add_devices, cdi_devices_from_visible_devices, dump_nvidia_cdi_yaml, handle_cdi_devices,
    update_env_pci,
};
use crate::features::get_build_features;
use crate::metrics::get_metrics;
use crate::mount::baremount;
use crate::namespace::{NSTYPEIPC, NSTYPEPID, NSTYPEUTS};
use crate::network::setup_guest_dns;
use crate::passfd_io;
use crate::pci;
use crate::random;
use crate::sandbox::{Sandbox, SandboxError};
use crate::storage::{add_storages, update_ephemeral_mounts, STORAGE_HANDLERS};
use crate::util;
use crate::version::{AGENT_VERSION, API_VERSION};
use crate::AGENT_CONFIG;
use crate::{confidential_data_hub, linux_abi::*};

use crate::trace_rpc_call;
use crate::tracer::extract_carrier_from_ttrpc;

#[cfg(all(feature = "agent-policy", not(feature = "strict-policy")))]
use crate::policy::do_set_policy;
#[cfg(feature = "agent-policy")]
use crate::policy::is_allowed;
#[cfg(feature = "agent-policy")]
use crate::policy::is_allowed_with_entrypoint;

use opentelemetry::global;
use tracing::span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use tracing::instrument;

use libc::{self, c_char, c_ushort, pid_t, winsize, TIOCSWINSZ};
use std::fs;
use std::os::unix::prelude::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::SystemTime;

use lazy_static::lazy_static;
use nix::unistd::{Gid, Uid};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;

#[cfg(feature = "devicemapper")]
use kata_types::dmverity::cleanup_dmverity_devices;
use kata_types::k8s;

pub const CONTAINER_BASE: &str = "/run/kata-containers";
const MODPROBE_PATH: &str = "/sbin/modprobe";
const TRUSTED_IMAGE_STORAGE_DEVICE: &str = "/dev/trusted_store";
/// the iptables seriers binaries could appear either in /sbin
/// or /usr/sbin, we need to check both of them
const USR_IPTABLES_SAVE: &str = "/usr/sbin/iptables-save";
const IPTABLES_SAVE: &str = "/sbin/iptables-save";
const USR_IPTABLES_RESTORE: &str = "/usr/sbin/iptables-store";
const IPTABLES_RESTORE: &str = "/sbin/iptables-restore";
const USR_IP6TABLES_SAVE: &str = "/usr/sbin/ip6tables-save";
const IP6TABLES_SAVE: &str = "/sbin/ip6tables-save";
const USR_IP6TABLES_RESTORE: &str = "/usr/sbin/ip6tables-save";
const IP6TABLES_RESTORE: &str = "/sbin/ip6tables-restore";
const KATA_GUEST_SHARE_DIR: &str = "/run/kata-containers/shared/containers/";
const KATA_GUEST_VOLUMES_DIR: &str = "/run/kata-containers/shared/containers/volumes";

/// This mask is applied to parent directories implicitly created for CopyFile requests.
const IMPLICIT_DIRECTORY_PERMISSION_MASK: u32 = 0o777;

/// This mask is applied to files and directories created for CopyFile requests.
/// In addition to the permissions, it allows setuid/setgid/sticky bits.
/// Note that the setuid bit does not have an effect on Linux, though.
const FILE_PERMISSION_MASK: u32 = 0o7777;

const ERR_CANNOT_GET_WRITER: &str = "Cannot get writer";
const ERR_INVALID_BLOCK_SIZE: &str = "Invalid block size";
const ERR_NO_LINUX_FIELD: &str = "Spec does not contain linux field";
const ERR_NO_SANDBOX_PIDNS: &str = "Sandbox does not have sandbox_pidns";

// IPTABLES_RESTORE_WAIT_SEC is the timeout value provided to iptables-restore --wait. Since we
// don't expect other writers to iptables, we don't expect contention for grabbing the iptables
// filesystem lock. Based on this, 5 seconds seems a resonable timeout period in case the lock is
// not available.
const IPTABLES_RESTORE_WAIT_SEC: u64 = 5;

#[derive(Clone, Debug, Default)]
struct VolumeState {
    current_revision: Option<String>,
    pending_revision: Option<String>,
}

lazy_static! {
    static ref VOLUMES: StdMutex<HashMap<String, VolumeState>> =
        StdMutex::new(HashMap::new());
}

#[cfg(test)]
lazy_static! {
    static ref TEST_GUEST_SHARE_DIR: StdMutex<Option<PathBuf>> = StdMutex::new(None);
    static ref TEST_VOLUMES_DIR: StdMutex<Option<PathBuf>> = StdMutex::new(None);
}

// Convenience function to obtain the scope logger.
fn sl() -> slog::Logger {
    slog_scope::logger()
}

// Convenience function to wrap an error and response to ttrpc client
pub fn ttrpc_error(code: ttrpc::Code, err: impl Debug) -> ttrpc::Error {
    get_rpc_status(code, format!("{err:?}"))
}

/// Convert SandboxError to ttrpc error with appropriate code.
/// Process not found errors map to NOT_FOUND, others to INVALID_ARGUMENT.
fn sandbox_err_to_ttrpc(err: SandboxError) -> ttrpc::Error {
    let code = match &err {
        SandboxError::InitProcessNotFound | SandboxError::InvalidExecId => ttrpc::Code::NOT_FOUND,
        SandboxError::InvalidContainerId => ttrpc::Code::INVALID_ARGUMENT,
    };
    ttrpc_error(code, err)
}

#[cfg(not(feature = "agent-policy"))]
async fn is_allowed(_req: &impl serde::Serialize) -> ttrpc::Result<()> {
    Ok(())
}

fn same<E>(e: E) -> E {
    e
}

/// FR-14: authorize a network-mutating RPC against the network phase (strict builds). The
/// network surface is frozen once a workload container starts, so post-start network
/// mutation is refused with FAILED_PRECONDITION.
#[cfg(feature = "strict-policy")]
async fn net_phase_authorize(op: kata_security_reference_monitor::NetOp) -> ttrpc::Result<()> {
    crate::NET_PHASE
        .lock()
        .await
        .authorize(op)
        .map_err(|e| ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e))
}

trait ResultToTtrpcResult<T, E: Debug>: Sized {
    fn map_ttrpc_err<R: Debug>(self, msg_builder: impl FnOnce(E) -> R) -> ttrpc::Result<T>;
    fn map_ttrpc_err_do(self, doer: impl FnOnce(&E)) -> ttrpc::Result<T> {
        self.map_ttrpc_err(|e| {
            doer(&e);
            e
        })
    }
}

impl<T, E: Debug> ResultToTtrpcResult<T, E> for Result<T, E> {
    fn map_ttrpc_err<R: Debug>(self, msg_builder: impl FnOnce(E) -> R) -> ttrpc::Result<T> {
        self.map_err(|e| ttrpc_error(ttrpc::Code::INTERNAL, msg_builder(e)))
    }
}

trait OptionToTtrpcResult<T>: Sized {
    fn map_ttrpc_err(self, code: ttrpc::Code, msg: &str) -> ttrpc::Result<T>;
}

impl<T> OptionToTtrpcResult<T> for Option<T> {
    fn map_ttrpc_err(self, code: ttrpc::Code, msg: &str) -> ttrpc::Result<T> {
        self.ok_or_else(|| ttrpc_error(code, msg))
    }
}

#[derive(Clone, Debug)]
pub struct AgentService {
    sandbox: Arc<Mutex<Sandbox>>,
    init_mode: bool,
    oma: Option<mem_agent::agent::MemAgent>,
}

impl AgentService {
    /// Construct a service instance for tests. Used by the FR-7 mediation conformance
    /// sweep in `mediation.rs`, which lives in another module and so cannot reach the
    /// private fields directly.
    #[cfg(test)]
    pub(crate) fn new_for_test(sandbox: Arc<Mutex<Sandbox>>) -> Self {
        Self {
            sandbox,
            init_mode: true,
            oma: None,
        }
    }

    #[instrument]
    async fn do_create_container(
        &self,
        req: protocols::agent::CreateContainerRequest,
        #[cfg_attr(not(feature = "strict-policy"), allow(unused_variables))] srm_txn_id: Option<
            &str,
        >,
    ) -> Result<()> {
        // create the proc_io first, in case there's some error occur below, thus we can make sure
        // the io stream closed when error occur.
        let proc_io = if AGENT_CONFIG.passfd_listener_port != 0 {
            Some(passfd_io::take_io_streams(req.stdin_port, req.stdout_port, req.stderr_port).await)
        } else {
            None
        };

        let cid = req.container_id.clone();

        kata_sys_util::validate::verify_id(&cid)?;

        // F-78: `verify_id` above is an upstream sanity check -- it accepts any Unicode
        // alphanumeric string of length > 1, with no bound on length. Strict builds hold
        // the host to the shape a CRI runtime actually produces (64 lowercase hex),
        // matching hcsshim's `checkValidContainerID` under a confidential policy.
        #[cfg(feature = "strict-policy")]
        kata_security_reference_monitor::validate_container_id(&cid)
            .map_err(|e| anyhow!("refusing CreateContainer: {}", e))?;

        let use_sandbox_pidns = req.sandbox_pidns();

        let mut oci = match req.OCI.into_option() {
            Some(spec) => spec.into(),
            None => {
                error!(sl(), "no oci spec in the create container request!");
                return Err(anyhow!(nix::Error::EINVAL));
            }
        };

        let container_name = k8s::container_name(&oci);

        // FR-3 (canonical object): digest the authorized OCI spec BEFORE any in-guest
        // transformer runs, so we can compare it to the executed spec after resolution.
        #[cfg(feature = "strict-policy")]
        let authorized_oci_digest = plan_digest(&oci);
        // Retain the authorized object itself, not just its digest: a digest can only
        // report *that* the plan changed, and FR-3 needs to decide whether the specific
        // change was one the resolution chain is permitted to make.
        #[cfg(feature = "strict-policy")]
        let authorized_oci = oci.clone();

        info!(sl(), "receive createcontainer, spec: {:?}", &oci);
        info!(
            sl(),
            "receive createcontainer, storages: {:?}", &req.storages
        );

        // Some devices need some extra processing (the ones invoked with
        // --device for instance), and that's what this call is doing. It
        // updates the devices listed in the OCI spec, so that they actually
        // match real devices inside the VM. This step is necessary since we
        // cannot predict everything from the caller.
        add_devices(&cid, &sl(), &req.devices, &mut oci, &self.sandbox).await?;

        // In guest-kernel mode some devices need extra handling. Taking the
        // GPU as an example the shim will inject CDI annotations that will
        // be used by the kata-agent to do containerEdits according to the
        // CDI spec coming from a registry that is created on the fly by UDEV
        // or other entities for a specifc device.
        // In Kata we only consider the directory "/var/run/cdi", "/etc" may be
        // readonly
        dump_nvidia_cdi_yaml(&sl())?;
        // When enabled, translate the container's VISIBLE_CDI_DEVICES
        // environment variable into CDI GPU device requests, so that a
        // container can select which of the VM's GPUs it sees at runtime.
        let visible_cdi_devices = if AGENT_CONFIG.visible_cdi_devices {
            cdi_devices_from_visible_devices(&oci)?
        } else {
            Vec::new()
        };
        handle_cdi_devices(
            &sl(),
            &mut oci,
            "/var/run/cdi",
            AGENT_CONFIG.cdi_timeout,
            &visible_cdi_devices,
        )
        .await?;

        // FR-11 (trusted CDI): the CDI edits applied above come from spec files in the
        // guest that may be host-influenced. In strict builds, require every CDI spec that
        // *provides* a requested device to be measured (its content digest authorized);
        // otherwise refuse the create rather than apply host-arbitrary device edits.
        // Resolution is closed-door by default. The verified devices are bound to the
        // occurrence once the container is created.
        //
        // This deliberately runs *after* `handle_cdi_devices`, which waits (up to
        // `cdi_timeout`) for the spec files to appear: authorizing first would refuse a
        // legitimate device whose spec has not been written yet. The edits are therefore
        // already in `oci` by this point, which is safe only because the refusal is fatal
        // -- the `?` below fails the create before `setup_bundle` writes anything and
        // before the container is started, so nothing observes the unauthorized spec.
        // `the_cdi_edits_are_authorized_before_anything_acts_on_them` pins that ordering.
        #[cfg(feature = "strict-policy")]
        let verified_cdi_devices =
            crate::device::authorize_cdi_resolution(&oci, "/var/run/cdi", &visible_cdi_devices)?;

        // Handle trusted storage configuration before mounting any storage
        cdh_handler_trusted_storage(&mut oci)
            .await
            .map_err(|e| anyhow!("failed to handle trusted storage: {}", e))?;

        // Both rootfs and volumes (invoked with --volume for instance) will
        // be processed the same way. The idea is to always mount any provided
        // storage to the specified MountPoint, so that it will match what's
        // inside oci.Mounts.
        // After all those storages have been processed, no matter the order
        // here, the agent will rely on rustjail (using the oci.Mounts
        // list) to bind mount all of them inside the container.
        let m = add_storages(
            sl(),
            req.storages.clone(),
            &self.sandbox,
            Some(req.container_id),
        )
        .await?;

        // Handle sealed secrets after storage is mounted
        cdh_handler_sealed_secrets(&mut oci)
            .await
            .map_err(|e| anyhow!("failed to handle sealed secrets: {}", e))?;

        translate_bind_safer_path_mounts(&mut oci)?;

        let mut s = self.sandbox.lock().await;
        s.container_mounts.insert(cid.clone(), m);

        update_container_namespaces(&s, &mut oci, use_sandbox_pidns)?;

        // Append guest hooks
        append_guest_hooks(&s, &mut oci)?;

        // write spec to bundle path, hooks might
        // read ocispec
        let olddir = setup_bundle(&cid, &mut oci)?;
        // restore the cwd for kata-agent process. Registered immediately, so that an
        // early return from the checks below cannot leave the agent process parked in
        // the container bundle directory.
        defer!(unistd::chdir(&olddir).unwrap());

        // FR-3 (canonical object): the OCI spec is now fully resolved (devices, CDI,
        // storage, sealed secrets, namespaces, guest hooks). Bind the digest of this
        // executed object to the create transaction and compare it to the digest of the
        // authorized spec captured before transformation. Divergence is expected (trusted
        // in-guest transforms) but is not unlimited: it is checked against the bounds the
        // resolution chain is allowed to move within, so that "the plan the policy
        // authorized" and "the plan the runtime executes" remain the same plan.
        //
        // The binding is only meaningful against the transaction the caller actually
        // prepared, so the caller passes its operation id down rather than this code
        // re-deriving one: an id that does not match is a silent loss of the FR-3
        // guarantee, which is why a failure here fails the create.
        #[cfg(feature = "strict-policy")]
        if let Some(op_id) = srm_txn_id {
            let executed_oci_digest = plan_digest(&oci);
            crate::SRM
                .lock()
                .await
                .attach_executed(op_id, executed_oci_digest.clone())
                // Keep the SrmError typed rather than stringifying it: this call is a
                // quarantine gate (F-40), and create_container maps the error back to a
                // ttrpc code with `srm_code` by downcasting. An `anyhow!` here would
                // flatten a quarantine into INTERNAL, which the shim reads as "bad
                // request" and retries — the exact confusion RM-7's DATA_LOSS code exists
                // to prevent.
                .map_err(|e| {
                    anyhow::Error::new(e).context(format!(
                        "FR-3: failed to bind executed OCI object to {}",
                        op_id
                    ))
                })?;
            // The digests routinely differ, which on its own says nothing: the
            // resolution chain legitimately rewrites parts of the spec. What must
            // not differ is anything the policy actually decided on. C-ACI/hcsshim
            // obtains this property by ordering -- it evaluates policy on the
            // already transformed spec -- so authorizing first, as we do, means the
            // relationship has to be re-established explicitly here.
            enforce_plan_binding(
                &cid,
                &authorized_oci,
                &authorized_oci_digest,
                &oci,
                &executed_oci_digest,
            )?;
        }

        // determine which cgroup driver to take and then assign to use_systemd_cgroup
        // systemd: "[slice]:[prefix]:[name]"
        // fs: "/path_a/path_b"
        // If agent is init we can't use systemd cgroup mode, no matter what the host tells us
        let cgroups_path = &oci
            .linux()
            .as_ref()
            .and_then(|linux| linux.cgroups_path().as_ref())
            .map(|cgrps_path| cgrps_path.display().to_string())
            .unwrap_or_default();

        let use_systemd_cgroup = if self.init_mode {
            false
        } else {
            SYSTEMD_CGROUP_PATH_FORMAT.is_match(cgroups_path)
        };

        let opts = CreateOpts {
            cgroup_name: "".to_string(),
            use_systemd_cgroup,
            no_pivot_root: s.no_pivot_root,
            no_new_keyring: false,
            spec: Some(oci.clone()),
            rootless_euid: false,
            rootless_cgroup: false,
            container_name,
        };

        let mut ctr: LinuxContainer = LinuxContainer::new(
            cid.as_str(),
            CONTAINER_BASE,
            Some(s.devcg_info.clone()),
            opts,
            &sl(),
        )?;

        let pipe_size = AGENT_CONFIG.container_pipe_size;

        let Some(p) = oci.process() else {
            info!(sl(), "no process configurations!");
            return Err(anyhow!(nix::Error::EINVAL));
        };

        let new_p = confidential_data_hub::image::get_process(p, &oci, req.storages.clone())?;
        let p = Process::new(&sl(), &new_p, cid.as_str(), true, pipe_size, proc_io)?;

        // if starting container failed, we will do some rollback work
        // to ensure no resources are leaked.
        if let Err(err) = ctr.start(p).await {
            error!(sl(), "failed to start container: {:?}", err);
            if let Err(e) = ctr.destroy().await {
                error!(sl(), "failed to destroy container: {:?}", e);
            }
            if let Err(e) = remove_container_resources(&mut s, &cid).await {
                error!(sl(), "failed to remove container resources: {:?}", e);
            }
            return Err(err);
        }

        s.update_shared_pidns(&ctr)?;
        s.setup_shared_mounts(&ctr, &req.shared_mounts)?;
        s.add_container(ctr);
        info!(sl(), "created container!");

        // FR-9/FR-11: the container now exists. Record its occurrence in the `created`
        // state and bind the trusted-resolved CDI devices to it, so lifecycle and device
        // handles are tracked against the enforcer's own occurrence (not the host alias).
        //
        // F-35: these results must not be discarded. A failure here means the occurrence
        // registry has diverged from the sandbox, and the container is already started and
        // registered while `create_container`'s error arm does not tear it down -- so
        // returning an error on its own would leave a running, untracked container.
        // Quarantining first is what makes the error safe to return: no further SRM-gated
        // operation is authorized afterwards, so the untracked container cannot be exec'd
        // into, signalled or given new devices, and the shim is told DATA_LOSS (RM-7)
        // rather than a retryable INTERNAL.
        //
        // No production path reaches this today: a duplicate create is answered from the
        // SRM replay cache before it gets here. This is defence in depth against a future
        // divergence between the transaction log and the occurrence registry.
        //
        // The occurrence lock is taken as a temporary inside the `let`, so it is released
        // before the monitor lock is acquired below. Nothing in this file ever holds both,
        // and nothing should start to.
        #[cfg(feature = "strict-policy")]
        {
            let outcome = record_occurrence(
                &mut *crate::OCCURRENCES.lock().await,
                &cid,
                &verified_cdi_devices,
            );
            if let Err(e) = outcome {
                let reason = format!(
                    "occurrence registry diverged while recording container {}: {}",
                    cid, e
                );
                error!(sl(), "{}", reason);
                crate::SRM.lock().await.quarantine(reason.clone());
                return Err(anyhow::Error::new(
                    kata_security_reference_monitor::SrmError::Quarantined(reason),
                )
                .context("failed to record the container occurrence"));
            }
        }

        Ok(())
    }

    #[instrument]
    async fn do_start_container(&self, req: protocols::agent::StartContainerRequest) -> Result<()> {
        let mut s = self.sandbox.lock().await;
        let sid = s.id.clone();
        let cid = req.container_id.clone();

        let ctr = s
            .get_container(&cid)
            .ok_or_else(|| anyhow!("Invalid container id"))?;

        if sid != cid {
            // start oom event loop
            if let Ok(cg_path) = ctr.cgroup_manager.as_ref().get_cgroup_path("memory") {
                let rx = notifier::notify_oom(cid.as_str(), cg_path.to_string()).await?;
                s.run_oom_event_monitor(rx, cid.clone()).await;
            }
        }

        let ctr = s
            .get_container(&cid)
            .ok_or_else(|| anyhow!("Invalid container id"))?;

        ctr.exec().await
    }

    #[instrument]
    async fn do_remove_container(
        &self,
        req: protocols::agent::RemoveContainerRequest,
    ) -> Result<()> {
        let cid = req.container_id;

        // Drop the host guest mapping for this container so we can reuse the
        // PCI slots for the next containers

        // RM-26: a removal the policy admitted for an id with no container behind it is a
        // no-op, not an error.
        //
        // `rules.rego` now admits `RemoveContainerRequest` for a container id that was
        // never created (no state key and no tombstone), because refusing it left pods
        // stuck in `Terminating` whenever a `CreateContainerRequest` was denied -- the
        // shim's cleanup removal was denied too and it had no other exit. Returning
        // `Invalid container id` here would reintroduce exactly that deadlock one layer
        // down, so the guest has to agree with the policy: there is nothing to destroy,
        // and saying so is the whole point.
        //
        // Resource cleanup still runs. A create that failed part-way (an SRM abort, a
        // storage error) can leave mounts or dm-verity devices behind without ever
        // registering a container, and this is the only path that reclaims them.
        //
        // Confined to strict builds so the upstream contract is unchanged elsewhere.
        #[cfg(feature = "strict-policy")]
        {
            let mut sandbox = self.sandbox.lock().await;
            if sandbox.get_container(&cid).is_none() {
                info!(
                    sl(),
                    "no container to remove for {}; treating the removal as a no-op", cid
                );
                sandbox.bind_watcher.remove_container(&cid).await;
                remove_container_resources(&mut sandbox, &cid).await?;
                return Ok(());
            }
        }

        if req.timeout == 0 {
            let mut sandbox = self.sandbox.lock().await;
            sandbox.bind_watcher.remove_container(&cid).await;
            sandbox
                .get_container(&cid)
                .ok_or_else(|| anyhow!("Invalid container id"))?
                .destroy()
                .await?;
            remove_container_resources(&mut sandbox, &cid).await?;
            return Ok(());
        }

        // timeout != 0
        let s = self.sandbox.clone();
        let cid2 = cid.clone();
        let handle = tokio::spawn(async move {
            let mut sandbox = s.lock().await;
            sandbox.bind_watcher.remove_container(&cid2).await;
            sandbox
                .get_container(&cid2)
                .ok_or_else(|| anyhow!("Invalid container id"))?
                .destroy()
                .await
        });

        let to = Duration::from_secs(req.timeout.into());
        tokio::time::timeout(to, handle)
            .await
            .map_err(|_| anyhow!(nix::Error::ETIME))???;

        remove_container_resources(&mut *self.sandbox.lock().await, &cid).await
    }

    #[instrument]
    async fn do_exec_process(&self, req: protocols::agent::ExecProcessRequest) -> Result<()> {
        let cid = req.container_id;
        let exec_id = req.exec_id;

        info!(sl(), "do_exec_process cid: {} eid: {}", cid, exec_id);

        // create the proc_io first, in case there's some error occur below, thus we can make sure
        // the io stream closed when error occur.
        let proc_io = if AGENT_CONFIG.passfd_listener_port != 0 {
            Some(passfd_io::take_io_streams(req.stdin_port, req.stdout_port, req.stderr_port).await)
        } else {
            None
        };

        let mut sandbox = self.sandbox.lock().await;
        let mut process = req
            .process
            .into_option()
            .ok_or_else(|| anyhow!("Unable to parse process from ExecProcessRequest"))?;

        // Apply any necessary corrections for PCI addresses
        update_env_pci(&cid, &mut process.Env, &sandbox.pcimap)?;

        let pipe_size = AGENT_CONFIG.container_pipe_size;
        let ocip = process.into();
        let p = Process::new(&sl(), &ocip, exec_id.as_str(), false, pipe_size, proc_io)?;

        let ctr = sandbox
            .get_container(&cid)
            .ok_or_else(|| anyhow!("Invalid container id"))?;

        ctr.run(p).await
    }

    #[instrument]
    // FR-3: compute the signal that will actually be delivered, matching the rewrite in
    // do_signal_process (a container init process with no SIGTERM handler receives SIGKILL).
    // Called before authorization so the policy authorizes the effective signal.
    //
    // RM-8: also reports whether that delivery is *lethal* — i.e. it terminates the target
    // without running any guest-defined handler. Only a lethal delivery is teardown. A
    // SIGTERM that will be caught by a handler asks a running workload to run new code,
    // which is exactly the property used to exclude SIGHUP/SIGUSR1 from the exemption.
    #[cfg(feature = "strict-policy")]
    async fn effective_signal(&self, cid: &str, eid: &str, requested: u32) -> (u32, bool) {
        let sig: libc::c_int = requested as libc::c_int;
        let all = eid.is_empty() && sig == libc::SIGKILL;
        if !all {
            let mut sandbox = self.sandbox.lock().await;
            if let Ok(p) = sandbox.find_container_process(cid, eid) {
                let proc_status_file = format!("/proc/{}/status", p.pid);
                if p.init
                    && sig == libc::SIGTERM
                    && !is_signal_handled(&proc_status_file, sig as u32)
                {
                    return (libc::SIGKILL as u32, true);
                }
            }
        }
        // SIGKILL is uncatchable, so it is always lethal. Everything else — including a
        // SIGTERM that reached here unrewritten, meaning it is either handled or targets a
        // non-init process — may run guest code and is not teardown.
        (requested, sig == libc::SIGKILL)
    }

    async fn do_signal_process(&self, req: protocols::agent::SignalProcessRequest) -> Result<()> {
        let cid = req.container_id;
        let eid = req.exec_id;

        info!(
            sl(),
            "signal process";
            "container-id" => &cid,
            "exec-id" => &eid,
            "signal" => req.signal,
        );

        let mut sig: libc::c_int = req.signal as libc::c_int;
        {
            let mut sandbox = self.sandbox.lock().await;
            let p = sandbox
                .find_container_process(cid.as_str(), eid.as_str())
                .map_err(sandbox_err_to_ttrpc)?;
            // For container initProcess, if it hasn't installed handler for "SIGTERM" signal,
            // it will ignore the "SIGTERM" signal sent to it, thus send it "SIGKILL" signal
            // instead of "SIGTERM" to terminate it.
            let proc_status_file = format!("/proc/{}/status", p.pid);
            if p.init && sig == libc::SIGTERM && !is_signal_handled(&proc_status_file, sig as u32) {
                sig = libc::SIGKILL;
            }

            match p.signal(sig) {
                Err(Errno::ESRCH) => {
                    info!(
                        sl(),
                        "signal encounter ESRCH, continue";
                        "container-id" => &cid,
                        "exec-id" => &eid,
                        "pid" => p.pid,
                        "signal" => sig,
                    );
                }
                Err(err) => return Err(anyhow!(err)),
                Ok(()) => (),
            }
        };

        if eid.is_empty() {
            // eid is empty, signal all the remaining processes in the container cgroup
            info!(
                sl(),
                "signal all the remaining processes";
                "container-id" => &cid,
                "exec-id" => &eid,
            );

            if let Err(err) = self.freeze_cgroup(&cid, FreezerState::Frozen).await {
                warn!(
                    sl(),
                    "freeze cgroup failed";
                    "container-id" => &cid,
                    "exec-id" => &eid,
                    "error" => format!("{:?}", err),
                );
            }

            let pids = self.get_pids(&cid).await?;
            for pid in pids.iter() {
                let res = unsafe { libc::kill(*pid, sig) };
                if let Err(err) = Errno::result(res).map(drop) {
                    warn!(
                        sl(),
                        "signal failed";
                        "container-id" => &cid,
                        "exec-id" => &eid,
                        "pid" => pid,
                        "error" => format!("{:?}", err),
                    );
                }
            }
            if let Err(err) = self.freeze_cgroup(&cid, FreezerState::Thawed).await {
                warn!(
                    sl(),
                    "unfreeze cgroup failed";
                    "container-id" => &cid,
                    "exec-id" => &eid,
                    "error" => format!("{:?}", err),
                );
            }
        }

        Ok(())
    }

    async fn freeze_cgroup(&self, cid: &str, state: FreezerState) -> Result<()> {
        let mut sandbox = self.sandbox.lock().await;
        let ctr = sandbox
            .get_container(cid)
            .ok_or_else(|| anyhow!("Invalid container id {}", cid))?;
        ctr.cgroup_manager.as_ref().freeze(state)
    }

    async fn get_pids(&self, cid: &str) -> Result<Vec<i32>> {
        let mut sandbox = self.sandbox.lock().await;
        let ctr = sandbox
            .get_container(cid)
            .ok_or_else(|| anyhow!("Invalid container id {}", cid))?;
        ctr.cgroup_manager.as_ref().get_pids()
    }

    #[instrument]
    async fn do_wait_process(
        &self,
        req: protocols::agent::WaitProcessRequest,
    ) -> Result<protocols::agent::WaitProcessResponse> {
        let cid = req.container_id;
        let mut eid = req.exec_id;
        let mut resp = WaitProcessResponse::new();

        info!(
            sl(),
            "wait process";
            "container-id" => &cid,
            "exec-id" => &eid
        );

        let pid: pid_t;
        let (exit_send, mut exit_recv) = tokio::sync::mpsc::channel(100);
        let exit_rx = {
            let mut sandbox = self.sandbox.lock().await;
            let p = sandbox
                .find_container_process(cid.as_str(), eid.as_str())
                .map_err(sandbox_err_to_ttrpc)?;

            p.exit_watchers.push(exit_send);
            pid = p.pid;

            p.exit_rx.clone()
        };

        if let Some(mut exit_rx) = exit_rx {
            info!(sl(), "cid {} eid {} waiting for exit signal", &cid, &eid);
            while exit_rx.changed().await.is_ok() {}
            info!(sl(), "cid {} eid {} received exit signal", &cid, &eid);
        }

        let mut sandbox = self.sandbox.lock().await;
        let ctr = sandbox
            .get_container(&cid)
            .ok_or_else(|| anyhow!("Invalid container id"))?;

        let p = match ctr.processes.values_mut().find(|p| p.pid == pid) {
            Some(p) => p,
            None => {
                // Lost race, pick up exit code from channel
                resp.status = exit_recv
                    .recv()
                    .await
                    .ok_or_else(|| anyhow!("Failed to receive exit code"))?;

                return Ok(resp);
            }
        };

        eid = p.exec_id.clone();

        // need to close all fd
        // ignore errors for some fd might be closed by stream
        p.cleanup_process_stream();

        resp.status = p.exit_code;
        // broadcast exit code to all parallel watchers
        for s in p.exit_watchers.iter_mut() {
            // Just ignore errors in case any watcher quits unexpectedly
            let _ = s.send(p.exit_code).await;
        }

        ctr.processes.remove(&eid);

        Ok(resp)
    }

    #[cfg_attr(feature = "strict-policy", allow(dead_code))]
    async fn do_read_termination_log(
        &self,
        container_id: &str,
    ) -> Result<protocols::agent::GetDiagnosticDataResponse> {
        let host_path = {
            let sandbox = self.sandbox.lock().await;
            let ctr = sandbox
                .containers
                .get(container_id)
                .ok_or_else(|| anyhow!("Invalid container id: {}", container_id))?;

            let spec = ctr
                .config
                .spec
                .as_ref()
                .ok_or_else(|| anyhow!("No OCI spec for container {}", container_id))?;

            let annotations = spec.annotations().as_ref();
            let termination_path = annotations
                .and_then(|a| a.get("io.kubernetes.container.terminationMessagePath"))
                .ok_or_else(|| anyhow!("No terminationMessagePath annotation"))?;

            // The path is the *container* destination (e.g. /dev/termination-log). The agent
            // runs outside the container mount namespace; the file is on the guest at the
            // bind-mount source (e.g. /run/kata-containers/shared/containers/...-termination-log).
            let term_dest = Path::new(termination_path.as_str());
            spec.mounts()
                .as_ref()
                .and_then(|mounts| {
                    mounts.iter().find_map(|m| {
                        if m.destination() == term_dest {
                            m.source().clone()
                        } else {
                            None
                        }
                    })
                })
                .ok_or_else(|| {
                    anyhow!(
                        "termination message mount not found for {}",
                        termination_path
                    )
                })?
        };

        // Kubernetes caps termination messages at 4 KiB; read raw bytes with
        // the same limit so a malicious workload cannot exhaust agent memory,
        // and handle non-UTF-8 content gracefully.
        const MAX_TERMINATION_MSG: usize = 4096;
        let contents = match tokio::fs::read(&host_path).await {
            Ok(mut buf) => {
                buf.truncate(MAX_TERMINATION_MSG);
                String::from_utf8_lossy(&buf).into_owned()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(anyhow!("Failed to read termination log: {}", e)),
        };

        let mut resp = protocols::agent::GetDiagnosticDataResponse::new();
        resp.data = contents;
        Ok(resp)
    }

    async fn do_write_stream(
        &self,
        req: protocols::agent::WriteStreamRequest,
    ) -> Result<protocols::agent::WriteStreamResponse> {
        let cid = req.container_id;
        let eid = req.exec_id;

        let mut resp = WriteStreamResponse::new();
        resp.set_len(req.data.len() as u32);

        // EOF of stdin
        if req.data.is_empty() {
            let mut sandbox = self.sandbox.lock().await;
            let p = sandbox.find_container_process(cid.as_str(), eid.as_str())?;
            p.close_stdin().await;
        } else {
            let writer = {
                let mut sandbox = self.sandbox.lock().await;
                let p = sandbox.find_container_process(cid.as_str(), eid.as_str())?;

                // use ptmx io
                if p.term_master.is_some() {
                    p.get_writer(StreamType::TermMaster)
                } else {
                    // use piped io
                    p.get_writer(StreamType::ParentStdin)
                }
            };

            let writer = writer.ok_or_else(|| anyhow!(ERR_CANNOT_GET_WRITER))?;
            writer.lock().await.write_all(req.data.as_slice()).await?;
        }

        Ok(resp)
    }

    async fn do_read_stream(
        &self,
        req: &protocols::agent::ReadStreamRequest,
        stdout: bool,
    ) -> Result<protocols::agent::ReadStreamResponse> {
        let cid = &req.container_id;
        let eid = &req.exec_id;

        let term_exit_notifier;
        let reader = {
            let mut sandbox = self.sandbox.lock().await;
            let p = sandbox
                .find_container_process(cid.as_str(), eid.as_str())
                .map_err(sandbox_err_to_ttrpc)?;

            term_exit_notifier = p.term_exit_notifier.clone();

            if p.term_master.is_some() {
                p.get_reader(StreamType::TermMaster)
            } else if stdout {
                if p.parent_stdout.is_some() {
                    p.get_reader(StreamType::ParentStdout)
                } else {
                    None
                }
            } else {
                p.get_reader(StreamType::ParentStderr)
            }
        };

        let reader = reader.ok_or_else(|| anyhow!("cannot get stream reader"))?;

        // Create one in-flight read future and reuse it in both branches.
        let read_fut = read_stream(&reader, req.len as usize);
        tokio::pin!(read_fut);

        // Cancellation and polling model: Rust async is polled, not preempted.
        // `Future::poll()` is a synchronous function call that runs to completion and
        // returns Ready or Pending (`std::future::Future`).
        // Readiness notifications (Waker::wake / Tokio Notify) only schedule the task
        // to be polled again later; they do not interrupt an in-progress poll.
        // Therefore, a Notify becoming ready while `poll_read()` is executing cannot cause
        // the read future to be dropped mid-way; cancellation can only happen when the branch
        // is still pending between polls (Tokio `select!` cancels by dropping non-selected futures).
        // Detailed information, please refer to Tokio doc for more information:
        // - Future::poll: https://doc.rust-lang.org/std/future/trait.Future.html
        // - Waker: https://doc.rust-lang.org/std/task/struct.Waker.html
        // - Tokio select!: https://docs.rs/tokio/latest/tokio/macro.select.html
        let data = tokio::select! {
            // Use `biased` to make the polling order deterministic (top-to-bottom).
            // This ensures that *when multiple branches are ready at the same time*,
            // we prefer reading pending output over reacting to the exit notification.
            //
            // Note: `biased` does NOT guarantee that we won't lose output. If the exit
            // notification becomes ready while `read_stream` is still pending, the
            // exit branch may be selected and we may stop reading before draining the
            // remaining buffered data.
            //
            // Detailed information, please refer to Tokio doc for more information:
            // https://docs.rs/tokio/latest/src/tokio/macros/select.rs.html#67
            biased;

            v = &mut read_fut => v?,
            _ = term_exit_notifier.notified() => {
                // Drain-after-exit rationale:
                // The process has exited, but the data may still be buffered in the pipe/pty.
                // We should keep waiting for the same in-flight read for a bounded window to drain the data.
                //
                // It enters this branch only if `term_exit_notifier.notified()` fires. It then try to "drain"
                // any remaining buffered output for a short, bounded time window:
                // - If non-empty data is read: return immediately.
                // - else then return empty data as EOF.

                const DRAIN_DEADLINE_MS: u64 = 500; // 500ms
                let deadline = Duration::from_millis(DRAIN_DEADLINE_MS);

                // Attempt to drain remaining buffered output after process exit
                // Try reading with timeout
                match timeout(deadline, &mut read_fut).await {
                    Ok(v) => v?, // got data or EOF (empty)
                    _ => {
                        warn!(sl(), "exit-drain timeout, return EOF"; "container-id" => cid, "exec-id" => eid);
                        Vec::new() // Return empty as EOF
                    }
                }
            }
        };

        let mut resp = ReadStreamResponse::new();
        resp.set_data(data);

        Ok(resp)
    }

    /// Authorize before reading, then read.
    ///
    /// The previous order was inverted: `do_read_stream` ran first and the policy verdict
    /// was applied afterwards by clearing the response. Reading a pipe is **destructive** —
    /// the bytes are consumed — so a caller the policy denied still drained the container's
    /// stdout/stderr, discarding output the legitimate reader would otherwise have received,
    /// and could distinguish container/exec states from the error it got back. The
    /// authorization also came too late to prevent the read from blocking on the stream.
    ///
    /// The host-visible contract is unchanged: a denied read still returns an empty
    /// response rather than an error, so `kubectl logs` behaves as before. What changes is
    /// that a denied read now has no effect at all.
    async fn do_read_stream_gated(
        &self,
        req: &protocols::agent::ReadStreamRequest,
        stdout: bool,
    ) -> ttrpc::Result<ReadStreamResponse> {
        if is_allowed(req).await.is_err() {
            // Policy does not allow reading logs. Return an empty response without
            // touching the stream.
            return Ok(ReadStreamResponse::new());
        }
        self.do_read_stream(req, stdout).await.map_ttrpc_err(same)
    }
}

fn mem_agent_memcgconfig_to_memcg_optionconfig(
    mc: &protocols::agent::MemAgentMemcgConfig,
) -> mem_agent::memcg::OptionConfig {
    mem_agent::memcg::OptionConfig {
        default: mem_agent::memcg::SingleOptionConfig {
            disabled: mc.disabled,
            swap: mc.swap,
            swappiness_max: mc.swappiness_max.map(|x| x as u8),
            period_secs: mc.period_secs,
            period_psi_percent_limit: mc.period_psi_percent_limit.map(|x| x as u8),
            eviction_psi_percent_limit: mc.eviction_psi_percent_limit.map(|x| x as u8),
            eviction_run_aging_count_min: mc.eviction_run_aging_count_min,
        },
        ..Default::default()
    }
}

fn mem_agent_compactconfig_to_compact_optionconfig(
    cc: &protocols::agent::MemAgentCompactConfig,
) -> mem_agent::compact::OptionConfig {
    mem_agent::compact::OptionConfig {
        disabled: cc.disabled,
        period_secs: cc.period_secs,
        period_psi_percent_limit: cc.period_psi_percent_limit.map(|x| x as u8),
        compact_psi_percent_limit: cc.compact_psi_percent_limit.map(|x| x as u8),
        compact_sec_max: cc.compact_sec_max,
        compact_order: cc.compact_order.map(|x| x as u8),
        compact_threshold: cc.compact_threshold,
        compact_force_times: cc.compact_force_times,
        ..Default::default()
    }
}

#[async_trait]
impl agent_ttrpc::AgentService for AgentService {
    async fn create_container(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::CreateContainerRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "create_container", req);

        // BL-8 fail-closed gate. The measured base policy may declare policy fragments that
        // the host is responsible for delivering (the guest has no network of its own — see
        // policy_fragments.rs). Refuse to create anything while a declaration the policy
        // marked `required: true` is undelivered, otherwise a host that simply never pushes
        // would get the workload running under a policy missing grants it was measured to
        // include. Declarations without that flag are lazy (C-ACI/hcsshim behaviour) and do
        // not gate: an undelivered fragment grants nothing, so it cannot widen what runs.
        //
        // Before is_allowed(), because the point is that the active policy is not yet the
        // policy that was measured — its verdict is not the one to act on.
        #[cfg(feature = "strict-policy")]
        crate::policy_fragments::assert_all_declared_satisfied()
            .await
            .map_err(|e| ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e))?;

        // FR-6: snapshot policy state before authorization. The policy applies its
        // pstate mutations during is_allowed; if the create fails we restore this
        // snapshot so no committed enforcer state survives a failed operation.
        #[cfg(feature = "strict-policy")]
        let policy_before = crate::AGENT_POLICY.lock().await.snapshot_state().ok();

        is_allowed(&req).await?;
        #[cfg(feature = "strict-policy")]
        let policy_snapshot = capture_policy_snapshot(policy_before).await;
        #[cfg(feature = "strict-policy")]
        {
            use kata_security_reference_monitor::Prepared;

            let op_id = srm_op_id("create", &[&req.container_id]);
            let digest = plan_digest(&req);
            let txn_guard = {
                let mut srm = crate::SRM.lock().await;
                let version = srm.state_version();
                let prepared = srm.prepare(op_id.clone(), version, digest.clone());
                let guard = srm.guard(&op_id);
                match prepared {
                    // Idempotent replay of an already-committed create: no new effect.
                    Ok(Prepared::AlreadyCommitted(_)) => {
                        drop(srm);
                        guard.disarm();
                        // Authorization re-applied this container's pstate entry before
                        // we knew the create was a replay. Reverting our own delta keeps
                        // the enforcer's state owned by the transaction that committed it.
                        rollback_policy_state(&policy_snapshot, "duplicate create_container").await;
                        return Ok(Empty::new());
                    }
                    Ok(Prepared::New) => {}
                    Err(e) => {
                        drop(srm);
                        guard.disarm();
                        // `prepare` refused (in-flight duplicate, or the monitor is
                        // quarantined), but authorization already added the container to
                        // pstate. Without this the enforcer keeps a phantom entry for a
                        // container that was never created.
                        rollback_policy_state(&policy_snapshot, "create_container prepare").await;
                        return Err(ttrpc_error(srm_code(&e), e));
                    }
                }
                // From here on every exit must resolve the transaction; the guard covers
                // the paths that never run, i.e. this future being dropped mid-flight.
                if let Err(e) = srm.execute(&op_id, &digest) {
                    abort_or_quarantine(&mut srm, &op_id, "create_container execute");
                    drop(srm);
                    guard.disarm();
                    rollback_policy_state(&policy_snapshot, "create_container execute").await;
                    return Err(ttrpc_error(srm_code(&e), e));
                }
                guard
            };

            return match self.do_create_container(req, Some(&op_id)).await {
                Ok(_) => {
                    let mut srm = crate::SRM.lock().await;
                    commit_or_quarantine(&mut srm, &op_id, "container-created", "create_container");
                    drop(srm);
                    txn_guard.disarm();
                    // FR-9 occurrence creation (and FR-11 device binding) is performed
                    // inside do_create_container once the container actually exists.
                    Ok(Empty::new())
                }
                Err(e) => {
                    let mut srm = crate::SRM.lock().await;
                    abort_or_quarantine(&mut srm, &op_id, "create_container");
                    drop(srm);
                    txn_guard.disarm();
                    // Roll back the policy pstate mutations applied during authorization.
                    rollback_policy_state(&policy_snapshot, "create_container").await;
                    // RM-7: an SrmError that reached us from inside do_create_container
                    // (the FR-3 executed-object binding) keeps its own terminal code, so a
                    // quarantine arrives as DATA_LOSS rather than as an INTERNAL the shim
                    // would retry.
                    let code = e
                        .downcast_ref::<kata_security_reference_monitor::SrmError>()
                        .map_or(ttrpc::Code::INTERNAL, srm_code);
                    Err(ttrpc_error(code, e))
                }
            };
        }

        #[cfg(not(feature = "strict-policy"))]
        {
            self.do_create_container(req, None)
                .await
                .map_ttrpc_err(same)?;
            Ok(Empty::new())
        }
    }

    async fn start_container(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::StartContainerRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "start_container", req);

        // FR-6: bracket authorization with a policy-state snapshot, as the other gated
        // handlers do. `StartContainerRequest` emits no `ops` under the reference policy,
        // so there is normally nothing to revert -- but that is a property of one policy,
        // not of the request, so every failure path below unwinds it.
        #[cfg(feature = "strict-policy")]
        let policy_before = crate::AGENT_POLICY.lock().await.snapshot_state().ok();

        is_allowed(&req).await?;

        #[cfg(feature = "strict-policy")]
        let policy_snapshot = capture_policy_snapshot(policy_before).await;

        // FR-9: a container may only be started from the `created` state. This rejects
        // start-before-create and double-start against the enforcer's own occurrence
        // record (the host container_id is an untrusted alias).
        #[cfg(feature = "strict-policy")]
        if let Err(e) = crate::OCCURRENCES.lock().await.start(&req.container_id) {
            rollback_policy_state(&policy_snapshot, "start_container occurrence").await;
            return Err(ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e));
        }

        // FR-6: start is the point at which a container's capability actually
        // materialises -- until then it is a bundle on disk with no process. Leaving it
        // ungated meant a quarantined monitor still admitted it, so the set of operations
        // reachable from a degraded guest was not purely destructive, and it was the only
        // edge in create -> start -> signal -> remove with no audit record and no refusal
        // of a duplicate in flight.
        #[cfg(feature = "strict-policy")]
        {
            use kata_security_reference_monitor::Prepared;

            // Namespaced by kind: the create for this container is keyed `create/<cid>`,
            // and an un-kinded start would collide with the create it follows.
            let op_id = srm_op_id("start", &[&req.container_id]);
            let digest = plan_digest(&req);
            let txn_guard = {
                let mut srm = crate::SRM.lock().await;
                let version = srm.state_version();
                // Deliberately `prepare`, not `prepare_teardown`: a start builds
                // capability, so it must be refused while the monitor is quarantined.
                let prepared = srm.prepare(op_id.clone(), version, digest.clone());
                let guard = srm.guard(&op_id);
                drop(srm);
                match prepared {
                    Ok(Prepared::New) => {}
                    // A double start is already refused by the occurrence registry above,
                    // so a committed transaction here means the operation id was reused
                    // rather than that this is a legitimate replay. Refuse instead of
                    // reporting a start that did not happen. Reaching this arm should be
                    // impossible: the transaction is retired the moment the start commits.
                    Ok(Prepared::AlreadyCommitted(_)) => {
                        guard.disarm();
                        unstart_or_warn(&req.container_id).await;
                        rollback_policy_state(&policy_snapshot, "duplicate start_container").await;
                        return Err(ttrpc_error(
                            ttrpc::Code::FAILED_PRECONDITION,
                            format!("start transaction {op_id} already committed"),
                        ));
                    }
                    Err(e) => {
                        guard.disarm();
                        unstart_or_warn(&req.container_id).await;
                        rollback_policy_state(&policy_snapshot, "start_container prepare").await;
                        return Err(ttrpc_error(srm_code(&e), e));
                    }
                }
                let mut srm = crate::SRM.lock().await;
                if let Err(e) = srm.execute(&op_id, &digest) {
                    abort_or_quarantine(&mut srm, &op_id, "start_container execute");
                    drop(srm);
                    guard.disarm();
                    unstart_or_warn(&req.container_id).await;
                    rollback_policy_state(&policy_snapshot, "start_container execute").await;
                    return Err(ttrpc_error(srm_code(&e), e));
                }
                guard
            };

            return match self.do_start_container(req.clone()).await {
                Ok(_) => {
                    // FR-14: a workload container is now running; freeze the network so
                    // post-start network mutation is refused. Do this before recording the
                    // commit: a freeze without a commit costs availability, a commit
                    // without a freeze costs containment, and the host controls when this
                    // future is cancelled (ttrpc honours its `timeout_nano`).
                    crate::NET_PHASE.lock().await.to_workload_running();
                    {
                        let mut srm = crate::SRM.lock().await;
                        commit_or_quarantine(
                            &mut srm,
                            &op_id,
                            "container-started",
                            "start_container",
                        );
                        // Retire immediately, as `exec_process` does. A committed
                        // transaction is a replay-cache entry, and this one would buy
                        // nothing -- a double start is already refused by the occurrence
                        // registry -- while `remove_container` is the only other place
                        // that could free it. Retiring there instead is not sound: a
                        // removal racing this start finds the transaction still `Executed`,
                        // its retire fails, and the id is then stranded `Committed` with no
                        // owner left, making the container id permanently unstartable.
                        retire_or_warn(&mut srm, &op_id);
                    }
                    txn_guard.disarm();
                    Ok(Empty::new())
                }
                Err(e) => {
                    {
                        let mut srm = crate::SRM.lock().await;
                        abort_or_quarantine(&mut srm, &op_id, "start_container");
                    }
                    txn_guard.disarm();
                    // Runtime start failed: roll the occurrence back to `created` so the
                    // trusted state matches reality and a legitimate retry is possible.
                    unstart_or_warn(&req.container_id).await;
                    rollback_policy_state(&policy_snapshot, "start_container").await;
                    Err(ttrpc_error(ttrpc::Code::INTERNAL, e))
                }
            };
        }

        #[cfg(not(feature = "strict-policy"))]
        {
            self.do_start_container(req).await.map_ttrpc_err(same)?;
            Ok(Empty::new())
        }
    }

    async fn remove_container(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::RemoveContainerRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "remove_container", req);

        // FR-6: snapshot policy state before authorization.
        //
        // `RemoveContainerRequest` is one of only two rules that mutate the policy's
        // persisted state: it deletes the container from `pstate` while authorizing the
        // request. If the teardown then fails, the container is still running but the
        // policy no longer knows about it, and `get_state_val` is undefined for it. That
        // makes every later `SignalProcessRequest` and `RemoveContainerRequest` for that
        // container undefined, so the fail-closed default denies them -- the container
        // cannot be signalled and cannot be removed, permanently. Restoring this snapshot
        // on failure is what keeps a failed removal retryable.
        #[cfg(feature = "strict-policy")]
        let policy_before = crate::AGENT_POLICY.lock().await.snapshot_state().ok();

        is_allowed(&req).await?;
        #[cfg(feature = "strict-policy")]
        let policy_snapshot = capture_policy_snapshot(policy_before).await;

        // FR-6: a removal destroys state, so run it as a transaction like create and exec.
        #[cfg(feature = "strict-policy")]
        {
            use kata_security_reference_monitor::Prepared;

            // Namespaced by kind: `create_container` builds its id the same way, so an
            // un-kinded removal would collide with the create it undoes.
            let op_id = srm_op_id("remove", &[&req.container_id]);
            let digest = plan_digest(&req);
            let txn_guard = {
                let mut srm = crate::SRM.lock().await;
                let version = srm.state_version();
                let prepared = srm.prepare_teardown(op_id.clone(), version, digest.clone());
                // RM-8: removal only tears capability down, so it stays available while
                // the monitor is quarantined; otherwise a degraded sandbox cannot be
                // cleaned up at all and the host's only recourse is sandbox-level destroy.
                // Take the guard under the same lock acquisition that prepared the
                // transaction. The lock has to be released before `rollback_policy_state`
                // (which acquires AGENT_POLICY then SRM, so holding SRM here would invert
                // the order), and re-acquiring it is a suspension point. A transaction that
                // is Prepared across that point without a guard is never reclaimed if the
                // host cancels the call, which wedges the operation id forever.
                let guard = srm.guard(&op_id);
                drop(srm);
                match prepared {
                    Ok(Prepared::New) => {}
                    // Removal is already single-shot at the policy layer: a second remove
                    // of the same container is undefined and denied before reaching here.
                    // A committed transaction therefore means the operation id was reused,
                    // not a legitimate replay. Refuse rather than report a removal that
                    // did not happen.
                    Ok(Prepared::AlreadyCommitted(_)) => {
                        // The committed transaction this collided with is already
                        // resolved; there is nothing for the guard to reclaim.
                        guard.disarm();
                        rollback_policy_state(&policy_snapshot, "duplicate remove_container").await;
                        return Err(ttrpc_error(
                            ttrpc::Code::FAILED_PRECONDITION,
                            format!("remove transaction {op_id} already committed"),
                        ));
                    }
                    Err(e) => {
                        // `prepare` failed, so no transaction of ours is in flight.
                        guard.disarm();
                        rollback_policy_state(&policy_snapshot, "remove_container prepare").await;
                        return Err(ttrpc_error(srm_code(&e), e));
                    }
                }
                let mut srm = crate::SRM.lock().await;
                if let Err(e) = srm.execute(&op_id, &digest) {
                    abort_or_quarantine(&mut srm, &op_id, "remove_container execute");
                    drop(srm);
                    guard.disarm();
                    rollback_policy_state(&policy_snapshot, "remove_container execute").await;
                    return Err(ttrpc_error(srm_code(&e), e));
                }
                guard
            };

            return match self.do_remove_container(req.clone()).await {
                Ok(_) => {
                    {
                        let mut srm = crate::SRM.lock().await;
                        commit_or_quarantine(
                            &mut srm,
                            &op_id,
                            "container-removed",
                            "remove_container",
                        );
                        // The container id is now free again. Retire every transaction
                        // keyed on it -- the create and the removal itself -- so a later
                        // create for the same id is a genuinely new operation rather than
                        // an idempotent replay of the one just undone. The start
                        // transaction is retired by `start_container` on commit and so is
                        // never outstanding here.
                        let create_op_id = srm_op_id("create", &[&req.container_id]);
                        for id in [&create_op_id, &op_id] {
                            retire_or_warn(&mut srm, id);
                        }
                    }
                    txn_guard.disarm();
                    // FR-9: retire the occurrence. Its alias may not be operated on again
                    // until a fresh create re-mints it with a new generation.
                    //
                    // F-35: log-and-continue rather than propagate or quarantine. `remove`
                    // returns `Err` only when there was no live occurrence to retire in the
                    // first place -- every non-removed state is an allowed source -- so a
                    // failure here strands nothing, and a later create for this alias mints
                    // a fresh generation regardless. The result is still not discarded: it
                    // is the only signal that the registry and the transaction log disagree
                    // about whether this container ever existed.
                    if let Err(e) = crate::OCCURRENCES.lock().await.remove(&req.container_id) {
                        error!(
                            sl(),
                            "no live occurrence to retire for {} after removing the container: \
                             {:?}; the occurrence registry disagrees with the transaction log",
                            req.container_id,
                            e
                        );
                    }
                    Ok(Empty::new())
                }
                Err(e) => {
                    {
                        let mut srm = crate::SRM.lock().await;
                        abort_or_quarantine(&mut srm, &op_id, "remove_container");
                    }
                    txn_guard.disarm();
                    // The container is still running: put it back in `pstate` so it stays
                    // signallable and the removal can be retried.
                    rollback_policy_state(&policy_snapshot, "remove_container").await;
                    Err(ttrpc_error(ttrpc::Code::INTERNAL, e))
                }
            };
        }

        #[cfg(not(feature = "strict-policy"))]
        {
            self.do_remove_container(req).await.map_ttrpc_err(same)?;
            Ok(Empty::new())
        }
    }

    async fn exec_process(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::ExecProcessRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "exec_process", req);

        // FR-3 (exec-env canonicalization): the agent rewrites the process environment
        // via update_env_pci (PCI address corrections) after authorization. In strict
        // builds, apply that resolution BEFORE authorization so the policy authorizes
        // (and the transaction digests) the environment that is actually executed
        // (authorized == executed). do_exec_process re-applies it idempotently.
        #[cfg(feature = "strict-policy")]
        let req = {
            let mut req = req;
            let cid = req.container_id.clone();
            if let Some(process) = req.process.as_mut() {
                let sandbox = self.sandbox.lock().await;
                let _ = update_env_pci(&cid, &mut process.Env, &sandbox.pcimap);
            }
            req
        };

        // FR-6: snapshot policy state before authorization for rollback on failure.
        #[cfg(feature = "strict-policy")]
        let policy_before = crate::AGENT_POLICY.lock().await.snapshot_state().ok();

        is_allowed(&req).await?;
        #[cfg(feature = "strict-policy")]
        let policy_snapshot = capture_policy_snapshot(policy_before).await;

        // FR-6: an exec creates a new process, so run it as an SRM transaction. The
        // operation id is the container+exec id, and a duplicate arriving while the first
        // is in flight is refused. Agent-internal (no new shim<->agent API).
        //
        // The transaction is retired once the process is running. An exec id is unique
        // only while its process exists: containerd allows the id to be reused after the
        // exec is deleted, so retaining the committed transaction would make a later,
        // legitimate exec an idempotent replay and return success without starting
        // anything.
        #[cfg(feature = "strict-policy")]
        {
            use kata_security_reference_monitor::Prepared;

            // FR-9: an exec is only permitted into a running occurrence. This rejects
            // exec on an unknown container_id or one that has not been started.
            //
            // The policy delta is reverted before returning, as on every other early
            // return in this handler: `ExecProcessRequest` emits no `ops` under the
            // reference policy, but that is a property of one policy and not of the
            // request, which is why the snapshot is taken at all. `start_container`
            // brackets the same gate the same way.
            if let Err(e) = crate::OCCURRENCES
                .lock()
                .await
                .require_running(&req.container_id, "exec")
            {
                rollback_policy_state(&policy_snapshot, "exec_process occurrence").await;
                return Err(ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e));
            }

            let op_id = srm_op_id("exec", &[&req.container_id, &req.exec_id]);
            let digest = plan_digest(&req);
            let txn_guard = {
                let mut srm = crate::SRM.lock().await;
                let version = srm.state_version();
                let prepared = srm.prepare(op_id.clone(), version, digest.clone());
                let guard = srm.guard(&op_id);
                match prepared {
                    Ok(Prepared::AlreadyCommitted(_)) => {
                        drop(srm);
                        guard.disarm();
                        rollback_policy_state(&policy_snapshot, "duplicate exec_process").await;
                        return Ok(Empty::new());
                    }
                    Ok(Prepared::New) => {}
                    Err(e) => {
                        drop(srm);
                        guard.disarm();
                        rollback_policy_state(&policy_snapshot, "exec_process prepare").await;
                        return Err(ttrpc_error(srm_code(&e), e));
                    }
                }
                // From here on every exit must resolve the transaction; the guard covers
                // the paths that never run, i.e. this future being dropped mid-flight.
                if let Err(e) = srm.execute(&op_id, &digest) {
                    abort_or_quarantine(&mut srm, &op_id, "exec_process execute");
                    drop(srm);
                    guard.disarm();
                    rollback_policy_state(&policy_snapshot, "exec_process execute").await;
                    return Err(ttrpc_error(srm_code(&e), e));
                }
                guard
            };
            return match self.do_exec_process(req).await {
                Ok(_) => {
                    let mut srm = crate::SRM.lock().await;
                    commit_or_quarantine(&mut srm, &op_id, "process-execed", "exec_process");
                    retire_or_warn(&mut srm, &op_id);
                    drop(srm);
                    txn_guard.disarm();
                    Ok(Empty::new())
                }
                Err(e) => {
                    let mut srm = crate::SRM.lock().await;
                    abort_or_quarantine(&mut srm, &op_id, "exec_process");
                    drop(srm);
                    txn_guard.disarm();
                    rollback_policy_state(&policy_snapshot, "exec_process").await;
                    Err(ttrpc_error(ttrpc::Code::INTERNAL, e))
                }
            };
        }

        #[cfg(not(feature = "strict-policy"))]
        {
            self.do_exec_process(req).await.map_ttrpc_err(same)?;
            Ok(Empty::new())
        }
    }

    async fn signal_process(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::SignalProcessRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "signal_process", req);

        // FR-3 (effective-signal canonicalization): the agent may rewrite a requested
        // SIGTERM to SIGKILL for a container init process that installs no SIGTERM handler.
        // In strict builds, resolve the effective signal BEFORE authorization so the policy
        // authorizes (and the transaction digests) the signal that is actually delivered
        // (authorized == executed), rather than the requested one.
        #[cfg(feature = "strict-policy")]
        let (req, lethal) = {
            let mut req = req;
            let (sig, lethal) = self
                .effective_signal(&req.container_id, &req.exec_id, req.signal)
                .await;
            req.signal = sig;
            (req, lethal)
        };

        is_allowed(&req).await?;

        // FR-9: a signal may only be delivered to an occurrence that has been started and
        // not removed. This rejects signalling an unknown, never-started, or already
        // removed occurrence. `Stopped` is deliberately admitted: the shim signals a
        // container whose init has already exited as part of stopping the pod, and
        // refusing that would leave the container unkillable and the pod wedged in
        // `Terminating`. A signal delivered then reaches nothing an exec could not.
        #[cfg(feature = "strict-policy")]
        crate::OCCURRENCES
            .lock()
            .await
            .require_started(&req.container_id, "signal")
            .map_err(|e| ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e))?;

        // FR-6: wrap signal delivery in an SRM transaction for a consistent audit record
        // and to refuse a duplicate while one is in flight. The operation id includes the
        // (effective) signal number so distinct signals to the same process are distinct
        // transactions.
        //
        // The transaction is retired once the signal is delivered. `(container, exec,
        // signal)` names a *kind* of event, not a unique one: repeated delivery is normal
        // (SIGHUP to reload, SIGUSR1 to rotate, SIGTERM before SIGKILL). Retaining the
        // committed transaction would make every later identical signal an idempotent
        // replay, so the agent would return success without delivering anything. Replay
        // protection here is therefore scoped to a duplicate arriving while the first is
        // still in flight, which `prepare` refuses.
        #[cfg(feature = "strict-policy")]
        {
            use kata_security_reference_monitor::Prepared;

            let op_id = srm_op_id(
                "signal",
                &[&req.container_id, &req.exec_id, &req.signal.to_string()],
            );
            let digest = plan_digest(&req);
            // No policy snapshot here: `SignalProcessRequest` is not one of the rules that
            // mutate `pstate` (only create and remove are), so there is nothing to roll
            // back, and snapshotting on every signal would serialize the whole enforcer
            // data blob twice on a hot path. If a future policy revision starts mutating
            // state in this rule, bracket it the way `exec_process` does.
            //
            // RM-8: a stop signal only tears capability down, so it stays available while
            // the monitor is quarantined -- otherwise a degraded sandbox cannot be stopped
            // gracefully and the host's only recourse is sandbox-level destroy. The test is
            // *lethal delivery*, not the signal number: `effective_signal` reports whether
            // the signal terminates the target without running guest code (SIGKILL, or a
            // SIGTERM it rewrote to SIGKILL for an unhandled init). A SIGTERM that will be
            // caught by a handler, like SIGHUP or SIGUSR1, asks a running workload to do
            // something new, so it stays gated.
            let teardown = lethal && is_teardown_signal(req.signal);
            let txn_guard = {
                let mut srm = crate::SRM.lock().await;
                let version = srm.state_version();
                let prepared = if teardown {
                    srm.prepare_teardown(op_id.clone(), version, digest.clone())
                } else {
                    srm.prepare(op_id.clone(), version, digest.clone())
                };
                match prepared {
                    Ok(Prepared::AlreadyCommitted(_)) => return Ok(Empty::new()),
                    Ok(Prepared::New) => {}
                    Err(e) => return Err(ttrpc_error(srm_code(&e), e)),
                }
                // From here on every exit must resolve the transaction; the guard covers
                // the paths that never run, i.e. this future being dropped mid-flight.
                let guard = srm.guard(&op_id);
                if let Err(e) = srm.execute(&op_id, &digest) {
                    abort_or_quarantine(&mut srm, &op_id, "signal_process execute");
                    drop(srm);
                    guard.disarm();
                    return Err(ttrpc_error(srm_code(&e), e));
                }
                guard
            };
            return match self.do_signal_process(req).await {
                Ok(_) => {
                    let mut srm = crate::SRM.lock().await;
                    commit_or_quarantine(&mut srm, &op_id, "signal-delivered", "signal_process");
                    retire_or_warn(&mut srm, &op_id);
                    drop(srm);
                    txn_guard.disarm();
                    Ok(Empty::new())
                }
                Err(e) => {
                    let mut srm = crate::SRM.lock().await;
                    abort_or_quarantine(&mut srm, &op_id, "signal_process");
                    drop(srm);
                    txn_guard.disarm();
                    Err(ttrpc_error(ttrpc::Code::INTERNAL, e))
                }
            };
        }

        #[cfg(not(feature = "strict-policy"))]
        {
            self.do_signal_process(req).await.map_ttrpc_err(same)?;
            Ok(Empty::new())
        }
    }

    async fn wait_process(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::WaitProcessRequest,
    ) -> ttrpc::Result<WaitProcessResponse> {
        trace_rpc_call!(ctx, "wait_process", req);
        is_allowed(&req).await?;
        self.do_wait_process(req).await.map_ttrpc_err(same)
    }

    async fn update_container(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::UpdateContainerRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "update_container", req);
        is_allowed(&req).await?;

        let mut sandbox = self.sandbox.lock().await;
        let ctr = sandbox
            .get_container(&req.container_id)
            .map_ttrpc_err(ttrpc::Code::INVALID_ARGUMENT, "invalid container id")?;
        if let Some(res) = req.resources.as_ref() {
            let oci_res = res.clone().into();
            ctr.set(oci_res).map_ttrpc_err(same)?;
        }

        Ok(Empty::new())
    }

    async fn stats_container(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::StatsContainerRequest,
    ) -> ttrpc::Result<StatsContainerResponse> {
        trace_rpc_call!(ctx, "stats_container", req);
        is_allowed(&req).await?;

        let mut sandbox = self.sandbox.lock().await;
        let ctr = sandbox
            .get_container(&req.container_id)
            .map_ttrpc_err(ttrpc::Code::INVALID_ARGUMENT, "invalid container id")?;
        ctr.stats().map_ttrpc_err(same)
    }

    async fn pause_container(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::PauseContainerRequest,
    ) -> ttrpc::Result<protocols::empty::Empty> {
        trace_rpc_call!(ctx, "pause_container", req);
        is_allowed(&req).await?;

        let mut sandbox = self.sandbox.lock().await;
        let ctr = sandbox
            .get_container(&req.container_id)
            .map_ttrpc_err(ttrpc::Code::INVALID_ARGUMENT, "invalid container id")?;
        ctr.pause().map_ttrpc_err(same)?;
        Ok(Empty::new())
    }

    async fn resume_container(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::ResumeContainerRequest,
    ) -> ttrpc::Result<protocols::empty::Empty> {
        trace_rpc_call!(ctx, "resume_container", req);
        is_allowed(&req).await?;

        let mut sandbox = self.sandbox.lock().await;
        let ctr = sandbox
            .get_container(&req.container_id)
            .map_ttrpc_err(ttrpc::Code::INVALID_ARGUMENT, "invalid container id")?;
        ctr.resume().map_ttrpc_err(same)?;
        Ok(Empty::new())
    }

    async fn remove_stale_virtiofs_share_mounts(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::RemoveStaleVirtiofsShareMountsRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "remove_stale_virtiofs_share_mounts", req);
        is_allowed(&req).await?;
        let mount_infos = parse_mount_table("/proc/self/mountinfo").map_ttrpc_err(same)?;
        for m in &mount_infos {
            if m.mount_point.starts_with(KATA_GUEST_SHARE_DIR) {
                // stat the mount point, virtiofs daemon will remove the stale cache and release the fds if the mount point doesn't exist any more.
                // More details in https://github.com/kata-containers/kata-containers/issues/6455#issuecomment-1477137277
                match stat::stat(Path::new(&m.mount_point)) {
                    Ok(_) => info!(sl(), "stat {} success", m.mount_point),
                    Err(e) => info!(sl(), "stat {} failed: {}", m.mount_point, e),
                }
            }
        }

        Ok(Empty::new())
    }

    async fn write_stdin(
        &self,
        _ctx: &TtrpcContext,
        req: protocols::agent::WriteStreamRequest,
    ) -> ttrpc::Result<WriteStreamResponse> {
        is_allowed(&req).await?;
        self.do_write_stream(req).await.map_ttrpc_err(same)
    }

    async fn read_stdout(
        &self,
        _ctx: &TtrpcContext,
        req: protocols::agent::ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        self.do_read_stream_gated(&req, true).await
    }

    async fn read_stderr(
        &self,
        _ctx: &TtrpcContext,
        req: protocols::agent::ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        self.do_read_stream_gated(&req, false).await
    }

    async fn close_stdin(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::CloseStdinRequest,
    ) -> ttrpc::Result<Empty> {
        // The stdin will be closed when EOF is got in rpc `write_stdin`[runtime-rs]
        // so this rpc will not be called anymore by runtime-rs.

        trace_rpc_call!(ctx, "close_stdin", req);
        is_allowed(&req).await?;

        let cid = req.container_id;
        let eid = req.exec_id;
        let mut sandbox = self.sandbox.lock().await;

        let p = sandbox
            .find_container_process(cid.as_str(), eid.as_str())
            .map_err(sandbox_err_to_ttrpc)?;

        p.close_stdin().await;

        Ok(Empty::new())
    }

    async fn tty_win_resize(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::TtyWinResizeRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "tty_win_resize", req);
        is_allowed(&req).await?;

        let mut sandbox = self.sandbox.lock().await;
        let p = sandbox
            .find_container_process(req.container_id(), req.exec_id())
            .map_err(sandbox_err_to_ttrpc)?;

        let fd = p
            .term_master
            .map_ttrpc_err(ttrpc::Code::UNAVAILABLE, "no tty")?;
        let win = winsize {
            ws_row: req.row as c_ushort,
            ws_col: req.column as c_ushort,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let err = unsafe { libc::ioctl(fd, TIOCSWINSZ, &win) };
        Errno::result(err)
            .map(drop)
            .map_ttrpc_err(|e| format!("ioctl error: {e:?}"))?;

        Ok(Empty::new())
    }

    async fn update_interface(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::UpdateInterfaceRequest,
    ) -> ttrpc::Result<Interface> {
        trace_rpc_call!(ctx, "update_interface", req);
        is_allowed(&req).await?;
        #[cfg(feature = "strict-policy")]
        net_phase_authorize(kata_security_reference_monitor::NetOp::ConfigureInterface).await?;

        let interface = req.interface.into_option().map_ttrpc_err(
            ttrpc::Code::INVALID_ARGUMENT,
            "empty update interface request",
        )?;

        // For network devices passed, check for the network interface
        // to be available first.
        if !interface.devicePath.is_empty() {
            #[cfg(not(target_arch = "s390x"))]
            {
                let (root_complex, pcipath) = pcipath_from_dev_tree_path(&interface.devicePath)
                    .map_ttrpc_err(|e| {
                        format!("Invalid PCI path for network interface: {:?}", e)
                    })?;
                wait_for_pci_net_interface(&self.sandbox, root_complex, &pcipath)
                    .await
                    .map_ttrpc_err(|e| format!("interface not available: {e:?}"))?;
            }
            #[cfg(target_arch = "s390x")]
            {
                let ccw_dev = ccw::Device::from_str(&interface.devicePath).map_ttrpc_err(|e| {
                    format!("Unexpected CCW path for network interface: {e:?}")
                })?;
                wait_for_ccw_net_interface(&self.sandbox, &ccw_dev)
                    .await
                    .map_ttrpc_err(|e| format!("interface not available: {e:?}"))?;
            }
        }

        let mut sandbox = self.sandbox.lock().await;

        #[cfg(not(target_arch = "s390x"))]
        if !interface.devicePath.is_empty() && !interface.hwAddr.is_empty() {
            match sandbox
                .rtnl
                .netdev_name_from_pci_path(&interface.devicePath)
            {
                Ok(Some(netdev_name)) => {
                    if let Err(err) = sandbox
                        .rtnl
                        .set_link_mac_by_name(&netdev_name, &interface.hwAddr)
                        .await
                    {
                        warn!(
                            sl(),
                            "update_interface: VFIO MAC reconciliation failed, fallback to by-MAC lookup";
                            "device-path" => interface.devicePath.as_str(),
                            "target-mac" => interface.hwAddr.as_str(),
                            "netdev" => netdev_name.as_str(),
                            "error" => format!("{:?}", err),
                        );
                    }
                }
                Ok(None) => {
                    info!(
                        sl(),
                        "update_interface: no netdev found for PCI path before by-MAC lookup";
                        "device-path" => interface.devicePath.as_str(),
                        "target-mac" => interface.hwAddr.as_str(),
                    );
                }
                Err(err) => {
                    warn!(
                        sl(),
                        "update_interface: unable to resolve netdev from PCI path, fallback to by-MAC lookup";
                        "device-path" => interface.devicePath.as_str(),
                        "target-mac" => interface.hwAddr.as_str(),
                        "error" => format!("{:?}", err),
                    );
                }
            }
        }

        sandbox
            .rtnl
            .update_interface(&interface)
            .await
            .map_ttrpc_err(|e| format!("update interface: {e:?}"))?;

        Ok(interface)
    }

    async fn update_routes(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::UpdateRoutesRequest,
    ) -> ttrpc::Result<Routes> {
        trace_rpc_call!(ctx, "update_routes", req);
        is_allowed(&req).await?;
        #[cfg(feature = "strict-policy")]
        net_phase_authorize(kata_security_reference_monitor::NetOp::ConfigureRoutes).await?;

        let new_routes = req
            .routes
            .into_option()
            .map(|r| r.Routes)
            .map_ttrpc_err(ttrpc::Code::INVALID_ARGUMENT, "empty update routes request")?;

        let mut sandbox = self.sandbox.lock().await;

        sandbox
            .rtnl
            .update_routes(new_routes)
            .await
            .map_ttrpc_err(|e| format!("Failed to update routes: {e:?}"))?;

        let list = sandbox
            .rtnl
            .list_routes()
            .await
            .map_ttrpc_err(|e| format!("Failed to list routes after update: {e:?}"))?;

        Ok(protocols::agent::Routes {
            Routes: list,
            ..Default::default()
        })
    }

    async fn update_ephemeral_mounts(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::UpdateEphemeralMountsRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "update_mounts", req);
        is_allowed(&req).await?;

        update_ephemeral_mounts(sl(), &req.storages, &self.sandbox)
            .await
            .map_ttrpc_err(|e| format!("Failed to update mounts: {e:?}"))?;
        Ok(Empty::new())
    }

    async fn get_ip_tables(
        &self,
        ctx: &TtrpcContext,
        req: GetIPTablesRequest,
    ) -> ttrpc::Result<GetIPTablesResponse> {
        trace_rpc_call!(ctx, "get_iptables", req);
        is_allowed(&req).await?;

        info!(sl(), "get_ip_tables: request received");

        // the binary could exists in either /usr/sbin or /sbin
        // here check both of the places and return the one exists
        // if none exists, return the /sbin one, and the rpc will
        // returns an internal error
        let cmd = if req.is_ipv6 {
            if Path::new(USR_IP6TABLES_SAVE).exists() {
                USR_IP6TABLES_SAVE
            } else {
                IP6TABLES_SAVE
            }
        } else if Path::new(USR_IPTABLES_SAVE).exists() {
            USR_IPTABLES_SAVE
        } else {
            IPTABLES_SAVE
        }
        .to_string();

        let output = Command::new(cmd.clone())
            .output()
            .map_ttrpc_err_do(|e| warn!(sl(), "failed to run {}: {:?}", cmd, e.kind()))?;
        Ok(GetIPTablesResponse {
            data: output.stdout,
            ..Default::default()
        })
    }

    async fn set_ip_tables(
        &self,
        ctx: &TtrpcContext,
        req: SetIPTablesRequest,
    ) -> ttrpc::Result<SetIPTablesResponse> {
        trace_rpc_call!(ctx, "set_iptables", req);
        is_allowed(&req).await?;
        #[cfg(feature = "strict-policy")]
        net_phase_authorize(kata_security_reference_monitor::NetOp::ConfigureIptables).await?;

        info!(sl(), "set_ip_tables request received");

        // the binary could exists in both /usr/sbin and /sbin
        // here check both of the places and return the one exists
        // if none exists, return the /sbin one, and the rpc will
        // returns an internal error
        let cmd = if req.is_ipv6 {
            if Path::new(USR_IP6TABLES_RESTORE).exists() {
                USR_IP6TABLES_RESTORE
            } else {
                IP6TABLES_RESTORE
            }
        } else if Path::new(USR_IPTABLES_RESTORE).exists() {
            USR_IPTABLES_RESTORE
        } else {
            IPTABLES_RESTORE
        }
        .to_string();

        let mut child = Command::new(cmd.clone())
            .arg("--wait")
            .arg(IPTABLES_RESTORE_WAIT_SEC.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_ttrpc_err_do(|e| warn!(sl(), "failure to spawn {}: {:?}", cmd, e.kind()))?;

        let mut stdin = match child.stdin.take() {
            Some(si) => si,
            None => {
                println!("failed to get stdin from child");
                return Err(ttrpc_error(
                    ttrpc::Code::INTERNAL,
                    "failed to take stdin from child",
                ));
            }
        };

        let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
        let handle = tokio::spawn(async move {
            let _ = match stdin.write_all(&req.data) {
                Ok(o) => o,
                Err(e) => {
                    warn!(sl(), "error writing stdin: {:?}", e.kind());
                    return;
                }
            };
            if tx.send(1).is_err() {
                warn!(sl(), "stdin writer thread receiver dropped");
            };
        });

        let _ = tokio::time::timeout(Duration::from_secs(IPTABLES_RESTORE_WAIT_SEC), rx)
            .await
            .map_ttrpc_err(|_| "timeout waiting for stdin writer to complete")?;

        handle
            .await
            .map_ttrpc_err(|_| "stdin writer thread failure")?;

        let output = child.wait_with_output().map_ttrpc_err_do(|e| {
            warn!(
                sl(),
                "failure waiting for spawned {} to complete: {:?}",
                cmd,
                e.kind()
            )
        })?;

        if !output.status.success() {
            warn!(sl(), "{} failed: {:?}", cmd, output.stderr);
            return Err(ttrpc_error(
                ttrpc::Code::INTERNAL,
                format!(
                    "{} failed: {:?}",
                    cmd,
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        Ok(SetIPTablesResponse {
            data: output.stdout,
            ..Default::default()
        })
    }

    async fn list_interfaces(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::ListInterfacesRequest,
    ) -> ttrpc::Result<Interfaces> {
        trace_rpc_call!(ctx, "list_interfaces", req);
        is_allowed(&req).await?;

        let list = self
            .sandbox
            .lock()
            .await
            .rtnl
            .list_interfaces()
            .await
            .map_ttrpc_err(|e| format!("Failed to list interfaces: {e:?}"))?;

        Ok(protocols::agent::Interfaces {
            Interfaces: list,
            ..Default::default()
        })
    }

    async fn list_routes(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::ListRoutesRequest,
    ) -> ttrpc::Result<Routes> {
        trace_rpc_call!(ctx, "list_routes", req);
        is_allowed(&req).await?;

        let list = self
            .sandbox
            .lock()
            .await
            .rtnl
            .list_routes()
            .await
            .map_ttrpc_err(|e| format!("list routes: {e:?}"))?;

        Ok(protocols::agent::Routes {
            Routes: list,
            ..Default::default()
        })
    }

    async fn create_sandbox(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::CreateSandboxRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "create_sandbox", req);
        is_allowed(&req).await?;

        {
            let mut s = self.sandbox.lock().await;

            let _ = fs::remove_dir_all(CONTAINER_BASE);
            let _ = fs::create_dir_all(CONTAINER_BASE);

            s.hostname = req.hostname.clone();
            s.running = true;

            if !req.sandbox_id.is_empty() {
                s.id = req.sandbox_id.clone();
            }

            for m in req.kernel_modules.iter() {
                load_kernel_module(m).map_ttrpc_err(same)?;
            }

            s.setup_shared_namespaces().await.map_ttrpc_err(same)?;
        }

        let m = add_storages(sl(), req.storages.clone(), &self.sandbox, None)
            .await
            .map_ttrpc_err(same)?;
        self.sandbox.lock().await.mounts = m;

        // Scan guest hooks upon creating new sandbox and append
        // them to guest OCI spec before running containers.
        {
            let mut s = self.sandbox.lock().await;
            if !req.guest_hook_path.is_empty() {
                let _ = s.add_hooks(&req.guest_hook_path).map_err(|e| {
                    error!(
                        sl(),
                        "add guest hook {} failed: {:?}", req.guest_hook_path, e
                    );
                });
            }
        }

        setup_guest_dns(sl(), &req.dns).map_ttrpc_err(same)?;
        {
            let mut s = self.sandbox.lock().await;
            for dns in req.dns {
                s.network.set_dns(dns);
            }
        }

        // FR-14: sandbox networking is now being set up; enter the setup phase in which
        // network-mutating RPCs are permitted.
        #[cfg(feature = "strict-policy")]
        crate::NET_PHASE.lock().await.to_sandbox_setup();

        Ok(Empty::new())
    }

    async fn destroy_sandbox(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::DestroySandboxRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "destroy_sandbox", req);
        is_allowed(&req).await?;

        let mut sandbox = self.sandbox.lock().await;
        // destroy all containers, clean up, notify agent to exit etc.
        sandbox.destroy().await.map_ttrpc_err(same)?;
        // Close get_oom_event connection,
        // otherwise it will block the shutdown of ttrpc.
        drop(sandbox.event_tx.take());

        sandbox
            .sender
            .take()
            .map_ttrpc_err(
                ttrpc::Code::INTERNAL,
                "failed to get sandbox sender channel",
            )?
            .send(1)
            .map_ttrpc_err(same)?;

        Ok(Empty::new())
    }

    async fn add_arp_neighbors(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::AddARPNeighborsRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "add_arp_neighbors", req);
        is_allowed(&req).await?;
        #[cfg(feature = "strict-policy")]
        net_phase_authorize(kata_security_reference_monitor::NetOp::ConfigureArp).await?;

        let neighs = req
            .neighbors
            .into_option()
            .map(|n| n.ARPNeighbors)
            .map_ttrpc_err(
                ttrpc::Code::INVALID_ARGUMENT,
                "empty add arp neighbours request",
            )?;

        self.sandbox
            .lock()
            .await
            .rtnl
            .add_arp_neighbors(neighs)
            .await
            .map_ttrpc_err(|e| format!("Failed to add ARP neighbours: {e:?}"))?;

        Ok(Empty::new())
    }

    async fn online_cpu_mem(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::OnlineCPUMemRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "online_cpu_mem", req);
        is_allowed(&req).await?;
        let sandbox = self.sandbox.lock().await;

        sandbox.online_cpu_memory(&req).map_ttrpc_err(same)?;

        Ok(Empty::new())
    }

    async fn reseed_random_dev(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::ReseedRandomDevRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "reseed_random_dev", req);
        is_allowed(&req).await?;

        random::reseed_rng(req.data.as_slice()).map_ttrpc_err(same)?;

        Ok(Empty::new())
    }

    async fn get_guest_details(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::GuestDetailsRequest,
    ) -> ttrpc::Result<GuestDetailsResponse> {
        trace_rpc_call!(ctx, "get_guest_details", req);
        is_allowed(&req).await?;

        info!(sl(), "get guest details!");
        let mut resp = GuestDetailsResponse::new();
        // to get memory block size
        let (u, v) = get_memory_info(
            req.mem_block_size,
            req.mem_hotplug_probe,
            SYSFS_MEMORY_BLOCK_SIZE_PATH,
            SYSFS_MEMORY_HOTPLUG_PROBE_PATH,
        )
        .map_ttrpc_err_do(|_| info!(sl(), "fail to get memory info!"))?;

        resp.mem_block_size_bytes = u;
        resp.support_mem_hotplug_probe = v;

        // to get agent details
        let detail = get_agent_details();
        resp.agent_details = MessageField::some(detail);

        Ok(resp)
    }

    async fn mem_hotplug_by_probe(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::MemHotplugByProbeRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "mem_hotplug_by_probe", req);
        is_allowed(&req).await?;

        do_mem_hotplug_by_probe(&req.memHotplugProbeAddr).map_ttrpc_err(same)?;

        Ok(Empty::new())
    }

    async fn set_guest_date_time(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::SetGuestDateTimeRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "set_guest_date_time", req);
        is_allowed(&req).await?;

        do_set_guest_date_time(req.Sec, req.Usec).map_ttrpc_err(same)?;

        Ok(Empty::new())
    }

    async fn copy_file(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::CopyFileRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "copy_file", req);

        // FR-10: the generic host->guest file write lets the host choose both the bytes and
        // the destination path, and the content is not policy-measured. Strict builds refuse
        // it outright, without a policy round trip, so no policy-authoring mistake can
        // re-open it. The traffic the runtime still needs goes through the typed content
        // channel (copy_single_file / init_watchable_volume / put_volume_file /
        // commit_volume_revision), where the guest -- not the host -- chooses the
        // destination.
        #[cfg(feature = "strict-policy")]
        {
            let _ = &req;
            return Err(ttrpc_error(
                ttrpc::Code::PERMISSION_DENIED,
                anyhow!("the generic CopyFile RPC is disabled in strict mode"),
            ));
        }

        #[cfg(not(feature = "strict-policy"))]
        {
            #[cfg(feature = "agent-policy")]
            {
                let req_for_policy: PolicyCopyFileRequest = (&req)
                    .try_into()
                    .context("parsing CopyFileRequest for policy")
                    .map_ttrpc_err(same)?;
                is_allowed_with_entrypoint(req.descriptor_dyn().name(), &req_for_policy).await?;
            }
            #[cfg(not(feature = "agent-policy"))]
            is_allowed(&req).await?;

            // Potentially untrustworthy data from the host needs to go into the shared dir.
            let root_path = PathBuf::from(KATA_GUEST_SHARE_DIR);
            do_copy_file(&req, &root_path).map_ttrpc_err(same)?;

            Ok(Empty::new())
        }
    }

    async fn resize_volume(
        &self,
        ctx: &TtrpcContext,
        req: ResizeVolumeRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "resize_volume", req);
        is_allowed(&req).await?;

        Err(ttrpc_error(
            ttrpc::Code::UNIMPLEMENTED,
            "resize_volume is not implemented in kata-agent",
        ))
    }

    async fn copy_single_file(
        &self,
        ctx: &TtrpcContext,
        req: CopySingleFileRequest,
    ) -> ttrpc::Result<protocols::agent::CopySingleFileResponse> {
        trace_rpc_call!(ctx, "copy_single_file", req);
        // The raw request carries the file payload and a bare `file_mode`. Hand the policy
        // the pre-processed view instead: it drops `data` and decodes the S_IFMT bits, so a
        // rule can tell a regular-file write apart from a symlink creation and can see where
        // that symlink would point. See PolicyCopySingleFileRequest.
        // The payload is stripped before policy evaluation; the S_IFREG guard below is
        // policy-independent.
        #[cfg(feature = "agent-policy")]
        {
            let req_for_policy = PolicyCopySingleFileRequest::from(&req);
            is_allowed_with_entrypoint(req.descriptor_dyn().name(), &req_for_policy).await?;
        }
        #[cfg(not(feature = "agent-policy"))]
        is_allowed(&req).await?;

        if stat::SFlag::from_bits_truncate(req.file_mode) != stat::SFlag::S_IFREG {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "copy single file source is not a regular file",
            ));
        }

        let target_file_name = match req.file_type.enum_value_or_default() {
            SingleFileType::SINGLE_FILE_TYPE_UNSPECIFIED
                if req.data_size == 0 && req.data.is_empty() => "empty-file",
            SingleFileType::SINGLE_FILE_TYPE_RESOLV_CONF => "resolv.conf",
            SingleFileType::SINGLE_FILE_TYPE_ETC_HOSTS => "hosts",
            SingleFileType::SINGLE_FILE_TYPE_HOSTNAME => "hostname",
            _ => {
                return Err(ttrpc_error(
                    ttrpc::Code::INVALID_ARGUMENT,
                    "invalid single file type",
                ));
            }
        };

        if req.data_size != req.data.len() as i64 {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "data_size mismatch",
            ));
        }

        // `sandbox_id` is host-supplied and is joined into the destination path below.
        // `do_copy_file` confines writes to the shared directory, but `pathrs` clamps a
        // leading `..` at the root rather than rejecting it, so without this check a host
        // could still redirect the write out of its own per-sandbox subdirectory and over
        // another sandbox's single-file content. The sibling handlers validate every
        // host-supplied path component the same way.
        let sandbox_id = Path::new(&req.sandbox_id);
        if !is_safe_relative_path(sandbox_id) {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "invalid sandbox_id",
            ));
        }

        let agent_file_id = Path::new("single-files")
            .join(&req.sandbox_id)
            .join(target_file_name);
        let target_path = guest_share_dir_path().join(&agent_file_id);
        let copy_req = CopyFileRequest {
            path: target_path.to_string_lossy().to_string(),
            file_size: req.data_size,
            file_mode: req.file_mode,
            dir_mode: 0o755,
            uid: req.uid,
            gid: req.gid,
            offset: 0,
            data: req.data,
            ..Default::default()
        };

        do_copy_file(&copy_req, &guest_share_dir_path())
            .map_ttrpc_err(|e| format!("copy_single_file failed: {e:?}"))?;

        let mut resp = protocols::agent::CopySingleFileResponse::new();
        resp.agent_file_id = agent_file_id.to_string_lossy().to_string();
        Ok(resp)
    }

    async fn init_volume(
        &self,
        ctx: &TtrpcContext,
        req: InitVolumeRequest,
    ) -> ttrpc::Result<InitVolumeResponse> {
        trace_rpc_call!(ctx, "init_volume", req);
        is_allowed(&req).await?;

        let agent_volume_id = format!(
            "volume-{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_ttrpc_err(same)?
                .as_nanos()
        );
        let root = volume_root_path(&agent_volume_id).map_ttrpc_err(same)?;
        std::fs::create_dir_all(&root).map_ttrpc_err(same)?;

        VOLUMES
            .lock()
            .map_ttrpc_err(|_| "failed to lock watchable volume map")?
            .insert(agent_volume_id.clone(), VolumeState::default());

        let mut resp = InitVolumeResponse::new();
        resp.agent_volume_id = agent_volume_id;
        Ok(resp)
    }

    async fn put_volume_file_revision(
        &self,
        ctx: &TtrpcContext,
        req: PutVolumeFileRevisionRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "put_volume_file_revision", req);
        // See copy_single_file: the policy gets the request without the file payload.
        #[cfg(feature = "agent-policy")]
        {
            let req_for_policy = PolicyPutVolumeFileRevisionRequest::from(&req);
            is_allowed_with_entrypoint(req.descriptor_dyn().name(), &req_for_policy).await?;
        }
        #[cfg(not(feature = "agent-policy"))]
        is_allowed(&req).await?;

        if stat::SFlag::from_bits_truncate(req.file_mode) != stat::SFlag::S_IFREG {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "put volume file source is not a regular file",
            ));
        }

        if req.revision.is_empty() {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "revision cannot be empty",
            ));
        }

        if req.file_size != req.data.len() as i64 {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "file_size mismatch",
            ));
        }

        let file_name = Path::new(&req.file_name);
        if !is_safe_relative_path(file_name) {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "invalid file_name",
            ));
        }

        let revision = Path::new(&req.revision);
        if !is_safe_relative_path(revision) {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "invalid revision",
            ));
        }

        {
            let mut map = VOLUMES
                .lock()
                .map_ttrpc_err(|_| "failed to lock watchable volume map")?;
            let state = map
                .get_mut(&req.agent_volume_id)
                .map_ttrpc_err(ttrpc::Code::NOT_FOUND, "unknown agent_volume_id")?;
            if let Some(existing) = &state.pending_revision {
                if existing != &req.revision {
                    return Err(ttrpc_error(
                        ttrpc::Code::INVALID_ARGUMENT,
                        "mixed revisions for one pending watchable volume update",
                    ));
                }
            } else {
                state.pending_revision = Some(req.revision.clone());
            }
        }

        let volume_root = volume_root_path(&req.agent_volume_id).map_ttrpc_err(same)?;
        std::fs::create_dir_all(&volume_root).map_ttrpc_err(same)?;

        let revision_root = volume_root.join(revision);
        create_watchable_directory(&revision_root, req.dir_mode, req.uid, req.gid)
            .map_ttrpc_err(same)?;

        let target_file = revision_root.join(file_name);
        let copy_file_req = CopyFileRequest {
            path: target_file.to_string_lossy().to_string(),
            file_size: req.file_size,
            file_mode: req.file_mode,
            dir_mode: req.dir_mode,
            uid: req.uid,
            gid: req.gid,
            offset: req.offset,
            data: req.data,
            ..Default::default()
        };
        do_copy_file(&copy_file_req, &guest_share_dir_path()).map_ttrpc_err(same)?;

        let root_link = volume_root.join(file_name);
        let link_target = Path::new("data")
            .join(file_name)
            .to_string_lossy()
            .into_owned();
        let link_req = CopyFileRequest {
            path: root_link.to_string_lossy().to_string(),
            file_size: link_target.len() as i64,
            file_mode: stat::SFlag::S_IFLNK.bits(),
            dir_mode: req.dir_mode,
            uid: req.uid,
            gid: req.gid,
            offset: 0,
            data: link_target.into_bytes(),
            ..Default::default()
        };
        do_copy_file(&link_req, &guest_share_dir_path()).map_ttrpc_err(same)?;

        Ok(Empty::new())
    }

    async fn commit_volume_revision(
        &self,
        ctx: &TtrpcContext,
        req: CommitVolumeRevisionRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "commit_volume_revision", req);
        is_allowed(&req).await?;

        let volume_root = volume_root_path(&req.agent_volume_id).map_ttrpc_err(same)?;

        let (pending_revision, previous_revision) = {
            let mut map = VOLUMES
                .lock()
                .map_ttrpc_err(|_| "failed to lock watchable volume map")?;
            let state = map
                .get_mut(&req.agent_volume_id)
                .map_ttrpc_err(ttrpc::Code::NOT_FOUND, "unknown agent_volume_id")?;
            let Some(pending) = state.pending_revision.clone() else {
                return Ok(Empty::new());
            };
            let previous = state.current_revision.clone();
            state.current_revision = Some(pending.clone());
            state.pending_revision = None;
            (pending, previous)
        };

        let data_link = volume_root.join("data");
        let data_req = CopyFileRequest {
            path: data_link.to_string_lossy().to_string(),
            file_size: pending_revision.len() as i64,
            file_mode: stat::SFlag::S_IFLNK.bits(),
            dir_mode: 0o750,
            uid: unistd::getuid().as_raw() as i32,
            gid: unistd::getgid().as_raw() as i32,
            offset: 0,
            data: pending_revision.clone().into_bytes(),
            ..Default::default()
        };
        do_copy_file(&data_req, &guest_share_dir_path()).map_ttrpc_err(same)?;

        if req.garbage_collect_previous {
            if let Some(prev) = previous_revision {
                if prev != pending_revision {
                    let old_revision_path = volume_root.join(prev);
                    let _ = std::fs::remove_dir_all(old_revision_path);
                }
            }
        }

        Ok(Empty::new())
    }

    async fn get_metrics(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::GetMetricsRequest,
    ) -> ttrpc::Result<Metrics> {
        trace_rpc_call!(ctx, "get_metrics", req);
        is_allowed(&req).await?;

        let s = get_metrics(&req).map_ttrpc_err(same)?;
        let mut metrics = Metrics::new();
        metrics.set_metrics(s);
        Ok(metrics)
    }

    async fn get_oom_event(
        &self,
        _ctx: &TtrpcContext,
        req: protocols::agent::GetOOMEventRequest,
    ) -> ttrpc::Result<OOMEvent> {
        is_allowed(&req).await?;
        let event_rx = {
            let s = self.sandbox.lock().await;
            s.event_rx.clone()
        };
        let mut event_rx = event_rx.lock().await;

        let container_id = event_rx
            .recv()
            .await
            .map_ttrpc_err(ttrpc::Code::INTERNAL, "")?;

        info!(sl(), "get_oom_event return {}", &container_id);

        let mut resp = OOMEvent::new();
        resp.container_id = container_id;
        Ok(resp)
    }

    async fn get_volume_stats(
        &self,
        ctx: &TtrpcContext,
        req: VolumeStatsRequest,
    ) -> ttrpc::Result<VolumeStatsResponse> {
        trace_rpc_call!(ctx, "get_volume_stats", req);
        is_allowed(&req).await?;

        info!(sl(), "get volume stats!");
        let mut resp = VolumeStatsResponse::new();
        let mut condition = VolumeCondition::new();

        File::open(&req.volume_guest_path)
            .map_ttrpc_err_do(|_| info!(sl(), "failed to open the volume"))?;

        condition.abnormal = false;
        condition.message = String::from("OK");

        let mut usage_vec = Vec::new();

        // to get volume capacity stats
        get_volume_capacity_stats(&req.volume_guest_path)
            .map(|u| usage_vec.push(u))
            .map_ttrpc_err(same)?;

        // to get volume inode stats
        get_volume_inode_stats(&req.volume_guest_path)
            .map(|u| usage_vec.push(u))
            .map_ttrpc_err(same)?;

        resp.usage = usage_vec;
        resp.volume_condition = MessageField::some(condition);
        Ok(resp)
    }

    async fn add_swap(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::AddSwapRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "add_swap", req);
        is_allowed(&req).await?;

        do_add_swap(&self.sandbox, &req).await.map_ttrpc_err(same)?;

        Ok(Empty::new())
    }

    async fn add_swap_path(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::AddSwapPathRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "add_swap_path", req);
        is_allowed(&req).await?;

        do_add_swap_path(&req).await.map_ttrpc_err(same)?;

        Ok(Empty::new())
    }

    // Policy delivery in strict builds is exclusively through initdata, which is bound to
    // the launch measurement. The `SetPolicy` RPC is a host-facing mutation channel with no
    // remaining consumer, so it is compiled out entirely rather than merely denied by the
    // baseline: a strict agent returns the ttRPC default (unimplemented). Note this removes
    // only the RPC surface -- `AgentPolicy::set_policy()` is still what installs the policy
    // carried in initdata (see `main.rs`).
    #[cfg(all(feature = "agent-policy", not(feature = "strict-policy")))]
    async fn set_policy(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::SetPolicyRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "set_policy", req);

        do_set_policy(&req).await?;

        Ok(Empty::new())
    }

    // FR-1: load a signed, add-only policy fragment. Present only in strict builds; a
    // non-strict agent returns the ttRPC default (unimplemented). The request is both
    // policy-gated (the active policy must permit fragment loading) and cryptographically
    // verified by the fragment store (issuer signature, monotonic SVN, add-only /
    // fail-closed, transparency receipt).
    #[cfg(feature = "strict-policy")]
    async fn load_policy_fragment(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::LoadPolicyFragmentRequest,
    ) -> ttrpc::Result<Empty> {
        trace_rpc_call!(ctx, "load_policy_fragment", req);
        is_allowed(&req).await?;

        // F-151: a fragment must arrive as a COSE_Sign1 envelope, and may not be described
        // by the caller. runtime-rs -- the only production courier -- carries nothing else:
        // its LoadPolicyFragmentRequest holds the envelope and the receipt fields and
        // deliberately no issuer/feed/SVN, "so the host cannot describe a fragment into
        // being something it is not". Honouring the described fields anyway made the guest's
        // acceptance strictly broader than the courier's expression, and the party on the
        // other end of this socket is the untrusted host.
        //
        // This was never a signature bypass -- a described fragment still had to carry a
        // valid issuer signature over the statement, which the host cannot forge. What it
        // cost was format surface: the bespoke signable statement exists only to give an
        // envelope-free path something to sign.
        if req.cose_sign1.is_empty() {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                "policy fragment must carry a cose_sign1 envelope".to_string(),
            ));
        }
        if let Some(name) = caller_described_fragment_field(&req) {
            return Err(ttrpc_error(
                ttrpc::Code::INVALID_ARGUMENT,
                format!(
                    "policy fragment field {name:?} is derived from the cose_sign1 envelope \
                     and must not be set by the caller"
                ),
            ));
        }

        // Everything the issuer signed comes out of the envelope. The receipt fields are not
        // covered by the issuer signature -- they are countersignatures over the same signed
        // bytes -- so they still come from the request and are verified separately.
        //
        // FR-1a: verify -> apply -> commit, atomically. Verification does not mutate the
        // fragment store; the module is applied to the live policy engine only after it
        // verifies, and the store's SVN/grant state is committed only after the apply
        // succeeds. A failed apply leaves both the engine and the store unchanged.
        //
        // F-159: "atomically" is only true while this guard is held. The individual store
        // locks below are taken and dropped three separate times, and the apply runs under a
        // different lock entirely, so without serializing the whole sequence two concurrent
        // loads interleave: both pass the SVN gate against the same pre-state, the later
        // apply wins the engine, and the later commit sets the high-water mark -- which lets
        // an older fragment both take effect and lower the floor.
        let _load_txn = crate::FRAGMENT_LOAD.lock().await;

        // FR-1d: if the envelope carries an x5chain (or x509 is required), the SRM verifies
        // the did:x509 certificate-chain identity. That routing lives in the SRM so that
        // every caller gets it, and so no caller can pick the weaker path.
        let extra_receipts = parse_extra_receipts(&req.extra_receipts)?;
        let verified = {
            let store = crate::FRAGMENTS.lock().await;
            store
                .verify_envelope_with(&req.cose_sign1, |f| {
                    f.receipt = (!req.receipt.is_empty()).then(|| req.receipt.clone());
                    f.receipt_ledger =
                        (!req.receipt_ledger.is_empty()).then(|| req.receipt_ledger.clone());
                    f.receipt_proof =
                        (!req.receipt_proof.is_empty()).then(|| req.receipt_proof.clone());
                    f.extra_receipts = extra_receipts;
                })
                .map_err(|e| ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e))?
        };

        // FR-1c: the fragment's own `includes` says where it *wants* to contribute; the
        // measured policy says where it *may*. Take the intersection, so neither side can
        // widen the other, and honour a grant that withholds module injection entirely.
        //
        // Without this the fragment was the sole authority over its own namespace, which
        // let any trust-root-authorized issuer populate a namespace the base policy meant a
        // different issuer to fill (F-62). hcsshim reads `includes` off the matched
        // candidate declaration for exactly this reason.
        let scope = {
            let store = crate::FRAGMENTS.lock().await;
            store.module_scope(&verified.issuer, &verified.feed)
        };

        let fragment_package = match &verified.policy_module {
            Some(module) if scope.allow_module => {
                let effective = crate::policy_fragments::effective_namespaces(
                    &scope.namespaces,
                    &verified.includes,
                );
                Some(
                    crate::AGENT_POLICY
                        .lock()
                        .await
                        .apply_fragment_module(
                            &format!("fragment:{}:{}", verified.issuer, verified.svn),
                            module,
                            &verified.feed,
                            &effective,
                            scope.parameters.as_deref(),
                            &verified.issuer,
                            verified.svn,
                        )
                        .map_err(|e| ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e))?,
                )
            }
            Some(_) => {
                info!(
                    sl(),
                    "policy-fragments: fragment {} accepted but its module was not applied — \
                     the measured grant for this feed sets allow_module = false",
                    verified.feed
                );
                None
            }
            None => None,
        };

        // FR-1i: persist the SVN high-water marks after commit so an agent restart cannot
        // reopen a rollback window. The store on the (encrypted-scratch / sealed) path is
        // re-imported at boot by seed_fragment_trust_root.
        {
            let mut store = crate::FRAGMENTS.lock().await;
            store.commit(&verified);
            crate::persist_fragment_svn_state(&store.export_svn_state());
        }

        // BL-8: this delivery may satisfy a fragment the measured base policy declared.
        // Cross-check it against that declaration — a valid signature over the wrong issuer,
        // or an SVN under the measured per-feed floor, must not clear the requirement.
        // Deliberately after commit, so the SVN/ordering chain still advances exactly as it
        // does for any other verified fragment; this gate governs whether containers may
        // start, not whether the fragment was genuine.
        crate::policy_fragments::satisfy_declared_fragment(
            &verified.issuer,
            &verified.feed,
            verified.svn,
        )
        .await
        .map_err(|e| ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e))?;

        // BL-8: a fragment may carry fragment declarations of its own, in its signed module.
        // They are honoured only if the declaration that authorized *this* fragment enabled
        // delegation, and only within the issuer scope it set; everything else is dropped.
        //
        // Read after commit and injection so the declarations come from the module the
        // engine actually accepted, and so a fragment that failed verification never gets to
        // influence the feed allow-list.
        if let Some(pkg) = fragment_package {
            let nested = crate::AGENT_POLICY
                .lock()
                .await
                .nested_fragment_specs(&pkg)
                .map_err(|e| ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e))?;
            crate::policy_fragments::register_nested_fragments(
                &verified.issuer,
                &verified.feed,
                nested,
            )
            .await
            .map_err(|e| ttrpc_error(ttrpc::Code::FAILED_PRECONDITION, e))?;
        }

        Ok(Empty::new())
    }

    async fn get_diagnostic_data(
        &self,
        ctx: &TtrpcContext,
        req: protocols::agent::GetDiagnosticDataRequest,
    ) -> ttrpc::Result<protocols::agent::GetDiagnosticDataResponse> {
        trace_rpc_call!(ctx, "get_diagnostic_data", req);

        // FR-7: guest diagnostics are an un-mediated data-exfiltration surface and are
        // disabled in strict confidential builds.
        #[cfg(feature = "strict-policy")]
        {
            let _ = &req;
            return Err(ttrpc_error(
                ttrpc::Code::PERMISSION_DENIED,
                anyhow!("guest diagnostics are disabled in strict mode"),
            ));
        }

        #[cfg(not(feature = "strict-policy"))]
        {
            is_allowed(&req).await?;

            match req.log_type.as_str() {
                "termination_log" => self
                    .do_read_termination_log(&req.container_id)
                    .await
                    .map_ttrpc_err(same),
                other => Err(ttrpc_error(
                    ttrpc::Code::INVALID_ARGUMENT,
                    format!("unsupported diagnostic log_type: {other}"),
                )),
            }
        }
    }

    async fn mem_agent_memcg_set(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        config: protocols::agent::MemAgentMemcgConfig,
    ) -> ::ttrpc::Result<Empty> {
        is_allowed(&config).await?;
        if let Some(ma) = &self.oma {
            ma.memcg_set_config_async(mem_agent_memcgconfig_to_memcg_optionconfig(&config))
                .await
                .map_err(|e| {
                    let estr = format!("ma.memcg_set_config_async fail: {e}");
                    error!(sl(), "{}", estr);
                    ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::INTERNAL, estr))
                })?;
        } else {
            let estr = "mem-agent is disabled";
            error!(sl(), "{}", estr);
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::INTERNAL,
                estr,
            )));
        }
        Ok(Empty::new())
    }

    async fn mem_agent_compact_set(
        &self,
        _ctx: &::ttrpc::r#async::TtrpcContext,
        config: protocols::agent::MemAgentCompactConfig,
    ) -> ::ttrpc::Result<Empty> {
        is_allowed(&config).await?;
        if let Some(ma) = &self.oma {
            ma.compact_set_config_async(mem_agent_compactconfig_to_compact_optionconfig(&config))
                .await
                .map_err(|e| {
                    let estr = format!("ma.compact_set_config_async fail: {e}");
                    error!(sl(), "{}", estr);
                    ttrpc::Error::RpcStatus(ttrpc::get_status(ttrpc::Code::INTERNAL, estr))
                })?;
        } else {
            let estr = "mem-agent is disabled";
            error!(sl(), "{}", estr);
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::INTERNAL,
                estr,
            )));
        }
        Ok(Empty::new())
    }
}

#[derive(Clone)]
struct HealthService;

#[async_trait]
impl health_ttrpc::Health for HealthService {
    async fn check(
        &self,
        _ctx: &TtrpcContext,
        _req: protocols::health::CheckRequest,
    ) -> ttrpc::Result<HealthCheckResponse> {
        let mut resp = HealthCheckResponse::new();
        resp.set_status(HealthCheckResponse_ServingStatus::SERVING);

        Ok(resp)
    }

    async fn version(
        &self,
        _ctx: &TtrpcContext,
        req: protocols::health::CheckRequest,
    ) -> ttrpc::Result<VersionCheckResponse> {
        info!(sl(), "version {:?}", req);
        let mut rep = protocols::health::VersionCheckResponse::new();
        rep.agent_version = AGENT_VERSION.to_string();
        rep.grpc_version = API_VERSION.to_string();

        Ok(rep)
    }
}

/// F-151: the name of the first signed field the caller tried to describe, if any.
///
/// Every field here is covered by the issuer signature and is derived from the COSE_Sign1
/// envelope, so a caller setting one is either confused or probing. Reject rather than
/// ignore: silently dropping the value would leave the caller believing it had constrained
/// a fragment it had not, which is the worse of the two failures.
///
/// `svn` is checked against 0 rather than emptiness because it is a scalar, and 0 is also
/// the proto default -- an unset field and an explicit `svn = 0` are indistinguishable on
/// the wire. That costs nothing: SVN 0 is below every floor, so a fragment claiming it
/// cannot be accepted through any path.
#[cfg(feature = "strict-policy")]
fn caller_described_fragment_field(
    req: &protocols::agent::LoadPolicyFragmentRequest,
) -> Option<&'static str> {
    [
        ("issuer", !req.issuer.is_empty()),
        ("feed", !req.feed.is_empty()),
        ("svn", req.svn != 0),
        ("grants", !req.grants.is_empty()),
        ("signature", !req.signature.is_empty()),
        ("policy_module", !req.policy_module.is_empty()),
        ("includes", !req.includes.is_empty()),
        ("requires", !req.requires.is_empty()),
        ("prev_log_head", !req.prev_log_head.is_empty()),
    ]
    .iter()
    .find_map(|&(name, present)| present.then_some(name))
}

/// FR-1f (trust list): parse `extra_receipts` wire entries of the form `<ledger>=<hex sig>`.
///
/// Ledger and signature are carried in one string rather than as parallel lists so the two
/// cannot be misaligned by a truncated or reordered request — a mismatch would silently
/// check a signature against the wrong ledger's keys. A malformed entry is rejected rather
/// than skipped: dropping it would quietly weaken a conjunctive requirement into one the
/// remaining receipts happen to satisfy.
#[cfg(feature = "strict-policy")]
fn parse_extra_receipts(entries: &[String]) -> ttrpc::Result<Vec<(String, String)>> {
    entries
        .iter()
        .map(|e| {
            let (ledger, sig) = e.split_once('=').ok_or_else(|| {
                ttrpc_error(
                    ttrpc::Code::INVALID_ARGUMENT,
                    "extra_receipts entry must be <ledger>=<hex signature>".to_string(),
                )
            })?;
            if ledger.is_empty() || sig.is_empty() {
                return Err(ttrpc_error(
                    ttrpc::Code::INVALID_ARGUMENT,
                    "extra_receipts entry has an empty ledger or signature".to_string(),
                ));
            }
            Ok((ledger.to_string(), sig.to_string()))
        })
        .collect()
}

fn get_memory_info(
    block_size: bool,
    hotplug: bool,
    block_size_path: &str,
    hotplug_probe_path: &str,
) -> Result<(u64, bool)> {
    let mut size: u64 = 0;
    let mut plug: bool = false;
    if block_size {
        match fs::read_to_string(block_size_path) {
            Ok(v) => {
                if v.is_empty() {
                    warn!(sl(), "file {} is empty", block_size_path);
                    return Err(anyhow!(ERR_INVALID_BLOCK_SIZE));
                }

                size = u64::from_str_radix(v.trim(), 16).map_err(|_| {
                    warn!(sl(), "failed to parse the str {} to hex", size);
                    anyhow!(ERR_INVALID_BLOCK_SIZE)
                })?;
            }
            Err(e) => {
                warn!(sl(), "memory block size error: {:?}", e.kind());
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(anyhow!(e));
                }
            }
        }
    }

    if hotplug {
        match stat::stat(hotplug_probe_path) {
            Ok(_) => plug = true,
            Err(e) => {
                warn!(sl(), "hotplug memory error: {:?}", e);
                match e {
                    nix::Error::ENOENT => plug = false,
                    _ => return Err(anyhow!(e)),
                }
            }
        }
    }

    Ok((size, plug))
}

fn get_volume_capacity_stats(path: &str) -> Result<VolumeUsage> {
    let mut usage = VolumeUsage::new();

    let stat = statfs::statfs(path)?;
    let block_size = stat.block_size() as u64;
    usage.total = stat.blocks() * block_size;
    usage.available = stat.blocks_free() * block_size;
    usage.used = usage.total - usage.available;
    usage.unit = VolumeUsage_Unit::BYTES.into();

    Ok(usage)
}

fn get_volume_inode_stats(path: &str) -> Result<VolumeUsage> {
    let mut usage = VolumeUsage::new();

    let stat = statfs::statfs(path)?;
    usage.total = stat.files();
    usage.available = stat.files_free();
    usage.used = usage.total - usage.available;
    usage.unit = VolumeUsage_Unit::INODES.into();

    Ok(usage)
}

pub fn have_seccomp() -> bool {
    if cfg!(feature = "seccomp") {
        return true;
    }

    false
}

// FR-6: digest of an authorized request. Used as the transaction's plan digest so the
// plan handed to execution can be verified against what policy authorized (authorized ==
// executed). Agent-internal; not sent on the wire.
#[cfg(feature = "strict-policy")]
fn plan_digest<T: serde::Serialize>(req: &T) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(req).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// FR-6: roll the policy's persisted state back to a snapshot taken before authorization.
///
/// The policy applies its `ops` (the `pstate` mutations) while it authorizes a request, so
/// a request that is authorized and then fails to execute has already changed enforcer
/// state. Restoring the snapshot is what keeps the enforcer's view of the world equal to
/// reality.
///
/// If the restore itself fails the enforcer state is no longer provable, and continuing
/// would be failing open. hcsshim's `WithMetadataRollback` panics at exactly this point;
/// the agent quarantines the reference monitor instead, which refuses all further
/// transactions.
///
/// Note that this is not as gentle as it sounds. Every SRM-gated RPC that builds or alters
/// capability is refused from here on, and the shim learns of it on its next such call --
/// as `DATA_LOSS` (RM-7), so it can tell a degraded guest from a bad request. RM-8 keeps
/// teardown working: `RemoveContainer` and a stop signal prepare as teardown transactions,
/// so the sandbox can still be shut down gracefully rather than only destroyed wholesale.
#[cfg(feature = "strict-policy")]
async fn rollback_policy_state(snapshot: &Option<PolicySnapshot>, context: &str) {
    let Some(snap) = snapshot else {
        error!(
            sl(),
            "no policy snapshot to roll back to after {}; enforcer state is unprovable", context
        );
        crate::SRM
            .lock()
            .await
            .quarantine(format!("no policy snapshot available after {context}"));
        return;
    };
    if let Err(e) = crate::AGENT_POLICY
        .lock()
        .await
        .revert_state_delta(&snap.before, &snap.after)
    {
        error!(
            sl(),
            "failed to roll back policy state after {}: {:?}", context, e
        );
        crate::SRM
            .lock()
            .await
            .quarantine(format!("policy state rollback failed after {context}"));
    }
}

/// FR-6: the policy state bracketing a single request's authorization.
///
/// `before` is captured ahead of `is_allowed` and `after` immediately once it succeeds, so
/// the difference between the two is exactly the `pstate` mutation this request made.
/// Rolling back that difference — rather than restoring `before` wholesale — is what keeps
/// a failed request from erasing a concurrent one's committed state; see
/// `AgentPolicy::revert_state_delta`.
#[cfg(feature = "strict-policy")]
struct PolicySnapshot {
    before: String,
    after: String,
}

/// Close the bracket opened before `is_allowed`. Returns `None` if either half is missing,
/// which `rollback_policy_state` treats as an unprovable state.
#[cfg(feature = "strict-policy")]
async fn capture_policy_snapshot(before: Option<String>) -> Option<PolicySnapshot> {
    let before = before?;
    let after = crate::AGENT_POLICY.lock().await.snapshot_state().ok()?;
    Some(PolicySnapshot { before, after })
}

/// FR-6: roll a transaction back, quarantining the monitor if even that is not possible.
///
/// Every path that leaves a handler after `prepare` has to resolve the transaction, or the
/// operation id stays in flight and `prepare` — which refuses in-flight ids rather than
/// clobbering them — will reject every later attempt at the same operation. An `abort`
/// that itself fails means the transaction is not where the caller believes it is, so the
/// monitor can no longer vouch for the state.
#[cfg(feature = "strict-policy")]
fn abort_or_quarantine(
    srm: &mut kata_security_reference_monitor::ReferenceMonitor,
    op_id: &str,
    context: &str,
) {
    if let Err(e) = srm.abort(op_id) {
        error!(
            sl(),
            "failed to abort transaction {} after {} failed: {:?}; monitor state is unprovable",
            op_id,
            context,
            e
        );
        srm.quarantine(format!("{context} failed with unprovable state"));
    }
}

/// FR-9: roll a container's occurrence back to `created` after a failed start.
///
/// `remove()` must not be used here -- it is terminal, and would leave the container
/// permanently unstartable while releasing its cardinality slot (F-34).
#[cfg(feature = "strict-policy")]
async fn unstart_or_warn(container_id: &str) {
    if let Err(e) = crate::OCCURRENCES.lock().await.unstart(container_id) {
        error!(
            sl(),
            "failed to roll occurrence {} back to created after a failed start: {:?}; \
             the container is left unstartable",
            container_id,
            e
        );
    }
}

/// FR-9/FR-11: record a freshly created container's occurrence and bind its devices.
///
/// Split out of `do_create_container` so the failure ordering is directly testable.
///
/// The ordering is the point. `create` failing means an occurrence is already live for
/// this alias, so binding into it anyway would attribute *this* container's devices to the
/// previous one and `devices()` would report the union of two containers' grants -- an
/// FR-11 integrity break. The loop is therefore skipped entirely when `create` fails.
///
/// The `?` on `bind_device` is defence in depth rather than a live guard: against today's
/// registry it cannot fire, because `bind_device` refuses only an absent or already-removed
/// alias and a successful `create` guarantees neither. It is there so that a future
/// registry whose binds *can* fail stops at the first one instead of walking the rest.
/// Note that no unwinding happens on that path: the occurrence is left partially bound and
/// the caller quarantines, which is what stops anything further being authorized against
/// an occurrence that under-reports what its container holds.
#[cfg(feature = "strict-policy")]
fn record_occurrence(
    occ: &mut kata_security_reference_monitor::OccurrenceRegistry,
    cid: &str,
    devices: &[kata_security_reference_monitor::VerifiedCdiDevice],
) -> Result<(), kata_security_reference_monitor::OccurrenceError> {
    occ.create(cid, None, None)?;
    for d in devices {
        occ.bind_device(cid, &d.device, &d.spec_digest)?;
    }
    Ok(())
}

/// FR-6 / RM-4: build an operation id that no other operation can be confused with.
///
/// Operation ids are assembled from container and exec ids, and under this threat model
/// both are supplied by the untrusted host. Joining them with a separator is therefore
/// not injective: `format!("{cid}:{exec}")` maps `("a:b", "c")` and `("a", "b:c")` to the
/// same id, and the bare container id used for a create collides with an exec id whose
/// container and exec parts happen to concatenate to it.
///
/// That matters because a committed transaction is retained as an idempotent replay
/// cache. Two different operations sharing an id means the second one is answered from
/// the first one's cached result -- the agent returns success for work it never did, which
/// is exactly the divergence FR-6 exists to prevent, reachable by a host that merely
/// chooses its own container and exec ids.
///
/// Each part is length-prefixed, so the encoding is unambiguous regardless of what
/// characters the host puts in a name. `kind` is a fixed literal and contains no `/`.
#[cfg(feature = "strict-policy")]
fn srm_op_id(kind: &str, parts: &[&str]) -> String {
    let mut id = String::from(kind);
    for part in parts {
        id.push('/');
        id.push_str(&part.len().to_string());
        id.push(':');
        id.push_str(part);
    }
    id
}

/// RM-8: is this (already effective) signal number a stop signal?
///
/// A *necessary* condition for teardown, not a sufficient one: the caller must also
/// establish that the delivery is lethal (see `effective_signal`), because a SIGTERM with a
/// handler installed runs guest code rather than terminating the target. Everything else --
/// SIGHUP to reload, SIGUSR1 to rotate -- asks a running workload to do something new,
/// which is exactly what a quarantine must keep refusing.
#[cfg(feature = "strict-policy")]
fn is_teardown_signal(signal: u32) -> bool {
    signal == libc::SIGTERM as u32 || signal == libc::SIGKILL as u32
}

/// RM-7: map an SRM failure onto a ttrpc status code.
///
/// `Quarantined` gets its own terminal code so the shim can tell "this request was
/// invalid" from "this guest is degraded and no SRM-gated request will ever succeed
/// again". Every other `SrmError` is a per-request precondition failure and stays
/// `FAILED_PRECONDITION`, which the shim may reasonably retry after fixing the request.
///
/// Because a commit failure quarantines while still returning success to its caller (see
/// [`commit_or_quarantine`]), the shim's first sight of a degraded guest is the *next*
/// SRM-gated call. Without a distinct code that arrives as an opaque
/// `FAILED_PRECONDITION`, indistinguishable from a malformed request, and the shim keeps
/// retrying. `DATA_LOSS` says what actually happened: state the monitor was tracking is no
/// longer provable. The correct response is to tear the sandbox down, and RM-8 keeps
/// teardown available for exactly that.
#[cfg(feature = "strict-policy")]
fn srm_code(e: &kata_security_reference_monitor::SrmError) -> ttrpc::Code {
    match e {
        kata_security_reference_monitor::SrmError::Quarantined(_) => ttrpc::Code::DATA_LOSS,
        _ => ttrpc::Code::FAILED_PRECONDITION,
    }
}

/// FR-6: record a successful operation, quarantining the monitor if that fails.
///
/// A `commit` failure means the runtime operation succeeded but the monitor could not
/// record it: either the transaction is gone (`UnknownOperation`) or it is not in
/// `Executed` (`InvalidState`, so `execute` never ran or another caller already resolved
/// it). Either way the monitor's view of the world no longer matches reality, which is the
/// precise divergence FR-6 exists to prevent, so the state is no longer provable.
///
/// The RPC still returns success to the caller, because it *did* succeed -- reporting a
/// failure would invite the shim to retry an operation that already happened, trading one
/// divergence for another. Quarantine is what stops any further SRM-gated operation from
/// building on state the monitor cannot vouch for.
#[cfg(feature = "strict-policy")]
fn commit_or_quarantine(
    srm: &mut kata_security_reference_monitor::ReferenceMonitor,
    op_id: &str,
    observed_result: &str,
    context: &str,
) {
    if let Err(e) = srm.commit(op_id, observed_result) {
        error!(
            sl(),
            "failed to commit transaction {} after a successful {}: {:?}; \
             monitor state is unprovable",
            op_id,
            context,
            e
        );
        srm.quarantine(format!("commit failed after a successful {context}"));
    }
}

/// FR-6: free a committed operation id so the same id can be used again.
///
/// A committed transaction is retained as an idempotent replay cache, which is only
/// correct for operations whose id names a unique object (a container id). For operations
/// whose id names a repeatable event (a signal) or a reusable name (an exec id), the
/// cached entry would answer a later legitimate request with a success it never performed.
///
/// A failure here is not fatal -- the operation itself succeeded -- but it does mean the
/// stale entry remains and a later request for the same id may be swallowed, so it is
/// logged rather than ignored.
#[cfg(feature = "strict-policy")]
fn retire_or_warn(srm: &mut kata_security_reference_monitor::ReferenceMonitor, op_id: &str) {
    if let Err(e) = srm.retire(op_id) {
        warn!(
            sl(),
            "could not retire transaction {}: {:?}; a later request for this id may be \
             answered from the replay cache",
            op_id,
            e
        );
    }
}

fn get_agent_details() -> AgentDetails {
    let mut detail = AgentDetails::new();

    detail.set_version(AGENT_VERSION.to_string());
    detail.set_supports_seccomp(have_seccomp());
    detail.init_daemon = unistd::getpid() == Pid::from_raw(1);

    detail.device_handlers = Vec::new();
    detail.storage_handlers = STORAGE_HANDLERS.get_handlers();
    detail.extra_features = get_build_features();

    detail
}

async fn read_stream(reader: &Mutex<ReadHalf<PipeStream>>, l: usize) -> Result<Vec<u8>> {
    let mut content = vec![0u8; l];

    let mut reader = reader.lock().await;
    let len = reader.read(&mut content).await?;
    content.resize(len, 0);

    Ok(content)
}

pub async fn start(
    s: Arc<Mutex<Sandbox>>,
    server_address: &str,
    init_mode: bool,
    oma: Option<mem_agent::agent::MemAgent>,
) -> Result<TtrpcServer> {
    let agent_service = Box::new(AgentService {
        sandbox: s,
        init_mode,
        oma,
    });
    let aservice = agent_ttrpc::create_agent_service(Arc::new(*agent_service));

    let health_service = Box::new(HealthService {});
    let hservice = health_ttrpc::create_health(Arc::new(*health_service));

    let server = TtrpcServer::new()
        .bind(server_address)?
        .register_service(aservice)
        .register_service(hservice);

    info!(sl(), "ttRPC server started"; "address" => server_address);

    Ok(server)
}

// This function updates the container namespaces configuration based on the
// sandbox information. When the sandbox is created, it can be setup in a way
// that all containers will share some specific namespaces. This is the agent
// responsibility to create those namespaces so that they can be shared across
// several containers.
// If the sandbox has not been setup to share namespaces, then we assume all
// containers will be started in their own new namespace.
// The value of a.sandbox.sharedPidNs.path will always override the namespace
// path set by the spec, since we will always ignore it. Indeed, it makes no
// sense to rely on the namespace path provided by the host since namespaces
// are different inside the guest.
fn update_container_namespaces(
    sandbox: &Sandbox,
    spec: &mut Spec,
    sandbox_pidns: bool,
) -> Result<()> {
    let linux = spec
        .linux_mut()
        .as_mut()
        .ok_or_else(|| anyhow!(ERR_NO_LINUX_FIELD))?;

    if let Some(namespaces) = linux.namespaces_mut() {
        for namespace in namespaces.iter_mut() {
            if namespace.typ().to_string() == NSTYPEIPC {
                namespace.set_path(if !sandbox.shared_ipcns.path.is_empty() {
                    Some(PathBuf::from(&sandbox.shared_ipcns.path))
                } else {
                    None
                });
                continue;
            }
            if namespace.typ().to_string() == NSTYPEUTS {
                namespace.set_path(if !sandbox.shared_utsns.path.is_empty() {
                    Some(PathBuf::from(&sandbox.shared_utsns.path))
                } else {
                    None
                });
                continue;
            }
        }

        // update pid namespace
        let mut pid_ns = LinuxNamespace::default();
        pid_ns.set_typ(oci::LinuxNamespaceType::try_from(NSTYPEPID).unwrap());

        // Use shared pid ns if useSandboxPidns has been set in either
        // the create_sandbox request or create_container request.
        // Else set this to empty string so that a new pid namespace is
        // created for the container.
        if sandbox_pidns {
            if let Some(ref pidns) = &sandbox.sandbox_pidns {
                if !pidns.path.is_empty() {
                    pid_ns.set_path(Some(PathBuf::from(&pidns.path)));
                }
            } else if !sandbox.containers.is_empty() {
                return Err(anyhow!(ERR_NO_SANDBOX_PIDNS));
            }
        }

        namespaces.push(pid_ns);
    }

    Ok(())
}

async fn remove_container_resources(sandbox: &mut Sandbox, cid: &str) -> Result<()> {
    let mut cmounts: Vec<String> = vec![];

    // Find the sandbox storage used by this container
    let mounts = sandbox.container_mounts.get(cid);
    if let Some(mounts) = mounts {
        for m in mounts.iter() {
            if sandbox.storages.contains_key(m) {
                cmounts.push(m.to_string());
            }
        }
    }

    for m in cmounts.iter() {
        if let Err(err) = sandbox.remove_sandbox_storage(m).await {
            error!(
                sl(),
                "failed to unset_and_remove_sandbox_storage for container {}, error: {:?}",
                cid,
                err
            );
        }
    }

    // Cleanup dm-verity devices for this container (after all mounts are unmounted)
    if let Some(verity_devices) = sandbox.container_verity_devices.remove(cid) {
        #[cfg(feature = "devicemapper")]
        if !verity_devices.is_empty() {
            cleanup_dmverity_devices(&verity_devices, &sandbox.logger);
        }
        let _ = verity_devices;
    }

    sandbox.container_mounts.remove(cid);
    sandbox.containers.remove(cid);
    // Remove any host -> guest mappings for this container
    sandbox.pcimap.remove(cid);
    Ok(())
}

fn append_guest_hooks(s: &Sandbox, oci: &mut Spec) -> Result<()> {
    if let Some(ref guest_hooks) = s.hooks {
        if let Some(hooks) = oci.hooks_mut() {
            util::merge(hooks.poststart_mut(), guest_hooks.prestart());
            util::merge(hooks.poststart_mut(), guest_hooks.poststart());
            util::merge(hooks.poststop_mut(), guest_hooks.poststop());
        } else {
            let _oci_hooks = oci.set_hooks(Some(Hooks::default()));
            if let Some(hooks) = oci.hooks_mut() {
                hooks.set_prestart(guest_hooks.prestart().clone());
                hooks.set_poststart(guest_hooks.poststart().clone());
                hooks.set_poststop(guest_hooks.poststop().clone());
            }
        }
    }

    Ok(())
}

// Check if the container process installed the
// handler for specific signal.
fn is_signal_handled(proc_status_file: &str, signum: u32) -> bool {
    let shift_count: u64 = if signum == 0 {
        // signum 0 is used to check for process liveness.
        // Since that signal is not part of the mask in the file, we only need
        // to know if the file (and therefore) process exists to handle
        // that signal.
        return fs::metadata(proc_status_file).is_ok();
    } else if signum > 64 {
        // Ensure invalid signum won't break bit shift logic
        warn!(sl(), "received invalid signum {}", signum);
        return false;
    } else {
        (signum - 1).into()
    };

    // Open the file in read-only mode (ignoring errors).
    let file = match File::open(proc_status_file) {
        Ok(f) => f,
        Err(_) => {
            warn!(sl(), "failed to open file {}", proc_status_file);
            return false;
        }
    };

    let sig_mask: u64 = 1 << shift_count;
    let reader = BufReader::new(file);

    // read lines start with SigBlk/SigIgn/SigCgt and check any match the signal mask
    reader
        .lines()
        .map_while(Result::ok)
        .filter(|line| {
            line.starts_with("SigBlk:")
                || line.starts_with("SigIgn:")
                || line.starts_with("SigCgt:")
        })
        .any(|line| {
            let mask_vec: Vec<&str> = line.split(':').collect();
            if mask_vec.len() == 2 {
                let sig_str = mask_vec[1].trim();
                if let Ok(sig) = u64::from_str_radix(sig_str, 16) {
                    return sig & sig_mask == sig_mask;
                }
            }
            false
        })
}

fn do_mem_hotplug_by_probe(addrs: &[u64]) -> Result<()> {
    for addr in addrs.iter() {
        fs::write(SYSFS_MEMORY_HOTPLUG_PROBE_PATH, format!("{:#X}", *addr))?;
    }
    Ok(())
}

fn do_set_guest_date_time(sec: i64, usec: i64) -> Result<()> {
    let tv = libc::timeval {
        tv_sec: sec,
        tv_usec: usec,
    };

    let ret = unsafe {
        libc::settimeofday(
            &tv as *const libc::timeval,
            std::ptr::null::<libc::timezone>(),
        )
    };

    Errno::result(ret).map(drop)?;

    Ok(())
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.is_absolute() && path.components().all(|c| matches!(c, Component::Normal(_)))
}

fn guest_share_dir_path() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(path) = TEST_GUEST_SHARE_DIR.lock().unwrap().clone() {
            return path;
        }
    }

    PathBuf::from(KATA_GUEST_SHARE_DIR)
}

fn volumes_dir_path() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(path) = TEST_VOLUMES_DIR.lock().unwrap().clone() {
            return path;
        }
    }

    PathBuf::from(KATA_GUEST_VOLUMES_DIR)
}

fn volume_root_path(agent_volume_id: &str) -> Result<PathBuf> {
    let id_path = Path::new(agent_volume_id);
    if !is_safe_relative_path(id_path) {
        return Err(anyhow!("invalid agent_volume_id: {agent_volume_id}"));
    }

    Ok(volumes_dir_path().join(id_path))
}

fn create_watchable_directory(path: &Path, mode: u32, uid: i32, gid: i32) -> Result<()> {
    let req = CopyFileRequest {
        path: path.to_string_lossy().to_string(),
        file_size: 0,
        file_mode: stat::SFlag::S_IFDIR.bits() | mode,
        dir_mode: mode,
        uid,
        gid,
        offset: 0,
        data: vec![],
        ..Default::default()
    };
    do_copy_file(&req, &guest_share_dir_path())
}

fn translate_bind_safer_path_mounts(oci: &mut Spec) -> Result<()> {
    let Some(mounts) = oci.mounts_mut().as_mut() else {
        return Ok(());
    };

    for mount in mounts.iter_mut() {
        if mount.typ().as_deref() != Some("bind-safer-path") {
            continue;
        }

        let source = mount
            .source()
            .as_ref()
            .ok_or_else(|| anyhow!("bind-safer-path mount missing source"))?;
        if source.is_absolute() {
            return Err(anyhow!(
                "bind-safer-path source must be relative: {source:?}"
            ));
        }
        // The host chooses this string, and the policy does not constrain it: the
        // `bind-safer-path` case of `mount_source_allows` in rules.rego matches any source,
        // because the guest mints watchable volume ids and genpolicy cannot predict them. The
        // policy therefore pins the destination but not the source, which leaves the agent as
        // the only check between a host-supplied path and a bind mount. Reject anything that
        // is not a plain relative path, before the branch below so that both translations are
        // covered: `join` does not normalise `..`, so the kernel would resolve it at mount
        // time and the mount would escape the directory the branch selected.
        if !is_safe_relative_path(source) {
            return Err(anyhow!(
                "bind-safer-path source must not contain '..' components: {source:?}"
            ));
        }

        let translated = if source
            .components()
            .next()
            .is_some_and(|c| c == Component::Normal(OsStr::new("single-files")))
        {
            guest_share_dir_path().join(source)
        } else {
            let source_id = source
                .to_str()
                .ok_or_else(|| anyhow!("bind-safer-path source is not valid UTF-8: {source:?}"))?;
            volume_root_path(source_id)?
        };

        mount.set_typ(Some("bind".to_string()));
        mount.set_source(Some(translated));
    }

    Ok(())
}

/// do_copy_file creates a file, directory or symlink beneath the provided directory.
///
/// The function guarantees that no content is written outside of the directory. However, a symlink
/// created by this function might point outside the shared directory. Other users of that
/// directory need to consider whether they trust the host, or handle the directory with the same
/// care as do_copy_file.
///
/// Parent directories are created, if they don't exist already. For these implicit operations, the
/// permissions are set with req.dir_mode. The actual target is created with permissions from
/// req.file_mode, even if it's a directory.
///
/// If req.file_mode requests a symbolic link, the link is created pointing to the path in
/// req.data. In that case, req.file_mode is ignored because symlinks don't have permissions on
/// Linux.
///
/// If this function returns an error, the filesystem may be in an unexpected state. This is not
/// significant for the caller, since errors are almost certainly not retriable. The runtime should
/// abandon this VM instead.
#[cfg_attr(feature = "strict-policy", allow(dead_code))]
fn do_copy_file(req: &CopyFileRequest, shared_dir: &PathBuf) -> Result<()> {
    let insecure_full_path = PathBuf::from(req.path.as_str());
    let path = insecure_full_path
        .strip_prefix(shared_dir)
        .context(format!(
            "removing {:?} prefix from {}",
            shared_dir, req.path
        ))?;

    // The shared directory might not exist yet, but we need to create it in order to open the root.
    std::fs::create_dir_all(shared_dir)?;
    let root = pathrs::Root::open(shared_dir)?;

    // Create parent directories if missing
    if let Some(parent) = path.parent() {
        let dir = root
            .mkdir_all(
                parent,
                &std::fs::Permissions::from_mode(req.dir_mode & IMPLICIT_DIRECTORY_PERMISSION_MASK),
            )
            .context("mkdir_all parent")?
            .reopen(OpenFlags::O_DIRECTORY)
            .context("reopen parent")?;

        // TODO(burgerdev): why are we only applying this to the immediate parent?
        unistd::fchown(
            dir,
            Some(Uid::from_raw(req.uid as u32)),
            Some(Gid::from_raw(req.gid as u32)),
        )
        .context("fchown parent")?
    }

    let sflag = stat::SFlag::from_bits_truncate(req.file_mode);

    if sflag.contains(stat::SFlag::S_IFDIR) {
        // Directories are somewhat special: for backwards compatibility, we need to preserve an
        // existing directory at path, so we can't just remove_all. Instead, we try to remove a
        // file and just don't propagate the error if it's a directory or doesn't exist.
        root.remove_file(path).or_else(|e| match e.kind() {
            pathrs::error::ErrorKind::OsError(Some(errno))
                if errno == libc::ENOENT || errno == libc::EISDIR =>
            {
                Ok(())
            }
            _ => Err(e),
        })?;

        // mkdir_all does not support the setuid/setgid/sticky bits, so we first create the
        // directory with the stricter mask and then change permissions with the correct mask.
        let dir = root
            .mkdir_all(
                path,
                &std::fs::Permissions::from_mode(
                    req.file_mode & IMPLICIT_DIRECTORY_PERMISSION_MASK,
                ),
            )
            .context("mkdir_all dir")?
            .reopen(OpenFlags::O_DIRECTORY)
            .context("reopen dir")?;
        dir.set_permissions(std::fs::Permissions::from_mode(
            req.file_mode & FILE_PERMISSION_MASK,
        ))?;

        unistd::fchown(
            dir,
            Some(Uid::from_raw(req.uid as u32)),
            Some(Gid::from_raw(req.gid as u32)),
        )
        .context("fchown dir")?;

        return Ok(());
    }

    // Remove any existing file if we're not resuming a chunked upload.
    if req.offset == 0 {
        // Remove anything that might already exist at the target location.
        // This is safe even for a symlink leaf, remove_all removes the named inode in its parent dir.
        root.remove_all(path).or_else(|e| match e.kind() {
            pathrs::error::ErrorKind::OsError(Some(errno)) if errno == libc::ENOENT => Ok(()),
            _ => Err(e),
        })?;
    }

    // Handle symlink creation
    if sflag.contains(stat::SFlag::S_IFLNK) {
        // Create new symbolic link
        let symlink_target = PathBuf::from(OsStr::from_bytes(&req.data));
        root.create(path, &pathrs::InodeType::Symlink(symlink_target))
            .context("create symlink")?;

        // Set symlink ownership.
        // At the time of writing this, there was no API for creating the symlink and opening a
        // handle to the created inode. Best we can do is to resolve it again under the root and
        // hope that its still the same inode, but at least we guarantee that we're changing
        // ownership only within the shared directory.
        nix::unistd::fchownat(
            root,
            path,
            Some(Uid::from_raw(req.uid as u32)),
            Some(Gid::from_raw(req.gid as u32)),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .context("fchownat")?;

        // Symlinks don't have permissions on Linux!
        return Ok(());
    }

    let mut tmpfile = path.to_path_buf();
    tmpfile.set_extension("tmp");

    // Write file content.
    let flags = if req.offset == 0 {
        OpenFlags::O_RDWR | OpenFlags::O_CREAT | OpenFlags::O_TRUNC
    } else {
        OpenFlags::O_RDWR | OpenFlags::O_CREAT
    };
    let file = root
        .create_file(
            &tmpfile,
            flags,
            &std::fs::Permissions::from_mode(req.file_mode & FILE_PERMISSION_MASK),
        )
        .context("create_file")?;
    file.write_all_at(req.data.as_slice(), req.offset as u64)
        .context("write_all_at")?;

    // Check whether we're waiting for more data.

    let st = nix::sys::stat::fstat(&file).context("fstat")?;
    if st.st_size != req.file_size {
        return Ok(());
    }

    // Things like umask can change the permissions after create, make sure that they stay
    file.set_permissions(std::fs::Permissions::from_mode(
        req.file_mode & FILE_PERMISSION_MASK,
    ))
    .context("set_permissions")?;

    unistd::fchown(
        file,
        Some(Uid::from_raw(req.uid as u32)),
        Some(Gid::from_raw(req.gid as u32)),
    )
    .context("fchown")?;

    nix::fcntl::renameat(&root, &tmpfile, &root, path).context("renameat")?;

    Ok(())
}

async fn do_add_swap(sandbox: &Arc<Mutex<Sandbox>>, req: &AddSwapRequest) -> Result<()> {
    let mut slots = Vec::new();
    for slot in &req.PCIPath {
        slots.push(pci::SlotFn::new(*slot, 0)?);
    }
    let pcipath = pci::Path::new(slots)?;
    // Default all virtio devices to root_complex 00 aka pcie.0
    let root_complex = "00";
    let dev_name = get_virtio_blk_pci_device_name(sandbox, root_complex, &pcipath).await?;

    let c_str = CString::new(dev_name)?;
    let ret = unsafe { libc::swapon(c_str.as_ptr() as *const c_char, 0) };
    if ret != 0 {
        return Err(anyhow!(
            "libc::swapon get error {}",
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

async fn do_add_swap_path(req: &AddSwapPathRequest) -> Result<()> {
    let c_str = CString::new(req.path.clone())?;
    let ret = unsafe { libc::swapon(c_str.as_ptr() as *const c_char, 0) };
    if ret != 0 {
        return Err(anyhow!(
            "libc::swapon get error {}",
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// The rootfs the guest prepares for `cid`, and the only path a created
/// container may be rooted at.
///
/// `setup_bundle` rebinds the host-supplied rootfs here, and the FR-3 plan
/// binding pins the executed spec's `/root/path` to this value. Both derive it
/// from this one function so they cannot drift apart: a change to the bundle
/// layout that bypassed the pin would silently re-open the re-rooting gap.
pub fn container_rootfs_path(cid: &str) -> PathBuf {
    Path::new(CONTAINER_BASE).join(cid).join("rootfs")
}

/// FR-3: decide whether the plan about to be executed is still the plan the
/// policy authorized, and deny the operation if it is not.
///
/// This lives apart from `do_create_container` so the agent's own enforcement
/// decision can be exercised directly. `plan_binding`'s unit tests only ever see
/// specs a test hands them; they cannot see which expected rootfs `rpc.rs`
/// passes, that the denial is returned rather than logged, or that the check is
/// reached at all. A regression that downgraded this to an audit-only `info!`
/// would leave every one of those tests green.
///
/// The check runs unconditionally: a spec whose digest is unchanged still has to
/// satisfy the pinned-root invariant rather than inheriting a pass from equality.
#[cfg(feature = "strict-policy")]
fn enforce_plan_binding(
    cid: &str,
    authorized_oci: &Spec,
    authorized_oci_digest: &str,
    executed_oci: &Spec,
    executed_oci_digest: &str,
) -> Result<()> {
    // Content-channel mounts are the one authorized entry the guest is required to
    // rewrite: the host names a guest-side identifier (`single-files/<sid>/<name>`
    // or a volume id) and never a path, precisely so it cannot choose where the
    // content lands. `translate_bind_safer_path_mounts` resolves that identifier
    // under the guest's own share directory after the authorized spec was captured,
    // so the authorized entry cannot survive verbatim and every container carrying
    // one -- network files and watchable volumes today, whenever `copy_volumes`
    // names them -- would otherwise be refused.
    //
    // The rewrite is *waived* nowhere: it is deterministic and derived by the guest
    // alone, so the same translation is applied to a copy of the authorized spec and
    // the executed side is held to that value. This is the treatment `/root/path`
    // already gets, and for the same reason -- computing the expected value is
    // strictly stronger than permitting the field to differ. An in-guest transform
    // that pointed a content-channel mount anywhere else still fails the binding.
    let mut authorized_resolved = authorized_oci.clone();
    translate_bind_safer_path_mounts(&mut authorized_resolved).inspect_err(|e| {
        error!(
            sl(),
            "FR-3: refusing to create container; an authorized content-channel \
             mount cannot be resolved to the path the guest derives";
            "container-id" => cid,
            "violation" => e.to_string(),
        );
    })?;

    crate::plan_binding::assert_within_resolution_bounds(
        &authorized_resolved,
        executed_oci,
        &container_rootfs_path(cid),
    )
    .inspect_err(|e| {
        error!(
            sl(),
            "FR-3: refusing to create container; the executed OCI object escapes \
             the bounds of the authorized plan";
            "container-id" => cid,
            "authorized-oci-digest" => authorized_oci_digest,
            "executed-oci-digest" => executed_oci_digest,
            "violation" => e.to_string(),
        );
    })?;

    if authorized_oci_digest != executed_oci_digest {
        info!(
            sl(),
            "FR-3: executed OCI object differs from authorized spec (trusted \
             in-guest transforms applied, within resolution bounds); \
             canonical-object binding recorded";
            "container-id" => cid,
            "authorized-oci-digest" => authorized_oci_digest,
            "executed-oci-digest" => executed_oci_digest,
        );
    }

    Ok(())
}

// Setup container bundle under CONTAINER_BASE, which is cleaned up
// before removing a container.
// - bundle path is /<CONTAINER_BASE>/<cid>/
// - config.json at /<CONTAINER_BASE>/<cid>/config.json
// - container rootfs bind mounted at /<CONTAINER_BASE>/<cid>/rootfs
// - modify container spec root to point to /<CONTAINER_BASE>/<cid>/rootfs
pub fn setup_bundle(cid: &str, spec: &mut Spec) -> Result<PathBuf> {
    let spec_root = if let Some(sr) = &spec.root() {
        sr
    } else {
        return Err(anyhow!(nix::Error::EINVAL));
    };

    let bundle_path = Path::new(CONTAINER_BASE).join(cid);
    let config_path = bundle_path.join("config.json");
    let rootfs_path = container_rootfs_path(cid);
    let spec_root_path = spec_root.path();

    let rootfs_exists = Path::new(&rootfs_path).exists();
    info!(
        sl(),
        "The rootfs_path is {:?} and exists: {}", rootfs_path, rootfs_exists
    );

    if !rootfs_exists {
        fs::create_dir_all(&rootfs_path)?;
        baremount(
            spec_root_path,
            &rootfs_path,
            "bind",
            MsFlags::MS_BIND,
            "",
            &sl(),
        )?;
    }

    let mut oci_root = oci::Root::default();
    oci_root.set_path(rootfs_path);
    oci_root.set_readonly(spec_root.readonly());
    spec.set_root(Some(oci_root));

    let _ = spec.save(
        config_path
            .to_str()
            .ok_or_else(|| anyhow!("cannot convert path to unicode"))?,
    );

    let olddir = unistd::getcwd().context("cannot getcwd")?;
    unistd::chdir(
        bundle_path
            .to_str()
            .ok_or_else(|| anyhow!("cannot convert bundle path to unicode"))?,
    )?;

    Ok(olddir)
}

fn load_kernel_module(module: &protocols::agent::KernelModule) -> Result<()> {
    if module.name.is_empty() {
        return Err(anyhow!("Kernel module name is empty"));
    }

    info!(
        sl(),
        "load_kernel_module {}: {:?}", module.name, module.parameters
    );

    let mut args = vec!["-v", &module.name];

    if !module.parameters.is_empty() {
        args.extend(module.parameters.iter().map(String::as_str));
    }

    let output = Command::new(MODPROBE_PATH)
        .args(args.as_slice())
        .stdout(Stdio::piped())
        .output()?;

    let status = output.status;
    if status.success() {
        return Ok(());
    }

    match status.code() {
        Some(code) => {
            let std_out = String::from_utf8_lossy(&output.stdout);
            let std_err = String::from_utf8_lossy(&output.stderr);
            let msg =
                format!("load_kernel_module return code: {code} stdout:{std_out} stderr:{std_err}");
            Err(anyhow!(msg))
        }
        None => Err(anyhow!("Process terminated by signal")),
    }
}

fn is_sealed_secret_path(source_path: &str) -> bool {
    // Base path to check
    let base_path = "/run/kata-containers/shared/containers";
    // Paths to exclude
    let excluded_suffixes = [
        "resolv.conf",
        "termination-log",
        "hostname",
        "hosts",
        "serviceaccount",
    ];

    // Ensure the path starts with the base path and does not end with any excluded suffix
    source_path.starts_with(base_path)
        && !excluded_suffixes
            .iter()
            .any(|suffix| source_path.ends_with(suffix))
}

async fn cdh_handler_trusted_storage(oci: &mut Spec) -> Result<()> {
    let linux = oci
        .linux()
        .as_ref()
        .ok_or_else(|| anyhow!("Spec didn't contain linux field"))?;

    if let Some(devices) = linux.devices() {
        for specdev in devices.iter() {
            if specdev.path().as_path().to_str() == Some(TRUSTED_IMAGE_STORAGE_DEVICE) {
                let dev_major_minor = format!("{}:{}", specdev.major(), specdev.minor());
                cdh_secure_mount(
                    "block-device",
                    &dev_major_minor,
                    "luks2",
                    KATA_IMAGE_WORK_DIR,
                    "-E lazy_journal_init",
                )
                .await?;
                break;
            }
        }
    }
    Ok(())
}

pub(crate) async fn cdh_secure_mount(
    device_type: &str,
    device_id: &str,
    encrypt_type: &str,
    mount_point: &str,
    mkfs_opts: &str,
) -> Result<()> {
    if !confidential_data_hub::is_cdh_client_initialized() {
        return Ok(());
    }

    let integrity = AGENT_CONFIG.secure_storage_integrity.to_string();

    info!(
        sl(),
        "cdh_secure_mount: device_type {}, device_id {}, encrypt_type {}, integrity {}, mkfs_opts {}",
        device_type,
        device_id,
        encrypt_type,
        integrity,
        mkfs_opts
    );

    let options = std::collections::HashMap::from([
        ("deviceId".to_string(), device_id.to_string()),
        ("sourceType".to_string(), "empty".to_string()),
        ("targetType".to_string(), "fileSystem".to_string()),
        ("filesystemType".to_string(), "ext4".to_string()),
        ("mkfsOpts".to_string(), mkfs_opts.to_string()),
        ("encryptionType".to_string(), encrypt_type.to_string()),
        ("dataIntegrity".to_string(), integrity),
    ]);

    std::fs::create_dir_all(mount_point).inspect_err(|e| {
        error!(
            sl(),
            "Failed to create mount point directory {}: {:?}", mount_point, e
        );
    })?;

    confidential_data_hub::secure_mount(device_type, &options, vec![], mount_point).await?;

    Ok(())
}

async fn cdh_handler_sealed_secrets(oci: &mut Spec) -> Result<()> {
    if !confidential_data_hub::is_cdh_client_initialized() {
        return Ok(());
    }
    let process = oci
        .process_mut()
        .as_mut()
        .ok_or_else(|| anyhow!("Spec didn't contain process field"))?;
    if let Some(envs) = process.env_mut().as_mut() {
        for env in envs.iter_mut() {
            match confidential_data_hub::unseal_env(env).await {
                Ok(unsealed_env) => *env = unsealed_env.to_string(),
                Err(e) => {
                    warn!(sl(), "Failed to unseal secret: {}", e)
                }
            }
        }
    }

    let mounts = oci
        .mounts_mut()
        .as_mut()
        .ok_or_else(|| anyhow!("Spec didn't contain mounts field"))?;

    for m in mounts.iter_mut() {
        let Some(source_path) = m.source().as_ref().and_then(|p| p.to_str()) else {
            warn!(sl(), "Mount source is None or invalid");
            continue;
        };

        // Check if source_path starts with "/run/kata-containers/shared/containers"
        // For a volume mount path /mydir,
        // the secret file path will be like this under the /run/kata-containers/shared/containers dir
        // a128482812bad768f404e063f225decd425fc94a673aec4add45a9caa1122ccb-75490e32e51da3ff-mydir
        // We can ignore few paths like: resolv.conf, termination-log, hostname,hosts,serviceaccount
        if is_sealed_secret_path(source_path) {
            debug!(
                sl(),
                "Calling unseal_file for - source: {:?} destination: {:?}",
                source_path,
                m.destination()
            );
            // Call unseal_file. This function checks the files under the source_path
            // for the sealed secret header and unseal it if the header is present.
            // This is suboptimal as we are going through every file under the source_path.
            // But currently there is no quick way to determine which volume-mount is referring
            // to a sealed secret without reading the file.
            // And relying on file naming heuristic is inflexible. So we are going with this approach.
            if let Err(e) = confidential_data_hub::unseal_file(source_path).await {
                warn!(
                    sl(),
                    "Failed to unseal file: {:?}, Error: {:?}", source_path, e
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {

    /// F-151: every signed field must be refused if the caller tries to describe it.
    ///
    /// Exhaustive by construction: the list is rebuilt from the same field set the guest
    /// checks, and a field added to the request without being added to the check would
    /// leave a host-describable field honoured again -- the exact regression this closes.
    #[cfg(feature = "strict-policy")]
    #[test]
    fn every_signed_fragment_field_is_refused_from_the_caller() {
        use protocols::agent::LoadPolicyFragmentRequest as R;

        /// Sets one signed field on the request, so each case can be driven uniformly.
        type Describe = Box<dyn Fn(&mut R)>;

        let described: Vec<(&str, Describe)> = vec![
            (
                "issuer",
                Box::new(|r: &mut R| r.issuer = "did:x509:0:a::b".into()),
            ),
            (
                "feed",
                Box::new(|r: &mut R| r.feed = "contoso.io/frag".into()),
            ),
            ("svn", Box::new(|r: &mut R| r.svn = 3)),
            ("grants", Box::new(|r: &mut R| r.grants = vec!["g".into()])),
            (
                "signature",
                Box::new(|r: &mut R| r.signature = vec![1, 2, 3]),
            ),
            (
                "policy_module",
                Box::new(|r: &mut R| r.policy_module = b"package p".to_vec()),
            ),
            (
                "includes",
                Box::new(|r: &mut R| r.includes = vec!["exec".into()]),
            ),
            (
                "requires",
                Box::new(|r: &mut R| r.requires = vec!["a/b/1".into()]),
            ),
            (
                "prev_log_head",
                Box::new(|r: &mut R| r.prev_log_head = vec![9]),
            ),
        ];

        for (name, set) in described {
            let mut req = R::new();
            req.cose_sign1 = vec![0xd2, 0x84]; // shape is irrelevant; the check precedes decoding
            set(&mut req);
            assert_eq!(
                caller_described_fragment_field(&req),
                Some(name),
                "field `{name}` was accepted from the caller, so the guest still honours a \
                 shape runtime-rs cannot send"
            );
        }
    }

    /// The courier's own shape must pass: envelope plus the receipt fields, nothing else.
    /// Receipts are countersignatures over the statement rather than part of it, so they
    /// are legitimately caller-supplied and must not be swept up by the same check.
    #[cfg(feature = "strict-policy")]
    #[test]
    fn the_runtime_rs_request_shape_is_accepted() {
        use protocols::agent::LoadPolicyFragmentRequest as R;
        let mut req = R::new();
        req.cose_sign1 = vec![0xd2, 0x84];
        req.receipt = "r1".into();
        req.receipt_ledger = "ledger-a".into();
        req.receipt_proof = "{}".into();
        req.extra_receipts = vec!["ledger-b=aabb".into()];
        assert_eq!(caller_described_fragment_field(&req), None);
    }
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{namespace::Namespace, protocols::agent_ttrpc_async::AgentService as _};
    use anyhow::{bail, ensure};
    use nix::mount;
    use nix::sched::{unshare, CloneFlags};
    use oci::{
        HookBuilder, HooksBuilder, Linux, LinuxBuilder, LinuxDeviceCgroupBuilder, LinuxNamespace,
        LinuxNamespaceBuilder, LinuxResourcesBuilder, SpecBuilder,
    };
    use oci_spec::runtime::{LinuxNamespaceType, Root};
    use tempfile::{tempdir, TempDir};
    use test_utils::{assert_result, skip_if_not_root};
    use ttrpc::{r#async::TtrpcContext, MessageHeader};
    use which::which;

    const CGROUP_PARENT: &str = "kata.agent.test.k8s.io";

    fn check_command(cmd: &str) -> bool {
        which(cmd).is_ok()
    }

    fn mk_ttrpc_context() -> TtrpcContext {
        TtrpcContext {
            fd: -1,
            mh: MessageHeader::default(),
            metadata: std::collections::HashMap::new(),
            timeout_nano: 0,
        }
    }

    fn setup_volume_rpc_test() -> TempDir {
        let temp_dir = tempdir().unwrap();
        let share_dir = temp_dir.path().join("share");
        let volumes_dir = share_dir.join("volumes");
        fs::create_dir_all(&volumes_dir).unwrap();

        *TEST_GUEST_SHARE_DIR.lock().unwrap() = Some(share_dir);
        *TEST_VOLUMES_DIR.lock().unwrap() = Some(volumes_dir);
        VOLUMES.lock().unwrap().clear();

        temp_dir
    }

    /// Installs a policy that admits the four content-channel RPCs.
    ///
    /// The policy builds deny any request whose rule the active policy does not define,
    /// so a test that drives these handlers has to put a policy in place first. The
    /// returned guard also serializes against every other policy-driven test, since
    /// `AGENT_POLICY` is process-global (see `policy::test_support`).
    #[cfg(feature = "agent-policy")]
    async fn install_content_channel_policy() -> crate::policy::test_support::PolicyTestGuard {
        crate::policy::test_support::install_policy(concat!(
            "package agent_policy\n",
            "default CopySingleFileRequest := true\n",
            "default InitWatchableVolumeRequest := true\n",
            "default PutVolumeFileRequest := true\n",
            "default CommitVolumeRevisionRequest := true\n",
            // Explicit, so a query for an unrelated endpoint still returns a result
            // rather than an engine error.
            "default AllowRequestsFailingPolicy := false\n",
        ))
        .await
    }

    fn test_agent_service() -> Box<AgentService> {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Sandbox::new(&logger).unwrap();
        Box::new(AgentService {
            sandbox: Arc::new(Mutex::new(sandbox)),
            init_mode: true,
            oma: None,
        })
    }

    async fn init_test_volume(agent_service: &AgentService) -> String {
        agent_service
            .init_volume(
                &mk_ttrpc_context(),
                InitVolumeRequest {
                    host_volume_id: "host-volume".to_string(),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .agent_volume_id
    }

    fn put_volume_file_request(
        agent_volume_id: &str,
        file_name: &str,
        revision: &str,
        data: &[u8],
    ) -> PutVolumeFileRevisionRequest {
        PutVolumeFileRevisionRequest {
            agent_volume_id: agent_volume_id.to_string(),
            file_name: file_name.to_string(),
            file_size: data.len() as i64,
            file_mode: 0o644 | libc::S_IFREG,
            uid: unistd::getuid().as_raw() as i32,
            gid: unistd::getgid().as_raw() as i32,
            offset: 0,
            data: data.to_vec(),
            revision: revision.to_string(),
            dir_mode: 0o750,
            ..Default::default()
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_put_volume_file_rejects_invalid_paths() {
        #[cfg(feature = "agent-policy")]
        let _policy_guard = install_content_channel_policy().await;
        let _temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let agent_volume_id = init_test_volume(&agent_service).await;
        let ctx = mk_ttrpc_context();

        let invalid_file = put_volume_file_request(&agent_volume_id, "../token", "rev1", b"token");
        assert!(agent_service
            .put_volume_file_revision(&ctx, invalid_file)
            .await
            .is_err());

        let invalid_revision =
            put_volume_file_request(&agent_volume_id, "token", "../rev1", b"token");
        assert!(agent_service
            .put_volume_file_revision(&ctx, invalid_revision)
            .await
            .is_err());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_put_volume_file_rejects_non_regular_file() {
        let _temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let agent_volume_id = init_test_volume(&agent_service).await;
        let ctx = mk_ttrpc_context();

        let mut req = put_volume_file_request(&agent_volume_id, "token", "rev1", b"token");
        req.file_mode = stat::SFlag::S_IFLNK.bits();

        assert!(agent_service.put_volume_file_revision(&ctx, req).await.is_err());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_copy_single_file_writes_to_shared_dir() {
        #[cfg(feature = "agent-policy")]
        let _policy_guard = install_content_channel_policy().await;
        let temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let ctx = mk_ttrpc_context();
        let data = b"nameserver 1.1.1.1".to_vec();

        let resp = agent_service
            .copy_single_file(
                &ctx,
                CopySingleFileRequest {
                    sandbox_id: "sandbox-id".to_string(),
                    file_type: protobuf::EnumOrUnknown::new(
                        SingleFileType::SINGLE_FILE_TYPE_RESOLV_CONF,
                    ),
                    uid: unistd::getuid().as_raw() as i32,
                    gid: unistd::getgid().as_raw() as i32,
                    data_size: data.len() as i64,
                    data,
                    file_mode: 0o644 | libc::S_IFREG,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(resp.agent_file_id, "single-files/sandbox-id/resolv.conf");
        assert_eq!(
            fs::read_to_string(temp_dir.path().join("share").join(resp.agent_file_id)).unwrap(),
            "nameserver 1.1.1.1"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_copy_single_file_rejects_non_regular_file() {
        let _temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let ctx = mk_ttrpc_context();
        let data = b"resolv.conf".to_vec();

        let result = agent_service
            .copy_single_file(
                &ctx,
                CopySingleFileRequest {
                    sandbox_id: "sandbox-id".to_string(),
                    file_type: protobuf::EnumOrUnknown::new(
                        SingleFileType::SINGLE_FILE_TYPE_RESOLV_CONF,
                    ),
                    uid: unistd::getuid().as_raw() as i32,
                    gid: unistd::getgid().as_raw() as i32,
                    data_size: data.len() as i64,
                    data,
                    file_mode: stat::SFlag::S_IFLNK.bits(),
                    ..Default::default()
                },
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_copy_single_file_accepts_empty_unspecified_file() {
        let temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let ctx = mk_ttrpc_context();

        let resp = agent_service
            .copy_single_file(
                &ctx,
                CopySingleFileRequest {
                    sandbox_id: "sandbox-id".to_string(),
                    file_type: protobuf::EnumOrUnknown::new(
                        SingleFileType::SINGLE_FILE_TYPE_UNSPECIFIED,
                    ),
                    uid: unistd::getuid().as_raw() as i32,
                    gid: unistd::getgid().as_raw() as i32,
                    data_size: 0,
                    data: vec![],
                    file_mode: 0o644 | libc::S_IFREG,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(resp.agent_file_id, "single-files/sandbox-id/empty-file");
        assert!(
            fs::metadata(temp_dir.path().join("share").join(resp.agent_file_id))
                .unwrap()
                .is_file()
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_copy_single_file_rejects_non_empty_unspecified_file() {
        let _temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let ctx = mk_ttrpc_context();

        let result = agent_service
            .copy_single_file(
                &ctx,
                CopySingleFileRequest {
                    sandbox_id: "sandbox-id".to_string(),
                    file_type: protobuf::EnumOrUnknown::new(
                        SingleFileType::SINGLE_FILE_TYPE_UNSPECIFIED,
                    ),
                    uid: unistd::getuid().as_raw() as i32,
                    gid: unistd::getgid().as_raw() as i32,
                    data_size: 1,
                    data: vec![1],
                    file_mode: 0o644 | libc::S_IFREG,
                    ..Default::default()
                },
            )
            .await;

        assert!(result.is_err());
    }

    #[test]
    #[serial_test::serial]
    fn test_translate_bind_safer_path_mounts() {
        let temp_dir = setup_volume_rpc_test();
        let share_dir = temp_dir.path().join("share");

        let mut single_file_mount = oci::Mount::default();
        single_file_mount.set_destination(PathBuf::from("/etc/resolv.conf"));
        single_file_mount.set_typ(Some("bind-safer-path".to_string()));
        single_file_mount.set_source(Some(PathBuf::from("single-files/sandbox-id/resolv.conf")));

        let mut watchable_mount = oci::Mount::default();
        watchable_mount.set_destination(PathBuf::from(
            "/var/run/secrets/kubernetes.io/serviceaccount",
        ));
        watchable_mount.set_typ(Some("bind-safer-path".to_string()));
        watchable_mount.set_source(Some(PathBuf::from("volume-id")));

        let mut spec = Spec::default();
        spec.set_mounts(Some(vec![single_file_mount, watchable_mount]));

        translate_bind_safer_path_mounts(&mut spec).unwrap();
        let mounts = spec.mounts().as_ref().unwrap();

        assert_eq!(mounts[0].typ().as_deref(), Some("bind"));
        assert_eq!(
            mounts[0].source().as_ref().unwrap(),
            &share_dir.join("single-files/sandbox-id/resolv.conf")
        );

        assert_eq!(mounts[1].typ().as_deref(), Some("bind"));
        assert_eq!(
            mounts[1].source().as_ref().unwrap(),
            &share_dir.join("volumes/volume-id")
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_translate_bind_safer_path_mounts_rejects_traversal() {
        let _temp_dir = setup_volume_rpc_test();

        // The policy does not pin the source of a bind-safer-path mount, so these strings
        // reach the agent under host control. Both translation branches must reject a
        // source that walks out of the directory the branch selected -- `join` keeps `..`
        // and the kernel would resolve it when the bind mount is performed.
        for source in [
            "single-files/../../../../etc/shadow",
            "single-files/sandbox-id/../../../etc/shadow",
            "../../etc/shadow",
            "watchable-volumes/../../etc/shadow",
        ] {
            let mut mount = oci::Mount::default();
            mount.set_destination(PathBuf::from("/etc/resolv.conf"));
            mount.set_typ(Some("bind-safer-path".to_string()));
            mount.set_source(Some(PathBuf::from(source)));

            let mut spec = Spec::default();
            spec.set_mounts(Some(vec![mount]));

            assert!(
                translate_bind_safer_path_mounts(&mut spec).is_err(),
                "expected {} to be rejected",
                source
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_put_volume_file_rejects_mixed_pending_revisions() {
        #[cfg(feature = "agent-policy")]
        let _policy_guard = install_content_channel_policy().await;
        let _temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let agent_volume_id = init_test_volume(&agent_service).await;
        let ctx = mk_ttrpc_context();

        let first = put_volume_file_request(&agent_volume_id, "token", "rev1", b"token");
        agent_service.put_volume_file_revision(&ctx, first).await.unwrap();

        let second = put_volume_file_request(&agent_volume_id, "ca.crt", "rev2", b"crt");
        assert!(agent_service.put_volume_file_revision(&ctx, second).await.is_err());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_commit_volume_revision_without_pending_revision_is_noop() {
        #[cfg(feature = "agent-policy")]
        let _policy_guard = install_content_channel_policy().await;
        let _temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let agent_volume_id = init_test_volume(&agent_service).await;
        let ctx = mk_ttrpc_context();

        let req = CommitVolumeRevisionRequest {
            agent_volume_id,
            garbage_collect_previous: true,
            ..Default::default()
        };
        agent_service
            .commit_volume_revision(&ctx, req)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_commit_volume_revision_switches_data_symlink_and_gc() {
        #[cfg(feature = "agent-policy")]
        let _policy_guard = install_content_channel_policy().await;
        let _temp_dir = setup_volume_rpc_test();
        let agent_service = test_agent_service();
        let agent_volume_id = init_test_volume(&agent_service).await;
        let ctx = mk_ttrpc_context();
        let volume_root = volume_root_path(&agent_volume_id).unwrap();

        let first = put_volume_file_request(&agent_volume_id, "token", "rev1", b"one");
        agent_service.put_volume_file_revision(&ctx, first).await.unwrap();
        agent_service
            .commit_volume_revision(
                &ctx,
                CommitVolumeRevisionRequest {
                    agent_volume_id: agent_volume_id.clone(),
                    garbage_collect_previous: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(
            fs::read_link(volume_root.join("token")).unwrap(),
            PathBuf::from("data/token")
        );
        assert_eq!(
            fs::read_link(volume_root.join("data")).unwrap(),
            PathBuf::from("rev1")
        );
        assert_eq!(
            fs::read_to_string(volume_root.join("rev1/token")).unwrap(),
            "one"
        );

        let second = put_volume_file_request(&agent_volume_id, "token", "rev2", b"two");
        agent_service.put_volume_file_revision(&ctx, second).await.unwrap();
        agent_service
            .commit_volume_revision(
                &ctx,
                CommitVolumeRevisionRequest {
                    agent_volume_id: agent_volume_id.clone(),
                    garbage_collect_previous: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(
            fs::read_link(volume_root.join("data")).unwrap(),
            PathBuf::from("rev2")
        );
        assert_eq!(
            fs::read_to_string(volume_root.join("rev2/token")).unwrap(),
            "two"
        );
        assert!(!volume_root.join("rev1").exists());
    }

    fn create_dummy_opts() -> CreateOpts {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let mut root = Root::default();
        root.set_path(PathBuf::from("/"));

        let linux_resources = LinuxResourcesBuilder::default()
            .devices(vec![LinuxDeviceCgroupBuilder::default()
                .allow(true)
                .access("rwm")
                .build()
                .unwrap()])
            .build()
            .unwrap();

        let cgroups_path = format!(
            "/{}/dummycontainer{}",
            CGROUP_PARENT,
            since_the_epoch.as_micros()
        );

        let spec = SpecBuilder::default()
            .linux(
                LinuxBuilder::default()
                    .cgroups_path(cgroups_path)
                    .resources(linux_resources)
                    .build()
                    .unwrap(),
            )
            .root(root)
            .build()
            .unwrap();

        CreateOpts {
            cgroup_name: "".to_string(),
            use_systemd_cgroup: false,
            no_pivot_root: false,
            no_new_keyring: false,
            spec: Some(spec),
            rootless_euid: false,
            rootless_cgroup: false,
            container_name: "".to_string(),
        }
    }

    fn create_linuxcontainer() -> (LinuxContainer, TempDir) {
        let dir = tempdir().expect("failed to make tempdir");

        (
            LinuxContainer::new(
                "some_id",
                dir.path().join("rootfs").to_str().unwrap(),
                None,
                create_dummy_opts(),
                &slog_scope::logger(),
            )
            .unwrap(),
            dir,
        )
    }

    #[test]
    fn test_load_kernel_module() {
        let mut m = protocols::agent::KernelModule {
            name: "module_not_exists".to_string(),
            ..Default::default()
        };

        // case 1: module not exists
        let result = load_kernel_module(&m);
        assert!(result.is_err(), "load module should failed");

        // case 2: module name is empty
        m.name = "".to_string();
        let result = load_kernel_module(&m);
        assert!(result.is_err(), "load module should failed");

        skip_if_not_root!();
        // case 3: normal module.
        // normally this module should eixsts...
        m.name = "bridge".to_string();
        let result = load_kernel_module(&m);

        // Skip test if loading kernel modules is not permitted
        // or kernel module is not found
        if let Err(e) = &result {
            let error_string = format!("{e:?}");
            // Let's print out the error message first
            println!("DEBUG: error: {error_string}");
            if error_string.contains("Operation not permitted")
                || error_string.contains("EPERM")
                || error_string.contains("Permission denied")
            {
                println!("INFO: skipping test - loading kernel modules is not permitted in this environment");
                return;
            }
            if error_string.contains("not found") {
                println!("INFO: skipping test - kernel module is not found in this environment");
                return;
            }
        }

        assert!(result.is_ok(), "load module should success");
    }

    #[tokio::test]
    async fn test_append_guest_hooks() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let mut s = Sandbox::new(&logger).unwrap();
        let hooks = HooksBuilder::default()
            .prestart(vec![HookBuilder::default()
                .path(PathBuf::from("foo"))
                .build()
                .unwrap()])
            .build()
            .unwrap();
        s.hooks = Some(hooks);

        let mut oci = Spec::default();
        append_guest_hooks(&s, &mut oci).unwrap();
        assert_eq!(s.hooks, oci.hooks().clone());
    }

    #[tokio::test]
    async fn test_update_interface() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Sandbox::new(&logger).unwrap();

        let agent_service = Box::new(AgentService {
            sandbox: Arc::new(Mutex::new(sandbox)),
            init_mode: true,
            oma: None,
        });

        let req = protocols::agent::UpdateInterfaceRequest::default();
        let ctx = mk_ttrpc_context();

        let result = agent_service.update_interface(&ctx, req).await;

        assert!(result.is_err(), "expected update interface to fail");
    }

    #[tokio::test]
    async fn test_update_routes() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Sandbox::new(&logger).unwrap();
        let agent_service = Box::new(AgentService {
            sandbox: Arc::new(Mutex::new(sandbox)),
            init_mode: true,
            oma: None,
        });

        let req = protocols::agent::UpdateRoutesRequest::default();
        let ctx = mk_ttrpc_context();

        let result = agent_service.update_routes(&ctx, req).await;

        assert!(result.is_err(), "expected update routes to fail");
    }

    #[tokio::test]
    async fn test_add_arp_neighbors() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Sandbox::new(&logger).unwrap();
        let agent_service = Box::new(AgentService {
            sandbox: Arc::new(Mutex::new(sandbox)),
            init_mode: true,
            oma: None,
        });

        let req = protocols::agent::AddARPNeighborsRequest::default();
        let ctx = mk_ttrpc_context();

        let result = agent_service.add_arp_neighbors(&ctx, req).await;

        assert!(result.is_err(), "expected add arp neighbors to fail");
    }

    #[tokio::test]
    #[cfg(not(target_arch = "powerpc64"))]
    async fn test_do_write_stream() {
        skip_if_not_root!();

        #[derive(Debug)]
        struct TestData<'a> {
            create_container: bool,
            has_fd: bool,
            has_tty: bool,
            break_pipe: bool,

            container_id: &'a str,
            exec_id: &'a str,
            data: Vec<u8>,
            result: Result<protocols::agent::WriteStreamResponse>,
        }

        impl Default for TestData<'_> {
            fn default() -> Self {
                TestData {
                    create_container: true,
                    has_fd: true,
                    has_tty: true,
                    break_pipe: false,

                    container_id: "1",
                    exec_id: "2",
                    data: vec![1, 2, 3],
                    result: Ok(WriteStreamResponse {
                        len: 3,
                        ..WriteStreamResponse::default()
                    }),
                }
            }
        }

        let tests = &[
            TestData {
                ..Default::default()
            },
            TestData {
                has_tty: false,
                ..Default::default()
            },
            TestData {
                break_pipe: true,
                result: Err(anyhow!(std::io::Error::from_raw_os_error(libc::EPIPE))),
                ..Default::default()
            },
            TestData {
                create_container: false,
                result: Err(anyhow!(crate::sandbox::SandboxError::InvalidContainerId)),
                ..Default::default()
            },
            TestData {
                container_id: "8181",
                result: Err(anyhow!(crate::sandbox::SandboxError::InvalidContainerId)),
                ..Default::default()
            },
            TestData {
                data: vec![],
                result: Ok(WriteStreamResponse {
                    len: 0,
                    ..WriteStreamResponse::default()
                }),
                ..Default::default()
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let logger = slog::Logger::root(slog::Discard, o!());
            let mut sandbox = Sandbox::new(&logger).unwrap();

            let (rfd, wfd) = unistd::pipe().unwrap();
            let rfd = if d.break_pipe {
                drop(rfd); // OwnedFd closes automatically on drop
                None
            } else {
                Some(rfd)
            };

            if d.create_container {
                let (mut linux_container, _root) = create_linuxcontainer();
                let exec_process_id = 2;

                linux_container.id = "1".to_string();

                let mut exec_process = Process::new(
                    &logger,
                    &oci::Process::default(),
                    &exec_process_id.to_string(),
                    false,
                    1,
                    None,
                )
                .unwrap();

                let fd = if d.has_fd {
                    let raw_fd = wfd.as_raw_fd();
                    std::mem::forget(wfd); // Prevent OwnedFd from closing the fd
                    Some(raw_fd)
                } else {
                    // Let wfd drop naturally to close the fd
                    drop(wfd);
                    None
                };

                if d.has_tty {
                    exec_process.parent_stdin = None;
                    exec_process.term_master = fd;
                } else {
                    exec_process.parent_stdin = fd;
                    exec_process.term_master = None;
                }
                linux_container
                    .processes
                    .insert(exec_process.exec_id.clone(), exec_process);

                sandbox.add_container(linux_container);
            }

            let agent_service = Box::new(AgentService {
                sandbox: Arc::new(Mutex::new(sandbox)),
                init_mode: true,
                oma: None,
            });

            let result = agent_service
                .do_write_stream(protocols::agent::WriteStreamRequest {
                    container_id: d.container_id.to_string(),
                    exec_id: d.exec_id.to_string(),
                    data: d.data.clone(),
                    ..Default::default()
                })
                .await;

            drop(rfd);
            // XXX: Do not close wfd.
            // the fd will be closed on Process's dropping.
            // unistd::close(wfd).unwrap();

            let msg = format!("{msg}, result: {result:?}");
            assert_result!(d.result, result, msg);
        }
    }
    #[tokio::test]
    async fn test_update_container_namespaces() {
        #[derive(Debug)]
        struct TestData<'a> {
            has_linux_in_spec: bool,
            sandbox_pidns_path: Option<&'a str>,

            namespaces: Vec<LinuxNamespace>,
            use_sandbox_pidns: bool,
            result: Result<()>,
            expected_namespaces: Vec<LinuxNamespace>,
        }

        impl Default for TestData<'_> {
            fn default() -> Self {
                TestData {
                    has_linux_in_spec: true,
                    sandbox_pidns_path: Some("sharedpidns"),
                    namespaces: vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Ipc)
                            .path("ipcpath")
                            .build()
                            .unwrap(),
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Uts)
                            .path("utspath")
                            .build()
                            .unwrap(),
                    ],
                    use_sandbox_pidns: false,
                    result: Ok(()),
                    expected_namespaces: vec![
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Ipc)
                            .build()
                            .unwrap(),
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Uts)
                            .build()
                            .unwrap(),
                        LinuxNamespaceBuilder::default()
                            .typ(LinuxNamespaceType::Pid)
                            .build()
                            .unwrap(),
                    ],
                }
            }
        }

        let tests = &[
            TestData {
                ..Default::default()
            },
            TestData {
                use_sandbox_pidns: true,
                expected_namespaces: vec![
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Ipc)
                        .build()
                        .unwrap(),
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Uts)
                        .build()
                        .unwrap(),
                    LinuxNamespaceBuilder::default()
                        .typ(LinuxNamespaceType::Pid)
                        .path("sharedpidns")
                        .build()
                        .unwrap(),
                ],
                ..Default::default()
            },
            TestData {
                namespaces: vec![],
                use_sandbox_pidns: true,
                expected_namespaces: vec![LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Pid)
                    .path("sharedpidns")
                    .build()
                    .unwrap()],
                ..Default::default()
            },
            TestData {
                namespaces: vec![],
                use_sandbox_pidns: false,
                expected_namespaces: vec![LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Pid)
                    .build()
                    .unwrap()],
                ..Default::default()
            },
            TestData {
                has_linux_in_spec: false,
                result: Err(anyhow!(ERR_NO_LINUX_FIELD)),
                ..Default::default()
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let logger = slog::Logger::root(slog::Discard, o!());
            let mut sandbox = Sandbox::new(&logger).unwrap();
            if let Some(pidns_path) = d.sandbox_pidns_path {
                let mut sandbox_pidns = Namespace::new(&logger);
                sandbox_pidns.path = pidns_path.to_string();
                sandbox.sandbox_pidns = Some(sandbox_pidns);
            }

            let mut oci = Spec::default();
            oci.set_linux(None);
            if d.has_linux_in_spec {
                let mut linux = Linux::default();
                linux.set_namespaces(Some(d.namespaces.clone()));
                oci.set_linux(Some(linux));
            }

            let result = update_container_namespaces(&sandbox, &mut oci, d.use_sandbox_pidns);

            let msg = format!("{msg}, result: {result:?}");

            assert_result!(d.result, result, msg);
            if let Some(linux) = oci.linux() {
                assert_eq!(
                    d.expected_namespaces,
                    linux.namespaces().clone().unwrap(),
                    "{msg}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_get_memory_info() {
        #[derive(Debug)]
        struct TestData<'a> {
            // if None is provided, no file will be generated, else the data in the Option will populate the file
            block_size_data: Option<&'a str>,

            hotplug_probe_data: bool,
            get_block_size: bool,
            get_hotplug: bool,
            result: Result<(u64, bool)>,
        }

        let tests = &[
            TestData {
                block_size_data: Some("10000000"),
                hotplug_probe_data: true,
                get_block_size: true,
                get_hotplug: true,
                result: Ok((268435456, true)),
            },
            TestData {
                block_size_data: Some("100"),
                hotplug_probe_data: false,
                get_block_size: true,
                get_hotplug: true,
                result: Ok((256, false)),
            },
            TestData {
                block_size_data: None,
                hotplug_probe_data: false,
                get_block_size: true,
                get_hotplug: true,
                result: Ok((0, false)),
            },
            TestData {
                block_size_data: Some(""),
                hotplug_probe_data: false,
                get_block_size: true,
                get_hotplug: false,
                result: Err(anyhow!(ERR_INVALID_BLOCK_SIZE)),
            },
            TestData {
                block_size_data: Some("-1"),
                hotplug_probe_data: false,
                get_block_size: true,
                get_hotplug: false,
                result: Err(anyhow!(ERR_INVALID_BLOCK_SIZE)),
            },
            TestData {
                block_size_data: Some("    "),
                hotplug_probe_data: false,
                get_block_size: true,
                get_hotplug: false,
                result: Err(anyhow!(ERR_INVALID_BLOCK_SIZE)),
            },
            TestData {
                block_size_data: Some("some data"),
                hotplug_probe_data: false,
                get_block_size: true,
                get_hotplug: false,
                result: Err(anyhow!(ERR_INVALID_BLOCK_SIZE)),
            },
            TestData {
                block_size_data: Some("some data"),
                hotplug_probe_data: true,
                get_block_size: false,
                get_hotplug: false,
                result: Ok((0, false)),
            },
            TestData {
                block_size_data: Some("100"),
                hotplug_probe_data: true,
                get_block_size: false,
                get_hotplug: false,
                result: Ok((0, false)),
            },
            TestData {
                block_size_data: Some("100"),
                hotplug_probe_data: true,
                get_block_size: false,
                get_hotplug: true,
                result: Ok((0, true)),
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let dir = tempdir().expect("failed to make tempdir");
            let block_size_path = dir.path().join("block_size_bytes");
            let hotplug_probe_path = dir.path().join("probe");

            if let Some(block_size_data) = d.block_size_data {
                fs::write(&block_size_path, block_size_data).unwrap();
            }
            if d.hotplug_probe_data {
                fs::write(&hotplug_probe_path, []).unwrap();
            }

            let result = get_memory_info(
                d.get_block_size,
                d.get_hotplug,
                block_size_path.to_str().unwrap(),
                hotplug_probe_path.to_str().unwrap(),
            );

            let msg = format!("{msg}, result: {result:?}");

            assert_result!(d.result, result, msg);
        }
    }

    #[tokio::test]
    async fn test_is_signal_handled() {
        #[derive(Debug)]
        struct TestData<'a> {
            status_file_data: Option<&'a str>,
            signum: u32,
            result: bool,
        }

        let tests = &[
            TestData {
                status_file_data: Some(
                    r#"
SigBlk:0000000000010000
SigCgt:0000000000000001
OtherField:other
                "#,
                ),
                signum: 1,
                result: true,
            },
            TestData {
                status_file_data: Some("SigCgt:000000004b813efb"),
                signum: 4,
                result: true,
            },
            TestData {
                status_file_data: Some("SigCgt:\t000000004b813efb"),
                signum: 4,
                result: true,
            },
            TestData {
                status_file_data: Some("SigCgt: 000000004b813efb"),
                signum: 4,
                result: true,
            },
            TestData {
                status_file_data: Some("SigCgt:000000004b813efb "),
                signum: 4,
                result: true,
            },
            TestData {
                status_file_data: Some("SigCgt:\t000000004b813efb "),
                signum: 4,
                result: true,
            },
            TestData {
                status_file_data: Some("SigCgt:000000004b813efb"),
                signum: 3,
                result: false,
            },
            TestData {
                status_file_data: Some("SigCgt:000000004b813efb"),
                signum: 65,
                result: false,
            },
            TestData {
                status_file_data: Some("SigCgt:000000004b813efb"),
                signum: 0,
                result: true,
            },
            TestData {
                status_file_data: Some("SigCgt:ZZZZZZZZ"),
                signum: 1,
                result: false,
            },
            TestData {
                status_file_data: Some("SigCgt:-1"),
                signum: 1,
                result: false,
            },
            TestData {
                status_file_data: Some("SigCgt"),
                signum: 1,
                result: false,
            },
            TestData {
                status_file_data: Some("any data"),
                signum: 0,
                result: true,
            },
            TestData {
                status_file_data: Some("SigBlk:0000000000000001"),
                signum: 1,
                result: true,
            },
            TestData {
                status_file_data: Some("SigIgn:0000000000000001"),
                signum: 1,
                result: true,
            },
            TestData {
                status_file_data: None,
                signum: 1,
                result: false,
            },
            TestData {
                status_file_data: None,
                signum: 0,
                result: false,
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");

            let dir = tempdir().expect("failed to make tempdir");
            let proc_status_file_path = dir.path().join("status");

            if let Some(file_data) = d.status_file_data {
                fs::write(&proc_status_file_path, file_data).unwrap();
            }

            let result = is_signal_handled(proc_status_file_path.to_str().unwrap(), d.signum);

            let msg = format!("{msg}, result: {result:?}");

            assert_eq!(d.result, result, "{msg}");
        }
    }

    #[tokio::test]
    async fn test_volume_capacity_stats() {
        skip_if_not_root!();

        // Verify error if path does not exist
        assert!(get_volume_capacity_stats("/does-not-exist").is_err());

        // Create a new tmpfs mount, and verify the initial values
        let mount_dir = tempfile::tempdir().unwrap();
        mount::mount(
            Some("tmpfs"),
            mount_dir.path().to_str().unwrap(),
            Some("tmpfs"),
            mount::MsFlags::empty(),
            None::<&str>,
        )
        .unwrap();
        let mut stats = get_volume_capacity_stats(mount_dir.path().to_str().unwrap()).unwrap();
        assert_eq!(stats.used, 0);
        assert_ne!(stats.available, 0);
        let available = stats.available;

        // Verify that writing a file will result in increased utilization
        fs::write(mount_dir.path().join("file.dat"), "foobar").unwrap();
        stats = get_volume_capacity_stats(mount_dir.path().to_str().unwrap()).unwrap();

        let size = get_block_size(mount_dir.path().to_str().unwrap()).unwrap();

        assert_eq!(stats.used, size);
        assert_eq!(stats.available, available - size);
    }

    fn get_block_size(path: &str) -> Result<u64, Errno> {
        let stat = statfs::statfs(path)?;
        let block_size = stat.block_size() as u64;
        Ok(block_size)
    }

    #[tokio::test]
    async fn test_get_volume_inode_stats() {
        skip_if_not_root!();

        // Verify error if path does not exist
        assert!(get_volume_inode_stats("/does-not-exist").is_err());

        // Create a new tmpfs mount, and verify the initial values
        let mount_dir = tempfile::tempdir().unwrap();
        mount::mount(
            Some("tmpfs"),
            mount_dir.path().to_str().unwrap(),
            Some("tmpfs"),
            mount::MsFlags::empty(),
            None::<&str>,
        )
        .unwrap();
        let mut stats = get_volume_inode_stats(mount_dir.path().to_str().unwrap()).unwrap();
        assert_eq!(stats.used, 1);
        assert_ne!(stats.available, 0);
        let available = stats.available;

        // Verify that creating a directory and writing a file will result in increased utilization
        let dir = mount_dir.path().join("foobar");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.as_path().join("file.dat"), "foobar").unwrap();
        stats = get_volume_inode_stats(mount_dir.path().to_str().unwrap()).unwrap();

        assert_eq!(stats.used, 3);
        assert_eq!(stats.available, available - 2);
    }

    #[tokio::test]
    async fn test_ip_tables() {
        skip_if_not_root!();

        let iptables_cmd_list = [
            USR_IPTABLES_SAVE,
            USR_IP6TABLES_SAVE,
            USR_IPTABLES_RESTORE,
            USR_IP6TABLES_RESTORE,
            IPTABLES_SAVE,
            IP6TABLES_SAVE,
            IPTABLES_RESTORE,
            IP6TABLES_RESTORE,
        ];

        for cmd in iptables_cmd_list {
            if !check_command(cmd) {
                warn!(
                    sl(),
                    "one or more commands for ip tables test are missing, skip it"
                );
                return;
            }
        }

        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Sandbox::new(&logger).unwrap();
        let agent_service = Box::new(AgentService {
            sandbox: Arc::new(Mutex::new(sandbox)),
            init_mode: true,
            oma: None,
        });

        let ctx = mk_ttrpc_context();

        // Move to a new netns in order to ensure we don't trash the hosts' iptables
        unshare(CloneFlags::CLONE_NEWNET).unwrap();

        // Get initial iptables, we expect to be empty:
        let result = agent_service
            .get_ip_tables(
                &ctx,
                GetIPTablesRequest {
                    is_ipv6: false,
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_ok(), "get ip tables should succeed");
        assert_eq!(
            result.unwrap().data.len(),
            0,
            "ip tables should be empty initially"
        );

        // Initial ip6 ip tables should also be empty:
        let result = agent_service
            .get_ip_tables(
                &ctx,
                GetIPTablesRequest {
                    is_ipv6: true,
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_ok(), "get ip6 tables should succeed");
        assert_eq!(
            result.unwrap().data.len(),
            0,
            "ip tables should be empty initially"
        );

        // Verify that attempting to write 'empty' iptables results in no error:
        let empty_rules = "";
        let result = agent_service
            .set_ip_tables(
                &ctx,
                SetIPTablesRequest {
                    is_ipv6: false,
                    data: empty_rules.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_ok(), "set ip tables with no data should succeed");

        // Verify that attempting to write "garbage" iptables results in an error:
        let garbage_rules = r#"
this
is
just garbage
"#;
        let result = agent_service
            .set_ip_tables(
                &ctx,
                SetIPTablesRequest {
                    is_ipv6: false,
                    data: garbage_rules.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_err(), "set iptables with garbage should fail");

        // Verify setup of valid iptables:Setup  valid set of iptables:
        let valid_rules = r#"
*nat
-A PREROUTING -d 192.168.103.153/32 -j DNAT --to-destination 192.168.188.153

COMMIT

"#;
        let result = agent_service
            .set_ip_tables(
                &ctx,
                SetIPTablesRequest {
                    is_ipv6: false,
                    data: valid_rules.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_ok(), "set ip tables should succeed");

        let result = agent_service
            .get_ip_tables(
                &ctx,
                GetIPTablesRequest {
                    is_ipv6: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!result.data.is_empty(), "we should have non-zero output:");
        assert!(
            std::str::from_utf8(&result.data).unwrap().contains(
                "PREROUTING -d 192.168.103.153/32 -j DNAT --to-destination 192.168.188.153"
            ),
            "We should see the resulting rule"
        );

        // Verify setup of valid ip6tables:
        let valid_ipv6_rules = r#"
*filter
-A INPUT -s 2001:db8:100::1/128 -i sit+ -p tcp -m tcp --sport 512:65535

COMMIT

"#;
        let result = agent_service
            .set_ip_tables(
                &ctx,
                SetIPTablesRequest {
                    is_ipv6: true,
                    data: valid_ipv6_rules.as_bytes().to_vec(),
                    ..Default::default()
                },
            )
            .await;
        assert!(result.is_ok(), "set ip6 tables should succeed");

        let result = agent_service
            .get_ip_tables(
                &ctx,
                GetIPTablesRequest {
                    is_ipv6: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(!result.data.is_empty(), "we should have non-zero output:");
        assert!(
            std::str::from_utf8(&result.data)
                .unwrap()
                .contains("INPUT -s 2001:db8:100::1/128 -i sit+ -p tcp -m tcp --sport 512:65535"),
            "We should see the resulting rule"
        );
    }

    #[tokio::test]
    async fn test_is_sealed_secret_path() {
        #[derive(Debug)]
        struct TestData<'a> {
            source_path: &'a str,
            result: bool,
        }

        let tests = &[
            TestData {
                source_path: "/run/kata-containers/shared/containers/somefile",
                result: true,
            },
            TestData {
                source_path: "/run/kata-containers/shared/containers/a128482812bad768f404e063f225decd425fc94a673aec4add45a9caa1122ccb-75490e32e51da3ff-resolv.conf",
                result: false,
            },
            TestData {
                source_path: "/run/kata-containers/shared/containers/a128482812bad768f404e063f225decd425fc94a673aec4add45a9caa1122ccb-75490e32e51da3ff-termination-log",
                result: false,
            },
            TestData {
                source_path: "/run/kata-containers/shared/containers/a128482812bad768f404e063f225decd425fc94a673aec4add45a9caa1122ccb-75490e32e51da3ff-hostname",
                result: false,
            },
            TestData {
                source_path: "/run/kata-containers/shared/containers/a128482812bad768f404e063f225decd425fc94a673aec4add45a9caa1122ccb-75490e32e51da3ff-hosts",
                result: false,
            },
            TestData {
                source_path: "/run/kata-containers/shared/containers/a128482812bad768f404e063f225decd425fc94a673aec4add45a9caa1122ccb-75490e32e51da3ff-serviceaccount",
                result: false,
            },
            TestData {
                source_path: "/run/kata-containers/shared/containers/a128482812bad768f404e063f225decd425fc94a673aec4add45a9caa1122ccb-75490e32e51da3ff-mysecret",
                result: true,
            },
            TestData {
                source_path: "/some/other/path",
                result: false,
            },
        ];

        for (i, d) in tests.iter().enumerate() {
            let msg = format!("test[{i}]: {d:?}");
            let result = is_sealed_secret_path(d.source_path);
            assert_eq!(d.result, result, "{msg}");
        }
    }

    // Drives two concurrent `GetOOMEvent` handlers to prove the lock discipline: the
    // handler must release the sandbox lock before awaiting `recv()`, or a second caller
    // deadlocks.
    //
    // This runs in every configuration. It used to be `cfg(not(agent-policy))`, because
    // `get_oom_event` calls `is_allowed` as its first statement and an empty policy
    // engine refuses everything, so the handler failed before reaching the `recv()` under
    // test. That was a defect in the test, not the handler — the property lives *after*
    // the policy gate and is configuration-independent — but the gate meant the only test
    // in this crate that drives a ttrpc handler at all was excluded from precisely the
    // builds that ship. Installing a permissive policy makes the policy builds exercise
    // byte-identical code.
    #[tokio::test]
    async fn test_get_oom_event_no_deadlock() {
        // Held for the duration: releasing it early would let another policy-driven test
        // swap the active policy out from under the handlers below.
        #[cfg(feature = "agent-policy")]
        let _policy_guard = crate::policy::test_support::install_policy(concat!(
            "package agent_policy\n",
            "default GetOOMEventRequest := true\n",
            // Explicit, so a query for an unrelated endpoint still returns a result
            // rather than an engine error. Without it this policy would be permissive
            // for `GetOOMEvent` and *indeterminate* for everything else.
            "default AllowRequestsFailingPolicy := false\n",
        ))
        .await;

        let logger = slog::Logger::root(slog::Discard, o!());
        let sandbox = Sandbox::new(&logger).unwrap();

        let agent_service = Arc::new(AgentService {
            sandbox: Arc::new(Mutex::new(sandbox)),
            init_mode: true,
            oma: None,
        });

        let svc1 = agent_service.clone();
        let handle1 = tokio::spawn(async move {
            let ctx = mk_ttrpc_context();
            let req = protocols::agent::GetOOMEventRequest::default();
            svc1.get_oom_event(&ctx, req).await
        });

        // Yield until handler #1 has released the sandbox lock (entered recv()).
        // Each yield_now() gives the spawned task a chance to make progress.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                tokio::task::yield_now().await;
                if agent_service.sandbox.try_lock().is_ok() {
                    return;
                }
            }
        })
        .await
        .expect("sandbox lock should be free while get_oom_event waits");

        let svc2 = agent_service.clone();
        let handle2 = tokio::spawn(async move {
            let ctx = mk_ttrpc_context();
            let req = protocols::agent::GetOOMEventRequest::default();
            svc2.get_oom_event(&ctx, req).await
        });

        // Yield until handler #2 has also released the sandbox lock (entered recv()).
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                tokio::task::yield_now().await;
                if agent_service.sandbox.try_lock().is_ok() {
                    return;
                }
            }
        })
        .await
        .expect("sandbox lock should be free with two concurrent get_oom_event handlers");

        let tx = {
            let s = agent_service.sandbox.lock().await;
            s.event_tx.as_ref().unwrap().clone()
        };
        tx.send("container-1".to_string()).await.unwrap();
        tx.send("container-2".to_string()).await.unwrap();

        let result1 = tokio::time::timeout(std::time::Duration::from_secs(5), handle1).await;
        let result2 = tokio::time::timeout(std::time::Duration::from_secs(5), handle2).await;

        assert!(result1.is_ok(), "handler #1 timed out — possible deadlock");
        assert!(result2.is_ok(), "handler #2 timed out — possible deadlock");

        let resp1 = result1.unwrap().unwrap().unwrap();
        let resp2 = result2.unwrap().unwrap().unwrap();

        let mut ids: Vec<String> = vec![resp1.container_id, resp2.container_id];
        ids.sort();
        assert_eq!(ids, vec!["container-1", "container-2"]);
    }

    #[tokio::test]
    async fn test_do_copy_file() {
        let temp_dir = tempdir().expect("creating temp dir failed");
        // We start one directory deeper such that we catch problems when the shared directory does
        // not exist yet.
        let base = temp_dir.path().join("shared");

        type Assertions = Box<dyn Fn(&Path) -> Result<()>>;
        struct TestCase {
            name: String,
            request: CopyFileRequest,
            assertions: Assertions,
            should_fail: bool,
        }

        // Attention: these test cases depend on each other and can't be reordered.
        // The first few cases build up a directory structure that the subsequent tests then rely
        // on or try to exploit.
        // TODO(burgerdev): define a common  directory structure for all tests up front.
        let tests = [
            TestCase {
                name: "Create a top-level file".into(),
                request: CopyFileRequest {
                    path: base.join("f").to_string_lossy().into(),
                    file_mode: 0o644 | libc::S_IFREG,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let f = base.join("f");
                    let f_stat = fs::metadata(&f).context("stat ./f failed")?;
                    ensure!(f_stat.is_file());
                    ensure!(0o644 == f_stat.permissions().mode() & 0o777);
                    let content = std::fs::read_to_string(&f).context("read ./f failed")?;
                    ensure!(content.is_empty());
                    Ok(())
                }),
            },
            TestCase {
                name: "Writing a file onto an existing file replaces it".into(),
                request: CopyFileRequest {
                    path: base.join("f").to_string_lossy().into(),
                    file_mode: 0o600 | libc::S_IFREG,
                    data: b"Hello!".to_vec(),
                    file_size: 6,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let f = base.join("f");
                    let f_stat = fs::metadata(&f).context("stat ./f failed")?;
                    ensure!(f_stat.is_file());
                    ensure!(0o600 == f_stat.permissions().mode() & 0o777);
                    let content = std::fs::read_to_string(&f).context("read ./f failed")?;
                    ensure!("Hello!" == content);
                    Ok(())
                }),
            },
            TestCase {
                name: "Creating a file implicitly creates parent directories".into(),
                request: CopyFileRequest {
                    path: base.join("a/b").to_string_lossy().into(),
                    dir_mode: 0o755 | libc::S_IFDIR,
                    file_mode: 0o644 | libc::S_IFREG,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let a_stat = fs::metadata(base.join("a")).context("stat ./a failed")?;
                    ensure!(a_stat.is_dir());
                    ensure!(0o755 == a_stat.permissions().mode() & 0o777);
                    let b_stat = fs::metadata(base.join("a/b")).context("stat ./a/b failed")?;
                    ensure!(b_stat.is_file());
                    ensure!(0o644 == b_stat.permissions().mode() & 0o777);
                    Ok(())
                }),
            },
            TestCase {
                name: "Create a file within an existing directory".into(),
                request: CopyFileRequest {
                    path: base.join("a/c").to_string_lossy().into(),
                    dir_mode: 0o700 | libc::S_IFDIR, // Test that existing directories are not touched - we expect this to stay 0o755.
                    file_mode: 0o621 | libc::S_IFREG,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let a_stat = fs::metadata(base.join("a")).context("stat ./a failed")?;
                    ensure!(a_stat.is_dir());
                    ensure!(0o755 == a_stat.permissions().mode() & 0o777);
                    let c_stat = fs::metadata(base.join("a/c")).context("stat ./a/c failed")?;
                    ensure!(c_stat.is_file());
                    ensure!(0o621 == c_stat.permissions().mode() & 0o777);
                    Ok(())
                }),
            },
            TestCase {
                name: "Create a directory".into(),
                request: CopyFileRequest {
                    path: base.join("a/d").to_string_lossy().into(),
                    dir_mode: 0o700 | libc::S_IFDIR, // Test that the permissions are taken from file_mode.
                    file_mode: 0o755 | libc::S_IFDIR,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let a_stat = fs::metadata(base.join("a")).context("stat ./a failed")?;
                    ensure!(a_stat.is_dir());
                    ensure!(0o755 == a_stat.permissions().mode() & 0o777);
                    let d_stat = fs::metadata(base.join("a/d")).context("stat ./a/d failed")?;
                    ensure!(d_stat.is_dir());
                    ensure!(0o755 == d_stat.permissions().mode() & 0o777);
                    Ok(())
                }),
            },
            TestCase {
                name: "Creating a dir onto an existing file replaces the file".into(),
                request: CopyFileRequest {
                    path: base.join("a/b").to_string_lossy().into(),
                    dir_mode: 0o700 | libc::S_IFDIR, // Test that the permissions are taken from file_mode.
                    file_mode: 0o755 | libc::S_IFDIR,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let b_stat = fs::metadata(base.join("a/b")).context("stat ./a/b failed")?;
                    ensure!(b_stat.is_dir());
                    ensure!(0o755 == b_stat.permissions().mode() & 0o777);
                    Ok(())
                }),
            },
            TestCase {
                name: "Creating a file onto an existing dir replaces the dir".into(),
                request: CopyFileRequest {
                    path: base.join("a/b").to_string_lossy().into(),
                    dir_mode: 0o755 | libc::S_IFDIR,
                    file_mode: 0o644 | libc::S_IFREG,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let b_stat = fs::metadata(base.join("a/b")).context("stat ./a/b failed")?;
                    ensure!(b_stat.is_file());
                    ensure!(0o644 == b_stat.permissions().mode() & 0o777);
                    Ok(())
                }),
            },
            TestCase {
                name: "Creating a dir onto an existing dir does not replace that dir".into(),
                request: CopyFileRequest {
                    path: base.join("a").to_string_lossy().into(),
                    dir_mode: 0o755 | libc::S_IFDIR,
                    file_mode: 0o751 | libc::S_IFDIR,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    // Check that a/b still exists
                    let b_stat = fs::metadata(base.join("a/b")).context("stat ./a/b failed")?;
                    ensure!(b_stat.is_file());
                    let a_stat = fs::metadata(base.join("a")).context("stat ./a failed")?;
                    ensure!(0o751 == a_stat.permissions().mode() & 0o777);
                    Ok(())
                }),
            },
            TestCase {
                name: "Create a symlink".into(),
                request: CopyFileRequest {
                    path: base.join("a/link").to_string_lossy().into(),
                    dir_mode: 0o700 | libc::S_IFDIR, // Test that the permissions are taken from file_mode.
                    file_mode: 0o755 | libc::S_IFLNK,
                    data: b"/etc/passwd".to_vec(),
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let link = base.join("a/link");
                    let link_stat = nix::sys::stat::lstat(&link).context("stat ./a/link failed")?;
                    // Linux symlinks have no permissions!
                    ensure!(0o777 | libc::S_IFLNK == link_stat.st_mode);
                    let target = fs::read_link(&link).context("read_link ./a/link failed")?;
                    ensure!(target.to_string_lossy() == "/etc/passwd");
                    Ok(())
                }),
            },
            TestCase {
                name: "Create a directory with setgid and sticky bit".into(),
                request: CopyFileRequest {
                    path: base.join("x/y").to_string_lossy().into(),
                    dir_mode: 0o3755 | libc::S_IFDIR,
                    file_mode: 0o3770 | libc::S_IFDIR,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    // Implicitly created directories should not get a sticky bit.
                    let x_stat = fs::metadata(base.join("x")).context("stat ./x failed")?;
                    ensure!(x_stat.is_dir());
                    ensure!(0o755 == x_stat.permissions().mode() & 0o7777);
                    // Explicitly created directories should.
                    let y_stat = fs::metadata(base.join("x/y")).context("stat ./x/y failed")?;
                    ensure!(y_stat.is_dir());
                    ensure!(0o3770 == y_stat.permissions().mode() & 0o7777);
                    Ok(())
                }),
            },
            TestCase {
                name: "Chunked upload 1".into(),
                request: CopyFileRequest {
                    path: base.join("x/chunked").to_string_lossy().into(),
                    dir_mode: 0o755 | libc::S_IFDIR,
                    file_mode: 0o644 | libc::S_IFREG,
                    offset: 0,
                    file_size: 11,
                    data: b"Hello ".to_vec(),
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    ensure!(
                        !(fs::exists(base.join("x/chunked"))
                            .context("exists ./x/chunked failed")?)
                    );
                    Ok(())
                }),
            },
            TestCase {
                name: "Chunked upload 2".into(),
                request: CopyFileRequest {
                    path: base.join("x/chunked").to_string_lossy().into(),
                    dir_mode: 0o755 | libc::S_IFDIR,
                    file_mode: 0o644 | libc::S_IFREG,
                    offset: 6,
                    file_size: 11,
                    data: b"World".to_vec(),
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    let content = std::fs::read(base.join("x/chunked"))?;
                    println!("{:?}", content);
                    ensure!(b"Hello World".to_vec() == content);
                    Ok(())
                }),
            },
            // =================================
            // Below are some adversarial tests.
            // =================================
            TestCase {
                name: "Malicious intermediate directory is a symlink".into(),
                request: CopyFileRequest {
                    path: base
                        .join("a/link/this-could-just-be-shadow-but-I-am-not-risking-it")
                        .to_string_lossy()
                        .into(),
                    dir_mode: 0o700 | libc::S_IFDIR, // Test that the permissions are taken from file_mode.
                    file_mode: 0o755 | libc::S_IFLNK,
                    data: b"root:password:19000:0:99999:7:::\n".to_vec(),
                    file_size: 33,
                    ..Default::default()
                },
                should_fail: true,
                assertions: Box::new(|base| -> Result<()> {
                    let link_stat = nix::sys::stat::lstat(&base.join("a/link"))
                        .context("stat ./a/link failed")?;
                    ensure!(0o777 | libc::S_IFLNK == link_stat.st_mode);
                    Ok(())
                }),
            },
            TestCase {
                name: "Creating a symlink onto an existing symlink should replace the symlink, not follow it".into(),
                request: CopyFileRequest {
                    path: base.join("a/link").to_string_lossy().into(),
                    dir_mode: 0o700 | libc::S_IFDIR, // Test that the permissions are taken from file_mode.
                    file_mode: 0o755 | libc::S_IFLNK,
                    data: b"/etc".to_vec(),
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    // The symlink should be created at the same place (not followed), with the new content.
                    let a_stat = fs::metadata(base.join("a")).context("stat ./a failed")?;
                    ensure!(a_stat.is_dir());
                    ensure!(0o751 == a_stat.permissions().mode() & 0o777);
                    let link = base.join("a/link");
                    let link_stat = nix::sys::stat::lstat(&link).context("stat ./a/link failed")?;
                    // Linux symlinks have no permissions!
                    ensure!(0o777 | libc::S_IFLNK == link_stat.st_mode);
                    let target = fs::read_link(&link).context("read_link ./a/link failed")?;
                    ensure!(target.to_string_lossy() == "/etc");
                    Ok(())
                }),
            },
            TestCase {
                name: "Creating a file at an existing symlink replaces the link and does not follow it".into(),
                request: CopyFileRequest {
                    path: base.join("a/link").to_string_lossy().into(),
                    file_mode: 0o600 | libc::S_IFREG,
                    data: b"Hello!".to_vec(),
                    file_size: 6,
                    ..Default::default()
                },
                should_fail: false,
                assertions: Box::new(|base| -> Result<()> {
                    // The symlink itself should be replaced with the file, not followed.
                    let link = base.join("a/link");
                    let link_stat = nix::sys::stat::lstat(&link).context("stat ./a/link failed")?;
                    ensure!(0o600 | libc::S_IFREG == link_stat.st_mode);
                    let content = std::fs::read_to_string(&link).context("read ./a/link failed")?;
                    ensure!("Hello!" == content);
                    Ok(())
                }),
            },
            TestCase {
                name: "Writing outside the shared directory is rejected".into(),
                request: CopyFileRequest {
                    path: base.parent().unwrap().join("not-shared").to_string_lossy().into(),
                    file_mode: 0o600 | libc::S_IFREG,
                    ..Default::default()
                },
                should_fail: true,
                assertions: Box::new(|base| -> Result<()> {
                    match fs::metadata(base.parent().unwrap().join("not-shared")) {
                        Ok(_) => bail!("successful write outside shared directory"),
                        Err(_) => Ok(())
                    }
                }),
            },
            TestCase {
                name: "Traversal outside shared directory is rejected".into(),
                request: CopyFileRequest {
                    path: base.join("../not-shared").to_string_lossy().into(),
                    file_mode: 0o600 | libc::S_IFREG,
                    ..Default::default()
                },
                should_fail: true,
                assertions: Box::new(|base| -> Result<()> {
                    match fs::metadata(base.join("../not-shared")) {
                        Ok(_) => bail!("successful write outside shared directory"),
                        Err(_) => Ok(())
                    }
                }),
            },
        ];

        let uid = unistd::getuid().as_raw() as i32;
        let gid = unistd::getgid().as_raw() as i32;

        for mut tc in tests {
            println!("Running test case: {}", tc.name);
            // Since we're in a unit test, using root ownership causes issues with cleaning the temp dir.
            tc.request.uid = uid;
            tc.request.gid = gid;

            let res = do_copy_file(&tc.request, &base);
            if tc.should_fail != res.is_err() {
                panic!("{}: unexpected do_copy_file result: {:?}", tc.name, res)
            }
            (tc.assertions)(&base).context(tc.name).unwrap()
        }
    }

    // RM-6: the reference-monitor integration lives here in `rpc.rs`, but every test for
    // it lived in the `kata-security-reference-monitor` crate. That crate is well covered,
    // and the defects still found in FR-6 -- removal never wrapped in a transaction, the
    // replay cache applied to repeatable operations, commit results discarded -- were all
    // wiring defects at this layer, which crate-level tests cannot see. These cover the
    // decisions this file makes.
    #[cfg(feature = "strict-policy")]
    mod srm_integration {
        use super::*;
        use kata_security_reference_monitor::{
            OccurrenceError, OccurrenceRegistry, Prepared, ReferenceMonitor, SrmError, TxnState,
            VerifiedCdiDevice,
        };

        /// The five operation ids `rpc.rs` builds, as the call sites build them.
        fn all_op_ids(cid: &str, exec: &str, signal: u32) -> Vec<String> {
            vec![
                srm_op_id("create", &[cid]),
                srm_op_id("start", &[cid]),
                srm_op_id("remove", &[cid]),
                srm_op_id("exec", &[cid, exec]),
                srm_op_id("signal", &[cid, exec, &signal.to_string()]),
            ]
        }

        const BOUND_CID: &str = "bound-ctr";

        /// A spec as the host supplies it, rooted where the host asked.
        fn authorized_spec() -> serde_json::Value {
            serde_json::json!({
                "ociVersion": "1.0.2",
                "root": { "path": "/host/supplied/rootfs", "readonly": true },
                "mounts": [{ "destination": "/proc", "type": "proc", "source": "proc" }],
                "process": {
                    "args": ["/bin/sh", "-c", "echo hello"],
                    "cwd": "/",
                    "user": { "uid": 1000, "gid": 1000 }
                },
                "linux": { "namespaces": [{ "type": "pid" }] }
            })
        }

        /// The same spec after the in-guest chain has run: `setup_bundle` has
        /// rebound the rootfs to the path the guest derived.
        fn executed_spec() -> serde_json::Value {
            let mut spec = authorized_spec();
            spec["root"]["path"] =
                serde_json::json!(container_rootfs_path(BOUND_CID).to_str().unwrap());
            spec
        }

        fn spec_of(value: serde_json::Value) -> Spec {
            serde_json::from_value(value).expect("test spec should deserialize")
        }

        /// Run the binding exactly as `do_create_container` does, digests included.
        fn bind(authorized: serde_json::Value, executed: serde_json::Value) -> Result<()> {
            let authorized = spec_of(authorized);
            let executed = spec_of(executed);
            enforce_plan_binding(
                BOUND_CID,
                &authorized,
                &plan_digest(&authorized),
                &executed,
                &plan_digest(&executed),
            )
        }

        /// FR-3: the resolved plan reaches the runtime only if it is still the
        /// plan the policy authorized.
        ///
        /// `plan_binding`'s own tests compare specs a test hands them; they never
        /// see the expected rootfs `rpc.rs` derives, nor whether the verdict is
        /// returned or merely logged. These exercise the agent's decision.
        #[test]
        fn the_resolved_plan_is_admitted_when_only_trusted_transforms_ran() {
            let mut executed = executed_spec();
            // update_container_namespaces rewrites namespaces; storage and device
            // handling append mounts.
            executed["linux"]["namespaces"] = serde_json::json!([{ "type": "ipc" }]);
            executed["mounts"] = serde_json::json!([
                { "destination": "/proc", "type": "proc", "source": "proc" },
                { "destination": "/dev/shm", "type": "tmpfs", "source": "shm" }
            ]);

            bind(authorized_spec(), executed)
                .expect("trusted in-guest transforms must not fail the create");
        }

        /// A host-supplied `bind-safer-path` mount is rewritten in place by
        /// `translate_bind_safer_path_mounts`, which runs *after* the authorized
        /// spec is captured. The rewrite is one of the trusted in-guest
        /// transforms and its result is derived by the guest alone, so it must
        /// not fail the create.
        ///
        /// Every content-channel mount takes this path -- network files and
        /// watchable volumes -- so a binding that refuses it refuses every
        /// container that has one.
        #[test]
        #[serial_test::serial]
        fn a_translated_bind_safer_path_mount_is_still_the_authorized_plan() {
            let _temp_dir = setup_volume_rpc_test();

            let mut safer = oci::Mount::default();
            safer.set_destination(PathBuf::from("/dev/termination-log"));
            safer.set_typ(Some("bind-safer-path".to_string()));
            safer.set_source(Some(PathBuf::from("single-files/sandbox-id/empty-file")));

            let mut authorized = spec_of(authorized_spec());
            authorized.mounts_mut().as_mut().unwrap().push(safer);

            let mut executed = authorized.clone();
            let mut root = executed.root().clone().unwrap();
            root.set_path(container_rootfs_path(BOUND_CID));
            executed.set_root(Some(root));
            translate_bind_safer_path_mounts(&mut executed)
                .expect("the translation itself must succeed");

            enforce_plan_binding(
                BOUND_CID,
                &authorized,
                &plan_digest(&authorized),
                &executed,
                &plan_digest(&executed),
            )
            .expect("a guest-derived content-channel mount rewrite must not fail the create");
        }

        /// The rewrite is pinned, not waived: resolving the identifier is the
        /// guest's job, but only to the path the guest itself derives. A
        /// transform that redirected the mount elsewhere -- to a path outside
        /// the share directory, say -- must still fail the create.
        #[test]
        #[serial_test::serial]
        fn a_redirected_content_channel_mount_still_fails_the_create() {
            let _temp_dir = setup_volume_rpc_test();

            let mut safer = oci::Mount::default();
            safer.set_destination(PathBuf::from("/dev/termination-log"));
            safer.set_typ(Some("bind-safer-path".to_string()));
            safer.set_source(Some(PathBuf::from("single-files/sandbox-id/empty-file")));

            let mut authorized = spec_of(authorized_spec());
            authorized.mounts_mut().as_mut().unwrap().push(safer);

            let mut executed = authorized.clone();
            let mut root = executed.root().clone().unwrap();
            root.set_path(container_rootfs_path(BOUND_CID));
            executed.set_root(Some(root));
            translate_bind_safer_path_mounts(&mut executed)
                .expect("the translation itself must succeed");
            executed.mounts_mut().as_mut().unwrap()[1]
                .set_source(Some(PathBuf::from("/etc/shadow")));

            let err = enforce_plan_binding(
                BOUND_CID,
                &authorized,
                &plan_digest(&authorized),
                &executed,
                &plan_digest(&executed),
            )
            .expect_err("a content-channel mount resolved elsewhere must fail the create");
            assert!(
                err.to_string().contains("plan binding violation"),
                "unexpected error: {}",
                err
            );
        }

        #[test]
        fn a_plan_mutated_outside_the_resolution_bounds_fails_the_create() {
            let mut executed = executed_spec();
            executed["process"]["args"] = serde_json::json!(["/bin/sh", "-c", "exfiltrate"]);

            // The verdict must be returned. An audit-only downgrade here would
            // leave every `plan_binding` unit test green.
            let err = bind(authorized_spec(), executed)
                .expect_err("a plan the policy never authorized must fail the create");
            assert!(
                err.to_string().contains("plan binding violation"),
                "unexpected error: {}",
                err
            );
        }

        #[test]
        fn the_created_container_is_rooted_only_where_the_guest_prepared() {
            let mut executed = executed_spec();
            executed["root"]["path"] = serde_json::json!("/run/kata-containers/other/rootfs");

            let err = bind(authorized_spec(), executed)
                .expect_err("a re-rooted container must fail the create");
            assert!(
                err.to_string().contains("is rooted at"),
                "unexpected error: {}",
                err
            );
        }

        /// The binding is not conditional on the digests differing: a plan that
        /// survived resolution untouched still has to be rooted where the guest
        /// prepared, or the host's own rootfs would pass unexamined.
        #[test]
        fn an_unchanged_plan_is_still_held_to_the_pinned_rootfs() {
            let host_rooted = authorized_spec();
            assert_eq!(
                plan_digest(&spec_of(host_rooted.clone())),
                plan_digest(&spec_of(host_rooted.clone())),
                "the two sides of this case must be digest-identical"
            );

            let err = bind(host_rooted.clone(), host_rooted)
                .expect_err("an unmodified but host-rooted plan must fail the create");
            assert!(
                err.to_string().contains("is rooted at"),
                "unexpected error: {}",
                err
            );
        }

        /// FR-3: the binding is only sound if the two objects it compares are
        /// captured at the right moments, and that is a property of the *order*
        /// of statements in `do_create_container`, not of any value the tests
        /// above can observe.
        ///
        /// The tests above prove that `enforce_plan_binding` decides correctly
        /// once it is called with an authorized object and an executed one. They
        /// cannot see (a) that `authorized_oci` is cloned before the first
        /// in-guest transformer runs, nor (b) that the check is reached after
        /// `setup_bundle` has rebound the rootfs. A regression that moved the
        /// clone below `add_devices` would authorize an already-transformed
        /// spec against itself; one that moved the check above `setup_bundle`
        /// would compare the plan before the rebinding it exists to police.
        /// Either leaves every other test in this module green.
        ///
        /// Asserting this end to end means driving `do_create_container`, which
        /// needs `baremount` and therefore root — it would be `skip_if_not_root!`
        /// gated and skipped in ordinary runs, i.e. no coverage where the
        /// regression would actually land. Reading the ordering out of the source
        /// is coarse, but it runs everywhere and fails loudly on exactly the
        /// rearrangement described above.
        #[test]
        fn the_authorized_object_is_captured_before_the_guest_transforms_it() {
            const SOURCE: &str = include_str!("rpc.rs");

            // Bound the search to the body of `do_create_container`, so that the
            // anchors this test names in its own source cannot satisfy it.
            let start = SOURCE
                .find("    async fn do_create_container(")
                .expect("do_create_container should be present");
            let end = start
                + SOURCE[start + 1..]
                    .find("\n    async fn ")
                    .expect("do_create_container should be followed by another method");
            let body = &SOURCE[start..end];

            let offset_of = |anchor: &str| -> usize {
                assert_eq!(
                    body.matches(anchor).count(),
                    1,
                    "anchor is no longer unique within do_create_container, so this \
                     test can no longer tell where it sits: {}",
                    anchor
                );
                body.find(anchor).unwrap()
            };

            let clone_of_authorized = offset_of("let authorized_oci = oci.clone();");
            let first_transform =
                offset_of("add_devices(&cid, &sl(), &req.devices, &mut oci, &self.sandbox)");
            let rootfs_rebinding = offset_of("let olddir = setup_bundle(&cid, &mut oci)?;");
            let binding_check = offset_of("enforce_plan_binding(");

            // (a) Nothing may transform `oci` between the host handing it over and
            // the clone, or the "authorized" object is one the guest already edited.
            assert!(
                clone_of_authorized < first_transform,
                "authorized_oci is cloned after add_devices: the object being \
                 authorized has already been transformed in-guest"
            );

            // (b) The executed object must be the fully resolved one, which is only
            // true once setup_bundle has rebound the rootfs.
            assert!(
                rootfs_rebinding < binding_check,
                "enforce_plan_binding runs before setup_bundle: it would compare \
                 the plan before the rootfs rebinding it exists to police"
            );
        }

        /// F-185: the trusted-CDI authorization must run before anything acts on the
        /// CDI-injected spec.
        ///
        /// `handle_cdi_devices` applies `containerEdits` from host-influenceable spec files
        /// directly into `oci`, and the authorization that decides whether those edits were
        /// ever permitted runs after it (deliberately -- the specs may not exist yet when
        /// the request arrives). That is safe only while nothing observes the mutated spec
        /// before the check: the moment `setup_bundle` writes it out or the container is
        /// started, an unauthorized edit has had an effect. This pins the order so that
        /// moving the check later, or moving `setup_bundle` earlier, fails loudly.
        #[cfg(feature = "strict-policy")]
        #[test]
        fn the_cdi_edits_are_authorized_before_anything_acts_on_them() {
            const SOURCE: &str = include_str!("rpc.rs");

            let start = SOURCE
                .find("    async fn do_create_container(")
                .expect("do_create_container should be present");
            let end = start
                + SOURCE[start + 1..]
                    .find("\n    async fn ")
                    .expect("do_create_container should be followed by another method");
            let body = &SOURCE[start..end];

            let offset_of = |anchor: &str| -> usize {
                assert_eq!(
                    body.matches(anchor).count(),
                    1,
                    "anchor is no longer unique within do_create_container, so this \
                     test can no longer tell where it sits: {}",
                    anchor
                );
                body.find(anchor).unwrap()
            };

            let cdi_injection = offset_of("handle_cdi_devices(");
            let cdi_authorization = offset_of("crate::device::authorize_cdi_resolution(");
            let bundle_written = offset_of("let olddir = setup_bundle(&cid, &mut oci)?;");

            assert!(
                cdi_injection < cdi_authorization,
                "authorize_cdi_resolution runs before handle_cdi_devices: the CDI specs \
                 may not have been written yet, so legitimate devices would be refused"
            );
            assert!(
                cdi_authorization < bundle_written,
                "the CDI edits are written to the bundle before they are authorized: an \
                 unauthorized containerEdit would have had an effect"
            );
        }

        #[test]
        fn the_operation_kinds_never_share_an_id() {
            let ids = all_op_ids("ctr1", "exec1", 15);
            let unique: std::collections::HashSet<_> = ids.iter().collect();
            assert_eq!(
                unique.len(),
                ids.len(),
                "operation kinds must not collide: {ids:?}"
            );
        }

        #[test]
        fn host_chosen_names_cannot_forge_another_operations_id() {
            // Container and exec ids come from the host, which is untrusted. With a plain
            // separator join these pairs all produce the same id, so a committed
            // transaction for one operation would be replayed as the result of another --
            // the agent returning success for work it never performed.
            //
            // Each case is a (container, exec) pair that a naive `{cid}:{exec}` encoding
            // maps onto the same string.
            let collisions = [(("a:b", "c"), ("a", "b:c")), (("x:", "y"), ("x", ":y"))];
            for ((c1, e1), (c2, e2)) in collisions {
                assert_ne!(
                    srm_op_id("exec", &[c1, e1]),
                    srm_op_id("exec", &[c2, e2]),
                    "({c1:?}, {e1:?}) and ({c2:?}, {e2:?}) must not share an operation id"
                );
            }

            // A container literally named so that its create id spells another kind's id.
            assert_ne!(
                srm_op_id("create", &[&srm_op_id("remove", &["victim"])]),
                srm_op_id("remove", &["victim"]),
            );

            // An exec id chosen to look like a signal operation on the same container.
            assert_ne!(
                srm_op_id("exec", &["ctr1", "e/1:9"]),
                srm_op_id("signal", &["ctr1", "e", "9"]),
            );
        }

        #[test]
        fn a_colliding_id_would_be_answered_from_the_replay_cache() {
            // Demonstrates why the above matters, using the monitor itself. A create
            // transaction is retained (it is only retired when the container is removed),
            // so any later operation that resolves to the same id is short-circuited.
            // Both `exec_process` and `signal_process` return `Ok(Empty)` on
            // `AlreadyCommitted` without running anything.
            let mut m = ReferenceMonitor::new();
            let create = srm_op_id("create", &["a:b"]);
            m.prepare(create.clone(), 0, "d1").unwrap();
            m.execute(&create, "d1").unwrap();
            m.commit(&create, "container-created").unwrap();

            // The exec that a separator-joined encoding would have aliased onto it.
            let exec = srm_op_id("exec", &["a", "b"]);
            assert_ne!(exec, create);
            assert_eq!(
                m.prepare(exec, m.state_version(), "d2").unwrap(),
                Prepared::New,
                "a distinct operation must not be answered from another's result"
            );
        }

        /// FR-3 regression: the executed-object binding must target the transaction the
        /// handler actually prepared.
        ///
        /// `create_container` prepares under `srm_op_id("create", ..)` but the binding used
        /// to be attempted against the bare container id, and the error was discarded. The
        /// two can never be equal — `srm_op_id` always prefixes a kind and a length — so
        /// the authorized->executed binding was silently never recorded. The handler now
        /// passes its operation id down to `do_create_container` instead of re-deriving
        /// one, and a failed binding fails the create.
        #[test]
        fn the_executed_binding_must_use_the_prepared_operation_id() {
            let cid = "mycid";
            let op = srm_op_id("create", &[cid]);
            assert_ne!(
                op, cid,
                "a bare container id is never a valid operation id; binding against it \
                 silently loses the FR-3 authorized->executed relationship"
            );

            let mut m = ReferenceMonitor::new();
            m.prepare(op.clone(), 0, "authorized").unwrap();
            m.execute(&op, "authorized").unwrap();

            assert!(
                m.attach_executed(cid, "executed".to_string()).is_err(),
                "the bare container id must not resolve to the create transaction"
            );
            m.attach_executed(&op, "executed".to_string())
                .expect("the prepared operation id must resolve");
            assert_eq!(
                m.transaction(&op).unwrap().executed_digest.as_deref(),
                Some("executed"),
                "FR-3 requires the executed object to be bound to the transaction"
            );
        }

        #[test]
        fn commit_or_quarantine_records_success_and_leaves_the_monitor_usable() {
            let mut m = ReferenceMonitor::new();
            let op = srm_op_id("create", &["ctr1"]);
            m.prepare(op.clone(), 0, "d").unwrap();
            m.execute(&op, "d").unwrap();

            commit_or_quarantine(&mut m, &op, "container-created", "create_container");

            assert_eq!(m.transaction(&op).unwrap().state, TxnState::Committed);
            assert!(
                m.prepare(srm_op_id("create", &["ctr2"]), m.state_version(), "d")
                    .is_ok(),
                "a successful commit must not quarantine the monitor"
            );
        }

        #[test]
        fn commit_or_quarantine_quarantines_when_the_record_cannot_be_made() {
            // The runtime operation has already succeeded by the time this runs, so a
            // failed commit means the monitor is silently wrong about a real effect.
            // Nothing may be admitted afterwards on state it cannot vouch for.
            let mut m = ReferenceMonitor::new();
            let op = srm_op_id("signal", &["ctr1", "", "15"]);

            // Never prepared: the shape an operation-id collision produces.
            commit_or_quarantine(&mut m, &op, "signal-delivered", "signal_process");

            assert!(matches!(
                m.prepare(srm_op_id("create", &["ctr2"]), m.state_version(), "d"),
                Err(SrmError::Quarantined(_))
            ));
        }

        /// FR-6: an operation id that is never resolved is never usable again, because
        /// `prepare` refuses an in-flight id rather than clobbering it. Every failure path
        /// after a successful `prepare` therefore has to abort.
        #[test]
        fn abort_or_quarantine_releases_the_id_for_a_later_attempt() {
            let mut m = ReferenceMonitor::new();
            let op = srm_op_id("remove", &["ctr1"]);
            m.prepare(op.clone(), 0, "d").unwrap();
            m.execute(&op, "d").unwrap();

            abort_or_quarantine(&mut m, &op, "remove_container");

            assert_eq!(
                m.prepare(op, m.state_version(), "d").unwrap(),
                Prepared::New,
                "a failed removal must stay retryable"
            );
        }

        /// An abort that itself fails means the transaction is not where the caller
        /// believes it is, so the monitor can no longer vouch for the state it guards.
        #[test]
        fn abort_or_quarantine_quarantines_when_the_transaction_is_unknown() {
            let mut m = ReferenceMonitor::new();

            abort_or_quarantine(&mut m, &srm_op_id("exec", &["ctr1", "e1"]), "exec_process");

            assert!(matches!(
                m.prepare(srm_op_id("create", &["ctr2"]), m.state_version(), "d"),
                Err(SrmError::Quarantined(_))
            ));
        }

        #[test]
        fn retire_or_warn_frees_the_id_and_tolerates_an_unknown_one() {
            let mut m = ReferenceMonitor::new();
            let op = srm_op_id("signal", &["ctr1", "", "1"]);
            m.prepare(op.clone(), 0, "d").unwrap();
            m.execute(&op, "d").unwrap();
            m.commit(&op, "signal-delivered").unwrap();

            retire_or_warn(&mut m, &op);
            assert!(m.transaction(&op).is_none());

            // A repeated signal is a legitimate request, not a replay, and must be
            // admitted rather than answered from the retained result.
            assert_eq!(
                m.prepare(op, m.state_version(), "d").unwrap(),
                Prepared::New
            );

            // Retiring something unknown must not panic or quarantine: the operation it
            // followed already succeeded.
            retire_or_warn(&mut m, "never-existed");
            assert!(m
                .prepare(srm_op_id("create", &["ctr2"]), m.state_version(), "d")
                .is_ok());
        }

        #[test]
        fn removing_a_container_frees_the_id_its_create_reserved() {
            // The sequence `remove_container` performs on success: commit the removal,
            // then retire both transactions so the container id is genuinely reusable.
            let mut m = ReferenceMonitor::new();
            let create = srm_op_id("create", &["ctr1"]);
            let remove = srm_op_id("remove", &["ctr1"]);

            m.prepare(create.clone(), 0, "d1").unwrap();
            m.execute(&create, "d1").unwrap();
            m.commit(&create, "container-created").unwrap();

            m.prepare(remove.clone(), m.state_version(), "d2").unwrap();
            m.execute(&remove, "d2").unwrap();
            commit_or_quarantine(&mut m, &remove, "container-removed", "remove_container");
            for id in [&create, &remove] {
                retire_or_warn(&mut m, id);
            }

            // Without retiring the create, this would be an idempotent replay and the new
            // container would never be created.
            assert_eq!(
                m.prepare(create, m.state_version(), "d3").unwrap(),
                Prepared::New
            );
        }

        /// RM-7: a quarantine must be distinguishable from a bad request. Everything else
        /// stays `FAILED_PRECONDITION`, which the shim may retry after fixing the request.
        #[test]
        fn only_a_quarantine_maps_to_data_loss() {
            assert_eq!(
                srm_code(&SrmError::Quarantined("unprovable".into())),
                ttrpc::Code::DATA_LOSS
            );
            for e in [
                SrmError::StaleStateVersion {
                    expected: 1,
                    current: 2,
                },
                SrmError::UnknownOperation("op".into()),
                SrmError::InvalidState {
                    op: "op".into(),
                    state: TxnState::Prepared,
                },
                SrmError::PlanMismatch {
                    authorized: "a".into(),
                    presented: "b".into(),
                },
                SrmError::ExecutedDigestAlreadyBound {
                    op: "op".into(),
                    bound: "a".into(),
                    presented: "b".into(),
                },
            ] {
                assert_eq!(
                    srm_code(&e),
                    ttrpc::Code::FAILED_PRECONDITION,
                    "{} is a per-request failure, not a degraded guest",
                    e
                );
            }
        }

        /// RM-7 regression: `do_create_container` performs the FR-3 executed-object
        /// binding, which is quarantine-gated (F-40). It is the only SRM call that
        /// returns its error through `anyhow` rather than being mapped by `srm_code` at
        /// the call site, so `create_container`'s error arm recovers the code by
        /// downcasting. Stringifying the error there — which is what the code used to do —
        /// flattens a quarantine into INTERNAL, and the shim reads INTERNAL as "malformed
        /// request" and retries a guest that can never succeed again.
        #[test]
        fn an_srm_error_keeps_its_code_through_the_create_container_boundary() {
            let wrapped = anyhow::Error::new(SrmError::Quarantined("unprovable".into()))
                .context("FR-3: failed to bind executed OCI object to op");

            let code = wrapped
                .downcast_ref::<SrmError>()
                .map_or(ttrpc::Code::INTERNAL, srm_code);

            assert_eq!(
                code,
                ttrpc::Code::DATA_LOSS,
                "a quarantine raised inside do_create_container must not reach the shim \
                 as a retryable INTERNAL"
            );

            let opaque = anyhow!("some unrelated create failure");
            assert_eq!(
                opaque
                    .downcast_ref::<SrmError>()
                    .map_or(ttrpc::Code::INTERNAL, srm_code),
                ttrpc::Code::INTERNAL,
                "non-SRM failures must keep the original INTERNAL mapping"
            );
        }

        /// F-35: an occurrence that could not be created must not be bound into.
        ///
        /// `create` fails only when a live occurrence already holds the alias. The old
        /// code discarded that error and ran the bind loop anyway, appending the new
        /// container's devices to the *stale* occurrence — so `devices()` returned the
        /// union of two containers' grants, which is an FR-11 integrity break.
        #[test]
        fn a_failed_occurrence_create_binds_no_devices() {
            let mut occ = OccurrenceRegistry::default();
            occ.create("ctr1", None, None).unwrap();
            occ.bind_device("ctr1", "vendor.com/gpu=0", "sha256:aaa")
                .unwrap();

            let devices = vec![VerifiedCdiDevice {
                device: "vendor.com/gpu=1".into(),
                spec_digest: "sha256:bbb".into(),
            }];

            assert_eq!(
                record_occurrence(&mut occ, "ctr1", &devices),
                Err(OccurrenceError::AliasInUse("ctr1".into())),
                "a second create for a live alias must be refused, not silently ignored"
            );
            assert_eq!(
                occ.devices("ctr1").map(<[_]>::to_vec),
                Some(vec![(
                    "vendor.com/gpu=0".to_string(),
                    "sha256:aaa".to_string()
                )]),
                "the incoming container's devices must not be attributed to the \
                 occurrence that already held the alias"
            );
        }

        /// F-35: the happy path still binds every verified device.
        #[test]
        fn a_successful_occurrence_create_binds_every_device() {
            let mut occ = OccurrenceRegistry::default();
            let devices = vec![
                VerifiedCdiDevice {
                    device: "vendor.com/gpu=0".into(),
                    spec_digest: "sha256:aaa".into(),
                },
                VerifiedCdiDevice {
                    device: "vendor.com/gpu=1".into(),
                    spec_digest: "sha256:bbb".into(),
                },
            ];

            assert_eq!(record_occurrence(&mut occ, "ctr1", &devices), Ok(()));
            assert_eq!(
                occ.devices("ctr1").map(<[_]>::len),
                Some(2),
                "every trusted-resolved device must be bound to the new occurrence"
            );
        }

        /// F-35: a bind failure cannot be reached through today's registry, and the test
        /// suite should say so rather than pretend otherwise.
        ///
        /// `bind_device` refuses only an absent or already-removed alias, and a successful
        /// `create` leaves the alias present and `Created`. So the `?` in
        /// `record_occurrence`'s loop is unreachable by construction. This test pins that
        /// premise: if a later change makes a bind fail mid-loop, this assertion breaks and
        /// forces the loop-break behaviour to be given a real test.
        #[test]
        fn no_bind_can_fail_once_the_occurrence_was_created() {
            let mut occ = OccurrenceRegistry::default();
            occ.create("ctr1", None, None).unwrap();
            for i in 0..3 {
                assert_eq!(
                    occ.bind_device("ctr1", format!("vendor.com/gpu={}", i), "sha256:aaa"),
                    Ok(()),
                    "binding into a freshly created occurrence must not fail; if this ever \
                     regresses, record_occurrence's loop-break needs a real test"
                );
            }
        }

        /// RM-8: only stop signals are teardown. Misclassifying, say, SIGHUP would let a
        /// quarantined monitor be told to reload a running workload.
        #[test]
        fn only_stop_signals_count_as_teardown() {
            for sig in [libc::SIGTERM, libc::SIGKILL] {
                assert!(is_teardown_signal(sig as u32), "signal {} tears down", sig);
            }
            for sig in [libc::SIGHUP, libc::SIGUSR1, libc::SIGUSR2, libc::SIGINT] {
                assert!(
                    !is_teardown_signal(sig as u32),
                    "signal {} keeps the workload running and must stay gated",
                    sig
                );
            }
        }

        /// RM-8 end to end at this layer: the ids and call order `remove_container` and
        /// `signal_process` use must still work once the monitor is quarantined, while the
        /// build-up paths (`create_container`, `exec_process`) stay refused.
        #[test]
        fn a_quarantined_monitor_can_still_be_torn_down() {
            let mut m = ReferenceMonitor::new();
            let create = srm_op_id("create", &["ctr1"]);
            m.prepare(create.clone(), 0, "d1").unwrap();
            m.execute(&create, "d1").unwrap();
            m.commit(&create, "container-created").unwrap();

            m.quarantine("policy state rollback failed after exec_process");

            for gated in [
                srm_op_id("create", &["ctr2"]),
                srm_op_id("exec", &["ctr1", "e1"]),
            ] {
                assert!(
                    matches!(
                        m.prepare(gated.clone(), m.state_version(), "d"),
                        Err(SrmError::Quarantined(_))
                    ),
                    "{} builds capability and must stay refused",
                    gated
                );
            }

            // A non-teardown signal is still gated ...
            let hup = srm_op_id(
                "signal",
                &["ctr1", "e1", &(libc::SIGHUP as u32).to_string()],
            );
            assert!(matches!(
                m.prepare(hup, m.state_version(), "d"),
                Err(SrmError::Quarantined(_))
            ));

            // ... but SIGKILL then removal complete, the same way the handlers drive them.
            let kill = srm_op_id(
                "signal",
                &["ctr1", "e1", &(libc::SIGKILL as u32).to_string()],
            );
            m.prepare_teardown(kill.clone(), m.state_version(), "d2")
                .unwrap();
            m.execute(&kill, "d2").unwrap();
            commit_or_quarantine(&mut m, &kill, "signal-delivered", "signal_process");
            retire_or_warn(&mut m, &kill);

            let remove = srm_op_id("remove", &["ctr1"]);
            m.prepare_teardown(remove.clone(), m.state_version(), "d3")
                .unwrap();
            m.execute(&remove, "d3").unwrap();
            commit_or_quarantine(&mut m, &remove, "container-removed", "remove_container");
            assert_eq!(
                m.transaction(&remove).map(|t| t.state.clone()),
                Some(TxnState::Committed),
                "teardown must commit even while quarantined"
            );
        }

        /// F-39: a start builds capability, so a quarantined monitor must refuse it --
        /// even for a container whose create committed before the quarantine. This asserts
        /// the *monitor* property the handler now relies on: that `prepare` (as opposed to
        /// `prepare_teardown`) is refused under quarantine for an already-created
        /// container. It does not exercise `start_container` itself -- see the F-39 notes
        /// for why a handler-level barrier is not available here.
        #[test]
        fn a_quarantined_monitor_refuses_to_start_an_already_created_container() {
            let mut m = ReferenceMonitor::new();
            let create = srm_op_id("create", &["ctr1"]);
            m.prepare(create.clone(), 0, "d1").unwrap();
            m.execute(&create, "d1").unwrap();
            m.commit(&create, "container-created").unwrap();

            // The container exists and is startable at this point.
            let start = srm_op_id("start", &["ctr1"]);
            assert!(m.prepare(start.clone(), m.state_version(), "d2").is_ok());
            m.abort(&start).unwrap();

            m.quarantine("policy state rollback failed after exec_process");

            assert!(
                matches!(
                    m.prepare(start.clone(), m.state_version(), "d2"),
                    Err(SrmError::Quarantined(_))
                ),
                "start materialises the container's capability and must be refused"
            );

            // Teardown of the same container is still admitted, so the sandbox can be
            // cleaned up rather than left with a created-but-unstartable container.
            let remove = srm_op_id("remove", &["ctr1"]);
            assert!(m.prepare_teardown(remove, m.state_version(), "d3").is_ok());
        }
    }
}
