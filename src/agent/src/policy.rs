// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use nix::fcntl::{self, OFlag};
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use slog::Drain;
use std::os::fd::{AsRawFd, FromRawFd};
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Duration};
use vmm_sys_util::ioctl::ioctl_with_val;
use vmm_sys_util::{ioctl_ioc_nr, ioctl_iowr_nr};

static EMPTY_JSON_INPUT: &str = "{\"input\":{}}";

static OPA_DATA_PATH: &str = "/data";
static OPA_POLICIES_PATH: &str = "/policies";

static POLICY_LOG_FILE: &str = "/tmp/policy.txt";

/// Convenience macro to obtain the scope logger
macro_rules! sl {
    () => {
        slog_scope::logger()
    };
}

/// Example of HTTP response from OPA: {"result":true}
#[derive(Debug, Serialize, Deserialize)]
struct AllowResponse {
    result: bool,
}

/// Singleton policy object.
#[derive(Debug, Default)]
pub struct AgentPolicy {
    /// When true policy errors are ignored, for debug purposes.
    allow_failures: bool,

    /// OPA path used to query if an Agent gRPC request should be allowed.
    /// The request name (e.g., CreateContainerRequest) must be added to
    /// this path.
    query_path: String,

    /// OPA path used to add or delete a rego format Policy.
    policy_path: String,

    /// Client used to connect a single time to the OPA service and reused
    /// for all the future communication with OPA.
    opa_client: Option<reqwest::Client>,

    /// "/tmp/policy.txt" log file for policy activity.
    log_file: Option<tokio::fs::File>,
}

impl AgentPolicy {
    /// Create AgentPolicy object.
    pub fn new() -> Self {
        Self {
            allow_failures: false,
            ..Default::default()
        }
    }

    /// Wait for OPA to start and connect to it.
    pub async fn initialize(
        &mut self,
        launch_opa: bool,
        opa_addr: &str,
        policy_name: &str,
        default_policy: &str,
    ) -> Result<()> {
        if sl!().is_enabled(slog::Level::Debug) {
            self.log_file = Some(
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(POLICY_LOG_FILE)
                    .await?,
            );
            debug!(sl!(), "policy: log file: {}", POLICY_LOG_FILE);
        }

        if launch_opa {
            start_opa(opa_addr)?;
        }

        let opa_uri = format!("http://{opa_addr}/v1");
        self.query_path = format!("{opa_uri}{OPA_DATA_PATH}{policy_name}/");
        self.policy_path = format!("{opa_uri}{OPA_POLICIES_PATH}{policy_name}");
        let opa_client = reqwest::Client::builder().http1_only().build()?;
        let policy = tokio::fs::read_to_string(default_policy).await?;

        // This loop is necessary to get the opa_client connected to the
        // OPA service while that service is starting. Future requests to
        // OPA are expected to work without retrying, after connecting
        // successfully for the first time.
        for i in 0..50 {
            if i > 0 {
                sleep(Duration::from_millis(100)).await;
                debug!(sl!(), "policy initialize: PUT failed, retrying");
            }

            // Set-up the default policy.
            if opa_client
                .put(&self.policy_path)
                .body(policy.clone())
                .send()
                .await
                .is_ok()
            {
                self.opa_client = Some(opa_client);

                // Check if requests causing policy errors should actually
                // be allowed. That is an insecure configuration but is
                // useful for allowing insecure pods to start, then connect to
                // them and inspect Guest logs for the root cause of a failure.
                //
                // Note that post_query returns Ok(false) in case
                // AllowRequestsFailingPolicy was not defined in the policy.
                self.allow_failures = self
                    .post_query("AllowRequestsFailingPolicy", EMPTY_JSON_INPUT)
                    .await?;
                return Ok(());
            }
        }
        bail!("Failed to connect to OPA")
    }

    /// Ask OPA to check if an API call should be allowed or not.
    pub async fn is_allowed_endpoint(&mut self, ep: &str, request: &str) -> bool {
        let post_input = format!("{{\"input\":{request}}}");
        self.log_opa_input(ep, &post_input).await;
        match self.post_query(ep, &post_input).await {
            Err(e) => {
                debug!(
                    sl!(),
                    "policy: failed to query endpoint {}: {:?}. Returning false.", ep, e
                );
                false
            }
            Ok(allowed) => allowed,
        }
    }

    /// Replace the Policy in OPA.
    pub async fn set_policy(&mut self, policy: &str) -> Result<()> {
        check_policy_hash(policy)?;

        if let Some(opa_client) = &mut self.opa_client {
            // Delete the old rules.
            opa_client.delete(&self.policy_path).send().await?;

            // Put the new rules.
            opa_client
                .put(&self.policy_path)
                .body(policy.to_string())
                .send()
                .await?;

            // Check if requests causing policy errors should actually be allowed.
            // That is an insecure configuration but is useful for allowing insecure
            // pods to start, then connect to them and inspect Guest logs for the
            // root cause of a failure.
            //
            // Note that post_query returns Ok(false) in case
            // AllowRequestsFailingPolicy was not defined in the policy.
            self.allow_failures = self
                .post_query("AllowRequestsFailingPolicy", EMPTY_JSON_INPUT)
                .await?;

            Ok(())
        } else {
            bail!("Agent Policy is not initialized")
        }
    }

    // Post query to OPA.
    async fn post_query(&mut self, ep: &str, post_input: &str) -> Result<bool> {
        debug!(sl!(), "policy check: {ep}");

        if let Some(opa_client) = &mut self.opa_client {
            let uri = format!("{}{ep}", &self.query_path);
            let response = opa_client
                .post(uri)
                .body(post_input.to_string())
                .send()
                .await?;

            if response.status() != http::StatusCode::OK {
                bail!("policy: POST {} response status {}", ep, response.status());
            }

            let http_response = response.text().await?;
            let opa_response: serde_json::Result<AllowResponse> =
                serde_json::from_str(&http_response);

            match opa_response {
                Ok(resp) => {
                    if !resp.result {
                        if self.allow_failures {
                            warn!(
                                sl!(),
                                "policy: POST {} response <{}>. Ignoring error!", ep, http_response
                            );
                            return Ok(true);
                        } else {
                            error!(sl!(), "policy: POST {} response <{}>", ep, http_response);
                        }
                    }
                    Ok(resp.result)
                }
                Err(_) => {
                    warn!(
                        sl!(),
                        "policy: endpoint {} not found in policy. Returning false.", ep,
                    );
                    Ok(false)
                }
            }
        } else {
            bail!("Agent Policy is not initialized")
        }
    }

    async fn log_opa_input(&mut self, ep: &str, input: &str) {
        if let Some(log_file) = &mut self.log_file {
            match ep {
                "StatsContainerRequest" | "ReadStreamRequest" | "SetPolicyRequest" => {
                    // - StatsContainerRequest and ReadStreamRequest are called
                    //   relatively often, so we're not logging them, to avoid
                    //   growing this log file too much.
                    // - Confidential Containers Policy documents are relatively
                    //   large, so we're not logging them here, for SetPolicyRequest.
                    //   The Policy text can be obtained directly from the pod YAML.
                }
                _ => {
                    let log_entry = format!("[\"ep\":\"{ep}\",{input}],\n\n");

                    if let Err(e) = log_file.write_all(log_entry.as_bytes()).await {
                        warn!(sl!(), "policy: log_opa_input: write_all failed: {}", e);
                    } else if let Err(e) = log_file.flush().await {
                        warn!(sl!(), "policy: log_opa_input: flush failed: {}", e);
                    }
                }
            }
        }
    }
}

fn start_opa(opa_addr: &str) -> Result<()> {
    let bin_dirs = vec!["/bin", "/usr/bin", "/usr/local/bin"];
    for bin_dir in &bin_dirs {
        let opa_path = bin_dir.to_string() + "/opa";
        if std::fs::metadata(&opa_path).is_ok() {
            // args copied from kata-opa.service.in.
            std::process::Command::new(&opa_path)
                .arg("run")
                .arg("--server")
                .arg("--disable-telemetry")
                .arg("--addr")
                .arg(opa_addr)
                .arg("--log-level")
                .arg("info")
                .spawn()?;
            return Ok(());
        }
    }
    bail!("OPA binary not found in {:?}", &bin_dirs);
}

fn check_policy_hash(policy: &str) -> Result<()> {
    if let Ok(expected_hash) = get_snp_expected_hash() {
        verify_snp_hash(policy, expected_hash.as_slice())
    } else if let Ok(expected_hash) = get_tdx_expected_hash() {
        verify_tdx_hash(policy, expected_hash.as_slice())
    } else {
        warn!(sl!(), "policy: integrity has not been verified!");

        // TODO: return an error if the current platform supports policy
        // integrity verification using this method.
        Ok(())
    }
}

fn get_snp_expected_hash() -> Result<Vec<u8>> {
    match sev::firmware::guest::Firmware::open() {
        Ok(mut firmware) => {
            let report_data: [u8; 64] = [0; 64];
            match firmware.get_report(None, Some(report_data), Some(0)) {
                Ok(report) => {
                    info!(sl!(), "policy: TEE hash ({:?})", &report.host_data);
                    return Ok(report.host_data.to_vec());
                }
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn verify_snp_hash(policy: &str, expected_hash: &[u8]) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(policy.as_bytes());
    let digest = hasher.finalize();
    info!(sl!(), "policy: calculated hash ({:?})", digest.as_slice());

    if expected_hash != digest.as_slice() {
        bail!(
            "policy: rejecting unexpected hash ({:?}), expected ({:?})",
            digest.as_slice(),
            expected_hash
        );
    }

    Ok(())
}

#[repr(C)]
#[derive(Default)]
/// Type header of TDREPORT_STRUCT.
struct TdTransportType {
    /// Type of the TDREPORT (0 - SGX, 81 - TDX, rest are reserved).
    type_: u8,

    /// Subtype of the TDREPORT (Default value is 0).
    sub_type: u8,

    /// TDREPORT version (Default value is 0).
    version: u8,

    /// Added for future extension.
    reserved: u8,
}

#[repr(C)]
/// TDX guest report data, MAC and TEE hashes.
struct ReportMac {
    /// TDREPORT type header.
    type_: TdTransportType,

    /// Reserved for future extension.
    reserved1: [u8; 12],

    /// CPU security version.
    cpu_svn: [u8; 16],

    /// SHA384 hash of TEE TCB INFO.
    tee_tcb_info_hash: [u8; 48],

    /// SHA384 hash of TDINFO_STRUCT.
    tee_td_info_hash: [u8; 48],

    /// User defined unique data passed in TDG.MR.REPORT request.
    reportdata: [u8; 64],

    /// Reserved for future extension.
    reserved2: [u8; 32],

    /// CPU MAC ID.
    mac: [u8; 32],
}

impl Default for ReportMac {
    fn default() -> Self {
        Self {
            type_: Default::default(),
            reserved1: [0; 12],
            cpu_svn: [0; 16],
            tee_tcb_info_hash: [0; 48],
            tee_td_info_hash: [0; 48],
            reportdata: [0; 64],
            reserved2: [0; 32],
            mac: [0; 32],
        }
    }
}

#[repr(C)]
#[derive(Default)]
/// TDX guest measurements and configuration.
struct TdInfo {
    /// TDX Guest attributes (like debug, spet_disable, etc).
    attr: [u8; 8],

    /// Extended features allowed mask.
    xfam: u64,

    /// Build time measurement register.
    mrtd: [u64; 6],

    /// Software-defined ID for non-owner-defined configuration of the guest - e.g., run-time or OS configuration.
    mrconfigid: [u64; 6],

    /// Software-defined ID for the guest owner.
    mrowner: [u64; 6],

    /// Software-defined ID for owner-defined configuration of the guest - e.g., specific to the workload.
    mrownerconfig: [u64; 6],

    /// Run time measurement registers.
    rtmr: [u64; 24],

    /// For future extension.
    reserved: [u64; 14],
}

#[repr(C)]
/// Output of TDCALL[TDG.MR.REPORT].
struct TdReport {
    /// Mac protected header of size 256 bytes.
    report_mac: ReportMac,

    /// Additional attestable elements in the TCB are not reflected in the report_mac.
    tee_tcb_info: [u8; 239],

    /// Added for future extension.
    reserved: [u8; 17],

    /// Measurements and configuration data of size 512 bytes.
    tdinfo: TdInfo,
}

impl Default for TdReport {
    fn default() -> Self {
        Self {
            report_mac: Default::default(),
            tee_tcb_info: [0; 239],
            reserved: [0; 17],
            tdinfo: Default::default(),
        }
    }
}

#[repr(C)]
/// Request struct for TDX_CMD_GET_REPORT0 IOCTL.
struct TdxReportReq {
    /// User buffer with REPORTDATA to be included into TDREPORT.
    /// Typically it can be some nonce provided by attestation, service,
    /// so the generated TDREPORT can be uniquely verified.
    reportdata: [u8; 64],

    /// User buffer to store TDREPORT output from TDCALL[TDG.MR.REPORT].
    tdreport: TdReport,
}

impl Default for TdxReportReq {
    fn default() -> Self {
        Self {
            reportdata: [0; 64],
            tdreport: Default::default(),
        }
    }
}

// Get TDREPORT0 (a.k.a. TDREPORT subtype 0) using TDCALL[TDG.MR.REPORT].
ioctl_iowr_nr!(
    TDX_CMD_GET_REPORT0,
    'T' as ::std::os::raw::c_uint,
    1,
    TdxReportReq
);

fn get_tdx_expected_hash() -> Result<Vec<u8>> {
    let fd = {
        let raw_fd = fcntl::open(
            "/dev/tdx_guest",
            OFlag::O_CLOEXEC | OFlag::O_RDWR | OFlag::O_SYNC,
            Mode::empty(),
        )?;
        unsafe { std::fs::File::from_raw_fd(raw_fd) }
    };

    let mut req = TdxReportReq {
        reportdata: [0; 64],
        tdreport: Default::default(),
    };
    let ret = unsafe {
        ioctl_with_val(
            &fd.as_raw_fd(),
            TDX_CMD_GET_REPORT0(),
            &mut req as *mut TdxReportReq as std::os::raw::c_ulong,
        )
    };
    if ret < 0 {
        bail!(
            "TDX_CMD_GET_REPORT0 failed: {:?}",
            std::io::Error::last_os_error(),
        );
    }

    let expected_hash: Vec<u8> = req
        .tdreport
        .tdinfo
        .mrconfigid
        .iter()
        .flat_map(|val| val.to_be_bytes())
        .collect();
    info!(sl!(), "policy: TEE hash ({:?})", &expected_hash);
    return Ok(expected_hash);
}

fn verify_tdx_hash(policy: &str, expected_hash: &[u8]) -> Result<()> {
    let mut hasher = Sha384::new();
    hasher.update(policy.as_bytes());
    let digest = hasher.finalize();
    info!(sl!(), "policy: calculated hash ({:?})", digest.as_slice());

    if expected_hash != digest.as_slice() {
        bail!(
            "policy: rejecting unexpected hash ({:?}), expected ({:?})",
            digest.as_slice(),
            expected_hash
        );
    }

    Ok(())
}
