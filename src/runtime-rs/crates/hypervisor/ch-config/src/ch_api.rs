// Copyright (c) 2022-2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    DeviceConfig, DiskConfig, FsConfig, NetConfig, VmConfig, VmInfo, VmResize, VsockConfig,
};
use anyhow::{anyhow, Context, Result};
use api_client::{
    simple_api_full_command_and_response, simple_api_full_command_with_fds_and_response,
};

use serde::{Deserialize, Serialize};
use std::os::{fd::RawFd, unix::net::UnixStream};
use tokio::sync::Mutex;
use tokio::task;

/// Type alias for the serialized API socket shared across callers.
///
/// All Cloud Hypervisor HTTP API calls share a single `UnixStream`. Because
/// the CH API uses HTTP/1.1 over a Unix domain socket without pipelining,
/// concurrent requests on the same stream corrupt the response framing.
/// Wrapping the socket in a `Mutex` ensures only one request-response cycle
/// is in flight at a time.
pub type ApiSocket = Mutex<Option<UnixStream>>;

/// Execute a CH API command while holding the API socket lock.
///
/// Acquires the mutex, clones the socket, and runs the blocking HTTP
/// request-response in `spawn_blocking`. The mutex guard is held until
/// the blocking task completes, ensuring no concurrent API calls.
async fn api_command(
    api_socket: &ApiSocket,
    method: &'static str,
    endpoint: &'static str,
    body: Option<String>,
    fds: Option<Vec<RawFd>>,
) -> Result<Option<String>> {
    let _guard = api_socket.lock().await;
    let mut socket = _guard
        .as_ref()
        .ok_or_else(|| anyhow!("missing api socket"))?
        .try_clone()
        .context("clone api socket")?;

    let result = task::spawn_blocking(move || -> Result<Option<String>> {
        let response = if let Some(fds) = fds {
            simple_api_full_command_with_fds_and_response(
                &mut socket,
                method,
                endpoint,
                body.as_deref(),
                &fds,
            )
        } else {
            simple_api_full_command_and_response(&mut socket, method, endpoint, body.as_deref())
        }
        .map_err(|e| anyhow!(e))?;
        Ok(response)
    })
    .await?;

    result
}

pub async fn cloud_hypervisor_vmm_ping(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "GET", "vmm.ping", None, None).await
}

pub async fn cloud_hypervisor_vmm_shutdown(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vmm.shutdown", None, None).await
}

pub async fn cloud_hypervisor_vm_create(
    api_socket: &ApiSocket,
    cfg: VmConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string_pretty(&cfg)?;
    api_command(api_socket, "PUT", "vm.create", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_start(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vm.boot", None, None).await
}

pub async fn cloud_hypervisor_vm_pause(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vm.pause", None, None).await
}

pub async fn cloud_hypervisor_vm_resume(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vm.resume", None, None).await
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmSnapshotConfig {
    pub destination_url: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct RestoreConfig {
    pub source_url: String,
    pub memory_restore_mode: MemoryRestoreMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_fds: Option<Vec<RestoredNetConfig>>,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug, PartialEq, Eq)]
pub enum MemoryRestoreMode {
    Copy,
    OnDemand,
    #[default]
    CopyOnWrite,
}

impl From<kata_types::config::hypervisor::MemoryRestoreMode> for MemoryRestoreMode {
    fn from(value: kata_types::config::hypervisor::MemoryRestoreMode) -> Self {
        match value {
            kata_types::config::hypervisor::MemoryRestoreMode::Copy => Self::Copy,
            kata_types::config::hypervisor::MemoryRestoreMode::OnDemand => Self::OnDemand,
            kata_types::config::hypervisor::MemoryRestoreMode::CopyOnWrite => Self::CopyOnWrite,
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Default, Debug, PartialEq, Eq)]
pub struct RestoredNetConfig {
    pub id: String,
    pub num_fds: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fds: Option<Vec<i32>>,
}

pub async fn cloud_hypervisor_vm_snapshot(
    api_socket: &ApiSocket,
    cfg: VmSnapshotConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&cfg)?;
    api_command(api_socket, "PUT", "vm.snapshot", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_restore(
    api_socket: &ApiSocket,
    cfg: RestoreConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&cfg)?;
    api_command(api_socket, "PUT", "vm.restore", Some(body), None).await
}

/// Restore a VM while replacing FD-backed network devices.
///
/// `RestoreConfig::net_fds` carries device IDs and expected FD counts, but no
/// descriptor numbers. Valid descriptors are transmitted out-of-band as an
/// SCM_RIGHTS control message by Cloud Hypervisor's `api_client` helper.
pub async fn cloud_hypervisor_vm_restore_with_fds(
    api_socket: &ApiSocket,
    cfg: RestoreConfig,
    request_fds: Vec<RawFd>,
) -> Result<Option<String>> {
    if request_fds.is_empty() {
        return Err(anyhow!("vm.restore with net_fds requires at least one FD"));
    }

    let body = serde_json::to_string(&cfg)?;
    api_command(
        api_socket,
        "PUT",
        "vm.restore",
        Some(body),
        Some(request_fds),
    )
    .await
}

#[allow(dead_code)]
pub async fn cloud_hypervisor_vm_stop(api_socket: &ApiSocket) -> Result<Option<String>> {
    api_command(api_socket, "PUT", "vm.shutdown", None, None).await
}

#[derive(Deserialize, Debug)]
pub struct PciDeviceInfo {
    pub id: String,
    pub bdf: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct VmRemoveDeviceData {
    #[serde(default)]
    pub id: String,
}

pub async fn cloud_hypervisor_vm_blockdev_add(
    api_socket: &ApiSocket,
    blk_config: DiskConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&blk_config)?;
    api_command(api_socket, "PUT", "vm.add-disk", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_netdev_add(
    api_socket: &ApiSocket,
    net_config: NetConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&net_config)?;
    api_command(api_socket, "PUT", "vm.add-net", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_netdev_add_with_fds(
    api_socket: &ApiSocket,
    net_config: NetConfig,
    request_fds: Vec<RawFd>,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&net_config)?;
    api_command(
        api_socket,
        "PUT",
        "vm.add-net",
        Some(body),
        Some(request_fds),
    )
    .await
}

pub async fn cloud_hypervisor_vm_device_add(
    api_socket: &ApiSocket,
    device_config: DeviceConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&device_config)?;
    api_command(api_socket, "PUT", "vm.add-device", Some(body), None).await
}

#[allow(dead_code)]
pub async fn cloud_hypervisor_vm_device_remove(
    api_socket: &ApiSocket,
    device_data: VmRemoveDeviceData,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&device_data)?;
    api_command(api_socket, "PUT", "vm.remove-device", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_fs_add(
    api_socket: &ApiSocket,
    fs_config: FsConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&fs_config)?;
    api_command(api_socket, "PUT", "vm.add-fs", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_vsock_add(
    api_socket: &ApiSocket,
    vsock_config: VsockConfig,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&vsock_config)?;
    api_command(api_socket, "PUT", "vm.add-vsock", Some(body), None).await
}

pub async fn cloud_hypervisor_vm_info(api_socket: &ApiSocket) -> Result<VmInfo> {
    let response = api_command(api_socket, "GET", "vm.info", None, None).await?;
    let vm_info = response.ok_or(anyhow!("failed to get vminfo"))?;
    serde_json::from_str(&vm_info).with_context(|| format!("failed to serde {vm_info}"))
}

pub async fn cloud_hypervisor_vm_resize(
    api_socket: &ApiSocket,
    vmresize: VmResize,
) -> Result<Option<String>> {
    let body = serde_json::to_string(&vmresize)?;
    api_command(api_socket, "PUT", "vm.resize", Some(body), None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::Write,
        os::fd::{AsRawFd, FromRawFd},
    };
    use vmm_sys_util::sock_ctrl_msg::ScmSocket;

    #[test]
    fn test_restore_config_memory_modes() {
        assert_eq!(
            RestoreConfig::default().memory_restore_mode,
            MemoryRestoreMode::CopyOnWrite
        );

        let cases = [
            (MemoryRestoreMode::Copy, "Copy"),
            (MemoryRestoreMode::OnDemand, "OnDemand"),
            (MemoryRestoreMode::CopyOnWrite, "CopyOnWrite"),
        ];

        for (mode, expected) in cases {
            let value = serde_json::to_value(RestoreConfig {
                source_url: "file:///snapshot".to_string(),
                memory_restore_mode: mode,
                net_fds: None,
            })
            .unwrap();

            assert_eq!(value["source_url"], "file:///snapshot");
            assert_eq!(value["memory_restore_mode"], expected);
            assert!(value.get("net_fds").is_none());
        }
    }

    #[test]
    fn test_restore_config_network_fds() {
        let value = serde_json::to_value(RestoreConfig {
            source_url: "file:///snapshot".to_string(),
            memory_restore_mode: MemoryRestoreMode::CopyOnWrite,
            net_fds: Some(vec![RestoredNetConfig {
                id: "net0".to_string(),
                num_fds: 2,
                fds: None,
            }]),
        })
        .unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "source_url": "file:///snapshot",
                "memory_restore_mode": "CopyOnWrite",
                "net_fds": [{
                    "id": "net0",
                    "num_fds": 2
                }]
            })
        );
    }

    #[test]
    fn test_restore_with_fds_sends_scm_rights() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (client, mut server) = UnixStream::pair().unwrap();
        let api_socket = ApiSocket::new(Some(client));

        let server_thread = std::thread::spawn(move || {
            let mut request = [0_u8; 512];
            let mut iovecs = [nix::libc::iovec {
                iov_base: request.as_mut_ptr().cast(),
                iov_len: request.len(),
            }];
            let mut received_fds = [-1];
            let (bytes, fd_count) = unsafe {
                server
                    .recv_with_fds(&mut iovecs, &mut received_fds)
                    .unwrap()
            };

            assert!(bytes > 0);
            assert_eq!(fd_count, 1);
            assert!(String::from_utf8_lossy(&request[..bytes]).contains("vm.restore"));

            let received = unsafe { File::from_raw_fd(received_fds[0]) };
            assert!(received.metadata().is_ok());

            server.write_all(b"HTTP/1.1 204\r\n\r\n").unwrap();
        });

        let fd = File::open("/dev/null").unwrap();
        runtime
            .block_on(cloud_hypervisor_vm_restore_with_fds(
                &api_socket,
                RestoreConfig {
                    source_url: "file:///snapshot".to_string(),
                    memory_restore_mode: MemoryRestoreMode::CopyOnWrite,
                    net_fds: Some(vec![RestoredNetConfig {
                        id: "net0".to_string(),
                        num_fds: 1,
                        fds: None,
                    }]),
                },
                vec![fd.as_raw_fd()],
            ))
            .unwrap();

        server_thread.join().unwrap();
    }
}
