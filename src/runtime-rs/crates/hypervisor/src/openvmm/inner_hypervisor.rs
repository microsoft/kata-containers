// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM hypervisor lifecycle management over the standalone VM service.

use anyhow::{anyhow, Context, Result};
use openvmm_ttrpc_vmservice as vmservice;
use std::fs;

use super::inner::OpenVmmInner;
use crate::kernel_param::KernelParams;
use crate::utils::{get_jailer_root, get_sandbox_path};
use crate::{DeviceType, MemoryConfig, VcpuThreadIds, VmmState, VM_ROOTFS_DRIVER_BLK};

const KATA_PATH: &str = "/run/kata";
const OPENVMM_STANDALONE_VIRTIO_FS: &str = "virtio-fs";
const OPENVMM_INLINE_VIRTIO_FS: &str = "inline-virtio-fs";
const OPENVMM_ROOTFS_SCSI_LUN: u32 = 0;

fn build_kernel_cmdline(
    debug: bool,
    kernel_params: &str,
    kernel_verity_params: &str,
    rootfs_type: &str,
) -> Result<String> {
    let mut params = KernelParams::new(debug);

    let mut rootfs_params = KernelParams::new_rootfs_kernel_params(
        kernel_verity_params,
        VM_ROOTFS_DRIVER_BLK,
        rootfs_type,
        false,
    )?;
    params.append(&mut rootfs_params);
    params.append(&mut KernelParams::from_string(kernel_params));

    params.to_string()
}

fn adapt_cmdline_for_rpc(cmdline: String) -> String {
    cmdline.replace("console=hvc0", "console=ttyS0")
}

fn scsi_disk(lun: u32, host_path: String, read_only: bool) -> vmservice::ScsiDisk {
    vmservice::ScsiDisk {
        controller: 0,
        lun,
        host_path,
        r#type: vmservice::DiskType::ScsiDiskTypePhysical as i32,
        read_only,
    }
}

fn nic_id(index: usize) -> String {
    format!("00000000-0000-0000-0000-{:012x}", index + 1)
}

fn mac_address(device: &crate::NetworkDevice, index: usize) -> String {
    device
        .config
        .guest_mac
        .as_ref()
        .map(|mac| {
            format!(
                "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]
            )
        })
        .unwrap_or_else(|| format!("02-00-00-00-00-{:02X}", index + 1))
}

impl OpenVmmInner {
    pub(crate) async fn prepare_vm(&mut self, id: &str, netns: Option<String>) -> Result<()> {
        info!(sl!(), "openvmm: prepare_vm id={}", id);
        self.id = id.to_string();
        self.state = VmmState::NotReady;
        self.pending_devices.clear();
        self.reset_block_hotplug_ports();
        self.vm_path = get_sandbox_path(id);
        self.jailer_root = get_jailer_root(id);
        self.netns = netns;

        self.run_dir = format!("{}/{}", KATA_PATH, id);
        fs::create_dir_all(&self.jailer_root)
            .with_context(|| format!("failed to create jailer root: {}", self.jailer_root))?;
        fs::create_dir_all(&self.run_dir)
            .with_context(|| format!("failed to create run dir: {}", self.run_dir))?;

        Ok(())
    }

    pub(crate) async fn start_vm(&mut self, _timeout: i32) -> Result<()> {
        info!(sl!(), "openvmm: start_vm via external ttrpc process");
        self.reset_block_hotplug_ports();

        let cmdline = build_kernel_cmdline(
            self.config.debug_info.enable_debug,
            &self.config.boot_info.kernel_params,
            &self.config.boot_info.kernel_verity_params,
            &self.config.boot_info.rootfs_type,
        )?;
        let cmdline = adapt_cmdline_for_rpc(cmdline);

        info!(sl!(), "openvmm: kernel={}", self.config.boot_info.kernel);
        info!(sl!(), "openvmm: image={}", self.config.boot_info.image);
        info!(sl!(), "openvmm: cmdline={}", cmdline);

        let mut devices_config = vmservice::DevicesConfig::default();
        let rootfs_disk_path = if !self.config.boot_info.image.is_empty() {
            let disk_path = self.config.boot_info.image.clone();
            warn!(
                sl!(),
                "openvmm: requesting rootfs disk as RPC lun {} for OpenVMM virtio-blk MMIO mapping: {}",
                OPENVMM_ROOTFS_SCSI_LUN,
                disk_path
            );
            devices_config.scsi_disks.push(scsi_disk(
                OPENVMM_ROOTFS_SCSI_LUN,
                disk_path.clone(),
                true,
            ));
            Some(disk_path)
        } else {
            None
        };

        let pending = std::mem::take(&mut self.pending_devices);
        let mut deferred_block_devices = Vec::new();
        let mut network_index = 0usize;

        for dev in &pending {
            match dev {
                DeviceType::HybridVsock(hvsock_dev) => {
                    info!(
                        sl!(),
                        "openvmm: HybridVsock requested, guest_cid={}, uds_path={}",
                        hvsock_dev.config.guest_cid,
                        hvsock_dev.config.uds_path
                    );
                }
                DeviceType::Vsock(vsock_dev) => {
                    info!(
                        sl!(),
                        "openvmm: Vsock requested, guest_cid={}", vsock_dev.config.guest_cid
                    );
                }
                DeviceType::Network(net_dev) => {
                    info!(
                        sl!(),
                        "openvmm: wiring Network device over RPC NetVSP TAP, tap={}",
                        net_dev.config.host_dev_name
                    );
                    devices_config.nic_config.push(vmservice::NicConfig {
                        nic_id: nic_id(network_index),
                        mac_address: mac_address(net_dev, network_index),
                        legacy_switch_id: String::new(),
                        nic_name: net_dev.device_id.clone(),
                        backend: Some(vmservice::nic_config::Backend::Tap(vmservice::TapBackend {
                            name: net_dev.config.host_dev_name.clone(),
                        })),
                    });
                    network_index += 1;
                }
                DeviceType::ShareFs(fs_dev) => {
                    match fs_dev.config.fs_type.as_str() {
                        OPENVMM_STANDALONE_VIRTIO_FS => warn!(
                            sl!(),
                            "openvmm: RPC has no vhost-user-fs; using inline virtio-fs for tag {}",
                            fs_dev.config.mount_tag
                        ),
                        OPENVMM_INLINE_VIRTIO_FS => info!(
                            sl!(),
                            "openvmm: wiring inline virtio-fs for tag {}", fs_dev.config.mount_tag
                        ),
                        other => {
                            return Err(anyhow!("openvmm unsupported shared fs type '{}'", other));
                        }
                    }

                    devices_config
                        .virtiofs_config
                        .push(vmservice::VirtioFsConfig {
                            tag: fs_dev.config.mount_tag.clone(),
                            root_path: fs_dev.config.host_shared_path.clone(),
                        });
                }
                DeviceType::Block(blk_dev) => {
                    if Some(blk_dev.config.path_on_host.as_str()) == rootfs_disk_path.as_deref() {
                        info!(
                            sl!(),
                            "openvmm: skipping duplicate Block device already used as rootfs: {}",
                            blk_dev.config.path_on_host
                        );
                    } else {
                        deferred_block_devices.push(dev.clone());
                    }
                }
                DeviceType::Vfio(_) => {
                    return Err(anyhow!(
                        "openvmm: VFIO cold-plug requires Linux PCI assignment support in the \
                         external OpenVMM TTRPC VM service"
                    ));
                }
                other => {
                    warn!(sl!(), "openvmm: unsupported pending device type: {}", other);
                }
            }
        }

        let hvsocket_path = format!("{}/vsock.sock", self.run_dir);
        let ttrpc_socket_path = format!("{}/openvmm.sock", self.run_dir);
        let serial_socket_path = format!("{}/serial.sock", self.run_dir);
        let _ = std::fs::remove_file(&hvsocket_path);
        let _ = std::fs::remove_file(&ttrpc_socket_path);
        let _ = std::fs::remove_file(&serial_socket_path);

        let request = vmservice::CreateVmRequest {
            config: Some(vmservice::VmConfig {
                memory_config: Some(vmservice::MemoryConfig {
                    memory_mb: self.config.memory_info.default_memory as u64,
                    allow_overcommit: false,
                    deferred_commit: false,
                    hot_hint: false,
                    cold_hint: false,
                    cold_discard_hint: false,
                    low_mmio_gap_in_mb: 0,
                    high_mmio_base_in_mb: 0,
                    high_mmio_gap_in_mb: 0,
                }),
                processor_config: Some(vmservice::ProcessorConfig {
                    processor_count: self.config.cpu_info.default_vcpus.ceil() as u32,
                    processor_weight: 0,
                    processor_limit: 0,
                }),
                devices_config: Some(devices_config),
                serial_config: Some(vmservice::SerialConfig {
                    ports: vec![vmservice::serial_config::Config {
                        port: 0,
                        socket_path: serial_socket_path,
                        connect: false,
                    }],
                }),
                boot_config: Some(vmservice::vm_config::BootConfig::DirectBoot(
                    vmservice::DirectBoot {
                        kernel_path: self.config.boot_info.kernel.clone(),
                        initrd_path: self.config.boot_info.initrd.clone(),
                        kernel_cmdline: cmdline,
                    },
                )),
                windows_options: None,
                extra_data: Default::default(),
                hvsocket_config: Some(vmservice::HvSocketConfig {
                    path: hvsocket_path,
                }),
            }),
            log_id: self.id.clone(),
        };

        info!(sl!(), "openvmm: launching standalone OpenVMM process");
        self.vmm_instance
            .launch(
                &self.config.path,
                ttrpc_socket_path,
                request,
                self.netns.clone(),
                Some(self.run_dir.clone()),
            )
            .await
            .context("failed to launch standalone OpenVMM")?;

        info!(sl!(), "openvmm: resuming VM");
        self.vmm_instance
            .resume()
            .await
            .context("failed to resume VM")?;

        self.state = VmmState::VmRunning;
        info!(sl!(), "openvmm: VM is running");

        for device in deferred_block_devices {
            self.add_device(device)
                .await
                .context("failed to hotplug deferred block device")?;
        }

        Ok(())
    }

    pub(crate) async fn stop_vm(&mut self) -> Result<()> {
        info!(sl!(), "openvmm: stop_vm");
        self.vmm_instance.stop().await?;
        self.state = VmmState::NotReady;
        Ok(())
    }

    pub(crate) async fn pause_vm(&self) -> Result<()> {
        self.vmm_instance.pause().await
    }

    pub(crate) async fn resume_vm(&self) -> Result<()> {
        self.vmm_instance.resume().await
    }

    pub(crate) async fn save_vm(&self) -> Result<()> {
        Err(anyhow!("openvmm save_vm not yet implemented"))
    }

    pub(crate) async fn resize_vcpu(&self, old_vcpus: u32, _new_vcpus: u32) -> Result<(u32, u32)> {
        Ok((old_vcpus, old_vcpus))
    }

    pub(crate) async fn resize_memory(&mut self, new_mem_mb: u32) -> Result<(u32, MemoryConfig)> {
        Ok((new_mem_mb, MemoryConfig::default()))
    }

    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        Ok(format!("hvsock://{}/vsock.sock", self.run_dir))
    }

    pub(crate) async fn disconnect(&mut self) {
        info!(sl!(), "openvmm: disconnect");
    }

    pub(crate) async fn get_thread_ids(&self) -> Result<VcpuThreadIds> {
        Ok(VcpuThreadIds::default())
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn get_pids(&self) -> Result<Vec<u32>> {
        Ok(self.vmm_instance.pid().into_iter().collect())
    }

    pub(crate) async fn get_vmm_master_tid(&self) -> Result<u32> {
        self.vmm_instance
            .pid()
            .ok_or_else(|| anyhow!("could not get openvmm process id"))
    }

    pub(crate) async fn get_ns_path(&self) -> Result<String> {
        let pid = self.get_vmm_master_tid().await?;
        Ok(format!("/proc/{pid}/ns"))
    }

    pub(crate) async fn check(&self) -> Result<()> {
        Ok(())
    }

    pub(crate) async fn get_jailer_root(&self) -> Result<String> {
        fs::create_dir_all(&self.jailer_root).with_context(|| {
            format!("failed to create openvmm jailer root {}", self.jailer_root)
        })?;
        Ok(self.jailer_root.clone())
    }

    pub(crate) async fn get_hypervisor_metrics(&self) -> Result<String> {
        Err(anyhow!("openvmm hypervisor metrics not implemented"))
    }

    pub(crate) async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        Err(anyhow!("openvmm passfd IO is not supported"))
    }
}
