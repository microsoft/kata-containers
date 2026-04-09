// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM hypervisor lifecycle management.

use anyhow::{anyhow, Context, Result};
use std::fs::{self, File};

use super::inner::OpenVmmInner;
use super::{
    OPENVMM_BLOCK_HOTPLUG_PORT_COUNT, OPENVMM_BLOCK_HOTPLUG_PORT_PREFIX,
    OPENVMM_CONSOLE_PCI_PORT, OPENVMM_NET_PCI_PORT, OPENVMM_ROOTFS_PCI_PORT,
    OPENVMM_SHAREFS_PCI_PORT,
};
use crate::kernel_param::KernelParams;
use crate::utils::{get_jailer_root, get_sandbox_path, open_named_tuntap};
use crate::{MemoryConfig, VcpuThreadIds, VmmState, VM_ROOTFS_DRIVER_BLK};

use openvmm_defs::config::{
    Config, DeviceVtl, HypervisorConfig as OvmmHypervisorConfig,
    LoadMode, MemoryConfig as OvmmMemoryConfig,
    PcieDeviceConfig, PcieRootComplexConfig, PcieRootPortConfig,
    ProcessorTopologyConfig, VmbusConfig, DEFAULT_MMIO_GAPS_X86,
};
use vm_resource::kind::VmbusDeviceHandleKind;
use vm_resource::IntoResource;

const KATA_PATH: &str = "/run/kata";
const OPENVMM_STANDALONE_VIRTIO_FS: &str = "virtio-fs";
const OPENVMM_INLINE_VIRTIO_FS: &str = "inline-virtio-fs";

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

impl OpenVmmInner {
    pub(crate) async fn prepare_vm(
        &mut self,
        id: &str,
        netns: Option<String>,
    ) -> Result<()> {
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
        info!(sl!(), "openvmm: start_vm");
        self.reset_block_hotplug_ports();

        let cmdline = build_kernel_cmdline(
            self.config.debug_info.enable_debug,
            &self.config.boot_info.kernel_params,
            &self.config.boot_info.kernel_verity_params,
            &self.config.boot_info.rootfs_type,
        )?;

        info!(sl!(), "openvmm: kernel={}", self.config.boot_info.kernel);
        info!(sl!(), "openvmm: image={}", self.config.boot_info.image);
        info!(sl!(), "openvmm: cmdline={}", cmdline);

        // Open kernel file
        let kernel = File::open(&self.config.boot_info.kernel)
            .with_context(|| format!("failed to open kernel: {}", self.config.boot_info.kernel))?;

        let load_mode = LoadMode::Linux {
            kernel,
            initrd: None,
            cmdline,
            custom_dsdt: None,
            enable_serial: false,
            boot_mode: openvmm_defs::config::LinuxDirectBootMode::Acpi,
        };

        // Set up virtio-console for guest output, piped to journalctl.
        // This is much faster than serial (2.5s vs 9.5s boot time).
        // Create a Unix socket pair — one end goes to the virtio-console
        // device, the other is read in a thread that logs to slog.
        let (console_vm_std, console_host) = std::os::unix::net::UnixStream::pair()
            .context("failed to create console socket pair")?;
        let console_vm = ovmm_unix_socket::UnixStream::from(
            std::os::fd::OwnedFd::from(console_vm_std)
        );
        let console_resource = ovmm_serial_socket::net::OpenSocketSerialConfig::from(console_vm)
            .into_resource();

        // Spawn a thread to read guest console output and log it.
        std::thread::Builder::new()
            .name("openvmm-console-reader".to_string())
            .spawn(move || {
                use std::io::{BufRead, BufReader};
                let reader = BufReader::new(console_host);
                for line in reader.lines() {
                    match line {
                        Ok(line) => {
                            info!(sl!(), "openvmm-guest: {}", line);
                        }
                        Err(_) => break,
                    }
                }
            })
            .context("failed to spawn console reader thread")?;

        // No serial ports — COM1 disabled for performance.
        let serial_ports: [Option<vm_resource::Resource<vm_resource::kind::SerialBackendHandle>>; 4] = [
            None, None, None, None,
        ];

        // Build chipset via VmManifestBuilder
        let chipset = vm_manifest_builder::VmManifestBuilder::new(
            vm_manifest_builder::BaseChipsetType::HyperVGen2LinuxDirect,
            vm_manifest_builder::MachineArch::X86_64,
        )
        .with_serial(serial_ports)
        .build()
        .context("failed to build VM chipset manifest")?;

        // Memory config
        let mem_size_bytes = (self.config.memory_info.default_memory as u64)
            .checked_mul(1024 * 1024)
            .context("memory size overflow")?;

        // PCIe root complex: ECAM range must match bus count.
        // 128MB ECAM = 128 buses (0..127), each bus has 256 devfns * 4KB config = 1MB.
        let pcie_root_complexes = vec![PcieRootComplexConfig {
            index: 0,
            name: "rc0".to_string(),
            segment: 0,
            start_bus: 0,
            end_bus: 127,
            ecam_range: ovmm_memory_range::MemoryRange::new(0xe800_0000..0xf000_0000),
            low_mmio: ovmm_memory_range::MemoryRange::new(0xc000_0000..0xd400_0000),
            high_mmio: ovmm_memory_range::MemoryRange::new(0x0020_3d30_0000..0x200f_3d30_0000),
            ports: {
                let mut ports = vec![
                    PcieRootPortConfig {
                        name: OPENVMM_ROOTFS_PCI_PORT.to_string(),
                        hotplug: false,
                    },
                    PcieRootPortConfig {
                        name: OPENVMM_SHAREFS_PCI_PORT.to_string(),
                        hotplug: false,
                    },
                    PcieRootPortConfig {
                        name: OPENVMM_NET_PCI_PORT.to_string(),
                        hotplug: false,
                    },
                    PcieRootPortConfig {
                        name: super::OPENVMM_VSOCK_PCI_PORT.to_string(),
                        hotplug: false,
                    },
                    PcieRootPortConfig {
                        name: OPENVMM_CONSOLE_PCI_PORT.to_string(),
                        hotplug: false,
                    },
                ];

                for index in 0..OPENVMM_BLOCK_HOTPLUG_PORT_COUNT {
                    ports.push(PcieRootPortConfig {
                        name: format!("{}{}", OPENVMM_BLOCK_HOTPLUG_PORT_PREFIX, index),
                        hotplug: true,
                    });
                }

                ports
            },
        }];

        // Add rootfs disk as virtio-blk via PCIe.
        // The actual file will be opened inside the VmWorker thread to avoid
        // FD loss through mesh channel serialization. We pass just the path
        // to vmm_instance::launch() which opens the file and creates the
        // PcieDeviceConfig in the worker thread.
        let mut pcie_devices = Vec::new();
        let rootfs_disk_path = if !self.config.boot_info.image.is_empty() {
            let disk_path = self.config.boot_info.image.clone();
            info!(sl!(), "openvmm: rootfs disk (opened in worker thread): {}", disk_path);
            Some(disk_path)
        } else {
            None
        };

        // Process pending devices into the VM config
        let pending = std::mem::take(&mut self.pending_devices);
        let vmbus_devices: Vec<(DeviceVtl, vm_resource::Resource<VmbusDeviceHandleKind>)> = Vec::new();
        let mut deferred_block_devices = Vec::new();

        for dev in &pending {
            match dev {
                crate::DeviceType::HybridVsock(hvsock_dev) => {
                    info!(sl!(), "openvmm: wiring HybridVsock device as virtio-vsock, uds_path={}", hvsock_dev.config.uds_path);
                    // Handled below via virtio-vsock PCIe device
                }
                crate::DeviceType::Vsock(vsock_dev) => {
                    info!(sl!(), "openvmm: wiring Vsock device as virtio-vsock, guest_cid={}", vsock_dev.config.guest_cid);
                    // Handled below via virtio-vsock PCIe device
                }
                crate::DeviceType::Network(net_dev) => {
                    info!(
                        sl!(),
                        "openvmm: wiring Network device as virtio-net-pci, tap={}",
                        net_dev.config.host_dev_name
                    );
                    let fd = open_named_tuntap(&net_dev.config.host_dev_name, 1)
                        .with_context(|| {
                            format!(
                                "failed to open TAP device {} for openvmm",
                                net_dev.config.host_dev_name
                            )
                        })?
                        .into_iter()
                        .next()
                        .ok_or_else(|| {
                            anyhow!(
                                "no TAP file descriptors returned for {}",
                                net_dev.config.host_dev_name
                            )
                        })?
                        .into();
                    let endpoint = net_backend_resources::tap::TapHandle { fd }.into_resource();
                    let mac = net_dev
                        .config
                        .guest_mac
                        .as_ref()
                        .map(|m| {
                            format!(
                                "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                                m.0[0], m.0[1], m.0[2], m.0[3], m.0[4], m.0[5]
                            )
                        })
                        .unwrap_or_default();
                    // Use virtio-net via PCIe (kernel has CONFIG_VIRTIO_NET=y
                    // but CONFIG_HYPERV_NET is not set).
                    let net_handle = virtio_resources::net::VirtioNetHandle {
                        max_queues: None,
                        mac_address: mac.parse().unwrap_or_else(|_| {
                            net_backend_resources::mac_address::MacAddress::from([0u8; 6])
                        }),
                        endpoint,
                    };
                    pcie_devices.push(PcieDeviceConfig {
                        port_name: OPENVMM_NET_PCI_PORT.to_string(),
                        resource: virtio_resources::VirtioPciDeviceHandle(
                            net_handle.into_resource(),
                        )
                        .into_resource(),
                    });
                }
                crate::DeviceType::ShareFs(fs_dev) => {
                    info!(
                        sl!(),
                        "openvmm: wiring ShareFs device, tag={}, path={}, fs_type={}, sock_path={}",
                        fs_dev.config.mount_tag,
                        fs_dev.config.host_shared_path,
                        fs_dev.config.fs_type,
                        fs_dev.config.sock_path
                    );
                    let resource = match fs_dev.config.fs_type.as_str() {
                        OPENVMM_STANDALONE_VIRTIO_FS => {
                            let socket =
                                std::os::unix::net::UnixStream::connect(&fs_dev.config.sock_path)
                                    .with_context(|| {
                                    format!(
                                        "failed to connect to virtiofsd socket {} for tag {}",
                                        fs_dev.config.sock_path, fs_dev.config.mount_tag
                                    )
                                })?;

                            virtio_resources::VirtioPciDeviceHandle(
                                virtio_resources::vhost_user::VhostUserFsHandle {
                                    socket: socket.into(),
                                    tag: fs_dev.config.mount_tag.clone(),
                                }
                                .into_resource(),
                            )
                            .into_resource()
                        }
                        OPENVMM_INLINE_VIRTIO_FS => virtio_resources::VirtioPciDeviceHandle(
                            virtio_resources::fs::VirtioFsHandle {
                                tag: fs_dev.config.mount_tag.clone(),
                                fs: virtio_resources::fs::VirtioFsBackend::HostFs {
                                    root_path: fs_dev.config.host_shared_path.clone(),
                                    mount_options: String::new(),
                                },
                            }
                            .into_resource(),
                        )
                        .into_resource(),
                        other => {
                            return Err(anyhow!("openvmm unsupported shared fs type '{}'", other));
                        }
                    };

                    pcie_devices.push(PcieDeviceConfig {
                        port_name: OPENVMM_SHAREFS_PCI_PORT.to_string(),
                        resource,
                    });
                }
                crate::DeviceType::Block(blk_dev) => {
                    if Some(blk_dev.config.path_on_host.as_str()) == rootfs_disk_path.as_deref() {
                        info!(sl!(), "openvmm: skipping duplicate Block device (already added as rootfs): {}",
                            blk_dev.config.path_on_host);
                    } else {
                        deferred_block_devices.push(dev.clone());
                    }
                }
                other => {
                    warn!(sl!(), "openvmm: unsupported pending device type: {}", other);
                }
            }
        }

        // Set up virtio-vsock for agent communication.
        // The vsock listener will be bound inside the worker thread to avoid
        // FD transfer issues with mesh channels across async runtimes.
        let vsock_uds_path = format!("{}/vsock.sock", self.run_dir);
        info!(sl!(), "openvmm: virtio-vsock uds path: {}", vsock_uds_path);
        let _ = std::fs::remove_file(&vsock_uds_path);

        // Add virtio-console PCIe device for guest console output.
        pcie_devices.push(PcieDeviceConfig {
            port_name: OPENVMM_CONSOLE_PCI_PORT.to_string(),
            resource: virtio_resources::VirtioPciDeviceHandle(
                virtio_resources::console::VirtioConsoleHandle {
                    backend: console_resource,
                }
                .into_resource(),
            )
            .into_resource(),
        });

        let vmbus_config = VmbusConfig {
            vsock_listener: None,
            vsock_path: None,
            ..Default::default()
        };

        let proc_count = self.config.cpu_info.default_vcpus.ceil() as u32;
        info!(
            sl!(),
            "openvmm: boot processor topology default_vcpus={} -> proc_count={}",
            self.config.cpu_info.default_vcpus,
            proc_count
        );

        let vm_config = Config {
            load_mode,
            floppy_disks: vec![],
            ide_disks: vec![],
            pcie_root_complexes,
            pcie_devices,
            pcie_switches: vec![],
            vpci_devices: vec![],
            memory: OvmmMemoryConfig {
                mem_size: mem_size_bytes,
                mmio_gaps: DEFAULT_MMIO_GAPS_X86.into(),
                pci_ecam_gaps: vec![],
                pci_mmio_gaps: vec![],
                prefetch_memory: false,
                private_memory: false,
                transparent_hugepages: false,
            },
            processor_topology: ProcessorTopologyConfig {
                proc_count,
                vps_per_socket: None,
                enable_smt: None,
                arch: Default::default(),
            },
            hypervisor: OvmmHypervisorConfig {
                with_hv: true,
                ..Default::default()
            },
            chipset: chipset.chipset,
            vmbus: Some(vmbus_config),
            vtl2_vmbus: None,
            #[cfg(windows)]
            kernel_vmnics: vec![],
            input: ovmm_mesh::Receiver::new(),
            framebuffer: None,
            vga_firmware: None,
            vtl2_gfx: false,
            virtio_devices: vec![],
            #[cfg(windows)]
            vpci_resources: vec![],
            vmgs: None,
            secure_boot_enabled: false,
            custom_uefi_vars: Default::default(),
            firmware_event_send: None,
            debugger_rpc: None,
            vmbus_devices,
            chipset_devices: chipset.chipset_devices,
            generation_id_recv: None,
            rtc_delta_milliseconds: 0,
            automatic_guest_reset: true,
            efi_diagnostics_log_level: Default::default(),
        };

        // Launch the VM worker
        info!(sl!(), "openvmm: launching VM worker");
        self.vmm_instance
            .launch(
                vm_config,
                vsock_uds_path,
                rootfs_disk_path,
                self.netns.clone(),
                Some(self.run_dir.clone()),
            )
            .await
            .context("failed to launch VM worker")?;

        // Resume (boot) the VM
        info!(sl!(), "openvmm: resuming VM");
        self.vmm_instance
            .resume()
            .await
            .context("failed to resume VM")?;

        self.state = VmmState::VmRunning;
        info!(sl!(), "openvmm: VM is running");

        for device in deferred_block_devices {
            self.add_device(device).await.context("failed to hotplug deferred block device")?;
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

    pub(crate) async fn resize_vcpu(
        &self,
        old_vcpus: u32,
        _new_vcpus: u32,
    ) -> Result<(u32, u32)> {
        Ok((old_vcpus, old_vcpus))
    }

    pub(crate) async fn resize_memory(
        &mut self,
        new_mem_mb: u32,
    ) -> Result<(u32, MemoryConfig)> {
        Ok((new_mem_mb, MemoryConfig::default()))
    }

    pub(crate) async fn get_agent_socket(&self) -> Result<String> {
        // With virtio-vsock the agent listens on vsock CID 3 (default guest),
        // port 1024. The runtime connects via the Unix socket that OpenVMM's
        // virtio-vsock device exposes on the host.
        let vsock_uds_path = format!("{}/vsock.sock", self.run_dir);
        Ok(format!("hvsock://{}", vsock_uds_path))
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
        Ok(vec![std::process::id()])
    }

    pub(crate) async fn get_vmm_master_tid(&self) -> Result<u32> {
        Ok(nix::unistd::gettid().as_raw() as u32)
    }

    pub(crate) async fn get_ns_path(&self) -> Result<String> {
        let pid = std::process::id();
        let tid = nix::unistd::gettid().as_raw() as u32;
        Ok(format!("/proc/{}/task/{}/ns", pid, tid))
    }

    pub(crate) async fn check(&self) -> Result<()> {
        if std::path::Path::new("/dev/mshv").exists() {
            Ok(())
        } else {
            Err(anyhow!("MSHV hypervisor is not available on this host"))
        }
    }

    pub(crate) async fn get_jailer_root(&self) -> Result<String> {
        Ok(get_jailer_root(&self.id))
    }

    pub(crate) async fn get_hypervisor_metrics(&self) -> Result<String> {
        Ok(String::new())
    }

    pub(crate) async fn get_passfd_listener_addr(&self) -> Result<(String, u32)> {
        Err(anyhow!(
            "openvmm get_passfd_listener_addr not yet implemented"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::build_kernel_cmdline;

    #[test]
    fn build_kernel_cmdline_includes_kata_defaults() {
        let cmdline = build_kernel_cmdline(
            false,
            "console=hvc0 cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1",
            "",
            "ext4",
        )
        .unwrap();

        assert!(cmdline.contains("reboot=k"));
        assert!(cmdline.contains("panic=1"));
        assert!(cmdline.contains("systemd.unit=kata-containers.target"));
        assert!(cmdline.contains("systemd.mask=systemd-networkd.service"));
        assert!(cmdline.contains("root=/dev/vda1"));
        assert!(cmdline.contains("rootfstype=ext4"));
        assert!(cmdline.contains("rootflags=data=ordered,errors=remount-ro ro"));
        assert!(cmdline.contains("console=hvc0"));
        assert!(cmdline.contains("cgroup_no_v1=all"));
    }
}
