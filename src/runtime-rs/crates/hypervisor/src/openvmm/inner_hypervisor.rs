// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM hypervisor lifecycle management.

use anyhow::{anyhow, Context, Result};
use std::fs::{self, File};

use super::inner::OpenVmmInner;
use crate::utils::{get_hvsock_path, get_jailer_root, get_sandbox_path};
use crate::{MemoryConfig, VcpuThreadIds, VmmState};

use openvmm_defs::config::{
    Config, DeviceVtl, HypervisorConfig as OvmmHypervisorConfig,
    LinuxDirectBootMode, LoadMode, MemoryConfig as OvmmMemoryConfig,
    PcieDeviceConfig, PcieRootComplexConfig, PcieRootPortConfig,
    ProcessorTopologyConfig, VmbusConfig, DEFAULT_MMIO_GAPS_X86,
};
use vm_resource::IntoResource;
use vm_resource::kind::VmbusDeviceHandleKind;

const KATA_PATH: &str = "/run/kata";

impl OpenVmmInner {
    pub(crate) async fn prepare_vm(
        &mut self,
        id: &str,
        netns: Option<String>,
    ) -> Result<()> {
        info!(sl!(), "openvmm: prepare_vm id={}", id);
        self.id = id.to_string();
        self.state = VmmState::NotReady;
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

        // Build kernel command line
        let mut cmdline = self.config.boot_info.kernel_params.clone();
        if !cmdline.contains("root=") {
            cmdline.push_str(" root=/dev/vda1");
        }
        if !cmdline.contains("rootfstype=") && !self.config.boot_info.rootfs_type.is_empty() {
            cmdline.push_str(&format!(" rootfstype={}", self.config.boot_info.rootfs_type));
        }

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
            enable_serial: true,
            boot_mode: LinuxDirectBootMode::Acpi,
        };

        // Build chipset via VmManifestBuilder
        let chipset = vm_manifest_builder::VmManifestBuilder::new(
            vm_manifest_builder::BaseChipsetType::HyperVGen2LinuxDirect,
            vm_manifest_builder::MachineArch::X86_64,
        )
        .build()
        .context("failed to build VM chipset manifest")?;

        // Memory config
        let mem_size_bytes = (self.config.memory_info.default_memory as u64)
            .checked_mul(1024 * 1024)
            .context("memory size overflow")?;

        // PCIe root complex with one port for virtio-blk rootfs
        // PCIe root complex: ECAM range must match bus count.
        // 128MB ECAM = 128 buses (0..127), each bus has 256 devfns * 4KB config = 1MB.
        let mut pcie_root_complexes = vec![PcieRootComplexConfig {
            index: 0,
            name: "rc0".to_string(),
            segment: 0,
            start_bus: 0,
            end_bus: 127,
            ecam_range: ovmm_memory_range::MemoryRange::new(0xe800_0000..0xf000_0000),
            low_mmio: ovmm_memory_range::MemoryRange::new(0xc000_0000..0xd400_0000),
            high_mmio: ovmm_memory_range::MemoryRange::new(0x0020_3d30_0000..0x200f_3d30_0000),
            ports: vec![
                PcieRootPortConfig {
                    name: "rp0".to_string(),
                    hotplug: false,
                },
            ],
        }];

        // Add rootfs disk as virtio-blk via PCIe
        let mut pcie_devices = Vec::new();
        if !self.config.boot_info.image.is_empty() {
            let disk_path = &self.config.boot_info.image;
            info!(sl!(), "openvmm: adding rootfs disk: {}", disk_path);

            let disk_file = File::open(disk_path)
                .with_context(|| format!("failed to open disk image: {}", disk_path))?;

            let disk_resource = disk_backend_resources::FileDiskHandle(disk_file).into_resource();

            let blk_handle = virtio_resources::blk::VirtioBlkHandle {
                disk: disk_resource,
                read_only: true,
            };

            pcie_devices.push(PcieDeviceConfig {
                port_name: "rp0".to_string(),
                resource: virtio_resources::VirtioPciDeviceHandle(
                    blk_handle.into_resource(),
                )
                .into_resource(),
            });
        }

        // Process pending devices into the VM config
        let pending = std::mem::take(&mut self.pending_devices);
        let mut vmbus_devices: Vec<(DeviceVtl, vm_resource::Resource<VmbusDeviceHandleKind>)> = Vec::new();
        let mut need_extra_pcie_port = false;

        for dev in &pending {
            match dev {
                crate::DeviceType::HybridVsock(hvsock_dev) => {
                    info!(sl!(), "openvmm: wiring HybridVsock device, uds_path={}", hvsock_dev.config.uds_path);
                    // hvsock is configured via vmbus_config.vsock_path below
                }
                crate::DeviceType::Vsock(vsock_dev) => {
                    info!(sl!(), "openvmm: wiring Vsock device, guest_cid={}", vsock_dev.config.guest_cid);
                    // vsock is configured via vmbus_config.vsock_path below
                }
                crate::DeviceType::Network(net_dev) => {
                    info!(sl!(), "openvmm: wiring Network device, tap={}", net_dev.config.host_dev_name);
                    let endpoint = net_backend_resources::tap::TapHandle {
                        name: net_dev.config.host_dev_name.clone(),
                    }
                    .into_resource();
                    let mac = net_dev.config.guest_mac.as_ref()
                        .map(|m| format!("{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
                            m.0[0], m.0[1], m.0[2], m.0[3], m.0[4], m.0[5]))
                        .unwrap_or_default();
                    let nic = netvsp_resources::NetvspHandle {
                        instance_id: ovmm_guid::Guid::new_random(),
                        mac_address: mac.parse().unwrap_or_else(|_| {
                            net_backend_resources::mac_address::MacAddress::from([0u8; 6])
                        }),
                        endpoint,
                        max_queues: None,
                    };
                    vmbus_devices.push((DeviceVtl::Vtl0, nic.into_resource()));
                }
                crate::DeviceType::ShareFs(fs_dev) => {
                    info!(sl!(), "openvmm: wiring ShareFs device, tag={}, path={}",
                        fs_dev.config.mount_tag, fs_dev.config.host_shared_path);
                    let fs_handle = virtio_resources::fs::VirtioFsHandle {
                        tag: fs_dev.config.mount_tag.clone(),
                        fs: virtio_resources::fs::VirtioFsBackend::HostFs {
                            root_path: fs_dev.config.host_shared_path.clone(),
                            mount_options: String::new(),
                        },
                    };
                    // Use PCIe for virtio-fs (needs an extra root port)
                    need_extra_pcie_port = true;
                    pcie_devices.push(PcieDeviceConfig {
                        port_name: "rp1".to_string(),
                        resource: virtio_resources::VirtioPciDeviceHandle(
                            fs_handle.into_resource(),
                        )
                        .into_resource(),
                    });
                }
                crate::DeviceType::Block(blk_dev) => {
                    // Block device for rootfs is already added above via config.boot_info.image
                    info!(sl!(), "openvmm: skipping duplicate Block device (already added as rootfs): {}",
                        blk_dev.config.path_on_host);
                }
                other => {
                    warn!(sl!(), "openvmm: unsupported pending device type: {}", other);
                }
            }
        }

        // Add extra PCIe root port for virtio-fs if needed
        if need_extra_pcie_port {
            pcie_root_complexes[0].ports.push(PcieRootPortConfig {
                name: "rp1".to_string(),
                hotplug: false,
            });
        }

        // Set up hvsocket for agent communication
        let hvsock_path = get_hvsock_path(&self.id);
        info!(sl!(), "openvmm: binding hvsock listener at: {}", hvsock_path);
        // Remove stale socket file if it exists
        let _ = std::fs::remove_file(&hvsock_path);
        let listener = ovmm_unix_socket::UnixListener::bind(&hvsock_path)
            .with_context(|| format!("failed to bind hvsock listener: {}", hvsock_path))?;
        let vmbus_config = VmbusConfig {
            vsock_listener: Some(listener),
            vsock_path: Some(hvsock_path),
            ..Default::default()
        };

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
                proc_count: self.config.cpu_info.default_vcpus.ceil() as u32,
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
            .launch(vm_config)
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
        const HYBRID_VSOCK_SCHEME: &str = "hvsock";
        Ok(format!(
            "{}://{}",
            HYBRID_VSOCK_SCHEME,
            get_hvsock_path(&self.id),
        ))
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
