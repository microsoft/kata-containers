// Copyright (c) 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! OpenVMM hypervisor lifecycle management.

use anyhow::{anyhow, Context, Result};
use std::{
    convert::TryFrom,
    fs::{self, File},
};

use super::inner::OpenVmmInner;
use super::vmm_instance::DeferredNetworkDevice;
use super::{
    openvmm_port_pci_path, OPENVMM_BLOCK_HOTPLUG_PORT_COUNT, OPENVMM_BLOCK_HOTPLUG_PORT_PREFIX,
    OPENVMM_CONSOLE_PCI_PORT, OPENVMM_NET_PCI_PORT, OPENVMM_ROOTFS_PCI_PORT,
    OPENVMM_SHAREFS_PCI_PORT, OPENVMM_STATIC_PCI_PORT_COUNT, OPENVMM_VFIO_COLDPLUG_PORT_COUNT,
    OPENVMM_VFIO_COLDPLUG_PORT_PREFIX,
};
use crate::device::driver::vfio_device::DeviceAddress;
use crate::device::pci_path::PciPath;
use crate::kernel_param::KernelParams;
use crate::utils::{get_jailer_root, get_sandbox_path};
use crate::{MemoryConfig, VcpuThreadIds, VmmState, VM_ROOTFS_DRIVER_BLK};

use openvmm_defs::config::{
    Config, DeviceVtl, HypervisorConfig as OvmmHypervisorConfig, LoadMode,
    MemoryConfig as OvmmMemoryConfig, NumaNode, NumaTopology, PcieDeviceConfig,
    PcieGenericInitiatorConfig, PcieMmioRangeConfig, PciePortConfig,
    PcieRootComplexConfig, ProcessorTopologyConfig, VmbusConfig, VpAssignment,
};
use vm_resource::kind::VmbusDeviceHandleKind;
use vm_resource::IntoResource;

const KATA_PATH: &str = "/run/kata";
const OPENVMM_STANDALONE_VIRTIO_FS: &str = "virtio-fs";
const OPENVMM_INLINE_VIRTIO_FS: &str = "inline-virtio-fs";

// ---------------------------------------------------------------------------
// GB200 / Grace+Blackwell coherent-GPU topology constants.
//
// On GB200 each GPU exposes a synthetic multi-hundred-GiB coherent-memory
// BAR (Grace LPDDR) through the nvgrace_gpu_vfio_pci variant driver. That
// BAR cannot be relocated after guest PCI probe, so the GPU must sit on its
// OWN PCIe root complex with preserve_bars + high_mmio pinned at the BAR's
// host physical address (GPA == HPA). This mirrors the standalone OpenVMM
// harness shape that was validated end-to-end (all 4 GB200 GPUs ->
// nvidia-smi 186 GiB coherent). Gated on the nvgrace driver so the x86
// A100/H100 flat-rc0 path is completely unaffected.
// ---------------------------------------------------------------------------

/// SRAT Generic-Initiator NUMA nodes emitted per GB200 GPU. Bounded by the
/// UVM kernel's `MAX_NUMNODES = 16`: node 0 (CPU) + K * N_GPU must stay
/// <= 16, so K = 3 supports up to ~4 GPUs (1 + 4*3 = 13 <= 16). One GI node
/// is enough for the NVIDIA driver's coherent-NUMA discovery; 3 leaves a
/// little headroom while staying within the cap.
const GB200_GI_NODES_PER_GPU: u32 = 3;

/// First guest PCI bus reserved for per-GPU root complexes. rc0 owns
/// [0, 127]; GB200 GPU RCs are carved out of [128, 255], one span each.
const GB200_GPU_RC_FIRST_BUS: u8 = 128;
/// Buses reserved per GB200 GPU root complex. (256 - 128) / 16 = 8 GPUs max.
const GB200_GPU_RC_BUS_SPAN: u8 = 16;
/// High-MMIO window pinned at each GPU's coherent-BAR HPA. Matches the
/// validated harness run (`high_mmio=2T`). Must be >= the coherent BAR plus
/// a 256 GiB-aligned slot for the small register BAR, and < the inter-GPU
/// HPA delta (2 TiB on this bench) to avoid overlap. Only the base (= HPA)
/// is load-bearing for coherent init; the size is allocation headroom.
const GB200_HIGH_MMIO_WINDOW: u64 = 2 * (1u64 << 40); // 2 TiB

/// True if the host PCI device at `bdf` (segment-qualified, e.g.
/// "0008:06:00.0") is bound to `nvgrace_gpu_vfio_pci` -- the NVIDIA variant
/// driver for GB200 coherent-memory GPUs. Gating the per-GPU-RC topology on
/// this keeps the x86 A100/H100 flat path (driver = vfio-pci) unchanged.
fn is_nvgrace_gpu(bdf: &str) -> bool {
    let link = format!("/sys/bus/pci/devices/{}/driver", bdf);
    std::fs::read_link(&link)
        .ok()
        .and_then(|p| p.file_name().map(|n| n == "nvgrace_gpu_vfio_pci"))
        .unwrap_or(false)
}

/// Read the GB200 coherent-memory BAR from host L1 sysfs and return its
/// host physical address (the largest IORESOURCE_MEM BAR). The coherent
/// aperture is hundreds of GiB; register BARs are far smaller, so we pick
/// the biggest memory BAR above a 1 GiB threshold.
///
/// `/sys/bus/pci/devices/<bdf>/resource` has one `start end flags` line per
/// BAR (BAR0..BAR5 = first six lines). IORESOURCE_MEM = 0x200.
///
/// NOTE: in the nested L1VH setup this is the L1 sysfs value -- the correct
/// nested "HPA" that OpenVMM's `preserve_bars` must pin -- not the
/// bare-metal L0 address.
fn nvgrace_coherent_bar_hpa(bdf: &str) -> Option<u64> {
    let path = format!("/sys/bus/pci/devices/{}/resource", bdf);
    let text = std::fs::read_to_string(&path).ok()?;
    let mut best_start = 0u64;
    let mut best_size = 0u64;
    for line in text.lines().take(6) {
        let mut it = line.split_whitespace();
        let start = u64::from_str_radix(it.next()?.trim_start_matches("0x"), 16).ok()?;
        let end = u64::from_str_radix(it.next()?.trim_start_matches("0x"), 16).ok()?;
        let flags = u64::from_str_radix(it.next()?.trim_start_matches("0x"), 16).ok()?;
        if start == 0 && end == 0 {
            continue;
        }
        // IORESOURCE_MEM = 0x200; skip IO-port BARs.
        if flags & 0x200 == 0 {
            continue;
        }
        let size = end - start + 1;
        if size > best_size {
            best_size = size;
            best_start = start;
        }
    }
    // 1 GiB threshold excludes small register BARs.
    (best_size > (1u64 << 30)).then_some(best_start)
}

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
        let console_vm =
            ovmm_unix_socket::UnixStream::from(std::os::fd::OwnedFd::from(console_vm_std));
        let console_resource =
            ovmm_serial_socket::net::OpenSocketSerialConfig::from(console_vm).into_resource();

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
        let serial_ports: [Option<vm_resource::Resource<vm_resource::kind::SerialBackendHandle>>;
            4] = [None, None, None, None];

        // Build chipset via VmManifestBuilder. Compute the default memory
        // layout from the same builder so it stays in sync with upstream
        // OpenVMM's per-chipset defaults (see VmManifestBuilder::layout_config).
        //
        // The MachineArch selection drives which chipset devices are attached
        // (e.g. ioapic/PIC/PIT/serial-16550 on x86_64, vs PL011 on aarch64);
        // the wrong choice yields runtime resolver errors such as
        // "no resolver for chipset_device_handle:generic-ioapic" on aarch64.
        // Track the build target since the shim is built per-arch.
        #[cfg(target_arch = "x86_64")]
        let host_arch = vm_manifest_builder::MachineArch::X86_64;
        #[cfg(target_arch = "aarch64")]
        let host_arch = vm_manifest_builder::MachineArch::Aarch64;
        let manifest_builder =
            vm_manifest_builder::VmManifestBuilder::new(
                vm_manifest_builder::BaseChipsetType::HyperVGen2LinuxDirect,
                host_arch,
            )
            .with_serial(serial_ports);
        let layout_config = manifest_builder.layout_config();
        let vm_manifest_builder::VmChipsetResult {
            chipset,
            chipset_devices,
            pci_chipset_devices,
            isa_dma_controller,
            capabilities: chipset_capabilities,
        } = manifest_builder
            .build()
            .context("failed to build VM chipset manifest")?;

        // Memory config
        let mem_size_bytes = (self.config.memory_info.default_memory as u64)
            .checked_mul(1024 * 1024)
            .context("memory size overflow")?;

        // PCIe root complex: low/high MMIO windows for BAR allocation.
        //
        // low_mmio is the 32-bit non-prefetchable BAR pool. Each cold-plug
        // root port consumes a bridge MMIO32 window sized for that device's
        // 32-bit MMIO BARs (rounded up to the bridge-alignment granularity);
        // 64-bit prefetchable BARs (e.g. H100 BAR1/2 = 128 GB, BAR3/4 = 32 MB)
        // go in high_mmio and do NOT count here.
        //
        // Worst case on the bench (NVIDIA A100/H100 + NVSwitch):
        //   8x GPU BAR0  (16 MB ea.) = 128 MB
        //   6x NVSwitch BAR0 (32 MB ea.) = 192 MB
        //   static + 24 block-hotplug + 16 vfio-coldplug bridge headers
        //     (each pre-reserves an aligned MMIO32 window even when empty)
        //     and 1 MB-aligned padding between bridges
        //                                    ~ 150-200 MB
        //   Total ≥ 512 MB; 640 MB gives ~2x headroom.
        //
        // Use a Dynamic (size-only) request rather than a Fixed absolute
        // range so OpenVMM's memory-layout resolver places the window in
        // free Mmio32 space below the chipset's architecture-specific
        // "chipset-low-mmio" reservation. That reservation is pinned to the
        // top of 32-bit space and its size is arch-dependent: on x86_64 it
        // is [0xF800_0000, 4 GiB) (128 MB), but on aarch64 it is
        // [0xE000_0000, 4 GiB) (512 MB, driven by the larger GIC/PL011
        // architectural reserved zone). A hardcoded Fixed low_mmio ending at
        // 0xE800_0000 works on x86_64 but overlaps the aarch64 chipset zone,
        // and the resolver then aborts with:
        //   "fixed/reserved requests pcie-rc0-low-mmio (0xc0000000-0xe8000000)
        //    and chipset-low-mmio (0xe0000000-0x100000000) overlap".
        // Dynamic sizing is arch-portable and lets the resolver route around
        // the chipset zone, ECAM, and virtio-mmio slots automatically.
        // preserve_bars is false here, so pinning an absolute base buys us
        // nothing.
        const RC0_LOW_MMIO_SIZE: u64 = 0x2800_0000; // 640 MB

        // high_mmio is the 64-bit prefetchable BAR pool: 8x H100 BAR1/2
        // (128 GB ea.) plus the GB200 coherent-memory BARs (186 GB ea.) all
        // land here. Like low_mmio, request it by size (Dynamic) rather than
        // pinning an absolute Fixed range so OpenVMM's resolver places the
        // window above RAM and routes chipset-high-mmio and dynamic RAM
        // around it automatically. A pinned range is not required here
        // (preserve_bars is false, so the guest re-assigns 64-bit BARs within
        // whatever window it is given during PCI enumeration) and the earlier
        // Fixed [~129 GB, ~35.1 TB) base only worked by accident: nothing
        // else requested a *fixed* 64-bit range, so the overlap check never
        // fired -- but it forced layout_top to ~35 TB and fragmented RAM for
        // any UVM larger than the fixed base. 4 TiB comfortably holds the
        // worst-case bench (8 GPUs x (128 GB BAR1 + 186 GB coherent) ~ 2.5 TB)
        // and matches the validated GB200 reference CLI (high_mmio=4T).
        const RC0_HIGH_MMIO_SIZE: u64 = 0x400_0000_0000; // 4 TiB
        let mut pcie_root_complexes = vec![PcieRootComplexConfig {
            index: 0,
            name: "rc0".to_string(),
            segment: 0,
            start_bus: 0,
            end_bus: 127,
            low_mmio: PcieMmioRangeConfig::Dynamic {
                size: RC0_LOW_MMIO_SIZE,
            },
            high_mmio: PcieMmioRangeConfig::Dynamic {
                size: RC0_HIGH_MMIO_SIZE,
            },
            cxl: None,
            iommu: None,
            vnode: None,
            preserve_bars: false,
            ports: {
                let mut ports = vec![
                    PciePortConfig {
                        name: OPENVMM_ROOTFS_PCI_PORT.to_string(),
                        devfn: None,
                        hotplug: false,
                        // ACS (Access Control Services) capability bits the
                        // emulated root port advertises. 0x5f = SV | TB | RR
                        // | CR | UF | DT (everything except EC, the standard
                        // PCIe ACS bitmask for downstream ports).
                        //
                        // Without ACS visible on the upstream root port, the
                        // in-guest NVIDIA driver concludes that peer-to-peer
                        // DMA between assigned PCI devices is not safely
                        // supported and silently disables P2P (which leaves
                        // NVLink fabric down on multi-GPU baseboards, since
                        // fabricmanager needs cross-device DMA to program
                        // the switches). OpenVMM's CLI default when the user
                        // passes --pcie-root-port is also 0x5f for the same
                        // reason — kata previously left this None, which
                        // OpenVMM treats as "do not synthesize the ACS
                        // capability at all" (see
                        // openvmm/vm/devices/pci/pcie/src/port.rs:353).
                        acs_capabilities_supported: Some(0x5f),
                        cxl: false,
                    },
                    PciePortConfig {
                        name: OPENVMM_SHAREFS_PCI_PORT.to_string(),
                        devfn: None,
                        hotplug: false,
                        acs_capabilities_supported: Some(0x5f),
                        cxl: false,
                    },
                    PciePortConfig {
                        name: OPENVMM_NET_PCI_PORT.to_string(),
                        devfn: None,
                        hotplug: false,
                        acs_capabilities_supported: Some(0x5f),
                        cxl: false,
                    },
                    PciePortConfig {
                        name: super::OPENVMM_VSOCK_PCI_PORT.to_string(),
                        devfn: None,
                        hotplug: false,
                        acs_capabilities_supported: Some(0x5f),
                        cxl: false,
                    },
                    PciePortConfig {
                        name: OPENVMM_CONSOLE_PCI_PORT.to_string(),
                        devfn: None,
                        hotplug: false,
                        acs_capabilities_supported: Some(0x5f),
                        cxl: false,
                    },
                ];

                for index in 0..OPENVMM_BLOCK_HOTPLUG_PORT_COUNT {
                    ports.push(PciePortConfig {
                        name: format!("{}{}", OPENVMM_BLOCK_HOTPLUG_PORT_PREFIX, index),
                        devfn: None,
                        hotplug: true,
                        acs_capabilities_supported: Some(0x5f),
                        cxl: false,
                    });
                }

                // Cold-plug ports for VFIO PCI pass-through (GPUs, NVSwitches,
                // InfiniBand VFs). These are always created so the OpenVMM
                // root-complex layout is stable; unused ones simply appear
                // empty in the guest.
                for index in 0..OPENVMM_VFIO_COLDPLUG_PORT_COUNT {
                    ports.push(PciePortConfig {
                        name: format!("{}{}", OPENVMM_VFIO_COLDPLUG_PORT_PREFIX, index),
                        devfn: None,
                        hotplug: false,
                        acs_capabilities_supported: Some(0x5f),
                        cxl: false,
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
            info!(
                sl!(),
                "openvmm: rootfs disk (opened in worker thread): {}", disk_path
            );
            Some(disk_path)
        } else {
            None
        };

        // Process pending devices into the VM config
        let pending = std::mem::take(&mut self.pending_devices);
        let vmbus_devices: Vec<(DeviceVtl, vm_resource::Resource<VmbusDeviceHandleKind>)> =
            Vec::new();
        let mut deferred_block_devices = Vec::new();
        let mut deferred_network_devices = Vec::new();
        let mut next_vfio_port: u8 = 0;

        // GB200/Grace coherent-GPU accumulators. Each nvgrace GPU gets its
        // own PCIe root complex (preserve_bars + high_mmio pinned at the
        // coherent BAR HPA + per-RC SMMU) plus K SRAT generic-initiator
        // NUMA nodes, instead of sharing rc0. See is_nvgrace_gpu().
        let mut gb200_gpu_count: u8 = 0;
        let mut gb200_next_gi_node: u32 = 1; // node 0 is the CPU node
        let mut gb200_generic_initiators: Vec<PcieGenericInitiatorConfig> = Vec::new();
        let mut gb200_extra_numa_nodes: Vec<NumaNode> = Vec::new();

        for dev in &pending {
            match dev {
                crate::DeviceType::HybridVsock(hvsock_dev) => {
                    info!(
                        sl!(),
                        "openvmm: wiring HybridVsock device as virtio-vsock, uds_path={}",
                        hvsock_dev.config.uds_path
                    );
                    // Handled below via virtio-vsock PCIe device
                }
                crate::DeviceType::Vsock(vsock_dev) => {
                    info!(
                        sl!(),
                        "openvmm: wiring Vsock device as virtio-vsock, guest_cid={}",
                        vsock_dev.config.guest_cid
                    );
                    // Handled below via virtio-vsock PCIe device
                }
                crate::DeviceType::Network(net_dev) => {
                    info!(
                        sl!(),
                        "openvmm: queueing Network device for worker-thread TAP open, tap={}",
                        net_dev.config.host_dev_name
                    );
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
                    deferred_network_devices.push(DeferredNetworkDevice {
                        port_name: OPENVMM_NET_PCI_PORT.to_string(),
                        tap_name: net_dev.config.host_dev_name.clone(),
                        mac_address: mac,
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

                            let num_queues = if fs_dev.config.queue_num > 0 {
                                Some(u16::try_from(fs_dev.config.queue_num).context(
                                    "openvmm vhost-user-fs queue_num does not fit in u16",
                                )?)
                            } else {
                                None
                            };
                            let queue_size = if fs_dev.config.queue_size > 0 {
                                Some(u16::try_from(fs_dev.config.queue_size).context(
                                    "openvmm vhost-user-fs queue_size does not fit in u16",
                                )?)
                            } else {
                                None
                            };

                            virtio_resources::VirtioPciDeviceHandle(
                                virtio_resources::vhost_user::VhostUserFsHandle {
                                    socket: socket.into(),
                                    tag: fs_dev.config.mount_tag.clone(),
                                    num_queues,
                                    queue_size,
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
                crate::DeviceType::VfioModern(vfio_handle) => {
                    // Modern-VFIO cold-plug. This is the variant that
                    // prepare_coldplug_cdi_devices() and
                    // prepare_coldplug_raw_vfio_devices() actually emit, so
                    // this arm is what fires for kubelet CDI grants and for
                    // `ctr --device /dev/vfio/N` standalone containers.
                    //
                    // For each PCI function in the IOMMU group we:
                    //   1. Reserve the next pre-allocated vfio<N> root port.
                    //   2. Open the group fd and hand it to openvmm.
                    //   3. Compute the guest PciPath [root_slot, 0] for that
                    //      port and write it back onto the device's
                    //      `config.guest_pci_path`.
                    //
                    // Step 3 is critical: downstream `handler_devices` in
                    // resource::manager_inner reads that field to build the
                    // agent's `vfio-pci` `device_options`
                    // ("HOST_BDF=GUEST_PCI_PATH"). With it unset the
                    // container create call fails with:
                    //     "VFIO device has no guest PCI path assigned"
                    // even though openvmm successfully attached the device.
                    //
                    // `vfio_handle` is the Arc<Mutex<VfioDeviceModern>> the
                    // VfioModern enum variant carries directly, so it locks
                    // exactly like ch/inner_device.rs does.
                    let mut vfio_device = vfio_handle.lock().await;

                    let host_path = vfio_device.config.host_path.clone();
                    let group_devices: Vec<_> = if !vfio_device.device.devices.is_empty() {
                        vfio_device.device.devices.clone()
                    } else {
                        vec![vfio_device.device.primary.clone()]
                    };
                    info!(
                        sl!(),
                        "openvmm: cold-plug VFIO group {} ({} device(s))",
                        host_path,
                        group_devices.len()
                    );

                    let mut primary_pci_path: Option<PciPath> = None;

                    for dev_info in &group_devices {
                        // openvmm needs the full segment-qualified BDF
                        // (e.g. "0001:00:00.0") so it can look up
                        // /sys/bus/pci/devices/<bdf>. Modern VFIO stores
                        // that as DeviceAddress::Pci(BdfAddress), whose
                        // Display impl prints exactly that form.
                        let host_bdf = match &dev_info.addr {
                            DeviceAddress::Pci(bdf) => bdf.to_string(),
                            other => {
                                warn!(
                                    sl!(),
                                    "openvmm: skipping non-PCI VFIO device {} in group {}",
                                    other,
                                    host_path
                                );
                                continue;
                            }
                        };

                        // GB200/Grace coherent GPU: give this GPU its own
                        // PCIe root complex with preserve_bars + high_mmio
                        // pinned at the coherent-BAR HPA + per-RC SMMU + K
                        // generic-initiator NUMA nodes. This is the shape
                        // validated end-to-end on the standalone OpenVMM
                        // harness (all 4 GB200 GPUs -> nvidia-smi 186 GiB
                        // coherent). Gated on nvgrace_gpu_vfio_pci so the
                        // x86 A100/H100 vfio-pci flat path below is
                        // unaffected. John's 2-level ACS-off switch (for
                        // multi-GPU P2P/NVLink) is intentionally DEFERRED to
                        // a later iteration; single-GPU coherent init does
                        // not need it, and a single root port keeps the
                        // guest topology simpler.
                        if is_nvgrace_gpu(&host_bdf) {
                            let max_gpu_rcs = (256u16 - GB200_GPU_RC_FIRST_BUS as u16)
                                / GB200_GPU_RC_BUS_SPAN as u16;
                            if (gb200_gpu_count as u16) >= max_gpu_rcs {
                                warn!(
                                    sl!(),
                                    "openvmm: GB200 GPU RC budget exhausted ({} max); \
                                     falling back to flat rc0 path for BDF {}",
                                    max_gpu_rcs,
                                    host_bdf
                                );
                            } else if let Some(hpa) = nvgrace_coherent_bar_hpa(&host_bdf) {
                                let rc_idx = gb200_gpu_count;
                                let bus_start =
                                    GB200_GPU_RC_FIRST_BUS + rc_idx * GB200_GPU_RC_BUS_SPAN;
                                let bus_end = bus_start + GB200_GPU_RC_BUS_SPAN - 1;
                                let rc_name = format!("gpurc{}", rc_idx);
                                let port_name = format!("gpu{}", rc_idx);

                                let group_fd = std::fs::OpenOptions::new()
                                    .read(true)
                                    .write(true)
                                    .open(&host_path)
                                    .with_context(|| {
                                        format!(
                                            "openvmm: failed to open VFIO group {} for GB200 GPU {}",
                                            host_path, host_bdf
                                        )
                                    })?;

                                pcie_root_complexes.push(PcieRootComplexConfig {
                                    index: pcie_root_complexes.len() as u32,
                                    name: rc_name.clone(),
                                    segment: 0,
                                    start_bus: bus_start,
                                    end_bus: bus_end,
                                    low_mmio: PcieMmioRangeConfig::Dynamic {
                                        size: 64 * 1024 * 1024,
                                    },
                                    // high_mmio pinned at the coherent-BAR
                                    // HPA so preserve_bars maps the aperture
                                    // at GPA == HPA. Base is load-bearing;
                                    // 2 TiB window matches the harness run.
                                    high_mmio: PcieMmioRangeConfig::Fixed(
                                        ovmm_memory_range::MemoryRange::new(
                                            hpa..hpa + GB200_HIGH_MMIO_WINDOW,
                                        ),
                                    ),
                                    ports: vec![PciePortConfig {
                                        name: port_name.clone(),
                                        devfn: None,
                                        hotplug: false,
                                        acs_capabilities_supported: Some(0x5f),
                                        cxl: false,
                                    }],
                                    cxl: None,
                                    // NO emulated SMMU. The validated harness
                                    // used --smmu rc=,accel, but that requires
                                    // the VFIO device to be wired to the SMMU
                                    // via the iommufd-cdev handle (which
                                    // carries an iommu_id). Kata cold-plugs
                                    // through the legacy VfioDeviceHandle
                                    // (host VFIO container, no iommu_id), so
                                    // declaring iommu:Some(Smmu) here would
                                    // emit a guest SMMUv3 (IORT) with nothing
                                    // behind it -- the guest's arm-smmu-v3
                                    // init then wedges and the VM resets ~1s
                                    // into boot. iommu:None matches the x86
                                    // A100/H100 flat path (legacy container,
                                    // works). preserve_bars + high_mmio pinned
                                    // at the HPA are the load-bearing pieces
                                    // for coherent init (proven in B1n).
                                    // TODO(P2P): restore nested SMMU accel by
                                    // switching to the cdev+iommufd VFIO
                                    // handle + a top-level --iommu context.
                                    iommu: None,
                                    // node=0 in the harness CLI: emit ACPI
                                    // _PXM binding devices under this RC to
                                    // the CPU node.
                                    vnode: Some(0),
                                    preserve_bars: true,
                                });

                                pcie_devices.push(PcieDeviceConfig {
                                    port_name: port_name.clone(),
                                    resource: vfio_assigned_device_resources::VfioDeviceHandle {
                                        pci_id: host_bdf.clone(),
                                        group: group_fd,
                                        bar_pt:
                                            [vfio_assigned_device_resources::BarPassthrough::None;
                                                6],
                                    }
                                    .into_resource(),
                                });

                                // K memoryless (CPU-less) NUMA nodes for this
                                // GPU's coherent LPDDR slices, each bound to
                                // the GPU's port via SRAT Generic Initiator
                                // Affinity. K <= 3 to respect MAX_NUMNODES=16.
                                for _ in 0..GB200_GI_NODES_PER_GPU {
                                    let node = gb200_next_gi_node;
                                    gb200_next_gi_node += 1;
                                    gb200_extra_numa_nodes.push(NumaNode {
                                        mem: None,
                                        vps: VpAssignment::Empty,
                                    });
                                    gb200_generic_initiators.push(PcieGenericInitiatorConfig {
                                        port_name: port_name.clone(),
                                        node,
                                    });
                                }
                                gb200_gpu_count += 1;

                                // Best-effort guest PciPath. The per-GPU RC
                                // has an IOMMU, which shifts OpenVMM's
                                // first_port_device_number, so the [0/0, 0]
                                // rule used for the IOMMU-less flat rc0 path
                                // may be off. VERIFY on the first bench boot
                                // (harness lspci shows the GPU's guest BDF,
                                // e.g. host 0008 -> guest <bus_start>:00.0)
                                // and correct if the container can't find it.
                                let pci_path = openvmm_port_pci_path(0).context(
                                    "openvmm: failed to build guest PciPath for GB200 GPU",
                                )?;
                                info!(
                                    sl!(),
                                    "openvmm: GB200 GPU {} -> RC {} (buses {}..{}), \
                                     high_mmio_base={:#x}, guest pci_path={} (VERIFY)",
                                    host_bdf,
                                    rc_name,
                                    bus_start,
                                    bus_end,
                                    hpa,
                                    pci_path
                                );
                                if primary_pci_path.is_none() {
                                    primary_pci_path = Some(pci_path);
                                }
                                continue;
                            } else {
                                warn!(
                                    sl!(),
                                    "openvmm: {} is nvgrace but its coherent BAR is \
                                     unreadable; falling back to flat rc0 path \
                                     (coherent init will likely fail)",
                                    host_bdf
                                );
                            }
                        }

                        if next_vfio_port >= OPENVMM_VFIO_COLDPLUG_PORT_COUNT {
                            return Err(anyhow!(
                                "openvmm: too many VFIO devices (limit {}), cannot cold-plug BDF {}",
                                OPENVMM_VFIO_COLDPLUG_PORT_COUNT,
                                host_bdf
                            ));
                        }

                        let group_fd = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&host_path)
                            .with_context(|| {
                                format!(
                                    "openvmm: failed to open VFIO group {} for BDF {}",
                                    host_path, host_bdf
                                )
                            })?;

                        let port_index = next_vfio_port;
                        let port_name = format!(
                            "{}{}",
                            OPENVMM_VFIO_COLDPLUG_PORT_PREFIX, port_index
                        );
                        next_vfio_port += 1;

                        // openvmm's PCIe root-bus port layout (kata side):
                        //   [0 .. OPENVMM_STATIC_PCI_PORT_COUNT)              static
                        //   [STATIC .. STATIC + BLOCK_HOTPLUG_PORT_COUNT)     hp<N>
                        //   [STATIC + BLOCK_HOTPLUG .. + VFIO_COLDPLUG)       vfio<N>
                        //
                        // OpenVMM packs root ports into multi-function
                        // device slots (device = i/8, function = i%8) so
                        // the total port count is bounded by the MMIO
                        // budget, not PCI's 5-bit device-number field.
                        // The VFIO endpoint sits behind the port at
                        // function 0 of its secondary bus, which kata
                        // models as the second slot in the PciPath.
                        let openvmm_port_index = OPENVMM_STATIC_PCI_PORT_COUNT
                            + OPENVMM_BLOCK_HOTPLUG_PORT_COUNT
                            + port_index;
                        let pci_path = openvmm_port_pci_path(openvmm_port_index).context(
                            "openvmm: failed to build guest PciPath for VFIO device",
                        )?;

                        info!(
                            sl!(),
                            "openvmm: assigning VFIO BDF {} to port {} (guest pci_path={})",
                            host_bdf,
                            port_name,
                            pci_path
                        );

                        pcie_devices.push(PcieDeviceConfig {
                            port_name,
                            resource: vfio_assigned_device_resources::VfioDeviceHandle {
                                pci_id: host_bdf,
                                group: group_fd,
                                bar_pt: [vfio_assigned_device_resources::BarPassthrough::None; 6],
                            }
                            .into_resource(),
                        });

                        if primary_pci_path.is_none() {
                            primary_pci_path = Some(pci_path);
                        }
                    }

                    // handler_devices() exposes a single device per
                    // VfioDeviceModern (the IOMMU-group primary), so we
                    // record the primary's guest path here. Matches what
                    // ch/inner_device.rs does in its own cold-plug branch.
                    if let Some(pp) = primary_pci_path {
                        vfio_device.config.guest_pci_path = Some(pp);
                    }
                }
                crate::DeviceType::Vfio(vfio_dev) => {
                    // Cold-plug VFIO PCI pass-through. Each HostDevice in the
                    // IOMMU group becomes its own PcieDeviceConfig on a
                    // pre-reserved root port. The /dev/vfio/<group> fd is
                    // opened here (one open per device, which the kernel
                    // allows for the same group).
                    let host_path = &vfio_dev.config.host_path;
                    info!(
                        sl!(),
                        "openvmm: cold-plug VFIO group {} ({} device(s))",
                        host_path,
                        vfio_dev.devices.len()
                    );

                    for hostdev in &vfio_dev.devices {
                        if hostdev.bus_slot_func.is_empty() {
                            warn!(
                                sl!(),
                                "openvmm: skipping VFIO device with empty BDF in group {}",
                                host_path
                            );
                            continue;
                        }
                        if hostdev.domain.is_empty() {
                            warn!(
                                sl!(),
                                "openvmm: skipping VFIO device with empty PCI domain (BDF {}) in group {}",
                                hostdev.bus_slot_func,
                                host_path
                            );
                            continue;
                        }
                        // OpenVMM expects the full PCI BDF including the segment/
                        // domain (e.g. "0001:00:00.0") to resolve
                        // /sys/bus/pci/devices/<full_bdf>. HostDevice splits
                        // these into `domain` ("0001") and `bus_slot_func`
                        // ("00:00.0"); recombine them here.
                        let full_bdf =
                            format!("{}:{}", hostdev.domain, hostdev.bus_slot_func);

                        if next_vfio_port >= OPENVMM_VFIO_COLDPLUG_PORT_COUNT {
                            return Err(anyhow!(
                                "openvmm: too many VFIO devices (limit {}), cannot cold-plug BDF {}",
                                OPENVMM_VFIO_COLDPLUG_PORT_COUNT,
                                full_bdf
                            ));
                        }

                        let group_fd = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(host_path)
                            .with_context(|| {
                                format!(
                                    "openvmm: failed to open VFIO group {} for BDF {}",
                                    host_path, full_bdf
                                )
                            })?;

                        let port_name = format!(
                            "{}{}",
                            OPENVMM_VFIO_COLDPLUG_PORT_PREFIX, next_vfio_port
                        );
                        next_vfio_port += 1;

                        info!(
                            sl!(),
                            "openvmm: assigning VFIO BDF {} to port {}", full_bdf, port_name
                        );

                        pcie_devices.push(PcieDeviceConfig {
                            port_name,
                            resource: vfio_assigned_device_resources::VfioDeviceHandle {
                                pci_id: full_bdf,
                                group: group_fd,
                                bar_pt: [vfio_assigned_device_resources::BarPassthrough::None; 6],
                            }
                            .into_resource(),
                        });
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

        // Hyper-V enlightenments (with_hv) and VMBus both require the backend
        // to emulate the Hyper-V synic. MSHV always provides it; KVM provides
        // it on x86_64 but NOT on aarch64, where OpenVMM aborts VM launch with
        // "failed to get partition synic access for vmbus: synic not supported
        // on KVM/aarch64". Detect the backend the same way vmm_instance::launch
        // and check() do (prefer /dev/mshv, else /dev/kvm) and enable hv+vmbus
        // only when a synic is actually available.
        let synic_available =
            std::path::Path::new("/dev/mshv").exists() || cfg!(target_arch = "x86_64");
        let vmbus_config = synic_available.then(|| VmbusConfig {
            vsock_listener: None,
            vsock_path: None,
            ..Default::default()
        });

        let vm_config = Config {
            load_mode,
            floppy_disks: vec![],
            ide_disks: vec![],
            pcie_root_complexes,
            pcie_devices,
            pcie_switches: vec![],
            vpci_devices: vec![],
            numa: NumaTopology {
                nodes: {
                    let mut nodes = vec![NumaNode {
                        mem: Some(OvmmMemoryConfig {
                            mem_size: mem_size_bytes,
                            prefetch_memory: false,
                            private_memory: false,
                            transparent_hugepages: false,
                            hugepages: false,
                            hugepage_size: None,
                            host_numa_node: None,
                        }),
                        vps: VpAssignment::FromTopology,
                    }];
                    // Append the GB200 memoryless generic-initiator nodes
                    // (one set per nvgrace GPU) after the CPU node.
                    nodes.append(&mut gb200_extra_numa_nodes);
                    nodes
                },
                distances: vec![],
            },
            pcie_generic_initiators: gb200_generic_initiators,
            processor_topology: ProcessorTopologyConfig {
                proc_count: self.config.cpu_info.default_vcpus.ceil() as u32,
                vps_per_socket: None,
                enable_smt: None,
                arch: {
                    // GB200/Grace (aarch64) needs GICv2m MSI delivery:
                    // John's validated CLI uses --gic-msi v2m because the
                    // GICv3 ITS path has known issues in this combination.
                    // The shim binary is arch-specific, so a compile-time
                    // cfg is correct here.
                    #[cfg(target_arch = "aarch64")]
                    {
                        Some(openvmm_defs::config::ArchTopologyConfig::Aarch64(
                            openvmm_defs::config::Aarch64TopologyConfig {
                                gic_msi: openvmm_defs::config::GicMsiConfig::V2m {
                                    spi_count: None,
                                },
                                ..Default::default()
                            },
                        ))
                    }
                    #[cfg(not(target_arch = "aarch64"))]
                    {
                        Default::default()
                    }
                },
            },
            hypervisor: OvmmHypervisorConfig {
                with_hv: synic_available,
                ..Default::default()
            },
            chipset,
            vmbus: vmbus_config,
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
            chipset_devices,
            pci_chipset_devices,
            isa_dma_controller,
            chipset_capabilities,
            layout: layout_config,
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
                deferred_network_devices,
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
        // Mirror vmm_instance.rs::launch backend selection: OpenVMM
        // accepts either /dev/mshv (MSHV, preferred when both are
        // present) or /dev/kvm (KVM, fallback). The shim is happy as
        // long as one of them exists; the actual handle is built in
        // launch().
        if std::path::Path::new("/dev/mshv").exists()
            || std::path::Path::new("/dev/kvm").exists()
        {
            Ok(())
        } else {
            Err(anyhow!(
                "no OpenVMM hypervisor backend available on this host: \
                 neither /dev/mshv nor /dev/kvm exists"
            ))
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
