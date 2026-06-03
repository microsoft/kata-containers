# OpenVMM RPC Binary Integration Gaps

This note captures the runtime blockers found while prototyping the Kata OpenVMM
backend as a standalone `openvmm --ttrpc` process.

## Validation

The runtime-rs build passed with the Azure Linux 3.0 `CONF_PODS=no` package
reference parameters and an external OpenVMM binary path:

```sh
make -C /mnt/data/kata-containers-openvmm-rpc-binary/src/runtime-rs \
  BUILD_TYPE=release \
  LIBC=gnu \
  OPENSSL_NO_VENDOR=Y \
  USE_BUILDIN_DB=false \
  QEMUCMD= \
  FCCMD= \
  DEFMEMSZ=0 \
  DEFSTATICSANDBOXWORKLOADMEM=512 \
  DEFVCPUS=0 \
  DEFSTATICSANDBOXWORKLOADVCPUS=1 \
  DEFSTATICRESOURCEMGMT_OPENVMM=true \
  DEFSANDBOXCGROUPONLY_OPENVMM=true \
  KERNELPATH_CLH=/usr/share/cloud-hypervisor/vmlinux.bin \
  KERNELPATH_OPENVMM=/usr/share/cloud-hypervisor/vmlinux.bin \
  OPENVMMPATH=/data/openvmm-repo/target/release/openvmm \
  OPENVMMVALIDHYPERVISORPATHS='["/data/openvmm-repo/target/release/openvmm"]'
```

The first deployment of `/data/busy.yaml` failed during `CreateVM`:

```text
openvmm RPC failed: Status { code: 2, message: "failed to launch worker: missing PCI INT#A line", details: [] }
```

After the OpenVMM TTRPC server was patched to map the MVP devices to virtio
MMIO, and after Kata stopped advertising OpenVMM passfd I/O, `/data/busy.yaml`
deployed successfully:

```sh
kubectl wait --for=condition=Ready pod/busybox --timeout=180s
kubectl exec busybox -- uname -a
```

```text
pod/busybox condition met
Linux busybox 6.6.96.mshv1-3.azl3 #1 SMP Wed Feb  4 04:41:10 UTC 2026 x86_64 GNU/Linux
```

The validated OpenVMM device model for that pod was `virtio-blk`, `virtio-net`,
inline `virtio-fs`, and `virtio-vsock` on `VirtioBus::Mmio`.

## Initial Root Cause

OpenVMM's TTRPC server currently maps Linux `VirtioFSConfig` to a legacy PCI
virtio-fs path that requires PCI INTx, while using a direct-boot Hyper-V Gen2
Linux chipset that does not expose a PCI INTx interrupt line.

This is not a hotplug issue. The failing path is already a coldplug path during
`CreateVM`: TTRPC pushes the device into `Config::virtio_devices` with
`VirtioBus::Pci`, and `openvmm_core` builds that legacy virtio-pci path with
`PciInterruptModel::IntX(PciInterruptPin::IntA, ...)`. Coldplugging the same
device through that `virtio_devices` PCI path still needs `pci_inta_line`.

The previous in-process Kata integration also used
`BaseChipsetType::HyperVGen2LinuxDirect`, but it did not put virtio-fs through
`Config::virtio_devices`. It built a `PcieRootComplexConfig` with named root
ports (`rp0`, `rp1`, `rp2`, `rp3`, `rp4`, and hotplug `hpN` ports), then added
rootfs, sharefs, net, vsock, and console as `PcieDeviceConfig` resources. That
PCIe path resolves `VirtioPciDeviceHandle` through `PciDeviceHandleKind`, which
uses MSI/MSI-X plumbing rather than the legacy PCI INTx line.

So the observed error is `missing PCI INT#A line`, but the useful gap statement
is not "add PCI INTx". The standalone RPC gap is that `CreateVM` cannot place
virtio-fs on the PCIe/MSI-X path used by the in-process integration, nor select
an MMIO virtio-fs alternative.

Relevant OpenVMM-owned code:

- `openvmm/openvmm_entry/src/ttrpc/mod.rs` hardcodes
  `BaseChipsetType::HyperVGen2LinuxDirect` for `CreateVM`.
- The same TTRPC implementation maps Linux `VirtioFSConfig` to
  `config.virtio_devices.push((VirtioBus::Pci, resource))`.
- `openvmm/openvmm_core/src/worker/dispatch.rs` rejects PCI virtio devices when
  no `pci_inta_line` is available, producing `missing PCI INT#A line`.

Kata needs `shared_fs = "virtio-fs"` for the container rootfs. The current RPC
schema does not provide a way to configure vhost-user-fs, nor does it provide a
way to describe the PCIe root complex/root-port placement used by the existing
virtio-fs device path. Under an RPC-only, Kata-only implementation constraint,
this blocks a working Kubernetes pod.

## MVP Busybox Pod Gaps

For the MVP, assume the OpenVMM runtime must keep `shared_fs = "virtio-fs"`.

### Confirmed

These gaps were confirmed while iterating to a working `busybox` pod. The MVP
workaround is intentionally narrow: it keeps the existing RPC schema but changes
the OpenVMM server-side interpretation of several fields to create virtio MMIO
devices that the Azure Linux guest supports.

| Confirmed standalone RPC gap | MVP workaround used for successful `busybox` deployment | Behavior in in-process integration |
| --- | --- | --- |
| `CreateVM` has no vhost-user-fs fields for virtiofsd socket, tag, queue count, queue size, or bus placement. That means standalone RPC cannot represent the production `shared_fs = "virtio-fs"` device model. | Reuse the existing Linux `VirtioFSConfig { tag, root_path }` as inline OpenVMM host fs and place it on `VirtioBus::Mmio`. This is enough for the MVP pod, but it is not vhost-user-fs parity. | Connects to the virtiofsd socket and creates `VhostUserFsHandle { socket, tag, num_queues, queue_size }`, then places it on the sharefs PCIe root port. |
| The only RPC-visible Linux virtio-fs fallback is inline OpenVMM host fs: `VirtioFSConfig { tag, root_path }`. That fallback can expose a directory to the guest, but it cannot express the production vhost-user-fs/virtiofsd socket model above. | Use inline host fs for the MVP sharefs device, accepting that this is a functional shortcut rather than package parity. | Does not use inline host fs for the normal Kata path; it uses external virtiofsd through vhost-user-fs. |
| The inline virtio-fs fallback was placed on `Config::virtio_devices` with `VirtioBus::Pci`, while the standalone TTRPC server also hardcodes a direct-boot Hyper-V Gen2 Linux chipset without building the explicit PCIe root complex/root ports that Kata used in process. This sent the device down OpenVMM's legacy virtio-pci/INTx path and failed with `missing PCI INT#A line`. | Change the OpenVMM TTRPC Linux virtio-fs fallback from `VirtioBus::Pci` to `VirtioBus::Mmio`, avoiding the PCI INTx dependency. | Uses `BaseChipsetType::HyperVGen2LinuxDirect` plus an explicit `PcieRootComplexConfig`. Sharefs is coldplugged on `rp1` as a `PcieDeviceConfig` wrapping `VirtioPciDeviceHandle`, resolved through `PciDeviceHandleKind` with MSI/MSI-X plumbing rather than legacy PCI INTx. |
| The prototype rootfs path used RPC `ScsiDisk` as VMBus SCSI and rewrote the cmdline to `root=/dev/sda1`. The Azure Linux guest used for validation has virtio-blk support but does not have Hyper-V storage support, so the guest reset before the agent became usable. | Preserve `root=/dev/vda1` in Kata and have OpenVMM reinterpret controller 0 lun 0 from RPC `ScsiDisk` as a `virtio-blk` MMIO root disk. Non-root SCSI disks still use the existing SCSI controller path. | Rootfs is a virtio-blk PCIe device on `rp0`, with the normal virtio block root device path. |
| RPC `HVSocketConfig` normally describes a VMBus hvsocket path. The Azure Linux guest has virtio-vsock support but does not have Hyper-V socket support, so the agent was not reachable with the VMBus hvsocket interpretation. | Reinterpret `HVSocketConfig.path` as the host hybrid-vsock Unix listener for a `virtio-vsock` MMIO device. This made the Kata agent reachable. | Agent transport is a virtio-vsock PCIe device on `rp3`, with the host listener bound by the in-process worker. |
| RPC `NicConfig` maps TAP networking to VMBus NetVSP. The guest did not expose a matching link, and sandbox setup failed in `UpdateInterface` with `Link not found`. | Reuse RPC `NicConfig` TAP name and MAC address, but create a `virtio-net` MMIO device instead of NetVSP for coldplugged pod networking. | Network is a virtio-net PCIe device on `rp2`, with TAP opened inside the worker thread after entering the sandbox netns. |
| Kata's OpenVMM backend advertised `vsock.sock` as a passfd listener. Runtime-rs then sent Kata's passfd protocol (`passfd\n` plus a passed fd) to OpenVMM's hybrid-vsock listener, which expects the hybrid-vsock connect protocol (`connect <port>\n`). OpenVMM closed the connection and container creation failed with `handshake error: malformed response code: ""`. | Disable `get_passfd_listener_addr()` for OpenVMM so runtime-rs does not enter passfd I/O mode. Container creation then falls back to the normal agent/container I/O path and `busybox` reaches `Ready`. | Passfd parity requires a real passfd-compatible listener or bridge for the OpenVMM virtio-vsock path. Simply reusing the hybrid-vsock listener is not sufficient. |

### Minimal Proto Delta for Proper PCI Coldplug

The smallest useful RPC API change for the busybox coldplug gaps is not the full
`openvmm_defs::config::Config`, and it does not need to expose OpenVMM's PCIe
root-complex/root-port topology. It is enough to expose the virtio device models
Kata needs at boot and add vhost-user-fs socket and queue fields. OpenVMM can own
the canonical PCIe topology, bus numbering, ECAM/MMIO windows, root-port
selection, and the exact internal `Config` translation.

```diff
diff --git a/openvmm/openvmm_ttrpc_vmservice/src/vmservice.proto b/openvmm/openvmm_ttrpc_vmservice/src/vmservice.proto
--- a/openvmm/openvmm_ttrpc_vmservice/src/vmservice.proto
+++ b/openvmm/openvmm_ttrpc_vmservice/src/vmservice.proto
@@
 message DevicesConfig {
     repeated SCSIDisk scsi_disks = 1;
     repeated VPMEMDisk vpmem_disks = 2;
     repeated NICConfig nic_config = 3;
@@
     repeated WindowsPCIDevice windows_device = 4;
     repeated VirtioFSConfig virtiofs_config = 5;
+    repeated VirtioBlkConfig virtio_blk_config = 6;
+    repeated VirtioNetConfig virtio_net_config = 7;
+    VirtioVsockConfig virtio_vsock_config = 8;
 }
@@
 message VMConfig {
@@
     // Optional k:v extra data. Up to the virtstack for how to interpret this.
     map<string, string> extra_data = 8;
     HVSocketConfig hvsocket_config = 9;
 }
@@
 message VirtioFSConfig {
     string tag = 1;
     string root_path = 2;
+    string vhost_user_socket_path = 3;
+    uint32 queue_count = 4;
+    uint32 queue_size = 5;
 }
+
+message VirtioBlkConfig {
+    string id = 1;
+    string host_path = 2;
+    DiskType type = 3;
+    bool read_only = 4;
+    uint32 queue_count = 5;
+    uint32 queue_size = 6;
+}
+
+message VirtioNetConfig {
+    NICConfig nic = 1;
+    uint32 queue_pairs = 2;
+    uint32 queue_size = 3;
+}
+
+message VirtioVsockConfig {
+    uint64 guest_cid = 1;
+    string path = 2;
+}
```

With that shape, Kata requests the same coldplug device-model intent as the
in-process path without dictating OpenVMM's PCIe topology. The OpenVMM service
can translate the semantic devices into its internal canonical layout, such as
rootfs/sharefs/net/vsock PCIe devices on fixed root ports. PCIe block hotplug
would still need a `ModifyResource` extension carrying `VirtioBlkConfig` plus a
stable device id; that is intentionally left to the post-MVP parity section.

## Post-MVP / Parity Gaps

| Standalone RPC gap | Behavior in in-process integration |
| --- | --- |
| No PCIe block hotplug in `ModifyResource`; the prototype maps block hotplug to SCSI luns instead of preserving guest PCI paths. | Uses `VmRpc::AddPcieDevice` and `VmRpc::RemovePcieDevice` on named hotplug root ports `hpN`, preserving a PCIe hotplug model. |

### Lifecycle and Introspection Parity

These are not required for the first busybox pod, and they should be judged
against Cloud Hypervisor/QEMU parity rather than against the old in-process
OpenVMM implementation.

| Area | OpenVMM standalone prototype | Cloud Hypervisor runtime-rs behavior | Gap assessment |
| --- | --- | --- | --- |
| Capabilities used by runtime-rs | Kata OpenVMM backend reports local `Capabilities` from its own backend state. The OpenVMM TTRPC service's `CapabilitiesVM` RPC returns `not supported`. | CH also reports capabilities from the Kata CH backend, not by querying a CH service capability RPC. | Not a CLH parity blocker for busybox. Implementing `CapabilitiesVM` would be useful for a richer external OpenVMM service contract, but runtime-rs does not need it for the current flow. |
| Properties / metrics | OpenVMM TTRPC `PropertiesVM` returns `not supported`; Kata OpenVMM `get_hypervisor_metrics()` is not implemented. | CH `get_hypervisor_metrics()` is also not implemented in runtime-rs. | Not a CLH parity regression. Keep as observability follow-up only if OpenVMM needs service-level metrics/properties. |
| vCPU thread IDs | Kata OpenVMM currently returns an empty `VcpuThreadIds`. | CH maps vCPU thread IDs by inspecting the VMM process threads. | Real parity gap for CPU pinning/resource-management flows, but not required for busybox. |
| VM save/restore | Kata OpenVMM `save_vm()` is not implemented; `save_state()` persists runtime state only. | CH `save_vm()` is currently a no-op success, while `save_state()` persists runtime state. | Not a CLH parity blocker as currently used. True VM snapshot/save support is broader post-MVP work. |
| Process identity / namespaces | Kata OpenVMM can report the external `openvmm` process pid and namespace path. | CH reports the cloud-hypervisor process pid and namespace path. | Mostly aligned after moving OpenVMM out of process. |