# How to Use EROFS Snapshotter with Kata Containers (runtime-rs)

## Project Overview

The [EROFS snapshotter](https://github.com/containerd/containerd/blob/main/docs/snapshotters/erofs.md) is a native containerd
snapshotter that converts OCI container image layers into EROFS-formatted blobs.
When used with Kata Containers `runtime-rs`, the EROFS snapshotter enables
**block-level image pass-through** to the guest VM, bypassing virtio-fs / 9p
entirely. This delivers lower overhead, better performance, and smaller memory
footprints compared to traditional shared-filesystem approaches.

> **Deploying with kata-deploy? It does all of this for you**: a
> [kata-deploy](../helm-configuration.md) deployment in `job` mode sets all of this
> up on every node it selects: containerd's EROFS snapshotter and differ
> configuration, the shims you enable pointed at the snapshotter, and the `erofs`
> and dm-verity modules loaded and recorded so they come back after a reboot.
>
> Those settings need erofs-utils 1.8.2 or newer. Where a node packages something
> older, or nothing at all, [`nodeBinaries`](../helm-configuration.md#nodebinaries)
> takes it from a container image instead:
>
> ```yaml
> deploymentMode: job
> snapshotter:
>   setup: ["erofs"]
> nodeBinaries:
>   erofs-utils:
>     image: quay.io/kata-containers/erofs-utils:1.9.3
>     binaries: [mkfs.erofs, dump.erofs, fsck.erofs]
> ```
>
> [`try-kata-nvidia-cpu.values.yaml`](https://github.com/kata-containers/kata-containers/blob/main/tools/packaging/kata-deploy/helm-chart/kata-deploy/try-kata-nvidia-cpu.values.yaml)
> sets the EROFS side of this up and carries that block commented out, to uncomment
> on nodes needing it. Read on for what any of it means, or to set a host up without
> kata-deploy.

## Experimental read-only NVDIMM images

The `runtime-rs` QEMU backend can materialize the read-only EROFS layers into
one raw NVDIMM backing image, with one GPT partition per layer, and hotplug it
read-only. Explicit EROFS DAX mounts avoid copying eligible file data into the
guest page cache. The writable upper layer is unchanged, including the
guest-memory upper used with `default_size = "0"`.

!!! warning "Prototype without guest image integrity verification"
    This path deliberately omits guest dm-verity, even when containerd supplies
    verity metadata. It is disabled by default and rejected for confidential
    guests. Use a separate, non-confidential test runtime configuration.

Enable the prototype in that runtime's configuration:

```toml title="Experimental runtime-rs configuration"
[hypervisor.qemu]
machine_type = "q35"
experimental_erofs_pmem = true
experimental_erofs_pmem_images_path = "/opt/kata/container-images"
memory_slots = 32
default_maxmemory = 16384
```

The optional `experimental_erofs_pmem_images_path` must be an absolute host
directory. The runtime creates it as needed and stores each image at
`<path>/<sandbox-id>/<container-id>/erofs-pmem.raw`. Image files are removed
during container cleanup; unrelated files in the configured base are untouched.
Directory creation or image-write failures are returned rather than falling
back to the default location. The setting is used only when
`experimental_erofs_pmem = true`.

!!! warning "Choose disk-backed storage"
    When the path is omitted or empty, images remain under
    `/run/kata-containers`, which is often tmpfs. Writing complete images there
    allocates host shared memory charged to the pod, offsetting guest DAX
    savings. Select a disk-backed filesystem and verify it with
    `findmnt -T /opt/kata` before enabling the example path.
    After writing and syncing each image, the runtime issues
    `POSIX_FADV_DONTNEED` for the whole image before attachment, requesting
    eviction of its clean cached pages. This is advisory: eviction is not
    guaranteed, particularly on tmpfs, and failures are logged without failing
    container creation. Guest accesses can populate the cache again.
    Source layer caches are left untouched; there is no global cache drop or
    cross-container image sharing.

The prototype requires x86_64 QEMU with ACPI NVDIMM support, a guest kernel
with NVDIMM PFN, device-memory mapping and EROFS DAX support, and an agent built with the corresponding
NVDIMM multi-layer storage support. Build both the shim and agent from this
source tree. No change to `vm_rootfs_driver` or `block_device_driver` is
necessary: this option changes only the EROFS container lower layers.

Choose `default_maxmemory` above the actual VM RAM size, leaving enough address
space for all image mappings. The example reserves address space, not 16 GiB
of resident RAM. VM templates and `enable_virtio_mem = true` are unsupported.

Use independent, self-contained, uncompressed EROFS layer images with 4096-byte
blocks and no inline file data. For the snapshotter, keep
`max_unmerged_layers = 0` and `enable_tar_index = false`; do not enable
compression in `mkfs_options`. The `mkfs.erofs` conversion path used by
containerd already supplies `-Enoinline_data`. Inspect existing layers with
`dump.erofs -s` and `dump.erofs -S` before using them. The prototype rejects
non-4096-byte blocks, compression-related superblock features and external
data devices rather than converting incompatible images.

Limitations:

- Each container gets its own raw disk file. Materialization copies all layer
  bytes, including any unused verity trees, increasing startup I/O and disk
  usage. The file begins with a 2 MiB Linux NVDIMM PFN metadata prefix,
  followed by a 2 MiB-aligned GPT payload with primary and backup GPT structures.
  Linux hides the prefix and presents the GPT disk through `/dev/pmemN`.
  PFN RAM mode keeps page metadata in guest RAM, not in the read-only file:
  budget approximately 64 bytes per 4 KiB of mapped capacity, depending on the
  guest kernel's page structure size.
- There is no cross-container raw-image cache. Separate files do not share
  host page-cache pages merely because their contents are identical.
- QEMU cannot hot-unplug these NVDIMMs. Container deletion unmounts the layers
  and removes the generated files, but QEMU retains the mappings and guest
  device numbers until sandbox shutdown. Container restarts consume additional
  memory slots and address space; exhaustion is reported as an attachment error.
- VM snapshots are rejected while the prototype is enabled.
- DAX does not eliminate application buffers, writable upper-layer pages,
  filesystem metadata, or the host's resident image pages.

Verify that guest EROFS lower mounts use `dax=always`, that representative
regular files report `STATX_ATTR_DAX` through `statx`, and that no
`kata-verity-*` devices are created for these lower layers. Mounts are in the
agent's mount namespace and may not be visible in the container's mount table.
Compare host pod `memory.current` and `memory.stat` under equivalent workloads;
a smaller guest cache alone does not establish a host-memory saving.

!!! note "Requested DAX versus active DAX"
    Linux can silently disable requested EROFS DAX on an unsupported device.
    The PFN prefix enables filesystem DAX for the read-only NVDIMM namespace;
    the agent also rejects a mount if its effective options omit `dax=always`.

## Quick Start Guide

This section provides a quick overview of the steps to get started with EROFS snapshotter and Kata Containers. For detailed instructions, see the [Installation Guide](#installation-guide) section.

### Quick Steps

1. **Install erofs-utils**: Install erofs-utils (version >= 1.8.2) on your host system
2. **Configure containerd**: Enable EROFS snapshotter and differ in containerd configuration
3. **Configure Kata Containers**: Set up runtime-rs with appropriate hypervisor settings
4. **Run a container**: Use `ctr` or Kubernetes to run containers with EROFS snapshotter

### Prerequisites

| Component | Version Requirement |
|-----------|-------------------|
| Linux kernel | >= 5.4 (with `erofs` module, higher recommended) |
| erofs-utils | >= 1.8.2 |
| containerd | >= 2.2 (with EROFS snapshotter and differ support, higher recommended) |
| Kata Containers | Latest `main` branch with runtime-rs |
| QEMU | >= 5.0 (VMDK flat-extent support and >= 9.0  higher recommended) |

> **Note**: When enabling the EROFS snapshotter on a node that is already in
> use, existing images in the containerd image store may not yet have EROFS
> snapshots. Since those images are already present, kubelet may skip pulling
> them again, so containerd can end up converting their layers into EROFS
> snapshots during `CreateContainer` rather than during the image pull phase.
> Configure kubelet's `runtimeRequestTimeout` to cover the slowest expected
> EROFS preparation path for the target node and workload. Large images can
> otherwise exceed kubelet's CRI request deadline before the sandbox starts.

## Installation Guide

This section provides detailed step-by-step instructions for installing and configuring EROFS snapshotter with Kata Containers.

### Step 1: Install erofs-utils

The configuration below uses fsmerge `mkfs_options` that require erofs-utils
>= 1.8.2.

```bash
# Debian/Ubuntu
$ sudo apt install erofs-utils

# Fedora
$ sudo dnf install erofs-utils
```

Verify the version:

```bash
$ mkfs.erofs --version
# Should show 1.8.2 or higher
```

Load the kernel module:

```bash
$ sudo modprobe erofs
```

When using EROFS dm-verity mode, also load the dm-verity device-mapper target:

```bash
$ sudo modprobe dm-mod
$ sudo modprobe dm-verity
```

Make these modules load persistently before containerd starts, for example via
your distribution's modules-load mechanism. If the required kernel support is
missing when containerd starts, enabling the EROFS snapshotter can fail early
instead of producing a useful workload-level error.

### Step 2: Configure containerd

#### Enable the EROFS snapshotter and differ

> **Note**: The following settings target containerd v2.3.0. The
> configured EROFS fsmerge `mkfs_options` require erofs-utils >= 1.8.2. Always
> cross-reference with the official documentation for your current versions.

Edit your containerd configuration (typically `/etc/containerd/config.toml`):

```toml
version = 3
...
  [plugins.'io.containerd.cri.v1.runtime']
    ...
    [plugins.'io.containerd.cri.v1.runtime'.containerd]
      ...
      [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes]
        [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.kata]
          runtime_type = 'io.containerd.kata.v2'
          pod_annotations = ["*"]
          container_annotations = ["*"]
          privileged_without_host_devices = false
          sandboxer = 'podsandbox'
  ...

  [plugins.'io.containerd.differ.v1.erofs']
    mkfs_options = ["-T0", "--mkfs-time", "--sort=none"]
    enable_tar_index = false

  [plugins.'io.containerd.service.v1.diff-service']
    default = ['erofs', 'walking']

  [plugins.'io.containerd.snapshotter.v1.erofs']
    default_size = '<SIZE>' # SIZE=6G or 10G or other size
    max_unmerged_layers = 0
    enable_fsverity = true
```

`enable_fsverity = true` enables host-side fs-verity handling for EROFS layer
blobs when the kernel and backing filesystem support it. This is separate from
the dm-verity mode described below: fs-verity protects layer blob files on the
host, while dm-verity protects the block devices mounted by the Kata guest.

Containerd treats fs-verity support as best-effort and may skip it if the host
kernel or backing filesystem does not support it. If fs-verity protection is
required, make sure the filesystem backing containerd's EROFS snapshotter state
supports fs-verity. For example, on ext4 this requires the `verity` filesystem
feature on the relevant device:

```bash
$ sudo tune2fs -O verity <device-backing-containerd-state>
```

For dm-verity, enable metadata generation in the differ and force strict
dm-verity use in the snapshotter:

```toml
  [plugins.'io.containerd.differ.v1.erofs']
    enable_dmverity = true

  [plugins.'io.containerd.snapshotter.v1.erofs']
    dmverity_mode = 'on'
```

Avoid switching a persistent node back and forth between dm-verity and
non-dm-verity EROFS modes without cleaning or rebuilding the EROFS snapshotter
state. Keep dm-verity consistently enabled or consistently disabled for a given
snapshotter state, because existing layers may have been prepared without
dm-verity metadata.

When dm-verity is enabled, avoid `dmverity_mode = 'auto'`. Auto mode does not
solve stale layer state, because layers prepared without dm-verity metadata can
still be used without dm-verity protection. Strict `dmverity_mode = 'on'` makes
such stale layers fail instead of silently falling back to an unprotected path.

#### Verify the EROFS plugins are loaded

Check if EROFS module is loaded

```bash
$ lsmod | grep erofs
erofs                 188416  0
netfs                 614400  1 erofs
```

If not loaded:

```bash
$ sudo modprobe erofs
```

Restart containerd and check:

```bash
$ sudo systemctl restart containerd
$ sudo ctr plugins ls | grep erofs
io.containerd.snapshotter.v1    erofs    linux/amd64    ok
io.containerd.differ.v1         erofs    linux/amd64    ok
```

Check containerd snapshotter status

```bash
$ sudo ctr plugins ls | grep erofs
io.containerd.mount-handler.v1            erofs                    linux/amd64    ok
io.containerd.snapshotter.v1              erofs                    linux/amd64    ok
io.containerd.differ.v1                   erofs                    linux/amd64    ok
```

Both `snapshotter` and `differ` should show `ok`.

### Step 3: Configure Kata Containers (runtime-rs)

Edit the Kata configuration file (e.g.,
`configuration-qemu-runtime-rs.toml`):

```toml
[hypervisor.qemu]
# shared_fs can be set to "none" since EROFS layers are passed via
# block devices, not via virtio-fs. If you still need virtio-fs for
# other purposes (e.g., file sharing), keep "virtio-fs".
# For pure block-device EROFS mode:
shared_fs = "none"
```

> **Note**: The `shared_fs = "none"` setting is for the case where all
> container images use the EROFS snapshotter. If you have a mixed environment,
> keep `shared_fs = "virtio-fs"` so that non-EROFS containers can still use
> virtio-fs.


### Quick Test

Once the installation is complete, you can quickly test with:

Using `ctr` for example.

```bash
# Pull the image
$ sudo ctr image pull docker.io/library/wordpress:latest

# Run with EROFS snapshotter and Kata runtime-rs
$ sudo ctr run --runtime io.containerd.kata.v2 --snapshotter=erofs --rm -t library/wordpress:latest test001 date
Wed Apr  1 07:10:53 UTC 2026

$ sudo ctr run --runtime io.containerd.kata.v2 --snapshotter=erofs --rm -t wordpress:latest test001 lsblk
NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
vda    254:0    0   256M  0 disk
`-vda1 254:1    0   253M  0 part
vdb    254:16   0     6G  0 disk
vdc    254:32   0 759.7M  0 disk
```

> **Note**: Ensure that the containerd CRI configuration maps the `kata`
> handler to the Kata runtime with `snapshotter = "erofs"` as shown in
> [Step 2](#step-2-configure-containerd).

### Architecture

The following diagram illustrates the data flow:

```
  Host                                        Guest VM
  ====                                        ========

  containerd                                  kata-agent
      |                                           |
      v                                           v
  EROFS snapshotter                           1. mount ext4 /dev/vdX
      |                                          (writable upper)
      |-- Mount[0]: ext4 rw layer                 |
      |     (block device on host)            2. mount erofs /dev/vdY
      |                                          (read-only lower)
      |-- Mount[1]: erofs layers                  |
      |     source: layer.erofs               3. overlay mount
      |     device=extra1.erofs                  lowerdir=<erofs_mount>
      |     device=extra2.erofs                  upperdir=<ext4_mount>/upper
      |                                          workdir=<ext4_mount>/work
      v                                           |
  runtime-rs                                      v
      |                                       container rootfs
      |-- single erofs: attach as Raw            ready
      |-- multi erofs:  generate VMDK
      |     descriptor + attach as Vmdk
      |
      v
  QEMU (virtio-blk)
      |-- /dev/vdX: ext4 rw layer
      |-- /dev/vdY: erofs layer(s)
```

### VMDK flat-extent descriptor (multi-layer case)

VMDK Descriptor Format (twoGbMaxExtentFlat)
The descriptor follows the [VMware Virtual Disk Format specification](https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc):

- Header: `# Disk DescriptorFile` marker and version info
- Extent descriptions: `RW <sectors> FLAT "<filename>" <offset>`
  - `sectors`: number of 512-byte sectors for this extent
  - `filename`: absolute path to the backing file
  - `offset`: starting sector offset within the file (0-based)
- DDB (Disk Data Base): virtual hardware and geometry metadata

Files larger than 2GB are automatically split into multiple extents
(MAX_2GB_EXTENT_SECTORS per extent) as required by the twoGbMaxExtentFlat format.

When multiple EROFS layers are merged, `runtime-rs` generates a VMDK
descriptor file (`twoGbMaxExtentFlat` format):

```
# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="twoGbMaxExtentFlat"

# Extent description
RW 2048 FLAT "/path/to/fsmeta.erofs" 0
RW 4096 FLAT "/path/to/layer1.erofs" 0
RW 8192 FLAT "/path/to/layer2.erofs" 0

# The Disk Data Base
#DDB

ddb.virtualHWVersion = "4"
ddb.geometry.cylinders = "15"
ddb.geometry.heads = "16"
ddb.geometry.sectors = "63"
ddb.adapterType = "ide"
```

QEMU's VMDK driver reads this descriptor and presents all extents as a
single contiguous block device to the guest. The guest kernel's EROFS driver
then mounts this combined device with multi-device support.

### How it works

The containerd EROFS snapshotter prepares a multi-layer rootfs layout:

```
Mount[0]: ext4  rw layer       --> virtio-blk device (writable upper layer)
Mount[1]: erofs layers          --> virtio-blk device (read-only, via VMDK for multi-extent)
Mount[2]: overlay               --> guest agent mounts overlay combining upper + lower
```

For the EROFS read-only layers:

- **Single layer**: The single `.erofs` blob is attached directly as a raw
  virtio-blk device.
- **Multiple layers**: Multiple `.erofs` blobs (the base layer + `device=`
  extra layers) are merged into a single virtual block device using a VMDK
  flat-extent descriptor (`twoGbMaxExtentFlat` format). QEMU's VMDK driver
  parses the descriptor and concatenates all extents transparently.

Inside the guest VM, the kata-agent:

1. Mounts the ext4 block device as the writable upper layer.
2. Mounts the erofs block device as the read-only lower layer.
3. Creates an overlay filesystem combining the two.

### Verify QEMU VMDK support

The multi-layer EROFS rootfs relies on QEMU's VMDK block driver to present
a VMDK flat-extent descriptor as a single virtual disk. QEMU must be compiled
with VMDK format support enabled (this is typically on by default, but some
minimal or custom builds may disable it).

Run the following command to check:

```bash
$ qemu-system-x86_64 -drive format=help 2>&1 | grep vmdk
```

You should see `vmdk` in the `Supported formats` list, for example:

```
Supported formats: blkdebug blklogwrites blkreplay blkverify bochs cloop
compress copy-before-write copy-on-read dmg file ftp ftps host_cdrom
host_device http https luks nbd null-aio null-co nvme parallels preallocate
qcow qcow2 qed quorum raw replication snapshot-access ssh throttle vdi vhdx
vmdk vpc vvfat
```

If `vmdk` does not appear, you need to rebuild QEMU with VMDK support enabled.

### Limitations

> **Hypervisor support**: The fsmerged EROFS rootfs feature currently **only
> supports QEMU** as the hypervisor, because it depends on the VMDK
> flat-extent descriptor format for merging multiple EROFS layers into a
> single block device. The following hypervisors do **not** support VMDK
> format block devices at this time, and therefore **cannot** be used with
> fsmerged EROFS rootfs:
>
> - **Cloud Hypervisor (CLH)** — no VMDK block device support ([WIP](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/7167))
> - **Firecracker** — no VMDK block device support ([WIP](https://github.com/firecracker-microvm/firecracker/pull/5741))
> - **Dragonball** — no VMDK block device support (TODO)
>
> For single-layer EROFS (only one `.erofs` blob, no `device=` extra layers),
> the blob is attached as a raw block device without a VMDK descriptor. This
> mode may work with other hypervisors that support raw virtio-blk devices,
> but has not been fully tested.

## References

- [EROFS documentation](https://erofs.docs.kernel.org)
- [Containerd EROFS snapshotter](https://github.com/containerd/containerd/blob/main/docs/snapshotters/erofs.md)
- [Kata Containers architecture](../design/architecture)
