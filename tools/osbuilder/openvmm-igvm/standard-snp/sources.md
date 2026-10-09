# Standard-injection Kata SNP image sources

Sources for the refreshed test stack, updated October 9, 2026. These artifacts
are installed temporarily for tests; the node's older baseline is restored afterward.

## Image artifacts

| Artifact | Test artifact | SHA-256 |
|---|---|---|
| Production IGVM | `kata-openvmm-snp.bin` | `5d37d203ea8595437ce6406dd48fac8c06902cc5bc3227febc4711e8acda1466` |
| Debug IGVM | `kata-openvmm-snp-debug.bin` | `dd7d45f7197178e36fde644fdd59dc2457682a3232b0e9162c82be16a3731fc7` |
| Guest root filesystem | `kata-containers.img` | `ec15077fdf234f29cb052adc4c6f6c1432be5d808f7b9492474f855f0bb93351` |

The IGVM contains the guest kernel and SNP bootshim. The guest root filesystem is supplied separately as a virtio block disk. No initrd is included.

## Guest kernel

| Field | Value |
|---|---|
| Repository | [chris-oo/CBL-Mariner-Linux-Kernel](https://github.com/chris-oo/CBL-Mariner-Linux-Kernel) |
| Branch | `snp-6.18-guest` |
| Commit | `a155739c182a97c11746002df305b9f91a0c0c42` |
| Commit subject | `hyperv: allocate output pages for enlightened SNP AP startup` |
| Built release | `6.18.34-mshv1-standard-snp-chris` |
| Additional source changes | None |
| Builder source directory | `~/refresh-review/fixed-profile/linux` |
| Builder configuration | [`kernel.config`](kernel.config), copied into `~/refresh-review/fixed-profile/kernel/.config` |
| IGVM kernel input | `~/refresh-review/fixed-profile/bzImage` |
| Kernel SHA-256 | `db33c2d4990a2b83efbba4680ffeb9c739937cd4068ced3a915dfc5e37efada5` |

This revision includes the boot-GHCB reservation, early x2APIC, and enlightened SNP AP-startup changes. It is not the GHCB-unregister branch.

The build uses `EXTRAVERSION=-mshv1`, `LOCALVERSION=`, and configuration value `CONFIG_LOCALVERSION="-standard-snp-chris"`.

Enabled kernel configuration includes:

```text
CONFIG_AMD_MEM_ENCRYPT=y
CONFIG_HYPERV=y
CONFIG_EROFS_FS=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_VERITY=y
```

## Host kernel

| Field | Value |
|---|---|
| Repository | [microsoft/CBL-Mariner-Linux-Kernel](https://github.com/microsoft/CBL-Mariner-Linux-Kernel) |
| Branch | [`user/cho/mshv-snp-normal-injection`](https://github.com/microsoft/CBL-Mariner-Linux-Kernel/tree/user/cho/mshv-snp-normal-injection) |
| Base commit | `f10394f7b07d5a1ee469fc3b85249d3bcdeee193` |
| Commit subject | `mshv: add an SNP interrupt injection policy field` |
| Additional patch | [`mshv-snp-unmap-first.patch`](https://github.com/chris-oo/openvmm/blob/801b9f4f401f237b7dfc194152c7954a81100874/mshv-snp-unmap-first.patch) |
| Modified source | `drivers/hv/mshv_regions.c` |
| Configuration | Copied from the published 6.18 MSHV host build; saved as `host.config` |
| Built release | `6.18.34.mshv3-unmap-first` |
| Builder source directory | `~/standard-snp-boot/linux-host-unmap-first` |
| Kernel SHA-256 | `9b684ee15633c0c77e09eb2ada901d3787542f99a7f1eaf66a647c0a93eeccda` |

The patch unmaps initialized-partition GPA mappings before sharing/reclaiming memory and skips redundant unmapping after finalization.

## IGVM generator

| Field | Value |
|---|---|
| Repository | [microsoft/openvmm](https://github.com/microsoft/openvmm) |
| Base commit | `49742cf0636bdda0dc94757d6185e5e50254873c` |
| Release tag | `openvmm-v0.2.0` |
| Tool | `igvmfilegen` |
| Image type | `snp_linux_direct` |
| Modified source | `vm/loader/igvmfilegen/src/snp_linux_direct.rs` |
| Source patch | [`igvmfilegen-pci-platform.patch`](igvmfilegen-pci-platform.patch) |
| Builder source directory | `~/refresh-review/fixed-profile/openvmm-src` |
| Build wrapper | [`../build.sh`](../build.sh), `igvm` target |
| Manifest generator | [`manifest.py`](manifest.py), producing `manifest.json` and `manifest-debug.json` |

The generator patch adds a PCI host bridge and fixed address layout and removes the COM1 ACPI node. It does not add SMBIOS metadata.

| Address range | Use |
|---|---|
| `0xe0000000..0xe8000000` | PCI ECAM |
| `0xe8000000..0xf8000000` | Low PCI MMIO |
| `0xf8000000..0x100000000` | Reserved low chipset range |
| `0x100000000..0x500000000` | High PCI MMIO |

The PCI bridge uses segment 0 and buses 0 through 127.

The build wrapper invokes:

```bash
"${igvmfilegen}" manifest \
    --manifest "${manifest}" \
    --resources "${out_dir}/resources.json" \
    --output "${out_dir}/kata-openvmm-snp.bin"
```

## SNP bootshim

| Field | Value |
|---|---|
| Component | OpenVMM `snp_bootshim` |
| Builder artifact | `~/refresh-review/fixed-profile/snp_bootshim` |
| Build | `MINIMAL_RT_BUILD=1`, target `x86_64-unknown-none`, profile `boot-release` |
| Exact source revision | `49742cf0636bdda0dc94757d6185e5e50254873c` |
| SHA-256 | `c80b8be4c8e7f9fe80b256501507e98d7a3f47a914adb2bf186927b647b141eb` |

## Manifest parameters

| Parameter | Value |
|---|---|
| Architecture | `x64` |
| Guest SVN | `1` for the tested images; selectable with `IGVM_SVN` in the builder |
| Maximum VTL | `0` |
| Isolation | SNP |
| Injection type | `normal` |
| Secure AVIC | `disabled` |
| Policy field | `196608` (`0x30000`) |
| SNP hardware debug enabled | `false` in both profiles |
| Guest console/debug shell | Production: disabled; debug: `hvc0`, agent debug logging and vsock shell on port `1026` |
| Processor count | `1` |
| Memory page count | `262144` (1 GiB) |
| C-bit position | `51` |
| Initrd | Disabled |
| Root filesystem type | `ext4` |
| Root device | `/dev/dm-0` |
| Root data partition | `/dev/vda1` |
| Root hash partition | `/dev/vda2` |
| dm-verity data blocks | `51712` |
| dm-verity data/hash block size | `4096` bytes |
| dm-verity algorithm | `sha256` |
| Root hash | `ee0f08f38c8b8cf98cd110764ca7eabf4018afd0d9981f89b8342ad6b65632a9` |
| Salt | `93b1c0836d1b94fb24fbdda106f31f62d27609917375f93ec9732c16b0744e40` |

## Guest root filesystem and agent

| Field | Value |
|---|---|
| Repository | `microsoft/kata-containers` |
| Source base | `e40d1e518740471dc703d1b9d4a8cb3006203776`, with the refreshed integration build recipe |
| Builder source directory | `~/kata-openvmm-refresh-20261005` |
| Base distribution | Azure Linux 3.0 (`cbl-mariner` osbuilder target) |
| Build target | `tools/osbuilder/openvmm-igvm`: `make guest-image` |
| Agent | `4.1.0`, release GNU build with `AGENT_POLICY=yes`, `SECCOMP=yes`, `INIT_DATA=yes`, `USE_DEVMAPPER=yes` |
| Rootfs | ext4 with dm-verity; systemd starts the agent |
| Build date | October 5, 2026 |

The refreshed agent/rootfs, kernel and bootshim were built from source. The production and debug IGVMs share this rootfs and differ in their measured guest command lines.

## Runtime components used with the image

### OpenVMM

| Field | Value |
|---|---|
| Repository | [microsoft/openvmm](https://github.com/microsoft/openvmm) |
| Base commit | `49742cf0636bdda0dc94757d6185e5e50254873c` |
| VMM source change | `pcie_ecam_below_4gb: isolation.is_some()` in `openvmm/openvmm_entry/src/ttrpc/mod.rs` |
| Release patch | [`0001-vmservice-use-low-ECAM-for-isolated-guests.patch`](0001-vmservice-use-low-ECAM-for-isolated-guests.patch), separate from the IGVM generator |
| Builder source directory | `~/openvmm-confidential-ecam-review-20261009` |
| Builder binary | `~/conditional-ecam-e2e-20261009/openvmm` |
| Test installation path | `/opt/kata-openvmm/bin/openvmm` |
| Binary SHA-256 | `1aa86384d59a1fe3251129e22fb1c5c4db6842d36d4450a5510424c6020c9443` |

The base includes the merged TTRPC boot and SNP HOST_DATA/guest-request support. The deployed VMM does not include the earlier ACI backend patches.

The recorded binary contains only the VMM release patch, not the generator
patch. October 9 production/debug SNP E2Es passed; a non-confidential pod also
booted with ECAM above 4 GiB at `0x520000000`.

### Kata runtime

| Field | Value |
|---|---|
| Repository | [microsoft/kata-containers](https://github.com/microsoft/kata-containers) |
| Runtime | `runtime-rs` |
| Base commit | `e40d1e518740471dc703d1b9d4a8cb3006203776` |
| Additional changes | Reviewed OpenVMM PR stack below, plus the separate EROFS single-layer classification fix through `b079f56fdd` |
| Latest full E2E source tree | `4e1472da6789be8557d18e901f56832d8a01698e` |
| Builder source directory | `~/kata-openvmm-debug-console-20261007` |
| Test installation path | `/usr/local/bin/containerd-shim-kata-cc-v2` |
| Tested binary SHA-256 | `cfcea527ca39fe7b9fbcef98ccd32d52d5394aa8b644e5d8ca555767b0fe0fa4` |

#### Kata SNP integration commits

Branch: `nbojanic/openvmm-dm-linear`. Commits are listed oldest first.

| Commit | Changes |
|---|---|
| `34d97d805c` | Refresh the OpenVMM VM-service protocol to `openvmm-v0.2.0`. |
| `2b48c70560` | Add SNP IGVM boot, measured command-line handling and the Azure SNP configuration. |
| `cbb30242eb` | Add debug-only virtio-console and reserve PCI slot 8. |
| `4db85cb3bf` | Cold-plug initdata and pass its 32-byte digest through SNP HOST_DATA. |
| `09da3b2471` | Map GPT metadata and independent EROFS layers through read-only host dm-linear devices. |

The tested binary predates the final dm-linear failed-create rollback flag adjustment and test simplification in `09da3b2471`; those later changes passed the privileged cleanup tests. The EROFS classification prerequisite is included in test builds but remains separate from this branch's ancestry.

### Host Hyper-V binaries

| Field | Value |
|---|---|
| Supplied build | `rs_prerelease/29683.1000.260930-1416` |
| Verified running Hyper-V version | `10.0.29683.1000-1-0` |
| Files | `hvax64.exe`, `hvix64.exe`, `kdstub.dll`, `kdcom.dll`, `kdnet.dll`, `lxhvloader.dll` |
| Acquisition | Matched build supplied separately; no public bundle URL confirmed |
| Loader | Existing `HvLoader.efi` retained |

## Container image used for the pod

| Field | Value |
|---|---|
| Image | `nvcr.io/nvidia/nemo` |
| Repository digest | `sha256:0b981b39cb822feec53d22f789c48be8967bc48567b7b051f4d0a3ffaeb44703` |
| Filesystem layer count | `106` |
| Containerd version | `2.3.3` |
| Snapshotter | EROFS |
| OpenVMM disk format | Raw host dm-linear device containing GPT metadata and layer files, exposed through virtio-blk; no VMDK conversion |
| Guest workload layer devices | `/dev/vdd1` through `/dev/vdd106`, each mounted through dm-verity |
| Guest container-layer dm-verity | Enabled for sandbox and workload |

Runs `gpt-dm-production-ef8d296c` and `gpt-dm-debug-5a1be15f` passed on October 8 with 107 guest layer-verity devices including pause. Their test policy required verity presence, not independently derived image root hashes. The October 9 MAP generated-policy startup case failed because the policy did not declare the host EROFS storage. No corruption-injection or report-signature verification is claimed.
