# Standard-injection SNP source boundaries

## Package-owned components

| Component | Source of truth | Consumed artifact |
|---|---|---|
| Guest kernel | Approved Azure Linux `kernel-uvm-cc` package | `/usr/share/kernel-uvm-cc/bzImage` and `kernel.release` |
| OpenVMM runtime | Approved Azure Linux `openvmm` package | `/usr/bin/openvmm` |
| Host kernel/modules | Approved Azure Linux `kernel-mshv` package | Versioned kernel and matching `/lib/modules` tree |
| Hyper-V and loader | Approved `mshv`, `mshv-bootloader-lx`, `mshv-kd` packages | Package-managed EFI files |

Configure package repositories outside this builder. Record package
epoch/version/release/architecture and supplying repository snapshots/build
IDs. The `packages` target verifies and stages its installed guest/runtime
inputs and writes `package-versions.txt`; host packages are consumed by the
node/image pipeline, not copied into the guest.

The guest package carries the distro configuration and the decompressor GHCB
unregister, early x2APIC and enlightened SNP AP-startup fixes. The host package
must include normal-injection policy and unmap-first teardown support.
The runtime package must include confidential-only low ECAM. Package presence
alone is not proof of these capabilities: pin approved builds and retain E2E
validation.

There is no private guest-kernel checkout/configuration or hand-copied host
kernel/module/EFI bundle in this build flow.

## Generator and bootshim

The source base is `assets.hypervisor.openvmm.version` from `versions.yaml`.
The currently carried patch targets OpenVMM `openvmm-v0.2.0`, commit
`49742cf0636bdda0dc94757d6185e5e50254873c`.

[`igvmfilegen-launch-sizing.patch`](igvmfilegen-launch-sizing.patch) contains
only generator/loader/bootshim changes, not the VMM runtime ECAM change. It:

- Adds the measured PCI platform template.
- Defines the required launch-sizing handoff using existing IGVM CPU count,
  memory-map and MADT inputs.
- Validates host-supplied CPU identities and RAM ranges.
- Constructs MADT/SRAT CPU records, reserves their output buffers and updates
  ACPI roots/checksums.
- Accepts added RAM and relocates the high PCI window.

The patch includes its bootshim contract documentation and unit tests.
Build `igvmfilegen` in release mode and `snp_bootshim` with
`MINIMAL_RT_BUILD=1`, target `x86_64-unknown-none`, profile `boot-release`.
Do not conflate the packaged runtime's source with these separate tooling
changes.

Linux-direct images always use launch-time sizing in this fork. There is no
fixed-profile execution path or manifest mode switch; generator and bootshim
must be built together, and legacy handoff formats are rejected.

## Manifest and trust boundaries

[`manifest.py`](manifest.py) binds the package kernel, bootshim, guest SVN and
matched rootfs verity inputs. Production/debug differ in guest diagnostics,
not SNP hardware-debug policy. Launch resource values are validated but are
not authenticated resource claims; resource attestation needs a separate
protocol.

The temporary `clearcpuid=rdpid` workaround follows the observed SNP CPU-ID
discrepancy. OpenHCL's separate SNP path already masks RDPID/RDTSCP when
TSC_AUX virtualization is unavailable; the direct MSHV SNP path needs the
equivalent dependency rule.

The agent/rootfs and runtime remain Kata source artifacts. Compatible
containerd and erofs-utils are separate prerequisites. Neither checksum files
nor successful nonce/HOST_DATA/measurement comparisons establish report
signature-chain validity or complete workload-policy parity.
