# OpenVMM standard-injection SNP

**DO NOT MERGE: temporary policy bring-up snapshot.** See `README-policy-bringup.md` and `DO-NOT-MERGE.txt` at the
repository root. The current boot ABI and matching runtime passed focused
hardware E2E; the root README records the exact source pin, tested sizes and
remaining node-provisioning/policy validation boundaries.

Build launch-sized SNP IGVMs from the installed Azure Linux `kernel-uvm-cc`
and `openvmm` packages. The image pipeline configures the approved package
repositories, including buddy repositories when evaluating candidate packages.
This builder does not fetch private host payloads or compile either kernel.

## Dependencies

On the Azure Linux 3 x86-64 builder, install the approved package versions:

```bash
sudo tdnf install -y kernel-uvm-cc openvmm
```

The guest kernel input is `/usr/share/kernel-uvm-cc/bzImage`, not
`vmlinux.bin`. The package owns the kernel configuration and release. Installing
the guest package alone does not update an IGVM; the image must be regenerated.
The OpenVMM package must match the release in `versions.yaml` and include the
confidential-only low-ECAM fix. Its runtime binary is staged from `/usr/bin/openvmm`.

The generator and bootshim still require a source build: their launch-sizing
changes are carried separately in
[`standard-snp/igvmfilegen-launch-sizing.patch`](standard-snp/igvmfilegen-launch-sizing.patch).
Use an OpenVMM checkout containing the pinned release, the repository Rust
toolchain, `protoc`, `yq`, and the Rust `x86_64-unknown-none` target.
Agent/rootfs assembly retains the normal osbuilder prerequisites, including GNU
agent and device-mapper development dependencies.

## Build

```bash
export OPENVMM_SOURCE=/path/to/openvmm
export OUT_DIR=/path/to/build/openvmm-snp
make -C tools/osbuilder/openvmm-igvm all
```

Use a fresh output directory. Individual targets are:

| Target | Work |
|---|---|
| `packages` | Verify installed packages; stage runtime, guest bzImage and package/release records |
| `tools` | Build only `igvmfilegen` and `snp_bootshim` from the pinned, patched source |
| `guest-image` | Build the Kata agent and matched dm-verity rootfs |
| `igvm` | Generate production/debug manifests, images, measurements and checksums |

`OPENVMM_TARGET_DIR` and `CARGO_TARGET_DIR` allow build-cache reuse. `IGVM_SVN`
selects the unsigned 32-bit security version; endorsed builds must choose it
explicitly. `AGENT_POLICY_FILE` selects the bootstrap policy.

There is no `KERNEL_SOURCE`, private kernel config, or VMM-runtime patch/build
step. The old `kernel`/`openvmm` targets and fixed `PROFILE_VCPUS` /
`PROFILE_MEMORY_MIB` settings have been replaced. Configure CPU/memory through
the runtime at VM launch instead.

## Resource and boot contract

The Kata-fork tooling always uses launch-time sizing, with one BSP/platform template,
reserves a 512-MiB minimum, and sets `nr_cpus=256`. The bootshim validates the
launch CPU count, memory map and MADT; constructs CPU ACPI tables; adjusts memory
and PCI windows; then enters Linux. Linux starts the secondary CPUs.

The prototype is bounded to 256 CPUs and 32 GiB RAM with one NUMA node.
Earlier hardware validation covered 1-32 CPUs and 512 MiB-32 GiB. The current
ABI passed focused checks at 1 CPU/1 GiB, 8 CPUs/2 GiB, 32 CPUs/8 GiB and
32 CPUs/32 GiB. This is boot-time sizing, not CPU/memory hotplug.
The 32-GiB E2Es required a longer CreateVM timeout. This temporary integration
snapshot includes the CreateVM-only 300-second extension in runtime-rs; the
IGVM recipe does not build the host shim, so build it separately from this same
Kata revision. Other RPC timeouts remain unchanged.

`clearcpuid=rdpid` temporarily forces Linux's GDT CPU-ID fallback. On the tested
MSHV SNP stack, RDPID/RDTSCP reported CPU 0 despite correct per-CPU TSC_AUX MSR
values. This kernel workaround does not fix raw instruction users or CPUID
advertisement; conditional feature masking belongs in OpenVMM.

The guest uses an ext4 dm-verity rootfs over `/dev/vda1` and `/dev/vda2`, without
an initrd. Its command line binds the exact root hash and salt from
`root_hash_.txt`. Rebuild the IGVM whenever the kernel, bootshim, command line
or rootfs verity inputs change.

Production is quiet with no debug console. The debug image enables `hvc0`,
agent logging and the vsock debug shell. SNP hardware debug remains disabled
in both profiles. Keep separate production/debug measurement expectations.

Use valid runtime boot defaults (1 CPU/1024 MiB), with `overhead_vcpus=0` and
`overhead_memory=0`. Static resource management replaces the boot defaults
with pod limits; setting `default_memory=0` fails OpenVMM configuration validation.

Apply the generated `runtimeclass.yaml` after configuring the `kata-openvmm`
containerd handler. Its pod memory overhead provides host VMM/shim headroom:
without it, a pod memory limit equal to guest RAM can OOM-kill OpenVMM.
This Kubernetes overhead is separate from the zero guest-sizing overhead
knobs and does not request additional guest RAM.

## Outputs and deployment boundary

Outputs include the package-provided `openvmm` and `bzImage`, `kernel.release`,
`package-versions.txt`, generator/bootshim, `kata-containers.img`,
`kata-openvmm-snp.bin`, `kata-openvmm-snp-debug.bin`, their native measurement
JSON/CBOR/ID-block files, manifests, resources, `runtimeclass.yaml` and `SHA256SUMS`.
Record the supplying repository snapshots/buddy build IDs alongside these
artifacts. Checksums are not signatures or endorsements.

The node/image pipeline separately installs `kernel-mshv`, `mshv`,
`mshv-bootloader-lx`, `mshv-kd`, and `openvmm` from approved repositories, then
configures the MSHV boot path and validates the actual kernel/modules and
Hyper-V build after reboot. This builder never installs/reboots a host or
replaces its EFI payload.

Runtime deployment also needs the reviewed OpenVMM-enabled Kata shim/configs
and compatible containerd/erofs-utils. Preserve the required EROFS differ,
dm-verity and host dm-linear settings. Workload-policy parity and report
signature-chain verification are separate from successful boot and sizing.

See [source boundaries](standard-snp/sources.md) and
[runtime follow-ups](standard-snp/follow-ups.md) for the remaining integration
work.
