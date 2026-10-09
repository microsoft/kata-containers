# OpenVMM standard-injection SNP

This builds fixed-profile SNP guests for the runtime-rs OpenVMM backend.
Each profile embeds its CPU count, memory layout, kernel command line and
rootfs verity hash in an IGVM. Changing CPU or memory size requires rebuilding
the IGVM. Dynamic sizing with one approved IGVM awaits the updated bootshim.

## Sources and prerequisites

- OpenVMM is pinned by `assets.hypervisor.openvmm` in `versions.yaml`.
- Guest kernel: `chris-oo/CBL-Mariner-Linux-Kernel`, commit
  `a155739c182a97c11746002df305b9f91a0c0c42`.
- `standard-snp/kernel.config` is the fixed guest configuration.
- `standard-snp/0001-vmservice-use-low-ECAM-for-isolated-guests.patch` is the VMM-only release patch:
  the VM service places ECAM below 4 GiB only for isolated guests.
- `standard-snp/igvmfilegen-pci-platform.patch` supplies the guest's measured
  PCI bridge layout and removes COM1 from its ACPI tables. It is separate for
  vendoring the generator independently of the VMM package. Both patches apply
  to the pinned OpenVMM release; neither changes the non-confidential ECAM default.
- Host MSHV must support normal SNP injection and correct teardown. The tested
  host used `f10394f7b07d5a1ee469fc3b85249d3bcdeee193` plus
  [the unmap-first fix](https://github.com/chris-oo/openvmm/blob/801b9f4f401f237b7dfc194152c7954a81100874/mshv-snp-unmap-first.patch).
  Host installation is separate; these scripts do not provision or reboot hosts.

Build on x86-64 Azure Linux 3 with the repository Rust toolchain, guest-kernel
build dependencies, GNU agent dependencies (including device-mapper development
libraries), `jq`, `yq`, and the existing osbuilder image dependencies.
Install the Rust `x86_64-unknown-none` target for `snp_bootshim`.
The node needs `dmsetup`, loop devices with `LOOP_CONFIGURE` support (Linux 5.8+),
device-mapper `linear` and `zero` targets, and root privileges.

## Build

Use a fresh output directory. Source repositories must already contain the
pinned revisions. The builder creates its own detached source worktrees.

```bash
export KERNEL_SOURCE=/path/to/CBL-Mariner-Linux-Kernel
export OPENVMM_SOURCE=/path/to/openvmm
export OUT_DIR=/path/to/build/openvmm-snp-1cpu-1g
export PROFILE_VCPUS=1 PROFILE_MEMORY_MIB=1024
make -C tools/osbuilder/openvmm-igvm all
```

Separate targets are `kernel`, `openvmm`, `guest-image`, and `igvm`.
`OPENVMM_TARGET_DIR` and `CARGO_TARGET_DIR` allow reuse of build caches.
`IGVM_SVN` selects the unsigned 32-bit guest security version (default `1`);
the release pipeline must choose it explicitly for endorsed builds.
The agent is built with policy, seccomp and device-mapper support.
Supply a reviewed `AGENT_POLICY_FILE` if the minimal bootstrap policy is not
appropriate. Workload policy is delivered through initdata.

The output contains `openvmm`, `igvmfilegen`, `snp_bootshim`, `bzImage`,
`kata-containers.img`, `kata-openvmm-snp.bin`, `kata-openvmm-snp-debug.bin`,
`manifest.json`, `manifest-debug.json`, `resources.json`, and `SHA256SUMS`.
Both IGVMs use the same kernel/rootfs and fixed resource sizes but have different
measured command lines. The production profile uses `quiet` without enabling
the HVC console or agent debug shell. The debug profile enables `console=hvc0`,
console systemd logging, `agent.log=debug`, and an agent debug shell over vsock
port 1026. SNP hardware debugging remains disabled in both profiles.
Use separate attestation expectations for production and debug guests.
One- and two-vCPU, 1-GiB profiles are the bring-up reference sizes; other profile
sizes require validation. The fixed low-MMIO layout limits this builder to
at most 3072 MiB until the platform/bootshim contract is updated.

Generate the corresponding runtime configuration:

```bash
make -C src/runtime-rs \
  PACKAGE_VERSION=dev USE_OPENVMM=true \
  OPENVMMPATH=/usr/bin/openvmm \
  IGVMPATH_OPENVMM_SNP=/usr/share/kata-containers/kata-openvmm-snp.bin \
  IMAGEPATH_OPENVMM_AZURE=/usr/share/kata-containers/kata-openvmm-snp.img \
  DEFVCPUS_OPENVMM_SNP=1 DEFMEMSZ_OPENVMM_SNP=1024 \
  config/configuration-openvmm-azure-snp-runtime-rs.toml
```

Install the VMM and matching IGVM/rootfs at those paths. Resource settings must
match the profile; kernel command-line overrides are rejected for SNP IGVM boot.
The Azure Linux node-builder can additionally package the configuration and a
`containerd-shim-kata-openvmm-v2` alias with `BUILD_OPENVMM_SNP=yes`. This does
not replace CLH defaults or select the legacy `CONF_PODS`/tardev recipe.
`OPENVMM_PROFILE_VCPUS` and `OPENVMM_PROFILE_MEMORY_MIB` select package config sizes.
The debug config selects `kata-openvmm-snp-debug.bin` and enables hypervisor
debugging, which attaches the virtio-console device. Production leaves it
unattached; PCI slot 8 remains reserved in both modes. When configuring manually,
set the debug config's `igvm` path to the debug artifact and enable
`[hypervisor.openvmm].enable_debug`. Guest boot/debug parameters are embedded in
the selected measured IGVM, not changed at launch. Install both IGVMs if using
both configurations; they share the same rootfs image.
Image/VMM artifacts are installed separately, not implicitly replaced by
`package_install.sh`.

For containerd 2.x, select the EROFS snapshotter for this runtime and enable
`plugins.'io.containerd.differ.v1.erofs'.enable_dmverity`. Pass a
`ConfigPath` pointing to the generated OpenVMM configuration. Keep
`pod_annotations = ["io.katacontainers.*"]` to forward initdata. Use a reviewed
RuntimeClass/Pod resource policy for the selected fixed guest profile.

## Signing and node-image integration

The builder produces unsigned artifacts. Signing and AgentBaker node-image
assembly are separate stages; no signing credentials belong in this builder.
The `igvm` target can run against an output directory populated by earlier build
jobs, without rebuilding the kernel, agent or rootfs.

Keep each fixed CPU/memory profile in its own artifact directory. Publish both
IGVMs, their shared rootfs, and their corresponding measurement files together:

| Profile | IGVM | Native measurement JSON |
|---|---|---|
| Production | `kata-openvmm-snp.bin` | `kata-openvmm-snp-snp.json` |
| Debug | `kata-openvmm-snp-debug.bin` | `kata-openvmm-snp-debug-snp.json` |

`igvmfilegen` also emits matching `.cbor` and `.idblock` files. `SHA256SUMS`
includes these, the images, the VMM, manifests and verity metadata, using relative
paths so artifact consumers can run `sha256sum --check SHA256SUMS`.
`resources.json` records build input paths; installation does not need those
paths to remain available.

The native JSON stores the launch digest in `series[0].reference.snp_ld` and
the SVN in `series[0].endorsement.snp_isvsvn`. It is not the legacy Kata signing
claims format containing `x-ms-sevsnpvm-launchmeasurement` and
`x-ms-sevsnpvm-guestsvn`. Whether to preserve that signing schema remains an
integration decision; no conversion or signed `.cose` file is produced here.
Do not relabel native JSON as a signed endorsement.

The generator's `debug_build` metadata describes hardware debug permission,
which is false for both profiles. It does not identify the guest debug-console
profile. Keep production and debug artifacts distinct; do not accidentally
publish a debug guest's measurement as the production endorsement.

AgentBaker integration must select the matching OpenVMM binary, IGVM, rootfs,
signed endorsement and runtime configuration. Artifact filenames may be renamed
during staging, but do not rebuild or modify measured inputs after endorsement.
The node also needs the MSHV host prerequisite and `device-mapper` (`dmsetup`).
The optional node-builder configuration in this series does not itself wire
AgentBaker download filters, install signed endorsements or switch its kata-cc
handler away from CLH. Those consumer changes remain separate.

## GPT layer disks

Only OpenVMM requests host-side composition. CLH retains its existing VMDK and
snapshot paths. GPT metadata and existing layer files are backed by read-only,
autoclear loop devices and assembled into one read-only dm-linear disk per
container. Alignment gaps use dm-zero. The guest verifies each partition with
dm-verity; host composition is not a replacement for guest verification.

No VMDK conversion, copied combined image, per-layer PCI device, multifunction
topology, Python helper, or experimental compile-time flag is needed.
The runtime holds the dm-linear device open while the VMM uses it and schedules
deferred device-mapper removal. Kernel references retain the loop backings until
the device is no longer in use. Setup/teardown failures are reported.
This temporary path supports GPT-partitioned independent layers only; OpenVMM
rejects fsmerge mounts. Correct single-layer classification requires the separate
EROFS detection change.

OpenVMM snapshot/restore of these disks is explicitly unsupported. Rootless
deployment is not supported. Validate host SELinux/device access and package
permissions before deployment. Production workload policy, attestation
certificate verification and corruption-injection tests are separate from
the functional SNP/report bring-up checks.

## Focused checks

```bash
cargo test -p resource --lib rootfs::
cargo test -p hypervisor --features openvmm --lib openvmm::
```

The privileged `readonly_mapping_and_deferred_cleanup` test is ignored by
default. Run the built resource test binary as root on a dedicated test node
with `--ignored` to verify mapped bytes, read-only behavior and final-close
cleanup. Do not run host device-mapper tests on an unapproved shared node.
