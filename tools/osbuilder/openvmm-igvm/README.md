# OpenVMM SNP Kata container validation

This directory builds and validates the working Kata Confidential Containers
flow on OpenVMM:

1. build the modified OpenVMM VM-service server and `igvmfilegen`;
2. generate an ACI Linux-direct SEV-SNP IGVM with a selected VP count;
3. build and install the runtime-rs OpenVMM shim and configuration;
4. configure containerd to use the EROFS snapshotter;
5. boot a Kata pod through CRI or Kubernetes and run an EROFS-backed BusyBox
   container.

> [!WARNING]
> This is a bring-up and validation configuration, not a production-ready
> deployment. A permissive SNP guest policy remains enabled, and the guest
> layout still depends on a fixed-GPA workaround. The separate diagnostic IGVM
> permits confidential debugging; the Kata rootfs IGVM does not.

The flow has been validated from clean Azure Linux 3 installations on:

- `Standard_DC16as_cc_v5`;
- `Standard_DC32as_cc_v6`.

## Required source trees

The complete setup builds from three source trees:

- this Kata Containers checkout;
- `OPENVMM_DIR`: OpenVMM source containing SNP IGVM VM-service support;
- `KERNEL_SRC`: the ACI Linux kernel source.

The checked-in `kernel.config` is the configuration extracted from the
validated ACI guest kernel. The setup builds the kernel from `KERNEL_SRC`,
builds kata-agent and a measured dm-verity image from this Kata checkout, and
uses the generated root hash when producing the IGVM.

Prebuilt `KERNEL`, `KATA_IMAGE`, and `ROOT_HASH_FILE` values remain supported
for faster iteration.

## Prepare an Azure Linux host

Use an SNP-capable confidential-child VM. Install the MSHV boot environment:

```sh
sudo dnf install -y \
    kernel-mshv mshv mshv-bootloader-lx edk2-hvloader
sudo reboot
```

After reconnecting, verify the host:

```sh
uname -r
test -e /dev/mshv
```

The kernel version must contain `mshv`, and `/dev/mshv` must exist.

Install the build and runtime dependencies:

```sh
sudo dnf install -y \
    bc binutils bison clang cmake containerd cpio cri-tools curl \
    device-mapper-devel elfutils-libelf-devel erofs-utils file flex gcc \
    gcc-c++ git glibc-devel gzip jq kernel-headers libseccomp-devel \
    llvm-devel make openssl-devel perl parted pkg-config protobuf \
    protobuf-devel python3-pip qemu-img tar veritysetup
```

Install Rust:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
    sh -s -- -y --profile minimal
. "$HOME/.cargo/env"
```

## Prepare OpenVMM

OpenVMM currently requires Rust 1.95:

```sh
cd "$OPENVMM_DIR"
rustup toolchain install 1.95.0 --profile minimal
rustup override set 1.95.0
```

Restore the packaged build dependencies without downloading compatibility-test
IGVMs:

```sh
PROTOC="$(command -v protoc)" \
    cargo xflowey restore-packages --no-compat-igvm
```

`--no-compat-igvm` avoids an interactive GitHub authentication prompt for
artifacts that are not needed by this flow.

## Run the end-to-end flow

Set the input paths:

```sh
cd /path/to/kata-containers/tools/osbuilder/openvmm-igvm

export OPENVMM_DIR="$HOME/openvmm"
export KERNEL_SRC="$HOME/src/openvmm-aci-kernel"
export VP_COUNT=2
```

Build and install the complete host-side stack:

```sh
make e2e-setup \
    OPENVMM_DIR="$OPENVMM_DIR" \
    KERNEL_SRC="$KERNEL_SRC" \
    VP_COUNT="$VP_COUNT"
```

This target:

- builds OpenVMM and `igvmfilegen`;
- builds the guest kernel using the checked-in configuration;
- builds kata-agent and the measured dm-verity Kata image;
- writes the matching `root_hash_.txt`;
- regenerates the dm-verity SNP IGVM;
- sets both the IGVM topology and runtime VM request to `VP_COUNT`;
- builds runtime-rs with OpenVMM support;
- installs `containerd-shim-kata-cc-v2`;
- generates the OpenVMM SNP runtime configuration;
- starts containerd with a dedicated EROFS configuration.

The `make e2e-setup` target does not modify the normal
`/etc/containerd/config.toml`.

Boot and validate the pod:

```sh
make e2e-test VP_COUNT="$VP_COUNT"
```

Successful output includes:

```text
OPENVMM_KATACC_E2E_OK
guest kernel: 6.6.31-aci-kata-openvmm+
```

The test verifies:

- CRI selected the `kata-cc` runtime;
- the container executes inside the Kata guest;
- the container has an active EROFS snapshot;
- the sandbox is backed by an OpenVMM process.
- the guest processor count matches `VP_COUNT`.

The pod and container are removed after the test. Use `KEEP_SANDBOX=yes` to
leave them running.

## Select the VP count

`VP_COUNT` is propagated to both places that must agree:

- `processor_topology.proc_count` in the generated IGVM manifest;
- `default_vcpus` in the generated runtime-rs configuration.

For example, build and validate a four-VP guest:

```sh
make e2e-setup \
    OPENVMM_DIR="$OPENVMM_DIR" \
    KERNEL_SRC="$KERNEL_SRC" \
    VP_COUNT=4

make e2e-test VP_COUNT=4
```

The generated IGVM is named:

```text
out/kata-aci-agent-dmverity-reserve-416b-4vp.bin
```

OpenVMM and MSHV require the runtime processor count to exactly match the
topology embedded in the IGVM. Always use the same `VP_COUNT` for setup and
test. The build target also injects the current
`memmap=4K$0x416b000` bring-up workaround; calling `build.sh` directly requires
passing that argument explicitly.

To force IGVM regeneration when an artifact for the selected VP count already
exists:

```sh
REBUILD_IGVM=yes make e2e-setup \
    OPENVMM_DIR="$OPENVMM_DIR" \
    KERNEL_SRC="$KERNEL_SRC" \
    VP_COUNT="$VP_COUNT"
```

Kubernetes CPU requests are not used to select the IGVM topology. Do not add
CPU sizing annotations or resource limits that change the Kata VM CPU count;
generate and install an IGVM with the desired fixed `VP_COUNT` instead.

## Validate through Kubernetes

The Kubernetes flow assumes `make e2e-setup` has already installed the Kata
runtime and configured containerd.

Create an experimental single-node Kubernetes cluster:

```sh
make e2e-k8s-setup
```

The setup target installs Kubernetes `v1.32.0` and CNI plugins `v1.6.2`,
initializes kubeadm against the existing containerd socket, installs a local
bridge CNI, and removes the control-plane scheduling taint. Override versions
or the pod CIDR with:

```sh
KUBERNETES_VERSION=v1.32.0 CNI_VERSION=v1.6.2 \
    POD_CIDR=10.244.0.0/16 make e2e-k8s-setup
```

Run the Kubernetes test:

```sh
make e2e-k8s-test VP_COUNT="$VP_COUNT"
```

This applies:

- a `kata-cc` `RuntimeClass` mapped to the containerd handler;
- an EROFS-backed BusyBox pod using that runtime class.

The test waits for the pod, executes a marker inside the guest, verifies the
guest VP count and kernel, checks the active EROFS snapshot and OpenVMM process,
and confirms SEV-SNP in guest `dmesg`. Set `KEEP_SANDBOX=yes` to retain the pod:

```sh
KEEP_SANDBOX=yes make e2e-k8s-test VP_COUNT="$VP_COUNT"
kubectl exec -it openvmm-kata-e2e -- sh
```

## Verify SEV-SNP explicitly

With a retained sandbox:

```sh
POD="$(sudo crictl pods -q | head -1)"
CTR="$(sudo crictl ps -q | head -1)"

sudo crictl pods --id "$POD"
pgrep -af "openvmm.*$POD"
sudo crictl exec "$CTR" dmesg |
    grep -E "Memory Encryption Features active|SNP CPUID|SNP guest platform"
```

Expected guest evidence includes:

```text
Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP
SEV: Using SNP CPUID table
SEV: SNP guest platform device initialized
```

## Current limitations

- The kernel command line reserves GPA `0x416b000` to avoid the
  layout-dependent `HvMessageTypeUnacceptedGpa` failure. This is not a
  production fix or stable ABI.
- The diagnostic BusyBox IGVM enables confidential debugging; the Kata rootfs
  IGVM does not.
- The development guest policy is permissive.
- When initdata is present, its digest is bound into the OpenVMM SNP launch
  measurement through `HOST_DATA`; SNP guests without initdata remain supported.
- A guest PCI rescan compensates for the missing OpenVMM PCIe hotplug
  notification under restricted interrupt injection.

## Lower-level troubleshooting targets

The original bring-up targets remain available for debugging:

| Target | Purpose |
|---|---|
| `make kernel` | Build the Kata-capable ACI kernel from `KERNEL_SRC` |
| `make guest-image` | Build kata-agent, dm-verity image, and root hash |
| `make shell-igvm` | Build a diagnostic BusyBox IGVM |
| `make shell-run` | Boot the diagnostic IGVM without a disk |
| `make shell-disk-run` | Boot the diagnostic IGVM with the Kata disk |
| `make agent-dmverity-igvm` | Generate the dm-verity Kata-agent IGVM |
| `make agent-dmverity-run` | Boot the dm-verity guest directly |
| `make e2e-setup` | Build and install a fixed-VP OpenVMM Kata runtime |
| `make e2e-test` | Validate the runtime directly through CRI |
| `make e2e-k8s-setup` | Install an experimental single-node Kubernetes cluster |
| `make e2e-k8s-test` | Validate the runtime through a Kubernetes RuntimeClass |
| `make check` | Validate scripts and manifests |
| `make clean` | Remove generated files under `out/` |
