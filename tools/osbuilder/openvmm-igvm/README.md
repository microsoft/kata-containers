# OpenVMM SNP IGVM bring-up

This directory reproduces the currently working OpenVMM SEV-SNP bring-up:

- build a one-vCPU ACI Linux-direct IGVM;
- boot it with OpenVMM over MSHV;
- reach a diagnostic BusyBox shell over COM1;
- optionally attach a Kata rootfs image as virtio-blk and discover
  `/dev/vda`, `/dev/vda1`, and `/dev/vda2`;
- boot the Kata rootfs through dm-verity and start the Kata agent.

This is experimental bring-up tooling, not a Kata runtime configuration.

## Current status

The following path works:

1. MSHV creates an SNP guest with restricted injection.
2. The ACI kernel boots from the IGVM.
3. The embedded diagnostic initramfs starts.
4. A PCIe virtio-blk Kata image is discovered when `KATA_IMAGE` is supplied.
5. The Kata rootfs boots through dm-verity and starts the agent.

Known limitations:

- The two-vCPU manifest tested during bring-up triple-faults while starting the
  second vCPU. This reproducer intentionally uses one vCPU.
- A layout-dependent decompressor page triggers `HvMessageTypeUnacceptedGpa`.
  The current kernel build reserves GPA `0x416b000` as a bring-up workaround;
  this is not a production fix.
- The reserved GPA moved when the kernel layout changed, so the workaround
  must not be treated as a stable ABI.
- The manifest enables confidential debugging and is not suitable for
  production.

## Prerequisites

- An SNP-capable Azure confidential-child VM with `/dev/mshv`.
- The OpenVMM branch containing MSHV SNP ACI IGVM support.
- The OpenVMM-tested ACI `bzImage`.
- A statically linked x86-64 BusyBox binary.
- `cargo`, `jq`, `cpio`, `gzip`, and `file`.
- Optionally, a Kata `kata-containers.img`.

The commands below assume:

```sh
cd /path/to/kata-containers/tools/osbuilder/openvmm-igvm

export OPENVMM_DIR="$HOME/openvmm-snp-mshv-aci-igvm"
export KERNEL="$HOME/openvmm-snp-artifacts/bzImage-aci-6.6-ioapic-virtio.bin"
export BUSYBOX="$HOME/openvmm-snp-artifacts/busybox"
export KATA_IMAGE="$HOME/kata-containers/tools/osbuilder/kata-containers.img"
```

## Build OpenVMM

OpenVMM currently requires Rust 1.95:

```sh
rustup toolchain install 1.95.0 --profile minimal
cd "$OPENVMM_DIR"
rustup override set 1.95.0
```

Restore its packaged build dependencies:

```sh
PROTOC="$(command -v protoc)" cargo xflowey restore-packages
```

The explicit `PROTOC` is useful for bootstrapping a fresh checkout before
OpenVMM's packaged `protoc` has been restored. The restore flow may prompt for
GitHub authentication after the public build artifacts have been installed.

Build the required binaries:

```sh
make openvmm OPENVMM_DIR="$OPENVMM_DIR"
```

## Build the Kata-capable ACI kernel

Start from the exact config embedded in the OpenVMM-tested ACI kernel:

```sh
make kernel \
    KERNEL_SRC="$HOME/src/LSG-linux-rolling-aci-openvmm" \
    BASE_KERNEL="$HOME/openvmm-snp-mshv-aci-igvm/bzImage-aci-6.6-ioapic-virtio.bin"
```

The script enables and verifies dm-init, dm-verity, EROFS, virtio-vsock,
SEV guest reporting, PCIe port support, TUN, nftables, and cgroup BPF.

The output is:

```text
$KERNEL_SRC/build-kata-openvmm/arch/x86/boot/bzImage
```

Linux 6.6 requires a compiler that does not default EFI stub compilation to
C23. GCC 13 on the Azure Linux build node is known to work.

## Build and run the diagnostic shell

```sh
make shell-igvm \
    OPENVMM_DIR="$OPENVMM_DIR" \
    KERNEL="$KERNEL" \
    BUSYBOX="$BUSYBOX"
```

The output is:

```text
out/kata-aci-shell-reserve-416b-1vp.bin
```

Boot the BusyBox shell without a disk:

```sh
make shell-run OPENVMM_DIR="$OPENVMM_DIR"
```

Boot the same shell with the Kata disk attached for manual inspection:

```sh
make shell-disk-run \
    OPENVMM_DIR="$OPENVMM_DIR" \
    KATA_IMAGE="$KATA_IMAGE"
```

The disk-backed shell exposes:

```text
/dev/vda
/dev/vda1
/dev/vda2
```

## Boot the dm-verity Kata agent

The image builder writes dm-verity metadata to `root_hash_*.txt`. Build and
run the working agent variant:

```sh
make agent-dmverity-igvm \
    OPENVMM_DIR="$OPENVMM_DIR" \
    KERNEL="$KERNEL" \
    ROOT_HASH_FILE=../root_hash_.txt

make agent-dmverity-run \
    OPENVMM_DIR="$OPENVMM_DIR" \
    KATA_IMAGE="$KATA_IMAGE"
```

The generated command line creates `/dev/dm-0` from `/dev/vda1` and
`/dev/vda2`, then mounts `/dev/dm-0` as the read-only ext4 root filesystem.
The boot reaches `kata-containers.target` and starts the agent ttRPC server on
`vsock://-1:1024`.

Exit OpenVMM with `Ctrl-C`.

## Validate the tooling

```sh
make check
```

Generated files are confined to `out/`:

```sh
make clean
```
