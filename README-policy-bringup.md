# DO NOT MERGE: OpenVMM SNP policy bring-up

This branch is a **source-based development baseline for policy work**, not a
release. Build the producer and host shim from the same pinned commit.
No prebuilt IGVM blobs, private EFI payloads, credentials or permissive
workload policies are supplied here.

## History and review boundary

| Layer | Source |
|---|---|
| Main baseline | `0fe9e6346f643cd7de5517d4ae69411baf327b94` |
| Already merged into that baseline | #563 EROFS classification, #564 OpenVMM protocol, #565 SNP boot/config, #567 console |
| Separate #568 commit | `095eceac0a874e6c16e77681f323e408a091eeea`, including the approved lifecycle-comment correction |
| Separate #572 commit | Replay of `09da3b24719be54639d546d3be84c1f2a738aa1c`; its `Original-commit` trailer records provenance |
| Final DO-NOT-MERGE commit | Package-based producer, current boot-tooling patch, prototype CreateVM timeout and these bring-up files |

The open PRs are not represented as merged/released work. The capability
implementation remains the chosen #568 approach; this branch does not add
the discarded mutable-capability fix.

For your policy stack, fetch the branch and record its full SHA:

```bash
git remote add kata-msft https://github.com/microsoft/kata-containers.git
git fetch kata-msft nbojanic/do-not-merge-policy-bringup-20261012
git rev-parse FETCH_HEAD
```

If that remote already exists, inspect its URL instead of adding it again.
Rebase only your policy commits: use
`git rebase --onto <recorded-integration-SHA> <old-policy-base> <policy-branch>`
after creating a safety branch. Do not blindly replay the old virtualization
stack or merge this temporary branch into main. Future review changes should
arrive as a new agreed source pin.

## What was validated, and what was not

Earlier source/artifact versions passed production and debug E2Es using these
package versions, including actual pod-limit sizing through 32 vCPUs/32 GiB,
24-GiB memory write/read, a 106-layer workload and clean teardown.

**The current boot patch includes** canonical IGVM
memory-map entries, a mandatory launch-only path, memory-map offset 8,
`katashim` magic/version 1 and the named `launch_params_gpa` field.
The producer and matching release shim built from
`c8655693745004d06cd3b8160479a392701109b5` passed focused hardware E2E on
October 12, 2026, including these ABI changes. Documentation-only updates
record this result without changing the tested implementation.

| Production pod limits | Result |
|---|---|
| 1 vCPU / 1 GiB | Passed |
| 8 vCPUs / 2 GiB | Passed |
| 32 vCPUs / 8 GiB | Passed, including 6 GiB written/read |
| 32 vCPUs / 32 GiB | Passed, including 24 GiB written/read |

One production IGVM, shim and fixed configuration were used. CPU-ID checks,
exact ACPI/memory sizing, workload dm-verity, exec/DNS and report
nonce/HOST_DATA/measurement checks passed. The 106-layer debug workload also
passed at 1 vCPU / 1 GiB, including its console and debug shell, networking,
layer verity and report fields. SNP hardware debug remained disabled.

The host was the previously validated Allen Pais kernel branch at
`bca7fae1ff0921ae8deacfb0507b256cbd2c736e`, booted as
`6.18.34.mshv3-apais-bca7fae1`, with Hyper-V `10.0.26100.9606-9-0`.
The existing node's containerd/CNI and RuntimeClass alias were reused, and
only deployment paths were adapted from the generated runtime configuration.
The original node runtime files were restored and teardown was clean.

This integration's runtime-rs, generator and host/bare-metal bootshim paths
passed remote compilation checks. The documented runtime-config generation
and debug transformation were also checked, as were the shell scripts and
containerd fragment.

This was not a fresh package-repository/node installation, AgentBaker/MAP
image build, full 12-case rerun or final policy-authorization test. Report
signature chains were not verified. Validate your resulting node and policy
stack separately; the earlier full matrix is not coverage of every case on
this exact revision.

`clearcpuid=rdpid` remains a measured kernel-command-line workaround for the
SNP fast CPU-ID issue. Runtime-rs in the final WIP commit includes a
**300-second CreateVM-only timeout**; other OpenVMM RPC timeouts remain 30s.
This extension is temporary and not part of the reviewed runtime PRs.

## Package inputs

Use Azure Linux 3 x86-64 with approved buddy-enabled repositories:

| Component | Buddy run | Exact package identity |
|---|---:|---|
| Guest kernel | 1221862 | `kernel-uvm-cc 0:6.18.52.mshv1-1.azl3.x86_64` |
| Host kernel | 1221853 | `kernel-mshv 0:6.18.34.mshv3-2.azl3.x86_64` |
| OpenVMM runtime | 1221766 | `openvmm 0:0.2.0-2.azl3.x86_64` |
| Hyper-V | 1221253 | `mshv 2:26100.9606.2609291929.1-1.azl3.x86_64` |
| Hyper-V Linux loader | 1221253 | `mshv-bootloader-lx 2:26100.9606.2609291929.1-1.azl3.x86_64` |
| Hyper-V debugger components | 1221253 | `mshv-kd 2:26100.9606.2609291929.1-1.azl3.x86_64` |

Run URLs have this form:

```text
https://dev.azure.com/mariner-org/mariner/_build/results?buildId=1221862
https://dev.azure.com/mariner-org/mariner/_build/results?buildId=1221853
https://dev.azure.com/mariner-org/mariner/_build/results?buildId=1221766
https://dev.azure.com/mariner-org/mariner/_build/results?buildId=1221253
```

The host build's partial-success result came from reviewed docs/tools license
warnings, not kernel compilation/install failure. The other builds succeeded.
Check availability and provenance before use; same-version RPMs from other
builds can have different bytes.

Ordinary AMD64 artifact: `drop_buddy_build_amd64_build_amd64`.
MSHV artifact: `drop_build_rpms_build`.
RPMs are under `build-artifacts/rpms.tar.gz` inside each artifact. Use your
organization's authorized buddy-repository setup; the recipe assumes packages
are installed and does not configure credentials or feeds.
Do not disable signature/TLS verification to get packages installed.
One ordinary buddy ID does not contain all three ordinary-package builds.

The guest RPM is a **build input**, not the host kernel. The producer consumes
`/usr/share/kernel-uvm-cc/bzImage` and generates new IGVMs. The host kernel RPM
provides `/boot/vmlinuz-6.18.34.mshv3-2.azl3` and matching modules. MSHV RPMs
provide EFI binaries, not a Linux kernel. The OpenVMM runtime RPM already
contains the confidential-only ECAM fix.

## 1. Build guest artifacts on the build machine

Use a separate, pinned checkout on a remote build machine, not the workstation
or another person's running test node. Ensure sufficient disk space and the
normal Azure Linux Kata agent/rootfs build dependencies are installed.
The recipe needs Rust/Cargo, GCC/build tools, GNU agent device-mapper/seccomp
dependencies, protobuf compiler, Python 3, `yq`, `tdnf`, filesystem/verity
tools and passwordless sudo for osbuilder. Start from a provisioned Kata
builder; resolve missing-package errors through the normal package manager.

```bash
sudo tdnf install -y kernel-uvm-cc openvmm
sudo tdnf upgrade -y kernel-uvm-cc openvmm
rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
  kernel-uvm-cc openvmm
```

Stop if versions differ from the table; fix repository selection first.

From this Kata checkout:

```bash
git clone --branch openvmm-v0.2.0 --single-branch \
  https://github.com/microsoft/openvmm.git ../openvmm-tooling-base
test "$(git -C ../openvmm-tooling-base rev-parse HEAD)" = \
  49742cf0636bdda0dc94757d6185e5e50254873c

export OPENVMM_SOURCE="$(realpath ../openvmm-tooling-base)"
export OUT_DIR="$(realpath -m ../kata-policy-artifacts)"
export CARGO_TARGET_DIR="$(pwd)/target"
export PROTOC="$(command -v protoc)"
export IGVM_SVN=1
rustup target add x86_64-unknown-none

make -C tools/osbuilder/openvmm-igvm all
(cd "$OUT_DIR" && sha256sum -c SHA256SUMS)
```

Use a fresh `OUT_DIR`. The recipe applies the committed tooling patch to the
public base, builds generator/bootshim, builds the agent/rootfs, and generates
production/debug IGVMs and measurements. Do not point it at an already-patched
tooling snapshot and apply the patch twice.

The package kernel/OpenVMM and source-built rootfs/tooling are recorded in
the output. The rootfs verity hash/salt are embedded in the measured command
line. Rebuilding the rootfs, kernel, bootshim or command line requires new
IGVMs and attestation expectations.

## 2. Build the matching host shim and configurations

This is a separate step; the IGVM recipe does not build the host shim.
Run from the same Kata source checkout:

```bash
export CARGO_TARGET_DIR="$(pwd)/target"
make -C src/runtime-rs runtime \
  USE_OPENVMM=true LIBC=gnu BUILD_TYPE=release \
  PREFIX=/opt/kata-openvmm \
  PACKAGE_VERSION=policy-bringup \
  OPENVMMPATH=/usr/bin/openvmm \
  IMAGEPATH_OPENVMM_AZURE=/opt/kata-openvmm/share/kata-containers/kata-containers.img \
  IGVMPATH_OPENVMM_SNP=/opt/kata-openvmm/share/kata-containers/kata-openvmm-snp.bin \
  DEFVCPUS_OPENVMM_SNP=1 DEFMEMSZ_OPENVMM_SNP=1024 \
  DEFSTATICSANDBOXWORKLOADMEM=1024 DEFSTATICSANDBOXWORKLOADVCPUS=1

cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/containerd-shim-kata-v2" \
  "$OUT_DIR/"
cp src/runtime-rs/config/configuration-openvmm-azure-snp-runtime-rs.toml "$OUT_DIR/"
sed \
  -e 's|/kata-openvmm-snp\.bin"|/kata-openvmm-snp-debug.bin"|' \
  -e 's/^enable_debug = false$/enable_debug = true/' \
  -e 's/^debug_console_enabled = false$/debug_console_enabled = true/' \
  "$OUT_DIR/configuration-openvmm-azure-snp-runtime-rs.toml" \
  > "$OUT_DIR/configuration-openvmm-azure-snp-runtime-rs-debug.toml"

cp tools/osbuilder/openvmm-igvm/containerd-bringup.toml "$OUT_DIR/"
cp tools/osbuilder/openvmm-igvm/grub-menuentry.sh "$OUT_DIR/"
(cd "$OUT_DIR" && sha256sum containerd-shim-kata-v2 \
  configuration-openvmm-azure-snp-runtime-rs.toml \
  configuration-openvmm-azure-snp-runtime-rs-debug.toml \
  containerd-bringup.toml grub-menuentry.sh > NODE-SHA256SUMS)
```

For repeated builds with different Make variables, remove only the generated
OpenVMM config files before regenerating them; Make does not track variable
changes as file dependencies. Do not reuse stale generated configurations.
Use an agreed `PACKAGE_VERSION` for reproducible distributed builds.

Verify the generated configs: `hypervisor_name="openvmm"`, static resource
management enabled, boot/static workload defaults 1 CPU/1024 MiB, and
`overhead_vcpus=0` / `overhead_memory=0`. Do not set boot memory to zero:
OpenVMM validates it before applying pod limits.

## 3. Prepare an approved disposable node

The reference node is Azure Linux 3, Generation 2, on an SNP-capable Azure SKU.
The tested host size was DC32as_cc_v6 with 128 GiB RAM. A 32-GiB guest needs
more than 32 GiB of host RAM. Check region capacity, permissions and the exact
VM/security profile with the owner; this README does not authorize resource
creation, role grants, or overwriting an existing node.

The node needs working Kubernetes/containerd/CNI and the normal
`kata-packages-host` boot support, including `HvLoader.efi` and
`/etc/grub.d/50_mariner_mshv_menuentry`. Back up boot configuration and EFI
payloads and agree on recovery before installing/upgrading host packages.
An old kernel entry is not an independent recovery path if its shared EFI
binaries are overwritten; preserve a separately bootable old-EFI path first.

With approved buddy repositories configured:

```bash
sudo tdnf install -y kata-packages-host kernel-mshv mshv mshv-bootloader-lx \
  mshv-kd openvmm device-mapper util-linux
sudo tdnf upgrade -y kernel-mshv mshv mshv-bootloader-lx mshv-kd openvmm
rpm -q --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' \
  kernel-mshv mshv mshv-bootloader-lx mshv-kd openvmm
```

Verify exact package versions before proceeding. Do not install the UVM kernel
as the host kernel. Keep signature enforcement and integrity lockdown enabled;
these development runs do not establish production Secure Boot trust.

Copy the artifact directory to the node as `$ARTIFACTS` and verify both checksum
files. For a **fresh node** with no existing OpenVMM installation:

```bash
cd "$ARTIFACTS"
sha256sum -c SHA256SUMS
sha256sum -c NODE-SHA256SUMS
test ! -e /opt/kata-openvmm
sudo install -d /opt/kata-openvmm/bin /opt/kata-openvmm/share/kata-containers \
  /opt/kata-openvmm/share/defaults/kata-containers
sudo install -m755 containerd-shim-kata-v2 /opt/kata-openvmm/bin/
sudo ln -s containerd-shim-kata-v2 \
  /opt/kata-openvmm/bin/containerd-shim-kata-openvmm-v2
sudo install -m644 kata-containers.img kata-openvmm-snp.bin \
  kata-openvmm-snp-debug.bin /opt/kata-openvmm/share/kata-containers/
sudo install -m644 configuration-openvmm-azure-snp-runtime-rs*.toml \
  /opt/kata-openvmm/share/defaults/kata-containers/
```

Do not copy the producer's `openvmm` binary over the node RPM; generated
configs use the package-managed `/usr/bin/openvmm`.

After arranging recovery, prepare the packaged host boot:

```bash
HOST_RELEASE=6.18.34.mshv3-2.azl3
sudo depmod -a "$HOST_RELEASE"
sudo test -s "/boot/initramfs-$HOST_RELEASE.img" || \
  sudo dracut --kver "$HOST_RELEASE" "/boot/initramfs-$HOST_RELEASE.img"
sudo install -m755 "$ARTIFACTS/grub-menuentry.sh" /etc/grub.d/51_openvmm_snp
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
sudo grub2-script-check /boot/grub2/grub.cfg
```

Inspect the resulting `OpenVMM SNP` entry. It must select the exact kernel and
initramfs above and contain `MSHV_FORCE_NESTED=TRUE`, `MSHV_SEV_SNP=TRUE`,
and the intended package-managed EFI paths. The wrapper reuses the package's
kernel discovery; if it selects another kernel, stop and fix selection.
Do not overwrite a recovery default to force a successful-looking build.

For an approved one-shot boot:

```bash
sudo grub2-reboot "OpenVMM SNP"
sudo systemctl reboot
```

After reconnecting, require:

```bash
test "$(uname -r)" = 6.18.34.mshv3-2.azl3
sudo dmesg | grep 'Hypervisor Build 10.0.26100.9606-9-0'
sudo dmesg | grep 'Hyper-V: running as root partition'
sudo dmesg | grep 'SEV-SNP support status: available'
sudo cat /sys/kernel/security/lockdown
sudo modprobe erofs
sudo modprobe dm_verity
test -c /dev/mshv
sudo dmsetup targets
```

A successful boot is not an attestation or workload-policy test.

## 4. Containerd and RuntimeClasses

The validated baseline used containerd **2.3.3** (source commit
`aad11006b869517fcd3009450b6f82da282e1a9b`) and erofs-utils **1.8.5**.
Obtain/build equivalent approved packages through your normal tooling.
These are not supplied by the four kernel/OpenVMM/MSHV buddy runs.
Verify runtime shared-library dependencies; do not assume the marketplace
containerd has the required plugins.

Before using the supplied fragment, inspect `containerd config default`:
the EROFS differ must expose `enable_dmverity`, `enable_tar_index` and
`mkfs_options`; the CRI images plugin must expose `use_local_image_pull`.
`default_size="0"` must select unmerged directory-backed layers, not fsmerge.
`mkfs.erofs --help` must support `--tar`, `--mkfs-time` and `--sort`.
The optional snapshotter `dmverity_mode` knob is deliberately not required.

Install the fragment:

```bash
sudo install -d /etc/containerd/conf.d
sudo install -m644 "$ARTIFACTS/containerd-bringup.toml" \
  /etc/containerd/conf.d/openvmm-bringup.toml
```

Merge that file into the **top-level** `imports` of the active containerd
configuration without discarding existing imports, CNI settings or CRI config:

```toml
imports = ["/etc/containerd/conf.d/openvmm-bringup.toml"]
```

Inspect the effective configuration with `containerd config dump` before an
approved containerd restart. This fragment changes the node-wide differ/image
path; it is for a dedicated test node, not a mixed production node.
Verify CRI health and `kubectl get nodes` after restart.

```bash
kubectl apply -f "$ARTIFACTS/runtimeclass.yaml"
```

Use `runtimeClassName: kata-openvmm`. The 600-MiB host memory overhead is
required: without it, a pod limit equal to guest RAM can OOM-kill OpenVMM.
It does not add to the guest's requested RAM. For debug testing create a
separate RuntimeClass named `kata-openvmm-debug` with handler
`kata-openvmm-debug` and the same `overhead.podFixed.memory: 600Mi`.
Do not enable the debug handler for normal policy enforcement tests.

## 5. Policy integration and pod tests

Rebase your policy changes on this branch; **do not enable allow-all policy
to manufacture a pass**. Generate the intended initdata/policy using your
policy tooling and attach it through:

```text
io.katacontainers.config.hypervisor.cc_init_data
```

The existing encoding is base64 of gzip-compressed UTF-8 TOML. The TOML
contains `version = "0.1.0"`, `algorithm = "sha256"` and a `[data]` table
whose `"policy.rego"` value is the policy text. Use a TOML serializer or
proper string escaping, not hand-concatenated Rego. The runtime hashes the
decoded initdata payload for SNP HOST_DATA and cold-plugs it before launch.

The host-pull EROFS/dm-linear path must be represented in policy for both
pause and workload containers. Check storage/mount/device fields against
actual agent requests. Bind approved image/layer root hashes and test policy
rejection; a check that merely requires a dm-verity option is not image
authorization. Do not inherit an old strict-policy/manifold mode merely
because a historical branch used that name.

Start with a pinned, policy-approved image and pod settings like:

```yaml
spec:
  runtimeClassName: kata-openvmm
  restartPolicy: Never
  containers:
    - name: workload
      image: <policy-approved-image@sha256:digest>
      command: ["sleep", "600"]
      resources:
        requests:
          cpu: 100m
          memory: 128Mi
        limits:
          cpu: "8"
          memory: 2Gi
```

Supply the generated initdata annotation in metadata; this is a resource
example, not a complete policy-ready manifest. Small requests with larger
limits allow testing a 32-vCPU guest on a 32-CPU single-control-plane node.
These are Burstable tests, not Guaranteed-QoS tests.

Recommended sizing matrix (CPU / MiB):

```text
1/512  1/1024  2/1024  3/1536  4/2048  4/5120
8/2048  8/8192  16/4096  32/8192  8/32768  32/32768
```

Keep one IGVM, configuration and shim throughout the matrix. Verify:

- Actual CPU count and guest RAM match limits; no-limit pods use 1 CPU/1 GiB.
- Work pinned to each CPU and both syscall/fast CPU-ID lookup agree.
- Large guests write/read a meaningful amount of RAM (24 GiB at 32 GiB).
- Exec, DNS/network access and expected policy enforcement work.
- Workload layers are read-only dm-verity devices with expected root hashes.
- Report nonce, HOST_DATA and generated launch measurement match.
- Production exposes no debug shell; the debug profile does, while SNP
  hardware-debug policy remains disabled in both.
- Teardown releases pods, VMM processes, guest MSHV partitions, page pins,
  loop devices and per-container DM mappings.

Compare `/proc/vmstat` `nr_foll_pin_acquired`/`nr_foll_pin_released` deltas,
MSHV debugfs partition listings, `losetup -a` and `dmsetup ls` before/after.
Run tests sequentially on an idle node so another workload cannot invalidate
cleanup observations. Preserve dmesg, containerd logs, pod events, VMM logs,
guest tables and reports for failures; do not suppress failed policy checks.

Report-field comparison is not report signature/certificate-chain validation.
The bootshim validates host resource inputs but does not attest CPU/RAM counts.
Do not claim production policy parity, endorsement or Secure Boot support
from a successful VM launch.

## Handoff back

Record the exact integration commit, your policy commits, resolved package
identities/build IDs, rootfs/IGVM hashes and measurements, active host/Hyper-V
versions, positive and negative policy results, sizing results and final
cleanup/boot-default state. Coordinate any needed boot ABI change rather than
silently modifying the producer while the boot review continues.
