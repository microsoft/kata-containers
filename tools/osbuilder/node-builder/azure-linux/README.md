# Overview

This guide serves as a reference on how to build and install the underlying software stack for *Pod Sandboxing with AKS* and for *Confidential Containers on AKS* using Azure Linux.
This enables running Kata (Confidential) Containers via the OCI interface, or via a local kubelet, or leveraging AKS' Kubernetes solution.

In the following, the terms *Kata* and *Kata-CC* refer to *Pod Sandboxing with AKS* and *Confidential Containers on AKS*, respectively.
The term *building* refers to build the components from source, whereas the term *installing* refers to utilizing components released by the Azure Linux team for straightforward evaluation.

The guide provides the steps for two different environments:
- Azure Linux 3 based systems, such as Azure VMs
  - Variant I: Utilize released components
  - Variant II: Build components from source
- AKS nodes based on Azure Linux 3

# Steps for Azure Linux 3 based environments

## Set up AzL3 environment

While build can happen in any Azure Linux 3 based environment, the stack can only be evaluated on environments with proper virtualization support and, for Kata-CC, on top of AMD SEV-SNP. An example of such environment are Azure Linux 3 based Azure VMs using a proper SKU:
- Deploy an Azure Linux 3 VM via `az vm create` using a [CC vm size SKU](https://learn.microsoft.com/en-us/azure/virtual-machines/dcasccv5-dcadsccv5-series)
  - Example: `az vm create --resource-group <rg_name> --name <vm_name> --os-disk-size-gb <e.g. 60> --public-ip-sku Standard --size <e.g. Standard_DC4as_cc_v5> --admin-username azureuser --ssh-key-values <ssh_pubkey> --image <MicrosoftCBLMariner:azure-linux-3:azure-linux-3-gen2:latest>`
- SSH onto the VM

Not validated for evaluation: Install [Azure Linux 3](https://github.com/microsoft/azurelinux) on a bare metal machine supporting AMD SEV-SNP.

To merely build the stack, we refer to the official [Azure Linux GitHub page](https://github.com/microsoft/azurelinux) to set up an Azure Linux 3 environment.

## Deploy required host packages (incl. VMM, SEV-SNP capable kernel and Microsoft Hypervisor) and extend containerd configuration

Install relevant packages, append a configuration snippet to `/etc/containerd/config.toml` to register the Kata(-CC) handlers, then reboot the system:
```
sudo dnf -y makecache
sudo dnf -y install kata-packages-host

sudo tee -a /etc/containerd/config.toml 2&>1 <<EOF

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  privileged_without_host_devices = true
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata.options]
    ConfigPath = "/usr/share/defaults/kata-containers/configuration.toml"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-cc]
  runtime_type = "io.containerd.kata-cc.v2"
  privileged_without_host_devices = true
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-cc.options]
    ConfigPath = "/opt/confidential-containers/share/defaults/kata-containers/runtime-rs/configuration.toml"
EOF

sudo reboot
```

The single-layer EROFS flow additionally requires an EROFS-enabled host
kernel, validated with `kernel-mshv-6.6.137.mshv2-2.azl3`.

```bash
sudo dnf install -y erofs-utils
sudo modprobe erofs
```

## Variant I: Utilize released components to assemble the UVM

While the priorly installed `kata-packages-host` package delivers all host-side components, the tools required to assemble the UVM components are delivered through the `kata-packages-uvm-build` package.
Using this package, it is straightforward to assemble the UVM and then to run pods.

For Kata:
```
sudo dnf -y install kata-packages-uvm-build
pushd /opt/kata-containers/uvm/tools/osbuilder/node-builder/azure-linux
sudo make uvm
sudo make deploy-uvm
popd
```

The runtime-rs Cloud Hypervisor SEV-SNP development flow is currently
source-build only. Follow Variant II for Kata-CC.

You environment is ready. Continue with section *Run Kata (Confidential) Containers*

## Variant II: Build components from source

### Install AzL3 build dependencies

```
sudo dnf -y install git golang rust cargo build-essential protobuf-compiler protobuf-devel expect openssl-devel clang-devel libseccomp-devel btrfs-progs-devel device-mapper-devel cmake fuse-devel kata-packages-uvm-build curl cpio
```

Continue with the section *Build the Kata(-CC) host and guest components from source and install*.

# Steps for AKS nodes

## Set up AKS environment

- Deploy a [Confidential Containers for AKS cluster](https://learn.microsoft.com/en-us/azure/aks/deploy-confidential-containers-default-policy) via `az aks create` (using `AzureLinux` as `os-sku`). Note, this way the bits built in this guide will already be present on the cluster's Azure Linux based nodes.
- Deploy a debugging pod onto one of the nodes
- From the debugging pod, SSH onto the node you intend to use to build on.

As released components are already pre-installed onto AKS nodes, the remainder of this section focuses on how to (re-)build the components from source.

## Install AKS build dependencies

```
sudo dnf -y makecache
sudo dnf -y install git golang rust cargo build-essential protobuf-compiler protobuf-devel expect openssl-devel clang-devel libseccomp-devel btrfs-progs-devel device-mapper-devel cmake fuse-devel kata-packages-uvm-build parted qemu-img kernel-uvm-devel curl jq # curl and jq are only required for installing the IGVM tool
```

From here on, continue with the following section to build.

# Build the Kata(-CC) host and guest components from source and install

Clone the Microsoft's fork of the kata-containers repository:

```git clone https://github.com/microsoft/kata-containers.git```

Note: use the compatible Rust version listed in `versions.yaml`; Azure Linux 3's packaged Rust may be older.

## Install IGVM tooling for ConfPods

When intending to build the components for Confidential Containers, install the IGVM tool that will be used by the build tooling to create IGVM files with their reference measurements for the ConfPods UVM.

```
pushd kata-containers/tools/osbuilder/igvm-builder
sudo ./igvm_builder.sh -i
popd
```

This command installs the latest release of the [IGVM tooling](https://github.com/microsoft/igvm-tooling/) using `pip3 install`. The repository applies
`igvm-tooling-cpuid.patch` during installation to omit CPUID entries that are
not portable across MSHV-backed SNP hosts. The tool can be uninstalled at any
time by calling the script using the `-u` parameter instead.

## Prepare SEV-SNP build inputs

The ConfPods Make targets consume, but do not build or install, Cloud
Hypervisor and the guest kernel. The current development stack uses the
upstream Cloud Hypervisor main branch after flat VMDK support was merged, with
the MSHV compatibility patch from this repository:

```bash
git clone https://github.com/cloud-hypervisor/cloud-hypervisor.git
pushd cloud-hypervisor
git checkout aa9678da67f6336c4a41add9095c9c917b800ea9
git apply ../kata-containers/cloud-hypervisor-mshv-vmdk-compat.patch
OPENSSL_NO_VENDOR=1 cargo build \
	--release \
	--no-default-features \
	--features mshv,sev_snp
popd
```

The compatibility patch fully reverts Cloud Hypervisor commit `4091e965`
(`vmm: return all-ones for unregistered MMIO reads`). The Kata-CC SNP
configuration explicitly caps the guest physical address width at 43 bits so
the runtime and the static IGVM ACPI platform addresses use the same layout.

For the single-layer EROFS flow, install containerd 2.3.3:

```bash
CONTAINERD_VERSION=2.3.3
curl -fsSLO \
	"https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz"
curl -fsSLO \
	"https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VERSION}/containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz.sha256sum"
sha256sum --check "containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz.sha256sum"

sudo systemctl stop containerd
sudo tar --directory /usr --extract --gzip \
	--file "containerd-${CONTAINERD_VERSION}-linux-amd64.tar.gz"
sudo systemctl start containerd

containerd --version
```

The Azure Linux `kernel-uvm` 6.6.137.mshv1 bzImage currently triple-faults
during IGVM boot. Build the known-good `kernel-uvm-6.1.58.mshv8` kernel with
EROFS enabled:

```bash
sudo dnf install -y \
	bc bison flex dwarves ncurses-devel elfutils-libelf-devel

mkdir -p kernel-uvm-6.1.58/{srpm,source,build}
pushd kernel-uvm-6.1.58

curl -fsSLO \
	https://packages.microsoft.com/azurelinux/3.0/prod/base/srpms/Packages/k/kernel-uvm-6.1.58.mshv8-1.azl3.src.rpm

rpm2cpio kernel-uvm-6.1.58.mshv8-1.azl3.src.rpm |
	(cd srpm && cpio -idm)

tar --extract \
	--file srpm/kernel-uvm-6.1.58.mshv8.tar.gz \
	--directory source \
	--strip-components=1

cp srpm/config build/.config
source/scripts/config --file build/.config --enable EROFS_FS

make --directory source O="${PWD}/build" olddefconfig
make --directory source O="${PWD}/build" --jobs "$(nproc)" bzImage

IGVM_KERNEL="${PWD}/build/arch/x86/boot/bzImage"
popd
```

Use the resulting `IGVM_KERNEL` path in the standard ConfPods build.

## Build and deploy

To build and install Kata components, run:
```
pushd kata-containers/tools/osbuilder/node-builder/azure-linux
make all
sudo make deploy
popd
```

To build and install Kata-CC components, use the `all-confpods` and
`deploy-confpods` targets. The ConfPods flow builds and installs runtime-rs as
the default Kata-CC shim:
```
pushd kata-containers/tools/osbuilder/node-builder/azure-linux
CLH_SNP_BIN=/path/to/cloud-hypervisor/target/release/cloud-hypervisor
IGVM_KERNEL=/path/to/kernel-uvm-6.1.58/build/arch/x86/boot/bzImage
make \
	AGENT_POLICY_FILE=allow-all.rego \
	CLH_SNP_PATH="${CLH_SNP_BIN}" \
	IGVM_KERNEL="${IGVM_KERNEL}" \
	all-confpods
sudo make \
	CLH_SNP_PATH="${CLH_SNP_BIN}" \
	deploy-confpods
popd
```

`allow-all.rego` is only for this direct development flow. Do not use it for
production confidential workloads.

The `all[-confpods]` target runs the targets `package[-confpods]` and `uvm[-confpods]` in a single step (the `uvm[-confpods]` target depends on the `package[-confpods]` target). The `deploy[-confpods]` target moves the build artifacts to proper places (and calls into `deploy[-confpods]-package`, `deploy[-confpods]-uvm`).

Notes:
  - To retrieve more detailed build output, prefix the make commands with `DEBUG=1`.
  - To build an IGVM file for CondPods with a non-default SVN of 0, prefix the `make uvm-confpods` command with `IGVM_SVN=<number>`
  - `IGVM_KERNEL=<path>` overrides `/usr/share/cloud-hypervisor/bzImage`.
  - `CLH_SNP_PATH=<path>` selects the prebuilt SNP-enabled Cloud Hypervisor binary referenced by the generated runtime-rs configuration.
  - The legacy tardev/tarfs stack is disabled because its source is absent. Use `BUILD_TARFS=yes` on branches that include it.
  - For build and deployment of both Kata and Kata-CC artifacts, first run the `make all` and `make deploy` commands to build and install the Kata Containers for AKS components followed by `make clean`, and then run `make all-confpods` and `make deploy-confpods` to build and install the Confidential Containers for AKS components - or vice versa (using `make clean-confpods`).

## Debug builds

This section describes how to build and deploy in debug mode.

`make all-confpods` takes the following variables:

 * `AGENT_BUILD_TYPE`: Specify `release` (default) to build the agent in
   release mode, or `debug` to build it in debug mode.
 * `AGENT_POLICY_FILE`: Specify `allow-set-policy.rego` (default) to use
   a restrictive policy, or `allow-all.rego` to use a permissive policy.

`make deploy-confpods` takes the following variable:

 * `SHIM_USE_DEBUG_CONFIG`: Specify `no` (default) to use the production
   configuration, or `yes` to use the debug configuration (all debug
   logging enabled). In this case you'll want to enable debug logging
   in containerd as well. Note that this variable has no effect if
   `SHIM_REDEPLOY_CONFIG=no`.

In general, you can specify the debug configuration for all the above
variables by using `BUILD_TYPE=debug` as such:

```shell
sudo make BUILD_TYPE=debug all-confpods deploy-confpods
```

Also note that make still lets you override the other variables even
after setting `BUILD_TYPE`. For example, you can use the production shim
config with `BUILD_TYPE=debug`:

```shell
sudo make BUILD_TYPE=debug SHIM_USE_DEBUG_CONFIG=no all-confpods deploy-confpods
```

### Prevent redeploying the shim configuration

If you're manually modifying the shim configuration directly on the host
during development and you don't want to redeploy and overwrite that
file each time you redeploy binaries, you can separately specify the
`SHIM_REDEPLOY_CONFIG` (default `yes`):

```shell
sudo make SHIM_REDEPLOY_CONFIG=no all-confpods deploy-confpods
```

Note that this variable is independent from the other variables
mentioned above. So if you want to avoid redeploying the shim
configuration AND build in debug mode, you have to use the following
command:

```shell
sudo make BUILD_TYPE=debug SHIM_REDEPLOY_CONFIG=no all-confpods deploy-confpods
```

# Run Kata (Confidential) Containers

## Run via the containerd API

Use `ctr` to run a confidential container with the Kata-CC runtime:

```bash
id="hello-$(date +%s)"
sudo ctr -n k8s.io run \
  --runtime io.containerd.kata-cc.v2 \
  --runtime-config-path /opt/confidential-containers/share/defaults/kata-containers/runtime-rs/configuration.toml \
  docker.io/library/busybox:latest "${id}" uname -a
```

With `shared_fs = "none"`, use containerd's EROFS snapshotter to pass a single
layer as a raw block device or multiple layers as one GPT-backed VMDK block
device:

```toml
[plugins."io.containerd.snapshotter.v1.erofs"]
  default_size = "0"

[plugins."io.containerd.service.v1.diff-service"]
  default = ["erofs", "walking"]
```

Restart containerd and verify the plugins:

```bash
sudo modprobe erofs
sudo systemctl restart containerd
sudo ctr plugins ls | grep erofs
```

Run a multi-layer image and verify both the workload and its overlay mount:

```bash
NS=erofs-repro
IMAGE=docker.io/library/nginx:alpine
ID="nginx-vmdk-$(date +%s)"

sudo ctr -n "${NS}" images pull \
  --snapshotter erofs \
  --platform linux/amd64 \
  "${IMAGE}"

sudo ctr -n "${NS}" run -d \
  --snapshotter erofs \
  --runtime io.containerd.kata-cc.v2 \
  --runtime-config-path \
  /opt/confidential-containers/share/defaults/kata-containers/runtime-rs/configuration.toml \
  "${IMAGE}" "${ID}"

sudo ctr -n "${NS}" tasks exec \
  --exec-id check \
  "${ID}" sh -c '
    wget -qO- http://127.0.0.1/
    mount | grep "overlay on / "
  '

sudo ctr -n "${NS}" tasks kill "${ID}"
sudo ctr -n "${NS}" tasks rm "${ID}"
sudo ctr -n "${NS}" containers rm "${ID}"
```

`nginx:alpine` currently has eight `linux/amd64` OCI layers. runtime-rs combines
them into a GPT-backed VMDK block device; the overlay mount should show
`lower-0` through `lower-7`. Container-layer verity is not yet enabled.

For further usage, refer to the upstream `ctr` documentation.

## Run via Kubernetes

On each target node, configure the existing `kata-cc` handler to use EROFS and
the deployed runtime-rs configuration:

```bash
sudo sed -i \
  '/runtimes.kata-cc/,/runtimes.kata-cc.options/ s/snapshotter = "tardev"/snapshotter = "erofs"/' \
  /etc/containerd/config.toml
sudo sed -i \
  's|ConfigPath = "/opt/confidential-containers/share/defaults/kata-containers/configuration-clh-snp.toml"|ConfigPath = "/opt/confidential-containers/share/defaults/kata-containers/runtime-rs/configuration.toml"|' \
  /etc/containerd/config.toml
sudo containerd config dump >/dev/null
sudo systemctl restart containerd
```

Then register a RuntimeClass from the machine that holds the cluster kubeconfig:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-cc-erofs
handler: kata-cc
overhead:
  podFixed:
    memory: 600Mi
scheduling:
  nodeSelector:
    kubernetes.azure.com/kata-vm-isolation: "true"
```

Run a multi-layer workload without explicit CPU or memory limits. This validated
configuration uses the static workload defaults from the runtime configuration:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kata-cc-erofs-nginx
spec:
  runtimeClassName: kata-cc-erofs
  containers:
    - name: nginx
      image: docker.io/library/nginx:alpine
```

Wait for the pod and verify the workload and eight-layer overlay:

```bash
kubectl wait \
  --for=condition=Ready \
  pod/kata-cc-erofs-nginx \
  --timeout=180s

kubectl exec kata-cc-erofs-nginx -- sh -c '
  wget -qO- http://127.0.0.1/ | grep -o "Welcome.to.nginx"
  cat /proc/mounts | grep "^overlay"
'
```

# Build attestation scenarios
The build artifacts for the UVM ConfPods target include an IGVM file and a so-called reference measurement file (unsigned). The IGVM file is being loaded into memory measured by the AMD SEV-SNP PSP (when a Confidential Container is started). With this and with the Kata security policy feature, attestation scenarios can be built: the reference measurement (often referred to as 'endorsement') can, for example, be signed by a trusted party (such as Microsoft in Confidential Containers on AKS) and be compared with the actual measurement part of the attestation report. The latter can be retrieved through respective system calls inside the Kata Confidential Containers Guest VM.

An example for an attestation scenario through Microsoft Azure Attestation is presented in [Attestation in Confidential containers on Azure Container Instances](https://learn.microsoft.com/en-us/azure/container-instances/confidential-containers-attestation-concepts).
Documentation for leveraging the Kata security policy feature can be found in [Security policy for Confidential Containers on Azure Kubernetes Service](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers-aks-security-policy).
