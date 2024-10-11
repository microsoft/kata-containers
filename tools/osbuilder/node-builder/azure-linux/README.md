# Overview

This guide enables to build and evaluate the underlying software stack for *Kata VM Isolated Containers on AKS* and for *Confidential Containers on AKS* using Azure Linux.
The underlying software stack referred to in this guide will stretch from containerd to lower layers, for instance, enabling to deploy Kata (Confidential) Containers via the OCI interface, or deploying a local kubelet, or leveraging AKS' Kubernetes solution.

In the following, the terms *Kata* and *Kata-CC* refer to *Kata VM Isolated Containers on AKS* and *Confidential Containers on AKS*, respectively. Note that, *Kata VM Isolated Containers on AKS* is also referred to as *Pod Sandboxing with AKS* in the public.

# Pre-requirements

While build can happen in any Azure Linux based environment, the stack can only be evaluated in Azure Linux environments on top of AMD SEV-SNP - the details here are omitted:
- Deploy an Azure Linux VM via `az vm create` using a [CC vm size SKU](https://learn.microsoft.com/en-us/azure/virtual-machines/dcasccv5-dcadsccv5-series)
  - Example: `az vm create --resource-group <rg_name> --name <vm_name> --os-disk-size-gb <e.g. 60> --public-ip-sku Standard --size <e.g. Standard_DC4as_cc_v5> --admin-username azureuser --ssh-key-values <ssh_pubkey> --image <MicrosoftCBLMariner:cbl-mariner:...> --security-type Standard`
- Deploy a [Confidential Containers for AKS cluster](https://learn.microsoft.com/en-us/azure/aks/deploy-confidential-containers-default-policy) via `az aks create`. Note, this way the bits built in this guide will already be present on the cluster's Azure Linux based nodes.
  - Deploy a debugging pod onto one of the nodes, SSH onto the node.
- Not validated for evaluation: Install [Azure Linux](https://github.com/microsoft/azurelinux) on a bare metal machine supporting AMD SEV-SNP.

To only build the stack, we refer to the official [Azure Linux GitHub page](https://github.com/microsoft/azurelinux) to set up Azure Linux.

The following steps assume the user has direct console access on the environnment that was set up.

# Deploy required virtualization packages (e.g., VMM, SEV-SNP capable kernel and Microsoft Hypervisor)

Note: This step can be skipped if your environment was set up through `az aks create`

Install relevant packages and modify the grub configuration to boot into the SEV-SNP capable kernel `kernel-mshv` upon next reboot:
```
sudo dnf -y makecache
sudo dnf -y install kata-packages-host

boot_uuid=$(sudo grep -o -m 1 '[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}' /boot/efi/boot/grub2/grub.cfg)

sudo sed -i -e 's@load_env -f \$bootprefix\/mariner.cfg@load_env -f \$bootprefix\/mariner-mshv.cfg\nload_env -f $bootprefix\/mariner.cfg\n@'  /boot/grub2/grub.cfg

sudo sed -i -e 's@menuentry "CBL-Mariner"@menuentry "Dom0" {\n    search --no-floppy --set=root --file /HvLoader.efi\n    chainloader /HvLoader.efi lxhvloader.dll MSHV_ROOT=\\\\Windows MSHV_ENABLE=TRUE MSHV_SCHEDULER_TYPE=ROOT MSHV_X2APIC_POLICY=ENABLE MSHV_SEV_SNP=TRUE MSHV_LOAD_OPTION=INCLUDETRACEMETADATA=1\n    boot\n    search --no-floppy --fs-uuid '"$boot_uuid"' --set=root\n    linux $bootprefix/$mariner_linux_mshv $mariner_cmdline_mshv $systemd_cmdline root=$rootdevice\n    if [ -f $bootprefix/$mariner_initrd_mshv ]; then\n    initrd $bootprefix/$mariner_initrd_mshv\n    fi\n}\n\nmenuentry "CBL-Mariner"@'  /boot/grub2/grub.cfg
```

Reboot the system:
```sudo reboot```

Note: We currently use a [forked version](https://github.com/microsoft/confidential-containers-containerd/tree/tardev-v1.7.7) of `containerd` called `containerd-cc` which is installed as part of the `kata-packages-host` package. This containerd version is based on stock containerd with patches to support the Confidential Containers on AKS use case and conflicts with the `containerd` package.

# Add Kata(-CC) handler configuration snippets to containerd configuration

Note: This step can be skipped if your environment was set up through `az aks create`.

Append the following containerd configuration snippet to `/etc/containerd/config.toml` to register the Kata(-CC) handlers, for example, using this command:

```
sudo tee -a /etc/containerd/config.toml 2&>1 <<EOF

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
  runtime_type = "io.containerd.kata.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata.options]
    ConfigPath = "/usr/share/defaults/kata-containers/configuration.toml"
[proxy_plugins]
  [proxy_plugins.tardev]
    type = "snapshot"
    address = "/run/containerd/tardev-snapshotter.sock"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-cc]
  snapshotter = "tardev"
  runtime_type = "io.containerd.kata-cc.v2"
  privileged_without_host_devices = true
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-cc.options]
    ConfigPath = "/opt/confidential-containers/share/defaults/kata-containers/configuration-clh-snp.toml"
EOF
```

Restart containerd (ensuring the configuration file is intact):

```sudo systemctl restart containerd```

# Install general build dependencies

```
sudo dnf -y makecache
sudo dnf -y install git vim golang rust cargo build-essential protobuf-compiler protobuf-devel expect openssl-devel clang-devel libseccomp-devel parted qemu-img btrfs-progs-devel device-mapper-devel cmake fuse-devel jq curl kata-packages-uvm-build kernel-uvm-devel
```

**Note:** The kernel-uvm-devel package in step above is only required for Confidential Containers and can be omitted for regular Kata Containers builds.

# Optional: Build and deploy the containerd fork from scratch

```
git clone --depth 1 --branch tardev-v1.7.7 https://github.com/microsoft/confidential-containers-containerd.git
pushd confidential-containers-containerd/
GODEBUG=1 make
popd
```

Overwrite existing containerd binary, restart service:
```
sudo cp -a --backup=numbered confidential-containers-containerd/bin/containerd /usr/bin/containerd
sudo systemctl restart containerd
```

# Build and install the Kata(-CC) host and guest components

Clone the Microsoft's fork of the kata-containers repository:

```git clone https://github.com/microsoft/kata-containers.git```

## Install IGVM tooling for ConfPods

When intending to build the components for Confidential Containers, install the IGVM tool that will be used by the build tooling to create IGVM files with their reference measurements for the ConfPods UVM.

```
pushd kata-containers/tools/osbuilder/igvm-builder
sudo ./igvm_builder.sh -i
popd
```

This command installs the latest release of the [IGVM tooling](https://github.com/microsoft/igvm-tooling/) using `pip3 install`. The tool can be uninstalled at any time by calling the script using the -u parameter instead.

## Build and deploy

To build and install Kata Containers for AKS components, run:
```
pushd kata-containers/tools/osbuilder/node-builder/azure-linux
make all
sudo make deploy
popd
```

To build and install Confidential Containers for AKS, use the `all-confpods` and `deploy-confpods` targets:
```
pushd kata-containers/tools/osbuilder/node-builder/azure-linux
make all-confpods
sudo make deploy-confpods
popd
```

The `all[-confpods]` target runs the targets `package[-confpods]` and `uvm[-confpods]` in a single step (the `uvm[-confpods]` target depends on the `package[-confpods]` target). The `deploy[-confpods]` target moves the build artifacts to proper places (and calls into `deploy[-confpods]-package`, `deploy[-confpods]-uvm`).

Notes:
  - To retrieve more detailed build output, prefix the make commands with `DEBUG=1`.
  - To build for Azure Linux 3, prefix the make commands that build artifacts with `OS_VERSION=3.0`
  - To build an IGVM file for CondPods with a non-default SVN of 0, prefix the `make uvm-confpods` command with `IGVM_SVN=<number>`
  - For build and deployment of both Kata and Kata-CC artifacts, first run the `make all` and `make deploy` commands to build and install the Kata Containers for AKS components followed by `make clean`, and then run `make all-confpods` and `make deploy-confpods` to build and install the Confidential Containers for AKS components - or vice versa (using `make clean-confpods`).

## Debug build

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
   in containerd as well.

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

## Run via CRI or via containerd API

Use e.g. `crictl` (or `ctr`) to schedule Kata (Confidential) containers, referencing either the Kata or Kata-CC handlers.

Note: On Kubernetes nodes, pods created via `crictl` will be deleted by the control plane.

The following instructions serve as a general reference:
- Install `crictl`, set runtime endpoint in `crictl` configuration:

  ```
  sudo dnf -y install cri-tools
  sudo crictl config --set runtime-endpoint=unix:///run/containerd/containerd.sock
  ```

- Install CNI binaries:

  ```
  sudo dnf -y install cni
  ```

- Set a proper CNI configuration and create a sample pod manifest: This step is omitted as it depends on the individual needs.

- Run pods with `crictl`, for example:

  `sudo crictl runp -T 30s -r <handler-name> <sample-pod.yaml>`

- Run containers with `ctr`, for example a confidential container:

  `sudo ctr -n=k8s.io image pull --snapshotter=tardev docker.io/library/busybox:latest`

  `sudo ctr -n=k8s.io run --cni --runtime io.containerd.run.kata-cc.v2 --runtime-config-path /opt/confidential-containers/share/defaults/kata-containers/configuration-clh-snp.toml --snapshotter tardev -t --rm docker.io/library/busybox:latest hello sh`

For further usage we refer to the upstream `crictl` (or `ctr`) and CNI documentation.

## Run via Kubernetes

If your environment was set up through `az aks create` the respective node is ready to run Kata (Confidential) Containers as AKS Kubernetes pods.
Other types of Kubernetes clusters should work as well - but this document doesn't cover how to set-up those clusters.

Next, apply the kata and kata-cc runtime classes on the machine that holds your kubeconfig file, for example:
```
cat << EOF > runtimeClass-kata-cc.yaml
kind: RuntimeClass
apiVersion: node.k8s.io/v1
metadata:
    name: kata-cc
handler: kata-cc
overhead:
    podFixed:
        memory: "2Gi"
scheduling:
  nodeSelector:
    katacontainers.io/kata-runtime: "true"
EOF

cat << EOF > runtimeClass-kata.yaml
kind: RuntimeClass
apiVersion: node.k8s.io/v1
metadata:
    name: kata
handler: kata
overhead:
    podFixed:
        memory: "2Gi"
scheduling:
  nodeSelector:
    katacontainers.io/kata-runtime: "true"
EOF

kubectl apply -f runtimeClass-kata-cc.yaml -f runtimeClass-kata.yaml
```

And label your node appropriately:
```
kubectl label node <nodename> katacontainers.io/kata-runtime=true
```

# Build attestation scenarios
The build artifacts for the UVM ConfPods target include an IGVM file and a so-called reference measurement file (unsigned). The IGVM file is being loaded into memory measured by the AMD SEV-SNP PSP (when a Confidental Container is started). With this and with the Kata security policy feature, attestation scenarios can be built: the reference measurement (often referred to as 'endorsement') can, for example, be signed by a trusted party (such as Microsoft in Confidential Containers on AKS) and be compared with the actual measurement part of the attestation report. The latter can be retrieved through respective system calls inside the Kata Confidential Containers Guest VM.

An example for an attestation scenario through Microsoft Azure Attestation is presented in [Attestation in Confidential containers on Azure Container Instances](https://learn.microsoft.com/en-us/azure/container-instances/confidential-containers-attestation-concepts).
Documentation for leveraging the Kata security policy feature can be found in [Security policy for Confidential Containers on Azure Kubernetes Service](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers-aks-security-policy).
