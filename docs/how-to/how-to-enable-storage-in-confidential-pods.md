# How to enable storage in AKS confidential pods

> [!WARNING]  
> **Confidentiality is NOT supported in this initial release.** This
> release is focused on first enabling persistence.

Currently, enabling storage in AKS confidential containers requires
manually installing Kubernetes CSI drivers into your clusters. We have
implemented three such drivers:

 * CoCo Azure Disk: Implements Azure Disk support.
 * CoCo Azure Files: Implements Azure Files support.
 * CoCo Azure Local: Implement ephemeral, node-local storage, equivalent
   to the native Kubernetes emptyDir.

This document describes how to install and test each driver in an AKS
cluster.

## Prerequisites for all drivers

These steps need to be performed before installing any driver. After
completing this section, you will have a 1-node cluster ready to install
the drivers and schedule test workloads.

### 1. Configure your environment

First, you'll need to configure your machine to install the required
Azure CLI extensions and enable the confidential containers feature in
your Azure subscription. Please follow the below links to do so: 

 1. [Install the AKS preview Azure CLI extension](https://learn.microsoft.com/en-us/azure/aks/deploy-confidential-containers-default-policy#install-the-aks-preview-azure-cli-extension)
 1. [Install the confcom Azure CLI extension](https://learn.microsoft.com/en-us/azure/aks/deploy-confidential-containers-default-policy#install-the-confcom-azure-cli-extension)
 1. [Register the KataCcIsolationPreview feature flag](https://learn.microsoft.com/en-us/azure/aks/deploy-confidential-containers-default-policy#register-the-kataccisolationpreview-feature-flag)

### 2. Create the cluster

Now you can create the cluster:

```shell
$ cluster="YOUR_AKS_CLUSTER_NAME"
$ rg="YOUR_AKS_CLUSTER_RESOURCE_GROUP_NAME"
$ az aks create \
    --resource-group "$rg" \
    --name "$cluster" \
    --os-sku AzureLinux \
    --node-vm-size Standard_DC4as_cc_v5 \
    --node-count 1 \
    --enable-oidc-issuer \
    --enable-workload-identity \
    --workload-runtime KataCcIsolation
```

When the cluster is ready, log into it:

```shell
$ az aks get-credentials --resource-group "$rg" --name "$cluster"
```

Now your machine should be ready, and listing the cluster nodes will get
you an output that looks like this:

```
$ kubectl get nodes
NAME                                STATUS   ROLES   AGE   VERSION
aks-nodepool1-38693887-vmss000000   Ready    agent   2m    v1.29.6
```

### 3. Grant the drivers permission to access your cluster

Run the following script to grant permission to the drivers to provision
Azure volumes in your node resource group. Note that the user logged
into the Azure CLI needs to have the permission to add such a role
assignment.

```shell
mc_rg="$(az aks show -g $rg -n $cluster --query nodeResourceGroup -o tsv)"
mc_rg_oid="$(az group show -g $mc_rg --query id -o tsv)"
umi_principal_id="$(az identity list --query "[?name == '$cluster-agentpool' && resourceGroup == '$mc_rg'].principalId" -o tsv)"
az role assignment create --role Contributor --assignee-principal-type ServicePrincipal --assignee-object-id "$umi_principal_id" --scope "$mc_rg_oid"
```

### 4. Enable running manual tests in the confidential containers

To make manual testing easier, run the following script to allow
executing any shell command in the guest VM. Note that this script is
idempotent so it is safe to rerun if it fails.

```shell
node="$(kubectl get nodes -o name)"
kata_version="$(kubectl debug "$node" -qi --image=alpine:latest -- chroot /host bash -c 'tdnf info --installed kata-containers-cc' | grep Version | awk '{print $3}')"
wget -O genpolicy-settings.json "https://raw.githubusercontent.com/microsoft/kata-containers/$kata_version/src/tools/genpolicy/genpolicy-settings.json"
sed -i 's/"regex": \[\]/"regex": \[".+"\]/g' genpolicy-settings.json
```

After running this script, `genpolicy-settings.json` should have its
field `request_defaults.ExecProcessRequest.regex` set to `[".+"]`.

## Installing the CoCo Azure Disk driver

Run the following command to deploy the driver in the cluster:

```shell
$ curl -sSf https://raw.githubusercontent.com/microsoft/kata-containers/cc-azuredisk-csi-driver/latest/cc-deploy/install.sh | bash
```

You can then verify that the driver containers are properly deployed and
in the `Running` state:

```shell
$ kubectl get pods -A | grep azuredisk-cc
kube-system   csi-azuredisk-cc-controller-fbf5fc87d-xm6wg             6/6     Running   0              32s
kube-system   csi-azuredisk-cc-node-b9bpf                             3/3     Running   0              32s
```

You can also verify that the storage classes are installed:

```shell
$ kubectl get storageclass cc-managed-csi cc-managed-csi-premium
cc-managed-csi cc.disk.csi.azure.com Delete WaitForFirstConsumer true 35s
cc-managed-csi-premium cc.disk.csi.azure.com Delete WaitForFirstConsumer true 35s
```

### Known limitations

 * Sharing volumes across pods on the same node is not supported.
 * Only tested with ext4 filesystems.
 * [`volumeMode:
   Block`](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#volume-mode)
   is not supported.
 * Specifying `securityContext.runAsUser` or `securityContext.fsGroup`
   in the pod spec is not supported.

### Quick testing

First, copy the below spec to your machine. You will generate its
security policy in the next step.

This spec will create two persistent volume claims (PVCs) of 10GB each,
one using the built-in `managed-csi` storage class, and the other using
our new `cc-managed-csi` storage class. It will also create a pod that
mounts the `managed-csi` PVC in `/mnt/persistent-broken` and the
`cc-managed-csi` PVC in `/mnt/persistent-ok`.

<details>
  <summary>demo-cc-azuredisk.yaml</summary>
  <br>

  ```yaml
  ---
  apiVersion: v1
  kind: PersistentVolumeClaim
  metadata:
    name: pvc-cc-managed-csi
  spec:
    accessModes:
      - ReadWriteOncePod
    resources:
      requests:
        storage: 10Gi
    storageClassName: cc-managed-csi
  ---
  apiVersion: v1
  kind: PersistentVolumeClaim
  metadata:
    name: pvc-managed-csi
  spec:
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: 10Gi
    storageClassName: managed-csi
  ---
  kind: Pod
  apiVersion: v1
  metadata:
    name: demo-cc-azuredisk
  spec:
    runtimeClassName: kata-cc-isolation
    containers:
      - image: busybox:latest
        name: busybox
        volumeMounts:
          - name: cc-managed-csi-vol
            mountPath: /mnt/persistent-ok
          - name: managed-csi-vol
            mountPath: /mnt/persistent-broken
    volumes:
      - name: cc-managed-csi-vol
        persistentVolumeClaim:
          claimName: pvc-cc-managed-csi
      - name: managed-csi-vol
        persistentVolumeClaim:
          claimName: pvc-managed-csi
  ```
</details>

Now you can generate the security policy for the spec (using the
`genpolicy-settings.json` file set up in the prerequisites section) and
deploy it:

```shell
$ az confcom katapolicygen -j genpolicy-settings.json -y demo-cc-azuredisk.yaml
$ kubectl apply -f demo-cc-azuredisk.yaml
```

Once the pod is deployed, you should be able to list the mounted
filesystems using the command below:

 * `/mnt/persistent-ok`, from our driver, correctly appears as an ext4
   filesystem with 10GB of capacity.
 * `/mnt/persistent-broken` shows that the built-in driver is not
   working properly and mounts a tmpfs in the guest root filesystem.

```shell
$ kubectl exec -it demo-cc-azuredisk -- df -hT | grep /mnt
/dev/vdc             ext4            9.7G      2.0M      9.7G   0% /mnt/persistent-ok
tmpfs                tmpfs         369.1M    236.0K    368.9M   0% /mnt/persistent-broken
```

Note: You may see the error `The request failed due to conflict with a
concurrent request` in the output of `kubectl describe pod
demo-cc-azuredisk`. This does not affect behavior and is expected when
using both the built-in and the new drivers simultaneously in the same
pod. Production workloads that only use our new driver will not
experience this error.

## Installing the CoCo Azure Files driver

> [!NOTE]  
> We are currently in the process of upstreaming this functionality to
> the built-in Azure Files driver, see
> [kubernetes-sigs/azurefile-csi-driver#1971](https://github.com/kubernetes-sigs/azurefile-csi-driver/pull/1971)
> to track status.

Run the following command to deploy the driver in the cluster:

```shell
$ curl -sSf https://raw.githubusercontent.com/microsoft/kata-containers/cc-azurefile-csi-driver/latest/deploy-cc/install.sh | bash
```

You can then verify that the driver containers are properly deployed and
in the `Running` state:

```shell
$ kubectl get pods -A | grep csi-azurefile-cc
kube-system      csi-azurefile-cc-controller-7f84c48459-clmq4            5/5     Running       0             22s
kube-system      csi-azurefile-cc-node-vgbb5                             3/3     Running       0             22s
```

You can also verify that the storage classes are installed:

```
$ kubectl get storageclass cc-azurefile-csi cc-azurefile-csi-premium
cc-azurefile-csi           cc.file.csi.azure.com   Delete          Immediate              true                   52s
cc-azurefile-csi-premium   cc.file.csi.azure.com   Delete          Immediate              true                   52s
```

### Known limitations

 * The NFS protocol is not supported.

### Important notes

 * The current implementation increases the size of the Trusted Compute
   Base (TCB) as it introduces an SMB client in the guest VM.
   Furthermore, it doesn't protect secrets from the control plane or
   other host components.

### Quick testing

First, copy the below spec to your machine. You will generate its
security policy in the next step.

This spec will create two persistent volume claims (PVCs) of 10GB each,
one using the built-in `azurefile-csi` storage class, and the other
using our new `cc-azurefile-csi` storage class. It will also create a
pod that mounts the `azurefile-csi` PVC in `/mnt/persistent-broken` and
the `cc-azurefile-csi` PVC in `/mnt/persistent-ok`.

<details>
  <summary>demo-cc-azurefile.yaml</summary>
  <br>

  ```yaml
  ---
  apiVersion: v1
  kind: PersistentVolumeClaim
  metadata:
    name: pvc-cc-azurefile-csi
  spec:
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: 10Gi
    storageClassName: cc-azurefile-csi
  ---
  apiVersion: v1
  kind: PersistentVolumeClaim
  metadata:
    name: pvc-azurefile-csi
  spec:
    accessModes:
      - ReadWriteOnce
    resources:
      requests:
        storage: 10Gi
    storageClassName: azurefile-csi
  ---
  kind: Pod
  apiVersion: v1
  metadata:
    name: demo-cc-azurefile
  spec:
    runtimeClassName: kata-cc-isolation
    containers:
      - image: busybox:latest
        name: busybox
        volumeMounts:
          - name: cc-azurefile-csi-vol
            mountPath: /mnt/persistent-ok
          - name: azurefile-csi-vol
            mountPath: /mnt/persistent-broken
    volumes:
      - name: cc-azurefile-csi-vol
        persistentVolumeClaim:
          claimName: pvc-cc-azurefile-csi
      - name: azurefile-csi-vol
        persistentVolumeClaim:
          claimName: pvc-azurefile-csi
  ```
</details>

Now you can generate the security policy for the spec (using the
`genpolicy-settings.json` file set up in the prerequisites section) and
deploy it:

```shell
$ az confcom katapolicygen -j genpolicy-settings.json -y demo-cc-azurefile.yaml
$ kubectl apply -f demo-cc-azurefile.yaml
```

Once the pod is deployed, you should be able to list the mounted filesystems using the command below:

 * `/mnt/persistent-ok`, from our driver, correctly appears as a cifs
   filesystem with 10GB of capacity.
 * `/mnt/persistent-broken` shows that the built-in driver is not
   working properly and mounts a tmpfs in the guest root filesystem.

```shell
$ kubectl exec -it demo-cc-azurefile -- df -hT
Filesystem           Type            Size      Used Available Use% Mounted on
...
//fcd8a0d3ad177481cac70bc.file.core.windows.net/pvc-72983850-8132-4673-afc8-0682bb480101
                     cifs           10.0G         0     10.0G   0% /mnt/persistent-ok
tmpfs                tmpfs         369.1M    232.0K    368.9M   0% /mnt/persistent-broken
...
```

## Installing the CoCo Azure Local driver

Run the following command to deploy the driver in the cluster:

```shell
$ curl -sSf https://raw.githubusercontent.com/microsoft/kata-containers/cc-azurelocal-csi-driver/latest/cc-deploy/install.sh | bash
```

You can then verify that the driver containers are properly deployed and
in the `Running` state:

```shell
$ kubectl get pods -A | grep cc-local
kube-system   csi-cc-local-controller-79ffb676f4-4w8mw                6/6     Running   0             32s
kube-system   csi-cc-local-node-g7png                                 3/3     Running   0             32s
```

You can also verify that the storage class is installed:

```shell
$ kubectl get storageclass cc-local-csi
NAME           PROVISIONER              RECLAIMPOLICY   VOLUMEBINDINGMODE      ALLOWVOLUMEEXPANSION   AGE
cc-local-csi   cc.local.csi.azure.com   Delete          WaitForFirstConsumer   true                   3d18h
```

### Known limitations

 * Sharing volumes across pods is not supported.
 * Only tested with ext4 filesystems.
 * [`volumeMode:
   Block`](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#volume-mode)
   has not been tested.
 * Specifying `securityContext.runAsUser` or `securityContext.fsGroup`
   in the pod spec is not supported.

### Notes

 * This following warning appears consistently in the output of `kubectl
   describe pod` when using this driver. This is by design of Kubernetes
   and does not affect behavior (see
   [kubernetes/kubernetes#104605](https://github.com/kubernetes/kubernetes/pull/104605)):
   ```
   Warning FailedScheduling 2m19s default-scheduler 0/1 nodes are available: waiting for ephemeral volume controller to create the persistentvolumeclaim "demo-cc-azurelocal". preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling..
   ```

### Quick testing

First, copy the below spec to your machine. You will generate its
security policy in the next step.

This spec will create a pod that mounts two ephemeral volumes of 1GB
each, one in `/mnt/scratch-broken` using the native Kubernetes emptyDir
feature in, and the other one in `/mnt/scratch-ok` using our
`cc-local-csi` storage class.

<details>
  <summary>demo-cc-azurelocal.yaml</summary>
  <br>

  ```yaml
  ---
  kind: Pod
  apiVersion: v1
  metadata:
    name: demo-cc-azurelocal
  spec:
    runtimeClassName: kata-cc-isolation
    containers:
      - image: busybox:latest
        name: busybox
        volumeMounts:
          - name: cc-local
            mountPath: /mnt/scratch-ok
          - name: emptydir
            mountPath: /mnt/scratch-broken
    volumes:
      - name: cc-local
        ephemeral:
          volumeClaimTemplate:
            spec:
              accessModes:
                - ReadWriteOncePod
              storageClassName: cc-local-csi
              resources:
                requests:
                  storage: 1Gi
      - name: emptydir
        emptyDir: {}
  ```
</details>

Now you can generate the security policy for the spec (using the
`genpolicy-settings.json` file set up in the prerequisites section) and
deploy it:

```shell
$ az confcom katapolicygen -j genpolicy-settings.json -y demo-cc-azurelocal.yaml
$ kubectl apply -f demo-cc-azurelocal.yaml
```

Once the pod is deployed, you should be able to list the mounted filesystems using the command below:

 * `/mnt/scratch-ok`, from our driver, correctly appears as an ext4
   filesystem with 1GB of capacity.
 * `/mnt/scratch-broken` shows that the emptyDir is not working properly
   and mounts an overlayfs in the guest root filesystem.

```shell
$ kubectl exec -it demo-cc-azurelocal -- df -hT | grep /mnt
/dev/vdd             ext4          973.4M    280.0K    905.9M   0% /mnt/scratch-ok
none                 overlay       369.2M    280.0K    368.9M   0% /mnt/scratch-broken
```
