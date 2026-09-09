# Nested Policy Compatibility Appliance

## Goal

Test whether an externally generated Kata Agent policy remains compatible with
the shim requests produced by a specific Kubernetes and containerd version.
Policy generation is a separate phase from nested execution, but both phases
run in the same self-contained profile image.

The image builds GenPolicy from the checked-out source tree and vendors the
versioned appliance profiles, API server, kubelet, containerd, etcd, CNI
plugins, image preparation, and workload normalization needed by the test. It
uses an unmodified Kata shim to boot a real guest through nested virtualization
exposed by the disposable L1 VM.

```text
externally annotated workload
             |
             v
pinned API server -> pinned kubelet -> pinned containerd
                                           |
                                           v
                                 unmodified Kata shim
                                           |
                                  hybrid-vsock relay
                                           |
                                           v
                              policy-enabled Kata Agent
```

The Agent's allow or deny response is authoritative for compatibility. The
captured byte streams and component logs explain the result.

## Appliance boundary

The harness carries its appliance profile beneath `appliance/`. The Docker
build downloads the exact component versions declared by the selected profile
and embeds OCI fixtures, the workload submitter, kubelet and CNI configuration,
and startup orchestration. It has no dependency on another Git branch, source
worktree, or prebuilt appliance image.

The compatibility matrix invokes the embedded GenPolicy binary in a dedicated
generation mode before annotating the workload. Consequently the generated
policy, rules, and settings all come from the same `manifold-cc`-based commit
as the harness. Policy generation is separate from the nested runtime path and
remains independent of the Kubernetes/containerd version under test.

An unmodified Kata installation is mounted at `/opt/kata`. This separates the
Kubernetes/containerd profile from the Kata build being tested and avoids
rebuilding Kata inside every version-matrix image.

Before a matrix starts, the host-side harness extracts the commits embedded in
the installed runtime-rs shim and the Agent inside the configured guest image.
Each installed commit must exist in the checkout, and the corresponding
`src/runtime-rs` or `src/agent` tree must match the current working tree.
Tracked differences and untracked component files both stop the run, while
harness-only commits do not require rebuilding unrelated Kata binaries. A
mismatch invokes the repository's local-build pipeline with its artifact cache
disabled, atomically replaces the installed shim and measured guest image, and
writes a marker binding their hashes to fingerprints of both source trees.
For CI, `prepare-kata-stack` is the artifact-production phase,
`verify-kata-provenance` is the artifact-consumption gate, and
`ci-fixture-e2e` deliberately verifies without rebuilding so a stale artifact
cannot be hidden by work performed inside the test job.

## Test-only policy reasons

Strict-policy Agent builds intentionally avoid exposing request contents or a
full policy trace to the host. A bare GenPolicy denial can therefore
identify the rejected endpoint without identifying which comparison failed.
The compatibility appliance adds test-only `reason` rules so a failed matrix
case can attribute the denial without weakening enforcement.

The reason rules are Rego source, not a GenPolicy settings option and not a
runtime-rs or Agent configuration flag. During the appliance image build,
`tests/policy/create-sandbox-reasons.rego.inc` is appended to the repository-tip
`rules.rego`. During policy generation, that combined module is supplied to
GenPolicy through:

```text
--rego-rules-path /opt/genpolicy/policy/rules.rego
```

GenPolicy embeds the resulting rules module in each generated workload policy.
The same reason rules are therefore used by every appliance profile; profile
environment files and profile JSON settings patches do not enable or alter
them.

The rules add only explanatory entries to the policy's existing `errors`
collection. They do not define an allow result, bypass a check, mutate policy
data, or change the request. Current attribution covers:

- non-empty guest hook paths;
- unexpected kernel modules;
- sandbox PID namespace mode;
- unmatched or duplicate sandbox storage entries;
- the field category of a sandbox-storage mismatch; and
- failure to match a container's root path, mounts, or storages.

Reason text crosses the guest boundary in the denied RPC status. The rules keep
it concise by reporting rule categories, field names, counts, or indexes.
Detailed request values remain available in the raw hybrid-vsock captures when
deeper debugging is required.

## Capture

Cloud Hypervisor, Firecracker, and OpenVMM expose the host side of the Agent
channel as a Unix socket. The capture supervisor watches the Kata runtime
directories, renames a newly created backend socket, and binds a relay at the
original pathname before the shim connects. It forwards both directions
without decoding or modifying bytes.

Each connection produces:

- `shim-to-agent.bin`;
- `agent-to-shim.bin`;
- connection timing and socket metadata.

The raw streams include the hybrid-vsock `CONNECT` handshake followed by ttRPC
frames. They may also contain the synthetic Secret or ConfigMap fixture
payloads sent through `CopyFile`. The `agent-rpcs` directory is mode `0700` to
keep each run's diagnostic artifacts isolated.

The initial implementation supports hybrid-vsock configurations only. Native
QEMU AF_VSOCK does not expose a Unix pathname that this relay can interpose.
Failure to capture at least one connection is an infrastructure failure.

## Verdict

The harness accepts an already annotated `/input/workload.yaml`. It rejects a
workload without the `io.katacontainers.config.hypervisor.cc_init_data`
annotation so a successful boot cannot accidentally test the guest's baked-in
default policy. It also rejects a Kata configuration whose selected hypervisor
does not enable the `cc_init_data` annotation; accepting such a configuration
would cause the runtime to discard the supplied policy before VM creation.

The result is:

- `compatible` when every expected Pod reaches `Ready` and every operation
  declared by the fixture completes, including any exec, graceful stop,
  finalizer removal, and Pod deletion checks;
- `policy-incompatible` when the workload fails and the collected logs contain
  a policy denial;
- `infrastructure-failure` for all other failures.

All retries remain in the raw stream. The primary evidence is never
deduplicated.

## Isolation

Run the harness container only inside a disposable L1 VM with nested KVM. The
image is a normal OCI image; privilege is granted when the container is
started. The container requires `--privileged`, `--cgroupns=host`, cgroup v2,
mount propagation, and access to `/dev/kvm` because it acts as a complete
nested Kubernetes node rather than as an ordinary workload container. These
permissions allow it to:

- start containerd, kubelet, etcd, and the Kubernetes API server;
- create and manage cgroups and mount namespaces;
- configure CNI networking, network namespaces, routes, and iptables rules;
- start udev and manage block and device-mapper nodes for EROFS dm-verity;
- launch nested Kata virtual machines through the host KVM device.

Depending on the selected VMM, `/dev/net/tun` and `/dev/vhost-vsock` must also
be passed through. The privileged container can modify kernel-visible state in
its L1 host, so this is a test-only deployment model. It must not run directly
on a developer workstation, shared host, or production node.

The appliance supports EROFS dm-verity and digest-pinned guest pull. Both paths
boot the same monolithic dm-verity-protected guest image containing the strict
Agent, Confidential Data Hub, and pause bundle. Profile behavior comes from
containerd, GenPolicy, and a temporary derived Kata configuration; the
caller-supplied configuration and runtime-rs source are not modified.

The EROFS profiles use containerd's EROFS snapshotter with dm-verity enabled.
Container image content is converted to verified block-backed root filesystems
before the nested shim starts the guest. The selected Kata configuration must
set `shared_fs = "none"`; this matches confidential-runtime configurations and
prevents host filesystem sharing from becoming either a policy artifact or a
content channel. The EROFS snapshotter's writable layer size is zero, leaving
the Agent to create an ephemeral upper under `/run` instead of presenting an
additional, unverified host-backed ext4 storage.

The guest-pull profiles use the native snapshotter for host-side CRI metadata,
then enable runtime-rs `force_guest_pull` in the derived test configuration.
Runtime-rs sends an `image_guest_pull` storage source to the Agent. The policy
requires its digest to equal the digest recorded by GenPolicy in
`io.kubernetes.cri.image-name`. The Agent delegates the approved reference to
CDH, whose image-rs/rust-oci-client path verifies the downloaded manifest bytes
against that digest before unpacking.

The local TLS registry binds the CNI gateway `10.188.0.1:5000`, which is
reachable from the nested guest without external DNS. The appliance image
contains a dedicated registry certificate with that IP address as a subject
alternative name, and the harness embeds its CA certificate in the workload's
CDH init-data configuration. Policy generation rewrites only the synthetic
fixture registry authority to that address. Runtime publication pushes the
matching deterministic OCI manifests, then the appliance drops forwarded IPv4
and IPv6 traffic so guest workloads cannot use the node as an external-network
gateway. The `10.188.0.0/16` subnet deliberately avoids Podman's default
`10.88.0.0/16` network, which would otherwise make registry routing ambiguous
inside the privileged appliance container.

### EROFS profile settings override and encrypted-emptyDir coverage gap

The Kata configuration used for the current results sets `shared_fs = "none"`
but omits the runtime-rs `emptydir_mode` setting. Its default is `shared-fs`;
because filesystem sharing is unavailable, runtime-rs falls back to
representing a disk-backed Kubernetes `emptyDir` as guest-local Agent storage
with `driver`, `source`, `fstype`, and mount type set to `local`. GenPolicy's
default `block-encrypted` emptyDir template instead describes an encrypted ext4
block device. Without an adjustment, the generated policy rejects the
runtime-rs `CreateContainerRequest` because those declarations differ.

Both EROFS profiles therefore select a shared JSON Patch settings drop-in.
During policy generation, `generate_policy.sh` copies the repository-tip
GenPolicy settings to an output-local directory and installs the patch as
`genpolicy-settings.d/20-profile.json`. GenPolicy applies that drop-in through
`--json-settings-path` and emits a policy whose disk-backed emptyDir declaration
matches runtime-rs's existing guest-local request:

```text
driver = local
source = local
fstype = local
mount type = local
options = mode=0777
shared = false
```

This is exclusively a policy-generation override. It does not rebuild or
reconfigure runtime-rs, change Cargo features or build flags, enable an
experimental feature, alter `force_guest_pull`, or modify the runtime binary.
The runtime-rs request remains unchanged; only GenPolicy's declaration of the
expected request is adjusted. No GenPolicy source change or new emptyDir mode
is required.

This workaround means the current eight-fixture positive matrix validates policy
compatibility for the guest-local fallback; it does not establish compatibility
for runtime-rs's `block-encrypted` path. That path creates and hot-plugs a
host-backed sparse disk, then requests Agent-side LUKS2/dm-crypt setup through
Confidential Data Hub. The harness accepts a caller-supplied Kata installation
and does not currently verify the required Agent build features, guest tools,
CDH availability, or effective dm-crypt mapping. It must not claim encrypted
disk-backed `emptyDir` coverage until those prerequisites and the resulting
Agent request are validated end to end.

The positive matrix also excludes Kubernetes termination-message files.
GenPolicy can authorize the `/dev/termination-log` mount and can set
`request_defaults.GetDiagnosticDataRequest` to `true`. With `shared_fs =
"none"`, however, runtime-rs must retrieve the guest file through
`GetDiagnosticData`, and strict Agent builds reject that RPC before policy
evaluation. The separate `termination-log-e2e` target reproduces this gap while
still completing container stop and Pod deletion. Other runtime operations are
covered by the positive `runtime-operations-workload.yaml` fixture.

The positive service-account fixture uses `serviceAccountName: default`.
GenPolicy currently reads the value used for
`fieldRef: spec.serviceAccountName` from its container representation instead
of the Pod spec, where the field is defined. A production Pod using a custom
service account therefore gets `SERVICE_ACCOUNT_NAME=default` in policy while
Kubernetes injects the custom name at runtime. The separate
`custom-service-account-e2e` target preserves that policy-denial reproducer
without making it part of the positive matrix.

The runtime-rs multi-layer EROFS implementation consolidates image layers into
a GPT-partitioned VMDK. Cloud Hypervisor configurations therefore require a
binary with flat VMDK support from cloud-hypervisor/cloud-hypervisor#8599; the
repository-pinned v51.1 binary is rejected during harness preflight.
