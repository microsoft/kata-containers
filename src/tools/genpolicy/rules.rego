# Copyright (c) 2023 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
package agent_policy

# Not required for rego v1. regorus still defaults to v0, so keep it for now.
import future.keywords.in
import future.keywords.every
import future.keywords.if

# GetDiagnosticDataRequest is not supported yet when using the CoCo policy unless enabled in policy_data.request_defaults.
default GetDiagnosticDataRequest := false

# Default values, returned by OPA when rules cannot be evaluated to true.
default AddARPNeighborsRequest := false
default AddSwapPathRequest := false
default AddSwapRequest := false
default CloseStdinRequest := false
default CommitVolumeRevisionRequest := false
default CopyFileRequest := false
default CopySingleFileRequest := false
default CreateContainerRequest := false
default CreateSandboxRequest := false
default DestroySandboxRequest := true
default ExecProcessRequest := false
default GetIPTablesRequest := false
default GetMetricsRequest := false
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default InitVolumeRequest := false
default ListInterfacesRequest := false
default ListRoutesRequest := false
default MemAgentCompactConfig := false
default MemAgentMemcgConfig := false
default MemHotplugByProbeRequest := false
default OnlineCPUMemRequest := true
default PauseContainerRequest := false
default PutVolumeFileRevisionRequest := false
default ReadStreamRequest := false
default RemoveContainerRequest := false
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := false
default ResizeVolumeRequest := false
default ResumeContainerRequest := false
default SetGuestDateTimeRequest := false
default SetIPTablesRequest := false
default SetPolicyRequest := false
default SignalProcessRequest := false
default StartContainerRequest := false
default StartTracingRequest := false
default StatsContainerRequest := false
default StopTracingRequest := false
default TtyWinResizeRequest := false
default UpdateContainerRequest := false
default UpdateEphemeralMountsRequest := false
default UpdateInterfaceRequest := false
default UpdateRoutesRequest := false
default VolumeStatsRequest := false
default WaitProcessRequest := false
default WriteStreamRequest := false

# Intentionally-allowed infrastructure / sandbox-lifecycle endpoints (reviewed, not an
# unexamined gap). The endpoints below keep `:= true` above by design: they are part of
# the trusted, host-driven sandbox lifecycle and carry no attacker-constrainable,
# security-relevant payload that an in-guest Rego gate could restrict without breaking
# legitimate VM sizing, boot, or teardown.
#
#   DestroySandboxRequest                  empty payload; sandbox teardown. The host
#                                          already controls the VM lifecycle (it can
#                                          destroy the VM directly), so gating adds no
#                                          guarantee.
#   GetOOMEventRequest                     empty payload; read-only OOM notification
#                                          stream polled by the runtime.
#   GuestDetailsRequest                    read-only guest capability query (memory block
#                                          size / hotplug probe) issued early in the boot
#                                          handshake, before any container state exists.
#   OnlineCPUMemRequest                    host-driven online of CPU/memory the host
#                                          itself provisions; onlining host-provided
#                                          hardware is not an in-guest trust boundary and
#                                          the count is fixed by VM config, not the guest.
#   RemoveStaleVirtiofsShareMountsRequest  empty payload; housekeeping of stale virtiofs
#                                          shares the host already controls.
#
# This matches the reference, which likewise does not gate its GuestDetails/OOM/lifecycle
# equivalents; the diagnostics surface the reference *does* gate (get-properties /
# dump-stacks) is instead hard-disabled (GetDiagnosticDataRequest is `:= false` above with
# no rule that can make it true, as is CopyFileRequest -- the host->guest content channel
# now runs through the four typed endpoints mediated further below). Per-container
# operations (Create/Exec/Signal/Start/Wait/Stats/TtyWinResize/RemoveContainer) ARE gated
# on authorized container state (see below).

# AllowRequestsFailingPolicy := true configures the Agent to *allow any
# requests causing a policy failure*. This is an unsecure configuration
# but is useful for allowing unsecure pods to start, then connect to
# them and inspect OPA logs for the root cause of a failure.
default AllowRequestsFailingPolicy := false

# Constants
S_NAME_KEY = "io.kubernetes.cri.sandbox-name"
S_NAMESPACE_KEY = "io.kubernetes.cri.sandbox-namespace"
CDI_VFIO_ANNOTATION_PREFIX = "cdi.k8s.io/vfio"
VFIO_PCI_ADDRESS_REGEX = "^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[01][0-9a-fA-F]\\.[0-7]=[0-9a-fA-F]{2}/[0-9a-fA-F]{2}$"

CreateContainerRequest := {"ops": ops, "allowed": true} if {
    # Check if the input request should be rejected even before checking the
    # policy_data.containers information.
    allow_create_container_input

    # RM-20: a container id is consumed for the sandbox's lifetime. RemoveContainerRequest
    # deletes the id's own state key (so no stale id -> container reference survives) but
    # records a separate tombstone, and a create for a tombstoned id is refused here.
    # Without this the same host-chosen id could name a second container, which is the
    # property the baseline relies on to make an untrusted id harmless: hcsshim's
    # create_container requires `not container_started` and never clears that mark, not
    # even in shutdown_container. get_state_val is undefined for an absent key, and `not`
    # over an undefined expression succeeds, so this admits every first create.
    not get_state_val(retired_key(input.container_id))
    print("CreateContainerRequest: container id", input.container_id, "has not been used before")

    i_oci := input.OCI
    i_storages := input.storages
    i_devices := input.devices

    # array of possible state operations
    ops_builder := []

    # check sandbox name
    sandbox_name = i_oci.Annotations[S_NAME_KEY]
    add_sandbox_name_to_state := state_allows("sandbox_name", sandbox_name)
    ops_builder1 := concat_op_if_not_null(ops_builder, add_sandbox_name_to_state)

    # Check if any element from the allowed-container set (base + composed fragment
    # containers) allows the input request.
    some entry in all_policy_container_entries
    p_container := entry.container
    print("======== CreateContainerRequest: trying next policy container")

    p_pidns := p_container.sandbox_pidns
    i_pidns := input.sandbox_pidns
    print("CreateContainerRequest: p_pidns =", p_pidns, "i_pidns =", i_pidns)
    p_pidns == i_pidns

    p_oci := p_container.OCI

    # check namespace
    p_namespace := p_oci.Annotations[S_NAMESPACE_KEY]
    i_namespace := i_oci.Annotations[S_NAMESPACE_KEY]
    print("CreateContainerRequest: p_namespace =", p_namespace, "i_namespace =", i_namespace)
    add_namespace_to_state := allow_namespace(p_namespace, i_namespace)
    ops_builder2 := concat_op_if_not_null(ops_builder1, add_namespace_to_state)

    print("CreateContainerRequest: p Version =", p_oci.Version, "i Version =", i_oci.Version)
    p_oci.Version == i_oci.Version

    print("CreateContainerRequest: p Readonly =", p_oci.Root.Readonly, "i Readonly =", i_oci.Root.Readonly)
    p_oci.Root.Readonly == i_oci.Root.Readonly

    allow_anno(p_container, i_oci)

    p_storages := p_container.storages
    allow_by_anno(p_oci, i_oci, p_storages, i_storages)

    p_devices := p_container.devices
    allow_devices(p_devices, i_devices, i_oci)

    ret := allow_linux(ops_builder2, p_oci, i_oci)
    ret.allowed

    # save to policy state
    # key: input.container_id
    # val: a stable reference to the policy container that authorized it. NOT its index
    #      in the combined set: that set grows as fragments load, so an index recorded
    #      now can name a different container later (see all_policy_container_entries).
    print("CreateContainerRequest: adding container_id=", input.container_id, " to state")
    add_p_container_to_state := state_allows(input.container_id, entry.ref)

    ops := concat_op_if_not_null(ret.ops, add_p_container_to_state)

    print("CreateContainerRequest: true")
}

allow_create_container_input if {
    print("allow_create_container_input: input =", input)

    count(input.shared_mounts) == 0
    is_null(input.string_user)

    i_oci := input.OCI
    is_null(i_oci.Hooks)
    is_null(i_oci.Solaris)
    is_null(i_oci.Windows)

    i_linux := i_oci.Linux
    count(i_linux.GIDMappings) == 0
    count(i_linux.MountLabel) == 0
    count(i_linux.Resources.Devices) == 0
    count(i_linux.RootfsPropagation) == 0
    count(i_linux.UIDMappings) == 0
    is_null(i_linux.IntelRdt)
    is_null(i_linux.Resources.BlockIO)
    is_null(i_linux.Resources.Network)
    is_null(i_linux.Resources.Pids)
    is_null(i_linux.Seccomp)

    i_process := i_oci.Process
    count(i_process.SelinuxLabel) == 0
    count(i_process.User.Username) == 0

    print("allow_create_container_input: true")
}

allow_namespace(p_namespace, i_namespace) = add_namespace if {
    p_namespace == i_namespace
    add_namespace := state_allows("namespace", i_namespace)
    print("allow_namespace 1: input namespace matches policy data")
}

allow_namespace(p_namespace, i_namespace) = add_namespace if {
    p_namespace == ""
    print("allow_namespace 2: no namespace found on policy data")
    add_namespace := state_allows("namespace", i_namespace)
}

# key hasn't been seen before, save key, value pair to state
state_allows(key, value) = action if {
  state := get_state()
  print("state_allows 1: state[key] =", state[key], "value =", value)
  not state[key]
  print("state_allows 1: saving to state key =", key, "value =", value)
  path := get_state_path(key)
  action := {
    "op": "add",
    "path": path,
    "value": value,
  }
}

# value matches what's in state, allow it
state_allows(key, value) = action if {
  print("state_allows 2: start")
  state := get_state()
  print("state_allows 2: state[key] =", state[key], "value =", value)
  value == state[key]
  print("state_allows 2: found key =", key, "value =", value, " in state")
  action := null
}

# delete key=value from state
state_del_key(key) = action if {
  print("state_del_key: ", key)
  state := get_state()
  print("state_del_key: deleting from state key =", key)
  path := get_state_path(key)
  action := {
    "op": "remove",
    "path": path,
  }
}

# helper functions to interact with the state
get_state() = state if {
  state := data["pstate"]
}

get_state_val(key) = value if {
    state := get_state()
    value := state[key]
}

get_state_path(key) = path if {
    # prepend "/pstate/" to key
    path := concat("/", ["/pstate", key])
}

# RM-20: state key under which a removed container id is tombstoned. Namespaced so it can
# never collide with a container id's own key -- a container id is hex, so it cannot start
# with "retired:".
retired_key(container_id) = key if {
    key := concat("", ["retired:", container_id])
}

# Helper functions to conditionally concatenate op is not null
concat_op_if_not_null(ops, op) = result if {
    op == null
    result := ops
}

concat_op_if_not_null(ops, op) = result if {
    op != null
    result := array.concat(ops, [op])
}

# Reject unexpected annotations.
allow_anno(p_container, i_oci) if {
    print("allow_anno 1: start")

    not i_oci.Annotations

    print("allow_anno 1: true")
}
allow_anno(p_container, i_oci) if {
    p_oci := p_container.OCI

    print("allow_anno 2: p Annotations =", p_oci.Annotations)
    print("allow_anno 2: i Annotations =", i_oci.Annotations)

    every i_key, i_value in i_oci.Annotations {
        allow_anno_key_value(i_key, i_value, p_container)
    }

    print("allow_anno 2: true")
}

allow_anno_key_value(i_key, i_value, p_container) if {
    print("allow_anno_key_value 1: i key =", i_key)

    startswith(i_key, "io.kubernetes.cri.")

    print("allow_anno_key_value 1: true")
}
allow_anno_key_value(i_key, i_value, p_container) if {
    print("allow_anno_key_value 2: i key =", i_key)

    some p_key, _ in p_container.OCI.Annotations
    p_key == i_key

    print("allow_anno_key_value 2: true")
}
allow_anno_key_value(i_key, i_value, p_container) if {
    print("allow_anno_key_value 3: i key =", i_key, "i_value =", i_value)

    some p_key_regex, p_value_regex in p_container.runtime_anno_patterns
    print("allow_anno_key_value 3: p_key_regex =", p_key_regex, "p_value_regex =", p_value_regex)

    regex.match(p_key_regex, i_key)
    regex.match(p_value_regex, i_value)

    print("allow_anno_key_value 3: true")
}

# Get the value of the S_NAME_KEY annotation and
# correlate it with other annotations and process fields.
allow_by_anno(p_oci, i_oci, p_storages, i_storages) if {
    print("allow_by_anno 1: start")

    not p_oci.Annotations[S_NAME_KEY]

    i_s_name := i_oci.Annotations[S_NAME_KEY]
    print("allow_by_anno 1: i_s_name =", i_s_name)

    i_s_namespace := i_oci.Annotations[S_NAMESPACE_KEY]
    print("allow_by_anno 1: i_s_namespace =", i_s_namespace)

    allow_by_sandbox_name(p_oci, i_oci, p_storages, i_storages, i_s_name, i_s_namespace)

    print("allow_by_anno 1: true")
}
allow_by_anno(p_oci, i_oci, p_storages, i_storages) if {
    print("allow_by_anno 2: start")

    p_s_name := p_oci.Annotations[S_NAME_KEY]
    i_s_name := i_oci.Annotations[S_NAME_KEY]
    print("allow_by_anno 2: i_s_name =", i_s_name, "p_s_name =", p_s_name)

    allow_sandbox_name(p_s_name, i_s_name)

    i_s_namespace := i_oci.Annotations[S_NAMESPACE_KEY]
    print("allow_by_anno 2: i_s_namespace =", i_s_namespace)

    allow_by_sandbox_name(p_oci, i_oci, p_storages, i_storages, i_s_name, i_s_namespace)

    print("allow_by_anno 2: true")
}

allow_by_sandbox_name(p_oci, i_oci, p_storages, i_storages, s_name, s_namespace) if {
    print("allow_by_sandbox_name: start")

    i_namespace := i_oci.Annotations[S_NAMESPACE_KEY]

    allow_by_container_types(p_oci, i_oci, s_name, i_namespace)
    allow_by_bundle_or_sandbox_id(p_oci, i_oci, p_storages, i_storages)
    allow_process(p_oci.Process, i_oci.Process, s_name, s_namespace)

    print("allow_by_sandbox_name: true")
}

allow_sandbox_name(p_s_name, i_s_name) if {
    print("allow_sandbox_name: start")
    regex.match(p_s_name, i_s_name)

    print("allow_sandbox_name: true")
}

# Check that the "io.kubernetes.cri.container-type" and
# "io.katacontainers.pkg.oci.container_type" annotations designate the
# expected type - either a "sandbox" or a "container". Then, validate
# other annotations based on the actual "sandbox" or "container" value
# from the input container.
allow_by_container_types(p_oci, i_oci, s_name, s_namespace) if {
    print("allow_by_container_types: checking io.kubernetes.cri.container-type")

    c_type := "io.kubernetes.cri.container-type"

    p_cri_type := p_oci.Annotations[c_type]
    i_cri_type := i_oci.Annotations[c_type]
    print("allow_by_container_types: p_cri_type =", p_cri_type, "i_cri_type =", i_cri_type)
    p_cri_type == i_cri_type

    allow_by_container_type(i_cri_type, p_oci, i_oci, s_name, s_namespace)

    print("allow_by_container_types: true")
}

allow_by_container_type(i_cri_type, p_oci, i_oci, s_name, s_namespace) if {
    print("allow_by_container_type 1: i_cri_type =", i_cri_type)
    i_cri_type == "sandbox"

    i_kata_type := i_oci.Annotations["io.katacontainers.pkg.oci.container_type"]
    print("allow_by_container_type 1: i_kata_type =", i_kata_type)
    i_kata_type == "pod_sandbox"

    allow_sandbox_container_name(p_oci, i_oci)
    allow_sandbox_net_namespace(p_oci, i_oci)
    allow_sandbox_log_directory(p_oci, i_oci, s_name, s_namespace)

    print("allow_by_container_type 1: true")
}

allow_by_container_type(i_cri_type, p_oci, i_oci, s_name, s_namespace) if {
    print("allow_by_container_type 2: i_cri_type =", i_cri_type)
    i_cri_type == "container"

    i_kata_type := i_oci.Annotations["io.katacontainers.pkg.oci.container_type"]
    print("allow_by_container_type 2: i_kata_type =", i_kata_type)
    i_kata_type == "pod_container"

    allow_container_name(p_oci, i_oci)
    allow_net_namespace(p_oci, i_oci)
    allow_log_directory(p_oci, i_oci)

    print("allow_by_container_type 2: true")
}

# "io.kubernetes.cri.container-name" annotation
allow_sandbox_container_name(p_oci, i_oci) if {
    print("allow_sandbox_container_name: start")

    container_annotation_missing(p_oci, i_oci, "io.kubernetes.cri.container-name")

    print("allow_sandbox_container_name: true")
}

allow_container_name(p_oci, i_oci) if {
    print("allow_container_name: start")

    allow_container_annotation(p_oci, i_oci, "io.kubernetes.cri.container-name")

    print("allow_container_name: true")
}

container_annotation_missing(p_oci, i_oci, key) if {
    print("container_annotation_missing:", key)

    not p_oci.Annotations[key]
    not i_oci.Annotations[key]

    print("container_annotation_missing: true")
}

allow_container_annotation(p_oci, i_oci, key) if {
    print("allow_container_annotation: key =", key)

    p_value := p_oci.Annotations[key]
    i_value := i_oci.Annotations[key]
    print("allow_container_annotation: p_value =", p_value, "i_value =", i_value)

    p_value == i_value

    print("allow_container_annotation: true")
}

# "nerdctl/network-namespace" annotation
allow_sandbox_net_namespace(p_oci, i_oci) if {
    print("allow_sandbox_net_namespace: start")

    key := "nerdctl/network-namespace"

    p_namespace := p_oci.Annotations[key]
    i_namespace := i_oci.Annotations[key]
    print("allow_sandbox_net_namespace: p_namespace =", p_namespace, "i_namespace =", i_namespace)

    regex.match(p_namespace, i_namespace)

    print("allow_sandbox_net_namespace: true")
}

allow_net_namespace(p_oci, i_oci) if {
    print("allow_net_namespace: start")

    key := "nerdctl/network-namespace"

    not p_oci.Annotations[key]
    not i_oci.Annotations[key]

    print("allow_net_namespace: true")
}

# "io.kubernetes.cri.sandbox-log-directory" annotation
allow_sandbox_log_directory(p_oci, i_oci, s_name, s_namespace) if {
    print("allow_sandbox_log_directory: start")

    key := "io.kubernetes.cri.sandbox-log-directory"

    p_dir := p_oci.Annotations[key]
    regex1 := replace(p_dir, "$(sandbox-name)", s_name)
    regex2 := replace(regex1, "$(sandbox-namespace)", s_namespace)
    print("allow_sandbox_log_directory: regex2 =", regex2)

    i_dir := i_oci.Annotations[key]
    print("allow_sandbox_log_directory: i_dir =", i_dir)

    regex.match(regex2, i_dir)

    print("allow_sandbox_log_directory: true")
}

allow_log_directory(p_oci, i_oci) if {
    print("allow_log_directory: start")

    key := "io.kubernetes.cri.sandbox-log-directory"

    not p_oci.Annotations[key]
    not i_oci.Annotations[key]

    print("allow_log_directory: true")
}

allow_devices(p_devices, i_devices, i_oci) if {
    print("allow_devices: start")

    vfio_device_path := policy_data.devices.vfio.device_path

    p_volume_devices := [d | d := p_devices[_]; d.container_path != vfio_device_path]
    i_volume_devices := [d | d := i_devices[_]; not startswith(d.container_path, vfio_device_path)]
    print("allow_devices: p_volume_devices =", p_volume_devices, "i_volume_devices =", i_volume_devices)
    allow_volume_devices(p_volume_devices, i_volume_devices)

    p_vfio_devices := [d | d := p_devices[_]; d.container_path == vfio_device_path]
    i_vfio_devices := [d | d := i_devices[_]; startswith(d.container_path, vfio_device_path)]
    print("allow_devices: p_vfio_devices =", p_vfio_devices, "i_vfio_devices =", i_vfio_devices)
    allow_vfio_devices(p_vfio_devices, i_vfio_devices, i_oci)

    print("allow_devices: true")
}

allow_volume_devices(p_volume_devices, i_volume_devices) if {
    print("allow_volume_devices: start")

    every i_volume_device in i_volume_devices {
        some p_device in p_volume_devices
        p_device.container_path == i_volume_device.container_path
    }

    print("allow_volume_devices: true")
}

allow_vfio_devices(p_vfio_devices, i_vfio_devices, i_oci) if {
    print("allow_vfio_devices: start")

    every i_vfio_device in i_vfio_devices {
        allow_vfio_device(p_vfio_devices, i_vfio_device)
    }

    allow_vfio_device_cdi_correlation(p_vfio_devices, i_vfio_devices, i_oci)

    print("allow_vfio_devices: true")
}

allow_vfio_device(p_vfio_devices, i_vfio_device) if {
    print("allow_vfio_device: start")

    some p_device in p_vfio_devices

    vfio_device_path := policy_data.devices.vfio.device_path
    startswith(i_vfio_device.container_path, vfio_device_path)
    suffix := trim_prefix(i_vfio_device.container_path, vfio_device_path)
    regex.match("^[0-9]+$", suffix)

    i_vfio_device.id == concat("", ["vfio", suffix])

    i_vfio_device.type_ == p_device.type_

    i_vfio_device.vm_path == p_device.vm_path

    count(i_vfio_device.options) > 0
    every option in i_vfio_device.options {
        regex.match(VFIO_PCI_ADDRESS_REGEX, option)
    }
    print("allow_vfio_device: true")
}

get_cdi_vfio_anno_suffixes(annotations) := [suffix |
    some key, _ in annotations
    startswith(key, CDI_VFIO_ANNOTATION_PREFIX)
    suffix := trim_prefix(key, CDI_VFIO_ANNOTATION_PREFIX)
    regex.match("^[0-9]+$", suffix)
]

allow_vfio_device_cdi_correlation(p_vfio_devices, i_vfio_devices, i_oci) if {
    print("allow_vfio_device_cdi_correlation 1: start")

    count(i_vfio_devices) == 0
    count(p_vfio_devices) == 0

    print("allow_vfio_device_cdi_correlation 1: true")
}

# VFIO device hot-plug: input VFIO devices are present.
# Input VFIO devices must match policy VFIO devices and unique set of CDI annotations.
allow_vfio_device_cdi_correlation(p_vfio_devices, i_vfio_devices, i_oci) if {
    print("allow_vfio_device_cdi_correlation 2: start")

    count(i_vfio_devices) == count(p_vfio_devices)

    vfio_device_path := policy_data.devices.vfio.device_path
    vfio_numbers := [suffix |
        d := i_vfio_devices[_];
        suffix := trim_prefix(d.container_path, vfio_device_path);
        regex.match("^[0-9]+$", suffix)
    ]
    # Convert array to set to reject possible duplicate entries in the array
    count(vfio_numbers) == count({n | n := vfio_numbers[_]})

    cdi_suffixes := get_cdi_vfio_anno_suffixes(i_oci.Annotations)
    count(cdi_suffixes) == count({s | s := cdi_suffixes[_]})
    {n | n := vfio_numbers[_]} == {s | s := cdi_suffixes[_]}

    print("allow_vfio_device_cdi_correlation 2: true")
}

# VFIO device cold-plug: no input VFIO devices expected.
# Number of VFIO policy devices must match unique set of CDI annotations.
allow_vfio_device_cdi_correlation(p_vfio_devices, i_vfio_devices, i_oci) if {
    print("allow_vfio_device_cdi_correlation 3: start")

    count(i_vfio_devices) == 0
    count(p_vfio_devices) > 0

    cdi_suffixes := get_cdi_vfio_anno_suffixes(i_oci.Annotations)
    count(cdi_suffixes) == count({s | s := cdi_suffixes[_]})
    count(cdi_suffixes) == count(p_vfio_devices)

    print("allow_vfio_device_cdi_correlation 3: true")
}

allow_linux(state_ops, p_oci, i_oci) := {"ops": ops, "allowed": true} if {
    p_namespaces := p_oci.Linux.Namespaces
    print("allow_linux: p namespaces =", p_namespaces)

    p_namespaces_normalized := [
        {"Path": obj.Path, "Type": normalize_namespace_type(obj.Type)}
        | obj := p_namespaces[_]
    ]

    i_namespaces := i_oci.Linux.Namespaces
    print("allow_linux: i namespaces =", i_namespaces)

    i_namespace_without_network_normalized := [
        {"Path": obj.Path, "Type": normalize_namespace_type(obj.Type)}
        | obj := i_namespaces[_]; obj.Type != "network"; obj.Type != "cgroup"
    ]

    print("allow_linux: p_namespaces_normalized =", p_namespaces_normalized)
    print("allow_linux: i_namespace_without_network_normalized =", i_namespace_without_network_normalized)

    p_namespaces_normalized == i_namespace_without_network_normalized

    allow_masked_paths(p_oci, i_oci)
    allow_readonly_paths(p_oci, i_oci)
    allow_linux_devices(p_oci.Linux.Devices, i_oci.Linux.Devices)
    allow_linux_sysctl(p_oci.Linux, i_oci.Linux)
    ret := allow_network_namespace_start(state_ops, p_oci, i_oci)
    ret.allowed

    ops := ret.ops

    print("allow_linux: true")
}

# Retrieve the "network" namespace from the input data and pass it on for the
# network namespace policy checks.
allow_network_namespace_start(state_ops, p_oci, i_oci) := {"ops": ops, "allowed": true} if {
    print("allow_network_namespace start: start")

    p_namespaces := p_oci.Linux.Namespaces
    print("allow_network_namespace start: p namespaces =", p_namespaces)

    i_namespaces := i_oci.Linux.Namespaces
    print("allow_network_namespace start: i namespaces =", i_namespaces)

    # Return path of the "network" namespace
    network_ns := [obj | obj := i_namespaces[_]; obj.Type == "network"]

    print("allow_network_namespace start: network_ns =", network_ns)

    ret := allow_network_namespace(state_ops, network_ns)
    ret.allowed

    ops := ret.ops
}

# This rule is when there's no network namespace in the input data.
allow_network_namespace(state_ops, network_ns) := {"ops": ops, "allowed": true} if {
    count(network_ns) == 0

    network_ns_path = ""

    add_network_namespace_to_state := state_allows("network_namespace", network_ns_path)
    ops := concat_op_if_not_null(state_ops, add_network_namespace_to_state)

    print("allow_network_namespace 1: true")
}

# This rule is when there's exactly one network namespace in the input data.
allow_network_namespace(state_ops, network_ns) := {"ops": ops, "allowed": true} if {
    count(network_ns) == 1

    add_network_namespace_to_state := state_allows("network_namespace", network_ns[0].Path)
    ops := concat_op_if_not_null(state_ops, add_network_namespace_to_state)

    print("allow_network_namespace 2: true")
}

allow_masked_paths(p_oci, i_oci) if {
    p_paths := p_oci.Linux.MaskedPaths
    print("allow_masked_paths 1: p_paths =", p_paths)

    i_paths := i_oci.Linux.MaskedPaths
    print("allow_masked_paths 1: i_paths =", i_paths)

    allow_masked_paths_array(p_paths, i_paths)

    print("allow_masked_paths 1: true")
}
allow_masked_paths(p_oci, i_oci) if {
    print("allow_masked_paths 2: start")

    not p_oci.Linux.MaskedPaths
    not i_oci.Linux.MaskedPaths

    print("allow_masked_paths 2: true")
}

# All the policy masked paths must be masked in the input data too.
# Input is allowed to have more masked paths than the policy.
allow_masked_paths_array(p_array, i_array) if {
    every p_elem in p_array {
        allow_masked_path(p_elem, i_array)
    }
}

allow_masked_path(p_elem, i_array) if {
    print("allow_masked_path: p_elem =", p_elem)

    some i_elem in i_array
    p_elem == i_elem

    print("allow_masked_path: true")
}

allow_readonly_paths(p_oci, i_oci) if {
    p_paths := p_oci.Linux.ReadonlyPaths
    print("allow_readonly_paths 1: p_paths =", p_paths)

    i_paths := i_oci.Linux.ReadonlyPaths
    print("allow_readonly_paths 1: i_paths =", i_paths)

    allow_readonly_paths_array(p_paths, i_paths, i_oci.Linux.MaskedPaths)

    print("allow_readonly_paths 1: true")
}
allow_readonly_paths(p_oci, i_oci) if {
    print("allow_readonly_paths 2: start")

    not p_oci.Linux.ReadonlyPaths
    not i_oci.Linux.ReadonlyPaths

    print("allow_readonly_paths 2: true")
}

# All the policy readonly paths must be either:
# - Present in the input readonly paths, or
# - Present in the input masked paths.
# Input is allowed to have more readonly paths than the policy.
allow_readonly_paths_array(p_array, i_array, masked_paths) if {
    every p_elem in p_array {
        allow_readonly_path(p_elem, i_array, masked_paths)
    }
}

allow_readonly_path(p_elem, i_array, masked_paths) if {
    print("allow_readonly_path 1: p_elem =", p_elem)

    some i_elem in i_array
    p_elem == i_elem

    print("allow_readonly_path 1: true")
}
allow_readonly_path(p_elem, i_array, masked_paths) if {
    print("allow_readonly_path 2: p_elem =", p_elem)

    some i_masked in masked_paths
    p_elem == i_masked

    print("allow_readonly_path 2: true")
}

allow_linux_devices(p_devices, i_devices) if {
    print("allow_linux_devices: start")
    every i_device in i_devices {
        print("allow_linux_devices: i_device =", i_device)
        some p_device in p_devices
        i_device.Path == p_device.Path
    }
    print("allow_linux_devices: true")
}

allow_linux_sysctl(p_linux, i_linux) if {
    print("allow_linux_sysctl 1: start")
    not i_linux.Sysctl
    print("allow_linux_sysctl 1: true")
}

allow_linux_sysctl(p_linux, i_linux) if {
    print("allow_linux_sysctl 2: start")
    p_sysctl := p_linux.Sysctl
    i_sysctl := i_linux.Sysctl
    every i_name, i_val in i_sysctl {
        print("allow_linux_sysctl 2: i_name =", i_name, "i_val =", i_val)
        p_sysctl[i_name] == i_val
    }
    print("allow_linux_sysctl 2: true")
}

# Check the consistency of the input "io.katacontainers.pkg.oci.bundle_path"
# and io.kubernetes.cri.sandbox-id" values with other fields.
allow_by_bundle_or_sandbox_id(p_oci, i_oci, p_storages, i_storages) if {
    print("allow_by_bundle_or_sandbox_id: start")

    key := "io.kubernetes.cri.sandbox-id"

    p_regex := p_oci.Annotations[key]
    sandbox_id := i_oci.Annotations[key]

    print("allow_by_bundle_or_sandbox_id: sandbox_id =", sandbox_id, "regex =", p_regex)
    regex.match(p_regex, sandbox_id)

    i_root := i_oci.Root.Path
    p_root_pattern1 := p_oci.Root.Path
    p_root_pattern2 := replace(p_root_pattern1, "$(root_path)", policy_data.common.root_path)
    # Bundle path segment can be a 64-char hex (OCI bundle ID) or the runtime's container/bundle identifier used in paths (e.g. short ID or CRI container ID).
    p_root_pattern3 := replace(p_root_pattern2, "$(bundle-id)", "([0-9a-f]{64}|[a-z0-9][a-z0-9.-]*)")
    print("allow_by_bundle_or_sandbox_id: i_root =", i_root, "regex =", p_root_pattern3)

    # Verify that the root path matches the substituted pattern and extract the bundle-id.
    bundle_id := regex.find_all_string_submatch_n(p_root_pattern3, i_root, 1)[0][1]

    # Match each input mount with a Policy mount.
    # Reject possible attempts to match multiple input mounts with a single Policy mount.
    #
    # FR-1o: mounts a signed fragment is authorized to contribute are set aside first, and
    # the bijection below is then required of what remains. Adding them to the candidate
    # set instead would not work: `allow_mount` returns an *index into p_oci.Mounts*, and
    # the count check depends on those indices being distinct, so a fragment mount would
    # either have to invent an index that cannot collide with a real one or silently
    # collapse two matches into one. Excusing them keeps the base check exactly as it was
    # and confines the new surface to `fragment_mount_permitted`.
    i_fragment_mounts := {i_index |
        some i_index, i_mount in i_oci.Mounts
        fragment_mount_permitted(p_oci, i_mount)
    }
    i_base_mounts := [i_mount |
        some i_index, i_mount in i_oci.Mounts
        not i_index in i_fragment_mounts
    ]
    print("allow_by_bundle_or_sandbox_id: fragment mounts =", count(i_fragment_mounts))

    p_matches := { p_index | some i_index; p_index = allow_mount(p_oci, i_base_mounts[i_index], i_storages, bundle_id, sandbox_id) }

    print("allow_by_bundle_or_sandbox_id: p_matches =", p_matches)
    count(p_matches) == count(i_base_mounts)

    # Every presented mount must claim a distinct destination.
    #
    # The check above is an injection from presented mounts into Policy mounts, not a
    # bijection: it rejects two presented mounts collapsing onto one Policy mount, but it
    # does not require every Policy mount to be presented and it says nothing about order.
    # So wherever the Policy holds two entries for one destination -- which genpolicy emits
    # deliberately for a shared-fs emptyDir, as two alternative sources for one path -- the
    # host could satisfy both at once and stack them, and the later mount would be the one
    # the container actually sees. Requiring the destinations to be distinct removes that
    # choice: a container sees exactly one mount per path, whichever alternative was used.
    #
    # This is the constraint hcsshim enforces statefully -- `plan9_mount` refuses a target
    # already recorded in `data.metadata.p9mounts` -- and it costs nothing here, because a
    # runtime presenting two mounts for one destination is presenting a shadowed mount.
    mount_destinations_are_distinct(i_oci)

    allow_storages(p_storages, i_storages, bundle_id, sandbox_id, p_oci)

    print("allow_by_bundle_or_sandbox_id: true")
}

mount_destinations_are_distinct(i_oci) if {
    i_destinations := {i_destination |
        some i_mount in i_oci.Mounts
        i_destination := i_mount.destination
    }
    print("mount_destinations_are_distinct: distinct =", count(i_destinations), "presented =", count(i_oci.Mounts))
    count(i_destinations) == count(i_oci.Mounts)
}

allow_process_common(p_process, i_process, s_name, s_namespace) if {    print("allow_process_common: p_process =", p_process)
    print("allow_process_common: i_process = ", i_process)
    print("allow_process_common: s_name =", s_name)

    p_process.Cwd == i_process.Cwd
    p_process.NoNewPrivileges == i_process.NoNewPrivileges

    allow_user(p_process, i_process)
    allow_env(p_process, i_process, s_name, s_namespace)

    print("allow_process_common: true")
}

# Compare the OCI Process field of a policy container with the input OCI Process from a CreateContainerRequest
allow_process(p_process, i_process, s_name, s_namespace) if {
    print("allow_process: start")

    allow_args(p_process, i_process, s_name)
    allow_process_common(p_process, i_process, s_name, s_namespace)
    allow_caps(p_process.Capabilities, i_process.Capabilities)
    p_process.Terminal == i_process.Terminal
    allow_process_fields_fr16(p_process, i_process)

    print("allow_process: true")
}

# Enforce OCI Process security fields that the host forwards from the CRI/kubelet
# but that were previously left unconstrained by the policy: ApparmorProfile and
# Rlimits.
#
# - Rlimits are exact-matched (as a set) against the policy-modeled value
#   (defaulting to empty), so a compromised host cannot silently relax them.
# - ApparmorProfile is exact-matched only when the policy models an expected
#   value (i.e. the pod spec pins a Localhost/Unconfined profile, or an operator
#   configures a cluster default). When unmodeled the field is absent from the
#   policy and left unconstrained, because the profile emitted for the
#   RuntimeDefault case depends on host apparmor state, which is not derivable
#   from the pod spec.
#
# OOMScoreAdj is intentionally not enforced here: kubelet computes it from the
# pod QoS class and node memory, so its value is environment-derived and not
# predictable at policy-generation time; it only influences OOM-kill ordering
# and is not a container-sandbox integrity boundary.
allow_process_fields_fr16(p_process, i_process) if {
    p_rlimits := {r | some r in object.get(p_process, "Rlimits", [])}
    i_rlimits := {r | some r in object.get(i_process, "Rlimits", [])}
    print("allow_process_fields_fr16: policy rlimits =", p_rlimits, "input rlimits =", i_rlimits)
    p_rlimits == i_rlimits

    allow_apparmor_profile(p_process, i_process)

    print("allow_process_fields_fr16: true")
}

# No expected apparmor profile modeled -> unconstrained.
allow_apparmor_profile(p_process, _) if {
    not p_process.ApparmorProfile
    print("allow_apparmor_profile: not modeled, allow")
}

# Expected apparmor profile modeled -> exact match against the input.
allow_apparmor_profile(p_process, i_process) if {
    p_apparmor := p_process.ApparmorProfile
    i_apparmor := object.get(i_process, "ApparmorProfile", "")
    print("allow_apparmor_profile: policy =", p_apparmor, "input =", i_apparmor)
    p_apparmor == i_apparmor
}

# Compare the OCI Process field of a policy container with the input process field from ExecProcessRequest
allow_interactive_process(p_process, i_process, s_name, s_namespace) if {
    print("allow_interactive_process: start")

    allow_process_common(p_process, i_process, s_name, s_namespace)
    allow_exec_caps(i_process.Capabilities)

    # These are commands enabled using ExecProcessRequest commands and/or regex from the settings file.
    # They can be executed interactively so allow them to use any value for i_process.Terminal.

    print("allow_interactive_process: true")
}

# Compare the OCI Process field of a policy container with the input process field from ExecProcessRequest
allow_probe_process(p_process, i_process, s_name, s_namespace) if {
    print("allow_probe_process: start")

    allow_process_common(p_process, i_process, s_name, s_namespace)
    allow_exec_caps(i_process.Capabilities)
    p_process.Terminal == i_process.Terminal

    print("allow_probe_process: true")
}

allow_user(p_process, i_process) if {
    p_user := p_process.User
    i_user := i_process.User

    print("allow_user: input uid =", i_user.UID, "policy uid =", p_user.UID)
    p_user.UID == i_user.UID

    print("allow_user: input gid =", i_user.GID, "policy gid =", p_user.GID)
    p_user.GID == i_user.GID

    print("allow_user: input additionalGids =", i_user.AdditionalGids, "policy additionalGids =", p_user.AdditionalGids)
    {e | some e in p_user.AdditionalGids} == {e | some e in i_user.AdditionalGids}
}

allow_args(p_process, i_process, s_name) if {
    print("allow_args 1: no args")

    not p_process.Args
    not i_process.Args

    print("allow_args 1: true")
}
allow_args(p_process, i_process, s_name) if {
    print("allow_args 2: policy args =", p_process.Args)
    print("allow_args 2: input args =", i_process.Args)

    count(p_process.Args) == count(i_process.Args)

    every i, i_arg in i_process.Args {
        allow_arg(i, i_arg, p_process, s_name)
    }

    print("allow_args 2: true")
}
allow_arg(i, i_arg, p_process, s_name) if {
    p_arg := p_process.Args[i]
    print("allow_arg 1: i =", i, "i_arg =", i_arg, "p_arg =", p_arg)

    p_arg2 := replace(p_arg, "$$", "$")
    p_arg2 == i_arg

    print("allow_arg 1: true")
}
allow_arg(i, i_arg, p_process, s_name) if {
    p_arg := p_process.Args[i]
    print("allow_arg 2: i =", i, "i_arg =", i_arg, "p_arg =", p_arg)

    # TODO: can $(node-name) be handled better?
    contains(p_arg, "$(node-name)")

    print("allow_arg 2: true")
}
allow_arg(i, i_arg, p_process, s_name) if {
    p_arg := p_process.Args[i]
    print("allow_arg 3: i =", i, "i_arg =", i_arg, "p_arg =", p_arg)

    p_arg2 := replace(p_arg, "$$", "$")
    p_arg3 := replace(p_arg2, "$(sandbox-name)", s_name)
    print("allow_arg 3: p_arg3 =", p_arg3)
    p_arg3 == i_arg

    print("allow_arg 3: true")
}

# OCI process.Env field
allow_env(p_process, i_process, s_name, s_namespace) if {
    print("allow_env: p env =", p_process.Env)
    print("allow_env: i env =", i_process.Env)

    every i_var in i_process.Env {
        print("allow_env: i_var =", i_var)
        allow_var(p_process, i_process, i_var, s_name, s_namespace)
    }

    print("allow_env: true")
}

# Allow input env variables that are present in the policy data too.
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    some p_var in p_process.Env
    p_var == i_var
    print("allow_var 1: true")
}

# Match input with one of the policy variables, after substituting $(sandbox-name).
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    some p_var in p_process.Env
    p_var2 := replace(p_var, "$(sandbox-name)", s_name)

    print("allow_var 2: p_var =", p_var)

    p_var_split := split(p_var, "=")
    count(p_var_split) == 2

    p_var_split[1] == "$(sandbox-name)"

    i_var_split := split(i_var, "=")
    count(i_var_split) == 2

    i_var_split[0] == p_var_split[0]
    regex.match(s_name, i_var_split[1])

    print("allow_var 2: true")
}

# Allow input env variables that match with a request_defaults regex.
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    some p_regex1 in policy_data.request_defaults.CreateContainerRequest.allow_env_regex
    p_regex2 := replace(p_regex1, "$(ipv4_a)", policy_data.common.ipv4_a)
    p_regex3 := replace(p_regex2, "$(ip_p)", policy_data.common.ip_p)
    p_regex4 := replace(p_regex3, "$(svc_name_downward_env)", policy_data.common.svc_name_downward_env)
    p_regex5 := replace(p_regex4, "$(dns_label)", policy_data.common.dns_label)

    print("allow_var 3: p_regex5 =", p_regex5)
    regex.match(p_regex5, i_var)

    print("allow_var 3: true")
}

# Allow fieldRef "fieldPath: status.podIP" values.
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    name_value := split(i_var, "=")
    count(name_value) == 2
    is_ip(name_value[1])

    some p_var in p_process.Env
    allow_pod_ip_var(name_value[0], p_var)

    print("allow_var 4: true")
}

# Allow common fieldRef variables.
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    name_value := split(i_var, "=")
    count(name_value) == 2

    some p_var in p_process.Env
    p_name_value := split(p_var, "=")
    count(p_name_value) == 2

    p_name_value[0] == name_value[0]

    # TODO: should these be handled in a different way?
    always_allowed := ["$(host-name)", "$(node-name)", "$(pod-uid)"]
    some allowed in always_allowed
    contains(p_name_value[1], allowed)

    print("allow_var 5: true")
}

# Allow fieldRef "fieldPath: status.hostIP" values.
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    name_value := split(i_var, "=")
    count(name_value) == 2
    is_ip(name_value[1])

    some p_var in p_process.Env
    allow_host_ip_var(name_value[0], p_var)

    print("allow_var 6: true")
}

# Allow resourceFieldRef values (e.g., "limits.cpu").
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    name_value := split(i_var, "=")
    count(name_value) == 2

    some p_var in p_process.Env
    p_name_value := split(p_var, "=")
    count(p_name_value) == 2

    p_name_value[0] == name_value[0]

    # TODO: should these be handled in a different way?
    always_allowed = ["$(resource-field)", "$(todo-annotation)"]
    some allowed in always_allowed
    contains(p_name_value[1], allowed)

    print("allow_var 7: true")
}

allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    some p_var in p_process.Env
    p_var2 := replace(p_var, "$(sandbox-namespace)", s_namespace)

    print("allow_var 8: p_var2 =", p_var2)
    p_var2 == i_var

    print("allow_var 8: true")
}

# FR-1n: allow an input env variable admitted by an `env_rules` entry that a trusted
# fragment contributes, within a ceiling the measured base policy declares.
#
# This is the Kata-CC form of hcsshim's `platform_rules`. The problem both solve is that a
# deployment pipeline is not static: a given version of the API server, kubelet or
# containerd may inject a variable the policy author never wrote down, and a feature flag
# may be turned on by a pipeline stage rather than by the workload manifest. Without a
# delegation path the only way to admit such a variable is to regenerate and re-measure the
# base policy, which means the security boundary has to be re-established for a change that
# was never about security.
#
# hcsshim answers this by letting an included fragment carry env rules that apply across
# every container. That is effective but unbounded: including the fragment hands it the
# whole environment namespace, and nothing in the base policy limits which variables it may
# speak for. Here the base policy states the ceiling — a set of name patterns, per declared
# (issuer, feed) — and the fragment supplies concrete rules inside it. Omitting the ceiling
# delegates nothing, so this arm cannot be reached by any policy that has not deliberately
# opted in; writing "^.+$" reproduces hcsshim's behaviour exactly. Both ends are available
# and the default end is closed.
#
# Three properties make the ceiling actually hold rather than merely look like it does:
#
#   * The fragment's rule names a *literal* variable, and the ceiling is checked against
#     that literal. A ceiling expressed over whole rules could not be enforced -- deciding
#     whether one regex admits a subset of another is undecidable in general -- so the
#     grant is over names, where an exact test exists.
#   * Every pattern is matched fully anchored, on both sides. Rego's `regex.match` is an
#     unanchored search, so a ceiling of "FEATURE_FLAG" would otherwise admit
#     "EVIL_FEATURE_FLAG_X", and a value pattern of "true" would admit "untrue".
#   * `fragment_env_name_permitted` requires the name to be permitted by *every* base
#     declaration naming that (issuer, feed), and requires at least one to exist. Using
#     `some spec` would be an existential, so a stale, laxer duplicate declaration would
#     win; this mirrors the strictest-wins rule `svn_floor` applies to rollback floors.
#     It also means a feed that exists only because another fragment delegated to it has no
#     ceiling at all and therefore contributes no env rules -- delegation cannot manufacture
#     env-rule authority the measured policy never granted.
allow_var(p_process, i_process, i_var, s_name, s_namespace) if {
    # Split on the *first* "=" only. The `split(i_var, "=")` / `count == 2` idiom the arms
    # above use silently refuses any value that itself contains an "=" -- base64 payloads,
    # connection strings, JWTs -- which is a common shape for a pipeline-injected variable.
    # POSIX has the name end at the first "=" with the value being the whole remainder.
    eq := indexof(i_var, "=")
    eq > 0
    name := substring(i_var, 0, eq)
    value := substring(i_var, eq + 1, -1)

    some feed, mod in data.agent_policy.fragments
    to_number(mod.svn) >= svn_floor(mod.issuer, feed)

    fragment_env_name_permitted(mod.issuer, feed, name)

    some rule in mod.env_rules
    rule.name == name
    fragment_env_value_matches(rule, value)

    print("allow_var 9: true")
}

# The ceiling: the name must be permitted by every measured base declaration naming this
# (issuer, feed), and there must be at least one such declaration. A declaration that omits
# `allow_env_rules` contributes an empty pattern list, which matches nothing, so a single
# declaration without the grant closes the door for the whole feed.
fragment_env_name_permitted(issuer, feed, name) if {
    specs := [spec |
        some spec in all_fragment_specs
        spec.issuer == issuer
        spec.feed == feed
    ]
    count(specs) > 0

    every spec in specs {
        some pattern in object.get(spec, "allow_env_rules", [])
        regex.match(fragment_anchored(pattern), name)
    }
}

# Anchor a pattern to the whole string. Nesting anchors an author already wrote -- turning
# "^X$" into "^(?:^X$)$" -- is harmless in RE2 and means the wrapping is unconditional
# rather than conditional on parsing the pattern, which is the part that could be got wrong.
# Shared by the env-rule and mount-rule ceilings: both delegate by pattern, so both depend
# on the same property, and having one definition means it cannot hold for one and not the
# other.
fragment_anchored(pattern) := concat("", ["^(?:", pattern, ")$"])

# A rule's value is a literal by default. hcsshim's equivalent field takes a strategy with
# no safe default, and reading "string" as though it meant "regex" is a mistake that is easy
# to make and invisible when made: the rule simply never matches, or -- with an unanchored
# pattern -- matches far more than intended. Defaulting to literal equality makes the quiet
# outcome the safe one and reserves regex for authors who ask for it by name.
fragment_env_value_matches(rule, value) if {
    not rule.value_strategy
    rule.value == value
}

fragment_env_value_matches(rule, value) if {
    rule.value_strategy == "string"
    rule.value == value
}

fragment_env_value_matches(rule, value) if {
    rule.value_strategy == "re2"
    regex.match(fragment_anchored(rule.value), value)
}

allow_pod_ip_var(var_name, p_var) if {
    print("allow_pod_ip_var: var_name =", var_name, "p_var =", p_var)

    p_name_value := split(p_var, "=")
    count(p_name_value) == 2

    p_name_value[0] == var_name
    p_name_value[1] == "$(pod-ip)"

    print("allow_pod_ip_var: true")
}

allow_host_ip_var(var_name, p_var) if {
    print("allow_host_ip_var: var_name =", var_name, "p_var =", p_var)

    p_name_value := split(p_var, "=")
    count(p_name_value) == 2

    p_name_value[0] == var_name
    p_name_value[1] == "$(host-ip)"

    print("allow_host_ip_var: true")
}

is_ip(value) if {
    bytes = split(value, ".")
    count(bytes) == 4

    is_ip_first_byte(bytes[0])
    is_ip_other_byte(bytes[1])
    is_ip_other_byte(bytes[2])
    is_ip_other_byte(bytes[3])
}
is_ip_first_byte(component) if {
    number = to_number(component)
    number >= 1
    number <= 255
}
is_ip_other_byte(component) if {
    number = to_number(component)
    number >= 0
    number <= 255
}

allow_mount(p_oci, i_mount, i_storages, bundle_id, sandbox_id):= p_index if {
    print("-------- allow_mount 1: i_mount =", i_mount)

    some p_index, p_mount in p_oci.Mounts

    print("allow_mount 1: p_mount =", p_mount)
    check_mount(p_mount, i_mount, bundle_id, sandbox_id)

    print("allow_mount 1: true, p_index =", p_index)
}
allow_mount(p_oci, i_mount, i_storages, bundle_id, sandbox_id):= p_index if {
    print("-------- allow_mount 2: i_mount =", i_mount)

    some p_index, p_mount in p_oci.Mounts
    print("allow_mount 2: p_mount =", p_mount)

    p_mount.destination == i_mount.destination
    p_mount.type_ == i_mount.type_
    p_mount.options == i_mount.options

    some i_storage in i_storages
    print("allow_mount 2: i_storage =", i_storage)

    i_storage.mount_point == i_mount.source

    print("allow_mount 2: true, p_index =", p_index)
}

check_mount(p_mount, i_mount, bundle_id, sandbox_id) if {
    p_mount == i_mount
    print("check_mount 1: true")
}
check_mount(p_mount, i_mount, bundle_id, sandbox_id) if {
    p_mount.destination == i_mount.destination
    p_mount.type_ == i_mount.type_
    p_mount.options == i_mount.options

    mount_source_allows(p_mount, i_mount, bundle_id, sandbox_id)

    print("check_mount 2: true")
}
check_mount(p_mount, i_mount, bundle_id, sandbox_id) if {
    # This check passes if the policy container has RW, the input container has
    # RO and the volume type is sysfs, working around different handling of
    # privileged containers after containerd 2.0.4.
    i_mount.type_ == "sysfs"
    p_mount.type_ == i_mount.type_
    p_mount.destination == i_mount.destination
    p_mount.source == i_mount.source

    i_options := {x | x = i_mount.options[_]} | {"rw"}
    p_options := {x | x = p_mount.options[_]} | {"ro"}
    p_options == i_options

    print("check_mount 3: true")
}
check_mount(p_mount, i_mount, bundle_id, sandbox_id) if {
    # Unified cgroup v2 mounts on newer kernels may add flags genpolicy does not
    # embed (e.g. nsdelegate, memory_recursiveprot). Allow extras listed in
    # policy_data.cluster_config.cgroup_mount_extras_allowed (from genpolicy-settings.json).
    i_mount.type_ == "cgroup"
    p_mount.type_ == "cgroup"
    p_mount.destination == i_mount.destination
    p_mount.source == i_mount.source

    allowed_extras := {x | x = policy_data.cluster_config.cgroup_mount_extras_allowed[_]}

    p_opts := {x | x = p_mount.options[_]}
    i_opts := {x | x = i_mount.options[_]}
    every opt in p_mount.options {
        opt in i_opts
    }

    extras := i_opts - p_opts
    every extra in extras {
        extra in allowed_extras
    }

    mount_source_allows(p_mount, i_mount, bundle_id, sandbox_id)

    print("check_mount 4: true")
}
check_mount(p_mount, i_mount, bundle_id, sandbox_id) if {
    print("check_mount 5: i_mount.type_ = ", i_mount.type_)

    p_mount.destination == i_mount.destination
    i_mount.type_ == "bind-safer-path"
    p_mount.type_ == "bind"
    p_mount.options == i_mount.options

    mount_source_allows(p_mount, i_mount, bundle_id, sandbox_id)

    print("check_mount 5: true")
}

mount_source_allows(p_mount, i_mount, bundle_id, sandbox_id) if {
    regex1 := p_mount.source
    print("mount_source_allows 1: regex1 =", regex1)

    regex2 := replace(regex1, "$(sfprefix)", policy_data.common.sfprefix)
    print("mount_source_allows 1: regex2 =", regex2)

    regex3 := replace(regex2, "$(cpath)", policy_data.common.cpath)
    print("mount_source_allows 1: regex3 =", regex3)

    regex4 := replace(regex3, "$(bundle-id)", bundle_id)
    print("mount_source_allows 1: regex4 =", regex4)
    regex.match(regex4, i_mount.source)

    print("mount_source_allows 1: true")
}
mount_source_allows(p_mount, i_mount, bundle_id, sandbox_id) if {
    regex1 := p_mount.source
    print("mount_source_allows 2: regex1 =", regex1)

    regex2 := replace(regex1, "$(sfprefix)", policy_data.common.sfprefix)
    print("mount_source_allows 2: regex2 =", regex2)

    regex3 := replace(regex2, "$(cpath)", policy_data.common.cpath)
    print("mount_source_allows 2: regex3 =", regex3)

    regex4 := replace(regex3, "$(sandbox-id)", sandbox_id)
    print("mount_source_allows 2: regex4 =", regex4)
    regex.match(regex4, i_mount.source)

    print("mount_source_allows 2: true")
}
mount_source_allows(p_mount, i_mount, bundle_id, sandbox_id) if {
    i_mount.type_ == "bind-safer-path"
    p_mount.type_ == "bind"

    print("mount_source_allows 3: true")
}

# FR-1o: a mount a signed fragment contributes, within a ceiling the measured base policy
# declares. The mount half of hcsshim's `platform_rules`; the env half is `allow_var` arm 9.
#
# The motivation is the same drift problem: a deployment pipeline may attach a mount the
# policy author never wrote down -- a projected token path a newer kubelet adds, a CSI
# driver's directory, an observability socket a cluster-wide admission webhook injects.
# Without a delegation path the only remedy is to regenerate and re-measure the base policy.
#
# Three differences from hcsshim's model, all in the direction of a tighter bound:
#
#   * hcsshim concatenates a fragment's platform mounts onto the container's mount list
#     unconditionally, so including the fragment grants it the whole mount namespace. Here
#     the base policy names the destinations it will let a feed speak for, and a declaration
#     that omits `allow_mount_rules` delegates nothing -- the closed default again.
#   * A fragment may only *add* a destination, never restate one the base policy already
#     declares (`fragment_mount_is_new`). Otherwise a fragment could shadow a base mount
#     with a laxer one -- declaring /data read-only in the measured policy would count for
#     nothing if a fragment could re-admit /data read-write -- and the weakening would be
#     invisible, because the base declaration would still be sitting there saying "ro".
#     Fragments extend the mount set; they cannot rewrite it.
#   * Options must match exactly rather than by subset, and a rule that omits `options`
#     therefore admits only a mount with none. Mount options are the security-relevant part
#     of a mount -- ro/rw, nosuid, nodev, noexec -- so "close enough" is the wrong default.
fragment_mount_permitted(p_oci, i_mount) if {
    some feed, mod in data.agent_policy.fragments
    to_number(mod.svn) >= svn_floor(mod.issuer, feed)

    fragment_mount_destination_permitted(mod.issuer, feed, i_mount.destination)
    fragment_mount_is_new(p_oci, i_mount.destination)

    some rule in mod.mount_rules
    # The destination is compared literally, which is what makes the ceiling above an exact
    # test rather than a regex-subset question. Same argument as the env rule's `name`.
    rule.destination == i_mount.destination
    rule.type_ == i_mount.type_
    fragment_mount_source_matches(rule, i_mount.source)
    fragment_mount_options_match(rule, i_mount.options)

    print("fragment_mount_permitted: true for", i_mount.destination)
}

# The ceiling: the destination must be permitted by every measured base declaration naming
# this (issuer, feed), and at least one must exist. `every` rather than `some` for the same
# reason as the env ceiling -- an existential would let a stale, laxer duplicate declaration
# win -- and the "at least one" requirement means a feed reachable only through delegation
# has no ceiling and so contributes no mounts.
fragment_mount_destination_permitted(issuer, feed, destination) if {
    specs := [spec |
        some spec in all_fragment_specs
        spec.issuer == issuer
        spec.feed == feed
    ]
    count(specs) > 0

    every spec in specs {
        some pattern in object.get(spec, "allow_mount_rules", [])
        regex.match(fragment_anchored(pattern), destination)
    }
}

# A fragment may not speak for a destination the base policy already declares.
fragment_mount_is_new(p_oci, destination) if {
    every p_mount in p_oci.Mounts {
        p_mount.destination != destination
    }
}

# Literal by default, regex only when asked for by name -- as for env rule values, so that
# a misread strategy fails closed rather than matching more than intended.
fragment_mount_source_matches(rule, source) if {
    not rule.source_strategy
    rule.source == source
}

fragment_mount_source_matches(rule, source) if {
    rule.source_strategy == "string"
    rule.source == source
}

fragment_mount_source_matches(rule, source) if {
    rule.source_strategy == "re2"
    regex.match(fragment_anchored(rule.source), source)
}

fragment_mount_options_match(rule, i_options) if {
    {x | some x in object.get(rule, "options", [])} == {x | some x in i_options}
}

######################################################################
# Create container Storages

allow_storages(p_storages, i_storages, bundle_id, sandbox_id, p_oci) if {
    print("allow_storages: p_storages =", p_storages)
    print("allow_storages: i_storages =", i_storages)

    p_count := count(p_storages)
    i_count := count(i_storages)
    img_pull_count := count([s | s := i_storages[_]; s.driver == "image_guest_pull"])
    print("allow_storages: p_count =", p_count, "i_count =", i_count, "img_pull_count =", img_pull_count)

    p_count == i_count - img_pull_count

    # FR-4A: the presented storages must be a *bijection* of the declared ones, not
    # merely an equal-sized set in which every presented storage happens to match some
    # declaration. Count equality plus an existential match alone accepts a request that
    # presents one declared storage twice while never presenting another: the counts
    # still balance and both duplicates satisfy the same declaration. The two checks
    # below close that, in both directions.
    #
    # 1. No presented storage may repeat another's identity.
    #
    # RM-41: [driver, source, mount_point] alone is not an identity for EROFS image
    # layers. runtime-rs attaches *one* block device spanning every layer's GPT
    # partition and clones it per partition, so all N of a container's lower layers
    # present the same driver, the same guest device path and the same mount point;
    # only the partition number and the dm-verity parameters differ. Without a
    # discriminator this check would reject every multi-layer image outright, and were
    # the count check ever relaxed it would also stop distinguishing "N distinct layers"
    # from "the same layer N times". The root hash is the natural discriminator: it is
    # what makes one layer a different layer from another.
    storage_identities := {storage_identity(s) | some s in i_storages}
    print("allow_storages: distinct identities =", count(storage_identities))
    count(storage_identities) == i_count

    # 2. Every presented storage is covered by a declaration (as before) ...
    every i_storage in i_storages {
        allow_storage(p_storages, i_storage, bundle_id, sandbox_id, p_oci)
    }

    # ... and every declaration is covered by a presented storage, so no declared
    # storage can be silently dropped in favour of a duplicate of another.
    every p_storage in p_storages {
        storage_is_presented(p_storage, i_storages, bundle_id, sandbox_id)
    }

    print("allow_storages: true")
}

# FR-4A: the reverse direction of allow_storage — is this *declaration* satisfied by
# some presented storage? Together with the count check and the duplicate rejection in
# allow_storages this makes the declared/presented relation a bijection.
storage_is_presented(p_storage, i_storages, bundle_id, sandbox_id) if {
    some i_storage in i_storages
    storage_pair_matches(p_storage, i_storage, bundle_id, sandbox_id)
    print("storage_is_presented: true for", p_storage)
}

allow_storage(p_storages, i_storage, bundle_id, sandbox_id, p_oci) if {
    some p_storage in p_storages

    print("allow_storage: p_storage =", p_storage)
    print("allow_storage: i_storage =", i_storage)

    storage_pair_matches(p_storage, i_storage, bundle_id, sandbox_id)

    print("allow_storage: true")
}

# Pairwise storage match: does this single declaration admit this single presented
# storage? Factored out of allow_storage so that the same relation can be evaluated in
# the declaration -> presented direction by storage_is_presented. The three bodies below
# mirror the three p_storage-consuming allow_storage variants exactly.
storage_pair_matches(p_storage, i_storage, bundle_id, sandbox_id) if {
    p_storage.driver == i_storage.driver
    allow_storage_source(p_storage, i_storage, bundle_id)
    allow_storage_base(p_storage, i_storage, bundle_id, sandbox_id)
}
storage_pair_matches(p_storage, i_storage, bundle_id, sandbox_id) if {
    i_storage.driver == "scsi"
    regex.match("^[0-9]+:[0-9]+$", i_storage.source)
    allow_host_chosen_device(p_storage)
    allow_storage_base(p_storage, i_storage, bundle_id, sandbox_id)
}
storage_pair_matches(p_storage, i_storage, bundle_id, sandbox_id) if {
    i_storage.driver == "blk"
    regex.match("^[0-9a-f]{2}(/[0-9a-f]{2})?$", i_storage.source)
    allow_host_chosen_device(p_storage)
    allow_storage_base(p_storage, i_storage, bundle_id, sandbox_id)
}

# RM-38: a dm-verity backed EROFS image layer.
#
# In unmerged mode each image layer is its own erofs image, presented as one GPT
# partition of a single block device. Neither the block driver nor the guest device path
# is predictable at policy generation time, so — as with the host-chosen emptyDir
# devices above — the declaration cannot name them and instead carries the marker driver
# "erofs-verity-layer". This body then checks everything that *is* predictable and
# constrains the shape of the rest.
#
# The security-relevant part is the option handling. Every declared option must be
# present, and every *extra* presented option must be one of the dm-verity parameters
# whose value is assigned at runtime. That inverted check is what makes the rule safe:
# it means a host cannot bolt an unrecognised X-kata option (say, one that disables
# verification, or an overlay-upper marker) onto a layer that the policy believes is a
# read-only verity-protected lower layer.
storage_pair_matches(p_storage, i_storage, bundle_id, sandbox_id) if {
    print("storage_pair_matches erofs: start")

    p_storage.driver == "erofs-verity-layer"

    # Presented as a block device whose id the host chose.
    i_storage.driver in erofs_block_drivers

    p_storage.driver_options == i_storage.driver_options
    p_storage.fs_group == i_storage.fs_group

    # protobuf omits false booleans from some JSON encodings, so read defensively.
    object.get(i_storage, "shared", false) == false
    object.get(p_storage, "shared", false) == false

    p_storage.fstype == i_storage.fstype
    p_storage.fstype == "erofs"

    allow_erofs_layer_mount_point(p_storage, i_storage, bundle_id)
    allow_erofs_verity_options(p_storage, i_storage)

    print("storage_pair_matches erofs: true")
}

# The layer mounts under the container's own bundle directory. Pinning it here is what
# stops a layer from being redirected at another container's rootfs, or at a sandbox
# path: bundle_id is taken from the request being evaluated, not from the storage.
allow_erofs_layer_mount_point(p_storage, i_storage, bundle_id) if {
    mount1 := p_storage.mount_point
    mount2 := replace(mount1, "$(cpath)", policy_data.common.cpath)
    mount3 := replace(mount2, "$(bundle-id)", bundle_id)

    print("allow_erofs_layer_mount_point: regex =", mount3)
    regex.match(mount3, i_storage.mount_point)
}

erofs_block_drivers := {"blk", "scsi", "mmioblk", "nvdimm", "local"}

allow_erofs_verity_options(p_storage, i_storage) if {
    print("allow_erofs_verity_options: p_options =", p_storage.options)
    print("allow_erofs_verity_options: i_options =", i_storage.options)

    # No option may be repeated: a set built from the presented options would otherwise
    # let a duplicate stand in for a required distinct one.
    count({o | some o in i_storage.options}) == count(i_storage.options)

    # Every declared option is present, verbatim.
    every p_option in p_storage.options {
        p_option in i_storage.options
    }

    # The layer must actually be verity backed. This is redundant with the declaration
    # (genpolicy always emits it) but is stated here so the rule remains correct if a
    # declaration is ever hand-edited.
    "X-kata.dmverity-enabled=true" in i_storage.options

    # Exactly one root hash must be present among the runtime-assigned options.
    #
    # "At least one" is not enough: the duplicate check above only rejects options that
    # are byte-identical, so a storage could carry both the declared root hash and a
    # second, different one. Which of the two the guest would act on is an
    # implementation detail of option parsing, and relying on it would be a way to
    # smuggle an undeclared hash past a policy that looks like it pinned one.
    #
    # The declaration carries `X-kata.dmverity.roothash=<hash>` (RM-42, derived by
    # rebuilding the layer's erofs image with containerd's own mkfs.erofs invocation),
    # the "every declared option is present" check above binds that exact value, and
    # this count makes it the only one — so the mounted layer is bound to the image the
    # policy was generated for.
    count([o | some o in i_storage.options; startswith(o, "X-kata.dmverity.roothash=")]) == 1

    # The *declaration* must pin a root hash too (RM-51). Without this, a declaration
    # that simply omitted the hash would still satisfy every check above: the presented
    # layer would be required to be verity backed and to carry exactly one root hash,
    # but that hash would be whatever the host chose. That used to be acceptable because
    # the guest cross-checked it against the measured initdata allowlist
    # (verified-layers.toml); that store is gone, so the policy is now the only thing
    # that says which content a layer may have, and it has to actually say it.
    # genpolicy always emits the hash and fails closed when it cannot derive one
    # (RM-47), so this only rejects a hand-edited or stale declaration.
    count([o | some o in p_storage.options; startswith(o, "X-kata.dmverity.roothash=")]) == 1

    # Anything the declaration did not ask for must be a runtime-assigned dm-verity
    # parameter of the expected shape.
    every i_option in i_storage.options {
        allow_erofs_extra_option(p_storage, i_option)
    }

    print("allow_erofs_verity_options: true")
}

allow_erofs_extra_option(p_storage, i_option) if {
    i_option in p_storage.options
}
allow_erofs_extra_option(_, i_option) if {
    erofs_verity_dynamic_option(i_option)
}

erofs_verity_dynamic_option(o) if regex.match("^X-kata\\.dmverity\\.roothash=[0-9a-f]{64}$", o)
erofs_verity_dynamic_option(o) if regex.match("^X-kata\\.dmverity\\.hashoffset=[0-9]+$", o)
erofs_verity_dynamic_option(o) if regex.match("^X-kata\\.dmverity\\.no-superblock=(true|false)$", o)
erofs_verity_dynamic_option(o) if regex.match("^X-kata\\.dmverity\\.salt=[0-9a-f]{2,128}$", o)

# RM-41: identity of a presented storage, for the duplicate check in allow_storages.
# The dm-verity root hash is appended so that the N lower layers of a multi-layer image
# — which necessarily share driver, source and mount point — are distinguished from one
# another. concat over a sorted array is total: it yields "" for the storages that carry
# no root hash, leaving their identity exactly as it was before.
storage_identity(s) := [s.driver, s.source, s.mount_point, verity_discriminator(s)]

verity_discriminator(s) := concat(",", sort([o |
    some o in object.get(s, "options", [])
    startswith(o, "X-kata.dmverity.roothash=")
]))

# RM-35: restrict the blk/scsi bodies above to declarations that actually opted into
# host-chosen block backing.
#
# Those two bodies exist because a device id -- a SCSI address or a PCI path -- is
# assigned at runtime and cannot be predicted when the policy is generated, so they
# key on the *presented* driver and check only the shape of the presented source.
# That is unavoidable for the source. What was avoidable is that they said nothing
# about p_storage: any declaration at all could be satisfied by a presented block
# device, including declarations written for `ephemeral`, `local` or `overlayfs`
# storage, whose author never contemplated a host-attached disk appearing in their
# place.
#
# Only two declarations are meant to be backed by a host-chosen device --
# emptyDir_encrypted and emptyDir_plain -- and both mark themselves the same way:
# an empty driver and an empty source (the generator cannot fill either), and a
# mount point derived from the device id rather than fixed. Requiring that marking
# turns "any declaration" into "a declaration that asked for this", which is the
# part of the binding that can be established at generation time.
#
# What this deliberately does NOT do is pin *which* device is presented. That is
# hcsshim's data.metadata.devices[path] property. Note the blocker is NOT that this
# policy lacks state -- it has some: `pstate` (see state_allows above) already records
# container_id -> authorizing policy container, the direct analogue of hcsshim's
# data.metadata.matches. The blocker is that hcsshim can record a device's identity
# because its *guest* produces one: it reads the dm-verity superblock off the device
# on every read-only mount and refuses the mount if it cannot. Kata's agent never
# measures a block device, so there is nothing trustworthy to record -- the only hash
# it ever sees arrives in host-supplied storage.options. Closing this therefore needs
# RM-31 (measure in the guest) and RM-34 (a declaration to compare against) first;
# state is already available. Tracked as RM-35's open half. The exact `options` and
# `driver_options` equality in allow_storage_base, the bijection in allow_storages,
# and `create_filesystem` on both surviving declarations (the agent formats the
# device, destroying whatever content the host put there) are what stand in the
# meantime.
allow_host_chosen_device(p_storage) if {
    print("allow_host_chosen_device: start")

    p_storage.driver == ""
    p_storage.source == ""
    contains(p_storage.mount_point, "$(b64_device_id)")

    print("allow_host_chosen_device: true")
}
allow_storage(p_storages, i_storage, bundle_id, sandbox_id, p_oci) if {
    i_storage.driver == "image_guest_pull"
    print("allow_storage with image_guest_pull: start")
    i_storage.fstype == "overlay"
    i_storage.fs_group == null
    i_storage.shared == false
    count(i_storage.options) == 0

    # RM-29: bind the pulled image to *this* container's declaration, and bind the
    # bundle it unpacks into to *this* container's id.
    #
    # This storage carries the container root filesystem, and it has no p_storage:
    # genpolicy emits no declaration for it, which is why it is subtracted from the
    # cardinality check above and why this body used to check nothing but shape. The
    # effect was that `source` -- the image reference -- and `mount_point` were entirely
    # host-chosen. Since the *process* spec is checked against this container's
    # declaration and the *root filesystem* was checked against nothing, the policy
    # authorized a set of images and a set of process specs and permitted any pairing
    # between them rather than the declared pairings.
    #
    # The declaration does name the image, in an annotation genpolicy fills from the pod
    # spec (policy.rs, "io.kubernetes.cri.image-name"), and the runtime builds `source`
    # from the same annotation (virtual_volume.rs::get_image_reference). Comparing the
    # presented source against the *declared* value -- not against the input annotation,
    # which is host-supplied and unconstrained -- is what binds code to container. It is
    # the property hcsshim gets from data.metadata.matches[input.containerID].
    #
    # Two guest-pull storages naming *different* images are refused here; two naming the
    # *same* image are refused by the distinct-identities check in allow_storages, since
    # the mount point is pinned below and their identities therefore coincide. So the
    # cardinality exemption can no longer admit a second root filesystem.
    allow_image_guest_pull_source(p_oci, i_storage)

    # The agent derives the unpack directory from the container id and ignores
    # mount_point entirely, so this is defence in depth rather than the load-bearing
    # check -- but a storage naming another container's bundle has no honest reason to
    # exist, and leaving it unconstrained is what let probe B pass.
    #
    # `root_path` is a regular expression, not a literal: it has to match both the
    # bare `/run/kata-containers/<id>/rootfs` a guest pull mounts and the
    # `shared/containers/passthrough/` form the host-erofs path presents. Comparing
    # it with `==` would test a mount point against a string still containing
    # `(?:...)?`, which nothing can equal, so this check could only ever fail and
    # guest pull would be denied outright. Match it as a regex, anchored at both
    # ends so a mount point may not merely contain the declared path. This mirrors
    # how the same setting is already consumed for `Root.Path` above, where it is
    # substituted into a pattern and matched with regex.find_all_string_submatch_n.
    p_mount_point := replace(policy_data.common.root_path, "$(bundle-id)", bundle_id)
    print("allow_storage with image_guest_pull: p_mount_point =", p_mount_point, "i_mount_point =", i_storage.mount_point)
    regex.match(sprintf("^%s$", [p_mount_point]), i_storage.mount_point)

    print("allow_storage with image_guest_pull: true")
}

# The image reference this container's declaration names. Digest-pinned references are
# compared by digest rather than by string, because the two sides spell the same image
# differently: genpolicy records the canonical reference from the registry
# (`ghcr.io/x/gid:latest@sha256:bdbb...`) while the runtime passes through the reference
# from the pod spec (`ghcr.io/x/gid@sha256:bdbb...`). Requiring string equality would
# deny every legitimate guest pull. The digest is also the *right* thing to compare: it
# is what pins content, and two references sharing a digest name the same bytes whatever
# the registry path says.
#
# RM-51: whether an unpinned reference is admitted at all is controlled by
# `require_pinned_image_digests`. Guest pull unpacks into the guest's own filesystem, so
# there is no read-only block device and no dm-verity root hash to bind — the manifest
# digest is the *only* thing that identifies the content, and pinning it transitively pins
# every layer digest the manifest lists. A tag names whatever the host decides to serve.
# The guest used to catch that separately, in VerifiedImageStore::authorize
# (ImageError::UnpinnedImage); that store is gone, so the requirement lives here now.
#
# RM-119: both bodies below are gated on `allow_guest_pull_images`, which ships **false**.
# Guest pull is the one storage path with no declaration behind it -- genpolicy emits no
# `p_storage`, which is why `allow_storages` subtracts it from the cardinality check --
# so a host may present an `image_guest_pull` storage *in addition to* a container's
# declared dm-verity layers. Every declaration is still satisfied and the extra storage
# is exempt from the count, so the request passes while a second, undeclared root
# filesystem is admitted. With an unpinned reference that is host-chosen content at the
# container root in a deployment whose layers are otherwise verity-bound: the guest-pull
# path sidesteps the host-pull integrity guarantee without ever failing a verity check.
# Refusing workload guest pull outright removes that, and removes a path whose content
# verification happens in image-rs inside CDH and is never reported back to the policy.
allow_image_guest_pull_source(p_oci, i_storage) if {
    policy_data.common.allow_guest_pull_images
    p_image := p_oci.Annotations["io.kubernetes.cri.image-name"]
    p_digest := image_pinned_digest(p_image)
    i_digest := image_pinned_digest(i_storage.source)
    print("allow_image_guest_pull_source 1: p_digest =", p_digest, "i_digest =", i_digest)
    p_digest == i_digest
    print("allow_image_guest_pull_source 1: true")
}
# An unpinned reference is admitted only where guest pull is enabled *and* pinning is not
# required. `allow_guest_pull_images` ships false and `require_pinned_image_digests` ships
# true, so by default this body does not apply and an unpinned reference has no matching
# rule and is denied. A deployment that clears both gets this body back, which is still no
# weaker than the tag the tenant wrote -- but it is a materially weaker posture, because
# guest pull has no dm-verity root hash to fall back on and the setting is the only thing
# pinning content. Both settings are emitted into `policy_data.common`, so a relying party
# can confirm from the measured policy which posture was in force.
allow_image_guest_pull_source(p_oci, i_storage) if {
    policy_data.common.allow_guest_pull_images
    not policy_data.common.require_pinned_image_digests
    p_image := p_oci.Annotations["io.kubernetes.cri.image-name"]
    not contains(p_image, "@")
    print("allow_image_guest_pull_source 2: unpinned p_image =", p_image, "i_source =", i_storage.source)
    i_storage.source == p_image
    print("allow_image_guest_pull_source 2: true")
}
# The pause container is the one case with no declared image: genpolicy deliberately
# omits the annotation for it (policy.rs, `if !is_pause_container`), and the runtime
# names its rootfs with the literal "pause" -- get_image_reference returns that for
# ContainerType::PodSandbox -- because in a guest-pull deployment the pause image ships
# inside the measured guest rootfs and is never pulled. Admitting the sentinel only for a
# declaration that is *both* image-less and typed "sandbox" keeps the pause path from
# becoming a wildcard that any container could claim.
#
# RM-119: gated on `allow_guest_pull_images` like the two bodies above, so that setting
# refuses *every* `image_guest_pull` storage rather than all but one. This is safe
# because the sentinel is only ever produced by the guest-pull path itself:
# `get_image_reference` is reached from exactly one place,
# `handle_virtual_volume_storage` in runtime-rs, and only when the snapshotter's volume
# type is `image_guest_pull`. A host-pull deployment's sandbox rootfs is an overlay or
# EROFS volume, so no pause sentinel is ever presented and this body is unreachable
# there. In `host-erofs-dm-verity` mode the pause container's layers are already declared
# and verity-bound like any other image -- `get_erofs_layer_storages` is called without an
# `is_pause_container` gate, and `add_pause_container` pulls `pause_container_image` from
# the registry to obtain them -- so the sandbox rootfs comes from the host and needs no
# exemption. Guest-pull deployments, which do rely on the inboxed pause bundle, set
# `allow_guest_pull_images` and get this body back along with the other two.
allow_image_guest_pull_source(p_oci, i_storage) if {
    policy_data.common.allow_guest_pull_images
    not p_oci.Annotations["io.kubernetes.cri.image-name"]
    p_oci.Annotations["io.kubernetes.cri.container-type"] == "sandbox"
    print("allow_image_guest_pull_source 3: sandbox container, i_source =", i_storage.source)
    i_storage.source == "pause"
    print("allow_image_guest_pull_source 3: true")
}

# The `algorithm:hex` digest pinned in an OCI reference of the form `name@algorithm:hex`.
# Undefined when the reference is not pinned, which is what makes the two bodies above
# mutually exclusive rather than overlapping.
image_pinned_digest(image_ref) := digest if {
    contains(image_ref, "@")
    parts := split(image_ref, "@")
    digest := lower(parts[count(parts) - 1])
}
# NOTE: the former scsi/blk allow_storage variants are now expressed as bodies of
# storage_pair_matches above, so the generic p_storage-consuming allow_storage variant
# covers them. allow_block_storage became dead with them and has been removed.

# Validates all storage fields except driver and source.
allow_storage_base(p_storage, i_storage, bundle_id, sandbox_id) if {
    # Not logging as this is reused multiple times.

    p_storage.driver_options == i_storage.driver_options
    p_storage.fs_group       == i_storage.fs_group
    p_storage.fstype         == i_storage.fstype
    p_storage.shared         == i_storage.shared

    allow_mount_point(p_storage, i_storage, bundle_id, sandbox_id)
    allow_storage_options(p_storage, i_storage)
}

allow_storage_source(p_storage, i_storage, bundle_id) if {
    print("allow_storage_source 1: start")

    p_storage.source == i_storage.source

    print("allow_storage_source 1: true")
}
allow_storage_source(p_storage, i_storage, bundle_id) if {
    print("allow_storage_source 2: start")

    source1 := p_storage.source
    source2 := replace(source1, "$(sfprefix)", policy_data.common.sfprefix)
    source3 := replace(source2, "$(cpath)", policy_data.common.cpath)
    source4 := replace(source3, "$(bundle-id)", bundle_id)

    print("allow_storage_source 2: source =", source4)
    regex.match(source4, i_storage.source)

    print("allow_storage_source 2: true")
}
allow_storage_source(p_storage, i_storage, bundle_id) if {
    print("allow_storage_source 3: start")

    p_storage.driver == "overlayfs"
    i_storage.source == "none"

    print("allow_storage_source 3: true")
}

allow_storage_options(p_storage, i_storage) if {
    print("allow_storage_options 1: start")

    p_storage.driver != "blk"
    p_storage.driver != "overlayfs"
    p_storage.options == i_storage.options

    print("allow_storage_options 1: true")
}

allow_mount_point(p_storage, i_storage, bundle_id, sandbox_id) if {
    print("allow_mount_point 1: start")

    p_storage.fstype == "local"

    mount1 := p_storage.mount_point
    print("allow_mount_point 3: mount1 =", mount1)

    mount2 := replace(mount1, "$(cpath)", policy_data.common.cpath)
    print("allow_mount_point 1: mount2 =", mount2)

    mount3 := replace(mount2, "$(sandbox-id)", sandbox_id)
    print("allow_mount_point 1: mount3 =", mount3)

    regex.match(mount3, i_storage.mount_point)

    print("allow_mount_point 1: true")
}
allow_mount_point(p_storage, i_storage, bundle_id, sandbox_id) if {
    print("allow_mount_point 2: start")

    p_storage.fstype == "bind"

    mount1 := p_storage.mount_point
    print("allow_mount_point 2: mount1 =", mount1)

    mount2 := replace(mount1, "$(cpath)", policy_data.common.cpath)
    print("allow_mount_point 2: mount2 =", mount2)

    mount3 := replace(mount2, "$(bundle-id)", bundle_id)
    print("allow_mount_point 2: mount3 =", mount3)

    regex.match(mount3, i_storage.mount_point)

    print("allow_mount_point 2: true")
}
allow_mount_point(p_storage, i_storage, bundle_id, sandbox_id) if {
    print("allow_mount_point 3: start")

    p_storage.fstype == "tmpfs"

    mount1 := p_storage.mount_point
    print("allow_mount_point 3: mount1 =", mount1)

    regex.match(mount1, i_storage.mount_point)

    print("allow_mount_point 3: true")
}
allow_mount_point(p_storage, i_storage, bundle_id, sandbox_id) if {
    print("allow_mount_point 4: start")

    i_storage.driver == "blk"
    allow_mount_point_by_device_id(p_storage, i_storage)

    print("allow_mount_point 4: true")
}
allow_mount_point(p_storage, i_storage, bundle_id, sandbox_id) if {
    print("allow_mount_point 5: start")

    i_storage.driver == "scsi"
    allow_mount_point_by_device_id(p_storage, i_storage)

    print("allow_mount_point 5: true")
}

allow_mount_point_by_device_id(p_storage, i_storage) if {
    print("allow_mount_point_by_device_id: start")

    mount1 := p_storage.mount_point
    print("allow_mount_point_by_device_id: mount1 =", mount1)

    mount2 := replace(mount1, "$(spath)", policy_data.common.spath)
    print("allow_mount_point_by_device_id: mount2 =", mount2)

    mount3 := replace(mount2, "$(b64_device_id)", base64url.encode(i_storage.source))
    print("allow_mount_point_by_device_id: mount3 =", mount3)

    mount3 == i_storage.mount_point

    print("allow_mount_point_by_device_id: true")
}

# ExecProcessRequest.process.Capabilities
allow_exec_caps(i_caps) if {
    not i_caps.Ambient
    not i_caps.Bounding
    not i_caps.Effective
    not i_caps.Inheritable
    not i_caps.Permitted
}

# OCI.Process.Capabilities
allow_caps(p_caps, i_caps) if {
    print("allow_caps: policy Ambient =", p_caps.Ambient)
    print("allow_caps: input Ambient =", i_caps.Ambient)
    match_caps(p_caps.Ambient, i_caps.Ambient)

    print("allow_caps: policy Bounding =", p_caps.Bounding)
    print("allow_caps: input Bounding =", i_caps.Bounding)
    match_caps(p_caps.Bounding, i_caps.Bounding)

    print("allow_caps: policy Effective =", p_caps.Effective)
    print("allow_caps: input Effective =", i_caps.Effective)
    match_caps(p_caps.Effective, i_caps.Effective)

    print("allow_caps: policy Inheritable =", p_caps.Inheritable)
    print("allow_caps: input Inheritable =", i_caps.Inheritable)
    match_caps(p_caps.Inheritable, i_caps.Inheritable)

    print("allow_caps: policy Permitted =", p_caps.Permitted)
    print("allow_caps: input Permitted =", i_caps.Permitted)
    match_caps(p_caps.Permitted, i_caps.Permitted)
}

match_caps(p_caps, i_caps) if {
    print("match_caps 1: start")

    norm_p_caps := { strip_cap_prefix(c) | c := p_caps[_] }
    norm_i_caps := { strip_cap_prefix(c) | c := i_caps[_] }
    norm_p_caps == norm_i_caps

    print("match_caps 1: true")
}
match_caps(p_caps, i_caps) if {
    print("match_caps 2: start")

    count(p_caps) == 1
    p_caps[0] == "$(default_caps)"

    print("match_caps 2: i_caps =", i_caps)
    print("match_caps 2: default_caps =", policy_data.common.default_caps)

    norm_defaults := { strip_cap_prefix(c) | c := policy_data.common.default_caps[_] }
    norm_input := { strip_cap_prefix(c) | c := i_caps[_] }
    print("match_caps 2: norm_defaults =", norm_defaults)
    print("match_caps 2: norm_input    =", norm_input)

    norm_defaults == norm_input

    print("match_caps 2: true")
}
match_caps(p_caps, i_caps) if {
    print("match_caps 3: start")

    count(p_caps) == 1
    p_caps[0] == "$(privileged_caps)"

    print("match_caps 3: i_caps =", i_caps)
    print("match_caps 3: privileged_caps =", policy_data.common.privileged_caps)

    norm_defaults := { strip_cap_prefix(c) | c := policy_data.common.privileged_caps[_] }
    norm_input    := { strip_cap_prefix(c) | c := i_caps[_] }
    print("match_caps 3: norm_defaults =", norm_defaults)
    print("match_caps 3: norm_input    =", norm_input)

    norm_defaults == norm_input

    print("match_caps 3: true")
}

######################################################################

normalize_namespace_type(type) := normalized_type if {
    lower(type) == "mount"
    normalized_type := "mnt"
} else := normalized_type if {
    normalized_type := type
}

strip_cap_prefix(s) := result if {
    startswith(s, "CAP_")
    result := substring(s, 4, count(s) - 4)
} else := result if {
    result := s
}

check_directory_traversal(i_path) if {
    not regex.match("(^|/)\\.\\.($|/)", i_path)
}

allow_sandbox_storages(i_storages) if {
    print("allow_sandbox_storages: i_storages =", i_storages)

    p_storages := policy_data.sandbox.storages

    # RM-30: the repetition half of the bijection allow_storages received in 1b335c0e2,
    # which stopped short of this rule. The body below was purely existential -- every
    # presented storage had to match *some* declaration, with no distinctness check --
    # so the host could present one declared storage several times.
    #
    # Injection was already bounded, because allow_sandbox_storage demands exact
    # equality against a declared entry, and exact equality also makes distinctness
    # cheap to state: no two presented storages may be the same object.
    i_set := {s | some s in i_storages}
    print("allow_sandbox_storages: distinct =", count(i_set), "presented =", count(i_storages))
    count(i_set) == count(i_storages)

    every i_storage in i_storages {
        allow_sandbox_storage(p_storages, i_storage)
    }

    # NOTE: the *omission* half is deliberately not closed here, and this is the reason.
    # The presented list is legitimately a strict subset of the declared one -- the
    # genpolicy test corpus contains a sandbox that declares an ephemeral `shm` tmpfs
    # and presents no storages at all -- so a cardinality or reverse-coverage check of
    # the kind allow_storages uses denies ordinary pods. Closing omission needs genpolicy
    # to record which sandbox storages are *required* rather than merely permitted, which
    # is a policy-format change; until then a dropped sandbox mount is indistinguishable
    # from a pod that never needed it. Tracked as the residual of RM-30.
    print("allow_sandbox_storages: true")
}

allow_sandbox_storage(p_storages, i_storage) if {
    print("allow_sandbox_storage: i_storage =", i_storage)

    some p_storage in p_storages
    print("allow_sandbox_storage: p_storage =", p_storage)
    i_storage == p_storage

    print("allow_sandbox_storage: true")
}

CreateSandboxRequest if {
    print("CreateSandboxRequest: input.guest_hook_path =", input.guest_hook_path)
    count(input.guest_hook_path) == 0

    print("CreateSandboxRequest: input.kernel_modules =", input.kernel_modules)
    count(input.kernel_modules) == 0

    i_pidns := input.sandbox_pidns
    print("CreateSandboxRequest: i_pidns =", i_pidns)
    i_pidns == false
    allow_sandbox_storages(input.storages)
}

allow_exec(p_container, i_process) if {
    print("allow_exec: start")

    p_oci = p_container.OCI
    p_s_name = p_oci.Annotations[S_NAME_KEY]
    s_namespace = get_state_val("namespace")
    allow_probe_process(p_oci.Process, i_process, p_s_name, s_namespace)

    print("allow_exec: true")
}

allow_interactive_exec(p_container, i_process) if {
    print("allow_interactive_exec: start")

    p_oci = p_container.OCI
    p_s_name = p_oci.Annotations[S_NAME_KEY]
    s_namespace = get_state_val("namespace")
    allow_interactive_process(p_oci.Process, i_process, p_s_name, s_namespace)

    print("allow_interactive_exec: true")
}

get_state_container(container_id):= p_container if {
    ref := get_state_val(container_id)
    p_container := container_by_ref(ref)
}

ExecProcessRequest if {
    print("ExecProcessRequest 1: input =", input)
    allow_exec_process_input

    some p_command in policy_data.request_defaults.ExecProcessRequest.allowed_commands
    print("ExecProcessRequest 1: p_command =", p_command)
    p_command == input.process.Args

    p_container := get_state_container(input.container_id)
    allow_interactive_exec(p_container, input.process)

    print("ExecProcessRequest 1: true")
}
ExecProcessRequest if {
    print("ExecProcessRequest 2: input =", input)
    allow_exec_process_input

    p_container := get_state_container(input.container_id)

    some p_command in p_container.exec_commands
    print("ExecProcessRequest 2: p_command =", p_command)

    p_command == input.process.Args

    allow_exec(p_container, input.process)

    print("ExecProcessRequest 2: true")
}
ExecProcessRequest if {
    print("ExecProcessRequest 3: input =", input)
    allow_exec_process_input

    i_command = concat(" ", input.process.Args)
    print("ExecProcessRequest 3: i_command =", i_command)

    some p_regex in policy_data.request_defaults.ExecProcessRequest.regex
    print("ExecProcessRequest 3: p_regex =", p_regex)

    regex.match(p_regex, i_command)

    p_container := get_state_container(input.container_id)

    allow_interactive_exec(p_container, input.process)

    print("ExecProcessRequest 3: true")
}

allow_exec_process_input if {
    is_null(input.string_user)

    i_process := input.process
    count(i_process.SelinuxLabel) == 0
    count(i_process.ApparmorProfile) == 0

    print("allow_exec_process_input: true")
}

UpdateRoutesRequest if {
    print("UpdateRoutesRequest: input =", input)
    print("UpdateRoutesRequest: policy =", policy_data.request_defaults.UpdateRoutesRequest)

    i_routes := input.routes.Routes
    p_source_regex = policy_data.request_defaults.UpdateRoutesRequest.forbidden_source_regex
    p_names = policy_data.request_defaults.UpdateRoutesRequest.forbidden_device_names
    p_dest_regex = object.get(
        policy_data.request_defaults.UpdateRoutesRequest,
        "allowed_dest_regex",
        [".*"],
    )
    p_gateway_regex = object.get(
        policy_data.request_defaults.UpdateRoutesRequest,
        "allowed_gateway_regex",
        [".*"],
    )

    every i_route in i_routes {
        print("i_route.source =", i_route.source)
        every p_regex in p_source_regex {
            print("p_regex =", p_regex)
            not regex.match(p_regex, i_route.source)
        }

        print("i_route.device =", i_route.device)
        not i_route.device in p_names

        # FR-14: the destination and gateway must each match the allowlist. Absent fields
        # are treated as "" so that a default route is checked against the same list.
        i_dest := object.get(i_route, "dest", "")
        print("i_route.dest =", i_dest)
        some p_dest in p_dest_regex
        regex.match(p_dest, i_dest)

        i_gateway := object.get(i_route, "gateway", "")
        print("i_route.gateway =", i_gateway)
        some p_gateway in p_gateway_regex
        regex.match(p_gateway, i_gateway)
    }

    print("UpdateRoutesRequest: true")
}

UpdateInterfaceRequest if {
    print("UpdateInterfaceRequest: input =", input)
    print("UpdateInterfaceRequest: policy =", policy_data.request_defaults.UpdateInterfaceRequest)

    i_interface := input.interface
    p_flags := policy_data.request_defaults.UpdateInterfaceRequest.allow_raw_flags

    # Typically, just IFF_NOARP is used.
    bits.and(i_interface.raw_flags, bits.negate(p_flags)) == 0

    p_names := policy_data.request_defaults.UpdateInterfaceRequest.forbidden_names

    not i_interface.name in p_names

    p_hwaddrs := policy_data.request_defaults.UpdateInterfaceRequest.forbidden_hw_addrs

    not i_interface.hwAddr in p_hwaddrs

    # FR-14: constrain the addresses being assigned. An address implies a connected route
    # for its prefix, so an unconstrained address is an unconstrained route.
    p_ip_regex := object.get(
        policy_data.request_defaults.UpdateInterfaceRequest,
        "allowed_ip_regex",
        [".*"],
    )

    every i_ip in object.get(i_interface, "IPAddresses", []) {
        i_address := object.get(i_ip, "address", "")
        print("i_ip.address =", i_address)
        some p_ip in p_ip_regex
        regex.match(p_ip, i_address)
    }

    print("UpdateInterfaceRequest: true")
}

AddARPNeighborsRequest if {
    p_defaults := policy_data.request_defaults.AddARPNeighborsRequest
    print("AddARPNeighborsRequest: policy =", p_defaults)

    every i_neigh in input.neighbors.ARPNeighbors {
        print("AddARPNeighborsRequest: i_neigh =", i_neigh)

        not i_neigh.device in p_defaults.forbidden_device_names
        i_neigh.toIPAddress.mask == ""
        every p_cidr in p_defaults.forbidden_cidrs_regex {
            not regex.match(p_cidr, i_neigh.toIPAddress.address)
        }
        i_neigh.state in p_defaults.allowed_states
        bits.or(i_neigh.flags, 136) == 136
    }

    print("AddARPNeighborsRequest: true")
}

# ---------------------------------------------------------------------------
# Host -> guest content channel.
#
# These four endpoints replace the free-form CopyFileRequest, which is `:= false` above.
# The host no longer names a destination path: it names one of a fixed set of file kinds
# (CopySingleFileRequest) or a volume id the *guest* minted (the watchable-volume trio),
# and the guest derives the path. That removes the arbitrary-write primitive, but it does
# not by itself constrain what the host writes, so the rules below mediate the fields that
# are still host-controlled.
#
# For the two endpoints that carry file content the agent evaluates a pre-processed input
# (PolicyCopySingleFileRequest / PolicyPutVolumeFileRevisionRequest, in src/agent/policy) whose
# `data` blob is stripped, so the host cannot load the rules engine with the payload.
#
# The S_IFMT bits are not mediated here. The agent refuses any request on these two
# endpoints whose `file_mode` is not S_IFREG, before policy is consulted, so a rule could
# only restate that. The *permission* bits are a different matter: that guard ignores
# them, and do_copy_file preserves file_mode & 0o7777.
# ---------------------------------------------------------------------------

# Host-supplied content must not carry setuid, setgid or the sticky bit: do_copy_file
# preserves file_mode & 0o7777, so those bits reach the file the container sees.
allow_content_mode(i_mode) if {
    # 3584 = 0o7000, i.e. S_ISUID | S_ISGID | S_ISVTX.
    bits.and(i_mode, 3584) == 0
}

# A host-supplied path component must be a plain relative name: no "..", no leading "/",
# and not empty. The agent enforces the same thing, but stating it here means the request
# is refused before it reaches the filesystem code.
allow_content_path_component(i_component) if {
    i_component != ""
    not startswith(i_component, "/")
    check_directory_traversal(i_component)
}

CopySingleFileRequest if {
    p_defaults := policy_data.request_defaults.CopySingleFileRequest
    print("CopySingleFileRequest: input =", input, "policy =", p_defaults)

    # Which of the guest's files the host may supply is not mediated here. The host names
    # a file *kind* from a closed enum rather than a path, and the guest derives the
    # destination from it, so every reachable destination is one the guest chose. Should a
    # policy ever need to narrow that set -- to deny Hostname for a workload that should
    # not learn the sandbox name, say -- the enum is the field to add.

    allow_content_mode(input.file_mode)

    # sandbox_id is a host-supplied path component.
    allow_content_path_component(input.sandbox_id)

    input.data_size >= 0
    input.data_size <= p_defaults.max_file_size

    print("CopySingleFileRequest: true")
}

# The request carries only host_volume_id, which the guest ignores -- it mints its own
# "watchable-<nanos>" id and returns it. There is no host-controlled field to constrain,
# so this is a plain on/off switch for workloads that use no projected volumes.
InitVolumeRequest if {
    policy_data.request_defaults.InitVolumeRequest == true
}

PutVolumeFileRevisionRequest if {
    p_defaults := policy_data.request_defaults.PutVolumeFileRevisionRequest
    print("PutVolumeFileRevisionRequest: input =", input, "policy =", p_defaults)

    # agent_volume_id, revision and file_name are all joined into the destination path.
    allow_content_path_component(input.agent_volume_id)
    allow_content_path_component(input.revision)
    allow_content_path_component(input.file_name)

    allow_content_mode(input.file_mode)
    allow_content_mode(input.dir_mode)

    input.offset >= 0
    input.file_size >= 0
    input.file_size <= p_defaults.max_file_size

    print("PutVolumeFileRevisionRequest: true")
}

CommitVolumeRevisionRequest if {
    policy_data.request_defaults.CommitVolumeRevisionRequest == true

    # agent_volume_id is joined into the path of the tree that gets published and, with
    # garbage_collect_previous, of the tree that gets deleted.
    allow_content_path_component(input.agent_volume_id)

    print("CommitVolumeRevisionRequest: true")
}

CloseStdinRequest if {
    policy_data.request_defaults.CloseStdinRequest == true
}
ReadStreamRequest if {
    policy_data.request_defaults.ReadStreamRequest == true
}

UpdateEphemeralMountsRequest if {
    policy_data.request_defaults.UpdateEphemeralMountsRequest == true
}

WriteStreamRequest if {
    policy_data.request_defaults.WriteStreamRequest == true
}

GetDiagnosticDataRequest if {
    policy_data.request_defaults.GetDiagnosticDataRequest == true
}

RemoveContainerRequest:= {"ops": ops, "allowed": true} if {
    print("RemoveContainerRequest: input =", input)

    # Only a container this policy authorized to run may be removed. get_state_val is
    # undefined for an unknown or already-removed container_id, which makes this rule
    # undefined and falls through to the fail-closed default, closing the "remove any
    # container_id" gap (and making removal idempotent: a second remove is denied).
    p_container_index := get_state_val(input.container_id)
    print("RemoveContainerRequest: container", input.container_id, "known at index", p_container_index)

    # Delete input.container_id from p_state, and tombstone the id so it can never name a
    # second container in this sandbox (RM-20). Deleting is still right -- it is what makes
    # every later start/exec/signal/remove for the id undefined and therefore denied -- but
    # on its own it also frees the id for reuse, which the baseline never does.
    ops_builder1 := []
    del_container := state_del_key(input.container_id)
    ops_builder2 := concat_op_if_not_null(ops_builder1, del_container)
    retire_container := state_allows(retired_key(input.container_id), input.container_id)
    ops := concat_op_if_not_null(ops_builder2, retire_container)

    print("RemoveContainerRequest: true")
}

# RM-26: removing an id this policy never admitted is a successful no-op.
#
# The rule above is deliberately undefined for an unknown container_id, and on its own
# that produced a deadlock during teardown. When a CreateContainerRequest is denied, the
# shim's cleanup path still issues RemoveContainerRequest for the same id -- but no state
# key was ever written for it, so the removal was denied too. The shim retried, the
# kubelet waited, and the pod sat in `Terminating` until someone force-deleted it. Each
# individual decision was correct; the composition had no exit. That failure mode is
# worse than it looks: an operator experiences a *correctly enforced* denial as a hung
# workload, which is exactly the pressure that gets policies loosened.
#
# Admitting the no-op gives up nothing. There is no container behind the id, so there is
# nothing to destroy and no state to delete -- the request cannot have an effect beyond
# the tombstone written below. What it must NOT do is re-admit the cases the strict rule
# closes, so it is guarded on *both* keys: an id with live state takes the rule above,
# and an id that is already tombstoned (a genuine second remove of a container that did
# run) still falls through to the fail-closed default.
#
# The tombstone is written here as well, so removal stays single-shot per id no matter
# which path admitted it (RM-20). This does let the host burn an id by removing it before
# creating it, but that is not a new capability: the host chooses the ids and decides
# whether to send the create at all, so it can only deny itself.
RemoveContainerRequest := {"ops": ops, "allowed": true} if {
    print("RemoveContainerRequest: input =", input)

    not get_state_val(input.container_id)
    not get_state_val(retired_key(input.container_id))
    print("RemoveContainerRequest: container", input.container_id, "was never admitted; no-op removal")

    ops := concat_op_if_not_null([], state_allows(retired_key(input.container_id), input.container_id))

    print("RemoveContainerRequest: true (no-op)")
}

# Gate SignalProcessRequest instead of allowing every signal unconditionally.
# A signal is permitted only when (1) its number is in the policy's sandbox-wide
# allowed_signals set, (2) it targets a container this policy authorized to run (tracked
# in persisted state by CreateContainerRequest and cleared by RemoveContainerRequest),
# and (3) its number is in *that container's own* allowed_signals set.
#
# (3) is the hcsshim parity property (F-76): the reference stack stores a per-container
# `Signals` list on securityPolicyContainer and consults the signalled container's own
# list, so a signal admitted for one workload is not thereby admitted for every other
# process in the sandbox. Checking (1) as well as (3) makes the sandbox-wide list a
# ceiling rather than a second source of truth: a container carried by a policy fragment
# is resolved through get_state_container -> container_by_ref, which re-runs the fragment
# declaration gates, and even then it can only ever narrow what the measured base policy
# admits -- a fragment cannot widen the signal surface.
SignalProcessRequest if {
    print("SignalProcessRequest: input =", input)

    # (1) The signal number must be explicitly allowed by the sandbox-wide policy.
    i_signal := input.signal
    some allowed_signal in policy_data.request_defaults.SignalProcessRequest.allowed_signals
    i_signal == allowed_signal
    print("SignalProcessRequest: signal", i_signal, "is allowed sandbox-wide")

    # (2)+(3) The target container must be known to this policy (present in state), and
    # the signal must be in that container's own set. get_state_container is undefined for
    # an unknown/removed container_id -- and p_container.allowed_signals is undefined for a
    # container entry generated before this field existed -- which makes this rule
    # undefined and falls through to the fail-closed default.
    p_container := get_state_container(input.container_id)
    some container_signal in p_container.allowed_signals
    i_signal == container_signal
    print("SignalProcessRequest: signal", i_signal, "is allowed for container", input.container_id)

    print("SignalProcessRequest: true")
}

# Gate container-scoped lifecycle/inspection endpoints on a known-container check
# instead of allowing them unconditionally. StartContainerRequest, WaitProcessRequest,
# StatsContainerRequest and TtyWinResizeRequest each act on a specific container_id and
# are permitted only for a container this policy authorized to run (recorded in
# persisted state by CreateContainerRequest and cleared by RemoveContainerRequest).
# get_state_val is undefined for an unknown or already-removed container_id, which makes
# the rule undefined and falls through to the fail-closed default. This mirrors the
# reference behavior of scoping per-container operations to containers the policy
# actually created, closing the "operate on any container_id" gap of the previous
# unconditional defaults.
allow_known_container(container_id) if {
    p_container_index := get_state_val(container_id)
    print("allow_known_container: container", container_id, "known at index", p_container_index)
}

StartContainerRequest if {
    print("StartContainerRequest: input =", input)
    allow_known_container(input.container_id)
    print("StartContainerRequest: true")
}

WaitProcessRequest if {
    print("WaitProcessRequest: input =", input)
    allow_known_container(input.container_id)
    print("WaitProcessRequest: true")
}

StatsContainerRequest if {
    print("StatsContainerRequest: input =", input)
    allow_known_container(input.container_id)
    print("StatsContainerRequest: true")
}

TtyWinResizeRequest if {
    print("TtyWinResizeRequest: input =", input)
    allow_known_container(input.container_id)
    print("TtyWinResizeRequest: true")
}

# ---- BL-7 (Jiri Feature A): policy fragment composition (issuer + feed + minimum SVN gate) ----
# Fragments are separate signed modules that the guest agent's Security Reference Monitor
# verifies (COSE/did:x509 + SVN + feed + ordering/transparency gates) and then applies into
# the reserved `agent_policy.fragments` namespace (see docs/cc/fr1-fragments.md FR-1c). The
# base policy declares which fragments it trusts in `policy_data.fragments[]`
# (issuer/feed/minimum_svn); those declarations are measured into HostData, so composition is
# attested.
#
# Runtime data contract: a verified fragment for feed F contributes, under this namespace, a
# keyed entry `data.agent_policy.fragments[F] == {"issuer": <did/id>, "svn": <n>,
# "containers": [<container-policy>, ...]}`. Because a feed is an OCI reference
# (`myregistry.io/fragments/sidecar`) and not a Rego identifier, a fragment writes that key by
# declaring its package with a quoted path segment:
#
#     package agent_policy.fragments["myregistry.io/fragments/sidecar"]
#     issuer := "did:x509:..."
#     svn := 3
#     containers := [ ... ]
#
# The agent accepts that form only when the quoted segment equals the feed the SRM verified
# from the fragment's own COSE envelope, so a fragment can only ever populate its own key and
# never another publisher's. At genpolicy generation time no fragment is loaded
# (`data.agent_policy.fragments` is empty) and an unloaded / under-versioned / wrong-issuer
# fragment contributes nothing => behaviour identical to a monolithic policy (no regression).

# The full allowed-container set: base policy containers plus verified fragment-contributed
# containers. All container-matching rules iterate this set.
#
# Each element carries a **stable reference** next to the container, because policy state
# has to be able to name the container that authorized a running container_id, and the set
# itself is not stable: `fragment_container_entries` is a comprehension over the fragments that
# are *currently loaded*, so delivering another fragment inserts entries and shifts every
# position after them. Recording a position would silently re-bind a running container to a
# different policy entry the next time a fragment arrives, and the host chooses fragment
# delivery order and timing. A reference names the source instead — the measured base array,
# or a specific (feed, svn) — so it means the same thing however the combined set is
# rebuilt.
base_container_entries := [{"ref": {"base": true, "idx": i}, "container": c} |
    some i, c in policy_data.containers
]

# A policy can declare a trusted fragment in two places, and both are measured, so both
# have to be honoured here.
#
#   * `policy_data.fragments` — BL-7. Comes from `genpolicy-settings.json`, is serialized
#     into `policy_data` at generation time, and is what a settings-driven deployment uses.
#   * `policy_fragments` — BL-8. A rule in the generated policy text; this is the list the
#     *agent* reads to decide what the host must deliver and what it must refuse.
#
# Reading only the first was a silent hole in the other direction from the usual one: a
# fragment declared for delivery (BL-8), fetched by the host, verified by the SRM and
# applied into the engine still contributed **no containers**, because the rule that reads
# its contribution was looking at a list the BL-8 declaration never appears in. Nothing
# reported an error — the fragment loaded, and the container it carried was simply refused.
# Declaring the same fragment twice, in two different files, would have been the only way to
# make it work, with divergence between the two failing silently.
#
# Duplicates across the two are expected rather than exceptional: an operator raising a
# floor in one place can easily leave a stale declaration behind in the other. When that
# happens the *strictest* floor is the one that counts. `svn_floor` takes the maximum over
# every declaration naming the same `(issuer, feed)`, which is what the SRM already does --
# `declare_feed` keeps the stricter floor when a feed is declared twice (RM-87). Selecting
# with `some spec in all_fragment_specs` instead would be an existential, admitting a
# container if *any* declaration accepted it, so the weakest floor would win and this Rego
# re-check would be laxer than the SRM gate it is meant to independently confirm.
#
# Iterating the delivered modules rather than the specs also makes each feed appear exactly
# once, so duplicate declarations no longer produce duplicate container entries.
all_fragment_specs := array.concat(policy_data.fragments, policy_fragments)

svn_floor(issuer, feed) := max(floors) if {
    floors := [spec.minimum_svn |
        some spec in all_fragment_specs
        spec.issuer == issuer
        spec.feed == feed
    ]
    count(floors) > 0
}

fragment_container_entries := [{"ref": {"feed": feed, "svn": to_number(mod.svn), "idx": j}, "container": c} |
    some feed, mod in data.agent_policy.fragments
    to_number(mod.svn) >= svn_floor(mod.issuer, feed)
    some j, c in mod.containers
]

all_policy_container_entries := array.concat(base_container_entries, fragment_container_entries)

# Resolve a reference recorded by CreateContainerRequest back to a policy container.
#
# The fragment arm re-runs the declaration gates rather than trusting the reference: the
# fragment must still be one the measured base policy declares, from the issuer it declares,
# at or above the declared SVN floor. The recorded SVN must match exactly, so a container
# authorized by one version of a fragment is never later evaluated against the containers of
# another version of it. Both arms are undefined when they do not hold, which makes the
# calling rule undefined and falls through to the fail-closed default.
container_by_ref(ref) := c if {
    ref.base == true
    c := policy_data.containers[ref.idx]
}

container_by_ref(ref) := c if {
    not ref.base
    mod := data.agent_policy.fragments[ref.feed]
    to_number(mod.svn) >= svn_floor(mod.issuer, ref.feed)
    to_number(mod.svn) == ref.svn
    c := mod.containers[ref.idx]
}

# ---- BL-8: delivery of fragments the base policy declares ----
# Fragments the measured base policy declares in `policy_fragments[]` are fetched by the
# host and pushed to the agent one at a time over LoadPolicyFragmentRequest. That endpoint
# has to be policy-covered like every other one: an undefined rule makes allow_request bail,
# which is fail-closed and therefore safe, but it is also indistinguishable from a rejected
# fragment and it leaves the delivery path unusable.
#
# Each declaration carries an optional `required` flag, read by the agent and not by this
# rule. It defaults to false, which is C-ACI/hcsshim behaviour: delivery is lazy, and a
# fragment that never arrives contributes no grants, so anything only it would have
# permitted is refused by the composed policy on its own merits. `required: true` is
# stricter than C-ACI — it makes the declaration an obligation, so the agent refuses to
# create any container until that fragment has been delivered and verified. Use it when the
# fragment's absence is not fail-safe (a deny rule, an audit obligation, a constraint the
# base policy assumes has been composed in). Either way a delivered fragment is verified
# identically; `required` governs only whether absence is an error.
#
# A declaration may also carry `allow_nested`, which decides whether the fragment it names
# may itself declare further fragments, and whose. It is absent by default, meaning no
# delegation, so a policy written before the attribute existed cannot acquire the capability
# by upgrade. The accepted forms are `false` / "none", "same-issuer" (the delivering
# fragment's own issuer only), "any-authorized" (any issuer the measured trust root
# authorizes), or an explicit list of issuer strings. Bare `true` is rejected by the agent
# because it enables delegation without saying to whom.
#
# Delegation does not widen trust. A nested declaration only says a feed is expected; the
# fragment behind it must still be signed by an issuer the measured trust root authorizes,
# and the issuer-wide SVN floor still binds, so a nested declaration can raise the bar but
# never lower it. Nested declarations live in the delivering fragment's signed Rego module
# (at `policy_fragments` inside its own package), so they are covered by the same COSE
# signature as everything else it carries and the host cannot edit them.
#
# A declaration may also carry `allow_env_rules`: a list of name patterns bounding which
# environment variables the fragment may contribute `env_rules` for. It is absent by
# default, meaning the fragment decides nothing about the environment, so — as with
# `allow_nested` — a policy written before the attribute existed cannot acquire the
# capability by upgrade. See the `allow_var` arm that consumes it for why the grant is
# expressed over variable *names* and why duplicate declarations are intersected rather
# than combined.
#
# The rule is coarse by construction, because the request carries nothing finer to bind to.
# The host sends only the COSE envelope: issuer, feed and SVN are derived from the bytes the
# guest verifies rather than from anything the host asserts, precisely so that a lying host
# cannot describe a fragment into acceptance. Coarse is sufficient here. The Security
# Reference Monitor verifies the envelope against the measured trust anchors and refuses
# anything not signed by a declared issuer at or above the declared minimum SVN, so a
# permitted call grants the host no power beyond offering bytes -- its worst case is denial,
# never bypass.
#
# What this rule adds is the outer bound: a policy that declares no fragments has no reason
# to accept any, so the endpoint stays shut for it.
#
# `policy_fragments` must be *defined* for that to work. Rego's undefined-is-fail-closed
# behaviour applies to evaluation, not to compilation: a bare reference to a rule nothing
# declares is an unsafe variable, and regorus rejects the whole module rather than leaving
# this one rule undefined. That is not fail-closed, it is fail-to-load -- the agent cannot
# build its engine at all, so every request is refused and no pod can start. genpolicy does
# not emit `policy_fragments` (only base policies that declare fragments append it), which
# is the ordinary case, so the default below is what keeps the ordinary case working.
default policy_fragments := []

default LoadPolicyFragmentRequest := false

LoadPolicyFragmentRequest if {
    count(policy_fragments) > 0
}

# ---------------------------------------------------------------------------
# FR-8 / RM-64: denial reasons.
#
# When a request is refused, the endpoint rule simply fails to produce a value and the
# agent has nothing to tell the operator beyond "denied". The only diagnostic available
# was the `print()` trace, which is unstructured, is the largest thing in the message,
# and is truncated by containerd before it reaches anyone -- so three unrelated defects
# (a dm-verity gap, an inverted partition ordering and a Root.Readonly mismatch) all
# presented as the same opaque failure.
#
# This mirrors the C-ACI baseline, whose Rego framework accumulates a set of failure
# strings (`data.framework.errors`) and exposes them through `data.policy.reason`, which
# the enforcer queries on denial. The agent does the same: on refusal it re-evaluates
# `data.agent_policy.reason` with `rule` set to the endpoint name.
#
# Two properties this deliberately keeps:
#
#   - **Diagnostic only.** Nothing here participates in the allow decision. The agent
#     evaluates it *after* the request has already been refused, so a bug in this section
#     can make a message wrong but cannot make a denied request succeed. That is also why
#     injecting `rule` into the input is safe even if a request ever carried that field.
#
#   - **Names, never values.** Environment variables are reported by name only and
#     command arguments are not reported at all, matching the redaction the baseline
#     applies before a decision leaves the guest. Paths, mount destinations, root hashes
#     and partition numbers *are* reported: all of them appear in the policy itself, so
#     they reveal nothing the holder of the policy does not already have.
#
# The set is a set of *candidate* explanations, not a single root cause. Each entry means
# "no policy container satisfied this particular check", so several can be true at once
# and a container failing two checks contributes two entries. That is the same semantics
# the baseline has, and it is more useful than guessing which one mattered.
# ---------------------------------------------------------------------------

reason := {"errors": errors}

# A container id may only be used once per sandbox (RM-20). This is checked before any
# candidate is considered, so it is reported on its own.
errors[msg] if {
    input.rule == "CreateContainerRequest"
    get_state_val(retired_key(input.container_id))
    msg := sprintf("container id %v has already been used in this sandbox and cannot be reused", [input.container_id])
}

errors["the policy declares no containers, so no CreateContainerRequest can be allowed"] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) == 0
}

# Below: one error per discriminating field, emitted when *no* candidate container agrees
# with the request on that field. Each names the presented value and the set of values the
# policy would have accepted, which is the comparison an operator otherwise has to
# reconstruct by hand from a truncated trace.

errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    not candidate_agrees_on_readonly
    accepted := {c.container.OCI.Root.Readonly | some c in all_policy_container_entries}
    msg := sprintf("Root.Readonly: request has %v, policy accepts %v", [input.OCI.Root.Readonly, accepted])
}

candidate_agrees_on_readonly if {
    some entry in all_policy_container_entries
    entry.container.OCI.Root.Readonly == input.OCI.Root.Readonly
}

errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    not candidate_agrees_on_pidns
    accepted := {c.container.sandbox_pidns | some c in all_policy_container_entries}
    msg := sprintf("sandbox_pidns: request has %v, policy accepts %v", [input.sandbox_pidns, accepted])
}

candidate_agrees_on_pidns if {
    some entry in all_policy_container_entries
    entry.container.sandbox_pidns == input.sandbox_pidns
}

errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    not candidate_agrees_on_oci_version
    accepted := {c.container.OCI.Version | some c in all_policy_container_entries}
    msg := sprintf("OCI.Version: request has %v, policy accepts %v", [input.OCI.Version, accepted])
}

candidate_agrees_on_oci_version if {
    some entry in all_policy_container_entries
    entry.container.OCI.Version == input.OCI.Version
}

# RM-102: the fields `allow_create_container_input` refuses outright.
#
# Those checks are a flat conjunction with a single print at each end, so when one of them
# rejects a request the trace says only "allow_create_container_input" and the operator is
# left to diff the whole OCI spec by hand. Unlike the per-field checks above these are not
# comparisons against candidate containers -- the policy refuses the field for *any*
# container -- so the reason states the refusal rather than an accepted set.
#
# Only the three fields a workload can actually populate from a pod spec are reported.
# `Hooks`, `Solaris`, `Windows`, `IntelRdt`, the ID mappings and the unsupported cgroup
# resources are refused by the same conjunction, but nothing in the k8s -> containerd ->
# kata path can set them, so an error for each would be noise that never fires. If that
# ever changes, add them here.
#
# Each of these three names a security control the guest does not apply anyway, which is
# why refusing them costs nothing: see docs/cc/guest-security-controls.md.

# The reference has to be bound before it is negated. `not is_null(x)` is true when `x`
# is *undefined* as well as when it is a profile, so reading through `input.OCI.Linux`
# directly made this fire on any request whose OCI spec carries no `Linux` section at
# all -- reporting a seccomp profile the request did not have, ahead of the field that
# actually failed. Binding first makes the body undefined, and the error absent, unless
# `Seccomp` is really present.
errors["Linux.Seccomp: the request carries a seccomp profile, but the policy refuses any seccomp profile from the host. The kata guest applies no seccomp filtering, so set disable_guest_seccomp=true in the runtime configuration"] if {
    input.rule == "CreateContainerRequest"
    i_seccomp := input.OCI.Linux.Seccomp
    not is_null(i_seccomp)
}

errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(input.OCI.Process.SelinuxLabel) > 0
    msg := sprintf("Process.SelinuxLabel: the request carries the label %v, but the policy refuses any SELinux label from the host. The kata guest rootfs is not SELinux-labelled, so set disable_guest_selinux=true in the runtime configuration", [input.OCI.Process.SelinuxLabel])
}

errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(input.OCI.Linux.MountLabel) > 0
    msg := sprintf("Linux.MountLabel: the request carries the label %v, but the policy refuses any SELinux mount label from the host. The kata guest rootfs is not SELinux-labelled, so set disable_guest_selinux=true in the runtime configuration", [input.OCI.Linux.MountLabel])
}

# RM-97: there is deliberately no "sandbox namespace" error here. The enforcement path
# never compares the request's namespace against the policy's: `allow_by_anno` reads
# `S_NAMESPACE_KEY` from the *input* only and passes it down as a substitution variable
# for `allow_var` and `allow_sandbox_log_directory`. The policy's own annotation is not a
# constraint, and genpolicy commonly leaves it empty. Reporting a comparison the engine
# never makes produced a permanent, unconditional "request has default, policy accepts
# {\"\"}" on every guest-pull denial, which read like a root cause and was not one.

# Command arguments are compared but never reported: unlike mounts and hashes they are
# workload data rather than policy data, and the baseline redacts them for the same reason.
errors["command: no policy container declares this container's argument list"] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    not candidate_agrees_on_args
}

candidate_agrees_on_args if {
    some entry in all_policy_container_entries
    entry.container.OCI.Process.Args == input.OCI.Process.Args
}

errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    not candidate_agrees_on_cwd
    accepted := {c.container.OCI.Process.Cwd | some c in all_policy_container_entries}
    msg := sprintf("working directory: request has %v, policy accepts %v", [input.OCI.Process.Cwd, accepted])
}

candidate_agrees_on_cwd if {
    some entry in all_policy_container_entries
    entry.container.OCI.Process.Cwd == input.OCI.Process.Cwd
}

# RM-97: the process user. This check was missing entirely, and it was the actual cause of
# every denial investigated under RM-95 and RM-96 -- in each case the operator was handed
# three unrelated reasons and never told that `allow_user` had rejected the request. A
# UID/GID/AdditionalGids mismatch is also one of the likeliest real mismatches in practice,
# because supplementary groups are derived from the image's /etc/group rather than written
# by hand, so a stale policy disagrees here first.
#
# These are policy data, not workload data -- the same values appear in the policy the
# reader already holds -- so naming them leaks nothing, on the same rationale as mounts.
errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    not candidate_agrees_on_user
    accepted := {describe_user(c.container.OCI.Process.User) | some c in all_policy_container_entries}
    msg := sprintf("process user: request has %v, policy accepts %v", [describe_user(input.OCI.Process.User), accepted])
}

# Delegates to the enforcement rule for the same reason `env_declared_by_some_candidate`
# does: a hand-rolled comparison would drift, and `allow_user` compares AdditionalGids as
# a set rather than a list.
candidate_agrees_on_user if {
    some entry in all_policy_container_entries
    allow_user(entry.container.OCI.Process, input.OCI.Process)
}

describe_user(user) := sprintf("uid=%v gid=%v additionalGids=%v", [user.UID, user.GID, sort([g | some g in user.AdditionalGids])])

# Environment variables: names only. A value can be a password or a sealed secret, and the
# name alone is enough to say which variable was not expected.
errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    unmatched := unmatched_env_names
    count(unmatched) > 0
    msg := sprintf("environment variables no policy container declares: %v", [unmatched])
}

unmatched_env_names := {name |
    some i_env in input.OCI.Process.Env
    not env_declared_by_some_candidate(i_env)
    name := split(i_env, "=")[0]
}

# RM-97: ask the *enforcement* rule, not a private copy of it. A plain `p_env == i_env`
# ignores everything `allow_var` knows: the `$(host-name)`, `$(sandbox-name)` and
# `$(sandbox-namespace)` substitutions, the `allow_env_regex` list, and the fieldRef and
# IP-valued forms. It therefore reported `HOSTNAME` as undeclared against a policy that
# plainly declares `HOSTNAME=$(host-name)`, and reported every regex-admitted
# `KUBERNETES_*` variable as undeclared -- on requests whose real defect was elsewhere.
# Delegating keeps the diagnostic honest by construction: it can only name a variable the
# enforcement itself would have rejected.
env_declared_by_some_candidate(i_env) if {
    some entry in all_policy_container_entries
    allow_var(
        entry.container.OCI.Process,
        input.OCI.Process,
        i_env,
        request_sandbox_name,
        request_sandbox_namespace,
    )
}

# The substitution variables `allow_var` expects. Both are read from the request, which is
# what `allow_by_anno` passes to the enforcement path; default to "" so a request missing
# the annotation still produces a diagnostic instead of an undefined rule.
request_sandbox_name := object.get(input.OCI.Annotations, S_NAME_KEY, "")

request_sandbox_namespace := object.get(input.OCI.Annotations, S_NAMESPACE_KEY, "")

# Mount destinations. These are declared in the policy, so reporting them leaks nothing,
# and "which mount was not expected" is the single most common create-container question.
errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    unmatched := unmatched_mount_destinations
    count(unmatched) > 0
    msg := sprintf("mount destinations no policy container declares: %v", [unmatched])
}

unmatched_mount_destinations := {dest |
    some i_mount in input.OCI.Mounts
    not mount_destination_declared_by_some_candidate(i_mount.destination)
    dest := i_mount.destination
}

mount_destination_declared_by_some_candidate(dest) if {
    some entry in all_policy_container_entries
    some p_mount in entry.container.OCI.Mounts
    p_mount.destination == dest
}

# Storage shape. A count mismatch is reported separately from a content mismatch because
# the two have completely different causes: the first means the runtime and genpolicy
# disagree about how the image is laid out (how many layers, whether a scratch device is
# present), the second means they agree on the shape and disagree on what is in it.
errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    not candidate_agrees_on_storage_count
    accepted := {count(c.container.storages) | some c in all_policy_container_entries}
    msg := sprintf("storage count: request presents %v storages, policy declares %v", [presented_storage_count, accepted])
}

candidate_agrees_on_storage_count if {
    some entry in all_policy_container_entries
    count(entry.container.storages) == presented_storage_count
}

# RM-97: count the presented storages the way `allow_storages` does -- excluding
# `image_guest_pull`. genpolicy never emits an `image_guest_pull` storage into a policy
# (upstream does not either); the driver is matched against the container's image via
# `allow_image_guest_pull_source`, so a policy declaring zero of them is correct, not a
# mismatch. Counting them made every guest-pull denial carry a bogus
# "request presents 1 storages, policy declares {0}" line, which is the single most
# misleading thing an operator could be told about a correctly generated policy.
presented_storage_count := count(input.storages) - count([s |
	some s in input.storages
	s.driver == "image_guest_pull"
])

# dm-verity root hashes (RM-42). Reported with the partition number each was presented on,
# because a *correct* set of hashes on the *wrong* partitions is a real and previously
# observed failure (RM-62) that is otherwise indistinguishable from a genuine content
# mismatch -- the hashes match byte for byte and only the positions are swapped.
errors[msg] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    presented := presented_verity_roothashes
    count(presented) > 0
    declared := declared_verity_roothashes
    presented != declared
    msg := sprintf("dm-verity layers: request presents %v, policy declares %v (hashes that match but sit on different partition numbers mean the layer ordering disagrees, not the layer contents)", [presented, declared])
}

presented_verity_roothashes := {entry |
    some i_storage in input.storages
    i_storage.fstype == "erofs"
    some o in i_storage.options
    startswith(o, "X-kata.dmverity.roothash=")
    some p in i_storage.options
    startswith(p, "X-kata.partition-number=")
    entry := sprintf("partition %v = %v", [trim_prefix(p, "X-kata.partition-number="), trim_prefix(o, "X-kata.dmverity.roothash=")])
}

declared_verity_roothashes := {entry |
    some c in all_policy_container_entries
    some p_storage in c.container.storages
    p_storage.driver == "erofs-verity-layer"
    some o in p_storage.options
    startswith(o, "X-kata.dmverity.roothash=")
    some p in p_storage.options
    startswith(p, "X-kata.partition-number=")
    entry := sprintf("partition %v = %v", [trim_prefix(p, "X-kata.partition-number="), trim_prefix(o, "X-kata.dmverity.roothash=")])
}

# ExecProcessRequest is the other endpoint an operator hits routinely, and its denial is
# even more opaque because there is no candidate list to inspect -- the request simply is
# not in the allow list.
errors[msg] if {
    input.rule == "ExecProcessRequest"
    msg := sprintf("no policy rule permits this exec; the command must match a declared exec_process entry or an ExecProcessRequest.regex in the policy settings (requested command has %v arguments)", [count(input.process.Args)])
}
