# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

# Test-only, redaction-safe attribution for CreateSandboxRequest.
#
# GenPolicy appends this fragment to the repository rules module before embedding
# it in fixture policies. Do not report field values here: strict-policy denials
# cross the guest boundary and may be visible to the host.

errors["guest hook path: the request specifies a guest hook path, but policy requires it to be empty"] if {
    input.rule == "CreateSandboxRequest"
    count(input.guest_hook_path) != 0
}

errors["kernel modules: the request specifies kernel modules, but policy requires none"] if {
    input.rule == "CreateSandboxRequest"
    count(input.kernel_modules) != 0
}

errors["sandbox PID namespace: the request enables a shared PID namespace, but policy requires it disabled"] if {
    input.rule == "CreateSandboxRequest"
    input.sandbox_pidns != false
}

sandbox_storage_matches_policy(storage) if {
    some policy_storage in policy_data.sandbox.storages
    storage == policy_storage
}

unmatched_sandbox_storage_indexes := {index |
    some index, storage in input.storages
    not sandbox_storage_matches_policy(storage)
}

errors[msg] if {
    input.rule == "CreateSandboxRequest"
    indexes := unmatched_sandbox_storage_indexes
    count(indexes) > 0
    msg := sprintf("sandbox storages: request entries at indexes %v do not match any policy storage", [indexes])
}

storage_field_matches_policy(storage, field) if {
    some policy_storage in policy_data.sandbox.storages
    storage[field] == policy_storage[field]
}

errors[msg] if {
    input.rule == "CreateSandboxRequest"
    some index, storage in input.storages
    some field in [
        "driver",
        "driver_options",
        "source",
        "fstype",
        "options",
        "mount_point",
        "fs_group",
        "shared",
    ]
    not storage_field_matches_policy(storage, field)
    msg := sprintf("sandbox storage %v: field %v does not match any policy storage", [index, field])
}

errors["sandbox storages: the request contains duplicate storage entries"] if {
    input.rule == "CreateSandboxRequest"
    storage_set := {storage | some storage in input.storages}
    count(storage_set) != count(input.storages)
}

candidate_matches_bundle_mounts_and_storages if {
    some entry in all_policy_container_entries
    allow_by_bundle_or_sandbox_id(
        entry.container.OCI,
        input.OCI,
        entry.container.storages,
        input.storages,
    )
}

errors["container root path, mounts, or storages do not match any policy container"] if {
    input.rule == "CreateContainerRequest"
    count(all_policy_container_entries) > 0
    not candidate_matches_bundle_mounts_and_storages
}
