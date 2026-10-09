# OpenVMM runtime follow-ups

These items were left out of the initdata/HOST_DATA change for separate review.

## Dynamic sizing and memory resize reporting

`src/runtime-rs/crates/hypervisor/src/openvmm/inner_hypervisor.rs`:
`resize_memory()` currently returns the requested size without resizing the VM.
The proposed change to return `default_memory` was dropped because it is
unrelated to initdata and changes ordinary OpenVMM guests as well as SNP guests.

When revisiting dynamic sizing:

- Distinguish selectable CPU/memory sizes at boot from resizing a running VM.
- Define supported behavior for SNP IGVM and ordinary OpenVMM guests.
- Implement accurate resize results or explicit unsupported handling, and check
  how the resource manager consumes those results.
- Add targeted resize tests. The fixed-profile E2E uses
  `static_sandbox_resource_mgmt=true`, which bypasses runtime CPU/memory updates.

## Per-VM runtime directory cleanup

In the same file, `cleanup()` remains a no-op. The proposed removal of
`/run/kata/<sandbox-id>` was dropped because the directory, sockets and
`openvmm.log` predate initdata support.

Review cleanup separately:

- Confirm ownership and teardown ordering, including failed startup and repeated
  cleanup, before removing the per-VM directory.
- Decide whether and how to retain `openvmm.log` for post-shutdown diagnostics.
- Keep runtime-directory cleanup distinct from initdata disk and other resource
  cleanup; those artifacts live elsewhere.
- Test successful shutdown, failed startup, repeated cleanup and removal errors.
