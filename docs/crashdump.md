# Cloud Hypervisor automatic crashdump collection

## High level summary

This change adds automatic guest crashdump collection for Cloud Hypervisor in Kata Containers, matching the existing QEMU crashdump capability.

When a guest panic event is detected, the runtime collects a guest memory dump and related metadata so post-mortem analysis can be done without manual intervention.

## Major changes

- Added Cloud Hypervisor panic-event monitoring in `virtcontainers` to detect guest kernel panics.
- Enabled Cloud Hypervisor `pvpanic` and event monitor integration when crashdump collection is configured.
- Added Cloud Hypervisor guest memory dump collection flow (ELF `vmcore` plus metadata).
- Added `guest_memory_dump_path` to `configuration-clh.toml.in` so operators can configure where crashdumps are stored on the host.
- Set guest kernel panic behavior to avoid immediate reboot during dump collection (to allow dump capture to complete).

Crashdump artifacts are stored under:

`<guest_memory_dump_path>/<sandbox-id>/`

## Breaking changes

No API or config breaking changes were introduced.

Behavioral note:

- With crashdump collection enabled, VM teardown may wait briefly while dump capture completes (bounded by timeout safeguards in runtime logic).

## Azure-specific notes

- No Azure-only code path was introduced in this change.
- The feature is runtime/Cloud Hypervisor based and applies the same way on Azure-hosted Kata deployments as on other environments.
