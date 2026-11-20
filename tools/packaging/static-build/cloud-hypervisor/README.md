# Experimental MSHV PMEM copy-on-write

The optional `mshv_pmem_cow` build feature applies a patch to Kata's
[pinned Cloud Hypervisor release](../../../../versions.yaml). Set
`features=mshv_pmem_cow` when invoking `build-static-clh.sh` from an empty
build directory. This forces a source build; normal builds are unchanged.
The build requires the same Docker environment as other source builds.

This is an experimental, single-vCPU implementation, not a production-ready
replacement for Cloud Hypervisor. It requires `x86_64` and MSHV.

## What changes

For virtio-pmem devices with `discard_writes=true`, Cloud Hypervisor maps the
backing file shared and writable on the host, but initially registers the
guest physical range without write permission. MSHV read faults can then
populate shared file pages without creating private copies.

An actual guest write exits to Cloud Hypervisor. The stopped vCPU's mapping
is split around a private 4 KiB copy of the written page. The same guest
instruction is retried without emulation; subsequent writes to that page
run natively. The device remains guest-writable, and writes are discarded
when the VM exits. This does not provide guest-visible read-only protection.

Host file-cache compound pages smaller than 2 MiB expose an MSHV huge-page
optimization failure. The patch registers PMEM in chunks of at most 511
pages to bypass that optimization, without changing ordinary guest RAM.
Unexpected PMEM read faults fail explicitly instead of being emulated as
MMIO reads.

## Experimental restrictions

- Both boot and maximum vCPU counts must be one. Supporting more requires
  coordinated vCPU quiescence while replacing MSHV memory registrations.
- Snapshot, restore, live migration, and SNP guests are unsupported and
  rejected. Private pages are not included in the existing snapshot format.
- Use one **disposable, writable copy** of the rootfs image shared by all
  test VMs. Do not point the experiment at the original image, and do not
  create a different copy per VM. The shared mapping requires opening the
  backing file read-write. Kernel write faults can mark file-cache pages
  dirty even when their contents have not changed.
- Keep that backing file's contents unchanged for the lifetime of every VM
  using it. Guest writes must remain private to their respective VMs.
- MSHV can still populate shared file pages in 2 MiB batches. Only private
  copying is demand-driven at 4 KiB granularity; file-cache consumption
  and its cgroup ownership still need to be accounted for separately.

The feature is build-time opt-in. Using this binary with Kata requires
explicitly selecting it and the disposable image in a separate runtime
configuration; the build does not install or activate it.
