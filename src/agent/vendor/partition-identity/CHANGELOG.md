# 0.2.6

- Remove the eprintln statements

# 0.2.5

- Fix `PartitionID::get_device_path()` to handle `PartitionSource::Path`s that are already canonicalized.
- Fix change in last version which broke the `PartitionID::get_source()` method.
- Eliminate unnecessary allocations when canonicalizing paths

# 0.2.4

- Implement `Display` for `PartitionID` and `PartitionSource`.

# 0.2.3

- Derive `Eq` for `PartitionSource` and `PartitionID`

# 0.2.2

- Applies a workaround to handle intermittent unavailability of `/dev/disk/by-` path operations.

# 0.2.1

- Mark `PartitionIdentifier` fields as public.
- Switch from `failure` error crate to `err-derive`
- Set `rust-toolchain` to `1.24.1`
- Derive `PartialEq` for `Error`
