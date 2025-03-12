# 0.2.2

- Added a `MountTab` type for non-destructive editing of fstab
- Split the mounts module into sub-modules
- Fix the `Display` for `MountInfo` to write `defaults` if the `options` field is empty
- Added `Default` derives

# 0.2.1

- Implement `Display` for `MountInfo` and `SwapInfo`
- Implement `FromStr` for `MountInfo` and `SwapInfo`
- Add deprecation notice for `MountInfo`/`SwapInfo`::`parse_line`

# 0.2.0

- Support parsing the `/etc/fstab` file, in addition to `/proc/mounts`
    - `MountList::new_from_file("/etc/fstab")`
    - `MountIter::new_from_file("/etc/fstb")`
- Support parsing any type which implements `BufRead`:
    - `MountList::new_from_reader(reader)`
    - `MountIter::new_from_reader(reader)`
- Support equivalents for swap tab files
    - `SwapIter::new_from_file("/proc/swaps")`
    - `SwapIter::new_from_reader(reader)`
    - `SwapList::new_from_file("/proc/swaps")`
    - `SwapList::new_from_reader(reader)`

# 0.1.2

- Initial release
