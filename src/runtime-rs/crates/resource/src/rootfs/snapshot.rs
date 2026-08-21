// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

use super::{RootfsSnapshotArtifacts, SnapshotDiskPath};

fn matching_disk<'a>(
    artifacts: &'a [RootfsSnapshotArtifacts],
    live_path: &Path,
) -> Option<&'a SnapshotDiskPath> {
    artifacts.iter().find_map(|artifact| {
        if artifact.readonly_disk.live_path == live_path {
            return Some(&artifact.readonly_disk);
        }
        artifact
            .writable_disk
            .as_ref()
            .filter(|disk| disk.live_path == live_path)
    })
}

pub fn finalize_snapshot_config(
    snapshot_dir: &Path,
    artifacts: &[RootfsSnapshotArtifacts],
) -> Result<()> {
    let config_path = snapshot_dir.join("config.json");
    let memory_ranges = snapshot_dir.join("memory-ranges");
    let data = fs::read(&config_path)
        .with_context(|| format!("read snapshot config {}", config_path.display()))?;
    let mut config: Value = serde_json::from_slice(&data)
        .with_context(|| format!("parse snapshot config {}", config_path.display()))?;

    if memory_ranges.is_file() {
        let zones = config
            .get_mut("memory")
            .and_then(Value::as_object_mut)
            .and_then(|memory| memory.get_mut("zones"))
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("snapshot config missing memory zones"))?;
        for zone in zones {
            let zone = zone
                .as_object_mut()
                .ok_or_else(|| anyhow!("snapshot config has invalid memory zone"))?;
            zone.remove("file");
        }
    }

    let disks = config
        .get_mut("disks")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("snapshot config missing disks"))?;
    let mut rewritten = HashSet::<PathBuf>::new();
    for disk in disks {
        let disk = disk
            .as_object_mut()
            .ok_or_else(|| anyhow!("snapshot config has invalid disk"))?;
        let Some(live_path) = disk.get("path").and_then(Value::as_str).map(PathBuf::from) else {
            continue;
        };
        let Some(mapping) = matching_disk(artifacts, &live_path) else {
            continue;
        };
        if !rewritten.insert(live_path.clone()) {
            return Err(anyhow!(
                "snapshot config contains duplicate disk path {}",
                live_path.display()
            ));
        }
        disk.insert(
            "path".to_string(),
            Value::String(mapping.snapshot_path.display().to_string()),
        );
        disk.remove("extent_anchor_path");
    }

    let expected = artifacts
        .iter()
        .flat_map(|artifact| {
            std::iter::once(&artifact.readonly_disk).chain(artifact.writable_disk.as_ref())
        })
        .map(|disk| disk.live_path.clone())
        .collect::<HashSet<_>>();
    if rewritten != expected {
        let missing = expected.difference(&rewritten).collect::<Vec<_>>();
        return Err(anyhow!(
            "snapshot config did not reference packaged disks: {missing:?}"
        ));
    }

    let temporary = config_path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec(&config)?)
        .with_context(|| format!("write temporary snapshot config {}", temporary.display()))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    fs::rename(&temporary, &config_path).with_context(|| {
        format!(
            "replace snapshot config {} with {}",
            config_path.display(),
            temporary.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_packaged_disks_and_memory_backing() {
        let snapshot = tempfile::tempdir().unwrap();
        let container = snapshot.path().join("containers/host-workload-id");
        fs::create_dir_all(&container).unwrap();
        let vmdk = container.join("rootfs.vmdk");
        let writable = container.join("rwlayer.img");
        fs::write(&vmdk, b"descriptor").unwrap();
        fs::write(&writable, b"rw").unwrap();
        fs::write(snapshot.path().join("memory-ranges"), b"memory").unwrap();
        fs::write(
            snapshot.path().join("config.json"),
            serde_json::to_vec(&serde_json::json!({
                "memory": {"zones": [{"id": "mem0", "file": "/run/live-memory"}]},
                "disks": [
                    {"id": "ro", "path": "/run/live/rootfs.vmdk", "extent_anchor_path": "/"},
                    {"id": "rw", "path": "/var/lib/containerd/rwlayer.img", "extent_anchor_path": "/"}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let artifacts = vec![RootfsSnapshotArtifacts {
            cri_name: "workload".to_string(),
            source_host_id: "host-workload-id".to_string(),
            snapshot_guest_id: "guest-workload-id".to_string(),
            readonly_disk: SnapshotDiskPath {
                live_path: "/run/live/rootfs.vmdk".into(),
                snapshot_path: vmdk.clone(),
            },
            writable_disk: Some(SnapshotDiskPath {
                live_path: "/var/lib/containerd/rwlayer.img".into(),
                snapshot_path: writable.clone(),
            }),
            files: vec![vmdk.clone(), writable.clone()],
        }];

        finalize_snapshot_config(snapshot.path(), &artifacts).unwrap();

        let config: Value =
            serde_json::from_slice(&fs::read(snapshot.path().join("config.json")).unwrap())
                .unwrap();
        assert!(config["memory"]["zones"][0].get("file").is_none());
        assert_eq!(config["disks"][0]["path"], vmdk.display().to_string());
        assert!(config["disks"][0].get("extent_anchor_path").is_none());
        assert_eq!(config["disks"][1]["path"], writable.display().to_string());
        assert!(config["disks"][1].get("extent_anchor_path").is_none());
    }
}
