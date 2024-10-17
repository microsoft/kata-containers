// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow OCI spec field names.
#![allow(non_snake_case)]

use crate::agent;
use crate::pod;
use crate::policy;
use crate::pvc;
use crate::settings;
use crate::volume;

use log::{debug, warn};
use std::ffi::OsString;
use std::path::Path;
use std::str;

pub fn get_policy_mounts(
    settings: &settings::Settings,
    p_mounts: &mut Vec<policy::KataMount>,
    yaml_container: &pod::Container,
    is_pause_container: bool,
) {
    if let Some(volumeMounts) = &yaml_container.volumeMounts {
        for volumeMount in volumeMounts {
            if volumeMount.subPath.is_some() {
                panic!("Kata Containers doesn't support volumeMounts.subPath - see https://github.com/kata-containers/runtime/issues/2812");
            }
        }
    }

    let c_settings = settings.get_container_settings(is_pause_container);
    let settings_mounts = &c_settings.Mounts;
    let rootfs_access = if yaml_container.read_only_root_filesystem() {
        "ro"
    } else {
        "rw"
    };

    for s_mount in settings_mounts {
        if keep_settings_mount(settings, s_mount, &yaml_container.volumeMounts) {
            let mut mount = s_mount.clone();
            adjust_termination_path(&mut mount, yaml_container);

            if mount.source.is_empty() && mount.type_.eq("bind") {
                if let Some(file_name) = Path::new(&mount.destination).file_name() {
                    if let Some(file_name) = file_name.to_str() {
                        mount.source = format!("$(sfprefix){file_name}$");
                    }
                }
            }

            if let Some(policy_mount) = p_mounts
                .iter_mut()
                .find(|m| m.destination.eq(&s_mount.destination))
            {
                // Update an already existing mount.
                policy_mount.type_ = mount.type_.clone();
                policy_mount.source = mount.source.clone();
                policy_mount.options = mount.options.iter().map(String::from).collect();
            } else {
                // Add a new mount.
                if !is_pause_container
                    && (s_mount.destination.eq("/etc/hostname")
                        || s_mount.destination.eq("/etc/resolv.conf"))
                {
                    mount.options.push(rootfs_access.to_string());
                }
                p_mounts.push(mount);
            }
        }
    }
}

fn keep_settings_mount(
    settings: &settings::Settings,
    s_mount: &policy::KataMount,
    yaml_mounts: &Option<Vec<pod::VolumeMount>>,
) -> bool {
    let destinations = &settings.mount_destinations;
    let mut keep = destinations.iter().any(|d| s_mount.destination.eq(d));

    if !keep {
        if let Some(mounts) = yaml_mounts {
            keep = mounts.iter().any(|m| m.mountPath.eq(&s_mount.destination));
        }
    }

    keep
}

fn adjust_termination_path(mount: &mut policy::KataMount, yaml_container: &pod::Container) {
    if mount.destination == "/dev/termination-log" {
        if let Some(path) = &yaml_container.terminationMessagePath {
            mount.destination = path.clone();
        }
    }
}

pub fn get_mount_and_storage(
    settings: &settings::Settings,
    p_mounts: &mut Vec<policy::KataMount>,
    storages: &mut Vec<agent::Storage>,
    persistent_volume_claims: &[pvc::PersistentVolumeClaim],
    yaml_volume: &volume::Volume,
    yaml_mount: &pod::VolumeMount,
) {
    let propagation = match &yaml_mount.mountPropagation {
        Some(p) if p == "Bidirectional" => "rshared",
        _ => "rprivate",
    };

    let access = if let Some(true) = yaml_mount.readOnly {
        "ro"
    } else {
        "rw"
    };

    let mount_options = (propagation, access);

    if let Some(emptyDir) = &yaml_volume.emptyDir {
        let memory_medium = if let Some(medium) = &emptyDir.medium {
            medium == "Memory"
        } else {
            false
        };
        get_empty_dir_mount_and_storage(settings, p_mounts, storages, yaml_mount, memory_medium);
    } else if yaml_volume.persistentVolumeClaim.is_some() {
        get_persistent_volume_claim_mount(
            settings,
            yaml_mount,
            yaml_volume,
            p_mounts,
            storages,
            persistent_volume_claims,
            mount_options,
        );
    } else if yaml_volume.azureFile.is_some() {
        get_shared_bind_mount(yaml_mount, p_mounts, mount_options);
    } else if yaml_volume.hostPath.is_some() {
        get_host_path_mount(yaml_mount, yaml_volume, p_mounts, mount_options);
    } else if yaml_volume.configMap.is_some() || yaml_volume.secret.is_some() {
        get_config_map_mount_and_storage(settings, p_mounts, storages, yaml_mount);
    } else if yaml_volume.projected.is_some() {
        // Projected mounts are always read-only.
        get_shared_bind_mount(yaml_mount, p_mounts, ("rprivate", "ro"));
    } else if yaml_volume.downwardAPI.is_some() {
        get_downward_api_mount(yaml_mount, p_mounts);
    } else if yaml_volume.ephemeral.is_some() {
        get_ephemeral_mount(
            settings,
            yaml_mount,
            yaml_volume,
            p_mounts,
            storages,
            mount_options,
        );
    } else {
        todo!("Unsupported volume type {:?}", yaml_volume);
    }
}

fn get_empty_dir_mount_and_storage(
    settings: &settings::Settings,
    p_mounts: &mut Vec<policy::KataMount>,
    storages: &mut Vec<agent::Storage>,
    yaml_mount: &pod::VolumeMount,
    memory_medium: bool,
) {
    let settings_volumes = &settings.volumes;
    let settings_empty_dir = if memory_medium {
        &settings_volumes.emptyDir_memory
    } else {
        &settings_volumes.emptyDir
    };
    debug!("Settings emptyDir: {:?}", settings_empty_dir);

    if yaml_mount.subPathExpr.is_none() {
        storages.push(agent::Storage {
            driver: settings_empty_dir.driver.clone(),
            driver_options: Vec::new(),
            source: settings_empty_dir.source.clone(),
            fstype: settings_empty_dir.fstype.clone(),
            options: settings_empty_dir.options.clone(),
            mount_point: format!("{}{}$", &settings_empty_dir.mount_point, &yaml_mount.name),
            fs_group: None,
        });
    }

    let source = if yaml_mount.subPathExpr.is_some() {
        let file_name = Path::new(&yaml_mount.mountPath).file_name().unwrap();
        let name = OsString::from(file_name).into_string().unwrap();
        format!("{}{name}$", &settings_volumes.configMap.mount_source)
    } else {
        format!("{}{}$", &settings_empty_dir.mount_source, &yaml_mount.name)
    };

    let mount_type = if yaml_mount.subPathExpr.is_some() {
        "bind"
    } else {
        &settings_empty_dir.mount_type
    };

    p_mounts.push(policy::KataMount {
        destination: yaml_mount.mountPath.to_string(),
        type_: mount_type.to_string(),
        source,
        options: vec![
            "rbind".to_string(),
            "rprivate".to_string(),
            "rw".to_string(),
        ],
    });
}

fn get_persistent_volume_claim_mount(
    settings: &settings::Settings,
    yaml_mount: &pod::VolumeMount,
    yaml_volume: &volume::Volume,
    p_mounts: &mut Vec<policy::KataMount>,
    storages: &mut Vec<agent::Storage>,
    persistent_volume_claims: &[pvc::PersistentVolumeClaim],
    mount_options: (&str, &str),
) {
    let volume_pvc = yaml_volume.persistentVolumeClaim.as_ref().unwrap();
    let pvc_name = &volume_pvc.claimName;
    let pvc_resource = persistent_volume_claims
        .iter()
        .find(|pvc_resource| pvc_resource.metadata.name.as_ref() == Some(pvc_name));

    if pvc_resource.is_none() {
        warn!(
            "Unable to determine backing storage of persistent volume claim '{pvc_name}'. \
            Pass `-c <pvc.yaml>` to get rid of this warning."
        );
    }

    let is_blk_mount = pvc_resource
        .and_then(|pvc_resource| pvc_resource.spec.storageClassName.as_ref())
        .is_some_and(|sc| settings.common.virtio_blk_storage_classes.contains(sc));

    let is_smb_mount = pvc_resource
        .and_then(|pvc_resource| pvc_resource.spec.storageClassName.as_ref())
        .is_some_and(|sc| settings.common.smb_storage_classes.contains(sc));

    let is_coco_ephemeral_mount = pvc_resource
        .and_then(|pvc_resource| pvc_resource.spec.storageClassName.as_ref())
        .is_some_and(|sc| settings.common.coco_ephemeral_storage_classes.contains(sc));

    handle_persistent_volume_claim(
        is_blk_mount,
        is_smb_mount,
        is_coco_ephemeral_mount,
        yaml_mount,
        p_mounts,
        storages,
        mount_options,
    );
}

fn get_host_path_mount(
    yaml_mount: &pod::VolumeMount,
    yaml_volume: &volume::Volume,
    p_mounts: &mut Vec<policy::KataMount>,
    mount_options: (&str, &str),
) {
    let host_path = yaml_volume.hostPath.as_ref().unwrap().path.clone();
    let path = Path::new(&host_path);

    // TODO:
    //
    // - When volume.hostPath.path: /dev/ttyS0
    //      "source": "/dev/ttyS0"
    // - When volume.hostPath.path: /tmp/results
    //      "source": "^/run/kata-containers/shared/containers/$(bundle-id)-[a-z0-9]{16}-results$"
    //
    // What is the reason for this source path difference in the Guest OS?
    if !path.starts_with("/dev/") && !path.starts_with("/sys/") {
        debug!("get_host_path_mount: calling get_shared_bind_mount");
        get_shared_bind_mount(yaml_mount, p_mounts, mount_options);
    } else {
        let dest = yaml_mount.mountPath.clone();
        let type_ = "bind".to_string();
        let (propagation, access) = mount_options;
        let options = vec![
            "rbind".to_string(),
            propagation.to_string(),
            access.to_string(),
        ];

        if let Some(policy_mount) = p_mounts.iter_mut().find(|m| m.destination.eq(&dest)) {
            debug!("get_host_path_mount: updating dest = {dest}, source = {host_path}");
            policy_mount.type_ = type_;
            policy_mount.source = host_path;
            policy_mount.options = options;
        } else {
            debug!("get_host_path_mount: adding dest = {dest}, source = {host_path}");
            p_mounts.push(policy::KataMount {
                destination: dest,
                type_,
                source: host_path,
                options,
            });
        }
    }
}

fn get_config_map_mount_and_storage(
    settings: &settings::Settings,
    p_mounts: &mut Vec<policy::KataMount>,
    storages: &mut Vec<agent::Storage>,
    yaml_mount: &pod::VolumeMount,
) {
    let settings_volumes = &settings.volumes;
    let settings_config_map = if settings.kata_config.confidential_guest {
        &settings_volumes.confidential_configMap
    } else {
        &settings_volumes.configMap
    };
    debug!("Settings configMap: {:?}", settings_config_map);

    if !settings.kata_config.confidential_guest {
        let mount_path = Path::new(&yaml_mount.mountPath).file_name().unwrap();
        let mount_path_str = OsString::from(mount_path).into_string().unwrap();

        storages.push(agent::Storage {
            driver: settings_config_map.driver.clone(),
            driver_options: Vec::new(),
            source: format!("{}{}$", &settings_config_map.mount_source, &yaml_mount.name),
            fstype: settings_config_map.fstype.clone(),
            options: settings_config_map.options.clone(),
            mount_point: format!("{}{mount_path_str}$", &settings_config_map.mount_point),
            fs_group: None,
        });
    }

    let file_name = Path::new(&yaml_mount.mountPath).file_name().unwrap();
    let name = OsString::from(file_name).into_string().unwrap();
    p_mounts.push(policy::KataMount {
        destination: yaml_mount.mountPath.clone(),
        type_: settings_config_map.mount_type.clone(),
        source: format!("{}{name}$", &settings_config_map.mount_point),
        options: settings_config_map.options.clone(),
    });
}

fn get_shared_bind_mount(
    yaml_mount: &pod::VolumeMount,
    p_mounts: &mut Vec<policy::KataMount>,
    mount_options: (&str, &str),
) {
    let mount_path = if let Some(byte_index) = str::rfind(&yaml_mount.mountPath, '/') {
        str::from_utf8(&yaml_mount.mountPath.as_bytes()[byte_index + 1..]).unwrap()
    } else {
        &yaml_mount.mountPath
    };
    let source = format!("$(sfprefix){mount_path}$");

    let dest = yaml_mount.mountPath.clone();
    let type_ = "bind".to_string();
    let (propagation, access) = mount_options;
    let options = vec![
        "rbind".to_string(),
        propagation.to_string(),
        access.to_string(),
    ];

    if let Some(policy_mount) = p_mounts.iter_mut().find(|m| m.destination.eq(&dest)) {
        debug!("get_shared_bind_mount: updating dest = {dest}, source = {source}");
        policy_mount.type_ = type_;
        policy_mount.source = source;
        policy_mount.options = options;
    } else {
        debug!("get_shared_bind_mount: adding dest = {dest}, source = {source}");
        p_mounts.push(policy::KataMount {
            destination: dest,
            type_,
            source,
            options,
        });
    }
}

fn get_downward_api_mount(yaml_mount: &pod::VolumeMount, p_mounts: &mut Vec<policy::KataMount>) {
    let mount_path = if let Some(byte_index) = str::rfind(&yaml_mount.mountPath, '/') {
        str::from_utf8(&yaml_mount.mountPath.as_bytes()[byte_index + 1..]).unwrap()
    } else {
        &yaml_mount.mountPath
    };
    let source = format!("$(sfprefix){mount_path}$");

    let dest = yaml_mount.mountPath.clone();
    let type_ = "bind".to_string();
    let options = vec![
        "rbind".to_string(),
        "rprivate".to_string(),
        "ro".to_string(),
    ];

    if let Some(policy_mount) = p_mounts.iter_mut().find(|m| m.destination.eq(&dest)) {
        debug!("get_downward_api_mount: updating dest = {dest}, source = {source}");
        policy_mount.type_ = type_;
        policy_mount.source = source;
        policy_mount.options = options;
    } else {
        debug!("get_downward_api_mount: adding dest = {dest}, source = {source}");
        p_mounts.push(policy::KataMount {
            destination: dest,
            type_,
            source,
            options,
        });
    }
}

fn get_ephemeral_mount(
    settings: &settings::Settings,
    yaml_mount: &pod::VolumeMount,
    yaml_volume: &volume::Volume,
    p_mounts: &mut Vec<policy::KataMount>,
    storages: &mut Vec<agent::Storage>,
    mount_options: (&str, &str),
) {
    let storage_class = &yaml_volume
        .ephemeral
        .as_ref()
        .unwrap()
        .volumeClaimTemplate
        .spec
        .storageClassName;

    let is_blk_mount = storage_class
        .as_ref()
        .map(|sc| settings.common.virtio_blk_storage_classes.contains(sc))
        .unwrap_or(false);

    let is_smb_mount = storage_class
        .as_ref()
        .map(|sc| settings.common.smb_storage_classes.contains(sc))
        .unwrap_or(false);

    let is_coco_ephemeral_mount = storage_class
        .as_ref()
        .map(|sc| settings.common.coco_ephemeral_storage_classes.contains(sc))
        .unwrap_or(false);

    handle_persistent_volume_claim(
        is_blk_mount,
        is_smb_mount,
        is_coco_ephemeral_mount,
        yaml_mount,
        p_mounts,
        storages,
        mount_options,
    );
}

pub fn handle_persistent_volume_claim(
    is_blk_mount: bool,
    is_smb_mount: bool,
    is_coco_ephemeral_mount: bool,
    yaml_mount: &pod::VolumeMount,
    p_mounts: &mut Vec<policy::KataMount>,
    storages: &mut Vec<agent::Storage>,
    mount_options: (&str, &str),
) {
    if is_blk_mount || is_smb_mount || is_coco_ephemeral_mount {
        let source = "$(spath)/$(b64-direct-vol-path)".to_string();

        let mut driver_options = Vec::new();
        if is_coco_ephemeral_mount {
            driver_options.push("confidential=true".to_string());
            driver_options.push("ephemeral=true".to_string());
        }

        storages.push(agent::Storage {
            driver: if is_blk_mount {
                "blk".to_string()
            } else {
                "smb".to_string()
            },
            driver_options,
            fs_group: None,
            source: "$(direct-vol-path)".to_string(),
            mount_point: source.to_string(),
            fstype: "$(fs-type)".to_string(),
            options: Vec::new(),
        });

        let dest = yaml_mount.mountPath.clone();
        let type_ = "bind".to_string();
        let (propagation, access) = mount_options;
        let options = vec![
            "rbind".to_string(),
            propagation.to_string(),
            access.to_string(),
        ];

        if let Some(policy_mount) = p_mounts.iter_mut().find(|m| m.destination == dest) {
            debug!("handle_persistent_volume_claim: updating dest = {dest}, source = {source}");
            policy_mount.type_ = type_;
            policy_mount.source = source;
            policy_mount.options = options;
        } else {
            debug!("handle_persistent_volume_claim: adding dest = {dest}, source = {source}");
            p_mounts.push(policy::KataMount {
                destination: dest,
                type_,
                source,
                options,
            });
        }
    } else {
        get_shared_bind_mount(yaml_mount, p_mounts, mount_options);
    }
}
