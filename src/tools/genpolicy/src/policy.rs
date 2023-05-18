// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow OCI spec field names.
#![allow(non_snake_case)]

use crate::config_maps;
use crate::containerd;
use crate::infra;
use crate::kata;
use crate::registry;
use crate::utils;
use crate::yaml;

use anyhow::{anyhow, Result};
use log::info;
use oci::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct PodPolicy {
    yaml: yaml::Yaml,
    config_maps: Vec<config_maps::ConfigMap>,

    yaml_file: Option<String>,
    rules_input_file: String,

    infra_policy: infra::InfraPolicy,
}

// Example:
//
// policy_data := {
//   "containers": [
//     {
//       "oci": {
//         "ociVersion": "1.1.0-rc.1",
// ...
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyData {
    pub containers: Vec<ContainerPolicy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Volumes>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OciSpec {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ociVersion: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<OciProcess>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<Root>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Hooks>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<Linux>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OciProcess {
    pub terminal: bool,
    pub user: User,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,

    #[serde(skip_serializing_if = "String::is_empty")]
    pub cwd: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<LinuxCapabilities>,

    pub noNewPrivileges: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerPolicy {
    pub oci: OciSpec,
    storages: Vec<SerializedStorage>,
}

// TODO: can struct Storage from agent.proto be used here?
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedStorage {
    pub driver: String,
    pub driver_options: Vec<String>,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
    pub mount_point: String,
    pub fs_group: SerializedFsGroup,
}

// TODO: can struct FsGroup from agent.proto be used here?
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedFsGroup {
    pub group_id: u32,
    pub group_change_policy: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Volumes {
    pub emptyDir: Option<EmptyDirVolume>,
    pub persistentVolumeClaim: Option<PersistentVolumeClaimVolume>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmptyDirVolume {
    pub mount_type: String,
    pub mount_point: String,
    pub mount_source: String,
    pub driver: String,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistentVolumeClaimVolume {
    pub mount_type: String,
    pub mount_source: String,
}

impl PodPolicy {
    pub fn from_files(in_out_files: &utils::InOutFiles) -> Result<Self> {
        let yaml = yaml::Yaml::new(&in_out_files.yaml_file)?;

        let mut config_maps = Vec::new();
        if let Some(config_map_files) = &in_out_files.config_map_files {
            for file in config_map_files {
                config_maps.push(config_maps::ConfigMap::new(&file)?);
            }
        }

        let infra_policy = infra::InfraPolicy::new(&in_out_files.infra_data_file)?;

        let mut yaml_file = None;
        if let Some(yaml_path) = &in_out_files.yaml_file {
            yaml_file = Some(yaml_path.to_string());
        }

        Ok(PodPolicy {
            yaml,
            yaml_file,
            rules_input_file: in_out_files.rules_file.to_string(),
            infra_policy,
            config_maps,
        })
    }

    pub async fn export_policy(&mut self, in_out_files: &utils::InOutFiles) -> Result<()> {
        let mut policy_data = PolicyData {
            containers: Vec::new(),
            volumes: None,
        };

        if self.yaml.is_deployment() {
            if let Some(template) = &self.yaml.spec.template {
                policy_data.containers = self.get_policy_data(&template.spec.containers).await?;
            }
        } else {
            policy_data.containers = self.get_policy_data(&self.yaml.spec.containers).await?;
        }

        let json_data = serde_json::to_string_pretty(&policy_data)
            .map_err(|e| anyhow!(e))
            .unwrap();

        self.yaml.export_policy(
            &json_data,
            &self.rules_input_file,
            &self.yaml_file,
            &in_out_files.output_policy_file,
        )?;

        Ok(())
    }

    async fn get_policy_data(
        &self,
        spec_containers: &Option<Vec<yaml::Container>>,
    ) -> Result<Vec<ContainerPolicy>> {
        let mut policy_containers = Vec::new();

        if let Some(containers) = spec_containers {
            for index in 0..containers.len() {
                policy_containers.push(self.get_container_policy_by_yaml_type(index).await?);
            }
        }

        Ok(policy_containers)
    }

    // Create ContainerPolicy object based on:
    // - Container image configuration, pulled from the registry.
    // - containerd default values for each container.
    // - Kata Containers namespaces.
    // - K8s infrastructure information.
    pub async fn get_container_policy_by_yaml_type(
        &self,
        container_index: usize,
    ) -> Result<ContainerPolicy> {
        if self.yaml.is_deployment() {
            if let Some(template) = &self.yaml.spec.template {
                if let Some(containers) = &template.spec.containers {
                    self.get_container_policy(container_index, &containers[container_index])
                        .await
                } else {
                    Err(anyhow!("No containers in Deployment pod template!"))
                }
            } else {
                Err(anyhow!("No pod template in Deployment spec!"))
            }
        } else if let Some(containers) = &self.yaml.spec.containers {
            self.get_container_policy(container_index, &containers[container_index])
                .await
        } else {
            Err(anyhow!("No containers in Pod spec!"))
        }
    }

    pub async fn get_container_policy(
        &self,
        container_index: usize,
        yaml_container: &yaml::Container,
    ) -> Result<ContainerPolicy> {
        let is_pause_container = container_index == 0;
        let is_deployment_yaml = self.yaml.is_deployment();

        let mut pod_name = String::new();
        if let Some(name) = &self.yaml.metadata.name {
            pod_name = name.clone();
        }

        // Example: "hostname": "^busybox-cc$",
        let mut hostname = "^".to_string() + &pod_name;
        if is_deployment_yaml {
            // Example: "hostname": "^busybox-cc-5bdd867667-xxmdz$",
            hostname += "-[a-z0-9]{10}-[a-z0-9]{5}"
        }
        hostname += "$";

        let registry_container = registry::Container::new(&yaml_container.image).await?;
        let mut infra_container = &self.infra_policy.pause_container;
        if !is_pause_container {
            infra_container = &self.infra_policy.other_container;
        }

        let mut root: Option<Root> = None;
        if let Some(infra_root) = &infra_container.root {
            let mut policy_root = infra_root.clone();
            policy_root.readonly = yaml_container.read_only_root_filesystem();
            root = Some(policy_root);
        }

        let mut annotations = BTreeMap::new();
        infra::get_annotations(&mut annotations, infra_container)?;
        if !is_deployment_yaml {
            annotations.insert(
                "io.kubernetes.cri.sandbox-name".to_string(),
                pod_name.to_string(),
            );
        }
        if !is_pause_container {
            annotations.insert(
                "io.kubernetes.cri.image-name".to_string(),
                yaml_container.image.to_string(),
            );
        }

        let namespace = if let Some(ns) = &self.yaml.metadata.namespace {
            ns.clone()
        } else {
            "default".to_string()
        };
        annotations.insert("io.kubernetes.cri.sandbox-namespace".to_string(), namespace);

        if !yaml_container.name.is_empty() {
            annotations.insert(
                "io.kubernetes.cri.container-name".to_string(),
                yaml_container.name.to_string(),
            );
        }

        // Start with the Default Unix Spec from
        // https://github.com/containerd/containerd/blob/release/1.6/oci/spec.go#L132
        let privileged_container = yaml_container.is_privileged();
        let mut process = containerd::get_process(privileged_container);
        let (yaml_has_command, yaml_has_args) = yaml_container.get_process_args(&mut process.args);

        registry_container.get_process(&mut process, yaml_has_command, yaml_has_args)?;

        if container_index != 0 {
            process.env.push("HOSTNAME=".to_string() + &pod_name);
        }

        yaml_container.get_env_variables(&mut process.env, &self.config_maps);

        infra::get_process(&mut process, &infra_container)?;
        process.noNewPrivileges = !yaml_container.allow_privilege_escalation();

        let mut mounts = containerd::get_mounts(is_pause_container, privileged_container);
        self.infra_policy.get_policy_mounts(
            &mut mounts,
            &infra_container.mounts,
            &yaml_container,
            container_index == 0,
        )?;

        let image_layers = registry_container.get_image_layers();
        let mut storages = Default::default();
        get_image_layer_storages(&mut storages, &image_layers, &root)?;

        self.get_mounts_and_storages(
            &mut mounts,
            &mut storages,
            yaml_container,
            &self.infra_policy,
        )?;

        let mut linux = containerd::get_linux(privileged_container);
        linux.namespaces = kata::get_namespaces();
        infra::get_linux(&mut linux, &infra_container.linux)?;

        Ok(ContainerPolicy {
            oci: OciSpec {
                ociVersion: Some("1.1.0-rc.1".to_string()),
                process: Some(process),
                root,
                hostname: Some(hostname),
                mounts,
                hooks: None,
                annotations: Some(annotations),
                linux: Some(linux),
            },
            storages,
        })
    }

    fn get_mounts_and_storages(
        &self,
        policy_mounts: &mut Vec<oci::Mount>,
        storages: &mut Vec<SerializedStorage>,
        container: &yaml::Container,
        infra_policy: &infra::InfraPolicy,
    ) -> Result<()> {
        if let Some(volumes) = &self.yaml.spec.volumes {
            for volume in volumes {
                self.get_container_mounts_and_storages(
                    policy_mounts,
                    storages,
                    container,
                    infra_policy,
                    volume,
                )?;
            }
        }
        Ok(())
    }

    fn get_container_mounts_and_storages(
        &self,
        policy_mounts: &mut Vec<oci::Mount>,
        storages: &mut Vec<SerializedStorage>,
        container: &yaml::Container,
        infra_policy: &infra::InfraPolicy,
        volume: &yaml::Volume,
    ) -> Result<()> {
        if let Some(volume_mounts) = &container.volumeMounts {
            for volume_mount in volume_mounts {
                if volume_mount.name.eq(&volume.name) {
                    infra_policy.get_mount_and_storage(
                        policy_mounts,
                        storages,
                        volume,
                        volume_mount,
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn get_image_layer_storages(
    storages: &mut Vec<SerializedStorage>,
    image_layers: &Vec<registry::ImageLayer>,
    root: &Option<Root>,
) -> Result<()> {
    if let Some(root_mount) = root {
        let mut overlay_storage = SerializedStorage {
            driver: "blk".to_string(),
            driver_options: Vec::new(),
            source: String::new(), // TODO
            fstype: "tar-overlay".to_string(),
            options: Vec::new(),
            mount_point: root_mount.path.clone(),
            fs_group: SerializedFsGroup {
                group_id: 0,
                group_change_policy: 0,
            },
        };

        // TODO: load this path from data.json.
        let layers_path = "/run/kata-containers/sandbox/layers/".to_string();

        let mut previous_chain_id = String::new();
        for layer in image_layers {
            let verity_option = "kata.dm-verity=".to_string() + &layer.verity_hash;

            // See https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
            let chain_id = if previous_chain_id.is_empty() {
                layer.diff_id.clone()
            } else {
                let mut hasher = Sha256::new();
                hasher.update(previous_chain_id.clone() + " " + &layer.diff_id);
                format!("sha256:{:x}", hasher.finalize())
            };
            info!(
                "previous_chain_id = {}, chain_id = {}",
                &previous_chain_id, &chain_id
            );
            previous_chain_id = chain_id.clone();

            let layer_name = name_to_hash(&chain_id);

            storages.push(SerializedStorage {
                driver: "blk".to_string(),
                driver_options: Vec::new(),
                source: String::new(), // TODO
                fstype: "tar".to_string(),
                options: vec!["ro".to_string(), verity_option],
                mount_point: layers_path.clone() + &layer_name,
                fs_group: SerializedFsGroup {
                    group_id: 0,
                    group_change_policy: 0,
                },
            });

            overlay_storage
                .options
                .push("kata.layer=".to_string() + &layer_name + "," + &layer.verity_hash);
        }

        storages.push(overlay_storage);
    }

    Ok(())
}

// TODO: avoid copying this code from snapshotter.rs
/// Converts the given name to a string representation of its sha256 hash.
fn name_to_hash(name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name);
    format!("{:x}", hasher.finalize())
}
