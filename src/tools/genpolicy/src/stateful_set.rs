// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow K8s YAML field names.
#![allow(non_snake_case)]

use crate::agent;
use crate::mount_and_storage;
use crate::obj_meta;
use crate::pod;
use crate::pod_template;
use crate::policy;
use crate::pvc;
use crate::settings;
use crate::utils::Config;
use crate::yaml;

use async_trait::async_trait;
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// See Reference / Kubernetes API / Workload Resources / StatefulSet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatefulSet {
    apiVersion: String,
    kind: String,
    metadata: obj_meta::ObjectMeta,
    spec: StatefulSetSpec,

    #[serde(skip)]
    doc_mapping: serde_yaml::Value,
}

/// See Reference / Kubernetes API / Workload Resources / StatefulSet.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StatefulSetSpec {
    serviceName: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    replicas: Option<i32>,

    selector: yaml::LabelSelector,

    template: pod_template::PodTemplateSpec,

    #[serde(skip_serializing_if = "Option::is_none")]
    volumeClaimTemplates: Option<Vec<pvc::PersistentVolumeClaim>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    updateStrategy: Option<StatefulSetUpdateStrategy>,

    #[serde(skip_serializing_if = "Option::is_none")]
    revisionHistoryLimit: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    minReadySeconds: Option<i32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    podManagementPolicy: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    persistentVolumeClaimRetentionPolicy: Option<StatefulSetPersistentVolumeClaimRetentionPolicy>,
}

/// See Reference / Kubernetes API / Workload Resources / StatefulSet.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StatefulSetPersistentVolumeClaimRetentionPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    whenDeleted: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    whenScaled: Option<String>,
}

/// See Reference / Kubernetes API / Workload Resources / StatefulSet.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StatefulSetUpdateStrategy {
    #[serde(skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    rollingUpdate: Option<RollingUpdateStatefulSetStrategy>,
}

/// See Reference / Kubernetes API / Workload Resources / StatefulSet.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RollingUpdateStatefulSetStrategy {
    #[serde(skip_serializing_if = "Option::is_none")]
    maxUnavailable: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    partition: Option<i32>,
}

#[async_trait]
impl yaml::K8sResource for StatefulSet {
    async fn init(&mut self, config: &Config, doc_mapping: &serde_yaml::Value, _silent: bool) {
        yaml::k8s_resource_init(&mut self.spec.template.spec, config).await;
        self.doc_mapping = doc_mapping.clone();
    }

    fn get_sandbox_name(&self) -> Option<String> {
        None
    }

    fn get_namespace(&self) -> Option<String> {
        self.metadata.get_namespace()
    }

    fn get_container_mounts_and_storages(
        &self,
        policy_mounts: &mut Vec<policy::KataMount>,
        storages: &mut Vec<agent::Storage>,
        persistent_volume_claims: &[pvc::PersistentVolumeClaim],
        container: &pod::Container,
        settings: &settings::Settings,
    ) {
        yaml::get_container_mounts_and_storages(
            policy_mounts,
            storages,
            persistent_volume_claims,
            container,
            settings,
            &self.spec.template.spec.volumes,
        );

        // Example:
        //
        // containers:
        //   - name: nginx
        //     image: "nginx"
        //     volumeMounts:
        //       - mountPath: /usr/share/nginx/html
        //         name: www
        // ...
        //
        // volumeClaimTemplates:
        //   - metadata:
        //       name: www
        //     spec:
        //       accessModes:
        //         - ReadWriteOnce
        //       resources:
        //         requests:
        //           storage: 1Gi
        if let Some(volume_mounts) = &container.volumeMounts {
            if let Some(claims) = &self.spec.volumeClaimTemplates {
                StatefulSet::get_mounts_and_storages(
                    policy_mounts,
                    storages,
                    settings,
                    volume_mounts,
                    claims,
                );
            }
        }
    }

    fn generate_policy(&self, agent_policy: &policy::AgentPolicy) -> String {
        agent_policy.generate_policy(self)
    }

    fn serialize(&mut self, policy: &str) -> String {
        yaml::add_policy_annotation(&mut self.doc_mapping, "spec.template", policy);
        serde_yaml::to_string(&self.doc_mapping).unwrap()
    }

    fn get_containers(&self) -> &Vec<pod::Container> {
        &self.spec.template.spec.containers
    }

    fn get_annotations(&self) -> &Option<BTreeMap<String, String>> {
        if let Some(metadata) = &self.spec.template.metadata {
            return &metadata.annotations;
        }
        &None
    }

    fn use_host_network(&self) -> bool {
        if let Some(host_network) = self.spec.template.spec.hostNetwork {
            return host_network;
        }
        false
    }

    fn use_sandbox_pidns(&self) -> bool {
        if let Some(shared) = self.spec.template.spec.shareProcessNamespace {
            return shared;
        }
        false
    }
}

impl StatefulSet {
    fn get_mounts_and_storages(
        policy_mounts: &mut Vec<policy::KataMount>,
        storages: &mut Vec<agent::Storage>,
        settings: &settings::Settings,
        volume_mounts: &Vec<pod::VolumeMount>,
        claims: &[pvc::PersistentVolumeClaim],
    ) {
        debug!("StatefulSet::get_mounts_and_storages");
        for mount in volume_mounts {
            for claim in claims {
                if let Some(claim_name) = &claim.metadata.name {
                    if claim_name.eq(&mount.name) {
                        // check if a storage class is set and if it is a virtio-blk storage class
                        let is_blk_mount = if let Some(storage_class) = &claim.spec.storageClassName
                        {
                            settings
                                .common
                                .virtio_blk_storage_classes
                                .contains(storage_class)
                        } else {
                            false
                        };
                        // check if a storage class is set and if it is a smb storage class
                        let is_smb_mount = if let Some(storage_class) = &claim.spec.storageClassName
                        {
                            settings.common.smb_storage_classes.contains(storage_class)
                        } else {
                            false
                        };

                        let propagation = match &mount.mountPropagation {
                            Some(p) if p == "Bidirectional" => "rshared",
                            _ => "rprivate",
                        };

                        let access = if let Some(true) = mount.readOnly {
                            "ro"
                        } else {
                            "rw"
                        };

                        let mount_options = (propagation, access);
                        mount_and_storage::handle_persistent_volume_claim(
                            is_blk_mount,
                            is_smb_mount,
                            mount,
                            policy_mounts,
                            storages,
                            mount_options,
                        );
                    }
                }
            }
        }
    }
}
