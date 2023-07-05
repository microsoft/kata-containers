// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow K8s YAML field names.
#![allow(non_snake_case)]

use crate::obj_meta;
use crate::persistent_volume_claim;
use crate::pod;
use crate::pod_template;
use crate::policy;
use crate::yaml;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// See Reference / Kubernetes API / Workload Resources / StatefulSet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatefulSet {
    pub apiVersion: String,
    pub kind: String,
    pub metadata: obj_meta::ObjectMeta,
    pub spec: StatefulSetSpec,

    #[serde(skip)]
    doc_mapping: serde_yaml::Value,
}

/// See Reference / Kubernetes API / Workload Resources / StatefulSet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatefulSetSpec {
    serviceName: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    replicas: Option<i32>,

    selector: yaml::LabelSelector,

    pub template: pod_template::PodTemplateSpec,

    #[serde(skip_serializing_if = "Option::is_none")]
    volumeClaimTemplates: Option<Vec<persistent_volume_claim::PersistentVolumeClaim>>,
    // TODO: additional fields.
}

#[async_trait]
impl yaml::K8sResource for StatefulSet {
    async fn init(
        &mut self,
        use_cache: bool,
        doc_mapping: &serde_yaml::Value,
        _silent_unsupported_fields: bool,
    ) {
        yaml::k8s_resource_init(&mut self.spec.template.spec, use_cache).await;
        self.doc_mapping = doc_mapping.clone();
    }

    fn get_yaml_host_name(&self) -> Option<String> {
        if let Some(hostname) = &self.spec.template.spec.hostname {
            return Some(hostname.clone());
        }
        None
    }

    fn get_host_name(&self) -> String {
        // Example: "hostname": "no-exist-tdtd7",
        "^".to_string() + &self.metadata.get_name() + "-[a-z0-9]*$"
    }

    fn get_sandbox_name(&self) -> Option<String> {
        None
    }

    fn get_namespace(&self) -> String {
        self.metadata.get_namespace()
    }

    fn get_container_mounts_and_storages(
        &self,
        policy_mounts: &mut Vec<oci::Mount>,
        storages: &mut Vec<policy::SerializedStorage>,
        container: &pod::Container,
        agent_policy: &policy::AgentPolicy,
    ) {
        if let Some(volumes) = &self.spec.template.spec.volumes {
            yaml::get_container_mounts_and_storages(
                policy_mounts,
                storages,
                container,
                agent_policy,
                volumes,
            );
        }

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
                StatefulSet::get_mounts_and_storages(policy_mounts, volume_mounts, claims);
            }
        }
    }

    fn generate_policy(&self, agent_policy: &policy::AgentPolicy) -> String {
        agent_policy.generate_policy(self)
    }

    fn serialize(&mut self, policy: &str) -> String {
        yaml::add_policy_annotation(&mut self.doc_mapping, "spec.template.metadata", policy);
        serde_yaml::to_string(&self.doc_mapping).unwrap()
    }

    fn get_containers(&self) -> &Vec<pod::Container> {
        &self.spec.template.spec.containers
    }

    fn get_annotations(&self) -> Option<BTreeMap<String, String>> {
        if let Some(annotations) = &self.spec.template.metadata.annotations {
            return Some(annotations.clone());
        }
        None
    }
}

impl StatefulSet {
    fn get_mounts_and_storages(
        policy_mounts: &mut Vec<oci::Mount>,
        volume_mounts: &Vec<pod::VolumeMount>,
        claims: &Vec<persistent_volume_claim::PersistentVolumeClaim>,
    ) {
        for mount in volume_mounts {
            for claim in claims {
                if let Some(claim_name) = &claim.metadata.name {
                    if claim_name.eq(&mount.name) {
                        let file_name = Path::new(&mount.mountPath)
                            .file_name()
                            .unwrap()
                            .to_str()
                            .unwrap();
                        // TODO:
                        // - Get the source path below from the infra module.
                        // - Generate proper options value.
                        policy_mounts.push(oci::Mount {
                            destination: mount.mountPath.clone(),
                            r#type: "bind".to_string(),
                            source:
                                "^/run/kata-containers/shared/containers/$(bundle-id)-[a-z0-9]{16}-"
                                    .to_string()
                                    + &file_name
                                    + "$",
                            options: vec![
                                "rbind".to_string(),
                                "rprivate".to_string(),
                                "rw".to_string(),
                            ],
                        });
                    }
                }
            }
        }
    }
}