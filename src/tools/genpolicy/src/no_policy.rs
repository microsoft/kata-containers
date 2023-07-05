// Copyright (c) 2023 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Allow K8s YAML field names.
#![allow(non_snake_case)]

use crate::pod;
use crate::policy;
use crate::yaml;

use async_trait::async_trait;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct NoPolicyResource {
    pub yaml: String,
}

#[async_trait]
impl yaml::K8sResource for NoPolicyResource {
    async fn init(
        &mut self,
        _use_cache: bool,
        _doc_mapping: &serde_yaml::Value,
        _silent_unsupported_fields: bool,
    ) {
    }

    fn get_yaml_host_name(&self) -> Option<String> {
        panic!("Unsupported");
    }

    fn get_host_name(&self) -> String {
        panic!("Unsupported");
    }

    fn get_sandbox_name(&self) -> Option<String> {
        panic!("Unsupported");
    }

    fn get_namespace(&self) -> String {
        panic!("Unsupported");
    }

    fn get_container_mounts_and_storages(
        &self,
        _policy_mounts: &mut Vec<oci::Mount>,
        _storages: &mut Vec<policy::SerializedStorage>,
        _container: &pod::Container,
        _agent_policy: &policy::AgentPolicy,
    ) {
        panic!("Unsupported");
    }

    fn generate_policy(&self, _agent_policy: &policy::AgentPolicy) -> String {
        return "".to_string();
    }

    fn serialize(&mut self, _policy: &str) -> String {
        self.yaml.clone()
    }

    fn get_containers(&self) -> &Vec<pod::Container> {
        panic!("Unsupported");
    }

    fn get_annotations(&self) -> Option<BTreeMap<String, String>> {
        panic!("Unsupported");
    }
}