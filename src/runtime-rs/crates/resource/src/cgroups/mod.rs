// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod cgroup_persist;
mod resource;
pub use resource::CgroupsResource;
mod resource_inner;
mod utils;

use anyhow::{anyhow, Result};
use cgroups_rs::manager::is_systemd_cgroup;
use hypervisor::HYPERVISOR_DRAGONBALL;
use kata_sys_util::spec::load_oci_spec;
use kata_types::config::TomlConfig;

use crate::cgroups::cgroup_persist::CgroupState;

const SANDBOXED_CGROUP_PATH: &str = "kata_sandboxed_pod";

pub struct CgroupArgs {
    pub sid: String,
    pub config: TomlConfig,
}

pub struct CgroupConfig {
    pub path: String,
    pub overhead_path: String,
    pub sandbox_cgroup_only: bool,
    pub enable_vcpus_pinning: bool,
}

fn sandbox_cgroup_path(sid: &str, spec: Option<&oci_spec::runtime::Spec>) -> String {
    let Some(spec) = spec else {
        return format!("{SANDBOXED_CGROUP_PATH}/{sid}");
    };
    let path = spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.cgroups_path().as_ref())
        .map(|path| path.display().to_string().trim_start_matches('/').to_string())
        .unwrap_or_default();
    let is_pod_set = spec
        .annotations()
        .as_ref()
        .and_then(|annotations| annotations.get("io.podset/set_uid"))
        .is_some_and(|uid| !uid.is_empty());
    if !is_pod_set {
        return path;
    }
    if is_systemd_cgroup(&path) {
        format!("kubepods.slice:kata-podset:{sid}")
    } else {
        format!("kubepods/kata-podsets/{sid}")
    }
}

impl CgroupConfig {
    fn new(sid: &str, toml_config: &TomlConfig) -> Result<Self> {
        let spec = load_oci_spec().ok();
        let path = sandbox_cgroup_path(sid, spec.as_ref());

        let overhead_path = utils::gen_overhead_path(is_systemd_cgroup(&path), sid);

        // Dragonball and runtime are the same process, so that the
        // sandbox_cgroup_only is overwriten to true.
        let sandbox_cgroup_only = if toml_config.runtime.hypervisor_name == HYPERVISOR_DRAGONBALL {
            true
        } else {
            toml_config.runtime.sandbox_cgroup_only
        };

        let enable_vcpus_pinning = toml_config.runtime.enable_vcpus_pinning;

        Ok(Self {
            path,
            overhead_path,
            sandbox_cgroup_only,
            enable_vcpus_pinning,
        })
    }

    fn restore(state: &CgroupState) -> Result<Self> {
        let path = state
            .path
            .as_ref()
            .ok_or_else(|| anyhow!("cgroup path is missing in state"))?;
        let overhead_path = state
            .overhead_path
            .as_ref()
            .ok_or_else(|| anyhow!("overhead path is missing in state"))?;

        Ok(Self {
            path: path.clone(),
            overhead_path: overhead_path.clone(),
            sandbox_cgroup_only: state.sandbox_cgroup_only,
            enable_vcpus_pinning: state.enable_vcpus_pinning,
        })
    }
}

#[cfg(test)]
mod pod_set_tests {
    use super::*;
    use std::{collections::HashMap, path::PathBuf};

    #[test]
    fn shared_vm_cgroup_is_not_owned_by_first_pod() {
        for (original, shared) in [
            (
                "kubepods-burstable-podfirst.slice:cri-containerd:sandbox-1",
                "kubepods.slice:kata-podset:sandbox-1",
            ),
            (
                "/kubepods/burstable/podfirst/sandbox-1",
                "kubepods/kata-podsets/sandbox-1",
            ),
        ] {
            let mut spec = oci_spec::runtime::Spec::default();
            let mut linux = oci_spec::runtime::Linux::default();
            linux.set_cgroups_path(Some(PathBuf::from(original)));
            spec.set_linux(Some(linux));
            assert_eq!(
                sandbox_cgroup_path("sandbox-1", Some(&spec)),
                original.trim_start_matches('/')
            );
            spec.set_annotations(Some(HashMap::from([(
                "io.podset/set_uid".to_string(),
                String::new(),
            )])));
            assert_eq!(
                sandbox_cgroup_path("sandbox-1", Some(&spec)),
                original.trim_start_matches('/')
            );
            spec.annotations_mut()
                .as_mut()
                .unwrap()
                .insert("io.podset/set_uid".to_string(), "set-1".to_string());
            assert_eq!(sandbox_cgroup_path("sandbox-1", Some(&spec)), shared);
        }
    }
}
