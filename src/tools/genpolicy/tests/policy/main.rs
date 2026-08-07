// Copyright (c) 2024 Edgeless Systems GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use std::fmt::{self, Display};
    use std::fs;
    use std::path;
    use std::str;

    use protocols::agent::{
        AddARPNeighborsRequest, CreateContainerRequest, CreateSandboxRequest, ExecProcessRequest,
        RemoveContainerRequest, SignalProcessRequest, StartContainerRequest, StatsContainerRequest,
        TtyWinResizeRequest, UpdateInterfaceRequest, UpdateRoutesRequest, WaitProcessRequest,
    };
    use serde::{Deserialize, Serialize};

    use kata_agent_policy::policy::{AgentPolicy, PolicyCopyFileRequest};

    // Translate each test case in testcases.json
    // to one request type.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    #[serde(tag = "kind", content = "request")]
    #[allow(clippy::enum_variant_names)] // The tags need to match the entrypoint logged by the agent.
    enum TestRequest {
        CopyFileRequest(PolicyCopyFileRequest),
        CreateContainerRequest(CreateContainerRequest),
        CreateSandboxRequest(CreateSandboxRequest),
        ExecProcessRequest(ExecProcessRequest),
        RemoveContainerRequest(RemoveContainerRequest),
        SignalProcessRequest(SignalProcessRequest),
        StartContainerRequest(StartContainerRequest),
        StatsContainerRequest(StatsContainerRequest),
        TtyWinResizeRequest(TtyWinResizeRequest),
        WaitProcessRequest(WaitProcessRequest),
        UpdateInterfaceRequest(UpdateInterfaceRequest),
        UpdateRoutesRequest(UpdateRoutesRequest),
        AddARPNeighborsRequest(AddARPNeighborsRequest),
    }

    impl Display for TestRequest {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                TestRequest::CopyFileRequest(_) => write!(f, "CopyFileRequest"),
                TestRequest::CreateContainerRequest(_) => write!(f, "CreateContainerRequest"),
                TestRequest::CreateSandboxRequest(_) => write!(f, "CreateSandboxRequest"),
                TestRequest::ExecProcessRequest(_) => write!(f, "ExecProcessRequest"),
                TestRequest::RemoveContainerRequest(_) => write!(f, "RemoveContainerRequest"),
                TestRequest::SignalProcessRequest(_) => write!(f, "SignalProcessRequest"),
                TestRequest::StartContainerRequest(_) => write!(f, "StartContainerRequest"),
                TestRequest::StatsContainerRequest(_) => write!(f, "StatsContainerRequest"),
                TestRequest::TtyWinResizeRequest(_) => write!(f, "TtyWinResizeRequest"),
                TestRequest::WaitProcessRequest(_) => write!(f, "WaitProcessRequest"),
                TestRequest::UpdateInterfaceRequest(_) => write!(f, "UpdateInterfaceRequest"),
                TestRequest::UpdateRoutesRequest(_) => write!(f, "UpdateRoutesRequest"),
                TestRequest::AddARPNeighborsRequest(_) => write!(f, "AddARPNeighborsRequest"),
            }
        }
    }

    fn serialize_request_only(value: &TestRequest) -> serde_json::Result<serde_json::Value> {
        if let serde_json::Value::Object(map) = serde_json::to_value(value)? {
            for (k, v) in map {
                if k == "request" {
                    return Ok(v);
                }
            }
        }
        Ok(serde_json::Value::Null)
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct TestCase {
        description: String,
        allowed: bool,
        #[serde(flatten)]
        request: TestRequest,
    }

    /// Run tests from the given directory.
    /// The directory is searched under `src/tools/genpolicy/tests/testdata`, and
    /// it must contain a `resources.yaml` file as well as a `testcases.json` file.
    /// The resources must produce a policy when fed into genpolicy, so there
    /// should be exactly one entry with a PodSpec. The test case file must contain
    /// a JSON list of [TestCase] instances. Each instance will be of type enum TestRequest,
    /// with the tag `type` listing the exact type of request.
    async fn runtests(test_case_dir: &str) {
        // Check if config_map.yaml exists.
        // If it does, we need to copy it to the workdir.
        let is_config_map_file_present = path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/policy/testdata")
            .join(test_case_dir)
            .join("config_map.yaml")
            .exists();

        let files_to_copy = if is_config_map_file_present {
            vec!["pod.yaml", "config_map.yaml"]
        } else {
            vec!["pod.yaml"]
        };

        // Prepare temp dir for running genpolicy.
        let (workdir, testdata_dir) = prepare_workdir(test_case_dir, &files_to_copy);

        let config_files = if is_config_map_file_present {
            Some(vec![workdir
                .join("config_map.yaml")
                .to_str()
                .unwrap()
                .to_string()])
        } else {
            None
        };

        let config = genpolicy::utils::Config {
            base64_out: false,
            config_files,
            containerd_socket_path: None, // Some(String::from("/var/run/containerd/containerd.sock")),
            insecure_registries: Vec::new(),
            layers_cache: genpolicy::layers_cache::ImageLayersCache::new(&None),
            raw_out: false,
            rego_rules_path: workdir.join("rules.rego").to_str().unwrap().to_string(),
            runtime_class_names: Vec::new(),
            settings: genpolicy::settings::Settings::new(
                workdir.join("genpolicy-settings.json").to_str().unwrap(),
            ),
            silent_unsupported_fields: false,
            use_cache: false,
            version: false,
            yaml_file: workdir.join("pod.yaml").to_str().map(|s| s.to_string()),
            initdata: kata_types::initdata::InitData::new("sha256", "0.1.0"),
        };

        // The container repos/network calls can be unreliable, so retry
        // a few times before giving up.
        let mut initdata_anno = String::new();
        for i in 0..6 {
            initdata_anno = match genpolicy::policy::AgentPolicy::from_files(&config).await {
                Ok(policy) => {
                    assert_eq!(policy.resources.len(), 1);
                    policy.resources[0].generate_initdata_anno(&policy)
                }
                Err(e) => {
                    if i == 5 {
                        panic!("Failed to generate policy after 6 attempts");
                    } else {
                        println!("Retrying to generate policy: {e}");
                        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        continue;
                    }
                }
            };
            break;
        }
        let policy = decode_policy(&initdata_anno);

        // write policy to a file
        fs::write(workdir.join("policy.rego"), &policy).unwrap();

        // Write policy back to a file

        // Re-implement needed parts of AgentPolicy::initialize()
        let mut pol = AgentPolicy::new();
        pol.initialize(
            slog::Level::Debug.as_usize(),
            workdir.join("policy.rego").to_str().unwrap().to_string(),
            workdir.join("policy.log").to_str().map(|s| s.to_string()),
        )
        .await
        .unwrap();

        // Run through the test cases and evaluate the canned requests.

        let raw_cases =
            fs::read_to_string(testdata_dir.join("testcases.json")).expect("test cases readable");
        let test_cases: Vec<TestCase> =
            serde_json::from_str(&resolve_roothashes(&raw_cases, &policy))
                .expect("test case file should parse");

        for test_case in test_cases {
            println!("\n== case: {} ==\n", test_case.description);

            let v = serialize_request_only(&test_case.request).unwrap();

            let results = pol
                .allow_request(
                    &test_case.request.to_string(),
                    &serde_json::to_string(&v).unwrap(),
                )
                .await;

            let logs = fs::read_to_string(workdir.join("policy.log")).unwrap();
            let results = results.unwrap();

            // TODO(burgerdev): better description of failure (left != right)
            assert_eq!(
                test_case.allowed, results.0,
                "logs: {}\npolicy: {}",
                logs, results.1
            );
        }
    }

    /// Resolve `$(roothash-N)` placeholders in a test case file against the root
    /// hashes the generated policy actually declares, in declaration order.
    ///
    /// RM-42 derives each EROFS layer's dm-verity root hash from the layer content
    /// and the host's erofs-utils version, so the values are not knowable when the
    /// fixture is written. Baking them in would either make the suite depend on a
    /// particular erofs-utils build or -- worse -- leave stale hashes behind, which
    /// would make every negative case deny for the wrong reason and quietly stop
    /// testing what it claims to test.
    ///
    /// Index 0 is the pause container's single layer; the workload container's
    /// layers follow. A layer-count change breaks this loudly rather than silently.
    fn resolve_roothashes(cases: &str, policy: &str) -> String {
        let mut resolved = cases.to_string();
        let hashes: Vec<&str> = policy
            .match_indices("X-kata.dmverity.roothash=")
            .filter_map(|(i, m)| {
                let rest = &policy[i + m.len()..];
                let hash = rest.get(..64)?;
                hash.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    .then_some(hash)
            })
            .collect();
        for (index, hash) in hashes.iter().enumerate() {
            resolved = resolved.replace(&format!("$(roothash-{index})"), hash);
        }
        assert!(
            !resolved.contains("$(roothash-"),
            "unresolved root hash placeholder: the policy declared {} layer(s)",
            hashes.len()
        );
        resolved
    }

    fn decode_policy(initdata_anno: &str) -> String {
        let initdata = kata_types::initdata::decode_initdata(initdata_anno)
            .expect("should decode initdata anno");
        initdata
            .get_coco_data("policy.rego")
            .expect("should read policy from initdata")
            .to_string()
    }

    fn prepare_workdir(
        test_case_dir: &str,
        files_to_copy: &[&str],
    ) -> (path::PathBuf, path::PathBuf) {
        // Prepare temp dir for running genpolicy.
        let workdir = path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test_case_dir);
        fs::create_dir_all(&workdir)
            .expect("should be able to create directories under CARGO_TARGET_TMPDIR");

        let testdata_dir = path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/policy/testdata")
            .join(test_case_dir);

        // Make sure that workdir is empty.
        for entry in fs::read_dir(&workdir).expect("should be able to read directories") {
            let entry = entry.expect("should be able to read directory entries");
            fs::remove_file(entry.path()).expect("should be able to remove files");
        }

        for file in files_to_copy {
            fs::copy(testdata_dir.join(file), workdir.join(file))
                .context(format!(
                    "{:?} --> {:?}",
                    testdata_dir.join(file),
                    workdir.join(file)
                ))
                .expect("copying files around should not fail");
        }

        let genpolicy_dir = path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        for base in ["rules.rego", "genpolicy-settings.json"] {
            // A test case may ship its own settings to exercise a non-default
            // configuration (e.g. image_layer_verification); fall back to the shipped
            // defaults otherwise, so that most cases keep testing what users get.
            let source = if testdata_dir.join(base).exists() {
                testdata_dir.join(base)
            } else {
                genpolicy_dir.join(base)
            };

            fs::copy(&source, workdir.join(base))
                .context(format!("{:?} --> {:?}", &source, workdir.join(base)))
                .expect("copying files around should not fail");
        }

        (workdir, testdata_dir)
    }

    #[tokio::test]
    async fn test_copyfile() {
        runtests("copyfile").await;
    }

    #[tokio::test]
    async fn test_create_sandbox() {
        runtests("createsandbox").await;
    }

    #[tokio::test]
    async fn test_update_routes() {
        runtests("updateroutes").await;
    }

    #[tokio::test]
    async fn test_update_interface() {
        runtests("updateinterface").await;
    }

    #[tokio::test]
    async fn test_add_arp_neighbors() {
        runtests("addarpneighbors").await;
    }

    #[tokio::test]
    async fn test_create_container_network_namespace() {
        runtests("createcontainer/network_namespace").await;
    }

    #[tokio::test]
    async fn test_create_container_sysctls() {
        runtests("createcontainer/sysctls").await;
    }

    #[tokio::test]
    async fn test_create_container_generate_name() {
        runtests("createcontainer/generate_name").await;
    }

    #[tokio::test]
    async fn test_create_container_gid() {
        runtests("createcontainer/gid").await;
    }

    #[tokio::test]
    async fn test_create_container_cgroup_mount_extras() {
        runtests("createcontainer/cgroup_mount_extras").await;
    }

    #[tokio::test]
    async fn test_state_create_container() {
        runtests("state/createcontainer").await;
    }

    #[tokio::test]
    async fn test_state_exec_process() {
        runtests("state/execprocess").await;
    }

    #[tokio::test]
    async fn test_state_signal_process() {
        runtests("state/signalprocess").await;
    }

    #[tokio::test]
    async fn test_state_remove_container() {
        runtests("state/removecontainer").await;
    }

    #[tokio::test]
    async fn test_state_start_container() {
        runtests("state/startcontainer").await;
    }

    #[tokio::test]
    async fn test_state_stats_container() {
        runtests("state/statscontainer").await;
    }

    #[tokio::test]
    async fn test_state_tty_win_resize() {
        runtests("state/ttywinresize").await;
    }

    #[tokio::test]
    async fn test_state_wait_process() {
        runtests("state/waitprocess").await;
    }

    #[tokio::test]
    async fn test_state_exec_process_deployment() {
        runtests("state/execprocessdeployment").await;
    }

    #[tokio::test]
    async fn test_create_container_image_short_name() {
        runtests("createcontainer/image_short_name").await;
    }

    #[tokio::test]
    async fn test_create_container_security_context() {
        runtests("createcontainer/security_context/runas").await;
    }

    #[tokio::test]
    async fn test_create_container_security_context_supplemental_groups() {
        runtests("createcontainer/security_context/supplemental_groups").await;
    }

    #[tokio::test]
    async fn test_create_container_security_context_fsgroup() {
        runtests("createcontainer/security_context/fsgroup").await;
    }

    #[tokio::test]
    async fn test_create_container_erofs_layers() {
        // RM-38/RM-41: a container whose image layers are presented by the host as
        // dm-verity backed erofs lower layers (containerd's erofs snapshotter in
        // unmerged mode). Before RM-38 the generated policy said nothing about these
        // storages at all, so such a workload could not run under policy; before RM-41
        // the duplicate-identity check rejected every image with more than one layer,
        // because all of a container's layers are partitions of a single block device
        // and share driver, source and mount point.
        runtests("createcontainer/erofs_layers").await;
    }

    #[tokio::test]
    async fn test_create_container_volumes_empty_dir() {
        runtests("createcontainer/volumes/emptydir").await;
    }

    #[tokio::test]
    async fn test_create_container_volumes_empty_dir_memory() {
        // RM-35 (F-97): a memory-backed emptyDir is declared as an in-guest tmpfs --
        // driver "ephemeral", source "tmpfs" -- and is not one of the two declarations
        // that opt into host-chosen block backing. Before RM-35 the blk/scsi bodies of
        // storage_pair_matches ignored the declaration's driver and source entirely, so
        // a host-attached disk carrying arbitrary content satisfied this declaration.
        runtests("createcontainer/volumes/emptydir_memory").await;
    }

    #[tokio::test]
    async fn test_create_container_volumes_config_map() {
        runtests("createcontainer/volumes/config_map").await;
    }

    #[tokio::test]
    async fn test_create_container_volumes_container_image() {
        runtests("createcontainer/volumes/container_image").await;
    }

    #[tokio::test]
    async fn test_create_container_gpu_vfio_cdi() {
        runtests("createcontainer/gpu_vfio_cdi").await;
    }

    #[tokio::test]
    async fn test_create_container_ignored_fields() {
        runtests("createcontainer/ignored_fields").await;
    }

    #[tokio::test]
    async fn test_create_container_env_vars() {
        runtests("createcontainer/env_vars").await;
    }

    // FR-16: the policy exact-matches the OCI Process workingDir (Cwd), the
    // apparmor profile pinned by the pod spec, and the process rlimits, so a
    // compromised host cannot weaken these when starting a container.
    #[tokio::test]
    async fn test_create_container_fr16_oci_fields() {
        runtests("createcontainer/fr16").await;
    }
}
