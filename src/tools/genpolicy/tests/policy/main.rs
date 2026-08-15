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
    use std::sync;

    use protocols::agent::{
        AddARPNeighborsRequest, CommitVolumeRevisionRequest, CreateContainerRequest,
        CreateSandboxRequest, ExecProcessRequest, InitVolumeRequest, RemoveContainerRequest,
        SignalProcessRequest, StartContainerRequest, StatsContainerRequest, TtyWinResizeRequest,
        UpdateInterfaceRequest, UpdateRoutesRequest, WaitProcessRequest,
    };
    use serde::{Deserialize, Serialize};

    use kata_agent_policy::policy::{
        AgentPolicy, PolicyCopyFileRequest, PolicyCopySingleFileRequest,
        PolicyPutVolumeFileRevisionRequest,
    };

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
        CopySingleFileRequest(PolicyCopySingleFileRequest),
        InitVolumeRequest(InitVolumeRequest),
        PutVolumeFileRevisionRequest(PolicyPutVolumeFileRevisionRequest),
        CommitVolumeRevisionRequest(CommitVolumeRevisionRequest),
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
                TestRequest::CopySingleFileRequest(_) => write!(f, "CopySingleFileRequest"),
                TestRequest::InitVolumeRequest(_) => {
                    write!(f, "InitVolumeRequest")
                }
                TestRequest::PutVolumeFileRevisionRequest(_) => {
                    write!(f, "PutVolumeFileRevisionRequest")
                }
                TestRequest::CommitVolumeRevisionRequest(_) => {
                    write!(f, "CommitVolumeRevisionRequest")
                }
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
    async fn prepare_policy(
        test_case_dir: &str,
    ) -> (AgentPolicy, String, path::PathBuf, path::PathBuf) {
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

        // FR-1l: every generated policy states the enforcement framework it was written
        // against. Asserted here rather than in one dedicated case so that it holds for
        // every resource shape the suite covers, and so that dropping the stamp fails
        // loudly -- an unstamped policy is treated as legacy and silently skips the
        // agent's floor, which is precisely the failure this check exists to prevent.
        assert!(
            policy.contains(&format!(
                "framework_version := \"{}\"",
                genpolicy::policy::POLICY_FRAMEWORK_VERSION
            )),
            "generated policy does not declare its framework_version"
        );

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

        (pol, policy, testdata_dir, workdir)
    }

    /// Run tests from the given directory. See [`prepare_policy`] for the setup.
    async fn runtests(test_case_dir: &str) {
        let (mut pol, policy, testdata_dir, workdir) = prepare_policy(test_case_dir).await;

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
        // Prepare temp dir for running genpolicy. The directory is keyed on a per-process
        // counter rather than on `test_case_dir` alone, because several tests legitimately
        // share a fixture directory -- `test_state_exec_process_deployment` and
        // `a_denial_names_the_check_that_failed_and_no_others` both drive
        // `state/execprocessdeployment` -- and `cargo test` runs them concurrently. Sharing
        // the working directory made them race on the "make sure workdir is empty" sweep
        // below, where one test removed a file the other had just copied in and the loser
        // panicked with ENOENT. That surfaced as an intermittent failure naming a different
        // test on each run, which is a slow thing to diagnose from CI.
        static WORKDIR_SEQ: sync::atomic::AtomicUsize = sync::atomic::AtomicUsize::new(0);
        let unique = WORKDIR_SEQ.fetch_add(1, sync::atomic::Ordering::Relaxed);

        let workdir = path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{test_case_dir}-{unique}"));
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

    /// RM-114: the endpoints that replaced CopyFileRequest are mediated field by field,
    /// not merely reachable. The deny cases cover the symlink primitive that the deleted
    /// allow_copy_file rule used to guard.
    #[tokio::test]
    async fn test_content_channel() {
        runtests("contentchannel").await;
    }

    /// The legacy free-form CopyFileRequest is hard-denied (`default := false`, no rule
    /// body) now that the host->guest content channel goes through the four typed
    /// endpoints exercised by `test_content_channel`. Every case here asserts the door
    /// stayed shut, including the ones that used to be the endpoint's legitimate use.
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

    /// FR-14: the route destination/gateway allowlist actually constrains when a settings
    /// file narrows it (the shipped default is permissive).
    #[tokio::test]
    async fn test_update_routes_allowlist() {
        runtests("updateroutes_allowlist").await;
    }

    /// FR-14: interface addresses are constrained too — an address implies a connected
    /// route, so an unconstrained address would bypass the route allowlist.
    #[tokio::test]
    async fn test_update_interface_allowlist() {
        runtests("updateinterface_allowlist").await;
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

    /// This fixture ships its own settings enabling `allow_guest_pull_images` (which now
    /// defaults to `false`) and clearing `require_pinned_image_digests`. Its guest-pull
    /// image is the tag `quay.io/prometheus/busybox:latest`, and the fixture is shared by
    /// several tests that are about denial diagnostics and field mediation rather than
    /// image pinning; pinning it would churn those cases for no gain.
    #[tokio::test]
    async fn test_state_exec_process_deployment() {
        runtests("state/execprocessdeployment").await;
    }

    /// This fixture ships its own settings enabling `allow_guest_pull_images` (which now
    /// defaults to `false`) and clearing `require_pinned_image_digests`. Short-name
    /// normalization is what is under test here
    /// (`busybox:latest` -> `docker.io/library/busybox:latest`), and a short name is by
    /// definition unpinned, so the case cannot be expressed under the pinning default.
    #[tokio::test]
    async fn test_create_container_image_short_name() {
        runtests("createcontainer/image_short_name").await;
    }

    /// RM-119: guest pull is refused for workload containers by default. The same request
    /// as the allowed case in `createcontainer/gid` — a digest-pinned image that satisfies
    /// `require_pinned_image_digests` — is denied here purely because this fixture ships no
    /// settings of its own, so `allow_guest_pull_images` keeps its shipped `false`.
    ///
    /// The pair is the differential that shows pinning alone is not the control: `gid`
    /// enables guest pull and allows the request, this one does not and denies it. What
    /// pinning cannot fix is that the storage carries no declaration at all, so it is
    /// exempt from the `allow_storages` cardinality check and would otherwise be admitted
    /// *alongside* a container's declared dm-verity layers as a second root filesystem.
    #[tokio::test]
    async fn test_create_container_guest_pull_disabled() {
        runtests("createcontainer/guest_pull_disabled").await;
    }

    /// RM-51: the same request as `image_short_name`, but generated with
    /// `require_pinned_image_digests` on. The tag-named guest-pull image must now be
    /// denied — this is the check that replaced the removed `VerifiedImageStore`
    /// unpinned-reference refusal in the guest. The fixture keeps an explicit `true` in
    /// its own settings even though that is now the default, so the case still states
    /// what it depends on rather than inheriting it.
    ///
    /// RM-119: it also has to set `allow_guest_pull_images` explicitly, because guest pull
    /// is now refused for workload containers by default — with the path disabled there
    /// is no pinning decision left to make, and the case would pass for the wrong reason.
    ///
    /// The positive half of RM-51 is covered by the fixtures that already name
    /// digest-pinned images and now run under the pinning default: `cgroup_mount_extras`,
    /// `env_vars`, `gid` and `security_context/fsgroup`. Each of those ships settings
    /// enabling guest pull for the same reason.
    #[tokio::test]
    async fn test_create_container_require_pinned_images() {
        runtests("createcontainer/require_pinned_images").await;
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
    async fn test_create_container_volumes_empty_dir_shared_fs() {
        // RM-115 (F-212): a shared-fs emptyDir is the one shape where the Policy
        // deliberately holds two entries for a single destination -- the sandbox-scoped
        // volume directory and the per-container shared-fs path, as alternative sources
        // for the same path. The presented-vs-Policy mount check is an injection, so
        // before the distinct-destinations rule a host could satisfy both entries at
        // once and stack two mounts on one path, leaving the container looking at
        // whichever landed last. Either source alone is still legitimate.
        runtests("createcontainer/volumes/emptydir_shared_fs").await;
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

    /// FR-1l: the version genpolicy stamps must be the version the agent enforces.
    ///
    /// The two constants live in different crates on purpose — the agent's is the enforcer,
    /// genpolicy's is the copy it stamps into every policy, and genpolicy keeps the policy
    /// crate as a dev-dependency so the generator need not link the policy engine to read
    /// one string. The cost of that separation is that a drift is silent: nothing in either
    /// crate's own build can see both. Assert it here, the one place both are in scope.
    #[test]
    fn framework_version_matches_the_agent() {
        assert_eq!(
            genpolicy::policy::POLICY_FRAMEWORK_VERSION,
            kata_agent_policy::policy::POLICY_FRAMEWORK_VERSION,
            "genpolicy stamps a framework_version the agent does not implement; if the agent's \
             framework version was bumped deliberately, bump genpolicy's constant to match"
        );
    }

    /// RM-97: a denial must name the check that actually failed, and must not name checks
    /// that did not.
    ///
    /// This is a regression test for three diagnostics that were wrong at once. Debugging
    /// two unrelated failures (RM-95, RM-96) produced the same three reasons both times --
    /// undeclared `HOSTNAME`/`KUBERNETES_*`, a sandbox-namespace mismatch, and a storage
    /// count mismatch -- and all three were false every time, while the real cause, an
    /// `allow_user` mismatch, was never reported at all. The wrong reasons sent that
    /// investigation down the wrong path for a full pass, so each one is pinned here.
    ///
    /// The vehicle is a Deployment, deliberately: its pod name is generated, so `HOSTNAME`
    /// can only be admitted through the `$(host-name)` substitution and the
    /// `KUBERNETES_*` service variables only through `allow_env_regex`. Those are exactly
    /// the paths the old exact-match diagnostic could not see.
    #[tokio::test]
    async fn a_denial_names_the_check_that_failed_and_no_others() {
        let (mut pol, _policy, testdata_dir, _workdir) =
            prepare_policy("state/execprocessdeployment").await;

        let raw_cases =
            fs::read_to_string(testdata_dir.join("testcases.json")).expect("test cases readable");
        let cases: Vec<TestCase> = serde_json::from_str(&raw_cases).expect("test cases parse");

        // Start from a request the policy accepts, so the only thing under test is the
        // single field we break below.
        let case = cases
            .iter()
            .find(|c| c.allowed && matches!(c.request, TestRequest::CreateContainerRequest(_)))
            .expect("fixture must contain an allowed CreateContainerRequest");

        let mut req = serialize_request_only(&case.request).unwrap();
        let user = req
            .pointer_mut("/OCI/Process/User")
            .expect("request has a process user");

        // Add a supplementary group that no container in the policy declares. A value that
        // merely differs is not enough: the sandbox pause container runs as uid 0 with
        // gids [0], so dropping a group would still "agree" with *some* container and the
        // per-check diagnostic would correctly stay silent. The mismatch has to hold
        // against every candidate for the check to be the one that failed.
        user["AdditionalGids"] = serde_json::json!([0, 10, 4242]);

        let (allowed, message) = pol
            .allow_request(
                &case.request.to_string(),
                &serde_json::to_string(&req).unwrap(),
            )
            .await
            .expect("evaluation itself must succeed");

        assert!(!allowed, "a mismatched AdditionalGids must be refused");

        // The reason that must be present: it is the one that actually failed.
        assert!(
            message.contains("process user:"),
            "denial must name the process-user mismatch, got: {message}"
        );
        assert!(
            message.contains("additionalGids=[0, 10, 4242]"),
            "denial must show the presented supplementary groups, got: {message}"
        );

        // The reasons that must be absent, one per defect fixed.
        assert!(
            !message.contains("sandbox namespace"),
            "the engine never compares the policy's namespace annotation against the \
             request's, so a namespace mismatch must never be reported: {message}"
        );
        assert!(
            !message.contains("storage count"),
            "genpolicy never declares an image_guest_pull storage, so a request presenting \
             one must not be reported as a storage-count mismatch: {message}"
        );
        assert!(
            !message.contains("HOSTNAME"),
            "HOSTNAME is admitted via the $(host-name) substitution and must not be \
             reported as undeclared: {message}"
        );
        assert!(
            !message.contains("KUBERNETES_"),
            "the KUBERNETES_* service variables are admitted by allow_env_regex and must \
             not be reported as undeclared: {message}"
        );
    }

    /// The other half of the test above: an unmodified request from the same fixture is
    /// allowed. Without this, every assertion above would still hold if the policy denied
    /// everything for some unrelated reason.
    #[tokio::test]
    async fn the_unmodified_request_is_still_allowed() {
        let (mut pol, _policy, testdata_dir, _workdir) =
            prepare_policy("state/execprocessdeployment").await;

        let raw_cases =
            fs::read_to_string(testdata_dir.join("testcases.json")).expect("test cases readable");
        let cases: Vec<TestCase> = serde_json::from_str(&raw_cases).expect("test cases parse");
        let case = cases
            .iter()
            .find(|c| c.allowed && matches!(c.request, TestRequest::CreateContainerRequest(_)))
            .expect("fixture must contain an allowed CreateContainerRequest");

        let req = serialize_request_only(&case.request).unwrap();
        let (allowed, message) = pol
            .allow_request(
                &case.request.to_string(),
                &serde_json::to_string(&req).unwrap(),
            )
            .await
            .expect("evaluation itself must succeed");

        assert!(
            allowed,
            "unmodified request must be allowed, got: {message}"
        );
    }

    /// FR-1l: a policy carrying the stamp genpolicy emits is accepted, and one naming a
    /// newer framework is refused.
    ///
    /// The refusal case is what makes the acceptance meaningful: without it this test would
    /// still pass if `check_framework_version` were deleted outright. Together they prove
    /// the floor is armed — before genpolicy emitted the line at all, the gate existed but
    /// returned `Ok` for every policy we generate, because it read a rule nothing wrote.
    #[tokio::test]
    async fn a_stamped_policy_is_accepted_and_a_newer_one_is_refused() {
        let stamped =
            |version: &str| format!("package agent_policy\n\nframework_version := \"{version}\"\n");

        let mut pol = AgentPolicy::new();
        pol.set_policy(&stamped(genpolicy::policy::POLICY_FRAMEWORK_VERSION))
            .await
            .expect("the agent must accept a policy stamped with the version genpolicy emits");

        // One major ahead of whatever the current version is, so this stays a real test
        // after a version bump rather than silently becoming an "older policy" case.
        let ours = genpolicy::policy::POLICY_FRAMEWORK_VERSION;
        let major: u64 = ours.split('.').next().unwrap().parse().unwrap();
        let ahead = format!("{}.0.0", major + 1);

        let mut pol = AgentPolicy::new();
        let err = pol.set_policy(&stamped(&ahead)).await.expect_err(
            "the agent must refuse a policy naming a newer framework than it implements",
        );
        let err = err.to_string();
        assert!(
            err.contains("framework_version"),
            "refusal must name the framework version as the reason, got: {}",
            err
        );
    }

    /// RM-102: refusing a host-supplied security control must say so.
    ///
    /// `allow_create_container_input` refuses `Linux.Seccomp`, `Process.SelinuxLabel` and
    /// `Linux.MountLabel` outright, but it is a flat conjunction with a single print at
    /// each end -- so a request carrying any of them was denied with a trace that named
    /// only the rule, and the operator had to diff the whole OCI spec to find out which
    /// field was at fault. These are the three that a pod spec can actually populate.
    #[tokio::test]
    async fn a_refused_security_control_names_itself_in_the_denial() {
        for (pointer, value, expected) in [
            (
                "/OCI/Linux/Seccomp",
                serde_json::json!({"DefaultAction": "SCMP_ACT_ERRNO"}),
                "Linux.Seccomp",
            ),
            (
                "/OCI/Process/SelinuxLabel",
                serde_json::json!("system_u:system_r:container_t:s0"),
                "Process.SelinuxLabel",
            ),
            (
                "/OCI/Linux/MountLabel",
                serde_json::json!("system_u:object_r:container_file_t:s0"),
                "Linux.MountLabel",
            ),
        ] {
            let (mut pol, _policy, testdata_dir, _workdir) =
                prepare_policy("state/execprocessdeployment").await;

            let raw_cases = fs::read_to_string(testdata_dir.join("testcases.json"))
                .expect("test cases readable");
            let cases: Vec<TestCase> = serde_json::from_str(&raw_cases).expect("test cases parse");

            // Start from a request the policy accepts, so the refused field is the only
            // thing under test.
            let case = cases
                .iter()
                .find(|c| c.allowed && matches!(c.request, TestRequest::CreateContainerRequest(_)))
                .expect("fixture must contain an allowed CreateContainerRequest");

            let mut req = serialize_request_only(&case.request).unwrap();
            *req.pointer_mut(pointer)
                .unwrap_or_else(|| panic!("request has {pointer}")) = value;

            let (allowed, message) = pol
                .allow_request(
                    &case.request.to_string(),
                    &serde_json::to_string(&req).unwrap(),
                )
                .await
                .expect("evaluation itself must succeed");

            assert!(!allowed, "a request carrying {expected} must be refused");
            assert!(
                message.contains(expected),
                "denial must name the refused field {expected}, got: {message}"
            );
        }
    }
}
