// Copyright (c) 2024 Edgeless Systems GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(test)]
mod tests {
    use base64::prelude::*;
    use std::any;
    use std::fs::{self, File};
    use std::path;
    use std::str;

    use protocols::agent::{
        CreateContainerRequest, CreateSandboxRequest, ExecProcessRequest, UpdateInterfaceRequest,
        UpdateRoutesRequest,
    };
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};

    use kata_agent_policy::policy::{
        AgentPolicy, PolicyCopyFileRequest, PolicyCreateContainerRequest,
    };

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct TestCase<T> {
        description: String,
        allowed: bool,
        request: T,
    }

    /// Run tests from the given directory.
    /// The directory is searched under `src/tools/genpolicy/tests/testdata`, and
    /// it must contain a `resources.yaml` file as well as a `testcases.json` file.
    /// The resources must produce a policy when fed into genpolicy, so there
    /// should be exactly one entry with a PodSpec. The test case file must contain
    /// a JSON list of [TestCase] instances appropriate for `T`.
    async fn runtests<T>(test_case_dir: &str)
    where
        T: DeserializeOwned + Serialize,
    {
        // Prepare temp dir for running genpolicy.
        let workdir = path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test_case_dir);
        fs::create_dir_all(&workdir)
            .expect("should be able to create directories under CARGO_TARGET_TMPDIR");

        let testdata_dir = path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/testdata")
            .join(test_case_dir);
        fs::copy(testdata_dir.join("pod.yaml"), workdir.join("pod.yaml"))
            .expect("copying files around should not fail");

        let genpolicy_dir =
            path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/genpolicy");

        for base in ["rules.rego", "genpolicy-settings.json"] {
            fs::copy(genpolicy_dir.join(base), workdir.join(base))
                .expect("copying files around should not fail");
        }

        // Run the command and return the generated policy.

        let config = genpolicy::utils::Config {
            base64_out: false,
            config_files: None,
            containerd_socket_path: None, // Some(String::from("/var/run/containerd/containerd.sock")),
            // insecure_registries: Vec::new(),
            // layers_cache_file_path: None,
            raw_out: false,
            rego_rules_path: workdir.join("rules.rego").to_str().unwrap().to_string(),
            // runtime_class_names: Vec::new(),
            json_settings_path: workdir
                .join("genpolicy-settings.json")
                .to_str()
                .unwrap()
                .to_string(),
            silent_unsupported_fields: false,
            use_cache: false,
            version: false,
            yaml_file: workdir.join("pod.yaml").to_str().map(|s| s.to_string()),
        };

        let policy = genpolicy::policy::AgentPolicy::from_files(&config)
            .await
            .unwrap();
        assert_eq!(policy.resources.len(), 1);
        let policy = policy.resources[0].generate_policy(&policy);
        let policy = BASE64_STANDARD.decode(&policy).unwrap();

        // write policy to a file
        fs::write(workdir.join("policy.rego"), &policy).unwrap();

        // Write policy back to a file

        // Re-implement needed parts of AgentPolicy::initialize()
        let mut pol = AgentPolicy::new();
        pol.initialize(
            slog::Level::Debug.as_usize(),
            workdir.join("policy.rego").to_str().unwrap(),
            workdir.join("policy.log").to_str().map(|s| s.to_string()),
        )
        .await
        .unwrap();

        // Run through the test cases and evaluate the canned requests.

        let case_file =
            File::open(testdata_dir.join("testcases.json")).expect("test case file should open");
        let test_cases: Vec<TestCase<T>> =
            serde_json::from_reader(case_file).expect("test case file should parse");

        for test_case in test_cases {
            println!("\n== case: {} ==\n", test_case.description);

            let v = serde_json::to_value(&test_case.request).unwrap();

            let request_type = map_request(any::type_name::<T>().split("::").last().unwrap());

            let results = pol
                .allow_request(request_type, &serde_json::to_string(&v).unwrap())
                .await;

            let logs = fs::read_to_string(workdir.join("policy.log")).unwrap();
            let results = results.unwrap();

            assert_eq!(
                test_case.allowed, results.0,
                "logs: {}\npolicy: {}",
                logs, results.1
            );
        }
    }

    fn map_request(request: &str) -> &str {
        match request {
            "PolicyCopyFileRequest" => "CopyFileRequest",
            "PolicyCreateContainerRequest" => "CreateContainerRequest",
            _ => request,
        }
    }

    #[tokio::test]
    async fn test_copyfile() {
        runtests::<PolicyCopyFileRequest>("copyfile").await;
    }

    #[tokio::test]
    async fn test_create_sandbox() {
        runtests::<CreateSandboxRequest>("createsandbox").await;
    }

    #[tokio::test]
    async fn test_update_routes() {
        runtests::<UpdateRoutesRequest>("updateroutes").await;
    }

    #[tokio::test]
    async fn test_update_interface() {
        runtests::<UpdateInterfaceRequest>("updateinterface").await;
    }
    #[tokio::test]
    async fn test_legacy_basic_create_container() {
        runtests::<CreateContainerRequest>("createContainer/legacy").await;
    }

    #[tokio::test]
    async fn test_basic_create_container() {
        runtests::<PolicyCreateContainerRequest>("createContainer/basic").await;
    }

    #[tokio::test]
    async fn test_create_container_generate_name() {
        runtests::<PolicyCreateContainerRequest>("createcontainer/generate_name").await;
    }

    #[tokio::test]
    async fn test_create_exec() {
        runCreateExectest("createContainer/basicPlusExec").await;
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(untagged)]
    enum CreateOrExec {
        PolicyCreateContainerRequest(PolicyCreateContainerRequest),
        ExecProcessRequest(ExecProcessRequest),
    }

    #[derive(Debug, Deserialize)]
    struct CreateOrExecTestCase {
        description: String,
        allowed: bool,
        request: CreateOrExec,
    }

    async fn runCreateExectest(test_case_dir: &str) {
        // Prepare temp dir for running genpolicy.
        let workdir = path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test_case_dir);
        fs::create_dir_all(&workdir)
            .expect("should be able to create directories under CARGO_TARGET_TMPDIR");

        let testdata_dir = path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/testdata")
            .join(test_case_dir);
        fs::copy(testdata_dir.join("pod.yaml"), workdir.join("pod.yaml"))
            .expect("copying files around should not fail");

        let genpolicy_dir =
            path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/genpolicy");

        for base in ["rules.rego", "genpolicy-settings.json"] {
            fs::copy(genpolicy_dir.join(base), workdir.join(base))
                .expect("copying files around should not fail");
        }

        // Run the command and return the generated policy.

        let config = genpolicy::utils::Config {
            base64_out: false,
            config_files: None,
            containerd_socket_path: None, // Some(String::from("/var/run/containerd/containerd.sock")),
            // insecure_registries: Vec::new(),
            // layers_cache_file_path: None,
            raw_out: false,
            rego_rules_path: workdir.join("rules.rego").to_str().unwrap().to_string(),
            // runtime_class_names: Vec::new(),
            json_settings_path: workdir
                .join("genpolicy-settings.json")
                .to_str()
                .unwrap()
                .to_string(),
            silent_unsupported_fields: false,
            use_cache: false,
            version: false,
            yaml_file: workdir.join("pod.yaml").to_str().map(|s| s.to_string()),
        };

        let policy = genpolicy::policy::AgentPolicy::from_files(&config)
            .await
            .unwrap();
        assert_eq!(policy.resources.len(), 1);
        let policy = policy.resources[0].generate_policy(&policy);
        let policy = BASE64_STANDARD.decode(&policy).unwrap();

        // write policy to a file
        fs::write(workdir.join("policy.rego"), &policy).unwrap();

        // Write policy back to a file

        // Re-implement needed parts of AgentPolicy::initialize()
        let mut pol = AgentPolicy::new();
        pol.initialize(
            slog::Level::Debug.as_usize(),
            workdir.join("policy.rego").to_str().unwrap(),
            workdir.join("policy.log").to_str().map(|s| s.to_string()),
        )
        .await
        .unwrap();

        // Run through the test cases and evaluate the canned requests.

        let case_file =
            File::open(testdata_dir.join("testcases.json")).expect("test case file should open");
        let test_cases: Vec<CreateOrExecTestCase> =
            serde_json::from_reader(case_file).expect("test case file should parse");

        for test_case in test_cases {
            println!("\n== case: {} ==\n", test_case.description);

            let v = serde_json::to_value(&test_case.request).unwrap();

            // let request_type = map_request(any::type_name::<T>().split("::").last().unwrap());
            let request_type = match test_case.request {
                CreateOrExec::PolicyCreateContainerRequest(_) => "CreateContainerRequest",
                CreateOrExec::ExecProcessRequest(_) => "ExecProcessRequest",
            };

            let results = pol
                .allow_request(request_type, &serde_json::to_string(&v).unwrap())
                .await;

            let logs = fs::read_to_string(workdir.join("policy.log")).unwrap();
            let results = results.unwrap();

            assert_eq!(
                test_case.allowed, results.0,
                "logs: {}\npolicy: {}",
                logs, results.1
            );
        }
    }
}
