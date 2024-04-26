// Description: Agent Api forwarder to running shim management server

use crate::utils;
use anyhow::{anyhow, Context, Result};
use reqwest::StatusCode;
use regex::{Regex, Captures};
use slog::info;
use serde::{Deserialize, Serialize};
use std::{fs::{self, OpenOptions}, io::Write, time::Duration};
use std::io;
use std::process::Command;
use shim_interface::shim_mgmt::{client::MgmtClient, TEST_AGENT_APIS};

pub const TIMEOUT: Duration = Duration::from_millis(2000);

// TO-DO: Hard coded values for now
const CONTAINER_NAME: &str = "test-container";
const CONTAINER_IMAGE_NAME: &str ="mcr.microsoft.com/mirror/docker/library/busybox:1.35";
const SANDBOX_NAME: &str = "busybox-test-sandbox";

type PrepApiReqFp = fn(&str, &mut TestApiRequest, String, String) -> Result<()>;

struct PrepApiReq {
    name: &'static str,
    api: &'static str,
    fp: PrepApiReqFp,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Default, Debug)]
struct TestApiRequest {
    api: String,
    sandbox_id: String,
    params: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct CreateSandbox {
    // File(yaml/json format) corresponding to request pod sandbox
    configfile: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct DestroySandbox {
    id: String,

}
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct CreateContainer {
    // Container id
    id: String,
    // Rootfs options as created via snapshotter.
    // TO-DO: This will be hardcoded for now since we rely on using the same container image for this test
    rootfsoptions: String,
    // File containing the OCI config template entries.
    // TO-DO: For now, only a few entries will be updated and rest will be used hardcoded.
    config: String,
    // Reference to used snapshotter
    snapshotter: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct StartContainer {
    // Container id
    id: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct RemoveContainer {
    // Container id
    id: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct CopyFile {
    src: String,
    dest: String,
}

static PREP_API_REQ: &[PrepApiReq] = &[
    PrepApiReq{
        name: "copyfile",
        api: "CopyFileRequest",
        fp: prep_copy_file_req,
    },
    PrepApiReq{
        name: "createsandbox",
        api: "CreateSandboxRequest",
        fp: prep_create_sandbox_req,
    },
    PrepApiReq{
        name: "destroysandbox",
        api: "DestroySandboxRequest",
        fp: prep_destroy_sandbox_req,
    },
    PrepApiReq{
        name: "createcontainer",
        api: "CreateContainerRequest",
        fp: prep_create_container_req,
    },
    PrepApiReq{
        name: "startcontainer",
        api: "StartContainerRequest",
        fp: prep_start_container_req,
    },
    PrepApiReq{
        name: "removecontainer",
        api: "RemoveContainerRequest",
        fp: prep_remove_container_req,
    },
];

fn get_api_prep_handle(name: &str) -> Result<PrepApiReqFp> {
    for cmd in PREP_API_REQ {
        if cmd.name.eq(name) {
            return Ok(cmd.fp);
        }
    }

    Err(anyhow!("Invalid api: {:?}", name))
}
fn get_requesting_api_name(name: &str) -> Result<String> {
    for cmd in PREP_API_REQ {
        if cmd.name.eq(name) {
            return Ok(cmd.api.to_string());
        }
    }

    Err(anyhow!("Invalid api: {:?}", name))
}

pub fn handle_test_api_cmd(
    cmdline: &str,
) -> (Result<()>, bool) {
    info!(sl!(), "Test-shim::handle_test_api_cmd enter");
    info!(sl!(), "cmdline: {:}", cmdline);
    // break the whitespace separated cmdline args
    // ex: TestAgentApi createsandbox file:///<>
    //     TestAgentApi copyfile sandbox_id file:///<>
    let fields: Vec<&str> = cmdline.split_whitespace().collect();

    // Sanity check again
    let cmd = fields[0];
    if cmd.is_empty() {
        // Ignore empty commands
        return (Ok(()), false);
    }

    let args = if fields.len() > 1 {
        fields[1..].join(" ")
    } else {
        String::new()
    };

    info!(sl!(), "Test agent api: {:}", fields[1]);

    // Forward this to a subcommand handler to forward calls.
    // Not using ingore errors flag, return the result as retrieved.
    forward_cmds(&args)
}

fn forward_cmds(
    cmd: &str,
) -> (Result<()>, bool) {
    info!(sl!(), "Test-shim: forward cmds");

    let cmd_fields: Vec<&str> = cmd.split_whitespace().collect();
    let api_short_name = cmd_fields[0].to_string();

    if cmd_fields.len() < 2 {
        info!(sl!(), "Expecting atleast 2 arguments. See sub-command usage");
        return (Err(anyhow!("Invalid arguments.")), false);
    }

    let sandbox_id = cmd_fields[1].to_string();

    if !api_short_name.contains("createsandbox") && sandbox_id.len() == 0 {
        info!(sl!(), "Invalid sandbox id");
        return (Err(anyhow!("Invalid sandbox id")), false);
    }

    let args = if cmd_fields.len() > 2 {
        cmd_fields[2..].join(" ")
    }else{
        String::new()
    };

    let mut req = TestApiRequest{..Default::default()};

    let f = match get_api_prep_handle(&api_short_name) {
        Ok(fp) => fp,
        Err(e) => return (Err(e), false),
    };

    let api_name = match get_requesting_api_name(&api_short_name) {
        Ok(api) => api,
        Err(e) => return (Err(e), false),
    };

    let result = f(&args, &mut req, api_name, sandbox_id);
    if result.is_err() {
        return (result, false);
    }

    if api_short_name.contains("createsandbox") || api_short_name.contains("destroysandbox") {
        return (Ok(()), false);
    }

    let res = get_response(req, cmd_fields[1].to_string());
    if res.is_err() {
        return (res, false);
    }

    (Ok(()), false)
}

fn get_response(
    req: TestApiRequest,
    sandbox: String,
) -> Result<()> {
    let _cmd_result = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?
    .block_on(post_request(req, sandbox))
    .context("get post response")?;

    Ok(())
}

// We need to post the req now.
async fn post_request(
    req: TestApiRequest,
    sandbox: String,
) -> Result<()> {
    info!(sl!(), "post_request..");

    let encoded = serde_json::to_string(&req)?;
    let shim_client = MgmtClient::new(&sandbox, Some(TIMEOUT))?;

    let url = TEST_AGENT_APIS;
    let response = shim_client
        .post(url, &String::from("application/json"), &encoded)
        .await?;
    let status = response.status();
    if status != StatusCode::OK {
        let body = format!("{:?}", response.into_body());
        return Err(anyhow!(
            "failed to send API test request::({:?}): {:?}",
            status,
            body
        ));
    }

    Ok(())
}

fn fix_config_entry(path: &str, container_id: &str, sandbox_id: &str) -> Result<()>{
    info!(sl!(), "fix_config entry for path: {}", path);

    // Open the path for reading:
    let mut f = OpenOptions::new().write(true).open(path)?;
    let contents = fs::read_to_string(path)?;

    let mut modified_contents = String::new();

    for lines in contents.lines() {
        let reg = Regex::new(r"(^.*)(\$[A-Za-z]+)(.*$)")?;
        if reg.is_match(lines) {
            // Matches
            let res = reg.replace(&lines, |caps: &Captures| {
                match &caps[2] {
                    "$sandboxid" => format!("{}{}{}",&caps[1],sandbox_id, &caps[3]),
                    "$containerid" => format!("{}{}{}", &caps[1], container_id, &caps[3]),
                    "$imagename" => format!("{}{}{}", &caps[1], CONTAINER_IMAGE_NAME, &caps[3]),
                    "$sandboxname" => format!("{}{}{}", &caps[1], SANDBOX_NAME, &caps[3]),
                    "$containername" => format!("{}{}{}", &caps[1], CONTAINER_NAME, &caps[3]),
                    _ => format!{"{}{}{}", &caps[1],"ERROR",&caps[3]},
                }
            }).into_owned();
            modified_contents.push_str(&res);
            modified_contents.push('\n');
        } else {
            modified_contents.push_str(lines);
            modified_contents.push('\n');
        }
    }

    //dump the modified contents
    f.write_all(modified_contents.as_bytes())?;

    Ok(())
}

fn prep_create_sandbox_req(args: &str, _req: &mut TestApiRequest, _api: String, _id: String) -> Result<()>{
    info!(sl!(), "Inside create sandbox request");

    let input: CreateSandbox = utils::make_request(&args)?;

    if fs::metadata(&input.configfile).is_err() {
        info!(sl!(), "Invalid config file: {}", input.configfile);
        return Err(anyhow!("Invalid sandbox config file"));
    }

    let output = Command::new("crictl").args(["runp","-T","30s","-r","kata-cc",&input.configfile]).output()?;

    info!(sl!(), "Command status: {}", output.status);

    //forward stderr
    io::stderr().write_all(&output.stderr)?;
    //forward stdout
    io::stdout().write_all(&output.stdout)?;

    Ok(())

}

fn prep_destroy_sandbox_req(_args: &str, _req: &mut TestApiRequest, _api: String, id: String) -> Result<()>{
    info!(sl!(), "Inside destroy sandbox request for id:{}", id);

    let stop_output = Command::new("crictl").args(["stopp", &id]).output()?;
    info!(sl!(), "Command status: {}", stop_output.status);
    //forward stderr
    io::stderr().write_all(&stop_output.stderr)?;
    //forward stdout
    io::stdout().write_all(&stop_output.stdout)?;

    let rm_output = Command::new("crictl").args(["rmp",&id]).output()?;
    info!(sl!(), "Command status: {}", rm_output.status);
    //forward stderr
    io::stderr().write_all(&rm_output.stderr)?;
    //forward stdout
    io::stdout().write_all(&rm_output.stdout)?;

    Ok(())
}

fn prep_create_container_req(args: &str, req: &mut TestApiRequest, api: String, id: String) -> Result<()>{
    info!(sl!(), "Inside create container request");

    // Create a random container id.
    let container_id = utils::generate_random_hex_string(64);
    info!(sl!(), "CreateContainer called for id: {}", container_id);

    // TO-DO: For testing createContainer api, use a known busybox image for now.
    // This image will be pulled and unpacked using the specific snapshotter prior to testing this command. NO checks in place for now.
    // The rootFS options used are hardcoded since the image used is static with known pre-calculated hashes.
    // Image <name:version> : "mcr.microsoft.com/mirror/docker/library/busybox:1.35"
    let rootfs_options = "io.katacontainers.fs-opt.layer-src-prefix=/var/lib/containerd/io.containerd.snapshotter.v1.tardev/layers io.katacontainers.fs-opt.layer=ZmRmZmUwM2JhZjAwNWRhZjI2ODQ5MzBlYWQ0NGIwZWZiYWEyMjQ2YzhmM2Y5NjM0NmE3MmQ1MjdjZThiMzY1MCx0YXIscm8saW8ua2F0YWNvbnRhaW5lcnMuZnMtb3B0LmJsb2NrX2RldmljZT1maWxlLGlvLmthdGFjb250YWluZXJzLmZzLW9wdC5pcy1sYXllcixpby5rYXRhY29udGFpbmVycy5mcy1vcHQucm9vdC1oYXNoPTI4MWQ2N2NiYzc0ZGNjY2VjZDg1MTVkNTU2MGY3ZmViNWNkNmIwMTU5NDY4ODhhYTk4MmMxZDBlMzYyMDRmMWM= io.katacontainers.fs-opt.overlay-rw lowerdir=fdffe03baf005daf2684930ead44b0efbaa2246c8f3f96346a72d527ce8b3650".to_string();

    #[derive(Serialize, Deserialize, Clone, Default, Debug)]
    struct LocalConfig {
        path: String,
    }

    let config: LocalConfig = utils::make_request(&args)?;
    info!(sl!(), "Config path: {}", config.path);

    // Fix the config with correct values
    let _ = fix_config_entry(&config.path, &container_id, &id)?;

    let mut perms = fs::metadata(&config.path)?.permissions();
    perms.set_readonly(true);
    let _ = fs::set_permissions(&config.path, perms)?;

    let create_container_req = CreateContainer{
        id: container_id,
        rootfsoptions: rootfs_options,
        config: config.path,
        snapshotter: "tardev-snapshotter".to_string(),
    };

    req.api = api;
    req.sandbox_id = id;
    req.params = serde_json::to_value(create_container_req)?;

    Ok(())
}

fn prep_start_container_req(args: &str, req: &mut TestApiRequest, api: String, id: String) -> Result<()>{
    info!(sl!(), "Inside start container req");

    let screq: StartContainer = utils::make_request(&args)?;
    req.api = api;
    req.sandbox_id = id;
    req.params = serde_json::to_value(screq)?;
    Ok(())
}

fn prep_remove_container_req(args: &str, req: &mut TestApiRequest, api: String, id: String) -> Result<()>{
    info!(sl!(), "Inside start container req");

    let rmreq: RemoveContainer = utils::make_request(&args)?;
    req.api = api;
    req.sandbox_id = id;
    req.params = serde_json::to_value(rmreq)?;
    Ok(())
}

fn prep_copy_file_req(args: &str, req: &mut TestApiRequest, api: String, id: String) -> Result<()> {
    let cpreq: CopyFile = utils::make_request(&args)?;
    req.api = api;
    req.sandbox_id = id;
    req.params = serde_json::to_value(cpreq)?;
    Ok(())
}
