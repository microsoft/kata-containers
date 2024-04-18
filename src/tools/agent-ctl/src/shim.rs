// Description: Agent Api forwarder to running shim management server

use crate::types::{Config, Options};
use crate::utils;
use crate::client;

use anyhow::{anyhow, Context, Result};
use futures::executor;
use reqwest::StatusCode;
use slog::{debug, info};
use serde::{Deserialize, Serialize};
use std::time::Duration;


use shim_interface::shim_mgmt::client::MgmtClient;
use shim_interface::shim_mgmt::TEST_AGENT_APIS;

pub const TIMEOUT: Duration = Duration::from_millis(2000);

type PrepApiReqFp = fn(&str, &mut TestApiRequest, String, String) -> Result<()>;

struct PrepApiReq {
    name: &'static str,
    fp: PrepApiReqFp,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Default, Debug)]
struct TestApiRequest {
    api: String,
    sandbox_id: String,
    params: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct CopyFile {
    src: String,
    dest: String,
}

static PREP_API_REQ: &[PrepApiReq] = &[
    PrepApiReq{
        name: "copyfile",
        fp: prep_copy_file_req,
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
    // the cmd string slice format is space separated: 'agent-api data'
    // ex: copyfile sandbox-id json://{}
    // split the cmd and input
    let cmd_fields: Vec<&str> = cmd.split_whitespace().collect();
    let agent_api = cmd_fields[0].to_string();
    let sandbox_id = cmd_fields[1].to_string();

    if agent_api.eq("createsandbox") || agent_api.eq("destroysandbox") {
        // Special handling using crictl
        info!(sl!(), "To be implemented");
        return (Ok(()), false);
    }

    let args = if cmd_fields.len() > 2 {
        cmd_fields[2..].join(" ")
    }else{
        String::new()
    };

    let mut req = TestApiRequest{..Default::default()};

    let f = match get_api_prep_handle(&agent_api) {
        Ok(fp) => fp,
        Err(e) => return (Err(e), false),
    };
    let result = f(&args, &mut req, agent_api, sandbox_id);
    if result.is_err() {
        return (result, false);
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
    let cmd_result = tokio::runtime::Builder::new_current_thread()
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

fn prep_copy_file_req(args: &str, req: &mut TestApiRequest, api: String, id: String) -> Result<()> {
    let cpreq: CopyFile = utils::make_request(&args)?;
    req.api = api;
    req.sandbox_id = id;
    req.params = serde_json::to_value(cpreq)?;
    Ok(())
}
