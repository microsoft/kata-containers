// Description: Agent Api forwarder to running shim management server

use crate::types::{Config, Options};
use crate::utils;

use anyhow::{anyhow, Result};
use futures::executor;
use reqwest::StatusCode;
use slog::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use ttrpc::TtrpcContext;

use ttrpc::context::Context;

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
    cfg: &Config,
    ctx: &Context,
    options: &mut Options,
    cmdline: &str,
) -> (Result<()>, bool) {
    info!(sl!(), "Test-shim::handle_test_api_cmd enter");

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
    forward_cmds(ctx, &args)
}

fn forward_cmds(
    ctx: &Context,
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

    let cmd_result = executor::block_on(post_request(ctx, req, cmd_fields[1].to_string()));
    if cmd_result.is_err() {
        return (Err(anyhow!("Failed to post request")), false);
    }

    (Ok(()), false)
}

// We need to post the req now.
async fn post_request(
    ctx: &Context,
    req: TestApiRequest,
    sandbox: String,
) -> Result<Option<String>> {
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

    Ok(None)
}

fn prep_copy_file_req(args: &str, req: &mut TestApiRequest, api: String, id: String) -> Result<()> {
    let cpreq: CopyFile = utils::make_request(&args)?;
    req.api = api;
    req.sandbox_id = id;
    req.params = serde_json::to_value(cpreq)?;
    Ok(())
}
