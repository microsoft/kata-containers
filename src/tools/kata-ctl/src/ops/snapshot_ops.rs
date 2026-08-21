// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use http_body_util::BodyExt;
use hyper::StatusCode;
use shim_interface::shim_mgmt::{client::MgmtClient, SNAPSHOT_URL};

use crate::args::{SnapshotArgs, SnapshotCreateArgs, SnapshotSubCommand};

const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_SNAPSHOT_PATH_BYTES: usize = 4096;

pub fn handle_snapshot(args: SnapshotArgs) -> Result<()> {
    match args.command {
        SnapshotSubCommand::Create(args) => create_snapshot(args),
    }
}

fn create_snapshot(args: SnapshotCreateArgs) -> Result<()> {
    let destination = validate_destination(&args.path)?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create snapshot client runtime")?;
    runtime.block_on(async move {
        let client = MgmtClient::new(&args.sandbox_id, Some(SNAPSHOT_TIMEOUT))?;
        let response = client
            .put(SNAPSHOT_URL, destination.as_bytes().to_vec())
            .await
            .context("request portable snapshot")?;
        let status = response.status();
        let response_body = response
            .into_body()
            .collect()
            .await
            .context("read snapshot response")?
            .to_bytes();
        let response_body = parse_snapshot_response(status, &response_body)?;

        println!("{response_body}");
        Ok(())
    })
}

fn validate_destination(destination: &Path) -> Result<String> {
    if !destination.is_absolute() || destination == Path::new("/") {
        return Err(anyhow!(
            "snapshot destination must be absolute and non-root"
        ));
    }
    if destination.exists() {
        return Err(anyhow!(
            "snapshot destination already exists: {}",
            destination.display()
        ));
    }
    let destination = destination
        .to_str()
        .ok_or_else(|| anyhow!("snapshot destination is not valid UTF-8"))?;
    if destination.contains('\0') || destination.len() > MAX_SNAPSHOT_PATH_BYTES {
        return Err(anyhow!("snapshot destination contains NUL or is too long"));
    }
    Ok(destination.to_string())
}

fn parse_snapshot_response(status: StatusCode, response_body: &[u8]) -> Result<String> {
    let response_body =
        std::str::from_utf8(response_body).context("snapshot response is not valid UTF-8")?;
    if status != StatusCode::OK {
        return Err(anyhow!(
            "snapshot request failed with status {status}: {response_body}"
        ));
    }
    Ok(response_body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_destination_must_be_absolute_and_new() {
        assert!(validate_destination(Path::new("relative")).is_err());
        assert!(validate_destination(Path::new("/")).is_err());

        let parent = tempfile::tempdir().unwrap();
        assert_eq!(
            validate_destination(&parent.path().join("snapshot")).unwrap(),
            parent.path().join("snapshot").display().to_string()
        );
        assert!(validate_destination(parent.path()).is_err());
    }

    #[test]
    fn snapshot_response_requires_success_and_utf8() {
        assert_eq!(
            parse_snapshot_response(StatusCode::OK, b"/snapshot/final").unwrap(),
            "/snapshot/final"
        );
        assert!(parse_snapshot_response(StatusCode::BAD_REQUEST, b"invalid path").is_err());
        assert!(parse_snapshot_response(StatusCode::OK, &[0xff]).is_err());
    }
}
