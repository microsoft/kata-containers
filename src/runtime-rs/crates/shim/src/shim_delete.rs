// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Result};
use containerd_shim_protos::api;
use kata_sys_util::spec::{get_bundle_path, get_container_type, load_oci_spec};
use kata_types::container::ContainerType;
use nix::{sys::signal::kill, sys::signal::SIGKILL, unistd::Pid};
use protobuf::Message;
use std::{
    fs::{self, OpenOptions},
    path::Path,
};

use crate::{
    shim::{ShimExecutor, POD_SET_UID_ANNOTATION},
    Error,
};
use fs2::FileExt;

impl ShimExecutor {
    pub async fn delete(&mut self) -> Result<()> {
        self.args.validate(true).context("validate")?;
        let rsp = self.do_cleanup().await.context("shim do cleanup")?;
        rsp.write_to_writer(&mut std::io::stdout())
            .context(Error::FileWrite(format!("write {rsp:?} to stdout")))?;
        Ok(())
    }

    async fn do_cleanup(&self) -> Result<api::DeleteResponse> {
        let mut rsp = api::DeleteResponse::new();
        rsp.set_exit_status(128 + libc::SIGKILL as u32);
        let mut exited_time = protobuf::well_known_types::timestamp::Timestamp::new();
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(Error::SystemTime)?
            .as_secs() as i64;
        exited_time.seconds = seconds;
        rsp.set_exited_at(exited_time);

        let bundle_path = get_bundle_path().context("get bundle path")?;
        let pod_set_uid = self
            .load_oci_spec(&bundle_path)
            .ok()
            .and_then(|spec| spec.annotations().clone())
            .and_then(|annotations| annotations.get(POD_SET_UID_ANNOTATION).cloned())
            .filter(|uid| !uid.is_empty());

        let (address, cleanup_sid, last_member) = if let Some(pod_set_uid) = pod_set_uid {
            self.unregister_pod_set_sandbox(&pod_set_uid)?
        } else {
            (
                self.socket_address(&self.args.id)
                    .context("socket address")?,
                self.args.id.clone(),
                true,
            )
        };
        let trim_path = address.strip_prefix("unix://").context("trim path")?;
        let file_path = Path::new("/").join(trim_path);
        let file_path = file_path.as_path();
        if last_member && std::fs::metadata(file_path).is_ok() {
            info!(sl!(), "remote socket path: {:?}", &file_path);
            fs::remove_file(file_path).ok();
        }

        if last_member {
            if let Err(e) = service::ServiceManager::cleanup(&cleanup_sid).await {
                error!(
                    sl!(),
                    "failed to cleanup in service manager: {:?}. force shutdown shim process", e
                );

                if let Ok(spec) = load_oci_spec() {
                    if let Ok(ContainerType::PodSandbox) = get_container_type(&spec) {
                        // only force shutdown for sandbox container
                        if let Ok(shim_pid) = self.read_pid_file(&bundle_path) {
                            info!(sl!(), "force to shutdown shim process {}", shim_pid);
                            let pid = Pid::from_raw(shim_pid as i32);
                            if let Err(_e) = kill(pid, SIGKILL) {
                                // ignore kill errors
                            }
                        }
                    }
                }
            }
        }

        Ok(rsp)
    }

    fn unregister_pod_set_sandbox(
        &self,
        pod_set_uid: &str,
    ) -> Result<(std::path::PathBuf, String, bool)> {
        let state_dir = self.pod_set_state_dir(pod_set_uid);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(state_dir.join("lock"))
            .context("open PodSet state lock")?;
        lock.lock_exclusive().context("lock PodSet state")?;

        let member_address = self.socket_address(&self.args.id)?;
        let member_socket = ShimExecutor::socket_file(&member_address)?;
        let canonical_address = self.socket_address(pod_set_uid)?;
        let canonical_socket = ShimExecutor::socket_file(&canonical_address)?;
        if member_socket != canonical_socket {
            fs::remove_file(member_socket).ok();
        }
        fs::remove_file(self.pod_set_member_file(pod_set_uid, &self.args.id)).ok();

        let members_dir = state_dir.join("members");
        let last_member = fs::read_dir(&members_dir)
            .context("read PodSet members")?
            .next()
            .is_none();
        let owner =
            fs::read_to_string(state_dir.join("owner")).context("read PodSet runtime owner")?;

        if last_member {
            fs::remove_file(&canonical_socket).ok();
        }

        Ok((canonical_address, owner, last_member))
    }
}
