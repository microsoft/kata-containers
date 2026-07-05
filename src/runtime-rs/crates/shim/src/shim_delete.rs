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
use std::{fs, path::Path};

use crate::{shim::ShimExecutor, Error};

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

        let mut socket_id = self.args.id.clone();
        let bundle_path = get_bundle_path().context("get bundle path")?;

        match self.load_oci_spec(&bundle_path) {
            Ok(spec) => {
                let annotations = spec.annotations().clone().unwrap_or_default();
                if let Some(guest_vm_id_value) = annotations.get("io.katacontainers.config.hypervisor.guest_vm_id") {
                    socket_id = guest_vm_id_value.to_string();
                } else {
                }
            }
            Err(_e) => {
            }
        }
        
        let address = self
            // .socket_address(&self.args.id)
            .socket_address(&socket_id)
            .context("socket address")?;
        let trim_path = address.strip_prefix("unix://").context("trim path")?;
        let file_path = Path::new("/").join(trim_path);
        let file_path = file_path.as_path();
        
        /*
        if std::fs::metadata(file_path).is_ok() {
            info!(sl!(), "remote socket path: {:?}", &file_path);
            fs::remove_file(file_path).ok();
        }
        */
        let sandbox_id_path = file_path.with_extension("sandbox_id");
        let owned_by_this_sandbox = match fs::read_to_string(&sandbox_id_path) {
            Ok(saved_id) => {
                saved_id == self.args.id
            },
            Err(_) => true, // if file doesn't exist, allow removal for backward compat
        };

        if owned_by_this_sandbox {
            if std::fs::metadata(file_path).is_ok() {
                info!(sl!(), "ShimExecutor: remote socket path: {:?}", &file_path);

                fs::remove_file(file_path).ok();
            }
            fs::remove_file(&sandbox_id_path).ok();
        } else {
        }

        if let Err(e) = service::ServiceManager::cleanup(&self.args.id).await {
            error!(
                sl!(),
                "failed to cleanup in service manager: {:?}. force shutdown shim process", e
            );

            let bundle_path = get_bundle_path().context("get bundle path")?;
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

        Ok(rsp)
    }
}
