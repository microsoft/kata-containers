// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{io::IntoRawFd, prelude::OsStrExt},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use fs2::FileExt;
use kata_sys_util::spec::get_bundle_path;
use kata_types::{container::ContainerType, k8s};
use unix_socket::UnixListener;

use crate::{
    shim::{ShimExecutor, ENV_KATA_RUNTIME_BIND_FD, POD_SET_UID_ANNOTATION},
    Error,
};

impl ShimExecutor {
    pub fn start(&mut self) -> Result<()> {
        self.args.validate(false).context("validate")?;

        let address = self.do_start().context("do start")?;
        std::io::stdout()
            .write_all(address.as_os_str().as_bytes())
            .context("failed to write stdout")?;
        Ok(())
    }

    fn do_start(&mut self) -> Result<PathBuf> {
        let bundle_path = get_bundle_path().context("get bundle path")?;

        let mut container_type = ContainerType::PodSandbox;
        let mut id = None;

        let mut pod_set_uid = None;
        if let Ok(spec) = self.load_oci_spec(&bundle_path) {
            (container_type, id) = k8s::container_type_with_id(&spec);
            pod_set_uid = spec
                .annotations()
                .as_ref()
                .and_then(|annotations| annotations.get(POD_SET_UID_ANNOTATION))
                .filter(|uid| !uid.is_empty())
                .cloned();
        }

        match container_type {
            ContainerType::PodSandbox | ContainerType::SingleContainer => {
                if let Some(pod_set_uid) = pod_set_uid {
                    return self.start_pod_set_sandbox(&bundle_path, &pod_set_uid);
                }
                let address = self.socket_address(&self.args.id)?;
                let socket = new_listener(&address)?;
                let child_pid = self.create_shim_process(socket)?;
                self.write_pid_file(&bundle_path, child_pid)?;
                self.write_address(&bundle_path, &address)?;
                Ok(address)
            }
            ContainerType::PodContainer => {
                let sid = id
                    .ok_or(Error::InvalidArgument)
                    .context("get sid for container")?;
                let address = self.socket_address(&sid).context("socket address")?;
                self.write_address(&bundle_path, &address)?;
                Ok(address)
            }
        }
    }

    fn start_pod_set_sandbox(&self, bundle_path: &Path, pod_set_uid: &str) -> Result<PathBuf> {
        let state_dir = self.pod_set_state_dir(pod_set_uid);
        let members_dir = state_dir.join("members");
        fs::create_dir_all(&members_dir).context("create PodSet state directory")?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(state_dir.join("lock"))
            .context("open PodSet state lock")?;
        lock.lock_exclusive().context("lock PodSet state")?;

        let canonical_address = self.socket_address(pod_set_uid)?;
        let canonical_socket = ShimExecutor::socket_file(&canonical_address)?;
        let member_address = self.socket_address(&self.args.id)?;
        let member_socket = ShimExecutor::socket_file(&member_address)?;

        let child_pid = if canonical_socket.exists() {
            fs::read_to_string(state_dir.join("pid"))
                .context("read PodSet shim pid")?
                .parse::<u32>()
                .context("parse PodSet shim pid")?
        } else {
            let socket = new_listener(&canonical_address)?;
            let child_pid = self.create_shim_process(socket)?;
            fs::write(state_dir.join("pid"), child_pid.to_string())
                .context("write PodSet shim pid")?;
            fs::write(state_dir.join("owner"), &self.args.id)
                .context("write PodSet runtime owner")?;
            child_pid
        };

        if member_socket != canonical_socket {
            if member_socket.exists() {
                fs::remove_file(&member_socket).context("remove stale sandbox socket alias")?;
            }
            fs::hard_link(&canonical_socket, &member_socket)
                .context("create sandbox socket alias")?;
        }
        fs::write(
            self.pod_set_member_file(pod_set_uid, &self.args.id),
            &self.args.id,
        )
        .context("register PodSet sandbox")?;
        self.write_pid_file(bundle_path, child_pid)?;
        self.write_address(bundle_path, &member_address)?;

        Ok(member_address)
    }

    fn new_command(&self) -> Result<std::process::Command> {
        if self.args.id.is_empty()
            || self.args.namespace.is_empty()
            || self.args.publish_binary.is_empty()
        {
            return Err(anyhow!("invalid param"));
        }

        let bundle_path = get_bundle_path().context("get bundle path")?;
        let self_exec = std::env::current_exe().map_err(Error::SelfExec)?;
        let mut command = std::process::Command::new(self_exec);

        command
            .current_dir(bundle_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .arg("-id")
            .arg(&self.args.id)
            .arg("-namespace")
            .arg(&self.args.namespace)
            .arg("-address")
            .arg(&self.args.address)
            .arg("-publish-binary")
            .arg(&self.args.publish_binary)
            .env("RUST_BACKTRACE", "1");

        if self.args.debug {
            command.arg("-debug");
        }

        Ok(command)
    }

    fn create_shim_process<T: IntoRawFd>(&self, socket: T) -> Result<u32> {
        let mut cmd = self.new_command().context("new command")?;
        cmd.env(
            ENV_KATA_RUNTIME_BIND_FD,
            format!("{}", socket.into_raw_fd()),
        );
        let child = cmd
            .spawn()
            .map_err(Error::SpawnChild)
            .context("spawn child")?;

        Ok(child.id())
    }
}

fn new_listener(address: &Path) -> Result<UnixListener> {
    let trim_path = address.strip_prefix("unix:").context("trim path")?;
    let file_path = Path::new("/").join(trim_path);
    let file_path = file_path.as_path();
    if let Some(parent_dir) = file_path.parent() {
        fs::create_dir_all(parent_dir).context("create parent dir")?;
    }

    UnixListener::bind(file_path).context("bind address")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serial_test::serial;

    use super::*;
    use crate::Args;

    #[test]
    #[serial]
    fn test_new_command() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path();
        std::env::set_current_dir(bundle_path).unwrap();

        let args = Args {
            id: "default_id".into(),
            namespace: "default_namespace".into(),
            address: "default_address".into(),
            publish_binary: "containerd".into(),
            bundle: bundle_path.to_str().unwrap().into(),
            ..Default::default()
        };
        let mut executor = ShimExecutor::new(args);

        let cmd = executor.new_command().unwrap();
        assert_eq!(cmd.get_args().len(), 8);
        assert_eq!(cmd.get_envs().len(), 1);
        assert_eq!(cmd.get_current_dir().unwrap(), get_bundle_path().unwrap());

        executor.args.debug = true;
        let cmd = executor.new_command().unwrap();
        assert_eq!(cmd.get_args().len(), 9);
        assert_eq!(cmd.get_envs().len(), 1);
        assert_eq!(cmd.get_current_dir().unwrap(), get_bundle_path().unwrap());
    }

    #[test]
    #[serial]
    fn test_new_listener() {
        let path = "/tmp/aaabbbccc";
        let uds_path = format!("unix://{}", path);
        std::fs::remove_file(path).ok();

        let _ = new_listener(Path::new(&uds_path)).unwrap();
        std::fs::remove_file(path).ok();
    }
}
