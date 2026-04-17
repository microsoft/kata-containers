// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    convert::{TryFrom, TryInto},
    sync::Arc,
    time::Instant,
};

use async_trait::async_trait;
use common::error::Error as CommonError;
use common::types::{TaskRequest, TaskResponse};
use containerd_shim_protos::{api, shim_async};
use ttrpc::{self, r#async::TtrpcContext};

use runtimes::RuntimeHandlerManager;

pub(crate) struct TaskService {
    handler: Arc<RuntimeHandlerManager>,
}

impl TaskService {
    pub(crate) fn new(handler: Arc<RuntimeHandlerManager>) -> Self {
        Self { handler }
    }

    /// Convert handler errors to proper ttrpc status codes.
    /// Specifically, maps ContainerNotFound and ProcessAlreadyTerminated to NOT_FOUND
    /// so containerd stops polling/retrying and allows pods to exit Terminating state.
    fn convert_handler_error(err: anyhow::Error) -> ttrpc::Error {
        // Check if the error chain contains a known error type
        if let Some(common_err) = err.downcast_ref::<CommonError>() {
            match common_err {
                CommonError::ContainerNotFound(_) => {
                    // Return NOT_FOUND status so containerd stops polling this container
                    let mut status = ttrpc::Status::new();
                    status.set_code(ttrpc::Code::NOT_FOUND);
                    status.message = format!("container not found: {}", common_err);
                    return ttrpc::Error::RpcStatus(status);
                }
                CommonError::ProcessAlreadyTerminated => {
                    // Process is already gone - also return NOT_FOUND to stop retries
                    let mut status = ttrpc::Status::new();
                    status.set_code(ttrpc::Code::NOT_FOUND);
                    status.message = "process already terminated".to_string();
                    return ttrpc::Error::RpcStatus(status);
                }
                _ => {}
            }
        }
        // Default: return generic error
        ttrpc::Error::Others(format!("failed to handle message {err:?}"))
    }

    async fn handler_message<TtrpcReq, TtrpcResp>(
        &self,
        method: &'static str,
        ctx: &TtrpcContext,
        req: TtrpcReq,
    ) -> ttrpc::Result<TtrpcResp>
    where
        TaskRequest: TryFrom<TtrpcReq>,
        <TaskRequest as TryFrom<TtrpcReq>>::Error: std::fmt::Debug,
        TtrpcResp: TryFrom<TaskResponse>,
        <TtrpcResp as TryFrom<TaskResponse>>::Error: std::fmt::Debug,
    {
        let start = Instant::now();
        let logger = sl!().new(o!("stream id" =>  ctx.mh.stream_id, "method" => method));
        info!(logger, "task rpc begin");
        let r = req.try_into().map_err(|err| {
            ttrpc::Error::Others(format!("failed to translate from shim {err:?}"))
        })?;
        debug!(logger, "====> task service {:?}", &r);
        let resp = self
            .handler
            .handler_task_message(r)
            .await
            .map_err(|err| Self::convert_handler_error(err))?;
        debug!(logger, "<==== task service {:?}", &resp);
        info!(
            logger,
            "task rpc completed";
            "elapsed_ms" => start.elapsed().as_millis() as u64,
        );
        resp.try_into()
            .map_err(|err| ttrpc::Error::Others(format!("failed to translate to shim {err:?}")))
    }
}

macro_rules! impl_service {
    ($($name: tt | $req: ty | $resp: ty),*) => {
        #[async_trait]
        impl shim_async::Task for TaskService {
            $(async fn $name(&self, ctx: &TtrpcContext, req: $req) -> ttrpc::Result<$resp> {
                self.handler_message(stringify!($name), ctx, req).await
            })*
        }
    };
}

impl_service!(
    state | api::StateRequest | api::StateResponse,
    create | api::CreateTaskRequest | api::CreateTaskResponse,
    start | api::StartRequest | api::StartResponse,
    delete | api::DeleteRequest | api::DeleteResponse,
    pids | api::PidsRequest | api::PidsResponse,
    pause | api::PauseRequest | api::Empty,
    resume | api::ResumeRequest | api::Empty,
    kill | api::KillRequest | api::Empty,
    exec | api::ExecProcessRequest | api::Empty,
    resize_pty | api::ResizePtyRequest | api::Empty,
    update | api::UpdateTaskRequest | api::Empty,
    wait | api::WaitRequest | api::WaitResponse,
    stats | api::StatsRequest | api::StatsResponse,
    connect | api::ConnectRequest | api::ConnectResponse,
    shutdown | api::ShutdownRequest | api::Empty,
    close_io | api::CloseIORequest | api::Empty
);
