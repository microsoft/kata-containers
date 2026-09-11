// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use agent::Agent;
use anyhow::Context;
use tokio::sync::{mpsc, Mutex, Notify};

/// monitor check interval 30s
const HEALTH_CHECK_TIMER_INTERVAL: u64 = 30;

/// version check threshold 5min
const VERSION_CHECK_THRESHOLD: u64 = 5 * 60 / HEALTH_CHECK_TIMER_INTERVAL;

/// health check stop channel buffer size
const HEALTH_CHECK_STOP_CHANNEL_BUFFER_SIZE: usize = 1;

/// Marks the complete health operation, including the periodic version RPC.
/// Snapshot suspension waits for this guard rather than racing an intentional
/// disconnect against monitor failure handling.
struct HealthCheckActivity {
    checking: Arc<AtomicBool>,
    state_notify: Arc<Notify>,
}

impl HealthCheckActivity {
    fn new(checking: Arc<AtomicBool>, state_notify: Arc<Notify>) -> Self {
        checking.store(true, Ordering::Release);
        Self {
            checking,
            state_notify,
        }
    }
}

impl Drop for HealthCheckActivity {
    fn drop(&mut self) {
        self.checking.store(false, Ordering::Release);
        self.state_notify.notify_waiters();
    }
}

pub struct HealthCheck {
    pub keep_alive: bool,
    keep_abnormal: bool,
    stop_tx: mpsc::Sender<()>,
    stop_rx: Arc<Mutex<mpsc::Receiver<()>>>,
    suspended: Arc<AtomicBool>,
    checking: Arc<AtomicBool>,
    state_notify: Arc<Notify>,
}

impl HealthCheck {
    pub fn new(keep_alive: bool, keep_abnormal: bool) -> HealthCheck {
        let (tx, rx) = mpsc::channel(HEALTH_CHECK_STOP_CHANNEL_BUFFER_SIZE);
        HealthCheck {
            keep_alive,
            keep_abnormal,
            stop_tx: tx,
            stop_rx: Arc::new(Mutex::new(rx)),
            suspended: Arc::new(AtomicBool::new(false)),
            checking: Arc::new(AtomicBool::new(false)),
            state_notify: Arc::new(Notify::new()),
        }
    }

    pub fn start(&self, id: &str, agent: Arc<dyn Agent>) {
        if !self.keep_alive {
            return;
        }
        let id = id.to_string();

        info!(sl!(), "start runtime keep alive");

        let stop_rx = self.stop_rx.clone();
        let keep_abnormal = self.keep_abnormal;
        let suspended = self.suspended.clone();
        let checking = self.checking.clone();
        let state_notify = self.state_notify.clone();
        tokio::spawn(async move {
            let mut version_check_threshold_count = 0;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(HEALTH_CHECK_TIMER_INTERVAL))
                    .await;
                let mut stop_rx = stop_rx.lock().await;
                match stop_rx.try_recv() {
                    Ok(_) => {
                        info!(sl!(), "revive stop {} monitor signal", id);
                        break;
                    }

                    Err(mpsc::error::TryRecvError::Empty) => {
                        if suspended.load(Ordering::Acquire) {
                            continue;
                        }
                        let activity =
                            HealthCheckActivity::new(checking.clone(), state_notify.clone());
                        // suspend() may have won immediately before we marked
                        // the check active. Recheck after registration so it
                        // can observe either no check or this guarded check.
                        if suspended.load(Ordering::Acquire) {
                            continue;
                        }
                        // check agent
                        let result = agent
                            .check(agent::CheckRequest::new(""))
                            .await
                            .context("check health");
                        match result {
                            Ok(_) => {
                                debug!(sl!(), "check {} agent health successfully", id);
                                version_check_threshold_count += 1;
                                if version_check_threshold_count >= VERSION_CHECK_THRESHOLD {
                                    // need to check version
                                    version_check_threshold_count = 0;
                                    if let Ok(v) = agent
                                        .version(agent::CheckRequest::new(""))
                                        .await
                                        .context("check version")
                                    {
                                        info!(sl!(), "agent {}", v.agent_version)
                                    }
                                }
                                continue;
                            }
                            Err(e) => {
                                error!(sl!(), "failed to do {} agent health check: {}", id, e);
                                if let Err(mpsc::error::TryRecvError::Empty) = stop_rx.try_recv() {
                                    error!(sl!(), "failed to receive stop monitor signal");
                                    if !keep_abnormal {
                                        ::std::process::exit(1);
                                    }
                                } else {
                                    info!(sl!(), "wait to exit {}", id);
                                    break;
                                }
                            }
                        }
                        drop(activity);
                    }

                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        warn!(sl!(), "{} monitor channel has broken", id);
                        break;
                    }
                }
            }
        });
    }

    pub async fn stop(&self) {
        if !self.keep_alive {
            return;
        }
        info!(sl!(), "stop runtime keep alive");
        self.stop_tx
            .send(())
            .await
            .map_err(|e| {
                warn!(sl!(), "failed send monitor channel. {:?}", e);
            })
            .ok();
    }

    /// Prevent new monitor RPCs and wait for any active check to finish.
    pub async fn suspend(&self) {
        self.suspended.store(true, Ordering::Release);
        loop {
            // Arm before checking to avoid losing the final guard's wakeup.
            let notified = self.state_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.checking.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    pub fn resume(&self) {
        self.suspended.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn suspend_waits_for_active_health_activity() {
        let health_check = Arc::new(HealthCheck::new(true, true));
        let activity = HealthCheckActivity::new(
            health_check.checking.clone(),
            health_check.state_notify.clone(),
        );
        let suspend_task = {
            let health_check = health_check.clone();
            tokio::spawn(async move { health_check.suspend().await })
        };

        while !health_check.suspended.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        assert!(!suspend_task.is_finished());

        drop(activity);
        suspend_task.await.unwrap();
        assert!(health_check.suspended.load(Ordering::Acquire));

        health_check.resume();
        assert!(!health_check.suspended.load(Ordering::Acquire));
    }
}
