// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestorePhase {
    Cold,
    RestoringPaused,
    AdoptingPause,
    PauseAdopted,
    StartsStaged,
    Failed,
}

#[derive(Debug)]
struct RestoreState {
    phase: RestorePhase,
    source_sandbox_id: Option<String>,
    target_pause_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct RestoreCoordinator {
    state: Mutex<RestoreState>,
}

impl RestoreCoordinator {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RestoreState {
                phase: RestorePhase::Cold,
                source_sandbox_id: None,
                target_pause_id: None,
            }),
        }
    }

    pub(crate) async fn begin(&self, source_sandbox_id: &str) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.phase != RestorePhase::Cold || source_sandbox_id.is_empty() {
            return Err(anyhow!("invalid restore begin transition"));
        }
        state.phase = RestorePhase::RestoringPaused;
        state.source_sandbox_id = Some(source_sandbox_id.to_string());
        Ok(())
    }

    pub(crate) async fn restored_paused(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.phase != RestorePhase::RestoringPaused {
            return Err(anyhow!("invalid restored-paused transition"));
        }
        state.phase = RestorePhase::AdoptingPause;
        Ok(())
    }

    pub(crate) async fn adopt_pause(&self, target_id: &str, is_pause: bool) -> Result<bool> {
        let mut state = self.state.lock().await;
        match state.phase {
            RestorePhase::Cold => Ok(false),
            RestorePhase::AdoptingPause if is_pause && !target_id.is_empty() => {
                state.target_pause_id = Some(target_id.to_string());
                state.phase = RestorePhase::PauseAdopted;
                Ok(true)
            }
            RestorePhase::Failed => Err(anyhow!("restore attempt has failed")),
            _ if !is_pause => {
                state.phase = RestorePhase::Failed;
                Err(anyhow!(
                    "workload adoption requires Phase 4; restored VM remains paused"
                ))
            }
            _ => Err(anyhow!("invalid pause adoption transition")),
        }
    }

    pub(crate) async fn stage_pause_start(&self, target_id: &str) -> Result<bool> {
        let mut state = self.state.lock().await;
        match state.phase {
            RestorePhase::Cold => Ok(false),
            RestorePhase::PauseAdopted if state.target_pause_id.as_deref() == Some(target_id) => {
                state.phase = RestorePhase::StartsStaged;
                Ok(true)
            }
            RestorePhase::StartsStaged if state.target_pause_id.as_deref() == Some(target_id) => {
                Ok(true)
            }
            RestorePhase::Failed => Err(anyhow!("restore attempt has failed")),
            _ => Err(anyhow!("invalid restored pause start transition")),
        }
    }

    pub(crate) async fn is_adopted_pause(&self, target_id: &str) -> bool {
        self.state.lock().await.target_pause_id.as_deref() == Some(target_id)
    }

    pub(crate) async fn fail(&self) {
        self.state.lock().await.phase = RestorePhase::Failed;
    }

    #[cfg(test)]
    async fn phase(&self) -> RestorePhase {
        self.state.lock().await.phase
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stages_only_the_restored_pause_task() {
        let coordinator = RestoreCoordinator::new();
        coordinator.begin("source").await.unwrap();
        coordinator.restored_paused().await.unwrap();
        assert!(coordinator.adopt_pause("target", true).await.unwrap());
        assert!(coordinator.stage_pause_start("target").await.unwrap());
        assert_eq!(coordinator.phase().await, RestorePhase::StartsStaged);
    }

    #[tokio::test]
    async fn rejects_workloads_before_phase_four() {
        let coordinator = RestoreCoordinator::new();
        coordinator.begin("source").await.unwrap();
        coordinator.restored_paused().await.unwrap();
        assert!(coordinator.adopt_pause("workload", false).await.is_err());
    }
}
