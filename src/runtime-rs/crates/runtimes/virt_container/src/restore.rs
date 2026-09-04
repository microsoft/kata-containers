// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use tokio::sync::{Mutex, MutexGuard};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestoreActivation {
    Cold,
    RestoringPaused,
    PreparedPaused,
    Activating,
    Active,
    Failed,
}

#[derive(Debug)]
struct RestoreState {
    activation: RestoreActivation,
    source_sandbox_id: Option<String>,
    source_pause_guest_id: Option<String>,
    target_pause_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct RestoreContext {
    target_sandbox_id: String,
    state: Mutex<RestoreState>,
    activation_lock: Mutex<()>,
}

impl RestoreContext {
    pub(crate) fn new(target_sandbox_id: &str) -> Self {
        Self {
            target_sandbox_id: target_sandbox_id.to_string(),
            state: Mutex::new(RestoreState {
                activation: RestoreActivation::Cold,
                source_sandbox_id: None,
                source_pause_guest_id: None,
                target_pause_id: None,
            }),
            activation_lock: Mutex::new(()),
        }
    }

    pub(crate) async fn begin(
        &self,
        source_sandbox_id: &str,
        source_pause_guest_id: &str,
    ) -> Result<()> {
        if source_sandbox_id.is_empty() || source_pause_guest_id.is_empty() {
            return Err(anyhow!("snapshot restore identity is incomplete"));
        }
        let mut state = self.state.lock().await;
        if state.activation != RestoreActivation::Cold {
            return Err(anyhow!("restore is already initialized"));
        }
        state.activation = RestoreActivation::RestoringPaused;
        state.source_sandbox_id = Some(source_sandbox_id.to_string());
        state.source_pause_guest_id = Some(source_pause_guest_id.to_string());
        Ok(())
    }

    pub(crate) async fn prepared_paused(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.activation != RestoreActivation::RestoringPaused {
            return Err(anyhow!("invalid prepared-paused restore transition"));
        }
        state.activation = RestoreActivation::PreparedPaused;
        Ok(())
    }

    pub(crate) async fn adopt_pause(&self, target_id: &str, is_pause: bool) -> Result<bool> {
        let mut state = self.state.lock().await;
        if state.activation == RestoreActivation::Cold {
            return Ok(false);
        }
        if state.activation == RestoreActivation::Failed {
            return Err(anyhow!("restore attempt has failed"));
        }
        if !is_pause || target_id != self.target_sandbox_id {
            return Err(anyhow!(
                "only the target pause task may be adopted in Phase 3"
            ));
        }
        match state.target_pause_id.as_deref() {
            None => state.target_pause_id = Some(target_id.to_string()),
            Some(existing) if existing == target_id => {}
            Some(_) => return Err(anyhow!("restored pause task is already adopted")),
        }
        Ok(true)
    }

    pub(crate) async fn activation_guard(&self) -> MutexGuard<'_, ()> {
        self.activation_lock.lock().await
    }

    pub(crate) async fn begin_activation(&self, target_id: &str) -> Result<bool> {
        let mut state = self.state.lock().await;
        match state.activation {
            RestoreActivation::Cold => Ok(false),
            RestoreActivation::PreparedPaused if target_id == self.target_sandbox_id => {
                state.activation = RestoreActivation::Activating;
                Ok(true)
            }
            RestoreActivation::Active if target_id == self.target_sandbox_id => Ok(true),
            RestoreActivation::Failed => Err(anyhow!("restore attempt has failed")),
            _ => Err(anyhow!("invalid restored sandbox activation transition")),
        }
    }

    pub(crate) async fn needs_activation(&self) -> bool {
        self.state.lock().await.activation == RestoreActivation::Activating
    }

    pub(crate) async fn activate(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.activation != RestoreActivation::Activating {
            return Err(anyhow!("invalid active restore transition"));
        }
        state.activation = RestoreActivation::Active;
        Ok(())
    }

    pub(crate) async fn source_pause_guest_id(&self) -> Result<String> {
        self.state
            .lock()
            .await
            .source_pause_guest_id
            .clone()
            .ok_or_else(|| anyhow!("snapshot pause guest ID is unavailable"))
    }

    pub(crate) async fn target_pause_id(&self) -> Option<String> {
        self.state.lock().await.target_pause_id.clone()
    }

    pub(crate) async fn pause_guest_id_for_target(&self, target_id: &str) -> Option<String> {
        let state = self.state.lock().await;
        (state.target_pause_id.as_deref() == Some(target_id))
            .then(|| state.source_pause_guest_id.clone())
            .flatten()
    }

    pub(crate) async fn fail(&self) {
        self.state.lock().await.activation = RestoreActivation::Failed;
    }

    #[cfg(test)]
    async fn activation(&self) -> RestoreActivation {
        self.state.lock().await.activation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn activates_only_the_target_sandbox() {
        let context = RestoreContext::new("target");
        context.begin("source", "source-pause").await.unwrap();
        context.prepared_paused().await.unwrap();
        assert!(context.adopt_pause("target", true).await.unwrap());
        assert!(context.begin_activation("target").await.unwrap());
        assert!(context.needs_activation().await);
        context.activate().await.unwrap();
        assert_eq!(context.activation().await, RestoreActivation::Active);
    }

    #[tokio::test]
    async fn rejects_workload_adoption_in_phase_three() {
        let context = RestoreContext::new("target");
        context.begin("source", "source-pause").await.unwrap();
        context.prepared_paused().await.unwrap();
        assert!(context.adopt_pause("workload", false).await.is_err());
    }
}
