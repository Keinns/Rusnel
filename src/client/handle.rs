//! input: crate::ClientConfig, client::run_async_with_shutdown, tokio, futures
//! output: RusnelHandle with start/stop/state/subscribe lifecycle control
//! pos: embeddable client API for hosts that need programmatic shutdown.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use tokio::sync::{broadcast, watch, Mutex};
use tokio::task::JoinHandle;

use crate::client::error::ClientError;
use crate::client::lifecycle::{transition, ExitReason, LifecycleState, RusnelEvent};
use crate::ClientConfig;

/// Programmatic lifecycle handle for an embedded Rusnel client.
#[derive(Clone)]
pub struct RusnelHandle {
    inner: Arc<Inner>,
}

/// Shared handle state; `RusnelHandle` clones only clone this `Arc`.
struct Inner {
    /// Latest lifecycle state, readable without awaiting `task`.
    state_tx: watch::Sender<LifecycleState>,
    /// Broadcast event stream for all subscribers.
    event_tx: broadcast::Sender<RusnelEvent>,
    /// Current running task, protected so start/stop are mutually exclusive.
    task: Mutex<Option<RunningTask>>,
}

/// Spawned client task plus the shutdown sender wired to it.
struct RunningTask {
    /// Join handle for the isolated client future.
    handle: JoinHandle<()>,
    /// Sender paired with `run_async_with_shutdown`'s external receiver.
    shutdown: broadcast::Sender<()>,
}

impl Default for RusnelHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl RusnelHandle {
    /// Creates a handle with the default event buffer capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(256)
    }

    /// Creates a handle with a caller-selected event buffer capacity.
    #[must_use]
    pub fn with_capacity(event_capacity: usize) -> Self {
        let (state_tx, _) = watch::channel(LifecycleState::Idle);
        let (event_tx, _) = broadcast::channel(event_capacity);

        Self {
            inner: Arc::new(Inner {
                state_tx,
                event_tx,
                task: Mutex::new(None),
            }),
        }
    }

    /// Subscribes to lifecycle events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<RusnelEvent> {
        self.inner.event_tx.subscribe()
    }

    /// Returns the latest lifecycle state snapshot.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.inner.state_tx.borrow().clone()
    }

    /// Starts the client task with the provided native [`ClientConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::AlreadyRunning`] when the previous task has not
    /// exited yet.
    pub async fn start(&self, config: ClientConfig) -> Result<(), ClientError> {
        let mut guard = self.inner.task.lock().await;
        if let Some(task) = guard.as_ref() {
            if !task.handle.is_finished() {
                return Err(ClientError::AlreadyRunning);
            }
        }

        let _ = rustls::crypto::ring::default_provider().install_default();

        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let state_tx = self.inner.state_tx.clone();
        let event_tx = self.inner.event_tx.clone();

        transition(&state_tx, &event_tx, LifecycleState::Running);
        let handle = tokio::spawn(async move {
            run_client_session(config, shutdown_rx, state_tx, event_tx).await;
        });

        *guard = Some(RunningTask {
            handle,
            shutdown: shutdown_tx,
        });
        Ok(())
    }

    /// Requests graceful shutdown and waits up to five seconds before aborting.
    ///
    /// # Errors
    ///
    /// This method is currently infallible; it returns `Result` so callers can
    /// use one uniform async control path for start and stop.
    pub async fn stop(&self) -> Result<(), ClientError> {
        let task = {
            let mut guard = self.inner.task.lock().await;
            guard.take()
        };
        let Some(task) = task else {
            return Ok(());
        };

        transition(
            &self.inner.state_tx,
            &self.inner.event_tx,
            LifecycleState::Stopping,
        );
        let _ = task.shutdown.send(());
        let abort_handle = task.handle.abort_handle();

        match tokio::time::timeout(Duration::from_secs(5), task.handle).await {
            Ok(_) => {
                let current = self.inner.state_tx.borrow().clone();
                if !matches!(current, LifecycleState::Stopped { .. }) {
                    transition(
                        &self.inner.state_tx,
                        &self.inner.event_tx,
                        LifecycleState::Stopped {
                            reason: ExitReason::UserStopped,
                        },
                    );
                }
            }
            Err(_) => {
                abort_handle.abort();
                transition(
                    &self.inner.state_tx,
                    &self.inner.event_tx,
                    LifecycleState::Stopped {
                        reason: ExitReason::Error("stop timeout, hard aborted".to_string()),
                    },
                );
            }
        }

        Ok(())
    }
}

/// Runs one client session and maps all terminal paths to lifecycle events.
async fn run_client_session(
    config: ClientConfig,
    shutdown_rx: broadcast::Receiver<()>,
    state_tx: watch::Sender<LifecycleState>,
    event_tx: broadcast::Sender<RusnelEvent>,
) {
    let result = AssertUnwindSafe(crate::client::run_async_with_shutdown(config, shutdown_rx))
        .catch_unwind()
        .await;

    let reason = match result {
        Ok(Ok(())) => ExitReason::Clean,
        Ok(Err(error)) => ExitReason::Error(error.to_string()),
        Err(panic) => ExitReason::Panic(
            panic
                .downcast_ref::<&str>()
                .map(|message| (*message).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string()),
        ),
    };

    transition(
        &state_tx,
        &event_tx,
        LifecycleState::Stopped {
            reason: reason.clone(),
        },
    );
    let _ = event_tx.send(RusnelEvent::Exited { reason });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stop_is_ok_when_idle() {
        let handle = RusnelHandle::new();

        handle.stop().await.expect("idle stop should succeed");

        assert_eq!(handle.state(), LifecycleState::Idle);
    }
}
