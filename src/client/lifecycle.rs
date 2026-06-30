//! input: serde, tokio::sync::broadcast/watch
//! output: LifecycleState, RusnelEvent, ExitReason, transition()
//! pos: embeddable client lifecycle state and event model.

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};

/// Reason why an embedded client session reached a stopped state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitReason {
    /// `run_async_with_shutdown` returned successfully.
    Clean,
    /// `stop` completed before the client task wrote a more specific reason.
    UserStopped,
    /// The client returned an error.
    Error(String),
    /// The client task panicked and the handle isolated the panic.
    Panic(String),
}

/// Current lifecycle state for a [`crate::client::handle::RusnelHandle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// The handle has not started a client task.
    Idle,
    /// A client task has been spawned and owns the Rusnel session.
    Running,
    /// `stop` has sent shutdown and is waiting for the client task to exit.
    Stopping,
    /// The client task has exited or was aborted after a stop timeout.
    Stopped { reason: ExitReason },
}

impl LifecycleState {
    /// Returns true while the handle owns a live client task.
    #[must_use]
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }
}

/// Events emitted by an embedded client handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RusnelEvent {
    /// Lifecycle state changed.
    StateChange {
        /// Previous state observed from the watch channel.
        from: LifecycleState,
        /// New state written to the watch channel.
        to: LifecycleState,
    },
    /// The client task exited and will not emit more lifecycle transitions.
    Exited {
        /// Final exit reason.
        reason: ExitReason,
    },
}

/// Writes the latest lifecycle state and broadcasts a matching event.
pub(crate) fn transition(
    state_tx: &watch::Sender<LifecycleState>,
    event_tx: &broadcast::Sender<RusnelEvent>,
    to: LifecycleState,
) {
    let from = state_tx.borrow().clone();
    if from == to {
        return;
    }

    state_tx.send_replace(to.clone());
    let _ = event_tx.send(RusnelEvent::StateChange { from, to });
}
