//! input: std::fmt
//! output: ClientError
//! pos: embeddable client handle error boundary.

use std::fmt;

/// Errors returned by [`crate::client::handle::RusnelHandle`].
#[derive(Debug)]
pub enum ClientError {
    /// A previous client task is still running, so a second `start` would lose
    /// lifecycle ownership.
    AlreadyRunning,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => write!(f, "rusnel client already running"),
        }
    }
}

impl std::error::Error for ClientError {}
