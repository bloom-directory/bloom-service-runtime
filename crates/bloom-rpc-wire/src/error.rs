use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireErrorCode {
    MalformedFrame,
    UnknownField,
    LimitExceededFrame,
    UnauthenticatedPeer,
    UnsupportedVersion,
    OperationIdConflict,
    QuotaExceeded,
    ServiceUnavailable,
    ClockRollback,
    ClockUntrusted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, thiserror::Error)]
#[error("{code:?}: {message}")]
#[serde(deny_unknown_fields)]
pub struct WireError {
    pub code: WireErrorCode,
    pub message: String,
}

impl WireError {
    pub fn new(code: WireErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn fatal(code: WireErrorCode, message: impl Into<String>) -> Self {
        Self::new(code, message)
    }
}
