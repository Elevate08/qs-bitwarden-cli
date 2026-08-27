//! Strict, bounded panel-to-companion control messages.

use serde::Deserialize;

pub const CONTROL_VERSION: u8 = 1;
pub const MAX_CONTROL_LINE: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlMessage {
    Hello {
        v: u8,
    },
    KeyLoadBegin {
        v: u8,
        epoch: u64,
        #[serde(rename = "loadId")]
        load_id: String,
    },
    KeyLoadEnd {
        v: u8,
        epoch: u64,
        status: LoadStatus,
    },
    VaultLocked {
        v: u8,
        epoch: u64,
    },
    VaultLoggedOut {
        v: u8,
    },
    Approve {
        v: u8,
        #[serde(rename = "requestId")]
        request_id: u64,
        #[serde(rename = "grantSeconds")]
        grant_seconds: u64,
    },
    Deny {
        v: u8,
        #[serde(rename = "requestId")]
        request_id: u64,
    },
    UnlockCancelled {
        v: u8,
        #[serde(rename = "requestId")]
        request_id: u64,
        reason: String,
    },
    RevokeGrants {
        v: u8,
    },
    Shutdown {
        v: u8,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LoadStatus {
    Ok,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    Empty,
    TooLong,
    Malformed,
    WrongVersion,
}

impl ControlMessage {
    pub fn version(&self) -> u8 {
        match self {
            Self::Hello { v }
            | Self::VaultLoggedOut { v }
            | Self::RevokeGrants { v }
            | Self::Shutdown { v } => *v,
            Self::KeyLoadBegin { v, .. }
            | Self::KeyLoadEnd { v, .. }
            | Self::VaultLocked { v, .. }
            | Self::Approve { v, .. }
            | Self::Deny { v, .. }
            | Self::UnlockCancelled { v, .. } => *v,
        }
    }
}

pub fn parse_control_line(line: &[u8]) -> Result<ControlMessage, ControlError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
        return Err(ControlError::Empty);
    }
    if line.len() > MAX_CONTROL_LINE {
        return Err(ControlError::TooLong);
    }
    let message: ControlMessage =
        serde_json::from_slice(line).map_err(|_| ControlError::Malformed)?;
    if message.version() != CONTROL_VERSION {
        return Err(ControlError::WrongVersion);
    }
    Ok(message)
}
