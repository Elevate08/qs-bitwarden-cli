//! Verified peer snapshots used to scope approvals and grants.

use std::path::{Path, PathBuf};

/// Sanitized proc-snapshot failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerError {
    Unavailable,
    Malformed,
}

/// Process context from kernel peer/proc data. UID is the admission boundary;
/// PID, start time and executable path are prompt context and grant scope,
/// not identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerContext {
    pub uid: u32,
    pub pid: u32,
    pub start_time_ticks: u64,
    pub executable: PathBuf,
}

impl PeerContext {
    pub fn new(
        uid: u32,
        pid: u32,
        start_time_ticks: u64,
        executable: impl AsRef<Path>,
    ) -> Option<Self> {
        let executable = executable.as_ref();
        if pid == 0 || start_time_ticks == 0 || !executable.is_absolute() {
            return None;
        }
        Some(Self {
            uid,
            pid,
            start_time_ticks,
            executable: executable.to_owned(),
        })
    }

    /// Whether a grant taken for `self` covers `other`: same user and same
    /// program, not same process (Git runs a new `ssh-keygen` per commit). Any
    /// process at that path benefits during the window, which a same-UID
    /// attacker could achieve anyway; the UID check is never relaxed.
    pub fn shares_grant_scope(&self, other: &Self) -> bool {
        self.uid == other.uid && self.executable == other.executable
    }

    /// Capture grant-scoping context for a PID supplied by `SO_PEERCRED`.
    pub fn capture(uid: u32, pid: u32) -> Result<Self, PeerError> {
        if pid == 0 {
            return Err(PeerError::Malformed);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| PeerError::Unavailable)?;
        let close = stat.rfind(')').ok_or(PeerError::Malformed)?;
        let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
        // The remainder begins at field 3; starttime is field 22.
        let start_time_ticks = fields
            .get(19)
            .ok_or(PeerError::Malformed)?
            .parse()
            .map_err(|_| PeerError::Malformed)?;
        let executable =
            std::fs::read_link(format!("/proc/{pid}/exe")).map_err(|_| PeerError::Unavailable)?;
        Self::new(uid, pid, start_time_ticks, executable).ok_or(PeerError::Malformed)
    }
}
