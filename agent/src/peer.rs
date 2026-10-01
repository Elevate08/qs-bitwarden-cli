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

    /// Whether `current`, a fresh capture for the same connection, is still
    /// the process admitted at accept. A client can `exec` another program
    /// after connecting, which keeps its PID and start time but changes the
    /// executable, so everything is compared and a failed capture counts as a
    /// change.
    pub fn is_unchanged(&self, current: Result<Self, PeerError>) -> bool {
        current.is_ok_and(|current| current == *self)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn peer(pid: u32, start: u64, exe: &str) -> PeerContext {
        PeerContext::new(1000, pid, start, exe).unwrap()
    }

    #[test]
    fn unchanged_requires_every_field_to_match() {
        let admitted = peer(42, 100, "/usr/bin/ssh");
        assert!(admitted.is_unchanged(Ok(peer(42, 100, "/usr/bin/ssh"))));
        // exec: same process, different program.
        assert!(!admitted.is_unchanged(Ok(peer(42, 100, "/tmp/other"))));
        // PID reuse: same path, different process.
        assert!(!admitted.is_unchanged(Ok(peer(42, 101, "/usr/bin/ssh"))));
        assert!(!admitted.is_unchanged(Ok(peer(43, 100, "/usr/bin/ssh"))));
        let mut other_user = peer(42, 100, "/usr/bin/ssh");
        other_user.uid = 0;
        assert!(!admitted.is_unchanged(Ok(other_user)));
    }

    #[test]
    fn unchanged_fails_closed_when_the_capture_fails() {
        let admitted = peer(42, 100, "/usr/bin/ssh");
        assert!(!admitted.is_unchanged(Err(PeerError::Unavailable)));
        assert!(!admitted.is_unchanged(Err(PeerError::Malformed)));
    }

    #[test]
    fn a_live_process_matches_itself_and_an_exec_is_noticed() {
        let uid = rustix::process::getuid().as_raw();
        let own = PeerContext::capture(uid, std::process::id()).unwrap();
        assert!(own.is_unchanged(PeerContext::capture(uid, own.pid)));

        let mut child = Command::new("/bin/sh")
            .args(["-c", "read line; exec sleep 30"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        // Wait for the child to be the shell: a capture taken while it is
        // still the forked test binary is a different program.
        let shell = std::fs::canonicalize("/bin/sh").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let before = loop {
            let now = PeerContext::capture(uid, pid).unwrap();
            if now.executable == shell {
                break now;
            }
            assert!(Instant::now() < deadline, "child never became the shell");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(before.is_unchanged(PeerContext::capture(uid, pid)));
        child.stdin.as_mut().unwrap().write_all(b"go\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while PeerContext::capture(uid, pid).is_ok_and(|now| now.executable == before.executable) {
            assert!(Instant::now() < deadline, "child never exec'd");
            std::thread::sleep(Duration::from_millis(10));
        }
        let after = PeerContext::capture(uid, pid);
        assert_eq!(after.as_ref().unwrap().pid, before.pid);
        assert_eq!(
            after.as_ref().unwrap().start_time_ticks,
            before.start_time_ticks
        );
        assert!(!before.is_unchanged(after));
        child.kill().unwrap();
        child.wait().unwrap();
        // Once it is gone the capture fails, which also fails closed.
        assert!(!before.is_unchanged(PeerContext::capture(uid, pid)));
    }
}
