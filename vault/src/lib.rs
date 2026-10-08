//! Holds the unlocked vault outside the Quickshell panel, so a shell crash
//! cannot write the session key or the decrypted items into a core dump.
//!
//! The panel starts this as a child and talks to it only on stdin/stdout:
//! no socket, no FIFO, no port. It runs the panel's `bw` commands with the
//! session key added to their environment, keeps each item's secrets, and
//! answers for one item, one password copy, one TOTP code or one search at a
//! time. See docs/vault-helper.md.

pub mod assuan;
pub mod control;
pub mod store;
pub mod totp;

/// No core file, and no ptrace or /proc/<pid>/mem access from other
/// processes, before any secret is read. Children inherit the core limit.
pub fn harden_process() -> Result<(), &'static str> {
    use rustix::process::{self, DumpableBehavior, Resource, Rlimit};
    process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| "could not turn core dumps off")?;
    process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|_| "could not make the process undumpable")
}

/// What `--self-test` checks: the hardening took, and the parts that decide
/// what reaches the panel still behave.
pub fn self_test() -> Result<(), &'static str> {
    use rustix::process::{self, DumpableBehavior, Resource};
    let core = process::getrlimit(Resource::Core);
    if core.current != Some(0) || core.maximum != Some(0) {
        return Err("core dumps are not off");
    }
    if !matches!(
        process::dumpable_behavior(),
        Ok(DumpableBehavior::NotDumpable)
    ) {
        return Err("the process is dumpable");
    }
    let rfc = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
    if totp::generate(rfc, 59).map(|(code, _)| code).as_deref() != Some("94287082") {
        return Err("TOTP does not match RFC 6238");
    }
    let mut vault = store::Store::default();
    let read = r#"{"items":[{"id":"x","name":"n","notes":"secret-a","login":{"password":"secret-b","totp":"secret-c"}}],"sshKeys":[]}"#;
    let out = vault
        .strip_vault(read, true)
        .ok_or("a vault read was not understood")?;
    if out.contains("secret-") || vault.item("x").is_none() {
        return Err("a secret would reach the panel");
    }
    Ok(())
}
