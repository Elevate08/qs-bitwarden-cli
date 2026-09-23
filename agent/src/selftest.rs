//! Launch-time smoke test the panel runs before trusting this binary: it
//! executes here, its crypto and parsers work, and the kernel supports the
//! process hardening. Signing is not tested: that needs a private key, which
//! would mean an RNG in the dependency tree or an embedded key (the test suite
//! covers it). Touches no filesystem, socket or runtime directory.

use crate::control::{parse_control_line, ControlError, ControlMessage, MAX_CONTROL_LINE};
use crate::protocol::{self, AgentRequest, MAX_FRAME_LEN};
use ssh_encoding::Encode;
use ssh_key::{HashAlg, PublicKey};

/// A disposable public key with no private counterpart anywhere.
const FIXTURE_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDgSTquIEW1Ui0iRAQcZZAjS1OIA/D6Q+Arq/JfoVLkh";

/// One named check and whether it held.
struct Check {
    name: &'static str,
    ok: bool,
}

pub fn run() -> i32 {
    let checks = vec![
        Check {
            name: "process hardening (RLIMIT_CORE=0, PR_SET_DUMPABLE=0)",
            ok: hardening_available(),
        },
        Check {
            name: "public key parsing and SHA256 fingerprint",
            ok: public_key_math(),
        },
        Check {
            name: "agent frame encode and decode",
            ok: frame_round_trip(),
        },
        Check {
            name: "oversized frames rejected before allocation",
            ok: frame_bounds(),
        },
        Check {
            name: "control protocol v1 accepted, other versions refused",
            ok: control_versions(),
        },
    ];

    let failed = checks.iter().filter(|check| !check.ok).count();
    for check in &checks {
        println!("{} {}", if check.ok { "ok  " } else { "FAIL" }, check.name);
    }
    if failed == 0 {
        println!("ok: {} checks passed", checks.len());
        println!("note: signing is exercised by the test suite, not here -- see selftest.rs");
        0
    } else {
        println!("FAILED: {failed} of {} checks", checks.len());
        1
    }
}

/// Applies the hardening and reads it back; the panel should know before
/// handing over keys if core-dump and ptrace protections are unavailable.
fn hardening_available() -> bool {
    if crate::lifecycle::harden_process().is_err() {
        return false;
    }
    let core = rustix::process::getrlimit(rustix::process::Resource::Core);
    let dumpable = rustix::process::dumpable_behavior();
    core.current == Some(0)
        && matches!(dumpable, Ok(rustix::process::DumpableBehavior::NotDumpable))
}

/// Parse a public key and fingerprint it, using the signing path's backend.
fn public_key_math() -> bool {
    let Ok(key) = PublicKey::from_openssh(FIXTURE_PUBLIC_KEY) else {
        return false;
    };
    if !matches!(key.algorithm(), ssh_key::Algorithm::Ed25519) {
        return false;
    }
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    // A fingerprint is base64 of a SHA-256 digest, so its shape is fixed.
    fingerprint.starts_with("SHA256:") && fingerprint.len() > 20 && key.to_bytes().is_ok()
}

/// A sign request built here, decoded by the real decoder, and an identities
/// response encoded by the real encoder.
fn frame_round_trip() -> bool {
    let Ok(key) = PublicKey::from_openssh(FIXTURE_PUBLIC_KEY) else {
        return false;
    };
    let Ok(blob) = key.to_bytes() else {
        return false;
    };

    let mut body = Vec::new();
    if 13_u8.encode(&mut body).is_err()
        || blob.as_slice().encode(&mut body).is_err()
        || b"self-test".as_slice().encode(&mut body).is_err()
        || 0_u32.encode(&mut body).is_err()
    {
        return false;
    }
    let mut frame = match u32::try_from(body.len()) {
        Ok(length) => length.to_be_bytes().to_vec(),
        Err(_) => return false,
    };
    frame.extend_from_slice(&body);

    let decoded = matches!(
        protocol::decode_request(&frame),
        Some(AgentRequest::Sign { .. })
    );
    let listed = protocol::identities_response(&[(blob.as_slice(), "self-test")]);
    decoded && listed.len() > 4
}

/// A claimed length over the ceiling must be refused before allocating.
fn frame_bounds() -> bool {
    let mut oversized = u32::try_from(MAX_FRAME_LEN + 1)
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    oversized.push(11);
    let empty = [0_u8, 0, 0, 0];
    protocol::decode_request(&oversized).is_none() && protocol::decode_request(&empty).is_none()
}

/// Versioned, so a stale bundled binary fails clearly after an update.
fn control_versions() -> bool {
    let hello = parse_control_line(br#"{"v":1,"type":"hello"}"#);
    let wrong_version = parse_control_line(br#"{"v":2,"type":"hello"}"#);
    let unknown = parse_control_line(br#"{"v":1,"type":"exec"}"#);
    let mut overlong = vec![b'{'; MAX_CONTROL_LINE + 1];
    overlong.push(b'}');

    matches!(hello, Ok(ControlMessage::Hello { .. }))
        && matches!(wrong_version, Err(ControlError::WrongVersion))
        && matches!(unknown, Err(ControlError::Malformed))
        && matches!(parse_control_line(&overlong), Err(ControlError::TooLong))
}
