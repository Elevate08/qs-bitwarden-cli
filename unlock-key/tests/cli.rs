//! `qs-bitwarden-unlock-key` driven as the panel's pipelines drive it: secrets
//! in the environment, envelope on stdin, result on stdout, exit status as the
//! verdict. Key material is fixed text in `argon2`/`fido2-assert` formats, so
//! neither tool is needed.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_qs-bitwarden-unlock-key");
const ACCOUNT: [&str; 4] = [
    "--account-id",
    "user-1",
    "--server",
    "https://vault.bitwarden.com",
];
const MASTER_KDF: [&str; 8] = [
    "--salt",
    "bWFzdGVyLXNhbHQtMDAwMDA=",
    "--m",
    "65536",
    "--t",
    "3",
    "--p",
    "1",
];
const PIN_KDF: [&str; 8] = [
    "--salt",
    "cGluLXNhbHQtMDAwMDAwMDA=",
    "--m",
    "65536",
    "--t",
    "3",
    "--p",
    "1",
];
const CRED: &str = "Y3JlZGVudGlhbC1pZA==";
const FIDO_SALT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

/// `argon2 -r` prints 64 hex digits.
fn hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// `fido2-assert` prints the hmac-secret as base64.
fn hmac(byte: u8) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(&[byte; 32])
}

fn run(args: &[&str], env: &[(&str, &str)], stdin: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A command that refuses its flags exits before reading stdin; a broken
    // pipe then is expected, not a failure.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

fn ok(args: &[&str], env: &[(&str, &str)], stdin: &[u8]) -> Vec<u8> {
    let output = run(args, env, stdin);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn code(args: &[&str], env: &[(&str, &str)], stdin: &[u8]) -> i32 {
    run(args, env, stdin).status.code().unwrap()
}

fn with(parts: &[&[&str]]) -> Vec<String> {
    parts
        .iter()
        .flat_map(|p| p.iter().map(|s| s.to_string()))
        .collect()
}

fn refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

fn created() -> Vec<u8> {
    let args = with(&[&["create"], &ACCOUNT, &MASTER_KDF]);
    ok(
        &refs(&args),
        &[
            ("QSBW_UNLOCK_PASSWORD", "correct horse"),
            ("QSBW_UNLOCK_NEW_KEY", &hex(1)),
        ],
        b"",
    )
}

fn with_all_methods() -> Vec<u8> {
    let master = hex(1);
    let envelope = created();
    let args = with(&[
        &["add"],
        &ACCOUNT,
        &["--auth", "master", "--method", "pin"],
        &PIN_KDF,
    ]);
    let envelope = ok(
        &refs(&args),
        &[
            ("QSBW_UNLOCK_KEY", &master),
            ("QSBW_UNLOCK_NEW_KEY", &hex(2)),
        ],
        &envelope,
    );
    let args = with(&[
        &["add"],
        &ACCOUNT,
        &["--auth", "master", "--method", "fingerprint"],
    ]);
    let envelope = ok(&refs(&args), &[("QSBW_UNLOCK_KEY", &master)], &envelope);
    let args = with(&[
        &["add"],
        &ACCOUNT,
        &["--auth", "master", "--method", "fido"],
        &[
            "--cred",
            CRED,
            "--rp",
            "pam://host",
            "--fido-salt",
            FIDO_SALT,
        ],
    ]);
    ok(
        &refs(&args),
        &[
            ("QSBW_UNLOCK_KEY", &master),
            ("QSBW_UNLOCK_NEW_KEY", &hmac(3)),
        ],
        &envelope,
    )
}

fn open(envelope: &[u8], via: &[&str], key: Option<&str>) -> Output {
    let args = with(&[&["open"], &ACCOUNT, via]);
    let env: Vec<(&str, &str)> = key.map(|k| ("QSBW_UNLOCK_KEY", k)).into_iter().collect();
    run(&refs(&args), &env, envelope)
}

#[test]
fn every_method_yields_the_password_and_nothing_else() {
    let envelope = with_all_methods();
    let fido = hmac(3);
    let pin = hex(2);
    let master = hex(1);
    for (via, key) in [
        (vec!["--via", "master"], Some(master.as_str())),
        (vec!["--via", "pin"], Some(pin.as_str())),
        (vec!["--via", "fingerprint"], None),
        (vec!["--via", "fido", "--cred", CRED], Some(fido.as_str())),
    ] {
        let output = open(&envelope, &via, key);
        assert_eq!(output.status.code(), Some(0), "{via:?}");
        // Exactly the password: no newline, nothing else, so the shell can
        // hand it to `bw` byte for byte.
        assert_eq!(output.stdout, b"correct horse", "{via:?}");
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn the_stored_envelope_never_contains_the_password() {
    let envelope = with_all_methods();
    let text = String::from_utf8(envelope).unwrap();
    assert!(!text.contains("correct horse"));
    assert!(!text.contains(&hex(1)) && !text.contains(&hex(2)) && !text.contains(&hmac(3)));
}

#[test]
fn inspect_shows_what_the_panel_needs_and_no_secret() {
    let envelope = with_all_methods();
    let summary: serde_json::Value =
        serde_json::from_slice(&ok(&["inspect"], &[], &envelope)).unwrap();
    assert_eq!(summary["account"]["id"], "user-1");
    assert_eq!(summary["master"]["salt"], "bWFzdGVyLXNhbHQtMDAwMDA=");
    assert_eq!(summary["pin"]["m"], 65536);
    assert_eq!(summary["fingerprint"], true);
    assert_eq!(summary["fido"][0]["cred"], CRED);
    assert_eq!(summary["fido"][0]["rp"], "pam://host");
    assert_eq!(summary["stale"], false);
    let text = summary.to_string();
    for field in ["\"c\"", "\"n\"", "\"k\""] {
        assert!(!text.contains(field), "summary leaked {field}");
    }
}

#[test]
fn exit_codes_say_what_went_wrong() {
    let envelope = with_all_methods();
    // 3: a wrong key.
    assert_eq!(
        open(&envelope, &["--via", "master"], Some(&hex(9)))
            .status
            .code(),
        Some(3)
    );
    assert_eq!(
        open(
            &envelope,
            &["--via", "fido", "--cred", CRED],
            Some(&hmac(9))
        )
        .status
        .code(),
        Some(3)
    );
    // 4: not an envelope, or key material in the wrong format.
    assert_eq!(
        open(b"not json", &["--via", "master"], Some(&hex(1)))
            .status
            .code(),
        Some(4)
    );
    assert_eq!(
        open(&envelope, &["--via", "master"], Some("zz"))
            .status
            .code(),
        Some(4)
    );
    // 5: outside the limits.
    let weak = with(&[
        &["create"],
        &ACCOUNT,
        &[
            "--salt",
            "bWFzdGVyLXNhbHQtMDAwMDA=",
            "--m",
            "1024",
            "--t",
            "3",
            "--p",
            "1",
        ],
    ]);
    assert_eq!(
        code(
            &refs(&weak),
            &[
                ("QSBW_UNLOCK_PASSWORD", "x"),
                ("QSBW_UNLOCK_NEW_KEY", &hex(1))
            ],
            b""
        ),
        5
    );
    // 6: another account.
    let other = [
        "open",
        "--account-id",
        "user-2",
        "--server",
        "https://vault.bitwarden.com",
        "--via",
        "master",
    ];
    assert_eq!(code(&other, &[("QSBW_UNLOCK_KEY", &hex(1))], &envelope), 6);
    // 7: a method that is not there.
    let bare = created();
    assert_eq!(
        open(&bare, &["--via", "pin"], Some(&hex(2))).status.code(),
        Some(7)
    );
    assert_eq!(code(&["remove", "--method", "fingerprint"], &[], &bare), 7);
}

#[test]
fn usage_errors_are_refused_before_anything_runs() {
    let envelope = created();
    for args in [
        vec!["frobnicate"],
        vec!["inspect", "--unexpected", "1"],
        vec!["open", "--account-id", "user-1", "--account-id", "user-1"],
        vec!["open", "--via"],
        vec!["remove", "--method", "master"],
        // A secret offered as an argument is not an option this binary has.
        vec!["create", "--password", "hunter2"],
    ] {
        assert_eq!(code(&args, &[], &envelope), 2, "{args:?}");
    }
    // A required secret missing from the environment.
    let args = with(&[&["create"], &ACCOUNT, &MASTER_KDF]);
    assert_eq!(
        code(&refs(&args), &[("QSBW_UNLOCK_NEW_KEY", &hex(1))], b""),
        2
    );
    assert_eq!(code(&[], &[], b""), 2);
}

#[test]
fn a_changed_password_rotates_without_losing_a_method() {
    let envelope = with_all_methods();
    let stale = ok(&["mark-stale"], &[], &envelope);
    let summary: serde_json::Value =
        serde_json::from_slice(&ok(&["inspect"], &[], &stale)).unwrap();
    assert_eq!(summary["stale"], true);

    // The PIN reached the DEK; the new password came from the user.
    let args = with(&[&["rotate"], &ACCOUNT, &["--auth", "pin"], &MASTER_KDF]);
    let rotated = ok(
        &refs(&args),
        &[
            ("QSBW_UNLOCK_KEY", &hex(2)),
            ("QSBW_UNLOCK_PASSWORD", "battery staple"),
            ("QSBW_UNLOCK_NEW_KEY", &hex(4)),
        ],
        &stale,
    );
    let fido = hmac(3);
    for (via, key) in [
        (vec!["--via", "master"], Some(hex(4))),
        (vec!["--via", "pin"], Some(hex(2))),
        (vec!["--via", "fingerprint"], None),
        (vec!["--via", "fido", "--cred", CRED], Some(fido.clone())),
    ] {
        let output = open(&rotated, &via, key.as_deref());
        assert_eq!(output.stdout, b"battery staple", "{via:?}");
    }
    assert_eq!(
        open(&rotated, &["--via", "master"], Some(&hex(1)))
            .status
            .code(),
        Some(3)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&ok(&["inspect"], &[], &rotated)).unwrap();
    assert_eq!(summary["stale"], false);
}

#[test]
fn removing_every_method_keeps_the_master_wrap() {
    let mut envelope = with_all_methods();
    for args in [
        vec!["remove", "--method", "pin"],
        vec!["remove", "--method", "fingerprint"],
        vec!["remove", "--method", "fido", "--cred", CRED],
    ] {
        envelope = ok(&args, &[], &envelope);
    }
    let summary: serde_json::Value =
        serde_json::from_slice(&ok(&["inspect"], &[], &envelope)).unwrap();
    assert!(summary.get("pin").is_none());
    assert_eq!(summary["fingerprint"], false);
    assert_eq!(summary["fido"].as_array().unwrap().len(), 0);
    assert_eq!(
        open(&envelope, &["--via", "master"], Some(&hex(1))).stdout,
        b"correct horse"
    );
}

#[test]
fn a_wrong_password_cannot_authorize_a_new_method() {
    let envelope = created();
    let args = with(&[
        &["add"],
        &ACCOUNT,
        &["--auth", "master", "--method", "fingerprint"],
    ]);
    let output = run(&refs(&args), &[("QSBW_UNLOCK_KEY", &hex(9))], &envelope);
    assert_eq!(output.status.code(), Some(3));
    assert!(
        output.stdout.is_empty(),
        "nothing may be written on a refusal"
    );
}

#[test]
fn version_and_self_test_answer_without_input() {
    let version = ok(&["--version"], &[], b"");
    assert!(String::from_utf8(version)
        .unwrap()
        .starts_with("qs-bitwarden-unlock-key "));
    let output = run(&["--self-test"], &[], b"");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
