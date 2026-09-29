//! The helper as the panel drives it: the real binary, over stdin/stdout.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/==";

struct Helper {
    child: Child,
    stdin: ChildStdin,
    lines: std::sync::mpsc::Receiver<Value>,
    dir: PathBuf,
}

impl Helper {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "qsbw-vault-test-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // A stand-in wl-copy (and timeout) that records what it was given.
        let fake = dir.join("wl-copy");
        std::fs::write(&fake, "#!/bin/sh\ncat > \"$(dirname \"$0\")/clipboard\"\necho \"$*\" > \"$(dirname \"$0\")/clipboard-args\"\n").unwrap();
        std::fs::write(dir.join("timeout"), "#!/bin/sh\nshift\nexec \"$@\"\n").unwrap();
        for name in ["wl-copy", "timeout"] {
            Command::new("chmod")
                .arg("+x")
                .arg(dir.join(name))
                .status()
                .unwrap();
        }
        let path = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_qs-bitwarden-vault"))
            .env("PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout: ChildStdout = child.stdout.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(serde_json::from_str(&line).unwrap()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
            dir,
        }
    }

    fn send(&mut self, message: Value) {
        writeln!(self.stdin, "{message}").unwrap();
    }

    fn next(&self) -> Value {
        self.lines
            .recv_timeout(Duration::from_secs(10))
            .expect("a reply")
    }

    /// The reply for exec `id` or query `q`, skipping others.
    fn reply(&self, key: &str, id: u64) -> Value {
        loop {
            let message = self.next();
            if message[key] == id {
                return message;
            }
        }
    }

    fn exec(&mut self, id: u64, script: &str, extra: Value) -> Value {
        let mut request = json!({ "type": "exec", "v": 1, "id": id, "argv": ["sh", "-c", script] });
        for (k, v) in extra.as_object().unwrap() {
            request[k] = v.clone();
        }
        self.send(request);
        self.reply("id", id)
    }

    fn query(&mut self, q: u64, mut request: Value) -> Value {
        request["v"] = json!(1);
        request["q"] = json!(q);
        self.send(request);
        self.reply("q", q)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn vault_read() -> String {
    json!({
        "sshCapability": "unconfirmed",
        "items": [
            { "id": "a", "type": 1, "name": "Bank", "notes": "recovery words",
              "login": { "username": "me", "password": "hunter2",
                         "totp": "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8" } }
        ],
        "sshKeys": []
    })
    .to_string()
}

#[test]
fn handshake_and_strictness() {
    let mut helper = Helper::start();
    helper.send(json!({ "type": "hello", "v": 1 }));
    assert_eq!(helper.next(), json!({ "type": "ready", "protocol": 1 }));
    helper.send(json!({ "type": "hello", "v": 9 }));
    assert_eq!(helper.next()["type"], "error");
    writeln!(helper.stdin, "not json").unwrap();
    assert_eq!(helper.next()["type"], "error");
}

#[test]
fn the_session_key_goes_to_runs_and_never_back() {
    let mut helper = Helper::start();
    let captured = helper.exec(
        1,
        &format!("echo 'export BW_SESSION=\"{TOKEN}\"'"),
        json!({ "capture": "session" }),
    );
    let shown = "export BW_SESSION=\"HELD-BY-QS-BITWARDEN-VAULT-HELPER-SESSION\"\n";
    assert_eq!(
        (
            captured["code"].as_i64(),
            captured["out"].as_str(),
            captured["session"].as_bool()
        ),
        (Some(0), Some(shown), Some(true))
    );
    let prompt = helper.exec(
        9,
        "echo '? Two-step login code:'",
        json!({ "capture": "session" }),
    );
    assert_eq!(
        (prompt["out"].as_str(), prompt["session"].as_bool()),
        (Some("? Two-step login code:\n"), Some(false))
    );

    let check = format!("[ \"$BW_SESSION\" = '{TOKEN}' ] && echo injected");
    let run = helper.exec(2, &check, json!({ "inject": { "BW_SESSION": "session" } }));
    assert_eq!(run["out"], "injected\n");
    let bare = helper.exec(3, "echo \"${BW_SESSION:-none}\"", json!({}));
    assert_eq!(bare["out"], "none\n", "only runs that ask get the key");

    // Env from the panel, including removals.
    let env = helper.exec(
        4,
        "echo \"$A-${HOME:-gone}\"",
        json!({ "env": { "A": "x", "HOME": null } }),
    );
    assert_eq!(env["out"], "x-gone\n");

    helper.send(json!({ "type": "holdSession", "v": 1, "name": "lock1" }));
    helper.send(json!({ "type": "forget", "v": 1, "keep": ["lock1"] }));
    let after = helper.exec(5, &check, json!({ "inject": { "BW_SESSION": "session" } }));
    assert_eq!(after["out"], "", "forget drops the key");
    let kept = helper.exec(
        6,
        &check,
        json!({ "inject": { "BW_SESSION": "secret:lock1" } }),
    );
    assert_eq!(kept["out"], "injected\n", "a held copy outlives it");
}

#[test]
fn a_held_secret_is_injected_by_name() {
    let mut helper = Helper::start();
    let kept = helper.exec(
        1,
        "printf 'master pw'; exit 40",
        json!({ "capture": "secret:master" }),
    );
    assert_eq!(
        (
            kept["out"].as_str(),
            kept["held"].as_bool(),
            kept["code"].as_i64()
        ),
        (Some(""), Some(true), Some(40))
    );
    let run = helper.exec(
        2,
        "printf '%s' \"$PW\"",
        json!({ "inject": { "PW": "secret:master" } }),
    );
    assert_eq!(run["out"], "master pw");
    helper.send(json!({ "type": "forgetSecret", "v": 1, "name": "master" }));
    assert_eq!(
        helper.exec(
            3,
            "printf '%s' \"$PW\"",
            json!({ "inject": { "PW": "secret:master" } })
        )["out"],
        ""
    );
}

#[test]
fn a_vault_read_reaches_the_panel_without_secrets() {
    let mut helper = Helper::start();
    let script = format!("cat <<'EOF'\n{}\nEOF", vault_read());
    let read = helper.exec(1, &script, json!({ "capture": "vault" }));
    let out = read["out"].as_str().unwrap();
    assert!(
        out.contains("\"Bank\"")
            && !out.contains("hunter2")
            && !out.contains("recovery")
            && !out.contains("GEZDG"),
        "{out}"
    );

    let item = helper.query(10, json!({ "type": "item", "id": "a" }));
    assert!(item["value"].as_str().unwrap().contains("hunter2"));
    assert_eq!(
        helper.query(11, json!({ "type": "item", "id": "nope" }))["ok"],
        false
    );

    let found = helper.query(12, json!({ "type": "search", "query": "RECOVERY" }));
    assert_eq!(found["value"], json!(["a"]));

    let code = helper.query(13, json!({ "type": "totp", "id": "a" }));
    assert_eq!(code["ok"], true);
    assert_eq!(code["value"]["code"].as_str().unwrap().len(), 8);

    let copy = helper.query(
        14,
        json!({ "type": "copyPassword", "id": "a", "clearSec": 30 }),
    );
    assert_eq!(copy["ok"], true);
    let clip = helper.dir.join("clipboard");
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::read_to_string(&clip).unwrap_or_default() != "hunter2" {
        assert!(
            Instant::now() < deadline,
            "the password never reached wl-copy"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let args = std::fs::read_to_string(helper.dir.join("clipboard-args")).unwrap();
    assert_eq!(args.trim(), "--foreground --sensitive");

    // A failed or unparseable read forwards nothing.
    assert_eq!(
        helper.exec(
            2,
            "printf '{\"items\":[{\"id\":\"a\",\"login\":{\"password\":\"x'",
            json!({ "capture": "vault" })
        )["out"],
        ""
    );
    assert_eq!(
        helper.exec(
            3,
            "printf '__QSBW_SAVED_UNSANITIZED__'",
            json!({ "capture": "vaultMerge" })
        )["out"],
        "__QSBW_SAVED_UNSANITIZED__"
    );
}

#[test]
fn runs_can_be_killed_and_stdin_is_delivered() {
    let mut helper = Helper::start();
    helper.send(
        json!({ "type": "exec", "v": 1, "id": 7, "argv": ["sh", "-c", "sleep 30; echo late"] }),
    );
    std::thread::sleep(Duration::from_millis(200));
    helper.send(json!({ "type": "kill", "v": 1, "id": 7 }));
    let killed = helper.reply("id", 7);
    assert_eq!(
        (killed["code"].as_i64(), killed["out"].as_str()),
        (Some(143), Some("")),
        "stopped with SIGTERM"
    );

    // A run that ignores SIGTERM is killed after the grace period.
    helper.send(
        json!({ "type": "exec", "v": 1, "id": 10, "argv": ["sh", "-c", "trap '' TERM; sleep 30"] }),
    );
    std::thread::sleep(Duration::from_millis(200));
    helper.send(json!({ "type": "kill", "v": 1, "id": 10 }));
    assert_eq!(helper.reply("id", 10)["code"], 137);

    let echoed = helper.exec(8, "cat", json!({ "stdin": "payload" }));
    assert_eq!(echoed["out"], "payload");
    let missing = helper.exec(9, "true", json!({ "capture": "bogus" }));
    assert_eq!(missing["code"], 126);
}

#[test]
fn runs_do_not_outlive_a_crashed_helper() {
    let mut helper = Helper::start();
    let mark = helper.dir.join("stopped");
    let script = format!(
        "trap 'echo stopped > {}; exit 0' TERM; while :; do sleep 0.05; done",
        mark.display()
    );
    helper.send(json!({ "type": "exec", "v": 1, "id": 1, "argv": ["sh", "-c", script] }));
    std::thread::sleep(Duration::from_millis(300));
    // SIGKILL: no cleanup code of the helper's runs.
    helper.child.kill().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !mark.exists() {
        assert!(Instant::now() < deadline, "the run outlived the helper");
        std::thread::sleep(Duration::from_millis(50));
    }
}
