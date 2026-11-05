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
        Self::start_with(true)
    }

    /// `wtype`: whether a stand-in is on PATH. Without one PATH holds only
    /// the stand-ins and `sh` and `cat`, so the real `wtype` cannot be found
    /// either: no test ever types into a real window.
    fn start_with(wtype: bool) -> Self {
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
        // A stand-in wtype that records its stdin, arguments and locale, and
        // exits with the code in `wtype-exit` (0 when there is none), a second
        // late when `wtype-slow` exists, writing `typed-done` once it has
        // waited the second out.
        std::fs::write(
            dir.join("wtype"),
            "#!/bin/sh\nd=\"$(dirname \"$0\")\"\ncat > \"$d/typed\"\necho \"$*\" > \"$d/typed-args\"\necho \"$LC_ALL\" > \"$d/typed-locale\"\n[ -f \"$d/wtype-slow\" ] && sleep 1 && : > \"$d/typed-done\"\nexit \"$(cat \"$d/wtype-exit\" 2>/dev/null || echo 0)\"\n",
        )
        .unwrap();
        for name in ["wl-copy", "timeout", "wtype"] {
            Command::new("chmod")
                .arg("+x")
                .arg(dir.join(name))
                .status()
                .unwrap();
        }
        let path = if wtype {
            format!(
                "{}:{}",
                dir.display(),
                std::env::var("PATH").unwrap_or_default()
            )
        } else {
            std::fs::remove_file(dir.join("wtype")).unwrap();
            let tools = dir.join("tools");
            std::fs::create_dir_all(&tools).unwrap();
            for tool in ["sh", "cat", "dirname"] {
                let found = Command::new("sh")
                    .args(["-c", &format!("command -v {tool}")])
                    .output()
                    .unwrap();
                let found = String::from_utf8(found.stdout).unwrap();
                std::os::unix::fs::symlink(found.trim(), tools.join(tool)).unwrap();
            }
            format!("{}:{}", dir.display(), tools.display())
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_qs-bitwarden-vault"))
            .env("PATH", path)
            // Should a real wtype ever run, it has no display to type into.
            .env("WAYLAND_DISPLAY", "qsbw-test-no-display")
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
fn a_pinentry_answer_is_decoded_and_injected_by_name() {
    let mut helper = Helper::start();
    // What the panel's pinentry script prints: the `D` data, still encoded.
    let kept = helper.exec(
        1,
        "printf '%s\\n' 'p%25w%0Ad+'",
        json!({ "capture": "pinentry:pin" }),
    );
    assert_eq!(
        (kept["out"].as_str(), kept["held"].as_bool()),
        (Some(""), Some(true))
    );
    let run = helper.exec(
        2,
        "printf '%s' \"$PW\"",
        json!({ "inject": { "PW": "secret:pin" } }),
    );
    assert_eq!(run["out"], "p%w\nd+");
    // A cancel (exit 1) keeps nothing and tells the panel nothing.
    let cancelled = helper.exec(
        3,
        "printf 'x'; exit 1",
        json!({ "capture": "pinentry:other" }),
    );
    assert_eq!(
        (
            cancelled["out"].as_str(),
            cancelled["held"].as_bool(),
            cancelled["code"].as_i64()
        ),
        (Some(""), Some(false), Some(1))
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

fn wait_for_file(path: &std::path::Path, what: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            return text;
        }
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn auto_type_hands_the_login_to_wtype_and_not_the_panel() {
    let mut helper = Helper::start();
    let vault = json!({ "sshCapability": "unconfirmed", "sshKeys": [], "items": [
        { "id": "a", "type": 1, "name": "Bank", "login": { "username": "me", "password": "hunter2" } },
        { "id": "p", "type": 1, "name": "PIN only", "login": { "password": "4242" } },
        { "id": "n", "type": 1, "name": "Broken", "login": { "username": "me", "password": "two\nlines" } },
        { "id": "e", "type": 1, "name": "Empty", "login": { "username": "me" } }
    ]})
    .to_string();
    helper.exec(
        1,
        &format!("cat <<'EOF'\n{vault}\nEOF"),
        json!({ "capture": "vault" }),
    );

    let typed = helper.query(20, json!({ "type": "autoType", "id": "a" }));
    assert_eq!(
        typed,
        json!({ "type": "result", "q": 20, "ok": true, "value": true })
    );
    // The reply comes after wtype has exited, so its record is complete.
    assert_eq!(
        std::fs::read_to_string(helper.dir.join("typed")).unwrap(),
        "me\thunter2"
    );
    assert_eq!(
        std::fs::read_to_string(helper.dir.join("typed-args"))
            .unwrap()
            .trim(),
        "-s 250 -d 12 -"
    );
    assert_eq!(
        std::fs::read_to_string(helper.dir.join("typed-locale"))
            .unwrap()
            .trim(),
        "C.UTF-8"
    );

    // No username: the password alone.
    assert_eq!(
        helper.query(21, json!({ "type": "autoType", "id": "p" }))["ok"],
        true
    );
    assert_eq!(
        std::fs::read_to_string(helper.dir.join("typed")).unwrap(),
        "4242"
    );

    // Refused before wtype starts: nothing new is typed.
    std::fs::remove_file(helper.dir.join("typed")).unwrap();
    for (q, id, reason) in [
        (22, "n", "unsafe"),
        (23, "e", "empty"),
        (24, "nope", "empty"),
    ] {
        assert_eq!(
            helper.query(q, json!({ "type": "autoType", "id": id })),
            json!({ "type": "result", "q": q, "ok": false, "value": reason })
        );
    }
    assert!(!helper.dir.join("typed").exists());

    // One at a time: a second request while wtype runs is refused.
    std::fs::write(helper.dir.join("wtype-slow"), "").unwrap();
    helper.send(json!({ "type": "autoType", "v": 1, "q": 30, "id": "a" }));
    wait_for_file(&helper.dir.join("typed"), "wtype never ran");
    assert_eq!(
        helper.query(31, json!({ "type": "autoType", "id": "a" })),
        json!({ "type": "result", "q": 31, "ok": false, "value": "busy" })
    );
    assert_eq!(helper.reply("q", 30)["ok"], true);
    std::fs::remove_file(helper.dir.join("wtype-slow")).unwrap();

    // wtype failing (no virtual keyboard, say) is a failure, not a success.
    std::fs::write(helper.dir.join("wtype-exit"), "1").unwrap();
    assert_eq!(
        helper.query(25, json!({ "type": "autoType", "id": "a" })),
        json!({ "type": "result", "q": 25, "ok": false, "value": "failed" })
    );
    wait_for_file(&helper.dir.join("typed"), "wtype never ran");

    // A forget takes the item, and with it anything to type.
    helper.send(json!({ "type": "forget", "v": 1 }));
    assert_eq!(
        helper.query(26, json!({ "type": "autoType", "id": "a" }))["value"],
        "empty"
    );
}

/// Starts a helper holding one login and a slow `wtype` typing it: the
/// `typed` record is there, the second's sleep has a second to go.
fn typing_slowly(q: u64) -> Helper {
    let mut helper = Helper::start();
    let vault = json!({ "sshCapability": "unconfirmed", "sshKeys": [], "items": [
        { "id": "a", "type": 1, "name": "Bank", "login": { "username": "me", "password": "hunter2" } }
    ]})
    .to_string();
    helper.exec(
        1,
        &format!("cat <<'EOF'\n{vault}\nEOF"),
        json!({ "capture": "vault" }),
    );
    std::fs::write(helper.dir.join("wtype-slow"), "").unwrap();
    helper.send(json!({ "type": "autoType", "v": 1, "q": q, "id": "a" }));
    wait_for_file(&helper.dir.join("typed"), "wtype never ran");
    helper
}

#[test]
fn a_forget_stops_an_auto_type_in_progress() {
    let mut helper = typing_slowly(30);
    let asked = Instant::now();
    helper.send(json!({ "type": "forget", "v": 1 }));
    assert_eq!(
        helper.reply("q", 30),
        json!({ "type": "result", "q": 30, "ok": false, "value": "stopped" })
    );
    assert!(
        asked.elapsed() < Duration::from_millis(500),
        "the reply waited for wtype: {:?}",
        asked.elapsed()
    );
    // The stand-in never gets to the end of its second.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!helper.dir.join("typed-done").exists(), "wtype kept typing");

    // The next auto-type is not "busy", and a forget with nothing typing is
    // a plain forget.
    helper.send(json!({ "type": "forget", "v": 1, "keep": [] }));
    assert_eq!(
        helper.query(31, json!({ "type": "autoType", "id": "a" }))["value"],
        "empty"
    );
}

#[test]
fn a_shutdown_stops_an_auto_type_in_progress() {
    let mut helper = typing_slowly(40);
    let asked = Instant::now();
    helper.send(json!({ "type": "shutdown", "v": 1 }));
    let status = helper.child.wait().unwrap();
    assert!(status.success(), "{status}");
    assert!(
        asked.elapsed() < Duration::from_millis(500),
        "the helper waited for wtype: {:?}",
        asked.elapsed()
    );
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        !helper.dir.join("typed-done").exists(),
        "wtype outlived the helper"
    );
}

#[test]
fn auto_type_without_wtype_says_so() {
    let mut helper = Helper::start_with(false);
    let vault = json!({ "sshCapability": "unconfirmed", "sshKeys": [], "items": [
        { "id": "a", "type": 1, "name": "Bank", "login": { "username": "me", "password": "hunter2" } }
    ]})
    .to_string();
    let read = helper.exec(
        1,
        &format!("cat <<'EOF'\n{vault}\nEOF"),
        json!({ "capture": "vault" }),
    );
    assert_eq!(read["code"], 0, "{read}");
    assert_eq!(
        helper.query(20, json!({ "type": "autoType", "id": "a" })),
        json!({ "type": "result", "q": 20, "ok": false, "value": "missing" })
    );
}

#[test]
fn one_secret_is_served_or_copied_by_name() {
    let mut helper = Helper::start();
    let vault = json!({ "sshCapability": "unconfirmed", "sshKeys": [], "items": [
        { "id": "a", "type": 1, "name": "Bank", "notes": "recovery words",
          "login": { "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP" },
          "fields": [{ "name": "pin", "value": "4242", "type": 1 }] },
        { "id": "c", "type": 3, "name": "Card", "card": { "number": "4111111111111111", "code": "123" } }
    ] })
    .to_string();
    let script = format!("cat <<'EOF'\n{vault}\nEOF");
    let read = helper.exec(1, &script, json!({ "capture": "vault" }));
    assert!(!read["out"].as_str().unwrap().contains("4242"));

    let field = |helper: &mut Helper, q: u64, id: &str, name: &str| {
        helper.query(q, json!({ "type": "field", "id": id, "field": name }))
    };
    assert_eq!(
        field(&mut helper, 10, "a", "notes")["value"],
        "recovery words"
    );
    assert_eq!(
        field(&mut helper, 11, "a", "customField:0")["value"],
        "4242"
    );
    assert_eq!(
        field(&mut helper, 12, "c", "cardNumber")["value"],
        "4111111111111111"
    );
    for (q, id, name) in [
        (13, "a", "totp"),
        (14, "a", "login.password"),
        (15, "a", "customField:7"),
        (16, "a", "cardCode"),
        (17, "nope", "password"),
    ] {
        assert_eq!(field(&mut helper, q, id, name)["ok"], false, "{name}");
    }

    let copy = helper.query(
        20,
        json!({ "type": "copyField", "id": "c", "field": "cardCode", "clearSec": 30 }),
    );
    assert_eq!(copy["ok"], true);
    assert!(
        !copy.to_string().contains("123"),
        "a copy's reply holds no value: {copy}"
    );
    let clip = helper.dir.join("clipboard");
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::read_to_string(&clip).unwrap_or_default() != "123" {
        assert!(Instant::now() < deadline, "the code never reached wl-copy");
        std::thread::sleep(Duration::from_millis(20));
    }
    let args = std::fs::read_to_string(helper.dir.join("clipboard-args")).unwrap();
    assert_eq!(args.trim(), "--foreground --sensitive");
    for (q, id, name) in [
        (21, "c", "totp"),
        (22, "c", "ssn"),
        (23, "nope", "cardCode"),
    ] {
        let reply = helper.query(
            q,
            json!({ "type": "copyField", "id": id, "field": name, "clearSec": 0 }),
        );
        assert_eq!(reply["ok"], false, "{name}");
    }
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
fn a_reused_run_id_is_refused_and_the_first_run_stays_killable() {
    let mut helper = Helper::start();
    helper.send(json!({ "type": "exec", "v": 1, "id": 21, "argv": ["sh", "-c", "sleep 30"] }));
    std::thread::sleep(Duration::from_millis(200));
    let again = helper.exec(21, "echo second", json!({}));
    assert_eq!(again["code"], 126);
    assert_eq!(again["err"], "run id in use");
    // The first run still has its kill handle and its entry.
    helper.send(json!({ "type": "kill", "v": 1, "id": 21 }));
    assert_eq!(helper.reply("id", 21)["code"], 143);
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
