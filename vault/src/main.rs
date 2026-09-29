//! The helper's process: reads requests from the panel, one JSON object per
//! line, and writes replies the same way. See `lib.rs`.

use qs_bitwarden_vault::control::{self, Capture, Request, Source};
use qs_bitwarden_vault::store::{self, Store};
use qs_bitwarden_vault::{harden_process, self_test, totp};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const NAME: &str = "qs-bitwarden-vault";
/// Runs at once; more are refused (exit 126), as a bounded queue would be.
const MAX_RUNS: usize = 32;
/// Past the panel's own caps (16 MiB for the list), so they decide first.
const MAX_STDOUT: usize = 24 * 1024 * 1024;
const MAX_STDERR: usize = 64 * 1024;
/// What the save pipeline prints when the save worked but its output could
/// not be sanitized (BitwardenModel.js SAVED_UNSANITIZED_MARKER).
const SAVED_UNSANITIZED: &str = "__QSBW_SAVED_UNSANITIZED__";
const EXIT_REFUSED: i32 = 126;
/// Stands in for a kept session key in the output the panel gets. Shaped
/// like a key (BitwardenModel.js SESSION_TOKEN_RE), so the panel's parsing
/// of `bw unlock`/`bw login` output is unchanged.
const HELD_SESSION: &str = "HELD-BY-QS-BITWARDEN-VAULT-HELPER-SESSION";

type Shared<T> = Arc<Mutex<T>>;

struct Helper {
    store: Shared<Store>,
    /// Run id -> process group, for `kill`.
    runs: Shared<HashMap<u64, u32>>,
    out: Sender<String>,
}

fn main() {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("--version") => {
            println!(
                "{NAME} {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                control::PROTOCOL
            );
            return;
        }
        Some("--self-test") => {
            let result = harden_process().and_then(|_| self_test());
            match result {
                Ok(()) => println!("{NAME}: self-test passed"),
                Err(why) => {
                    eprintln!("{NAME}: self-test failed: {why}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(_) => {
            eprintln!("usage: {NAME} [--version | --self-test]");
            std::process::exit(2);
        }
        None => {}
    }
    if harden_process().is_err() {
        eprintln!("{NAME}: could not turn core dumps off; refusing to run");
        std::process::exit(1);
    }

    let (out, lines) = mpsc::channel::<String>();
    let writer = thread::spawn(move || {
        let mut stdout = std::io::stdout().lock();
        for line in lines {
            let line = Zeroizing::new(line);
            if stdout
                .write_all(line.as_bytes())
                .and_then(|_| stdout.write_all(b"\n"))
                .and_then(|_| stdout.flush())
                .is_err()
            {
                break;
            }
        }
    });

    let helper = Helper {
        store: Arc::default(),
        runs: Arc::default(),
        out,
    };
    let mut input = BufReader::new(std::io::stdin().lock());
    loop {
        let Some(line) = read_line(&mut input) else {
            break;
        };
        let Ok(text) = std::str::from_utf8(&line) else {
            helper.send(json!({ "type": "error", "reason": "not UTF-8" }));
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        match control::parse(text) {
            Ok(Request::Shutdown { .. }) => break,
            Ok(request) => helper.handle(request),
            Err(reason) => helper.send(json!({ "type": "error", "reason": reason })),
        }
    }

    // The panel is gone or asked us to stop: nothing it started should
    // outlive it with the session key in its environment. SIGTERM first, so
    // the scripts' traps stop the `bw` they started in their own groups.
    let groups: Vec<u32> = helper
        .runs
        .lock()
        .unwrap()
        .drain()
        .map(|(_, group)| group)
        .collect();
    for group in &groups {
        signal_group(*group, rustix::process::Signal::TERM);
    }
    if !groups.is_empty() {
        thread::sleep(std::time::Duration::from_millis(500));
        for group in &groups {
            signal_group(*group, rustix::process::Signal::KILL);
        }
    }
    helper.store.lock().unwrap().forget(&[]);
    drop(helper);
    let _ = writer.join();
}

/// One line, bounded; an overlong line is read to its end and dropped.
fn read_line(input: &mut impl BufRead) -> Option<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::new());
    let mut overlong = false;
    loop {
        let buffer = input.fill_buf().ok()?;
        if buffer.is_empty() {
            return (!line.is_empty() && !overlong).then_some(line);
        }
        let (chunk, done) = match buffer.iter().position(|b| *b == b'\n') {
            Some(at) => (&buffer[..at], Some(at + 1)),
            None => (buffer, None),
        };
        if !overlong {
            if line.len() + chunk.len() > control::MAX_LINE {
                overlong = true;
                line.clear();
            } else {
                grow(&mut line, chunk);
            }
        }
        let used = done.unwrap_or(buffer.len());
        input.consume(used);
        if done.is_some() {
            if overlong {
                line.clear();
                overlong = false;
                continue;
            }
            return Some(line);
        }
    }
}

/// Appends without letting `Vec` reallocate in place, which would free the
/// old buffer unwiped.
fn grow(buffer: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let needed = buffer.len() + bytes.len();
    if needed > buffer.capacity() {
        let mut next = Zeroizing::new(Vec::with_capacity(needed.max(buffer.capacity() * 2)));
        next.extend_from_slice(buffer);
        *buffer = next;
    }
    buffer.extend_from_slice(bytes);
}

impl Helper {
    fn send(&self, message: Value) {
        let _ = self.out.send(message.to_string());
    }

    fn result(&self, q: u64, value: Option<Value>) {
        match value {
            Some(value) => {
                self.send(json!({ "type": "result", "q": q, "ok": true, "value": value }))
            }
            None => self.send(json!({ "type": "result", "q": q, "ok": false })),
        }
    }

    fn handle(&self, request: Request) {
        match request {
            Request::Hello { .. } => {
                self.send(json!({ "type": "ready", "protocol": control::PROTOCOL }))
            }
            Request::Exec {
                id,
                argv,
                env,
                inject,
                capture,
                stdin,
                detach,
                ..
            } => self.exec(id, argv, env, inject, capture.as_deref(), stdin, detach),
            Request::Kill { id, .. } => {
                let group = self.runs.lock().unwrap().get(&id).copied();
                if let Some(group) = group {
                    stop_group(id, group, Arc::clone(&self.runs));
                }
            }
            Request::Forget { keep, .. } => self.store.lock().unwrap().forget(&keep),
            Request::HoldSession { name, .. } => {
                self.store.lock().unwrap().hold_session(name);
            }
            Request::ForgetSecret { name, .. } => self.store.lock().unwrap().forget_secret(&name),
            Request::Item { q, id, .. } => {
                let store = self.store.lock().unwrap();
                let item = store.item(&id).map(|full| Value::String(full.to_owned()));
                drop(store);
                self.result(q, item);
            }
            Request::CopyPassword {
                q, id, clear_sec, ..
            } => {
                let password = self.field(&id, &["login", "password"]);
                let copied = password
                    .filter(|p| !p.is_empty())
                    .map(|p| copy_to_clipboard(p, clear_sec))
                    .unwrap_or(false);
                self.result(q, copied.then_some(Value::Bool(true)));
            }
            Request::Totp { q, id, .. } => {
                let key = self.field(&id, &["login", "totp"]);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let code = key.and_then(|key| totp::generate(&key, now));
                self.result(
                    q,
                    code.map(|(code, period)| json!({ "code": code, "period": period })),
                );
            }
            Request::Search { q, query, .. } => {
                let store = self.store.lock().unwrap();
                let ids: Vec<Value> = store
                    .search(&query)
                    .into_iter()
                    .map(|id| Value::String(id.to_owned()))
                    .collect();
                drop(store);
                self.result(q, Some(Value::Array(ids)));
            }
            Request::Shutdown { .. } => {}
        }
    }

    /// One string field of a held item, e.g. `login.password`.
    fn field(&self, id: &str, path: &[&str]) -> Option<Zeroizing<String>> {
        let store = self.store.lock().unwrap();
        let full = store.item(id)?;
        let mut item: Value = serde_json::from_str(full).ok()?;
        drop(store);
        let mut node = &item;
        for key in path {
            node = node.get(*key)?;
        }
        let value = node.as_str().map(|s| Zeroizing::new(s.to_owned()));
        wipe(&mut item);
        value
    }

    #[allow(clippy::too_many_arguments)]
    fn exec(
        &self,
        id: u64,
        argv: Vec<String>,
        env: BTreeMap<String, Option<String>>,
        inject: BTreeMap<String, String>,
        capture: Option<&str>,
        stdin: Option<String>,
        detach: bool,
    ) {
        let stdin = stdin.map(Zeroizing::new);
        let env: Vec<(String, Option<Zeroizing<String>>)> = env
            .into_iter()
            .map(|(k, v)| (k, v.map(Zeroizing::new)))
            .collect();
        let refuse = |reason: &str| {
            self.send(
                json!({ "type": "exit", "id": id, "code": EXIT_REFUSED, "out": "", "err": reason }),
            )
        };
        let Some(capture) = Capture::parse(capture) else {
            return refuse("unknown capture");
        };
        if argv.is_empty()
            || env.iter().any(|(k, _)| !control::valid_env_name(k))
            || inject.keys().any(|k| !control::valid_env_name(k))
        {
            return refuse("malformed command");
        }

        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]).process_group(0);
        for (name, value) in &env {
            match value {
                Some(value) => command.env(name, value.as_str()),
                None => command.env_remove(name),
            };
        }
        {
            let store = self.store.lock().unwrap();
            for (name, source) in &inject {
                let value = match control::parse_source(source) {
                    Some(Source::Session) => store.session(),
                    Some(Source::Secret(secret)) => store.secret(secret),
                    None => return refuse("unknown inject source"),
                };
                // Absent: left unset, and `bw` answers "locked" as it would.
                if let Some(value) = value {
                    command.env(name, value);
                }
            }
        }

        if detach {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Ok(mut child) = command.spawn() {
                thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            return;
        }

        if self.runs.lock().unwrap().len() >= MAX_RUNS {
            return refuse("too many runs");
        }
        // A run never outlives the helper: if it dies (a crash, a SIGKILL),
        // the kernel sends each run SIGTERM, which the auth scripts' traps
        // pass on to their `bw`. Otherwise a `bw unlock` left waiting on the
        // password FIFO would read the next unlock's password.
        // SAFETY: only async-signal-safe work between fork and exec (prctl).
        unsafe {
            command.pre_exec(|| {
                rustix::process::set_parent_process_death_signal(Some(
                    rustix::process::Signal::TERM,
                ))
                .map_err(std::io::Error::from)
            });
        }
        command.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                return self.send(json!({ "type": "exit", "id": id, "code": 127, "out": "", "err": "could not start" }))
            }
        };
        self.runs.lock().unwrap().insert(id, child.id());

        let store = Arc::clone(&self.store);
        let runs = Arc::clone(&self.runs);
        let out = self.out.clone();
        thread::spawn(move || run(id, child, stdin, capture, store, runs, out));
    }
}

fn run(
    id: u64,
    mut child: Child,
    stdin: Option<Zeroizing<String>>,
    capture: Capture,
    store: Shared<Store>,
    runs: Shared<HashMap<u64, u32>>,
    out: Sender<String>,
) {
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        thread::spawn(move || {
            let _ = pipe.write_all(input.as_bytes());
        });
    }
    let stderr = child
        .stderr
        .take()
        .map(|pipe| thread::spawn(move || drain(pipe, MAX_STDERR)));
    let stdout = child
        .stdout
        .take()
        .map(|pipe| drain(pipe, MAX_STDOUT))
        .unwrap_or_default();
    let err = stderr.and_then(|t| t.join().ok()).unwrap_or_default();
    let status = child.wait();
    runs.lock().unwrap().remove(&id);
    let code = match status {
        Ok(status) => status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        Err(_) => 1,
    };

    let text = Zeroizing::new(String::from_utf8_lossy(&stdout).into_owned());
    let mut session = false;
    let mut held = false;
    let forwarded: Zeroizing<String> = match &capture {
        Capture::Plain => text.clone(),
        Capture::Session => match (code == 0).then(|| store::extract_session(&text)).flatten() {
            Some(key) => {
                let shown = Zeroizing::new(text.replace(key.as_str(), HELD_SESSION));
                store.lock().unwrap().set_session(key);
                session = true;
                shown
            }
            // Prompts and errors still reach the panel's login detectors.
            None => text.clone(),
        },
        // Kept whatever the exit code: the FIDO2 legacy path prints the
        // password with a non-zero code. The panel judges the code.
        Capture::Secret(name) => {
            if !text.is_empty() {
                store.lock().unwrap().set_secret(name.clone(), text.clone());
                held = true;
            }
            Zeroizing::new(String::new())
        }
        Capture::Vault | Capture::VaultMerge => {
            let replace = capture == Capture::Vault;
            let stripped = if code == 0 {
                store.lock().unwrap().strip_vault(&text, replace)
            } else {
                None
            };
            // Anything else could be a truncated read full of secrets: only
            // the save pipeline's marker passes.
            stripped.unwrap_or_else(|| {
                Zeroizing::new(if text.trim() == SAVED_UNSANITIZED {
                    SAVED_UNSANITIZED.to_owned()
                } else {
                    String::new()
                })
            })
        }
    };
    let err = String::from_utf8_lossy(&err).into_owned();
    let message = json!({ "type": "exit", "id": id, "code": code, "out": forwarded.as_str(), "err": err, "session": session, "held": held });
    let _ = out.send(message.to_string());
}

fn drain(mut pipe: impl Read, cap: usize) -> Zeroizing<Vec<u8>> {
    let mut kept = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; 8192]);
    loop {
        match pipe.read(&mut chunk[..]) {
            Ok(0) | Err(_) => break,
            // Past the cap, keep reading so the child is never blocked.
            Ok(count) if kept.len() + count > cap => {}
            Ok(count) => grow(&mut kept, &chunk[..count]),
        }
    }
    kept
}

/// As Quickshell stops a Process: SIGTERM first, so a script's trap can stop
/// what it started in its own process group (the auth scripts' `set -m` bw),
/// then SIGKILL if the run is still there after a grace period.
const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

fn stop_group(id: u64, group: u32, runs: Shared<HashMap<u64, u32>>) {
    signal_group(group, rustix::process::Signal::TERM);
    thread::spawn(move || {
        thread::sleep(STOP_GRACE);
        if runs.lock().unwrap().get(&id) == Some(&group) {
            signal_group(group, rustix::process::Signal::KILL);
        }
    });
}

fn signal_group(group: u32, signal: rustix::process::Signal) {
    use rustix::process::{kill_process_group, Pid};
    if let Some(pid) = i32::try_from(group).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(pid, signal);
    }
}

/// `timeout Ns wl-copy --foreground --sensitive` with the value on stdin: the
/// copy clears itself after N seconds, even if the shell restarts, and a
/// newer copy ends it early. In its own process group, so a run's kill
/// never reaches it.
fn copy_to_clipboard(value: Zeroizing<String>, clear_sec: u32) -> bool {
    let mut command = if clear_sec > 0 {
        let mut c = Command::new("timeout");
        c.arg(format!("{clear_sec}s"))
            .args(["wl-copy", "--foreground", "--sensitive"]);
        c
    } else {
        let mut c = Command::new("wl-copy");
        c.arg("--sensitive");
        c
    };
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let Some(mut pipe) = child.stdin.take() else {
        return false;
    };
    let written = pipe.write_all(value.as_bytes()).is_ok();
    drop(pipe);
    thread::spawn(move || {
        let _ = child.wait();
    });
    written
}

fn wipe(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => map.values_mut().for_each(wipe),
        _ => {}
    }
}
