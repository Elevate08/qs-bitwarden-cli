//! The helper's process: reads requests from the panel, one JSON object per
//! line, and writes replies the same way. See `lib.rs`.

use qs_bitwarden_vault::assuan;
use qs_bitwarden_vault::control::{self, Capture, Request, Source};
use qs_bitwarden_vault::store::{self, Store};
use qs_bitwarden_vault::{harden_process, self_test, totp};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
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
/// Detached commands at once (the lock the panel starts as it unloads); more
/// are dropped, as there is no reply to refuse them with.
const MAX_DETACHED: usize = 8;
const EXIT_REFUSED: i32 = 126;
/// `wtype` waits before the first key, so the shortcut that asked for the
/// typing is let go first, and between keys, so a page that moves focus on
/// Tab keeps up. The text comes on stdin; `-` reads it.
const WTYPE_ARGS: [&str; 5] = ["-s", "250", "-d", "12", "-"];
/// Stands in for a kept session key in the output the panel gets. Shaped
/// like a key (BitwardenModel.js SESSION_TOKEN_RE), so the panel's parsing
/// of `bw unlock`/`bw login` output is unchanged.
const HELD_SESSION: &str = "HELD-BY-QS-BITWARDEN-VAULT-HELPER-SESSION";

type Shared<T> = Arc<Mutex<T>>;

struct Helper {
    store: Shared<Store>,
    /// Run id -> process group, for `kill`.
    runs: Shared<HashMap<u64, u32>>,
    /// Detached commands still running.
    detached: Arc<AtomicUsize>,
    /// An auto-type in progress (at most one).
    typing: Arc<AtomicUsize>,
    /// The process group of the `wtype` typing, for `stop_typing`.
    typing_group: Shared<Option<u32>>,
    /// Reply lines; each is wiped once written, as any may carry a secret.
    out: Sender<Line>,
}

/// One reply line. Those that carry a secret are built with `json_line`,
/// not `json!`: the `Value` and `String` copies that makes are dropped
/// unwiped.
type Line = Zeroizing<String>;

/// One of the `MAX_DETACHED` places; gives it back when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn claim(count: &Arc<AtomicUsize>, max: usize) -> Option<Slot> {
        // By hand: `fetch_update` is deprecated and `try_update` is past the
        // crate's MSRV.
        let mut n = count.load(Ordering::Acquire);
        while n < max {
            match count.compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Slot(Arc::clone(count))),
                Err(current) => n = current,
            }
        }
        None
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
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

    let (out, lines) = mpsc::channel::<Line>();
    let writer = thread::spawn(move || {
        let mut stdout = std::io::stdout().lock();
        for line in lines {
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
        detached: Arc::default(),
        typing: Arc::default(),
        typing_group: Arc::default(),
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
    // outlive it with the session key in its environment. A `wtype` still
    // typing goes first: what it has not typed yet stays untyped. The runs
    // get SIGTERM before SIGKILL, so the scripts' traps stop the `bw` they
    // started in their own groups.
    // Signalled with the runs lock held: a run takes itself off the list
    // before it is reaped, so a group listed here is still ours.
    helper.stop_typing();
    let any = {
        let runs = helper.runs.lock().unwrap();
        for group in runs.values() {
            signal_group(*group, rustix::process::Signal::TERM);
        }
        !runs.is_empty()
    };
    if any {
        thread::sleep(std::time::Duration::from_millis(500));
        for group in helper.runs.lock().unwrap().values() {
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
    /// A reply with no secret in it.
    fn send(&self, message: Value) {
        let _ = self.out.send(Zeroizing::new(message.to_string()));
    }

    fn result(&self, q: u64, value: Option<Value>) {
        match value {
            Some(value) => {
                self.send(json!({ "type": "result", "q": q, "ok": true, "value": value }))
            }
            None => self.send(json!({ "type": "result", "q": q, "ok": false })),
        }
    }

    /// Sends a reply built with `json_line`; `None` is a failure.
    fn secret_result(&self, q: u64, line: Option<Line>) {
        match line {
            Some(line) => {
                let _ = self.out.send(line);
            }
            None => self.result(q, None),
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
                let runs = self.runs.lock().unwrap();
                if let Some(group) = runs.get(&id).copied() {
                    signal_group(group, rustix::process::Signal::TERM);
                    drop(runs);
                    stop_group(id, group, Arc::clone(&self.runs));
                }
            }
            Request::Forget { keep, .. } => {
                // The arm is dropped with the vault: a `wtype` still typing
                // its password stops here, however much is left.
                self.stop_typing();
                self.store.lock().unwrap().forget(&keep);
            }
            Request::HoldSession { name, .. } => {
                self.store.lock().unwrap().hold_session(name);
            }
            Request::ForgetSecret { name, .. } => self.store.lock().unwrap().forget_secret(&name),
            Request::ForgetItem { id, .. } => self.store.lock().unwrap().forget_item(&id),
            Request::Item { q, id, .. } => {
                let store = self.store.lock().unwrap();
                let line = store.item(&id).map(|full| secret_result_line(q, full));
                drop(store);
                self.secret_result(q, line);
            }
            Request::CopyPassword {
                q, id, clear_sec, ..
            } => {
                let password = self.field(&id, &["login", "password"]);
                self.copy(q, password, clear_sec);
            }
            Request::Field { q, id, field, .. } => {
                let value = store::SecretField::parse(&field)
                    .and_then(|field| self.store.lock().unwrap().item_secret(&id, &field));
                self.secret_result(q, value.map(|value| secret_result_line(q, &value)));
            }
            Request::CopyField {
                q,
                id,
                field,
                clear_sec,
                ..
            } => {
                let value = store::SecretField::parse(&field)
                    .and_then(|field| self.store.lock().unwrap().item_secret(&id, &field));
                self.copy(q, value, clear_sec);
            }
            Request::AutoType { q, id, .. } => self.auto_type(q, &id),
            Request::Totp { q, id, .. } => {
                let key = self.field(&id, &["login", "totp"]);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let code = key
                    .and_then(|key| totp::generate(&key, now))
                    .map(|(code, period)| (Zeroizing::new(code), period));
                self.secret_result(
                    q,
                    code.map(|(code, period)| totp_result_line(q, &code, period)),
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
        self.store.lock().unwrap().value_at(id, path)
    }

    /// Answers a copy request: the value goes to the clipboard and not into
    /// the reply. An absent or empty value is a failure.
    fn copy(&self, q: u64, value: Option<Zeroizing<String>>, clear_sec: u32) {
        let copied = value
            .filter(|value| !value.is_empty())
            .map(|value| copy_to_clipboard(value, clear_sec))
            .unwrap_or(false);
        self.result(q, copied.then_some(Value::Bool(true)));
    }

    /// Ends the auto-type in progress, if there is one: SIGKILL to its
    /// group, with the list locked and the entry taken, as `Kill` does for a
    /// run. The typing thread sees the entry gone and answers "stopped".
    fn stop_typing(&self) {
        let mut typing = self.typing_group.lock().unwrap();
        if let Some(group) = typing.take() {
            signal_group(group, rustix::process::Signal::KILL);
        }
    }

    /// Answers an auto-type once `wtype` has finished: `ok` only when it
    /// typed everything; otherwise the value says why not ("busy", "empty",
    /// "unsafe", "missing", "failed" or "stopped"). Neither value is in the
    /// reply.
    fn auto_type(&self, q: u64, id: &str) {
        let refuse = |reason: &str| {
            self.send(json!({ "type": "result", "q": q, "ok": false, "value": reason }))
        };
        let Some(slot) = Slot::claim(&self.typing, 1) else {
            return refuse("busy");
        };
        let username = self.field(id, &["login", "username"]);
        let password = self.field(id, &["login", "password"]);
        let text = match auto_type_text(
            username.as_ref().map(|u| u.as_str()),
            password.as_ref().map(|p| p.as_str()),
        ) {
            Ok(text) => text,
            Err(reason) => return refuse(reason),
        };
        let child = match spawn_wtype("wtype") {
            Ok(child) => child,
            Err(error) => return refuse(spawn_failure(&error)),
        };
        // Listed on this thread, the one that handles `forget`: no stop can
        // fall between the spawn and the entry.
        *self.typing_group.lock().unwrap() = Some(child.id());
        let group = Arc::clone(&self.typing_group);
        let out = self.out.clone();
        thread::spawn(move || {
            let typed = feed_and_wait(child, text, &group);
            drop(slot);
            let message = match typed {
                Typed::All => json!({ "type": "result", "q": q, "ok": true, "value": true }),
                Typed::Stopped => {
                    json!({ "type": "result", "q": q, "ok": false, "value": "stopped" })
                }
                Typed::Failed => {
                    json!({ "type": "result", "q": q, "ok": false, "value": "failed" })
                }
            };
            let _ = out.send(Zeroizing::new(message.to_string()));
        });
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
        // Read under the lock that resolves the injected values, so the run
        // holds exactly the vault whose key it was given.
        let generation;
        {
            let store = self.store.lock().unwrap();
            generation = store.generation();
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
            let Some(slot) = Slot::claim(&self.detached, MAX_DETACHED) else {
                return;
            };
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Ok(mut child) = command.spawn() {
                thread::spawn(move || {
                    let _ = child.wait();
                    drop(slot);
                });
            }
            return;
        }

        {
            let runs = self.runs.lock().unwrap();
            if runs.len() >= MAX_RUNS {
                return refuse("too many runs");
            }
            // A second run under a live id would take the first's place in
            // the list: it could no longer be killed, and its end would
            // remove the second's entry.
            if runs.contains_key(&id) {
                return refuse("run id in use");
            }
        }
        // A run never outlives the helper: if it dies (a crash, a SIGKILL),
        // the kernel sends each run SIGTERM, which the auth scripts' traps
        // pass on to their `bw`. Otherwise a `bw unlock` left waiting on the
        // password FIFO would read the next unlock's password.
        // The kernel ties the signal to the thread that forked, not the
        // process, so this exec must stay on the long-lived main loop thread:
        // spawning from a worker thread would send each run SIGTERM when that
        // thread exits.
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
        thread::spawn(move || run(id, child, stdin, capture, generation, store, runs, out));
    }
}

#[allow(clippy::too_many_arguments)]
fn run(
    id: u64,
    mut child: Child,
    stdin: Option<Zeroizing<String>>,
    capture: Capture,
    generation: u64,
    store: Shared<Store>,
    runs: Shared<HashMap<u64, u32>>,
    out: Sender<Line>,
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
    let truncated = stdout.truncated;
    let stdout = stdout.bytes;
    let err = stderr
        .and_then(|t| t.join().ok())
        .map(|drained| drained.bytes)
        .unwrap_or_default();
    // Leave the list before the child is reaped, not after: once reaped, its
    // process group id can be handed to another process, and a `kill` that
    // found the entry would signal that one. Waiting without reaping keeps
    // the id ours until the entry is gone; a `kill` signals with the list
    // locked, so it either lands before this or finds nothing.
    if let Some(pid) = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
        );
    }
    runs.lock().unwrap().remove(&id);
    let status = child.wait();
    let mut code = match status {
        Ok(status) => status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        Err(_) => 1,
    };

    // Output cut at the cap is not the command's output: a failure, and
    // nothing from it is kept.
    let text = if truncated {
        if code == 0 {
            code = 1;
        }
        Zeroizing::new(String::new())
    } else {
        Zeroizing::new(String::from_utf8_lossy(&stdout).into_owned())
    };
    let (forwarded, session, held) = keep(&store, generation, &capture, code, &text);
    let err = Zeroizing::new(String::from_utf8_lossy(&err).into_owned());
    let _ = out.send(exit_line(id, code, &forwarded, &err, session, held));
}

/// What the panel is told of a finished run, and whether the helper kept a
/// session key or a secret from it. Only a run that started under the
/// store's current generation may change the store: one that outlived a
/// lock, logout or account switch gets its output cleaned up the same way
/// but keeps nothing, or it would put the old vault back after the panel
/// has forgotten it.
fn keep(
    store: &Shared<Store>,
    generation: u64,
    capture: &Capture,
    code: i32,
    text: &Zeroizing<String>,
) -> (Zeroizing<String>, bool, bool) {
    let mut session = false;
    let mut held = false;
    let mut store = store.lock().unwrap();
    let current = store.generation() == generation;
    let forwarded: Zeroizing<String> = match capture {
        Capture::Plain => text.clone(),
        Capture::Session => match (code == 0).then(|| store::extract_session(text)).flatten() {
            Some(key) => {
                let shown = Zeroizing::new(text.replace(key.as_str(), HELD_SESSION));
                if current {
                    store.set_session(key);
                    session = true;
                }
                shown
            }
            // Prompts and errors still reach the panel's login detectors.
            None => text.clone(),
        },
        // Kept whatever the exit code: the FIDO2 legacy path prints the
        // password with a non-zero code. The panel judges the code.
        Capture::Secret(name) => {
            if current && !text.is_empty() {
                store.set_secret(name.clone(), text.clone());
                held = true;
            }
            Zeroizing::new(String::new())
        }
        // Only an answer the script finished (exit 0): a cancel or a crash
        // keeps nothing, and neither does an empty or malformed answer.
        Capture::Pinentry(name) => {
            if current && code == 0 {
                let answer = assuan::decode(text.trim_end_matches('\n'));
                if let Some(pin) = answer.filter(|pin| !pin.is_empty()) {
                    store.set_secret(name.clone(), pin);
                    held = true;
                }
            }
            Zeroizing::new(String::new())
        }
        Capture::Vault | Capture::VaultMerge => {
            let replace = *capture == Capture::Vault;
            let stripped = if code == 0 && current {
                store.strip_vault(text, replace)
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
    (forwarded, session, held)
}

/// A piece of a reply line (see `json_line`).
enum Part<'a> {
    /// JSON text as is: punctuation, a number, a boolean.
    Raw(&'a str),
    /// A string value, quoted and escaped.
    Str(&'a str),
}

/// A reply line built into a buffer sized up front: a secret in it is copied
/// once, and no reallocation leaves an unwiped copy behind.
fn json_line(parts: &[Part]) -> Line {
    let len = parts
        .iter()
        .map(|part| match part {
            Part::Raw(text) => text.len(),
            Part::Str(text) => escaped_len(text) + 2,
        })
        .sum();
    let mut line = Zeroizing::new(String::with_capacity(len));
    for part in parts {
        match part {
            Part::Raw(text) => line.push_str(text),
            Part::Str(text) => {
                line.push('"');
                escape_into(&mut line, text);
                line.push('"');
            }
        }
    }
    debug_assert_eq!(line.len(), len);
    line
}

/// `{"type":"result","q":<q>,"ok":true,"value":"<value>"}`: a reply whose
/// value is a secret (an item, a field).
fn secret_result_line(q: u64, value: &str) -> Line {
    let q = q.to_string();
    json_line(&[
        Part::Raw(r#"{"type":"result","q":"#),
        Part::Raw(&q),
        Part::Raw(r#","ok":true,"value":"#),
        Part::Str(value),
        Part::Raw("}"),
    ])
}

/// `{"type":"result","q":<q>,"ok":true,"value":{"code":"<code>","period":<period>}}`.
fn totp_result_line(q: u64, code: &str, period: u64) -> Line {
    let (q, period) = (q.to_string(), period.to_string());
    json_line(&[
        Part::Raw(r#"{"type":"result","q":"#),
        Part::Raw(&q),
        Part::Raw(r#","ok":true,"value":{"code":"#),
        Part::Str(code),
        Part::Raw(r#","period":"#),
        Part::Raw(&period),
        Part::Raw("}}"),
    ])
}

/// The `exit` reply of a run: its output and errors may hold a secret.
fn exit_line(id: u64, code: i32, out: &str, err: &str, session: bool, held: bool) -> Line {
    let (id, code) = (id.to_string(), code.to_string());
    let flag = |b: bool| if b { "true" } else { "false" };
    json_line(&[
        Part::Raw(r#"{"type":"exit","id":"#),
        Part::Raw(&id),
        Part::Raw(r#","code":"#),
        Part::Raw(&code),
        Part::Raw(r#","out":"#),
        Part::Str(out),
        Part::Raw(r#","err":"#),
        Part::Str(err),
        Part::Raw(r#","session":"#),
        Part::Raw(flag(session)),
        Part::Raw(r#","held":"#),
        Part::Raw(flag(held)),
        Part::Raw("}"),
    ])
}

/// Bytes `escape_into` writes for `value`.
fn escaped_len(value: &str) -> usize {
    value
        .chars()
        .map(|c| match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            c if c < ' ' => 6,
            c => c.len_utf8(),
        })
        .sum()
}

/// Appends `value` as the body of a JSON string, as serde_json writes it: `"`
/// and `\` escaped, the control characters with a short form as that, the
/// rest as `\u00XX`, and everything else (DEL and all of UTF-8) verbatim.
fn escape_into(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                out.push_str("\\u00");
                out.push(HEX[(c as usize) >> 4] as char);
                out.push(HEX[(c as usize) & 0xf] as char);
            }
            c => out.push(c),
        }
    }
}

#[derive(Default)]
struct Drained {
    bytes: Zeroizing<Vec<u8>>,
    /// Output past the cap was dropped.
    truncated: bool,
}

fn drain(mut pipe: impl Read, cap: usize) -> Drained {
    let mut kept = Zeroizing::new(Vec::new());
    let mut truncated = false;
    let mut chunk = Zeroizing::new([0_u8; 8192]);
    loop {
        match pipe.read(&mut chunk[..]) {
            Ok(0) | Err(_) => break,
            // Past the cap, keep reading so the child is never blocked, but
            // keep nothing more: a later small chunk would otherwise be
            // spliced onto the output with the dropped one missing.
            Ok(count) if truncated || kept.len() + count > cap => truncated = true,
            Ok(count) => grow(&mut kept, &chunk[..count]),
        }
    }
    Drained {
        bytes: kept,
        truncated,
    }
}

/// As Quickshell stops a Process: SIGTERM first, so a script's trap can stop
/// what it started in its own process group (the auth scripts' `set -m` bw),
/// then SIGKILL if the run is still there after a grace period.
const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

fn stop_group(id: u64, group: u32, runs: Shared<HashMap<u64, u32>>) {
    thread::spawn(move || {
        thread::sleep(STOP_GRACE);
        let runs = runs.lock().unwrap();
        if runs.get(&id) == Some(&group) {
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

/// What auto-type types: the username, Tab and the password, or the password
/// alone for a login without a username. `wtype` turns a newline into Enter
/// and a tab into Tab, and xkb maps backspace, delete and escape to their
/// keys, so a value holding any control character is refused rather than
/// typed: it would submit a half-typed form or move the password into
/// another field.
fn auto_type_text(
    username: Option<&str>,
    password: Option<&str>,
) -> Result<Zeroizing<String>, &'static str> {
    let password = password.filter(|p| !p.is_empty()).ok_or("empty")?;
    let username = username.unwrap_or("");
    if username
        .chars()
        .chain(password.chars())
        .any(char::is_control)
    {
        return Err("unsafe");
    }
    // Sized up front: a growing String would leave unwiped copies behind.
    let mut text = Zeroizing::new(String::with_capacity(username.len() + 1 + password.len()));
    if !username.is_empty() {
        text.push_str(username);
        text.push('\t');
    }
    text.push_str(password);
    Ok(text)
}

/// `program` (`wtype`) with the text to come on stdin. In its own process
/// group, so a run's kill never reaches it, and with a UTF-8 locale: under C,
/// `wtype` stops at the first character outside ASCII and still exits 0.
fn spawn_wtype(program: &str) -> std::io::Result<Child> {
    Command::new(program)
        .args(WTYPE_ARGS)
        .env("LC_ALL", "C.UTF-8")
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Why `wtype` did not start: not installed ("missing"), or anything else
/// ("failed": not executable, out of processes).
fn spawn_failure(error: &std::io::Error) -> &'static str {
    if error.kind() == std::io::ErrorKind::NotFound {
        "missing"
    } else {
        "failed"
    }
}

/// How an auto-type ended.
enum Typed {
    /// `wtype` took the whole text and exited 0.
    All,
    /// `stop_typing` ended it.
    Stopped,
    Failed,
}

/// Writes the text, closes stdin and waits. The group's entry is taken before
/// the child is reaped, as a run's is: once reaped, its id can be another
/// process's, and a stop that found the entry would signal that one.
fn feed_and_wait(mut child: Child, text: Zeroizing<String>, group: &Shared<Option<u32>>) -> Typed {
    let written = match child.stdin.take() {
        Some(mut pipe) => pipe.write_all(text.as_bytes()).is_ok(),
        None => false,
    };
    drop(text);
    if let Some(pid) = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
        );
    }
    let stopped = group.lock().unwrap().take().is_none();
    let status = child.wait();
    if written && status.map(|s| s.success()).unwrap_or(false) {
        Typed::All
    } else if stopped {
        Typed::Stopped
    } else {
        Typed::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_type_types_the_username_tab_and_password() {
        assert_eq!(
            auto_type_text(Some("me"), Some("hunter2"))
                .unwrap()
                .as_str(),
            "me\thunter2"
        );
        assert_eq!(
            auto_type_text(Some("j\u{f6}rg"), Some("p\u{e4}ss \u{1f511}"))
                .unwrap()
                .as_str(),
            "j\u{f6}rg\tp\u{e4}ss \u{1f511}"
        );
        // No username: the password alone, with no Tab before it.
        assert_eq!(
            auto_type_text(None, Some("hunter2")).unwrap().as_str(),
            "hunter2"
        );
        assert_eq!(
            auto_type_text(Some(""), Some("hunter2")).unwrap().as_str(),
            "hunter2"
        );
    }

    #[test]
    fn auto_type_refuses_what_it_cannot_type_as_written() {
        assert_eq!(auto_type_text(Some("me"), None).unwrap_err(), "empty");
        assert_eq!(auto_type_text(Some("me"), Some("")).unwrap_err(), "empty");
        for bad in [
            "a\nb", "a\tb", "a\rb", "a\u{8}b", "a\u{7f}b", "a\u{1b}b", "a\u{85}b",
        ] {
            assert_eq!(
                auto_type_text(Some("me"), Some(bad)).unwrap_err(),
                "unsafe",
                "{bad:?}"
            );
            assert_eq!(
                auto_type_text(Some(bad), Some("pw")).unwrap_err(),
                "unsafe",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn wtype_gets_no_secret_in_its_arguments() {
        assert_eq!(WTYPE_ARGS.last(), Some(&"-"));
        assert_eq!(WTYPE_ARGS.iter().filter(|a| **a == "-").count(), 1);
    }

    #[test]
    fn a_wtype_that_is_not_installed_is_missing_and_one_that_cannot_run_failed() {
        let absent = spawn_wtype("qsbw-no-such-wtype-for-this-test").unwrap_err();
        assert_eq!(spawn_failure(&absent), "missing");
        // A directory is found but cannot be executed.
        let dir = std::env::temp_dir();
        let unrunnable = spawn_wtype(dir.to_str().unwrap()).unwrap_err();
        assert_ne!(unrunnable.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(spawn_failure(&unrunnable), "failed");
    }

    const KEY: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH";

    fn shared() -> Shared<Store> {
        Arc::default()
    }

    fn text(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    #[test]
    fn a_session_captured_after_a_forget_is_not_kept() {
        let store = shared();
        let started = store.lock().unwrap().generation();
        store.lock().unwrap().forget(&[]);
        let (shown, session, _) = keep(&store, started, &Capture::Session, 0, &text(KEY));
        assert_eq!(shown.as_str(), HELD_SESSION);
        assert!(!session);
        assert!(store.lock().unwrap().session().is_none());

        let now = store.lock().unwrap().generation();
        let (_, session, _) = keep(&store, now, &Capture::Session, 0, &text(KEY));
        assert!(session);
        assert_eq!(store.lock().unwrap().session(), Some(KEY));
    }

    #[test]
    fn a_secret_captured_after_a_forget_is_not_kept() {
        let store = shared();
        let started = store.lock().unwrap().generation();
        store.lock().unwrap().forget(&[]);
        let capture = Capture::Secret("pw".to_owned());
        let (shown, _, held) = keep(&store, started, &capture, 0, &text("hunter2"));
        assert!(shown.is_empty());
        assert!(!held);
        assert!(store.lock().unwrap().secret("pw").is_none());
    }

    #[test]
    fn a_pinentry_answer_is_decoded_kept_and_never_forwarded() {
        let store = shared();
        let now = store.lock().unwrap().generation();
        let capture = Capture::Pinentry("pin".to_owned());
        let (shown, session, held) = keep(&store, now, &capture, 0, &text("a%25%0Ab+c\n"));
        assert!(shown.is_empty() && !session && held);
        assert_eq!(store.lock().unwrap().secret("pin"), Some("a%\nb+c"));

        // A cancel, an empty answer, malformed data and a crash keep
        // nothing, and do not replace what is held.
        for (code, answer) in [(1, "x"), (0, ""), (0, "%zz"), (4, "x")] {
            let (shown, _, held) = keep(&store, now, &capture, code, &text(answer));
            assert!(shown.is_empty() && !held, "{code} {answer}");
        }
        assert_eq!(store.lock().unwrap().secret("pin"), Some("a%\nb+c"));
        store.lock().unwrap().forget(&[]);
        let (_, _, held) = keep(&store, now, &capture, 0, &text("late"));
        assert!(!held);
        assert!(store.lock().unwrap().secret("pin").is_none());
    }

    #[test]
    fn a_vault_read_after_a_forget_is_not_kept_or_forwarded() {
        let store = shared();
        let started = store.lock().unwrap().generation();
        store.lock().unwrap().forget(&[]);
        let vault = r#"{"items":[{"id":"a","name":"n","login":{"password":"p"}}]}"#;
        let (shown, _, _) = keep(&store, started, &Capture::Vault, 0, &text(vault));
        assert!(shown.is_empty());
        assert!(store.lock().unwrap().item("a").is_none());

        // The save pipeline's marker still passes.
        let (shown, _, _) = keep(
            &store,
            started,
            &Capture::VaultMerge,
            0,
            &text(SAVED_UNSANITIZED),
        );
        assert_eq!(shown.as_str(), SAVED_UNSANITIZED);
    }

    #[test]
    fn a_forget_that_keeps_secrets_still_ends_the_runs_before_it() {
        let store = shared();
        let started = store.lock().unwrap().generation();
        store.lock().unwrap().forget(&["pw".to_owned()]);
        let (_, session, _) = keep(&store, started, &Capture::Session, 0, &text(KEY));
        assert!(!session);
    }

    #[test]
    fn detached_commands_are_capped_and_give_their_place_back() {
        let count: Arc<AtomicUsize> = Arc::default();
        let held: Vec<Slot> = (0..3)
            .map(|_| Slot::claim(&count, 3).expect("room"))
            .collect();
        assert!(Slot::claim(&count, 3).is_none());
        drop(held);
        assert!(Slot::claim(&count, 3).is_some());
    }

    /// Yields its chunks one read at a time.
    struct Chunks(std::vec::IntoIter<Vec<u8>>);

    impl Read for Chunks {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.next() {
                Some(chunk) => {
                    buf[..chunk.len()].copy_from_slice(&chunk);
                    Ok(chunk.len())
                }
                None => Ok(0),
            }
        }
    }

    #[test]
    fn output_past_the_cap_is_not_spliced_back_together() {
        let chunks = vec![vec![b'a'; 10], vec![b'b'; 100], vec![b'c'; 10]];
        let drained = drain(Chunks(chunks.into_iter()), 50);
        assert!(drained.truncated);
        assert_eq!(drained.bytes.as_slice(), &[b'a'; 10]);

        let fits = drain(Chunks(vec![vec![b'a'; 10]].into_iter()), 50);
        assert!(!fits.truncated);
        assert_eq!(fits.bytes.len(), 10);
    }

    /// Strings a reply may carry: quotes, backslashes, every control
    /// character, DEL, non-ASCII, emoji, `%`, and a large value.
    fn nasty_strings() -> Vec<String> {
        let mut all = vec![
            String::new(),
            "plain".to_owned(),
            "say \"hi\"".to_owned(),
            "C:\\path\\to".to_owned(),
            "\\\"\\".to_owned(),
            "tab\there\nnew\rline\u{8}\u{c}".to_owned(),
            "\u{7f}del\u{1b}esc\u{0}nul\u{1f}".to_owned(),
            "j\u{f6}rg \u{e9}t\u{e9} \u{4e2d}\u{6587}".to_owned(),
            "key \u{1f511} \u{1f1e9}\u{1f1ea}".to_owned(),
            "100% sure %25 %0A".to_owned(),
            "/slash and </script>".to_owned(),
            "\u{2028}\u{2029} separators".to_owned(),
            (0u8..0x20).map(char::from).collect(),
        ];
        all.push("x\"\\\n\u{1}\u{e9}\u{1f511}".repeat(10_000));
        assert!(all.last().unwrap().len() > 100 * 1024);
        all
    }

    #[test]
    fn the_escaper_writes_what_serde_json_writes() {
        for value in nasty_strings() {
            let expected = serde_json::to_string(&value).unwrap();
            let mut escaped = String::with_capacity(escaped_len(&value) + 2);
            escaped.push('"');
            escape_into(&mut escaped, &value);
            escaped.push('"');
            assert_eq!(escaped, expected, "{value:?}");
            assert_eq!(escaped.len(), escaped_len(&value) + 2, "{value:?}");
            let back: String = serde_json::from_str(&escaped).unwrap();
            assert_eq!(back, value);
        }
    }

    #[test]
    fn secret_reply_lines_parse_as_the_json_macro_would_write_them() {
        for value in nasty_strings() {
            let line = secret_result_line(7, &value);
            assert_eq!(line.capacity(), line.len(), "{value:?}");
            let parsed: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(
                parsed,
                json!({ "type": "result", "q": 7, "ok": true, "value": value })
            );

            let line = exit_line(u64::MAX, -3, &value, &value, true, false);
            assert_eq!(line.capacity(), line.len(), "{value:?}");
            let parsed: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(
                parsed,
                json!({ "type": "exit", "id": u64::MAX, "code": -3, "out": value, "err": value, "session": true, "held": false })
            );
        }
        let line = totp_result_line(1, "123456", 30);
        assert_eq!(line.capacity(), line.len());
        assert_eq!(
            line.as_str(),
            r#"{"type":"result","q":1,"ok":true,"value":{"code":"123456","period":30}}"#
        );
        let line = exit_line(2, 0, "", "", false, true);
        assert_eq!(
            line.as_str(),
            r#"{"type":"exit","id":2,"code":0,"out":"","err":"","session":false,"held":true}"#
        );
    }
}
