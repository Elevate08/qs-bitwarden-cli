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
    out: Sender<String>,
}

/// One of the `MAX_DETACHED` places; gives it back when dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn claim(count: &Arc<AtomicUsize>, max: usize) -> Option<Slot> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| Slot(Arc::clone(count)))
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
        detached: Arc::default(),
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
    // Signalled with the runs lock held: a run takes itself off the list
    // before it is reaped, so a group listed here is still ours.
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
                let runs = self.runs.lock().unwrap();
                if let Some(group) = runs.get(&id).copied() {
                    signal_group(group, rustix::process::Signal::TERM);
                    drop(runs);
                    stop_group(id, group, Arc::clone(&self.runs));
                }
            }
            Request::Forget { keep, .. } => self.store.lock().unwrap().forget(&keep),
            Request::HoldSession { name, .. } => {
                self.store.lock().unwrap().hold_session(name);
            }
            Request::ForgetSecret { name, .. } => self.store.lock().unwrap().forget_secret(&name),
            Request::ForgetItem { id, .. } => self.store.lock().unwrap().forget_item(&id),
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
    let err = String::from_utf8_lossy(&err).into_owned();
    let message = json!({ "type": "exit", "id": id, "code": code, "out": forwarded.as_str(), "err": err, "session": session, "held": held });
    let _ = out.send(message.to_string());
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

fn wipe(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => map.values_mut().for_each(wipe),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
