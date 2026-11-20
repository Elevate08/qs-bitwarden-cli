use qs_bitwarden_ssh_agent::approvals::{
    ApprovalManager, Authorization, RequestId, SignScope, Submit, MAX_PENDING,
};
use qs_bitwarden_ssh_agent::control::{
    parse_control_line, ControlMessage, LoadStatus, MAX_CONTROL_LINE,
};
use qs_bitwarden_ssh_agent::keystore::{KeyStore, LoadReport, MAX_KEYS};
use qs_bitwarden_ssh_agent::lifecycle::harden_process;
use qs_bitwarden_ssh_agent::load::LoadWindow;
use qs_bitwarden_ssh_agent::protocol::{self, AgentRequest};
use qs_bitwarden_ssh_agent::runtime::{read_payload_async, Runtime, RuntimeError, ServiceRuntime};
use qs_bitwarden_ssh_agent::server::{self, ClientEvent};
use qs_bitwarden_ssh_agent::state::VaultState;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Stdin};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Output {
    Ready {
        v: u8,
        #[serde(rename = "socketPath")]
        socket_path: String,
        #[serde(rename = "fifoPath")]
        fifo_path: String,
        #[serde(rename = "agentVersion")]
        agent_version: String,
        /// What this helper does that one before it did not; see `FEATURES`.
        features: &'static [&'static str],
    },
    ApprovalRequired {
        v: u8,
        #[serde(rename = "requestId")]
        request_id: u64,
        /// The id this request's `unlock_required` had, which still answers
        /// it once (`addressed`); 0 for a request that was never held. Always
        /// present, so the panel can tell this helper's "none" from an older
        /// helper's silence.
        #[serde(rename = "promotedFrom")]
        promoted_from: u64,
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "keyName")]
        key_name: String,
        fingerprint: String,
        pid: u32,
        #[serde(rename = "processPath")]
        process_path: String,
        /// `sshsig`, `ssh-auth`, or `ssh-sign` for data not recognised.
        operation: &'static str,
        /// The SSHSIG namespace or the login name; empty for `ssh-sign`.
        #[serde(rename = "operationDetail")]
        operation_detail: String,
        /// For `ssh-auth`, the server host key fingerprint the client bound
        /// the session to, unverified; "" when it reported none.
        #[serde(rename = "hostKey")]
        host_key: String,
        /// The fingerprint is only what the remote host of a forwarded
        /// connection said (`protocol::Classified::host_claimed`).
        #[serde(rename = "hostKeyClaimed")]
        host_key_claimed: bool,
        forwarded: bool,
        #[serde(rename = "grantOffered")]
        grant_offered: bool,
    },
    Locked {
        v: u8,
        epoch: u64,
    },
    /// A candidate load was refused. Not `locked`, which acknowledges
    /// `vault_locked`; the panel retries this one.
    LoadFailed {
        v: u8,
        epoch: u64,
    },
    KeysLoaded {
        v: u8,
        epoch: u64,
        #[serde(rename = "keyCount")]
        key_count: usize,
    },
    /// A signature asked for against a locked vault whose public cache knows
    /// the key; held until the panel unlocks or cancels.
    UnlockRequired {
        v: u8,
        #[serde(rename = "requestId")]
        request_id: u64,
        reason: &'static str,
        #[serde(rename = "keyName")]
        key_name: String,
        fingerprint: String,
        pid: u32,
        #[serde(rename = "processPath")]
        process_path: String,
        /// As on `approval_required`; empty for an identity listing.
        operation: &'static str,
        #[serde(rename = "operationDetail")]
        operation_detail: String,
        /// For `ssh-auth`, the server host key fingerprint the client bound
        /// the session to, unverified; "" when it reported none.
        #[serde(rename = "hostKey")]
        host_key: String,
        /// The fingerprint is only what the remote host of a forwarded
        /// connection said (`protocol::Classified::host_claimed`).
        #[serde(rename = "hostKeyClaimed")]
        host_key_claimed: bool,
        forwarded: bool,
        /// Whether approving may also open a grant, so the panel never assumes.
        #[serde(rename = "grantOffered")]
        grant_offered: bool,
    },
    /// A request the panel may still be prompting for is gone (client left,
    /// deadline passed, or a lock), so the prompt can close.
    RequestCancelled {
        v: u8,
        #[serde(rename = "requestId")]
        request_id: u64,
        reason: &'static str,
    },
    /// One validated public identity in OpenSSH form. One message per key,
    /// since 128 keys would exceed the 64 KiB line limit; the panel collects
    /// them until `keys_loaded`.
    PublicKey {
        v: u8,
        epoch: u64,
        #[serde(rename = "itemId")]
        item_id: String,
        name: String,
        fingerprint: String,
        #[serde(rename = "publicKey")]
        public_key: String,
    },
    /// The live grant set, whenever it changes. Public metadata only.
    GrantsChanged {
        v: u8,
        grants: Vec<GrantView>,
    },
}

#[derive(Serialize)]
struct GrantView {
    #[serde(rename = "grantId")]
    grant_id: u64,
    #[serde(rename = "keyName")]
    key_name: String,
    fingerprint: String,
    pid: u32,
    #[serde(rename = "processPath")]
    process_path: String,
    operation: &'static str,
    #[serde(rename = "operationDetail")]
    operation_detail: String,
    #[serde(rename = "hostKey")]
    host_key: String,
    #[serde(rename = "expiresInSec")]
    expires_in_sec: u64,
}

struct PendingSign {
    reply: oneshot::Sender<Vec<u8>>,
    message: Vec<u8>,
    flags: u32,
    /// The id of the `unlock_required` this request was held under, until a
    /// decision has been taken by it (`addressed`).
    promoted_from: Option<RequestId>,
    /// The grant window, if the user approved while no key could sign (a key
    /// load running, or keys set aside): applied by `settle_pending` when
    /// keys are in service again, never before.
    approved: Option<u64>,
}

/// What `ready` lists. `keys-aside`: a failed `key_load_end` sets keys in
/// service aside instead of dropping them, and `keys_resume` and `keys_drop`
/// are understood.
const FEATURES: &[&str] = &["keys-aside"];

/// A signature asked for while locked, kept whole so the unlock it triggers
/// can release it.
struct HeldSign {
    reply: oneshot::Sender<Vec<u8>>,
    public_blob: Vec<u8>,
    message: Vec<u8>,
    flags: u32,
    peer: qs_bitwarden_ssh_agent::peer::PeerContext,
    scope: SignScope,
    /// As on the `unlock_required` sent for it, for the `approval_required`
    /// that follows the load.
    host_claimed: bool,
    deadline_ms: u64,
    /// The grant window, if the user approved before the load finished (the
    /// prompt needs only public data). Decides nothing by itself: the load
    /// must produce the approved key, and the final epoch/state/key check still
    /// runs before signing.
    approved: Option<u64>,
}

/// Identity listings waiting on an unlock, sharing one request id. A fresh
/// companion has no public cache, so the session's first `ssh` would list
/// nothing and never lead to a sign request; concurrent clients share one
/// prompt.
struct HeldIdentities {
    request_id: RequestId,
    deadline_ms: u64,
    /// Each waiting reply with whether its connection is forwarded, which
    /// decides whether the answer carries item names.
    waiting: Vec<(oneshot::Sender<Vec<u8>>, bool)>,
}

/// How long a held request waits for an unlock (same as approvals).
const HELD_LIFETIME_MS: u64 = qs_bitwarden_ssh_agent::approvals::REQUEST_LIFETIME_MS;

struct ActiveLoad {
    epoch: u64,
    window: LoadWindow,
    payload: Option<Result<Zeroizing<Vec<u8>>, RuntimeError>>,
    end_received: bool,
    /// Set by `key_load_end`: when a payload still missing counts as never
    /// coming. See `LOAD_END_GRACE_MS`.
    payload_deadline_ms: Option<u64>,
    task: tokio::task::JoinHandle<()>,
}

/// How long after `key_load_end` the load's payload may still arrive. The
/// reader skips lines that are not this load's, so a wrong or malformed line
/// no longer ends the load by itself; without this, a load whose payload never
/// came would wait out the reader's 30 s. The panel sends `key_load_end` only
/// once its vault read has exited, and the FIFO writer holds that read's
/// output open until it is done, so the payload is normally already buffered.
const LOAD_END_GRACE_MS: u64 = 5_000;

struct ControlReader {
    stdin: Stdin,
    buffered: Vec<u8>,
}

impl ControlReader {
    fn new() -> Self {
        Self {
            stdin: tokio::io::stdin(),
            buffered: Vec::new(),
        }
    }

    async fn next_line(&mut self) -> Result<Option<Vec<u8>>, ()> {
        loop {
            if let Some(newline) = self.buffered.iter().position(|byte| *byte == b'\n') {
                let remainder = self.buffered.split_off(newline + 1);
                let line = std::mem::replace(&mut self.buffered, remainder);
                return Ok(Some(line));
            }
            if self.buffered.len() > MAX_CONTROL_LINE {
                return Err(());
            }
            let mut chunk = [0_u8; 4096];
            let count = self.stdin.read(&mut chunk).await.map_err(|_| ())?;
            if count == 0 {
                if self.buffered.is_empty() {
                    return Ok(None);
                }
                return Err(());
            }
            self.buffered.extend_from_slice(&chunk[..count]);
            if self.buffered.len() > MAX_CONTROL_LINE + 1 {
                return Err(());
            }
        }
    }
}

/// Control output uses `try_send`, and the writer cannot run until the select
/// loop yields, so the channel holds one iteration's largest burst: a
/// successful load (a `public_key` per key and `keys_loaded`, one message per
/// waiting request whose key went, then two per held sign request and one
/// for held listings). A full channel fails `emit`, which ends the helper.
const CONTROL_OUTPUT_CAPACITY: usize = MAX_KEYS + 1 + 3 * MAX_PENDING + 1 + 8;

fn emit(output: &mpsc::Sender<Output>, message: Output) -> Result<(), ()> {
    output.try_send(message).map_err(|_| ())
}

async fn write_output(mut messages: mpsc::Receiver<Output>) {
    let mut stdout = tokio::io::stdout();
    while let Some(message) = messages.recv().await {
        let Ok(mut bytes) = serde_json::to_vec(&message) else {
            return;
        };
        bytes.push(b'\n');
        if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
            return;
        }
    }
}

/// What the panel asks this binary before trusting it. Arguments are handled
/// exhaustively: the panel passes none, and a typo must not start a
/// key-holding daemon.
fn dispatch_arguments() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    let first = args.next()?;
    if args.next().is_some() {
        eprintln!("qs-bitwarden-ssh-agent: expected at most one argument");
        return Some(2);
    }
    match first.as_str() {
        "--version" => {
            println!(
                "qs-bitwarden-ssh-agent {} (control protocol {})",
                env!("CARGO_PKG_VERSION"),
                qs_bitwarden_ssh_agent::control::CONTROL_VERSION
            );
            Some(0)
        }
        "--self-test" => Some(qs_bitwarden_ssh_agent::selftest::run()),
        "--help" | "-h" => {
            println!("qs-bitwarden-ssh-agent [--version | --self-test]");
            println!();
            println!("With no arguments, serves the SSH agent protocol and speaks the");
            println!("panel's control protocol on stdin and stdout. It is launched by the");
            println!("Bitwarden Quickshell panel and is not useful on its own.");
            Some(0)
        }
        other => {
            eprintln!("qs-bitwarden-ssh-agent: unknown argument '{other}'");
            Some(2)
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // These modes answer and exit before any runtime setup.
    if let Some(code) = dispatch_arguments() {
        std::process::exit(code);
    }
    if run().await.is_err() {
        eprintln!("qs-bitwarden-ssh-agent: exiting");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ()> {
    harden_process().map_err(|_| ())?;
    let runtime_root = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or(())?;
    let runtime = ServiceRuntime::acquire(&runtime_root).map_err(|_| ())?;
    let listener = runtime.bind_socket().map_err(|_| ())?;
    let (output_tx, output_rx) = mpsc::channel(CONTROL_OUTPUT_CAPACITY);
    let output_task = tokio::spawn(write_output(output_rx));
    let (events_tx, mut events_rx) = mpsc::channel::<ClientEvent>(8);
    let (load_tx, mut load_rx) = mpsc::channel(1);
    let server = tokio::spawn(server::run(listener, events_tx));

    let socket = runtime.socket_path().to_string_lossy().into_owned();
    let fifo = runtime.runtime().fifo_path().to_string_lossy().into_owned();
    let mut control = ControlReader::new();
    let mut store = KeyStore::new();
    let mut approvals = ApprovalManager::new(rustix::process::geteuid().as_raw());
    let mut pending = HashMap::<RequestId, PendingSign>::new();
    let mut held = HashMap::<RequestId, HeldSign>::new();
    let mut held_identities: Option<HeldIdentities> = None;
    let mut unlock_on_demand = false;
    let mut grant_snapshot = Vec::<u64>::new();
    let mut active_load: Option<ActiveLoad> = None;
    let started = Instant::now();
    let mut gate_open = false;
    let mut handshake_complete = false;
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));

    loop {
        tokio::select! {
            line = control.next_line() => {
                let Some(line) = line? else { break };
                let message = parse_control_line(&line).map_err(|_| ())?;
                match message {
                    ControlMessage::Hello { .. } if !handshake_complete => {
                        handshake_complete = true;
                        // The gate stays closed until a load publishes keys
                        // (`finish_load_if_ready`), as `KeyStore::authorize`
                        // requires; nothing could be signed before then.
                        emit(&output_tx, Output::Ready { v: 1, socket_path: socket.clone(), fifo_path: fifo.clone(), agent_version: env!("CARGO_PKG_VERSION").to_owned(), features: FEATURES })?;
                    }
                    ControlMessage::Hello { .. } => return Err(()),
                    ControlMessage::VaultLocked { epoch, .. } => {
                        gate_open = false;
                        cancel_load(&mut active_load, runtime.runtime());
                        store.lock(epoch);
                        approvals.invalidate_all();
                        fail_pending(&mut pending);
                        cancel_held(&mut held, "locked", &output_tx)?;
                        release_held_identities(&mut held_identities, &store, &output_tx, "locked")?;
                        emit(&output_tx, Output::Locked { v: 1, epoch })?;
                    }
                    ControlMessage::VaultLoggedOut { .. } => {
                        gate_open = false;
                        cancel_load(&mut active_load, runtime.runtime());
                        store.logout(store.epoch().saturating_add(1));
                        approvals.invalidate_all();
                        fail_pending(&mut pending);
                        cancel_held(&mut held, "logged-out", &output_tx)?;
                        release_held_identities(&mut held_identities, &store, &output_tx, "logged-out")?;
                    }
                    ControlMessage::Approve { request_id, grant_seconds, .. } => {
                        // A held request still waiting on a load: record the
                        // approval now and apply it when the keys arrive.
                        if let Some(request) = held.get_mut(&request_id) {
                            request.approved = Some(grant_seconds);
                            continue;
                        }
                        approve(request_id, grant_seconds, gate_open, &store, &mut approvals, &mut pending, started, &output_tx)?;
                    }
                    ControlMessage::Deny { request_id, .. } | ControlMessage::UnlockCancelled { request_id, .. } => {
                        let request_id = addressed(&mut pending, request_id, &output_tx)?;
                        approvals.disconnect(request_id);
                        if let Some(sign) = pending.remove(&request_id) { let _ = sign.reply.send(protocol::failure_response()); }
                        // The panel asked, so no request_cancelled back.
                        if let Some(request) = held.remove(&request_id) { let _ = request.reply.send(protocol::failure_response()); }
                        if held_identities.as_ref().is_some_and(|w| w.request_id == request_id) {
                            release_held_identities(&mut held_identities, &store, &output_tx, "cancelled")?;
                        }
                    }
                    ControlMessage::KeysResume { .. } => {
                        // Only keys a failed `key_load_end` set aside: after a
                        // lock or a logout there are none, and a load still
                        // running decides for itself.
                        if active_load.is_none() && !gate_open && store.state() == VaultState::Unlocked {
                            gate_open = true;
                            settle_pending(&mut approvals, &mut pending, &store, started, &output_tx)?;
                        }
                    }
                    ControlMessage::KeysDrop { .. } => {
                        // The same keys and no others: with none loaded any
                        // more, every request that waited on them fails.
                        if active_load.is_none() && !gate_open && store.state() == VaultState::Unlocked {
                            store.lock(store.epoch());
                            settle_pending(&mut approvals, &mut pending, &store, started, &output_tx)?;
                        }
                    }
                    ControlMessage::Options { unlock_on_demand: on, .. } => unlock_on_demand = on,
                    ControlMessage::RevokeGrants { .. } => approvals.revoke_all_grants(),
                    ControlMessage::RevokeGrant { grant_id, .. } => approvals.revoke_grant(grant_id),
                    ControlMessage::Shutdown { .. } => break,
                    ControlMessage::KeyLoadBegin { epoch, load_id, .. } => {
                        if active_load.is_some() { return Err(()); }
                        // Nothing signs until the load has ended. Requests
                        // waiting for an answer wait on (`settle_pending`
                        // checks them against the keys the load leaves);
                        // grants end here, as they always have.
                        gate_open = false;
                        approvals.revoke_all_grants();
                        let window = LoadWindow::new(epoch, &load_id).map_err(|_| ())?;
                        // No drain here: the panel starts the vault read right
                        // after sending this line, so a drain could race this
                        // load's own payload. The filter drops stale ones.
                        let filter = window.filter().map_err(|_| ())?;
                        let fifo = runtime.runtime().fifo_reader().map_err(|_| ())?;
                        let sender = load_tx.clone();
                        let task = tokio::spawn(async move {
                            let result = read_payload_async(fifo, std::time::Duration::from_secs(30), filter).await;
                            let _ = sender.send((epoch, result)).await;
                        });
                        active_load = Some(ActiveLoad { epoch, window, payload: None, end_received: false, payload_deadline_ms: None, task });
                    }
                    ControlMessage::KeyLoadEnd { epoch, status, .. } => {
                        let Some(load) = active_load.as_mut() else { return Err(()) };
                        if load.epoch != epoch { return Err(()); }
                        if status != LoadStatus::Ok {
                            // The panel's vault read failed, which a session
                            // ended elsewhere looks like too. Keys in service
                            // stay loaded but sign nothing until the panel
                            // has read that vault again (`keys_resume`) or a
                            // load publishes, and go if it could not
                            // (`keys_drop`). Not a lock: `vault_locked` and
                            // `vault_logged_out` drop every key whatever was
                            // set aside here.
                            cancel_load(&mut active_load, runtime.runtime());
                            keep_or_lock(&mut store, epoch);
                            gate_open = false;
                            cancel_held(&mut held, "load-failed", &output_tx)?;
                            release_held_identities(&mut held_identities, &store, &output_tx, "load-failed")?;
                        } else {
                            load.end_received = true;
                            load.payload_deadline_ms = Some(elapsed_ms(started).saturating_add(LOAD_END_GRACE_MS));
                            settle_load(
                                finish_load_if_ready(&mut active_load, &mut store, &mut gate_open, runtime.runtime(), &output_tx)?,
                                &mut held,
                                &mut held_identities,
                                &store,
                                &mut approvals,
                                &mut pending,
                                started,
                                &output_tx,
                            )?;
                        }
                    }
                }
            }
            Some(event) = events_rx.recv() => handle_client(event, gate_open, &store, &mut approvals, &mut pending, &mut held, &mut held_identities, unlock_on_demand, started, &output_tx)?,
            Some((epoch, result)) = load_rx.recv() => {
                let Some(load) = active_load.as_mut() else { continue };
                if load.epoch != epoch { continue; }
                load.payload = Some(result);
                settle_load(
                    finish_load_if_ready(&mut active_load, &mut store, &mut gate_open, runtime.runtime(), &output_tx)?,
                    &mut held,
                    &mut held_identities,
                    &store,
                    &mut approvals,
                    &mut pending,
                    started,
                    &output_tx,
                )?;
            }
            _ = tick.tick() => {
                let now = elapsed_ms(started);
                approvals.expire(now);
                // A payload that has not arrived within the grace after
                // key_load_end is not coming: fail the load now.
                if let Some(load) = active_load.as_mut() {
                    if load.payload.is_none() && load.payload_deadline_ms.is_some_and(|deadline| now >= deadline) {
                        load.payload = Some(Err(RuntimeError::ReadTimeout));
                        settle_load(
                            finish_load_if_ready(&mut active_load, &mut store, &mut gate_open, runtime.runtime(), &output_tx)?,
                            &mut held,
                            &mut held_identities,
                            &store,
                            &mut approvals,
                            &mut pending,
                            started,
                            &output_tx,
                        )?;
                    }
                }
                let expired: Vec<_> = pending.iter().filter_map(|(id, sign)| (sign.reply.is_closed() || !approvals.is_pending(*id)).then_some(*id)).collect();
                for id in expired {
                    approvals.disconnect(id);
                    if let Some(sign) = pending.remove(&id) { let _ = sign.reply.send(protocol::failure_response()); }
                    // Client left or deadline passed; the panel may still be
                    // prompting.
                    emit(&output_tx, Output::RequestCancelled { v: 1, request_id: id, reason: "withdrawn" })?;
                }
                let stale: Vec<_> = held.iter().filter_map(|(id, request)| (request.reply.is_closed() || request.deadline_ms <= now).then_some(*id)).collect();
                for id in stale {
                    if let Some(request) = held.remove(&id) { let _ = request.reply.send(protocol::failure_response()); }
                    emit(&output_tx, Output::RequestCancelled { v: 1, request_id: id, reason: "withdrawn" })?;
                }
                if held_identities.as_ref().is_some_and(|w| {
                    w.deadline_ms <= now || w.waiting.iter().all(|(reply, _)| reply.is_closed())
                }) {
                    release_held_identities(&mut held_identities, &store, &output_tx, "withdrawn")?;
                }
                emit_grants_if_changed(&mut grant_snapshot, &approvals, &store, now, &output_tx)?;
            }
        }
    }

    approvals.invalidate_all();
    cancel_load(&mut active_load, runtime.runtime());
    fail_pending(&mut pending);
    let _ = cancel_held(&mut held, "shutdown", &output_tx);
    let _ = release_held_identities(&mut held_identities, &store, &output_tx, "shutdown");
    store.logout(store.epoch().saturating_add(1));
    server.abort();
    drop(output_tx);
    let _ = output_task.await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_client(
    event: ClientEvent,
    gate_open: bool,
    store: &KeyStore,
    approvals: &mut ApprovalManager,
    pending: &mut HashMap<RequestId, PendingSign>,
    held: &mut HashMap<RequestId, HeldSign>,
    held_identities: &mut Option<HeldIdentities>,
    unlock_on_demand: bool,
    started: Instant,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    match event.request {
        // The server answers binds itself and never forwards one here.
        AgentRequest::SessionBind { .. } => {
            let _ = event.reply.send(protocol::failure_response());
        }
        // Not behind `gate_open`: public keys are not secret, and listing them
        // while locked keeps unrelated `ssh` connections from raising unlock
        // prompts. The cache is empty when logged out or never loaded.
        AgentRequest::Identities => {
            // An empty cache with unlock-on-demand is the one case a listing
            // raises UI; otherwise a session's first client could never unlock.
            if store.public_identities().is_empty()
                && unlock_on_demand
                && approvals.expects_uid(event.peer.uid)
            {
                if let Some(waiters) = held_identities.as_mut() {
                    waiters.waiting.push((event.reply, event.forwarded));
                    return Ok(());
                }
                if let Ok(id) = approvals.reserve_request_id() {
                    emit(
                        output,
                        Output::UnlockRequired {
                            v: 1,
                            request_id: id,
                            reason: "list-identities",
                            key_name: String::new(),
                            fingerprint: String::new(),
                            pid: event.peer.pid,
                            process_path: protocol::visible_text(
                                &event.peer.executable.to_string_lossy(),
                            ),
                            operation: "",
                            operation_detail: String::new(),
                            host_key: String::new(),
                            host_key_claimed: false,
                            forwarded: event.forwarded,
                            grant_offered: false,
                        },
                    )?;
                    *held_identities = Some(HeldIdentities {
                        request_id: id,
                        deadline_ms: elapsed_ms(started).saturating_add(HELD_LIFETIME_MS),
                        waiting: vec![(event.reply, event.forwarded)],
                    });
                    return Ok(());
                }
            }
            let _ = event.reply.send(identities_for(store, event.forwarded));
        }
        AgentRequest::Sign {
            public_blob,
            message,
            flags,
        } => {
            let classified = protocol::classify(&public_blob, &message, &event.binds);
            // Only a forwarded connection has relayed binds (`server`), so a
            // claimed server already means forwarded; said here as well, so
            // that no such request can open or ride a grant whatever the
            // connection reported.
            let host_claimed = classified.host_claimed;
            let scope = SignScope {
                kind: classified.kind,
                forwarded: event.forwarded || host_claimed,
            };
            // With the key loaded but nothing signing (a key load running, or
            // keys set aside), the request is an ordinary one that waits: no
            // grant is live then, so it is always asked about.
            if !gate_open && store.authorize(&public_blob).is_none() {
                // Locked but the cache knows the key: ask the panel to unlock
                // and hold the request. Unknown keys are not ours.
                let Some(key) = store
                    .public_identities()
                    .iter()
                    .find(|key| key.public_blob() == public_blob)
                else {
                    let _ = event.reply.send(protocol::failure_response());
                    return Ok(());
                };
                if !approvals.expects_uid(event.peer.uid)
                    || approvals.capacity_remaining(held.len()) == 0
                {
                    let _ = event.reply.send(protocol::failure_response());
                    return Ok(());
                }
                let Ok(id) = approvals.reserve_request_id() else {
                    let _ = event.reply.send(protocol::failure_response());
                    return Ok(());
                };
                emit(
                    output,
                    Output::UnlockRequired {
                        v: 1,
                        request_id: id,
                        reason: "sign",
                        key_name: protocol::visible_text(&key.name),
                        fingerprint: key.fingerprint.clone(),
                        pid: event.peer.pid,
                        process_path: protocol::visible_text(
                            &event.peer.executable.to_string_lossy(),
                        ),
                        operation: scope.kind.operation(),
                        operation_detail: scope.kind.detail().to_owned(),
                        host_key: scope.kind.host().to_owned(),
                        host_key_claimed: host_claimed,
                        forwarded: scope.forwarded,
                        grant_offered: scope.grantable(),
                    },
                )?;
                held.insert(
                    id,
                    HeldSign {
                        reply: event.reply,
                        public_blob,
                        message,
                        flags,
                        peer: event.peer,
                        scope,
                        host_claimed,
                        deadline_ms: elapsed_ms(started).saturating_add(HELD_LIFETIME_MS),
                        approved: None,
                    },
                );
                return Ok(());
            }
            if store.authorize(&public_blob).is_none() {
                let _ = event.reply.send(protocol::failure_response());
                return Ok(());
            }
            match approvals.submit(
                store.epoch(),
                &public_blob,
                event.peer.clone(),
                scope.clone(),
                elapsed_ms(started),
            ) {
                Ok(Submit::Granted(authorization)) => {
                    // No grant is live with the gate closed; were one, it
                    // would still sign nothing.
                    let response = if gate_open {
                        authorized_signature(store, authorization, &message, flags)
                    } else {
                        protocol::failure_response()
                    };
                    let _ = event.reply.send(response);
                }
                Ok(Submit::Pending(id)) => {
                    let Some(key) = store
                        .public_identities()
                        .iter()
                        .find(|key| key.public_blob() == public_blob)
                    else {
                        approvals.disconnect(id);
                        let _ = event.reply.send(protocol::failure_response());
                        return Ok(());
                    };
                    let process_path =
                        protocol::visible_text(&event.peer.executable.to_string_lossy());
                    emit(
                        output,
                        Output::ApprovalRequired {
                            v: 1,
                            request_id: id,
                            promoted_from: 0,
                            key_id: key.item_id.clone(),
                            key_name: protocol::visible_text(&key.name),
                            fingerprint: key.fingerprint.clone(),
                            pid: event.peer.pid,
                            process_path,
                            operation: scope.kind.operation(),
                            operation_detail: scope.kind.detail().to_owned(),
                            host_key: scope.kind.host().to_owned(),
                            host_key_claimed: host_claimed,
                            forwarded: scope.forwarded,
                            grant_offered: scope.grantable(),
                        },
                    )?;
                    pending.insert(
                        id,
                        PendingSign {
                            reply: event.reply,
                            message,
                            flags,
                            promoted_from: None,
                            approved: None,
                        },
                    );
                }
                Err(_) => {
                    let _ = event.reply.send(protocol::failure_response());
                }
            }
        }
    }
    Ok(())
}

/// Release requests held for an unlock. Each goes through the ordinary
/// approval path at the new epoch; an unlock authorises nothing by itself.
fn release_held(
    held: &mut HashMap<RequestId, HeldSign>,
    store: &KeyStore,
    approvals: &mut ApprovalManager,
    pending: &mut HashMap<RequestId, PendingSign>,
    started: Instant,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    // In the order they were raised, so the panel's prompt and the approval it
    // is paired with agree on the request, not on a hash map's order.
    let mut released = held.drain().collect::<Vec<_>>();
    released.sort_by_key(|(old_id, _)| *old_id);
    for (old_id, request) in released {
        // Withdraw the unlock prompt; an approval prompt with its own id
        // follows, naming this one (`promotedFrom`).
        emit(
            output,
            Output::RequestCancelled {
                v: 1,
                request_id: old_id,
                reason: "released",
            },
        )?;
        if store.authorize(&request.public_blob).is_none() {
            let _ = request.reply.send(protocol::failure_response());
            continue;
        }
        // Approved during the load: submit at the new epoch and consume the
        // approval. The ordinary checks (key present, unlocked, current epoch)
        // still run.
        if let Some(grant_seconds) = request.approved {
            let response = match approvals.submit(
                store.epoch(),
                &request.public_blob,
                request.peer.clone(),
                request.scope.clone(),
                elapsed_ms(started),
            ) {
                Ok(Submit::Granted(authorization)) => {
                    authorized_signature(store, authorization, &request.message, request.flags)
                }
                Ok(Submit::Pending(id)) => approvals
                    .approve(id, grant_seconds, elapsed_ms(started))
                    .map(|authorization| {
                        authorized_signature(store, authorization, &request.message, request.flags)
                    })
                    .unwrap_or_else(|_| protocol::failure_response()),
                Err(_) => protocol::failure_response(),
            };
            let _ = request.reply.send(response);
            continue;
        }
        match approvals.submit(
            store.epoch(),
            &request.public_blob,
            request.peer.clone(),
            request.scope.clone(),
            elapsed_ms(started),
        ) {
            Ok(Submit::Granted(authorization)) => {
                let response =
                    authorized_signature(store, authorization, &request.message, request.flags);
                let _ = request.reply.send(response);
            }
            Ok(Submit::Pending(id)) => {
                let Some(key) = store
                    .public_identities()
                    .iter()
                    .find(|key| key.public_blob() == request.public_blob)
                else {
                    approvals.disconnect(id);
                    let _ = request.reply.send(protocol::failure_response());
                    continue;
                };
                emit(
                    output,
                    Output::ApprovalRequired {
                        v: 1,
                        request_id: id,
                        promoted_from: old_id,
                        key_id: key.item_id.clone(),
                        key_name: protocol::visible_text(&key.name),
                        fingerprint: key.fingerprint.clone(),
                        pid: request.peer.pid,
                        process_path: protocol::visible_text(
                            &request.peer.executable.to_string_lossy(),
                        ),
                        operation: request.scope.kind.operation(),
                        operation_detail: request.scope.kind.detail().to_owned(),
                        host_key: request.scope.kind.host().to_owned(),
                        host_key_claimed: request.host_claimed,
                        forwarded: request.scope.forwarded,
                        grant_offered: request.scope.grantable(),
                    },
                )?;
                pending.insert(
                    id,
                    PendingSign {
                        reply: request.reply,
                        message: request.message,
                        flags: request.flags,
                        promoted_from: Some(old_id),
                        approved: None,
                    },
                );
            }
            Err(_) => {
                let _ = request.reply.send(protocol::failure_response());
            }
        }
    }
    // One approved with a grant may follow another from the same program that
    // has just been queued.
    settle_granted(approvals, pending, store, started, output)
}

/// The request a decision is for. One released from an unlock is still
/// answered under the id its unlock prompt had, exactly once: that id is the
/// only one the panel knows until it has read the `approval_required` that
/// replaced it. The prompt under the new id, on its way or already up, is
/// withdrawn as "granted", which every panel reads as answered: it closes
/// the prompt and counts nothing toward the cooldown.
fn addressed(
    pending: &mut HashMap<RequestId, PendingSign>,
    id: RequestId,
    output: &mpsc::Sender<Output>,
) -> Result<RequestId, ()> {
    let Some((&current, sign)) = pending
        .iter_mut()
        .find(|(_, sign)| sign.promoted_from == Some(id))
    else {
        return Ok(id);
    };
    sign.promoted_from = None;
    emit(
        output,
        Output::RequestCancelled {
            v: 1,
            request_id: current,
            reason: "granted",
        },
    )?;
    Ok(current)
}

/// The panel's Approve for a request waiting for one.
#[allow(clippy::too_many_arguments)]
fn approve(
    request_id: RequestId,
    grant_seconds: u64,
    gate_open: bool,
    store: &KeyStore,
    approvals: &mut ApprovalManager,
    pending: &mut HashMap<RequestId, PendingSign>,
    started: Instant,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    let request_id = addressed(pending, request_id, output)?;
    if !gate_open {
        // Nothing signs now: kept for `settle_pending`.
        if let Some(sign) = pending.get_mut(&request_id) {
            sign.approved = Some(grant_seconds);
        }
        return Ok(());
    }
    let Some(sign) = pending.remove(&request_id) else {
        return Ok(());
    };
    let response = approvals
        .approve(request_id, grant_seconds, elapsed_ms(started))
        .map(|authorization| authorized_signature(store, authorization, &sign.message, sign.flags))
        .unwrap_or_else(|_| protocol::failure_response());
    let _ = sign.reply.send(response);
    if grant_seconds > 0 {
        settle_granted(approvals, pending, store, started, output)?;
    }
    Ok(())
}

/// Keys are in service again after a key load (published, or failed with the
/// keys before it kept) or after keys set aside were resumed. A request that
/// waited carries on if its key is among them, and fails if it is not; one
/// approved meanwhile is signed now.
fn settle_pending(
    approvals: &mut ApprovalManager,
    pending: &mut HashMap<RequestId, PendingSign>,
    store: &KeyStore,
    started: Instant,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    for id in approvals.rebase(store.epoch(), |blob| store.authorize(blob).is_some()) {
        if let Some(sign) = pending.remove(&id) {
            let _ = sign.reply.send(protocol::failure_response());
        }
        emit(
            output,
            Output::RequestCancelled {
                v: 1,
                request_id: id,
                reason: "withdrawn",
            },
        )?;
    }
    let mut approved: Vec<_> = pending
        .iter()
        .filter_map(|(id, sign)| sign.approved.map(|grant_seconds| (*id, grant_seconds)))
        .collect();
    approved.sort_unstable();
    for (id, grant_seconds) in approved {
        approve(
            id,
            grant_seconds,
            true,
            store,
            approvals,
            pending,
            started,
            output,
        )?;
    }
    Ok(())
}

/// Answers the queued requests a grant just opened covers, and withdraws
/// their prompts from the panel ("granted": answered, not refused).
fn settle_granted(
    approvals: &mut ApprovalManager,
    pending: &mut HashMap<RequestId, PendingSign>,
    store: &KeyStore,
    started: Instant,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    for (id, authorization) in approvals.release_granted(elapsed_ms(started)) {
        if let Some(sign) = pending.remove(&id) {
            let response = authorized_signature(store, authorization, &sign.message, sign.flags);
            let _ = sign.reply.send(response);
        }
        emit(
            output,
            Output::RequestCancelled {
                v: 1,
                request_id: id,
                reason: "granted",
            },
        )?;
    }
    Ok(())
}

/// The identities answer for one connection. A forwarded connection carries a
/// remote host's requests, so any process there could read vault item names
/// with `ssh-add -l`; it gets empty comments instead.
fn identities_for(store: &KeyStore, forwarded: bool) -> Vec<u8> {
    let identities: Vec<_> = store
        .public_identities()
        .iter()
        .map(|key| {
            let comment = if forwarded { "" } else { key.name.as_str() };
            (key.public_blob(), comment)
        })
        .collect();
    protocol::identities_response(&identities)
}

/// Answer identity listings held for an unlock: the real cache on success,
/// otherwise the empty list a locked companion returns anyway.
fn release_held_identities(
    held_identities: &mut Option<HeldIdentities>,
    store: &KeyStore,
    output: &mpsc::Sender<Output>,
    reason: &'static str,
) -> Result<(), ()> {
    let Some(waiters) = held_identities.take() else {
        return Ok(());
    };
    // Waiters differ only in forwarding, so build each answer at most once.
    let local = identities_for(store, false);
    let forwarded = identities_for(store, true);
    for (reply, is_forwarded) in waiters.waiting {
        let _ = reply.send(if is_forwarded { &forwarded } else { &local }.clone());
    }
    emit(
        output,
        Output::RequestCancelled {
            v: 1,
            request_id: waiters.request_id,
            reason,
        },
    )
}

/// Fail every held request and tell the panel to take its prompts down.
fn cancel_held(
    held: &mut HashMap<RequestId, HeldSign>,
    reason: &'static str,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    for (id, request) in held.drain().collect::<Vec<_>>() {
        let _ = request.reply.send(protocol::failure_response());
        emit(
            output,
            Output::RequestCancelled {
                v: 1,
                request_id: id,
                reason,
            },
        )?;
    }
    Ok(())
}

/// Announce the grant set only when it changed (the tick is 100 ms).
fn emit_grants_if_changed(
    snapshot: &mut Vec<u64>,
    approvals: &ApprovalManager,
    store: &KeyStore,
    now_ms: u64,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    let current: Vec<u64> = approvals.grants().iter().map(|grant| grant.id).collect();
    if current == *snapshot {
        return Ok(());
    }
    *snapshot = current;
    let grants = approvals
        .grants()
        .iter()
        .map(|grant| {
            let key = store
                .public_identities()
                .iter()
                .find(|key| key.public_blob() == grant.public_blob);
            GrantView {
                grant_id: grant.id,
                key_name: key
                    .map(|key| protocol::visible_text(&key.name))
                    .unwrap_or_default(),
                fingerprint: key.map(|key| key.fingerprint.clone()).unwrap_or_default(),
                pid: grant.peer.pid,
                process_path: protocol::visible_text(&grant.peer.executable.to_string_lossy()),
                operation: grant.kind.operation(),
                operation_detail: grant.kind.detail().to_owned(),
                host_key: grant.kind.host().to_owned(),
                expires_in_sec: grant.expires_at_ms.saturating_sub(now_ms) / 1000,
            }
        })
        .collect();
    emit(output, Output::GrantsChanged { v: 1, grants })
}

fn fail_pending(pending: &mut HashMap<RequestId, PendingSign>) {
    for (_, sign) in pending.drain() {
        let _ = sign.reply.send(protocol::failure_response());
    }
}

/// Stop any load and wipe what the FIFO holds. With no reader left, a
/// payload in the pipe belongs to no load, and it carries private keys; one
/// that arrives later is dropped by the next load's filter.
fn cancel_load(active: &mut Option<ActiveLoad>, runtime: &Runtime) {
    if let Some(load) = active.take() {
        load.task.abort();
    }
    runtime.discard_buffered();
}

enum LoadOutcome {
    Pending,
    Published,
    Failed,
}

#[allow(clippy::too_many_arguments)]
fn settle_load(
    outcome: LoadOutcome,
    held: &mut HashMap<RequestId, HeldSign>,
    held_identities: &mut Option<HeldIdentities>,
    store: &KeyStore,
    approvals: &mut ApprovalManager,
    pending: &mut HashMap<RequestId, PendingSign>,
    started: Instant,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    if !matches!(outcome, LoadOutcome::Pending) {
        settle_pending(approvals, pending, store, started, output)?;
    }
    match outcome {
        LoadOutcome::Pending => Ok(()),
        LoadOutcome::Published => {
            release_held(held, store, approvals, pending, started, output)?;
            release_held_identities(held_identities, store, output, "released")
        }
        LoadOutcome::Failed => {
            cancel_held(held, "load-failed", output)?;
            release_held_identities(held_identities, store, output, "load-failed")
        }
    }
}

fn finish_load_if_ready(
    active: &mut Option<ActiveLoad>,
    store: &mut KeyStore,
    gate_open: &mut bool,
    runtime: &Runtime,
    output: &mpsc::Sender<Output>,
) -> Result<LoadOutcome, ()> {
    let ready = active
        .as_ref()
        .is_some_and(|load| load.end_received && load.payload.is_some());
    if !ready {
        return Ok(LoadOutcome::Pending);
    }
    let mut load = active.take().ok_or(())?;
    load.task.abort();
    let payload = load.payload.take().ok_or(())?;
    match publish_load(&mut load.window, load.epoch, payload, store) {
        Ok(report) => {
            *gate_open = true;
            // Before keys_loaded, so the panel has the whole set.
            for identity in store.public_identities() {
                emit(
                    output,
                    Output::PublicKey {
                        v: 1,
                        epoch: load.epoch,
                        item_id: identity.item_id.clone(),
                        name: identity.name.clone(),
                        fingerprint: identity.fingerprint.clone(),
                        public_key: identity.public_key_openssh.clone(),
                    },
                )?;
            }
            emit(
                output,
                Output::KeysLoaded {
                    v: 1,
                    epoch: load.epoch,
                    key_count: report.loaded,
                },
            )?;
            Ok(LoadOutcome::Published)
        }
        Err(()) => {
            // A bad FIFO payload is a failed load (retryable), not a lock ack.
            // The panel's read of the vault succeeded (`key_load_end` said
            // so), so the session is the one the keys in service were loaded
            // in, and they stay in service.
            *gate_open = keep_or_lock(store, load.epoch);
            // Its payload may have landed after the reader gave up (a vault
            // read past the 30 s deadline). The next load's filter would skip
            // it anyway; wiping it now keeps keys from sitting in the pipe.
            runtime.discard_buffered();
            eprintln!("qs-bitwarden-ssh-agent: key load failed");
            emit(
                output,
                Output::LoadFailed {
                    v: 1,
                    epoch: load.epoch,
                },
            )?;
            Ok(LoadOutcome::Failed)
        }
    }
}

/// Decode a load's payload and put its keys in service. The candidate is
/// built aside and takes the store's place only whole, so a load that fails
/// at any point leaves the keys in service, and their epoch, as they were.
fn publish_load(
    window: &mut LoadWindow,
    epoch: u64,
    payload: Result<Zeroizing<Vec<u8>>, RuntimeError>,
    store: &mut KeyStore,
) -> Result<LoadReport, ()> {
    if epoch <= store.epoch() {
        return Err(());
    }
    let mut next = KeyStore::new();
    let candidate = window
        .decode(payload.map_err(|_| ())?, &mut next)
        .map_err(|_| ())?;
    let report = next.publish(candidate).map_err(|_| ())?;
    *store = next;
    Ok(report)
}

/// After a failed load: whether keys are loaded still. A failed load is not a
/// lock, so keys already in service are kept (`KeyStore::lock` and `logout`
/// alone drop them, on `vault_locked` and `vault_logged_out`); with none in
/// service the store is locked at the load's epoch, as it always was.
fn keep_or_lock(store: &mut KeyStore, epoch: u64) -> bool {
    let serving = store.state() == VaultState::Unlocked;
    if !serving {
        store.lock(epoch);
    }
    serving
}

fn authorized_signature(
    store: &KeyStore,
    authorization: Authorization,
    message: &[u8],
    flags: u32,
) -> Vec<u8> {
    authorization
        .finalize(store)
        .and_then(|permit| store.sign(&permit, message, flags))
        .and_then(protocol::signature_response)
        .unwrap_or_else(protocol::failure_response)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qs_bitwarden_ssh_agent::peer::PeerContext;

    /// A sign request from a client of the expected uid.
    fn sign(uid: u32) -> (ClientEvent, oneshot::Receiver<Vec<u8>>) {
        let (reply, answer) = oneshot::channel();
        let event = ClientEvent {
            peer: PeerContext::new(uid, 4242, 1, "/usr/bin/ssh").unwrap(),
            forwarded: false,
            binds: Vec::new(),
            request: AgentRequest::Sign {
                public_blob: vec![0; 32],
                message: vec![1; 32],
                flags: 0,
            },
            reply,
        };
        (event, answer)
    }

    /// Before any load, the gate is closed and the store empty: a sign
    /// request is refused without an unlock prompt, as it would be were the
    /// gate open, since nothing is unlocked to authorize it.
    #[test]
    fn a_sign_before_any_load_is_refused_without_a_prompt() {
        for gate_open in [false, true] {
            let store = KeyStore::new();
            let mut approvals = ApprovalManager::new(1000);
            let (output, mut outputs) = mpsc::channel(8);
            let (event, mut answer) = sign(1000);
            handle_client(
                event,
                gate_open,
                &store,
                &mut approvals,
                &mut HashMap::new(),
                &mut HashMap::new(),
                &mut None,
                true,
                Instant::now(),
                &output,
            )
            .unwrap();
            assert_eq!(answer.try_recv().unwrap(), protocol::failure_response());
            assert!(outputs.try_recv().is_err(), "gate open: {gate_open}");
        }
    }
    /// One Ed25519 key loaded at `epoch`, generated here.
    fn load_key(store: &mut KeyStore, key: &ssh_key::PrivateKey, epoch: u64) {
        use qs_bitwarden_ssh_agent::keystore::CandidateItem;
        let mut load = store.begin_load(epoch, 4096).unwrap();
        load.add(CandidateItem {
            item_id: "item".to_owned(),
            name: "key".to_owned(),
            private_key_pem: Zeroizing::new(
                key.to_openssh(Default::default())
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            ),
            public_key: key.public_key().to_openssh().unwrap(),
            fingerprint: key
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
            requires_reprompt: false,
        })
        .unwrap();
        store.publish(load).unwrap();
    }

    /// A plain `publickey` login as `git` on session `[7; 32]`.
    fn login(public_blob: &[u8]) -> Vec<u8> {
        use ssh_encoding::Encode;
        let mut data = Vec::new();
        [7_u8; 32].as_slice().encode(&mut data).unwrap();
        50_u8.encode(&mut data).unwrap();
        for field in [&b"git"[..], b"ssh-connection", b"publickey"] {
            field.encode(&mut data).unwrap();
        }
        1_u8.encode(&mut data).unwrap();
        b"ssh-ed25519".as_slice().encode(&mut data).unwrap();
        public_blob.encode(&mut data).unwrap();
        data
    }

    fn bind(host_key: &[u8], relayed: bool) -> protocol::SessionBinding {
        protocol::SessionBinding {
            session_id: vec![7; 32],
            host_key: protocol::host_key_fingerprint(host_key),
            relayed,
        }
    }

    fn login_event(
        public_blob: &[u8],
        forwarded: bool,
        binds: Vec<protocol::SessionBinding>,
    ) -> (ClientEvent, oneshot::Receiver<Vec<u8>>) {
        let (reply, answer) = oneshot::channel();
        let event = ClientEvent {
            peer: PeerContext::new(1000, 4242, 1, "/usr/bin/ssh").unwrap(),
            forwarded,
            binds,
            request: AgentRequest::Sign {
                public_blob: public_blob.to_vec(),
                message: login(public_blob),
                flags: 0,
            },
            reply,
        };
        (event, answer)
    }

    /// The line the panel reads for the next message.
    fn next(outputs: &mut mpsc::Receiver<Output>) -> serde_json::Value {
        serde_json::to_value(outputs.try_recv().expect("a message was sent")).unwrap()
    }

    /// The prompt for a forwarded login whose server only the remote host
    /// named says so (`hostKeyClaimed`), still carries the fingerprint, and
    /// offers no grant. A server the local client bound, and one the client
    /// did not report, are sent with the field false: always present, so the
    /// panel can tell this helper's "no" from an older helper's silence.
    #[test]
    fn a_prompt_says_when_the_remote_host_named_the_server() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let blob = key.public_key().to_bytes().unwrap();
        let mut store = KeyStore::new();
        load_key(&mut store, &key, 1);
        let github = protocol::host_key_fingerprint(b"github host key");

        for (case, forwarded, binds, host, claimed, shown_forwarded) in [
            (
                "relayed bind",
                true,
                vec![bind(b"hop", false), bind(b"github host key", true)],
                // The local client's bind for the session wins.
                protocol::host_key_fingerprint(b"hop"),
                false,
                true,
            ),
            (
                "only a relayed bind",
                true,
                vec![bind(b"github host key", true)],
                github.clone(),
                true,
                true,
            ),
            (
                // Not a state the server produces; a claim is forwarded
                // whatever the connection said.
                "a relayed bind on a connection not marked",
                false,
                vec![bind(b"github host key", true)],
                github.clone(),
                true,
                true,
            ),
            (
                "the local client's bind",
                false,
                vec![bind(b"github host key", false)],
                github.clone(),
                false,
                false,
            ),
            ("no bind", false, vec![], String::new(), false, false),
        ] {
            let mut approvals = ApprovalManager::new(1000);
            let (output, mut outputs) = mpsc::channel(8);
            let (event, _answer) = login_event(&blob, forwarded, binds);
            handle_client(
                event,
                true,
                &store,
                &mut approvals,
                &mut HashMap::new(),
                &mut HashMap::new(),
                &mut None,
                true,
                Instant::now(),
                &output,
            )
            .unwrap();
            let prompt = next(&mut outputs);
            assert_eq!(prompt["type"], "approval_required", "{case}");
            assert_eq!(prompt["operation"], "ssh-auth", "{case}");
            assert_eq!(prompt["hostKey"], host.as_str(), "{case}");
            assert_eq!(prompt["hostKeyClaimed"], claimed, "{case}");
            assert_eq!(prompt["forwarded"], shown_forwarded, "{case}");
            assert_eq!(prompt["grantOffered"], !shown_forwarded, "{case}");
        }
    }

    /// The same through a locked vault: the unlock prompt says it, and so
    /// does the approval prompt the held request becomes after the load.
    #[test]
    fn a_held_request_keeps_the_claim_through_the_unlock() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let blob = key.public_key().to_bytes().unwrap();
        let github = protocol::host_key_fingerprint(b"github host key");

        for claimed in [true, false] {
            let mut store = KeyStore::new();
            load_key(&mut store, &key, 1);
            store.lock(2);
            let mut approvals = ApprovalManager::new(1000);
            let (mut pending, mut held) = (HashMap::new(), HashMap::new());
            let (output, mut outputs) = mpsc::channel(8);
            let (event, _answer) =
                login_event(&blob, true, vec![bind(b"github host key", claimed)]);
            handle_client(
                event,
                false,
                &store,
                &mut approvals,
                &mut pending,
                &mut held,
                &mut None,
                true,
                Instant::now(),
                &output,
            )
            .unwrap();
            let unlock = next(&mut outputs);
            assert_eq!(unlock["type"], "unlock_required");
            assert_eq!(unlock["hostKey"], github.as_str());
            assert_eq!(unlock["hostKeyClaimed"], claimed);
            assert_eq!(unlock["forwarded"], true);
            assert_eq!(unlock["grantOffered"], false);

            load_key(&mut store, &key, 3);
            release_held(
                &mut held,
                &store,
                &mut approvals,
                &mut pending,
                Instant::now(),
                &output,
            )
            .unwrap();
            assert_eq!(next(&mut outputs)["type"], "request_cancelled");
            let prompt = next(&mut outputs);
            assert_eq!(prompt["type"], "approval_required");
            assert_eq!(prompt["hostKey"], github.as_str());
            assert_eq!(prompt["hostKeyClaimed"], claimed);
            assert_eq!(prompt["forwarded"], true);
            assert_eq!(prompt["grantOffered"], false);
        }
    }

    /// A request released from an unlock gets a new id, and its prompt says
    /// which id it had. A decision sent under that one, by a panel that has
    /// not read the new id yet, still reaches the request, once, and the
    /// prompt under the new id is withdrawn.
    #[test]
    fn a_decision_under_the_unlock_id_reaches_the_released_request_once() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let blob = key.public_key().to_bytes().unwrap();
        let mut store = KeyStore::new();
        load_key(&mut store, &key, 1);
        store.lock(2);
        let mut approvals = ApprovalManager::new(1000);
        let (mut pending, mut held) = (HashMap::new(), HashMap::new());
        let (output, mut outputs) = mpsc::channel(8);
        let (event, _answer) = login_event(&blob, false, vec![]);
        handle_client(
            event,
            false,
            &store,
            &mut approvals,
            &mut pending,
            &mut held,
            &mut None,
            true,
            Instant::now(),
            &output,
        )
        .unwrap();
        let unlock_id = next(&mut outputs)["requestId"].as_u64().unwrap();
        load_key(&mut store, &key, 3);
        release_held(
            &mut held,
            &store,
            &mut approvals,
            &mut pending,
            Instant::now(),
            &output,
        )
        .unwrap();
        assert_eq!(next(&mut outputs)["reason"], "released");
        let prompt = next(&mut outputs);
        let approval_id = prompt["requestId"].as_u64().unwrap();
        assert_eq!(prompt["promotedFrom"], unlock_id);

        assert_eq!(
            addressed(&mut pending, unlock_id, &output).unwrap(),
            approval_id
        );
        let withdrawn = next(&mut outputs);
        assert_eq!(withdrawn["requestId"], approval_id);
        assert_eq!(withdrawn["reason"], "granted");
        assert_eq!(
            addressed(&mut pending, unlock_id, &output).unwrap(),
            unlock_id
        );
        assert!(outputs.try_recv().is_err());
    }

    /// A request waiting for its answer when a key load begins is not failed
    /// by it. Approved during the load, it is signed when the load has put
    /// its key back in service, and failed when the load took the key away.
    #[test]
    fn a_waiting_request_outlives_a_key_load_that_keeps_its_key() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let other = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let blob = key.public_key().to_bytes().unwrap();
        for (reloaded, signed) in [(&key, true), (&other, false)] {
            let mut store = KeyStore::new();
            load_key(&mut store, &key, 1);
            let mut approvals = ApprovalManager::new(1000);
            let mut pending = HashMap::new();
            let (output, mut outputs) = mpsc::channel(8);
            let (event, mut answer) = login_event(&blob, false, vec![]);
            let now = Instant::now();
            handle_client(
                event,
                true,
                &store,
                &mut approvals,
                &mut pending,
                &mut HashMap::new(),
                &mut None,
                true,
                now,
                &output,
            )
            .unwrap();
            let id = next(&mut outputs)["requestId"].as_u64().unwrap();

            // `key_load_begin` closes the gate; the approval waits with it.
            approve(
                id,
                0,
                false,
                &store,
                &mut approvals,
                &mut pending,
                now,
                &output,
            )
            .unwrap();
            assert!(
                answer.try_recv().is_err(),
                "nothing is signed during a load"
            );

            let mut next_store = KeyStore::new();
            load_key(&mut next_store, reloaded, 2);
            settle_pending(&mut approvals, &mut pending, &next_store, now, &output).unwrap();
            let response = answer.try_recv().unwrap();
            assert_eq!(response != protocol::failure_response(), signed);
            assert_eq!(outputs.try_recv().is_err(), signed);
        }
    }

    /// A key load that fails leaves the keys in service where they were, and
    /// a lock still drops them.
    #[test]
    fn a_failed_key_load_keeps_the_keys_in_service_until_a_lock() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let blob = key.public_key().to_bytes().unwrap();
        let mut store = KeyStore::new();
        load_key(&mut store, &key, 1);

        let nonce = "0123456789abcdef0123456789abcdef";
        let mut window = LoadWindow::new(2, nonce).unwrap();
        let payload = format!("{{\"loadId\":\"{nonce}\",\"items\":[")
            .into_bytes()
            .into();
        assert!(publish_load(&mut window, 2, Ok(payload), &mut store).is_err());
        assert!(keep_or_lock(&mut store, 2));
        assert!(store.authorize(&blob).is_some());

        store.lock(3);
        assert!(store.authorize(&blob).is_none());
        assert!(!keep_or_lock(&mut store, 4));
    }

    /// An identity listing's unlock prompt has no server, so nothing claimed.
    #[test]
    fn an_identity_listings_unlock_prompt_claims_no_server() {
        let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let mut store = KeyStore::new();
        load_key(&mut store, &key, 1);
        store.logout(2);
        let mut approvals = ApprovalManager::new(1000);
        let (output, mut outputs) = mpsc::channel(8);
        let (reply, _answer) = oneshot::channel();
        handle_client(
            ClientEvent {
                peer: PeerContext::new(1000, 4242, 1, "/usr/bin/ssh").unwrap(),
                forwarded: true,
                binds: vec![bind(b"github host key", true)],
                request: AgentRequest::Identities,
                reply,
            },
            false,
            &store,
            &mut approvals,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut None,
            true,
            Instant::now(),
            &output,
        )
        .unwrap();
        let unlock = next(&mut outputs);
        assert_eq!(unlock["type"], "unlock_required");
        assert_eq!(unlock["hostKey"], "");
        assert_eq!(unlock["hostKeyClaimed"], false);
    }
}
