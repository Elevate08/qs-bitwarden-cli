use qs_bitwarden_ssh_agent::approvals::{ApprovalManager, RequestId, Submit};
use qs_bitwarden_ssh_agent::control::{
    parse_control_line, ControlMessage, LoadStatus, MAX_CONTROL_LINE,
};
use qs_bitwarden_ssh_agent::keystore::KeyStore;
use qs_bitwarden_ssh_agent::lifecycle::harden_process;
use qs_bitwarden_ssh_agent::load::LoadWindow;
use qs_bitwarden_ssh_agent::protocol::{self, AgentRequest};
use qs_bitwarden_ssh_agent::runtime::{read_payload_async, RuntimeError, ServiceRuntime};
use qs_bitwarden_ssh_agent::server::{self, ClientEvent};
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
    },
    ApprovalRequired {
        v: u8,
        #[serde(rename = "requestId")]
        request_id: u64,
        #[serde(rename = "keyId")]
        key_id: String,
        #[serde(rename = "keyName")]
        key_name: String,
        fingerprint: String,
        pid: u32,
        #[serde(rename = "processPath")]
        process_path: String,
        operation: &'static str,
        forwarded: bool,
        #[serde(rename = "grantOffered")]
        grant_offered: bool,
    },
    Locked {
        v: u8,
        epoch: u64,
    },
    KeysLoaded {
        v: u8,
        epoch: u64,
        #[serde(rename = "keyCount")]
        key_count: usize,
    },
    /// A signature was asked for against a locked vault whose public cache
    /// still knows the key. The request is held, not failed, until the panel
    /// either unlocks or cancels.
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
        /// Whether approving this request may also open a grant. Stated by
        /// the companion so the panel never has to assume it.
        #[serde(rename = "grantOffered")]
        grant_offered: bool,
    },
    /// A request the panel may still be prompting for has gone: the client
    /// disconnected, the deadline passed, or a lock cancelled it. Without
    /// this the prompt would sit there asking about something that no longer
    /// exists, which is how people learn to click prompts away.
    RequestCancelled {
        v: u8,
        #[serde(rename = "requestId")]
        request_id: u64,
        reason: &'static str,
    },
    /// One validated public identity, in the OpenSSH one-line form. Sent per
    /// key rather than as a list: at the documented 128-key limit a single
    /// message would exceed the 64 KiB control-line ceiling. The panel
    /// accumulates them for an epoch and writes the projection when the
    /// matching `keys_loaded` arrives.
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
    #[serde(rename = "expiresInSec")]
    expires_in_sec: u64,
}

struct PendingSign {
    reply: oneshot::Sender<Vec<u8>>,
    message: Vec<u8>,
    flags: u32,
}

/// A signature asked for while the vault was locked. It is kept whole rather
/// than failed, so the unlock the panel is being asked for can release the
/// very request that triggered it.
struct HeldSign {
    reply: oneshot::Sender<Vec<u8>>,
    public_blob: Vec<u8>,
    message: Vec<u8>,
    flags: u32,
    peer: qs_bitwarden_ssh_agent::peer::PeerContext,
    deadline_ms: u64,
    /// Set when the user approved before the load finished, carrying the
    /// grant window they chose. Approving needs the key's identity and the
    /// requesting program, both of which come from the public cache -- none
    /// of it depends on the vault read, so making the user wait for that read
    /// and only then asking is pure delay. The approval still decides
    /// nothing: the load must produce the very key that was approved, and the
    /// final epoch/state/key check runs immediately before signing.
    approved: Option<u64>,
}

/// Identity listings waiting on an unlock, and the one request id that was
/// raised for all of them. A fresh companion has no public cache, so the very
/// first `ssh` of a session lists nothing and would never produce a sign
/// request to unlock from. Coalesced deliberately: several clients starting
/// at once is normal, and each must not cost its own prompt.
struct HeldIdentities {
    request_id: RequestId,
    deadline_ms: u64,
    waiting: Vec<oneshot::Sender<Vec<u8>>>,
}

/// How long a held request waits for an unlock before giving up. The same
/// bound the approval path uses, for the same reason -- and unlocking asks
/// more of the user than approving does, so it certainly needs no less.
const HELD_LIFETIME_MS: u64 = qs_bitwarden_ssh_agent::approvals::REQUEST_LIFETIME_MS;

struct ActiveLoad {
    epoch: u64,
    window: LoadWindow,
    payload: Option<Result<Zeroizing<Vec<u8>>, RuntimeError>>,
    end_received: bool,
    task: tokio::task::JoinHandle<()>,
}

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

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if run().await.is_err() {
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
    let (output_tx, output_rx) = mpsc::channel(16);
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
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));

    loop {
        tokio::select! {
            line = control.next_line() => {
                let Some(line) = line? else { break };
                let message = parse_control_line(&line).map_err(|_| ())?;
                match message {
                    ControlMessage::Hello { .. } if !gate_open => {
                        gate_open = true;
                        emit(&output_tx, Output::Ready { v: 1, socket_path: socket.clone(), fifo_path: fifo.clone(), agent_version: env!("CARGO_PKG_VERSION").to_owned() })?;
                    }
                    ControlMessage::Hello { .. } => return Err(()),
                    ControlMessage::VaultLocked { epoch, .. } => {
                        gate_open = false;
                        cancel_load(&mut active_load);
                        store.lock(epoch);
                        approvals.invalidate_all();
                        fail_pending(&mut pending);
                        cancel_held(&mut held, "locked", &output_tx)?;
                        release_held_identities(&mut held_identities, &store, &output_tx, "locked")?;
                        emit(&output_tx, Output::Locked { v: 1, epoch })?;
                    }
                    ControlMessage::VaultLoggedOut { .. } => {
                        gate_open = false;
                        cancel_load(&mut active_load);
                        store.logout(store.epoch().saturating_add(1));
                        approvals.invalidate_all();
                        fail_pending(&mut pending);
                        cancel_held(&mut held, "logged-out", &output_tx)?;
                        release_held_identities(&mut held_identities, &store, &output_tx, "logged-out")?;
                    }
                    ControlMessage::Approve { request_id, grant_seconds, .. } => {
                        // A held request is one still waiting on a load. The
                        // approval is recorded now and applied the moment the
                        // keys arrive, so the user is not made to wait out the
                        // vault read before being asked.
                        if let Some(request) = held.get_mut(&request_id) {
                            request.approved = Some(grant_seconds);
                            continue;
                        }
                        let Some(sign) = pending.remove(&request_id) else { continue };
                        let response = approvals.approve(request_id, grant_seconds, elapsed_ms(started)).ok()
                            .and_then(|authorization| authorization.finalize(&store))
                            .and_then(|permit| store.sign(&permit, &sign.message, sign.flags))
                            .and_then(protocol::signature_response)
                            .unwrap_or_else(protocol::failure_response);
                        let _ = sign.reply.send(response);
                    }
                    ControlMessage::Deny { request_id, .. } | ControlMessage::UnlockCancelled { request_id, .. } => {
                        approvals.disconnect(request_id);
                        if let Some(sign) = pending.remove(&request_id) { let _ = sign.reply.send(protocol::failure_response()); }
                        // The panel asked, so it needs no request_cancelled
                        // back: it already knows this one is over.
                        if let Some(request) = held.remove(&request_id) { let _ = request.reply.send(protocol::failure_response()); }
                        if held_identities.as_ref().is_some_and(|w| w.request_id == request_id) {
                            release_held_identities(&mut held_identities, &store, &output_tx, "cancelled")?;
                        }
                    }
                    ControlMessage::Options { unlock_on_demand: on, .. } => unlock_on_demand = on,
                    ControlMessage::RevokeGrants { .. } => approvals.revoke_all_grants(),
                    ControlMessage::RevokeGrant { grant_id, .. } => approvals.revoke_grant(grant_id),
                    ControlMessage::Shutdown { .. } => break,
                    ControlMessage::KeyLoadBegin { epoch, load_id, .. } => {
                        if active_load.is_some() { return Err(()); }
                        gate_open = false;
                        approvals.invalidate_all();
                        fail_pending(&mut pending);
                        let window = LoadWindow::new(epoch, &load_id).map_err(|_| ())?;
                        let fifo = runtime.runtime().fifo_reader().map_err(|_| ())?;
                        let sender = load_tx.clone();
                        let task = tokio::spawn(async move {
                            let result = read_payload_async(fifo, std::time::Duration::from_secs(30)).await;
                            let _ = sender.send((epoch, result)).await;
                        });
                        active_load = Some(ActiveLoad { epoch, window, payload: None, end_received: false, task });
                    }
                    ControlMessage::KeyLoadEnd { epoch, status, .. } => {
                        let Some(load) = active_load.as_mut() else { return Err(()) };
                        if load.epoch != epoch { return Err(()); }
                        if status != LoadStatus::Ok {
                            cancel_load(&mut active_load);
                            store.lock(epoch);
                            gate_open = false;
                            cancel_held(&mut held, "load-failed", &output_tx)?;
                            release_held_identities(&mut held_identities, &store, &output_tx, "load-failed")?;
                        } else {
                            load.end_received = true;
                            finish_load_if_ready(&mut active_load, &mut store, &mut gate_open, &output_tx)?;
                            if gate_open {
                                release_held(&mut held, &store, &mut approvals, &mut pending, started, &output_tx)?;
                                release_held_identities(&mut held_identities, &store, &output_tx, "released")?;
                            }
                        }
                    }
                }
            }
            Some(event) = events_rx.recv() => handle_client(event, gate_open, &store, &mut approvals, &mut pending, &mut held, &mut held_identities, unlock_on_demand, started, &output_tx)?,
            Some((epoch, result)) = load_rx.recv() => {
                let Some(load) = active_load.as_mut() else { continue };
                if load.epoch != epoch { continue; }
                load.payload = Some(result);
                finish_load_if_ready(&mut active_load, &mut store, &mut gate_open, &output_tx)?;
                if gate_open {
                    release_held(&mut held, &store, &mut approvals, &mut pending, started, &output_tx)?;
                    release_held_identities(&mut held_identities, &store, &output_tx, "released")?;
                }
            }
            _ = tick.tick() => {
                let now = elapsed_ms(started);
                approvals.expire(now);
                let expired: Vec<_> = pending.iter().filter_map(|(id, sign)| (sign.reply.is_closed() || !approvals.is_pending(*id)).then_some(*id)).collect();
                for id in expired {
                    approvals.disconnect(id);
                    if let Some(sign) = pending.remove(&id) { let _ = sign.reply.send(protocol::failure_response()); }
                    // Whatever ended it -- a client that walked away or a
                    // deadline that passed -- the panel may still be prompting.
                    emit(&output_tx, Output::RequestCancelled { v: 1, request_id: id, reason: "withdrawn" })?;
                }
                let stale: Vec<_> = held.iter().filter_map(|(id, request)| (request.reply.is_closed() || request.deadline_ms <= now).then_some(*id)).collect();
                for id in stale {
                    if let Some(request) = held.remove(&id) { let _ = request.reply.send(protocol::failure_response()); }
                    emit(&output_tx, Output::RequestCancelled { v: 1, request_id: id, reason: "withdrawn" })?;
                }
                if held_identities.as_ref().is_some_and(|w| w.deadline_ms <= now) {
                    release_held_identities(&mut held_identities, &store, &output_tx, "withdrawn")?;
                }
                emit_grants_if_changed(&mut grant_snapshot, &approvals, &store, now, &output_tx)?;
            }
        }
    }

    approvals.invalidate_all();
    cancel_load(&mut active_load);
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
        // Deliberately not behind `gate_open`. Public keys are not secret, and
        // a locked vault that still lists them is what stops every `ssh` after
        // a lock from raising an unlock prompt for a connection that may have
        // nothing to do with the vault. The cache is empty when logged out or
        // locked before any load, so those answer with an empty list, and a
        // lock clears the private set that signing needs regardless.
        AgentRequest::Identities => {
            // An empty cache with unlock-on-demand on is the one case where a
            // listing may raise UI: without it the first client of a session
            // sees nothing and no sign request can ever follow to ask.
            if store.public_identities().is_empty()
                && unlock_on_demand
                && approvals.expects_uid(event.peer.uid)
            {
                if let Some(waiters) = held_identities.as_mut() {
                    waiters.waiting.push(event.reply);
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
                            process_path: event.peer.executable.to_string_lossy().into_owned(),
                            grant_offered: false,
                        },
                    )?;
                    *held_identities = Some(HeldIdentities {
                        request_id: id,
                        deadline_ms: elapsed_ms(started).saturating_add(HELD_LIFETIME_MS),
                        waiting: vec![event.reply],
                    });
                    return Ok(());
                }
            }
            let identities: Vec<_> = store
                .public_identities()
                .iter()
                .map(|key| (key.public_blob(), key.name.as_str()))
                .collect();
            let _ = event.reply.send(protocol::identities_response(&identities));
        }
        AgentRequest::Sign {
            public_blob,
            message,
            flags,
        } => {
            if !gate_open {
                // A locked vault that still knows this key asks the panel to
                // unlock and keeps the request, rather than failing a client
                // that has no way to retry. A key the cache does not know is
                // simply not ours to sign for.
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
                        key_name: key.name.clone(),
                        fingerprint: key.fingerprint.clone(),
                        pid: event.peer.pid,
                        process_path: event.peer.executable.to_string_lossy().into_owned(),
                        grant_offered: true,
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
                elapsed_ms(started),
            ) {
                Ok(Submit::Granted(authorization)) => {
                    let response = authorization
                        .finalize(store)
                        .and_then(|permit| store.sign(&permit, &message, flags))
                        .and_then(protocol::signature_response)
                        .unwrap_or_else(protocol::failure_response);
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
                    let process_path = event.peer.executable.to_string_lossy().into_owned();
                    emit(
                        output,
                        Output::ApprovalRequired {
                            v: 1,
                            request_id: id,
                            key_id: key.item_id.clone(),
                            key_name: key.name.clone(),
                            fingerprint: key.fingerprint.clone(),
                            pid: event.peer.pid,
                            process_path,
                            operation: "ssh-sign",
                            forwarded: false,
                            grant_offered: true,
                        },
                    )?;
                    pending.insert(
                        id,
                        PendingSign {
                            reply: event.reply,
                            message,
                            flags,
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

/// Release every request that was waiting on an unlock, now that one has
/// happened. Each goes through the ordinary approval path at the *new* epoch,
/// so an unlock authorises nothing by itself -- it only gets the request back
/// to the point where the user can be asked.
fn release_held(
    held: &mut HashMap<RequestId, HeldSign>,
    store: &KeyStore,
    approvals: &mut ApprovalManager,
    pending: &mut HashMap<RequestId, PendingSign>,
    started: Instant,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    for (old_id, request) in held.drain().collect::<Vec<_>>() {
        // The prompt the panel is showing is about to be replaced by an
        // approval prompt with its own id, so withdraw the old one first.
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
        // Already approved while the load was running: submit at the new
        // epoch and consume the approval straight away. Every check the
        // ordinary path makes still runs -- the key must be present, the
        // vault unlocked, and the epoch current at the signing primitive.
        if let Some(grant_seconds) = request.approved {
            let response = match approvals.submit(
                store.epoch(),
                &request.public_blob,
                request.peer.clone(),
                elapsed_ms(started),
            ) {
                Ok(Submit::Granted(authorization)) => authorization
                    .finalize(store)
                    .and_then(|permit| store.sign(&permit, &request.message, request.flags))
                    .and_then(protocol::signature_response)
                    .unwrap_or_else(protocol::failure_response),
                Ok(Submit::Pending(id)) => approvals
                    .approve(id, grant_seconds, elapsed_ms(started))
                    .ok()
                    .and_then(|authorization| authorization.finalize(store))
                    .and_then(|permit| store.sign(&permit, &request.message, request.flags))
                    .and_then(protocol::signature_response)
                    .unwrap_or_else(protocol::failure_response),
                Err(_) => protocol::failure_response(),
            };
            let _ = request.reply.send(response);
            continue;
        }
        match approvals.submit(
            store.epoch(),
            &request.public_blob,
            request.peer.clone(),
            elapsed_ms(started),
        ) {
            Ok(Submit::Granted(authorization)) => {
                let response = authorization
                    .finalize(store)
                    .and_then(|permit| store.sign(&permit, &request.message, request.flags))
                    .and_then(protocol::signature_response)
                    .unwrap_or_else(protocol::failure_response);
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
                        key_id: key.item_id.clone(),
                        key_name: key.name.clone(),
                        fingerprint: key.fingerprint.clone(),
                        pid: request.peer.pid,
                        process_path: request.peer.executable.to_string_lossy().into_owned(),
                        operation: "ssh-sign",
                        forwarded: false,
                        grant_offered: true,
                    },
                )?;
                pending.insert(
                    id,
                    PendingSign {
                        reply: request.reply,
                        message: request.message,
                        flags: request.flags,
                    },
                );
            }
            Err(_) => {
                let _ = request.reply.send(protocol::failure_response());
            }
        }
    }
    Ok(())
}

/// Answer every identity listing that was waiting on an unlock. On success
/// that is the real cache; otherwise it is the empty list a locked companion
/// would have returned anyway, which is a normal answer rather than a failure.
fn release_held_identities(
    held_identities: &mut Option<HeldIdentities>,
    store: &KeyStore,
    output: &mpsc::Sender<Output>,
    reason: &'static str,
) -> Result<(), ()> {
    let Some(waiters) = held_identities.take() else {
        return Ok(());
    };
    let identities: Vec<_> = store
        .public_identities()
        .iter()
        .map(|key| (key.public_blob(), key.name.as_str()))
        .collect();
    let response = protocol::identities_response(&identities);
    for reply in waiters.waiting {
        let _ = reply.send(response.clone());
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

/// Announce the live grant set, but only when it has actually changed --
/// otherwise the hundred-millisecond tick would narrate it forever.
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
                key_name: key.map(|key| key.name.clone()).unwrap_or_default(),
                fingerprint: key.map(|key| key.fingerprint.clone()).unwrap_or_default(),
                pid: grant.peer.pid,
                process_path: grant.peer.executable.to_string_lossy().into_owned(),
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

fn cancel_load(active: &mut Option<ActiveLoad>) {
    if let Some(load) = active.take() {
        load.task.abort();
    }
}

fn finish_load_if_ready(
    active: &mut Option<ActiveLoad>,
    store: &mut KeyStore,
    gate_open: &mut bool,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    let ready = active
        .as_ref()
        .is_some_and(|load| load.end_received && load.payload.is_some());
    if !ready {
        return Ok(());
    }
    let mut load = active.take().ok_or(())?;
    load.task.abort();
    let result = load
        .payload
        .take()
        .ok_or(())?
        .map_err(|_| ())
        .and_then(|payload| load.window.decode(payload, store).map_err(|_| ()))
        .and_then(|candidate| store.publish(candidate).map_err(|_| ()));
    match result {
        Ok(report) => {
            *gate_open = true;
            // Ahead of keys_loaded, so the panel has the whole set by the
            // time it is told the load finished.
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
            )
        }
        Err(()) => {
            store.lock(load.epoch);
            *gate_open = false;
            Err(())
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
