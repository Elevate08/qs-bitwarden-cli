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
}

struct PendingSign {
    reply: oneshot::Sender<Vec<u8>>,
    message: Vec<u8>,
    flags: u32,
}

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
                        emit(&output_tx, Output::Locked { v: 1, epoch })?;
                    }
                    ControlMessage::VaultLoggedOut { .. } => {
                        gate_open = false;
                        cancel_load(&mut active_load);
                        store.logout(store.epoch().saturating_add(1));
                        approvals.invalidate_all();
                        fail_pending(&mut pending);
                    }
                    ControlMessage::Approve { request_id, grant_seconds, .. } => {
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
                    }
                    ControlMessage::RevokeGrants { .. } => approvals.revoke_all_grants(),
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
                        } else {
                            load.end_received = true;
                            finish_load_if_ready(&mut active_load, &mut store, &mut gate_open, &output_tx)?;
                        }
                    }
                }
            }
            Some(event) = events_rx.recv() => handle_client(event, gate_open, &store, &mut approvals, &mut pending, started, &output_tx)?,
            Some((epoch, result)) = load_rx.recv() => {
                let Some(load) = active_load.as_mut() else { continue };
                if load.epoch != epoch { continue; }
                load.payload = Some(result);
                finish_load_if_ready(&mut active_load, &mut store, &mut gate_open, &output_tx)?;
            }
            _ = tick.tick() => {
                let now = elapsed_ms(started);
                approvals.expire(now);
                let expired: Vec<_> = pending.iter().filter_map(|(id, sign)| (sign.reply.is_closed() || !approvals.is_pending(*id)).then_some(*id)).collect();
                for id in expired {
                    approvals.disconnect(id);
                    if let Some(sign) = pending.remove(&id) { let _ = sign.reply.send(protocol::failure_response()); }
                }
            }
        }
    }

    approvals.invalidate_all();
    cancel_load(&mut active_load);
    fail_pending(&mut pending);
    store.logout(store.epoch().saturating_add(1));
    server.abort();
    drop(output_tx);
    let _ = output_task.await;
    Ok(())
}

fn handle_client(
    event: ClientEvent,
    gate_open: bool,
    store: &KeyStore,
    approvals: &mut ApprovalManager,
    pending: &mut HashMap<RequestId, PendingSign>,
    started: Instant,
    output: &mpsc::Sender<Output>,
) -> Result<(), ()> {
    if !gate_open {
        let _ = event.reply.send(protocol::failure_response());
        return Ok(());
    }
    match event.request {
        AgentRequest::Identities => {
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
