//! Bounded Unix-socket client transport for the single-owner state loop.

use crate::peer::PeerContext;
use crate::protocol::{self, AgentRequest, MAX_FRAME_LEN};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::{timeout, Duration};

pub const MAX_CLIENTS: usize = 8;
/// Socket I/O timeouts; machine-speed, independent of human answers.
pub const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a client waits for the state loop. Must exceed
/// `approvals::REQUEST_LIFETIME_MS`, or clients would give up first.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(150);
const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);
/// Session binds per connection (OpenSSH's agent limit; one per hop is
/// normal).
pub const MAX_SESSION_BINDS: usize = 16;

pub struct ClientEvent {
    pub peer: PeerContext,
    /// Set once bound for forwarding and never cleared, so the remote end
    /// cannot send a "not forwarded" bind to undo it.
    pub forwarded: bool,
    pub request: AgentRequest,
    pub reply: oneshot::Sender<Vec<u8>>,
}

pub async fn run(listener: UnixListener, events: mpsc::Sender<ClientEvent>) {
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                // accept(2) errors need not mean the listener is dead: keep
                // serving and pace repeated failures.
                tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let events = events.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_client(stream, events).await;
        });
    }
}

async fn serve_client(mut stream: UnixStream, events: mpsc::Sender<ClientEvent>) {
    let Ok(credentials) = stream.peer_cred() else {
        return;
    };
    let Some(pid) = credentials.pid() else { return };
    let Ok(pid) = u32::try_from(pid) else { return };
    let Ok(peer) = PeerContext::capture(credentials.uid(), pid) else {
        return;
    };

    let mut forwarded = false;
    let mut binds = 0_usize;
    loop {
        let Some(frame) = read_frame(&mut stream).await else {
            return;
        };
        let Some(request) = protocol::decode_request(&frame) else {
            if write_response(&mut stream, protocol::failure_response())
                .await
                .is_err()
            {
                return;
            }
            continue;
        };
        // Connection state; the state loop only sees its effect.
        if let AgentRequest::SessionBind { forwarding } = request {
            let response = if binds < MAX_SESSION_BINDS {
                binds += 1;
                forwarded |= forwarding;
                protocol::success_response()
            } else {
                protocol::failure_response()
            };
            if write_response(&mut stream, response).await.is_err() {
                return;
            }
            continue;
        }
        let (reply, response) = oneshot::channel();
        if events
            .try_send(ClientEvent {
                peer: peer.clone(),
                forwarded,
                request,
                reply,
            })
            .is_err()
        {
            if write_response(&mut stream, protocol::failure_response())
                .await
                .is_err()
            {
                return;
            }
            continue;
        }
        // Watch the socket while pending, so a client that left is noticed
        // before the deadline; returning drops the reply channel, which
        // withdraws the request. Anything arriving (EOF or a pipelined frame)
        // ends the connection.
        let mut probe = [0_u8; 1];
        let bytes = tokio::select! {
            result = timeout(RESPONSE_TIMEOUT, response) => match result {
                Ok(Ok(bytes)) => bytes,
                _ => protocol::failure_response(),
            },
            _ = stream.read(&mut probe) => return,
        };
        if write_response(&mut stream, bytes).await.is_err() {
            return;
        }
    }
}

async fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut header = [0_u8; 4];
    timeout(CLIENT_IO_TIMEOUT, stream.read_exact(&mut header))
        .await
        .ok()?
        .ok()?;
    let length = usize::try_from(u32::from_be_bytes(header)).ok()?;
    if length == 0 || length > MAX_FRAME_LEN {
        return None;
    }
    let mut frame = Vec::with_capacity(length + 4);
    frame.extend_from_slice(&header);
    frame.resize(length + 4, 0);
    timeout(CLIENT_IO_TIMEOUT, stream.read_exact(&mut frame[4..]))
        .await
        .ok()?
        .ok()?;
    Some(frame)
}

async fn write_response(stream: &mut UnixStream, response: Vec<u8>) -> std::io::Result<()> {
    timeout(CLIENT_IO_TIMEOUT, stream.write_all(&response))
        .await
        .map_err(|_| std::io::ErrorKind::TimedOut)??;
    Ok(())
}
