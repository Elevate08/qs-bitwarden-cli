//! Bounded Unix-socket client transport for the single-owner state loop.

use crate::peer::PeerContext;
use crate::protocol::{self, AgentRequest, MAX_FRAME_LEN};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::{timeout, Duration};

pub const MAX_CLIENTS: usize = 8;
/// Socket read and write timeouts. These are machine-speed operations, so
/// they stay short regardless of how long a person may take to answer.
pub const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a client blocks waiting for the state loop's answer. It must
/// exceed `approvals::REQUEST_LIFETIME_MS`, or a client would give up before
/// the request it is waiting on expires and the human deadline would be
/// decorative -- which it was when both were thirty seconds.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(150);
const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);

pub struct ClientEvent {
    pub peer: PeerContext,
    pub request: AgentRequest,
    pub reply: oneshot::Sender<Vec<u8>>,
}

pub async fn run(listener: UnixListener, events: mpsc::Sender<ClientEvent>) {
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                // accept(2) can surface connection and resource errors which
                // do not invalidate the listener. There is no portable error
                // taxonomy that proves this descriptor has become unusable,
                // so keep serving and pace persistent failures; shutdown
                // aborts this task with the rest of the companion.
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
        let (reply, response) = oneshot::channel();
        if events
            .try_send(ClientEvent {
                peer: peer.clone(),
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
        // Watch the socket while the request is pending. Awaiting only the
        // reply would leave a client that walked away undetected until the
        // deadline -- and a prompt on screen for a signature nobody is
        // waiting for any more. Returning here drops the reply channel, which
        // is what tells the state loop to withdraw the request.
        //
        // Anything that actually arrives is either EOF or a pipelined frame,
        // which this protocol does not use; both end the connection.
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
