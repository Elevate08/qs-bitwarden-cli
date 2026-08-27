//! Bounded Unix-socket client transport for the single-owner state loop.

use crate::peer::PeerContext;
use crate::protocol::{self, AgentRequest, MAX_FRAME_LEN};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::{timeout, Duration};

pub const MAX_CLIENTS: usize = 8;
pub const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ClientEvent {
    pub peer: PeerContext,
    pub request: AgentRequest,
    pub reply: oneshot::Sender<Vec<u8>>,
}

pub async fn run(listener: UnixListener, events: mpsc::Sender<ClientEvent>) {
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
    while let Ok((stream, _)) = listener.accept().await {
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
        let bytes = match timeout(CLIENT_IO_TIMEOUT, response).await {
            Ok(Ok(bytes)) => bytes,
            _ => protocol::failure_response(),
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
