//! Bounded Unix-socket client transport for the single-owner state loop.

use crate::peer::PeerContext;
use crate::protocol::{self, AgentRequest, SessionBinding, MAX_FRAME_LEN};
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
    /// Set once bound for forwarding, or once a bind is refused (it may have
    /// said forwarding), and never cleared, so the remote end cannot send a
    /// "not forwarded" bind to undo it.
    pub forwarded: bool,
    /// The connection's session binds so far, oldest first: which server a
    /// login on each bound session goes to, and whether the local client or
    /// the remote host of a forwarded connection said so.
    pub binds: Vec<SessionBinding>,
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
    let mut binds = Vec::<SessionBinding>::new();
    loop {
        let Some(frame) = read_frame(&mut stream).await else {
            return;
        };
        let Some(request) = protocol::decode_request(&frame) else {
            // Fail closed: a bind that does not parse may have been the one
            // saying this connection relays a remote host, so treat it as
            // forwarded. Leaving the flag alone let a server with an oversized
            // host key have its relayed logins answered by a local grant.
            if protocol::may_be_session_bind(&frame) {
                forwarded = true;
            }
            if write_response(&mut stream, protocol::failure_response())
                .await
                .is_err()
            {
                return;
            }
            continue;
        };
        // Connection state; the state loop only sees its effect.
        if let AgentRequest::SessionBind {
            forwarding,
            binding,
        } = request
        {
            let response = if record_bind(&mut binds, &mut forwarded, forwarding, binding) {
                protocol::success_response()
            } else {
                protocol::failure_response()
            };
            if write_response(&mut stream, response).await.is_err() {
                return;
            }
            continue;
        }
        // The peer was captured once, at accept. A client may have exec'd
        // another program since, so a signature is never attributed (or
        // grant-scoped) to the original executable: re-read it, and drop the
        // connection if it changed or cannot be read.
        if matches!(request, AgentRequest::Sign { .. })
            && !peer.is_unchanged(PeerContext::capture(peer.uid, peer.pid))
        {
            return;
        }
        let (reply, response) = oneshot::channel();
        if events
            .try_send(ClientEvent {
                peer: peer.clone(),
                forwarded,
                binds: binds.clone(),
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

/// Takes one decoded session bind into the connection's state; false if it
/// is refused.
///
/// The local `ssh` sends the binds of a connection up to and including the
/// one that says it is forwarding. Everything after that is written by the
/// remote host, further binds included, so those are recorded as `relayed`:
/// a login matched only to one of them shows its server as the remote
/// host's claim. The same goes for binds after a refused one, which may have
/// been the forwarding bind.
///
/// A bind that cannot be recorded is refused like an unparseable one, and
/// for the same reason marks the connection forwarded whatever its flag
/// said: later logins on its session could not be matched to their server.
fn record_bind(
    binds: &mut Vec<SessionBinding>,
    forwarded: &mut bool,
    forwarding: bool,
    mut binding: SessionBinding,
) -> bool {
    if binds.len() >= MAX_SESSION_BINDS {
        *forwarded = true;
        return false;
    }
    // Read before this bind's own flag is taken: the forwarding bind itself
    // is the local client's.
    binding.relayed = *forwarded;
    binds.push(binding);
    *forwarded |= forwarding;
    true
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

#[cfg(test)]
mod tests {
    use super::{record_bind, MAX_SESSION_BINDS};
    use crate::protocol::SessionBinding;

    fn bind(session: u8) -> SessionBinding {
        SessionBinding {
            session_id: vec![session; 32],
            host_key: format!("SHA256:{session}"),
            relayed: false,
        }
    }

    /// The local client's binds, the forwarding one included, are its own
    /// report; whatever follows the forwarding bind is the remote host's.
    #[test]
    fn binds_after_the_forwarding_bind_are_recorded_as_relayed() {
        let (mut binds, mut forwarded) = (Vec::new(), false);

        assert!(record_bind(&mut binds, &mut forwarded, false, bind(1)));
        assert!(!forwarded);
        assert!(record_bind(&mut binds, &mut forwarded, true, bind(2)));
        assert!(forwarded, "the forwarding bind marks the connection");
        // "Not forwarding" from the remote end undoes nothing.
        assert!(record_bind(&mut binds, &mut forwarded, false, bind(3)));
        assert!(forwarded);
        assert!(record_bind(&mut binds, &mut forwarded, true, bind(4)));

        let relayed: Vec<bool> = binds.iter().map(|bind| bind.relayed).collect();
        assert_eq!(relayed, [false, false, true, true]);
        // What was decoded is kept as it was otherwise.
        assert_eq!(binds[2].session_id, vec![3; 32]);
        assert_eq!(binds[2].host_key, "SHA256:3");
    }

    /// A sender cannot mark its own bind either way: the connection decides.
    #[test]
    fn the_relayed_mark_comes_from_the_connection_not_the_bind() {
        let (mut binds, mut forwarded) = (Vec::new(), false);
        let mut claimed_local = bind(1);
        claimed_local.relayed = true;
        assert!(record_bind(
            &mut binds,
            &mut forwarded,
            false,
            claimed_local
        ));
        assert!(!binds[0].relayed);

        let mut forwarded = true;
        assert!(record_bind(&mut binds, &mut forwarded, false, bind(2)));
        assert!(binds[1].relayed);
    }

    /// A bind past the limit is refused, not recorded, and marks the
    /// connection forwarded; a connection whose bind was refused records the
    /// next ones as relayed.
    #[test]
    fn a_refused_bind_marks_the_connection_and_what_follows() {
        let (mut binds, mut forwarded) = (Vec::new(), false);
        for session in 0..MAX_SESSION_BINDS {
            assert!(record_bind(
                &mut binds,
                &mut forwarded,
                false,
                bind(session as u8)
            ));
        }
        assert!(!forwarded);
        assert!(!record_bind(&mut binds, &mut forwarded, false, bind(99)));
        assert!(forwarded);
        assert_eq!(binds.len(), MAX_SESSION_BINDS);
        assert!(binds.iter().all(|bind| !bind.relayed));

        // As after an unparseable bind, which sets the flag with nothing
        // recorded.
        let (mut binds, mut forwarded) = (Vec::new(), true);
        assert!(record_bind(&mut binds, &mut forwarded, false, bind(1)));
        assert!(binds[0].relayed);
    }
}
