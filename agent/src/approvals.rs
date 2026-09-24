//! Bounded signature requests, single-use approvals, and process grants.

use crate::keystore::{AuthorizationPermit, KeyStore};
use crate::peer::PeerContext;
use crate::protocol::SignKind;

/// Requests pending approval and held for an unlock, counted together.
pub const MAX_PENDING: usize = 4;
/// How long a person has to answer a prompt. Two minutes, since 30 s expired
/// while users were still reading (each expiry counts toward the cooldown).
/// Client disconnects, watched while pending, reclaim resources sooner.
pub const REQUEST_LIFETIME_MS: u64 = 120_000;
const MAX_GRANT_SECONDS: u64 = 900;

/// Stable authorization failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalError {
    WrongUid,
    QueueFull,
    UnknownRequest,
    IdExhausted,
}

/// Unique process-lifetime request identifier.
pub type RequestId = u64;

/// Unique process-lifetime grant identifier.
pub type GrantId = u64;

/// Result of submitting a sign request.
#[derive(Debug, Eq, PartialEq)]
pub enum Submit {
    Pending(RequestId),
    Granted(Authorization),
}

/// Public-only authorization which must still pass the keystore's final gate.
#[derive(Debug, Eq, PartialEq)]
pub struct Authorization {
    epoch: u64,
    public_blob: Vec<u8>,
}

impl Authorization {
    /// Recheck epoch, lock state, and key identity at the final signing point.
    pub fn finalize(self, store: &KeyStore) -> Option<AuthorizationPermit> {
        let permit = store.authorize(&self.public_blob)?;
        // The epoch check stops a token from a previous unlock after a reload.
        (store.epoch() == self.epoch).then_some(permit)
    }
}

/// What one sign request asks for, beyond the key and the requesting program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignScope {
    pub kind: SignKind,
    /// Arrived over a connection OpenSSH bound for agent forwarding.
    pub forwarded: bool,
}

impl SignScope {
    /// Whether approving may open a grant, and a live grant may answer. Never
    /// for forwarded requests (the grant would cover local `ssh`, letting the
    /// remote host sign) or unrecognised data (a grant must say what it covers).
    pub fn grantable(&self) -> bool {
        !self.forwarded && self.kind != SignKind::Other
    }
}

/// Whether a live grant answers this request: same unlock, key, kind of
/// signature and program. The one rule both new and queued requests meet.
fn grant_covers(
    grant: &Grant,
    epoch: u64,
    public_blob: &[u8],
    peer: &PeerContext,
    scope: &SignScope,
) -> bool {
    scope.grantable()
        && grant.epoch == epoch
        && grant.public_blob == public_blob
        && grant.kind == scope.kind
        && grant.peer.shares_grant_scope(peer)
}

struct Pending {
    id: RequestId,
    epoch: u64,
    public_blob: Vec<u8>,
    peer: PeerContext,
    scope: SignScope,
    deadline_ms: u64,
}

/// Public grant projection safe for panel status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    pub id: GrantId,
    pub public_blob: Vec<u8>,
    pub peer: PeerContext,
    /// The one kind of signature this grant answers: logins as one user, or
    /// SSHSIG in one namespace.
    pub kind: SignKind,
    pub epoch: u64,
    pub expires_at_ms: u64,
}

/// Single-owner authorization state.
pub struct ApprovalManager {
    expected_uid: u32,
    next_id: RequestId,
    next_grant_id: GrantId,
    pending: Vec<Pending>,
    grants: Vec<Grant>,
}

impl ApprovalManager {
    pub fn new(expected_uid: u32) -> Self {
        Self {
            expected_uid,
            next_id: 1,
            next_grant_id: 1,
            pending: Vec::new(),
            grants: Vec::new(),
        }
    }

    pub fn submit(
        &mut self,
        epoch: u64,
        public_blob: &[u8],
        peer: PeerContext,
        scope: SignScope,
        now_ms: u64,
    ) -> Result<Submit, ApprovalError> {
        if peer.uid != self.expected_uid {
            return Err(ApprovalError::WrongUid);
        }
        self.expire(now_ms);
        if self
            .grants
            .iter()
            .any(|grant| grant_covers(grant, epoch, public_blob, &peer, &scope))
        {
            return Ok(Submit::Granted(Authorization {
                epoch,
                public_blob: public_blob.to_vec(),
            }));
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(ApprovalError::QueueFull);
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ApprovalError::IdExhausted)?;
        self.pending.push(Pending {
            id,
            epoch,
            public_blob: public_blob.to_vec(),
            peer,
            scope,
            deadline_ms: now_ms.saturating_add(REQUEST_LIFETIME_MS),
        });
        Ok(Submit::Pending(id))
    }

    pub fn approve(
        &mut self,
        id: RequestId,
        grant_seconds: u64,
        now_ms: u64,
    ) -> Result<Authorization, ApprovalError> {
        self.expire(now_ms);
        let index = self
            .pending
            .iter()
            .position(|request| request.id == id)
            .ok_or(ApprovalError::UnknownRequest)?;
        let request = self.pending.remove(index);
        // Enforced here, not trusted to the panel: a non-grantable request is
        // approved once whatever window came back.
        if grant_seconds > 0 && request.scope.grantable() {
            let grant_id = self.next_grant_id;
            self.next_grant_id = self
                .next_grant_id
                .checked_add(1)
                .ok_or(ApprovalError::IdExhausted)?;
            let duration_ms = grant_seconds.min(MAX_GRANT_SECONDS).saturating_mul(1_000);
            self.grants.push(Grant {
                id: grant_id,
                public_blob: request.public_blob.clone(),
                peer: request.peer,
                kind: request.scope.kind,
                epoch: request.epoch,
                expires_at_ms: now_ms.saturating_add(duration_ms),
            });
        }
        Ok(Authorization {
            epoch: request.epoch,
            public_blob: request.public_blob,
        })
    }

    /// Pending requests a live grant now covers, taken out of the queue and
    /// authorized as if they had arrived after it. An approval that opens a
    /// grant settles the requests already queued behind it from the same
    /// program, key and kind of signature, instead of leaving each to be
    /// approved again.
    pub fn release_granted(&mut self, now_ms: u64) -> Vec<(RequestId, Authorization)> {
        self.expire(now_ms);
        let grants = &self.grants;
        let mut released = Vec::new();
        self.pending.retain(|request| {
            let covered = grants.iter().any(|grant| {
                grant_covers(
                    grant,
                    request.epoch,
                    &request.public_blob,
                    &request.peer,
                    &request.scope,
                )
            });
            if covered {
                released.push((
                    request.id,
                    Authorization {
                        epoch: request.epoch,
                        public_blob: request.public_blob.clone(),
                    },
                ));
            }
            !covered
        });
        released
    }

    pub fn disconnect(&mut self, id: RequestId) {
        self.pending.retain(|request| request.id != id);
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.pending.retain(|request| request.deadline_ms > now_ms);
        self.grants.retain(|grant| grant.expires_at_ms > now_ms);
    }

    /// The one deny/cancel for lock, logout, account change, suspend, screen
    /// lock, disable and epoch change.
    pub fn invalidate_all(&mut self) {
        self.pending.clear();
        self.grants.clear();
    }

    pub fn revoke_grant(&mut self, id: GrantId) {
        self.grants.retain(|grant| grant.id != id);
    }

    pub fn revoke_all_grants(&mut self) {
        self.grants.clear();
    }

    pub fn revoke_peer(&mut self, peer: &PeerContext) {
        self.grants
            .retain(|grant| !grant.peer.shares_grant_scope(peer));
    }

    /// Reserve an id for a request the caller holds (waiting on an unlock),
    /// from the same sequence as pending ones.
    pub fn reserve_request_id(&mut self) -> Result<RequestId, ApprovalError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ApprovalError::IdExhausted)?;
        Ok(id)
    }

    /// Same-UID check for requests the caller holds.
    pub fn expects_uid(&self, uid: u32) -> bool {
        uid == self.expected_uid
    }

    /// Remaining capacity across pending and held requests (four in total).
    pub fn capacity_remaining(&self, held: usize) -> usize {
        MAX_PENDING.saturating_sub(self.pending.len() + held)
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn is_pending(&self, id: RequestId) -> bool {
        self.pending.iter().any(|request| request.id == id)
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }
}
