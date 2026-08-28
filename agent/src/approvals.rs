//! Bounded signature requests, single-use approvals, and process grants.

use crate::keystore::{AuthorizationPermit, KeyStore};
use crate::peer::PeerContext;

const MAX_PENDING: usize = 4;
/// How long a person has to answer a prompt before the request is abandoned.
///
/// This is a human deadline, not a machine one: the panel has to open, the
/// user has to notice it, read a fingerprint, and decide. Thirty seconds --
/// the figure the original design carried -- turned out to be shorter than
/// that takes in practice, and expired prompts under a user who was simply
/// reading them. See docs/decisions/0003-request-deadline.md.
///
/// The bound that actually reclaims resources promptly is the client
/// disconnect, which the server watches for while a request is pending.
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
        // `authorize` is current-state authoritative. The explicit epoch check
        // keeps a token from a previous unlock from crossing after a reload.
        (store.epoch() == self.epoch).then_some(permit)
    }
}

struct Pending {
    id: RequestId,
    epoch: u64,
    public_blob: Vec<u8>,
    peer: PeerContext,
    deadline_ms: u64,
}

/// Public grant projection safe for panel status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    pub id: GrantId,
    pub public_blob: Vec<u8>,
    pub peer: PeerContext,
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
        now_ms: u64,
    ) -> Result<Submit, ApprovalError> {
        if peer.uid != self.expected_uid {
            return Err(ApprovalError::WrongUid);
        }
        self.expire(now_ms);
        if self.grants.iter().any(|grant| {
            grant.epoch == epoch
                && grant.public_blob == public_blob
                && grant.peer.shares_grant_scope(&peer)
        }) {
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
        if grant_seconds > 0 {
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
                epoch: request.epoch,
                expires_at_ms: now_ms.saturating_add(duration_ms),
            });
        }
        Ok(Authorization {
            epoch: request.epoch,
            public_blob: request.public_blob,
        })
    }

    pub fn disconnect(&mut self, id: RequestId) {
        self.pending.retain(|request| request.id != id);
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.pending.retain(|request| request.deadline_ms > now_ms);
        self.grants.retain(|grant| grant.expires_at_ms > now_ms);
    }

    /// Lock, logout, account change, suspend, screen lock, disable, and epoch
    /// change all use this same deny/cancel operation.
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

    /// Reserve an identifier for a request the caller holds itself -- one
    /// waiting on an unlock rather than on an approval. Drawn from the same
    /// sequence, so no two live requests can ever share an id.
    pub fn reserve_request_id(&mut self) -> Result<RequestId, ApprovalError> {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ApprovalError::IdExhausted)?;
        Ok(id)
    }

    /// Same-UID enforcement, for requests the caller holds itself rather than
    /// registering as pending.
    pub fn expects_uid(&self, uid: u32) -> bool {
        uid == self.expected_uid
    }

    /// How many more requests may exist across both the pending set and any
    /// the caller is holding. The four-request bound covers them together.
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
