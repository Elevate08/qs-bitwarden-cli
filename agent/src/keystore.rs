//! Bounded candidate loading and epoch-authoritative private-key ownership.

use crate::signing;
use crate::state::{StateTracker, VaultState};
use ssh_key::{HashAlg, PrivateKey, PublicKey, Signature};
use std::fmt;
use zeroize::Zeroizing;

/// Maximum number of SSH items accepted in one candidate load.
pub const MAX_KEYS: usize = 128;
/// Maximum OpenSSH PEM bytes accepted for one item.
pub const MAX_PEM_BYTES: usize = 64 * 1024;
/// Maximum filtered FIFO payload accepted for one load.
pub const MAX_FILTERED_BYTES: usize = 8 * 1024 * 1024;

/// One allowlisted item from the bounded FIFO decoder.
pub struct CandidateItem {
    pub item_id: String,
    pub name: String,
    pub private_key_pem: Zeroizing<Vec<u8>>,
    pub public_key: String,
    pub fingerprint: String,
    pub requires_reprompt: bool,
}

/// Stable, non-secret reason why one item was not loaded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipCode {
    MalformedPrivateKey,
    InvalidPrivateKey,
    UnsupportedKeyType,
    MalformedPublicKey,
    PublicKeyMismatch,
    FingerprintMismatch,
    RequiresReprompt,
    Duplicate,
}

/// A skipped item safe to report over the control channel.
#[derive(Debug, Eq, PartialEq)]
pub struct SkippedItem {
    pub item_id: String,
    pub code: SkipCode,
}

/// Successful candidate publication summary.
#[derive(Debug, Eq, PartialEq)]
pub struct LoadReport {
    pub loaded: usize,
    pub skipped: Vec<SkippedItem>,
}

/// Whole-candidate failures. These never include parser input or errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadError {
    StaleEpoch,
    FilteredPayloadTooLarge,
    TooManyKeys,
    PemTooLarge,
    FailedCandidate,
}

/// Public values retained across lock.
#[derive(Debug, Eq, PartialEq)]
pub struct PublicIdentity {
    pub item_id: String,
    pub name: String,
    pub fingerprint: String,
    public_blob: Vec<u8>,
}

impl PublicIdentity {
    pub fn public_blob(&self) -> &[u8] {
        &self.public_blob
    }
}

struct PrivateIdentity {
    key: PrivateKey,
    public_index: usize,
}

/// A public-only authorization result. It cannot keep a private key alive.
pub struct AuthorizationPermit {
    epoch: u64,
    public_blob: Vec<u8>,
}

/// Candidate storage, separate from the live keystore until publication.
pub struct CandidateLoad {
    epoch: u64,
    seen_items: usize,
    failed: bool,
    public: Vec<PublicIdentity>,
    private: Vec<PrivateIdentity>,
    skipped: Vec<SkippedItem>,
}

// Debug output is intentionally redacted because this value owns private keys.
impl fmt::Debug for CandidateLoad {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CandidateLoad { private material redacted }")
    }
}

impl CandidateLoad {
    /// Validate and add one item. Individual key defects are reported as skips;
    /// a hard resource limit poisons the entire candidate.
    pub fn add(&mut self, item: CandidateItem) -> Result<Option<SkipCode>, LoadError> {
        self.seen_items = self.seen_items.saturating_add(1);
        if self.seen_items > MAX_KEYS {
            self.failed = true;
            return Err(LoadError::TooManyKeys);
        }
        if item.private_key_pem.len() > MAX_PEM_BYTES {
            self.failed = true;
            return Err(LoadError::PemTooLarge);
        }
        if item.requires_reprompt {
            return Ok(self.skip(item.item_id, SkipCode::RequiresReprompt));
        }

        let key = match PrivateKey::from_openssh(item.private_key_pem.as_slice()) {
            Ok(key) => key,
            Err(_) => return Ok(self.skip(item.item_id, SkipCode::MalformedPrivateKey)),
        };
        if !matches!(
            key.algorithm(),
            ssh_key::Algorithm::Ed25519 | ssh_key::Algorithm::Rsa { .. }
        ) {
            return Ok(self.skip(item.item_id, SkipCode::UnsupportedKeyType));
        }
        if let Some(rsa) = key.key_data().rsa() {
            if crate::rsa_keys::private_key(rsa).is_err() {
                return Ok(self.skip(item.item_id, SkipCode::InvalidPrivateKey));
            }
        }
        let metadata_key = match PublicKey::from_openssh(&item.public_key) {
            Ok(key) => key,
            Err(_) => return Ok(self.skip(item.item_id, SkipCode::MalformedPublicKey)),
        };
        let public_blob = match key.public_key().to_bytes() {
            Ok(blob) => blob,
            Err(_) => return Ok(self.skip(item.item_id, SkipCode::MalformedPrivateKey)),
        };
        if metadata_key.to_bytes().ok().as_deref() != Some(public_blob.as_slice()) {
            return Ok(self.skip(item.item_id, SkipCode::PublicKeyMismatch));
        }
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        if fingerprint != item.fingerprint {
            return Ok(self.skip(item.item_id, SkipCode::FingerprintMismatch));
        }
        if self
            .public
            .iter()
            .any(|identity| identity.public_blob == public_blob)
        {
            return Ok(self.skip(item.item_id, SkipCode::Duplicate));
        }

        let public_index = self.public.len();
        self.public.push(PublicIdentity {
            item_id: item.item_id,
            name: item.name,
            fingerprint,
            public_blob,
        });
        self.private.push(PrivateIdentity { key, public_index });
        Ok(None)
    }

    fn skip(&mut self, item_id: String, code: SkipCode) -> Option<SkipCode> {
        self.skipped.push(SkippedItem { item_id, code });
        Some(code)
    }
}

/// The only owner of live private keys.
pub struct KeyStore {
    state: StateTracker,
    public: Vec<PublicIdentity>,
    private: Vec<PrivateIdentity>,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            state: StateTracker::new(),
            public: Vec::new(),
            private: Vec::new(),
        }
    }

    /// Enter loading and drop the previous private set before validation.
    pub fn begin_load(
        &mut self,
        epoch: u64,
        filtered_bytes: usize,
    ) -> Result<CandidateLoad, LoadError> {
        if !self.state.begin_load(epoch) {
            return Err(LoadError::StaleEpoch);
        }
        self.private.clear();
        if filtered_bytes > MAX_FILTERED_BYTES {
            return Err(LoadError::FilteredPayloadTooLarge);
        }
        Ok(CandidateLoad {
            epoch,
            seen_items: 0,
            failed: false,
            public: Vec::new(),
            private: Vec::new(),
            skipped: Vec::new(),
        })
    }

    /// Atomically replace both public and private sets with one validated load.
    pub fn publish(&mut self, load: CandidateLoad) -> Result<LoadReport, LoadError> {
        if load.failed {
            return Err(LoadError::FailedCandidate);
        }
        if !self.state.publish(load.epoch) {
            return Err(LoadError::StaleEpoch);
        }
        self.public = load.public;
        self.private = load.private;
        Ok(LoadReport {
            loaded: self.private.len(),
            skipped: load.skipped,
        })
    }

    /// Deny first, then erase the live private set while retaining public data.
    pub fn lock(&mut self, epoch: u64) {
        self.state.lock(epoch, !self.public.is_empty());
        self.private.clear();
    }

    /// Clear both caches for logout or account change.
    pub fn logout(&mut self, epoch: u64) {
        self.state.logout(epoch);
        self.private.clear();
        self.public.clear();
    }

    pub fn state(&self) -> VaultState {
        self.state.state()
    }

    pub fn public_identities(&self) -> &[PublicIdentity] {
        &self.public
    }

    pub fn authorize(&self, public_blob: &[u8]) -> Option<AuthorizationPermit> {
        if !self.state.allows(self.state.epoch()) {
            return None;
        }
        self.private.iter().find_map(|identity| {
            let public = &self.public[identity.public_index];
            (public.public_blob == public_blob).then(|| AuthorizationPermit {
                epoch: self.state.epoch(),
                public_blob: public_blob.to_vec(),
            })
        })
    }

    /// Final epoch/state/key check immediately before the signing primitive.
    pub fn sign(
        &self,
        permit: &AuthorizationPermit,
        message: &[u8],
        flags: u32,
    ) -> Option<Signature> {
        if !self.state.allows(permit.epoch) {
            return None;
        }
        let identity = self.private.iter().find(|identity| {
            self.public[identity.public_index].public_blob == permit.public_blob
        })?;
        signing::sign(&identity.key, message, flags)
    }
}
