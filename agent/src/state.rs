//! Explicit vault state and epoch tracking for the signing worker.

/// State relevant to identity visibility and signing authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultState {
    /// No account/public cache is available.
    LoggedOut,
    /// A candidate is being validated; private signing is denied.
    Loading,
    /// A validated private set is available for the current epoch.
    Unlocked,
    /// Only the last validated public cache remains.
    LockedCached,
    /// Locked before any public cache has been loaded.
    LockedEmpty,
}

/// Single-owner state; mutating methods are the authorization linearization
/// points.
pub(crate) struct StateTracker {
    epoch: u64,
    state: VaultState,
}

impl StateTracker {
    pub(crate) fn new() -> Self {
        Self {
            epoch: 0,
            state: VaultState::LoggedOut,
        }
    }

    pub(crate) fn begin_load(&mut self, epoch: u64) -> bool {
        if epoch <= self.epoch {
            return false;
        }
        self.epoch = epoch;
        self.state = VaultState::Loading;
        true
    }

    pub(crate) fn publish(&mut self, epoch: u64) -> bool {
        if self.epoch != epoch || self.state != VaultState::Loading {
            return false;
        }
        self.state = VaultState::Unlocked;
        true
    }

    pub(crate) fn lock(&mut self, epoch: u64, has_public_cache: bool) {
        // The deny-signing linearization point; private keys are dropped after.
        self.epoch = self.epoch.max(epoch);
        self.state = if has_public_cache {
            VaultState::LockedCached
        } else {
            VaultState::LockedEmpty
        };
    }

    pub(crate) fn logout(&mut self, epoch: u64) {
        self.epoch = self.epoch.max(epoch);
        self.state = VaultState::LoggedOut;
    }

    pub(crate) fn allows(&self, epoch: u64) -> bool {
        self.epoch == epoch && self.state == VaultState::Unlocked
    }

    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn state(&self) -> VaultState {
        self.state
    }
}
