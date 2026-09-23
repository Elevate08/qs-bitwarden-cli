//! One-shot nonce-framed candidate payload decoding.

use crate::keystore::{CandidateItem, CandidateLoad, KeyStore, LoadError, MAX_FILTERED_BYTES};
use serde::Deserialize;
use std::fmt;
use zeroize::Zeroizing;

/// Sanitized whole-payload failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadError {
    InvalidNonce,
    Closed,
    NonceMismatch,
    Malformed,
    Load(LoadError),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Envelope {
    load_id: String,
    items: Vec<Item>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Item {
    item_id: String,
    name: String,
    #[serde(deserialize_with = "deserialize_pem")]
    private_key: Zeroizing<Vec<u8>>,
    public_key: String,
    fingerprint: String,
    requires_reprompt: bool,
}

fn deserialize_pem<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    Ok(Zeroizing::new(value.into_bytes()))
}

/// A single armed load nonce. Every decode attempt consumes the window.
pub struct LoadWindow {
    epoch: u64,
    nonce: Option<[u8; 32]>,
}

impl fmt::Debug for LoadWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LoadWindow { nonce redacted }")
    }
}

impl LoadWindow {
    pub fn new(epoch: u64, nonce: &str) -> Result<Self, PayloadError> {
        let nonce = parse_nonce(nonce)?;
        Ok(Self {
            epoch,
            nonce: Some(nonce),
        })
    }

    /// Decode one bounded JSON payload into an unpublished candidate. Raw JSON
    /// and PEMs wipe on drop; the nonce is checked before `begin_load`, so a
    /// rejected payload cannot wipe a live set.
    pub fn decode(
        &mut self,
        bytes: Zeroizing<Vec<u8>>,
        store: &mut KeyStore,
    ) -> Result<CandidateLoad, PayloadError> {
        let expected = self.nonce.take().ok_or(PayloadError::Closed)?;
        if bytes.len() > MAX_FILTERED_BYTES {
            return Err(PayloadError::Load(LoadError::FilteredPayloadTooLarge));
        }
        let envelope: Envelope =
            serde_json::from_slice(bytes.as_slice()).map_err(|_| PayloadError::Malformed)?;
        let supplied = parse_nonce(&envelope.load_id).map_err(|_| PayloadError::NonceMismatch)?;
        if !constant_time_eq(&supplied, &expected) {
            return Err(PayloadError::NonceMismatch);
        }
        let mut candidate = store
            .begin_load(self.epoch, bytes.len())
            .map_err(PayloadError::Load)?;
        for item in envelope.items {
            candidate
                .add(CandidateItem {
                    item_id: item.item_id,
                    name: item.name,
                    private_key_pem: item.private_key,
                    public_key: item.public_key,
                    fingerprint: item.fingerprint,
                    requires_reprompt: item.requires_reprompt,
                })
                .map_err(PayloadError::Load)?;
        }
        Ok(candidate)
    }
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn parse_nonce(nonce: &str) -> Result<[u8; 32], PayloadError> {
    let bytes: [u8; 32] = nonce
        .as_bytes()
        .try_into()
        .map_err(|_| PayloadError::InvalidNonce)?;
    if bytes.iter().all(u8::is_ascii_hexdigit) {
        Ok(bytes)
    } else {
        Err(PayloadError::InvalidNonce)
    }
}
