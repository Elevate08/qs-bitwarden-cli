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

    /// The filter the FIFO reader uses to find this load's payload.
    pub fn filter(&self) -> Result<PayloadFilter, PayloadError> {
        self.nonce
            .map(|nonce| PayloadFilter { nonce })
            .ok_or(PayloadError::Closed)
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

/// Picks one load's payload out of whatever else is in the FIFO.
///
/// The FIFO lives as long as the helper, so a payload written for an earlier
/// load stays buffered in it: one a lock cancelled before it arrived, or one
/// that outlived its reader's deadline. Taken first-come, that stale payload
/// was read in place of the next load's own, failed its nonce check, and left
/// the new payload behind for the load after it to fail on in turn -- every
/// later load failed until the helper restarted. The reader now keeps only
/// the line that names this load's nonce and drops everything else.
#[derive(Clone)]
pub struct PayloadFilter {
    nonce: [u8; 32],
}

impl fmt::Debug for PayloadFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PayloadFilter { nonce redacted }")
    }
}

impl PayloadFilter {
    /// Where this load's payload starts in `line` (one FIFO line without its
    /// newline), or `None` when the line is not this load's. The match is only
    /// a selection: `LoadWindow::decode` still checks the whole payload.
    pub fn locate(&self, line: &[u8]) -> Option<usize> {
        if self.names_this_load(line) {
            return Some(0);
        }
        // A writer stopped mid-payload (a lock reaps the panel's vault read)
        // leaves a fragment with no newline, and the next payload lands on the
        // same line behind it. The panel's jq filter writes `loadId` first, so
        // this load's payload starts where its own nonce is named. Only the
        // structural form can match: inside a JSON string the quotes would be
        // escaped.
        let mut marker = br#"{"loadId":""#.to_vec();
        marker.extend_from_slice(&self.nonce);
        marker.push(b'"');
        let start = line
            .windows(marker.len())
            .position(|window| window == marker.as_slice())?;
        (start > 0 && self.names_this_load(&line[start..])).then_some(start)
    }

    fn names_this_load(&self, bytes: &[u8]) -> bool {
        // Only `loadId` is kept; serde_json skips the other fields in place
        // without copying them, so no private key is duplicated here.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Named {
            load_id: String,
        }
        serde_json::from_slice::<Named>(bytes)
            .ok()
            .and_then(|named| parse_nonce(&named.load_id).ok())
            .is_some_and(|supplied| constant_time_eq(&supplied, &self.nonce))
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
