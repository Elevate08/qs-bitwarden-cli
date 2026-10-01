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
    /// The PEM, base64-encoded by the panel so the JSON string holds no
    /// escapes (a PEM's newlines would be `\n`); see `deserialize_pem`.
    #[serde(rename = "privateKeyB64", deserialize_with = "deserialize_pem")]
    private_key: Zeroizing<Vec<u8>>,
    public_key: String,
    fingerprint: String,
    requires_reprompt: bool,
}

/// Decodes the base64 key straight out of the payload buffer into a wiping
/// `Zeroizing<Vec<u8>>`. serde_json hands a string with no escapes over as a
/// borrow of that buffer, so no `String` or scratch copy of the key (or of its
/// encoding, which is as secret as the key) is ever made. A string that does
/// need unescaping arrives as an owned copy, which is refused: base64 has
/// nothing to escape, so it can only be a panel speaking another format.
fn deserialize_pem<'de, D>(deserializer: D) -> Result<Zeroizing<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Base64Pem;

    impl<'de> serde::de::Visitor<'de> for Base64Pem {
        type Value = Zeroizing<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an unescaped base64 string")
        }

        fn visit_borrowed_str<E: serde::de::Error>(
            self,
            value: &'de str,
        ) -> Result<Self::Value, E> {
            decode_base64(value.as_bytes()).ok_or_else(|| E::custom("invalid base64"))
        }
    }

    deserializer.deserialize_str(Base64Pem)
}

/// Strict standard-alphabet base64 with required padding: no whitespace, no
/// URL alphabet, no stray `=`, and no nonzero bits after the last byte, so
/// each key has exactly one accepted encoding. The output is allocated at its
/// final size, so a growing buffer never leaves a copy behind.
fn decode_base64(encoded: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if encoded.is_empty() || encoded.len() % 4 != 0 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(encoded.len() / 4 * 3));
    let last = encoded.len() / 4 - 1;
    for (index, group) in encoded.chunks_exact(4).enumerate() {
        let padding = group.iter().rev().take_while(|&&byte| byte == b'=').count();
        if padding > 2 || (padding > 0 && index != last) {
            return None;
        }
        let mut bits = 0_u32;
        for &byte in &group[..4 - padding] {
            bits = bits << 6 | u32::from(sextet(byte)?);
        }
        bits <<= 6 * padding as u32;
        let bytes = bits.to_be_bytes();
        let count = 3 - padding;
        // The unused low bits of the final sextet must be zero.
        if bytes[1 + count..].iter().any(|&byte| byte != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[1..1 + count]);
    }
    Some(out)
}

fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(text: &str) -> Option<Vec<u8>> {
        decode_base64(text.as_bytes()).map(|bytes| bytes.to_vec())
    }

    #[test]
    fn decodes_the_rfc_4648_vectors() {
        assert_eq!(decoded("Zg==").unwrap(), b"f");
        assert_eq!(decoded("Zm8=").unwrap(), b"fo");
        assert_eq!(decoded("Zm9v").unwrap(), b"foo");
        assert_eq!(decoded("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(decoded("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(decoded("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(decoded("+/+/").unwrap(), [0xfb, 0xff, 0xbf]);
        assert_eq!(decoded("LS0tCg==").unwrap(), b"---\n");
    }

    #[test]
    fn refuses_anything_but_canonical_padded_standard_base64() {
        for bad in [
            "",
            "Zg",
            "Zg=",
            "Zm9",
            "Z===",
            "====",
            "Zg==Zg==",
            "Zm=v",
            "Zm9v\n",
            " Zm9v",
            "Zm 9v",
            "-_-_",
            "Zm9\u{e9}",
            // Nonzero bits past the last byte: "Zh==" would also decode to "f".
            "Zh==",
            "Zm9=",
        ] {
            assert!(decoded(bad).is_none(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn an_escaped_key_or_the_old_field_name_is_refused() {
        let line = |field: &str, value: &str| {
            format!(
                r#"{{"loadId":"0123456789abcdef0123456789abcdef","items":[{{"itemId":"a","name":"n","{field}":"{value}","publicKey":"p","fingerprint":"f","requiresReprompt":false}}]}}"#
            )
        };
        let parse = |text: String| serde_json::from_slice::<Envelope>(text.as_bytes());
        let good = parse(line("privateKeyB64", "Zm9v")).unwrap();
        assert_eq!(good.items[0].private_key.as_slice(), b"foo");
        // An escaped value (valid once unescaped) is not a borrow, so refused.
        assert!(parse(line("privateKeyB64", "Zm9\\u0076")).is_err());
        // The pre-base64 field name: rejected at the key, before any value.
        assert!(parse(line("privateKey", "-----BEGIN-----\\n")).is_err());
    }
}
