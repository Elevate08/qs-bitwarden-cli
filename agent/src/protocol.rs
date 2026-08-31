//! Bounded, allowlisted SSH-agent protocol handling.
//!
//! Wire values follow RFC 9987. The handler answers only identity listing and
//! signing; every malformed, mutation, forwarding, extension, or unknown
//! request receives the same one-byte failure and no diagnostic data.

use crate::signing;
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use std::fmt;

/// Largest accepted agent message body, excluding its four-byte prefix.
pub const MAX_FRAME_LEN: usize = 256 * 1024;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

/// Parsed allowlisted request. It contains public key selection and the
/// payload to be signed, but never private material.
#[derive(Debug, Eq, PartialEq)]
pub enum AgentRequest {
    Identities,
    Sign {
        public_blob: Vec<u8>,
        message: Vec<u8>,
        flags: u32,
    },
}

/// A private identity and the bounded public values advertised for it.
pub struct Identity {
    key: PrivateKey,
    public_blob: Vec<u8>,
    comment: String,
}

impl Identity {
    /// Construct an identity for one of the two v1 key algorithms.
    pub fn new(key: PrivateKey, comment: impl Into<String>) -> Result<Self, ProtocolError> {
        if !matches!(key.algorithm(), Algorithm::Ed25519 | Algorithm::Rsa { .. }) {
            return Err(ProtocolError);
        }
        let comment = comment.into();
        if comment.len() > MAX_FRAME_LEN {
            return Err(ProtocolError);
        }
        let public_blob = key.public_key().to_bytes().map_err(|_| ProtocolError)?;
        Ok(Self {
            key,
            public_blob,
            comment,
        })
    }

    /// OpenSSH public-key blob used to select and advertise this identity.
    pub fn public_blob(&self) -> &[u8] {
        &self.public_blob
    }

    /// Human-readable identity comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Public half of this identity.
    pub fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }
}

/// An intentionally opaque construction error.
pub struct ProtocolError;

impl fmt::Debug for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid SSH identity")
    }
}

/// Handle exactly one length-prefixed agent frame.
///
/// The length is checked before the body is sliced or any request field is
/// allocated. The returned frame is always small enough for the configured
/// cap; otherwise it is the normal agent failure frame.
pub fn handle_frame(frame: &[u8], identities: &[Identity]) -> Vec<u8> {
    response(handle(frame, identities).unwrap_or_else(failure_payload))
}

fn handle(frame: &[u8], identities: &[Identity]) -> Option<Vec<u8>> {
    match decode_request(frame)? {
        AgentRequest::Identities => identities_answer(identities),
        AgentRequest::Sign {
            public_blob,
            message,
            flags,
        } => sign_response_fields(&public_blob, &message, flags, identities),
    }
}

pub fn decode_request(frame: &[u8]) -> Option<AgentRequest> {
    let header: [u8; 4] = frame.get(..4)?.try_into().ok()?;
    let declared = usize::try_from(u32::from_be_bytes(header)).ok()?;
    if declared == 0 || declared > MAX_FRAME_LEN || frame.len() != declared.checked_add(4)? {
        return None;
    }

    let payload = &frame[4..];
    match payload.first().copied()? {
        REQUEST_IDENTITIES if payload.len() == 1 => Some(AgentRequest::Identities),
        SIGN_REQUEST => decode_sign_request(&payload[1..]),
        _ => None,
    }
}

fn identities_answer(identities: &[Identity]) -> Option<Vec<u8>> {
    let mut payload = vec![IDENTITIES_ANSWER];
    u32::try_from(identities.len())
        .ok()?
        .encode(&mut payload)
        .ok()?;
    for identity in identities {
        identity.public_blob.encode(&mut payload).ok()?;
        identity.comment.encode(&mut payload).ok()?;
        if payload.len() > MAX_FRAME_LEN {
            return None;
        }
    }
    Some(payload)
}

fn decode_sign_request(mut fields: &[u8]) -> Option<AgentRequest> {
    let key_blob = Vec::<u8>::decode(&mut fields).ok()?;
    let message = Vec::<u8>::decode(&mut fields).ok()?;
    let flags = u32::decode(&mut fields).ok()?;
    if !fields.is_empty() {
        return None;
    }
    Some(AgentRequest::Sign {
        public_blob: key_blob,
        message,
        flags,
    })
}

fn sign_response_fields(
    key_blob: &[u8],
    message: &[u8],
    flags: u32,
    identities: &[Identity],
) -> Option<Vec<u8>> {
    let identity = identities
        .iter()
        .find(|identity| identity.public_blob == key_blob)?;
    let signature = signing::sign(&identity.key, message, flags)?;
    signature_payload(signature)
}

pub fn signature_response(signature: ssh_key::Signature) -> Option<Vec<u8>> {
    signature_payload(signature).map(response)
}

fn signature_payload(signature: ssh_key::Signature) -> Option<Vec<u8>> {
    let signature_bytes = Vec::<u8>::try_from(signature).ok()?;
    let mut payload = vec![SIGN_RESPONSE];
    signature_bytes.encode(&mut payload).ok()?;
    (payload.len() <= MAX_FRAME_LEN).then_some(payload)
}

pub fn identities_response(public: &[(&[u8], &str)]) -> Vec<u8> {
    let mut payload = vec![IDENTITIES_ANSWER];
    let Some(count) = u32::try_from(public.len()).ok() else {
        return failure_response();
    };
    if count.encode(&mut payload).is_err() {
        return failure_response();
    }
    for (blob, comment) in public {
        if blob.encode(&mut payload).is_err()
            || comment.encode(&mut payload).is_err()
            || payload.len() > MAX_FRAME_LEN
        {
            return failure_response();
        }
    }
    response(payload)
}

pub fn failure_response() -> Vec<u8> {
    response(failure_payload())
}

fn failure_payload() -> Vec<u8> {
    vec![FAILURE]
}

fn response(payload: Vec<u8>) -> Vec<u8> {
    if payload.len() > MAX_FRAME_LEN {
        return vec![0, 0, 0, 1, FAILURE];
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    let Ok(length) = u32::try_from(payload.len()) else {
        return vec![0, 0, 0, 1, FAILURE];
    };
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}
