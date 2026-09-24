//! Bounded, allowlisted SSH-agent protocol handling (RFC 9987): identity
//! listing, signing, and `session-bind@openssh.com` (read for whether the
//! connection is forwarded, and for the server host key a login goes to).
//! Anything else, and anything malformed, gets the same one-byte failure with
//! no diagnostics.

use sha2::{Digest, Sha256};
use ssh_encoding::{Decode, Encode};
use ssh_key::{Fingerprint, Signature};

/// Largest accepted agent message body, excluding its four-byte prefix.
pub const MAX_FRAME_LEN: usize = 256 * 1024;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// RFC 4252 SSH_MSG_USERAUTH_REQUEST, which follows the session id in login
/// signature data.
const USERAUTH_REQUEST: u8 = 50;
/// PROTOCOL.sshsig's preamble, which starts `ssh-keygen -Y sign` (Git) data.
const SSHSIG_PREAMBLE: &[u8] = b"SSHSIG";
/// Longest login name or namespace shown or granted. Longer is not something
/// OpenSSH produces, so it is unrecognised rather than truncated.
const MAX_SIGN_DETAIL: usize = 256;
/// Largest session identifier a bind may carry: a key-exchange hash, 64 bytes
/// at most today.
const MAX_SESSION_ID: usize = 256;
/// Largest server host key a bind or host-bound login may carry. An RSA-16384
/// public blob is about 2 KiB.
const MAX_HOST_KEY: usize = 16 * 1024;

/// Parsed allowlisted request: key selection and payload, never private
/// material.
#[derive(Debug, Eq, PartialEq)]
pub enum AgentRequest {
    Identities,
    Sign {
        public_blob: Vec<u8>,
        message: Vec<u8>,
        flags: u32,
    },
    /// `session-bind@openssh.com` (OpenSSH 8.9+), sent on every connection;
    /// `is_forwarding` is true on one relaying a remote host's requests. The
    /// host key and session id name the server a later login on that session
    /// goes to. The server's signature over them is not checked, so the host
    /// is what the client reports, shown as such.
    SessionBind {
        forwarding: bool,
        binding: SessionBinding,
    },
}

/// One bound session: its key-exchange hash and the server's host key, as
/// its SHA-256 fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionBinding {
    pub session_id: Vec<u8>,
    pub host_key: String,
}

/// What a sign request asks for, read from the signed data. Grants are scoped
/// to it (with the key and program), so approving Git signatures does not
/// also approve logins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignKind {
    /// A PROTOCOL.sshsig signature (as for Git); the namespace (`git`,
    /// `file`, ...) says what it is for.
    SshSig { namespace: String },
    /// An RFC 4252 public-key login, as the user named, to the server whose
    /// host key fingerprint is `host` ("" when the client reported none). A
    /// grant for a login covers that one server only.
    UserAuth { user: String, host: String },
    /// Anything else. Signed only on a prompt answered for that request.
    Other,
}

impl SignKind {
    /// The `operation` field the panel reads.
    pub fn operation(&self) -> &'static str {
        match self {
            Self::SshSig { .. } => "sshsig",
            Self::UserAuth { .. } => "ssh-auth",
            Self::Other => "ssh-sign",
        }
    }

    /// The namespace or login name that goes with `operation`, or "".
    pub fn detail(&self) -> &str {
        match self {
            Self::SshSig { namespace } => namespace,
            Self::UserAuth { user, .. } => user,
            Self::Other => "",
        }
    }

    /// The server host key fingerprint a login goes to, or "".
    pub fn host(&self) -> &str {
        match self {
            Self::UserAuth { host, .. } => host,
            _ => "",
        }
    }
}

/// Classify the data to be signed with `public_blob`. Both shapes must parse
/// whole or it is `Other`; they cannot be confused (`SSHS` as a login's
/// length prefix exceeds the frame limit). `binds` are the connection's
/// session binds, which name the server a login goes to.
pub fn classify_sign(public_blob: &[u8], message: &[u8], binds: &[SessionBinding]) -> SignKind {
    if let Some(namespace) = sshsig_namespace(message) {
        return SignKind::SshSig { namespace };
    }
    userauth(public_blob, message, binds).unwrap_or(SignKind::Other)
}

/// SHA256 fingerprint of an SSH public key blob, as `ssh-keygen -l` prints it.
/// Computed over the raw blob so any host key algorithm has one.
pub fn host_key_fingerprint(blob: &[u8]) -> String {
    Fingerprint::Sha256(Sha256::digest(blob).into()).to_string()
}

/// PROTOCOL.sshsig: the preamble, then namespace, reserved, hash algorithm
/// and the message hash, each an SSH string.
fn sshsig_namespace(message: &[u8]) -> Option<String> {
    let mut fields = message.strip_prefix(SSHSIG_PREAMBLE)?;
    let namespace = Vec::<u8>::decode(&mut fields).ok()?;
    let _reserved = Vec::<u8>::decode(&mut fields).ok()?;
    let hash = Vec::<u8>::decode(&mut fields).ok()?;
    let _digest = Vec::<u8>::decode(&mut fields).ok()?;
    if !fields.is_empty() || !matches!(hash.as_slice(), b"sha256" | b"sha512") {
        return None;
    }
    display_detail(namespace)
}

/// RFC 4252 section 7 and OpenSSH's host-bound variant. The key inside must be
/// the signing key, as OpenSSH's agent requires. The server is the host key
/// of the bind for this session, or the host-bound method's own; if both are
/// present they must agree, as OpenSSH's agent requires, or it is `Other`.
fn userauth(public_blob: &[u8], message: &[u8], binds: &[SessionBinding]) -> Option<SignKind> {
    let mut fields = message;
    let session_id = Vec::<u8>::decode(&mut fields).ok()?;
    if u8::decode(&mut fields).ok()? != USERAUTH_REQUEST {
        return None;
    }
    let user = Vec::<u8>::decode(&mut fields).ok()?;
    let _service = Vec::<u8>::decode(&mut fields).ok()?;
    let method = Vec::<u8>::decode(&mut fields).ok()?;
    let hostbound = match method.as_slice() {
        b"publickey" => false,
        b"publickey-hostbound-v00@openssh.com" => true,
        _ => return None,
    };
    if u8::decode(&mut fields).ok()? != 1 {
        return None;
    }
    let _algorithm = Vec::<u8>::decode(&mut fields).ok()?;
    let key = Vec::<u8>::decode(&mut fields).ok()?;
    let signed_host = if hostbound {
        let host_key = Vec::<u8>::decode(&mut fields).ok()?;
        if host_key.is_empty() || host_key.len() > MAX_HOST_KEY {
            return None;
        }
        Some(host_key_fingerprint(&host_key))
    } else {
        None
    };
    if !fields.is_empty() || key != public_blob {
        return None;
    }
    let bound_host = binds
        .iter()
        .rev()
        .find(|bind| bind.session_id == session_id)
        .map(|bind| bind.host_key.clone());
    let host = match (bound_host, signed_host) {
        (Some(bound), Some(signed)) if bound != signed => return None,
        (bound, signed) => bound.or(signed).unwrap_or_default(),
    };
    Some(SignKind::UserAuth {
        user: display_detail(user)?,
        host,
    })
}

/// A namespace or login fit to display and compare exactly: non-empty,
/// bounded UTF-8 without control characters.
fn display_detail(bytes: Vec<u8>) -> Option<String> {
    if bytes.is_empty() || bytes.len() > MAX_SIGN_DETAIL {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    (!text.chars().any(char::is_control)).then_some(text)
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
        EXTENSION => decode_session_bind(&payload[1..]),
        _ => None,
    }
}

fn decode_session_bind(mut fields: &[u8]) -> Option<AgentRequest> {
    if Vec::<u8>::decode(&mut fields).ok()? != SESSION_BIND {
        return None;
    }
    let host_key = Vec::<u8>::decode(&mut fields).ok()?;
    let session_id = Vec::<u8>::decode(&mut fields).ok()?;
    let _signature = Vec::<u8>::decode(&mut fields).ok()?;
    let forwarding = match u8::decode(&mut fields).ok()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    if !fields.is_empty()
        || host_key.is_empty()
        || host_key.len() > MAX_HOST_KEY
        || session_id.is_empty()
        || session_id.len() > MAX_SESSION_ID
    {
        return None;
    }
    Some(AgentRequest::SessionBind {
        forwarding,
        binding: SessionBinding {
            session_id,
            host_key: host_key_fingerprint(&host_key),
        },
    })
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

pub fn signature_response(signature: Signature) -> Option<Vec<u8>> {
    signature_payload(signature).map(response)
}

fn signature_payload(signature: Signature) -> Option<Vec<u8>> {
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

pub fn success_response() -> Vec<u8> {
    response(vec![SUCCESS])
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

#[cfg(test)]
mod tests {
    use super::{
        classify_sign, decode_request, failure_payload, host_key_fingerprint, response,
        signature_payload, AgentRequest, SessionBinding, SignKind, MAX_FRAME_LEN,
    };
    use crate::signing;
    use rand_core::OsRng;
    use signature::Verifier;
    use ssh_encoding::{Decode, Encode};
    use ssh_key::private::RsaKeypair;
    use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};
    use std::fmt;

    /// A private identity for testing the wire handling directly; production
    /// signing goes through `KeyStore` and `ApprovalManager`.
    struct Identity {
        key: PrivateKey,
        public_blob: Vec<u8>,
        comment: String,
    }

    impl Identity {
        /// Construct an identity for one of the two v1 key algorithms.
        fn new(key: PrivateKey, comment: impl Into<String>) -> Result<Self, ProtocolError> {
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
        fn public_blob(&self) -> &[u8] {
            &self.public_blob
        }

        /// Human-readable identity comment.
        fn comment(&self) -> &str {
            &self.comment
        }

        /// Public half of this identity.
        fn public_key(&self) -> &PublicKey {
            self.key.public_key()
        }
    }

    /// An intentionally opaque construction error.
    struct ProtocolError;

    impl fmt::Debug for ProtocolError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("invalid SSH identity")
        }
    }

    /// Handle one length-prefixed frame. The length is checked before
    /// anything is sliced or allocated; the reply always fits the cap.
    fn handle_frame(frame: &[u8], identities: &[Identity]) -> Vec<u8> {
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
            AgentRequest::SessionBind { .. } => Some(vec![SUCCESS]),
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

    const FAILURE: u8 = 5;
    const SUCCESS: u8 = 6;
    const REQUEST_IDENTITIES: u8 = 11;
    const IDENTITIES_ANSWER: u8 = 12;
    const SIGN_REQUEST: u8 = 13;
    const SIGN_RESPONSE: u8 = 14;
    const RSA_SHA2_256: u32 = 2;
    const RSA_SHA2_512: u32 = 4;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(payload.len() + 4);
        u32::try_from(payload.len())
            .unwrap()
            .encode(&mut encoded)
            .unwrap();
        encoded.extend_from_slice(payload);
        encoded
    }

    fn string(value: &[u8], out: &mut Vec<u8>) {
        value.encode(out).unwrap();
    }

    fn response_payload(response: &[u8]) -> &[u8] {
        let declared = u32::from_be_bytes(response[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, response.len() - 4);
        &response[4..]
    }

    fn sign_request(key_blob: &[u8], message: &[u8], flags: u32) -> Vec<u8> {
        let mut payload = vec![SIGN_REQUEST];
        string(key_blob, &mut payload);
        string(message, &mut payload);
        flags.encode(&mut payload).unwrap();
        frame(&payload)
    }

    fn signature(response: &[u8]) -> Signature {
        let payload = response_payload(response);
        assert_eq!(payload[0], SIGN_RESPONSE);
        let mut encoded = &payload[1..];
        let signature_bytes = Vec::<u8>::decode(&mut encoded).unwrap();
        assert!(encoded.is_empty());
        Signature::try_from(signature_bytes.as_slice()).unwrap()
    }

    #[test]
    fn lists_openssh_encoded_identities() {
        let ed25519 = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let rsa = PrivateKey::from(RsaKeypair::random(&mut OsRng, 2048).unwrap());
        let identities = [
            Identity::new(ed25519, "vault ed25519").unwrap(),
            Identity::new(rsa, "vault rsa").unwrap(),
        ];

        let response = handle_frame(&frame(&[REQUEST_IDENTITIES]), &identities);
        let payload = response_payload(&response);
        assert_eq!(payload[0], IDENTITIES_ANSWER);
        let mut fields = &payload[1..];
        assert_eq!(u32::decode(&mut fields).unwrap(), 2);
        for identity in identities.iter() {
            assert_eq!(
                Vec::<u8>::decode(&mut fields).unwrap(),
                identity.public_blob()
            );
            assert_eq!(String::decode(&mut fields).unwrap(), identity.comment());
        }
        assert!(fields.is_empty());
    }

    #[test]
    fn signs_ed25519_requests_and_rejects_nonzero_flags() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let identity = Identity::new(key, "ed25519").unwrap();
        let message = b"bounded agent protocol vector";

        let signed = signature(&handle_frame(
            &sign_request(identity.public_blob(), message, 0),
            std::slice::from_ref(&identity),
        ));
        assert_eq!(signed.algorithm(), Algorithm::Ed25519);
        Verifier::verify(identity.public_key(), message, &signed).unwrap();

        let rejected = handle_frame(
            &sign_request(identity.public_blob(), message, RSA_SHA2_256),
            &[identity],
        );
        assert_eq!(response_payload(&rejected), &[FAILURE]);
    }

    #[test]
    fn signs_rsa_with_exactly_the_requested_sha2_algorithm() {
        let key = PrivateKey::from(RsaKeypair::random(&mut OsRng, 2048).unwrap());
        let identity = Identity::new(key, "rsa").unwrap();
        let message = b"rsa protocol vector";

        for (flags, hash) in [
            (RSA_SHA2_256, HashAlg::Sha256),
            (RSA_SHA2_512, HashAlg::Sha512),
        ] {
            let signed = signature(&handle_frame(
                &sign_request(identity.public_blob(), message, flags),
                std::slice::from_ref(&identity),
            ));
            assert_eq!(signed.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            Verifier::verify(identity.public_key(), message, &signed).unwrap();
        }

        for flags in [0, RSA_SHA2_256 | RSA_SHA2_512, 8] {
            let rejected = handle_frame(
                &sign_request(identity.public_blob(), message, flags),
                std::slice::from_ref(&identity),
            );
            assert_eq!(response_payload(&rejected), &[FAILURE]);
        }
    }

    #[test]
    fn malformed_and_disallowed_requests_receive_only_bounded_failure() {
        let cases = [
            Vec::new(),
            vec![0, 0, 0, 2, REQUEST_IDENTITIES],
            frame(&[REQUEST_IDENTITIES, 0]),
            frame(&[17]),
            frame(&[18]),
            frame(&[19]),
            frame(&[20]),
            frame(&[21]),
            frame(&[22]),
            frame(&[23]),
            frame(&[25]),
            frame(&[26]),
            frame(&[27, 0, 0, 0, 1, 0xff]),
            frame(&[255]),
        ];

        for request in cases {
            assert_eq!(response_payload(&handle_frame(&request, &[])), &[FAILURE]);
        }
    }

    #[test]
    fn lengths_are_rejected_before_body_allocation_or_parsing() {
        let oversized_header = u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_be_bytes();
        assert_eq!(
            response_payload(&handle_frame(&oversized_header, &[])),
            &[FAILURE]
        );

        let mut invalid_string = vec![SIGN_REQUEST];
        invalid_string.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            response_payload(&handle_frame(&frame(&invalid_string), &[])),
            &[FAILURE]
        );

        let mut unknown_key = vec![SIGN_REQUEST];
        string(b"not an advertised public key", &mut unknown_key);
        string(b"message", &mut unknown_key);
        0_u32.encode(&mut unknown_key).unwrap();
        assert_eq!(
            response_payload(&handle_frame(&frame(&unknown_key), &[])),
            &[FAILURE]
        );

        unknown_key.push(0);
        assert_eq!(
            response_payload(&handle_frame(&frame(&unknown_key), &[])),
            &[FAILURE]
        );
    }
    fn session_bind(name: &[u8], forwarding: u8, trailing: &[u8]) -> Vec<u8> {
        let mut payload = vec![27];
        string(name, &mut payload);
        string(b"host key blob", &mut payload);
        string(b"session identifier", &mut payload);
        string(b"host signature", &mut payload);
        payload.push(forwarding);
        payload.extend_from_slice(trailing);
        frame(&payload)
    }

    fn bound(session_id: &[u8], host_key: &[u8]) -> SessionBinding {
        SessionBinding {
            session_id: session_id.to_vec(),
            host_key: host_key_fingerprint(host_key),
        }
    }

    #[test]
    fn session_bind_is_read_for_its_forwarding_flag_and_bound_host() {
        let binding = bound(b"session identifier", b"host key blob");
        assert_eq!(
            decode_request(&session_bind(b"session-bind@openssh.com", 0, b"")),
            Some(AgentRequest::SessionBind {
                forwarding: false,
                binding: binding.clone()
            })
        );
        assert_eq!(
            decode_request(&session_bind(b"session-bind@openssh.com", 1, b"")),
            Some(AgentRequest::SessionBind {
                forwarding: true,
                binding
            })
        );
        assert_eq!(
            response_payload(&handle_frame(
                &session_bind(b"session-bind@openssh.com", 1, b""),
                &[]
            )),
            &[SUCCESS]
        );

        // Other extensions, a non-boolean flag or a trailing byte all fail.
        for malformed in [
            session_bind(b"restrict-destination-v00@openssh.com", 1, b""),
            session_bind(b"session-bind@openssh.com", 2, b""),
            session_bind(b"session-bind@openssh.com", 1, b"x"),
        ] {
            assert_eq!(decode_request(&malformed), None);
            assert_eq!(response_payload(&handle_frame(&malformed, &[])), &[FAILURE]);
        }
    }

    fn sshsig(namespace: &[u8], hash: &[u8]) -> Vec<u8> {
        let mut data = b"SSHSIG".to_vec();
        string(namespace, &mut data);
        string(b"", &mut data);
        string(hash, &mut data);
        string(&[0xab; 32], &mut data);
        data
    }

    fn userauth(user: &[u8], method: &[u8], key: &[u8], host_key: Option<&[u8]>) -> Vec<u8> {
        let mut data = Vec::new();
        string(&[7; 32], &mut data);
        data.push(50);
        string(user, &mut data);
        string(b"ssh-connection", &mut data);
        string(method, &mut data);
        data.push(1);
        string(b"ssh-ed25519", &mut data);
        string(key, &mut data);
        if let Some(host_key) = host_key {
            string(host_key, &mut data);
        }
        data
    }

    #[test]
    fn host_key_fingerprints_match_ssh_keygen() {
        // `ssh-keygen -lf` on this ed25519 host key prints this fingerprint.
        let blob = [
            0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0,
            32,
        ]
        .iter()
        .copied()
        .chain([0x42; 32])
        .collect::<Vec<u8>>();
        assert_eq!(
            host_key_fingerprint(&blob),
            "SHA256:LgZpRzWEAbVvBimxTv69/UB88PD8jyOSDqfozr+iNX0"
        );
    }

    #[test]
    fn sign_requests_are_classified_by_what_they_sign() {
        let key = b"the requested key";
        assert_eq!(
            classify_sign(key, &sshsig(b"git", b"sha512"), &[]),
            SignKind::SshSig {
                namespace: "git".into()
            }
        );
        assert_eq!(
            classify_sign(key, &userauth(b"git", b"publickey", key, None), &[]),
            SignKind::UserAuth {
                user: "git".into(),
                host: String::new()
            }
        );
        assert_eq!(
            classify_sign(
                key,
                &userauth(
                    b"deploy",
                    b"publickey-hostbound-v00@openssh.com",
                    key,
                    Some(b"server host key")
                ),
                &[]
            ),
            SignKind::UserAuth {
                user: "deploy".into(),
                host: host_key_fingerprint(b"server host key")
            }
        );

        let mut trailing = sshsig(b"git", b"sha512");
        trailing.push(0);
        let unrecognised = [
            b"payload".to_vec(),
            trailing,
            sshsig(b"", b"sha512"),
            sshsig(b"git", b"md5"),
            sshsig(b"git\n", b"sha512"),
            sshsig(&[b'n'; 257], b"sha512"),
            sshsig(&[0xff, 0xfe], b"sha512"),
            // A login for a different key than the one asked to sign it.
            userauth(b"git", b"publickey", b"another key", None),
            // Host-bound without the host key, and a method that is not one.
            userauth(b"git", b"publickey-hostbound-v00@openssh.com", key, None),
            userauth(b"git", b"password", key, None),
        ];
        for data in unrecognised {
            assert_eq!(classify_sign(key, &data, &[]), SignKind::Other);
        }
    }

    #[test]
    fn a_login_goes_to_the_host_its_session_was_bound_to() {
        let key = b"the requested key";
        let login = userauth(b"git", b"publickey", key, None);
        let binds = [
            bound(&[9; 32], b"first hop host key"),
            bound(&[7; 32], b"github host key"),
        ];
        assert_eq!(
            classify_sign(key, &login, &binds),
            SignKind::UserAuth {
                user: "git".into(),
                host: host_key_fingerprint(b"github host key")
            }
        );

        // A bind for another session says nothing about this login.
        assert_eq!(
            classify_sign(key, &login, &binds[..1]),
            SignKind::UserAuth {
                user: "git".into(),
                host: String::new()
            }
        );

        // Host-bound logins must name the host their session is bound to.
        let hostbound = |host: &[u8]| {
            userauth(
                b"git",
                b"publickey-hostbound-v00@openssh.com",
                key,
                Some(host),
            )
        };
        assert_eq!(
            classify_sign(key, &hostbound(b"github host key"), &binds),
            SignKind::UserAuth {
                user: "git".into(),
                host: host_key_fingerprint(b"github host key")
            }
        );
        assert_eq!(
            classify_sign(key, &hostbound(b"some other host key"), &binds),
            SignKind::Other
        );
    }

    #[test]
    fn logins_to_different_hosts_are_different_kinds() {
        let to = |host: &str| SignKind::UserAuth {
            user: "git".into(),
            host: host.into(),
        };
        assert_ne!(to("SHA256:a"), to("SHA256:b"));
        assert_ne!(to("SHA256:a"), to(""));
        assert_eq!(to("SHA256:a").host(), "SHA256:a");
        assert_eq!(SignKind::Other.host(), "");
    }

    #[test]
    fn each_kind_names_its_operation_and_detail() {
        let sig = SignKind::SshSig {
            namespace: "git".into(),
        };
        assert_eq!((sig.operation(), sig.detail()), ("sshsig", "git"));
        let login = SignKind::UserAuth {
            user: "root".into(),
            host: String::new(),
        };
        assert_eq!((login.operation(), login.detail()), ("ssh-auth", "root"));
        assert_eq!(
            (SignKind::Other.operation(), SignKind::Other.detail()),
            ("ssh-sign", "")
        );
    }
}
