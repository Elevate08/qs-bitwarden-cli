//! The two signing paths allowed by the v1 agent protocol.

use crate::rsa_keys;
use signature::{SignatureEncoding, Signer};
use ssh_key::{private::KeypairData, Algorithm, HashAlg, PrivateKey, Signature};

/// Sign `message` with the exact algorithm selected by agent-protocol flags.
///
/// Callers deliberately receive no underlying crypto error: errors can carry
/// parser or key context and the wire protocol has only a generic failure.
pub(crate) fn sign(key: &PrivateKey, message: &[u8], flags: u32) -> Option<Signature> {
    match key.key_data() {
        KeypairData::Ed25519(_) if flags == 0 => key.try_sign(message).ok(),
        KeypairData::Rsa(keypair) => {
            let hash = match flags {
                2 => HashAlg::Sha256,
                4 => HashAlg::Sha512,
                _ => return None,
            };
            let bytes = match rsa_keys::sha2_signing_key(keypair, hash).ok()? {
                rsa_keys::Sha2SigningKey::Sha256(signing) => {
                    signing.try_sign(message).ok()?.to_vec()
                }
                rsa_keys::Sha2SigningKey::Sha512(signing) => {
                    signing.try_sign(message).ok()?.to_vec()
                }
            };
            Signature::new(Algorithm::Rsa { hash: Some(hash) }, bytes).ok()
        }
        _ => None,
    }
}
