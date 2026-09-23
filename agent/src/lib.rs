//! Headless SSH-agent companion for the qs-bitwarden-cli Quickshell panel.
//!
//! The panel owns `bw` and `BW_SESSION`; this process never sees either. It
//! receives decrypted private keys on a private FIFO, holds them only while
//! the vault is unlocked, and signs only against a live approval. It speaks
//! the SSH agent protocol on a per-user socket and the panel's NDJSON control
//! protocol on stdin/stdout. Every dependency was reviewed before pinning;
//! new ones need the same review.

use zeroize::ZeroizeOnDrop;

pub mod approvals;
pub mod control;
pub mod keystore;
pub mod lifecycle;
pub mod load;
pub mod peer;
pub mod protocol;
pub mod runtime;
pub mod selftest;
pub mod server;
mod signing;
pub mod state;

/// Compile-time proof that a private-key type zeroizes on drop. A function,
/// not a comment, because one crate's features anywhere in the graph could
/// turn the wipe into a plain deallocation; if a call stops compiling, the
/// keystore's lock semantics no longer hold.
pub fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

/// RSA signing keys, built here rather than through ssh-key.
///
/// ssh-key 0.6.7 (the latest release) passes `p` twice to
/// `RsaPrivateKey::from_components`, so its RSA keys fail validation. The fix
/// is unreleased. Building the key from the same components here avoids a
/// release-candidate dependency or a fork, and goes away with a fixed release.
///
pub mod rsa_keys {
    use rsa::pkcs1v15;
    use rsa::traits::PublicKeyParts;
    use rsa::BigUint;
    use ssh_key::private::RsaKeypair;
    use ssh_key::{Error, HashAlg, Result};

    /// The RSA private key for `keypair`, with p and q in order. It zeroizes
    /// on drop; callers must not clone it out of the keystore.
    pub fn private_key(keypair: &RsaKeypair) -> Result<rsa::RsaPrivateKey> {
        let key = rsa::RsaPrivateKey::from_components(
            BigUint::try_from(&keypair.public.n)?,
            BigUint::try_from(&keypair.public.e)?,
            BigUint::try_from(&keypair.private.d)?,
            vec![
                BigUint::try_from(&keypair.private.p)?,
                BigUint::try_from(&keypair.private.q)?,
            ],
        )
        .map_err(|_| Error::Crypto)?;

        // Below 2048 bits is a failed load, as in OpenSSH.
        if key.size().saturating_mul(8) < MIN_RSA_KEY_BITS {
            return Err(Error::Crypto);
        }
        Ok(key)
    }

    /// Smallest RSA modulus this agent will sign with, in bits.
    pub const MIN_RSA_KEY_BITS: usize = 2048;

    /// A PKCS#1 v1.5 signing key for `rsa-sha2-256` or `rsa-sha2-512`, chosen
    /// by the request's flags (the wrong one fails authentication).
    pub enum Sha2SigningKey {
        Sha256(pkcs1v15::SigningKey<sha2::Sha256>),
        Sha512(pkcs1v15::SigningKey<sha2::Sha512>),
    }

    /// Build the signing key the requested flag asks for.
    pub fn sha2_signing_key(keypair: &RsaKeypair, hash: HashAlg) -> Result<Sha2SigningKey> {
        let key = private_key(keypair)?;
        Ok(match hash {
            HashAlg::Sha256 => Sha2SigningKey::Sha256(pkcs1v15::SigningKey::new(key)),
            HashAlg::Sha512 => Sha2SigningKey::Sha512(pkcs1v15::SigningKey::new(key)),
            // HashAlg is non-exhaustive; nothing else is advertised.
            _ => return Err(Error::Crypto),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{assert_zeroize_on_drop, rsa_keys};
    use rand_core::OsRng;
    use signature::{SignatureEncoding, Signer, Verifier};
    use ssh_key::private::RsaKeypair;
    use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};
    use zeroize::Zeroizing;

    /// The secret types alive while unlocked: dalek's per-signature Ed25519
    /// key and the RSA private key. dalek zeroizes only with its `zeroize`
    /// feature, which this crate enables via a direct dependency; removing it
    /// makes this test fail to compile.
    #[test]
    fn every_private_key_representation_wipes_itself_on_drop() {
        assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
        assert_zeroize_on_drop::<rsa::RsaPrivateKey>();
    }

    /// Ed25519, used by nearly every Bitwarden SSH key.
    #[test]
    fn ed25519_keys_parse_sign_and_verify() {
        let generated = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        // Keys arrive as OpenSSH PEM text, held in a zeroizing buffer as the
        // loader does.
        let pem = Zeroizing::new(
            generated
                .to_openssh(Default::default())
                .unwrap()
                .to_string(),
        );
        let key = PrivateKey::from_openssh(pem.as_bytes()).unwrap();

        let signature = key.try_sign(b"agent sign request").unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
        // The Verifier trait, which the signing gate uses (not the inherent
        // SSHSIG `verify`).
        Verifier::verify(key.public_key(), b"agent sign request", &signature)
            .expect("a signature this agent produced must verify under the key it advertises");
        assert!(Verifier::verify(key.public_key(), b"a different payload", &signature).is_err());
    }

    /// RSA SHA-2, both flags, through this crate's key construction. 2048-bit
    /// keys keep the per-build test fast.
    #[test]
    fn rsa_keys_sign_under_both_sha2_flags() {
        let keypair = RsaKeypair::random(&mut OsRng, rsa_keys::MIN_RSA_KEY_BITS).unwrap();
        let key = PrivateKey::from(keypair.clone());

        let mut signatures = Vec::new();
        for hash in [HashAlg::Sha256, HashAlg::Sha512] {
            let signature = match rsa_keys::sha2_signing_key(&keypair, hash).unwrap() {
                rsa_keys::Sha2SigningKey::Sha256(signing) => {
                    signing.try_sign(b"agent sign request").unwrap().to_vec()
                }
                rsa_keys::Sha2SigningKey::Sha512(signing) => {
                    signing.try_sign(b"agent sign request").unwrap().to_vec()
                }
            };
            let signature = Signature::new(Algorithm::Rsa { hash: Some(hash) }, signature).unwrap();
            Verifier::verify(key.public_key(), b"agent sign request", &signature).unwrap_or_else(
                |_| panic!("an rsa-sha2 signature must verify under the advertised key: {hash:?}"),
            );
            assert!(
                Verifier::verify(key.public_key(), b"a different payload", &signature).is_err()
            );
            signatures.push(signature);
        }
        assert_ne!(
            signatures[0].as_bytes(),
            signatures[1].as_bytes(),
            "the two RSA SHA-2 algorithms must not produce the same signature"
        );
    }

    /// Why `rsa_keys` exists: ssh-key 0.6.7 cannot sign with RSA itself. When
    /// this starts passing, a fixed release is out and `rsa_keys` can go.
    #[test]
    fn ssh_key_0_6_7_still_cannot_sign_with_rsa_itself() {
        let keypair = RsaKeypair::random(&mut OsRng, rsa_keys::MIN_RSA_KEY_BITS).unwrap();
        let key = PrivateKey::from(keypair);
        assert!(
            key.try_sign(b"agent sign request").is_err(),
            "ssh-key can sign RSA again: drop the rsa_keys module and its ADR entry"
        );
    }

    /// v1 signs only Ed25519 and RSA SHA-2, enforced by what compiles in: with
    /// ssh-key's default features off, ECDSA has no signing implementation.
    #[test]
    fn algorithms_outside_v1_have_no_signing_path() {
        let unsupported = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        );
        assert!(
            unsupported.is_err(),
            "an algorithm v1 does not support must fail closed at key construction"
        );
    }
}
