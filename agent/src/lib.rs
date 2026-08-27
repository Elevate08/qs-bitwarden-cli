//! Headless SSH-agent companion for the qs-bitwarden-cli Quickshell panel.
//!
//! The panel owns `bw` and `BW_SESSION`; this process never sees either. It
//! receives already-decrypted private keys on a private FIFO, holds them only
//! while the vault is unlocked, and signs only against a live approval. The
//! full design is in `docs/ideas/ssh-agent.md`, and the dependency set below is
//! justified in `docs/decisions/0001-ssh-agent-dependencies.md`.
//!
//! At this stage the crate is the dependency spike itself: it pins the crates
//! the agent will be built from and proves, in tests that need no vault, no
//! network, and no socket, that they can do the two things the design cannot
//! compromise on -- sign what v1 promises to sign, and wipe private key memory
//! when it is dropped.

use zeroize::ZeroizeOnDrop;

pub mod approvals;
pub mod control;
pub mod keystore;
pub mod lifecycle;
pub mod load;
pub mod peer;
pub mod protocol;
pub mod runtime;
pub mod server;
mod signing;
pub mod state;

/// Compile-time proof that a private-key representation wipes its own memory
/// when dropped.
///
/// Rust drops the value either way; what this asserts is that the drop is a
/// zeroizing one. It is a function rather than a comment because the property
/// depends on Cargo features resolved across the whole dependency graph -- one
/// crate anywhere in the tree can turn a wipe into a plain deallocation, and
/// nothing in the source of this crate would look any different afterwards.
/// If a call to this stops compiling, the keystore's lock semantics are no
/// longer true, whatever the documentation says.
pub fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

/// RSA signing keys, built here rather than through ssh-key.
///
/// ssh-key 0.6.7 -- the newest release; the 0.7 line has been in release
/// candidates since 2025 -- cannot produce a usable RSA private key. Its
/// `TryFrom<&RsaKeypair> for rsa::RsaPrivateKey` passes `p` twice where
/// `from_components` expects `p` and `q`, so the key fails validation and
/// every RSA signature returns an opaque error. The fix is on the project's
/// master branch and unreleased.
///
/// That leaves three options: ship a release candidate of a security
/// dependency, drop RSA from v1, or build the private key here from the same
/// components. This crate takes the third: it is a dozen lines against a
/// stable API, it needs no fork or patch section in Cargo.toml, and it drops
/// out the day a fixed 0.6.x or 0.7.0 is released. See
/// `docs/decisions/0001-ssh-agent-dependencies.md`.
pub mod rsa_keys {
    use rsa::pkcs1v15;
    use rsa::traits::PublicKeyParts;
    use rsa::BigUint;
    use ssh_key::private::RsaKeypair;
    use ssh_key::{Error, HashAlg, Result};

    /// The RSA private key for `keypair`, with p and q the right way round.
    ///
    /// The returned key zeroizes its own components on drop; the caller is
    /// responsible for not cloning it out of the keystore.
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

        // OpenSSH refuses RSA below 2048 bits and so does this agent; a
        // shorter key is a failed load, not a weaker signature.
        if key.size().saturating_mul(8) < MIN_RSA_KEY_BITS {
            return Err(Error::Crypto);
        }
        Ok(key)
    }

    /// Smallest RSA modulus this agent will sign with, in bits.
    pub const MIN_RSA_KEY_BITS: usize = 2048;

    /// A PKCS#1 v1.5 signing key for one of the two RSA SHA-2 algorithms.
    ///
    /// The hash is not a detail the agent gets to choose: `rsa-sha2-256` and
    /// `rsa-sha2-512` are distinct signature algorithms on the wire, selected
    /// by flags on the sign request, and answering with the other one is a
    /// failed authentication.
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
            // ssh-key's HashAlg is non-exhaustive; anything else is not an
            // algorithm this agent advertises.
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

    /// The two secret representations that exist while the vault is unlocked:
    /// the transient dalek signing key ssh-key builds for each Ed25519
    /// signature, and the RSA private key it converts into for each RSA one.
    ///
    /// dalek implements this only behind its `zeroize` feature, and ssh-key
    /// depends on dalek with default features off without asking for it. This
    /// crate names dalek as a direct dependency for that feature alone; drop
    /// that line from Cargo.toml and this test stops compiling rather than
    /// silently leaving 32 secret bytes in freed memory.
    #[test]
    fn every_private_key_representation_wipes_itself_on_drop() {
        assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
        assert_zeroize_on_drop::<rsa::RsaPrivateKey>();
    }

    /// Ed25519: the algorithm nearly every Bitwarden SSH key will use.
    #[test]
    fn ed25519_keys_parse_sign_and_verify() {
        let generated = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        // Private keys reach this process as OpenSSH PEM text on the FIFO, so
        // the test takes the same route in -- and holds the text the way the
        // loader will, in a buffer that wipes itself.
        let pem = Zeroizing::new(
            generated
                .to_openssh(Default::default())
                .unwrap()
                .to_string(),
        );
        let key = PrivateKey::from_openssh(pem.as_bytes()).unwrap();

        let signature = key.try_sign(b"agent sign request").unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
        // PublicKey's inherent `verify` is the namespaced SSHSIG one; the
        // agent path is the Verifier trait, named explicitly here so the test
        // exercises what the signing gate will call.
        Verifier::verify(key.public_key(), b"agent sign request", &signature)
            .expect("a signature this agent produced must verify under the key it advertises");
        assert!(Verifier::verify(key.public_key(), b"a different payload", &signature).is_err());
    }

    /// RSA SHA-2, both flags, through this crate's own key construction.
    ///
    /// The generated key is 2048 bits rather than ssh-key's 4096-bit default
    /// because this test runs on every build and key generation dominates it.
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

    /// The reason `rsa_keys` exists at all. ssh-key 0.6.7 builds its RSA
    /// private key from `p` twice instead of `p` and `q`, so its own signing
    /// path cannot sign anything. This test pins that failure: when it starts
    /// passing, a fixed ssh-key has been released and `rsa_keys` can go.
    #[test]
    fn ssh_key_0_6_7_still_cannot_sign_with_rsa_itself() {
        let keypair = RsaKeypair::random(&mut OsRng, rsa_keys::MIN_RSA_KEY_BITS).unwrap();
        let key = PrivateKey::from(keypair);
        assert!(
            key.try_sign(b"agent sign request").is_err(),
            "ssh-key can sign RSA again: drop the rsa_keys module and its ADR entry"
        );
    }

    /// v1 signs Ed25519 and RSA SHA-2 and nothing else, and that promise is
    /// kept by what compiles in rather than by a runtime check someone can
    /// forget: with ssh-key's default features off, an ECDSA key has no
    /// signing implementation to reach.
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
