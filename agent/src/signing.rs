//! The two signing paths allowed by the v1 agent protocol.

use crate::rsa_keys;
use rsa::rand_core::{CryptoRng, CryptoRngCore, Error as RngError, RngCore};
use rsa::signature::RandomizedSigner;
use signature::{SignatureEncoding, Signer};
use ssh_key::{private::KeypairData, Algorithm, HashAlg, PrivateKey, Signature};
use std::fs::File;
use std::io::Read;

/// Sign `message` with the algorithm the agent-protocol flags select. Errors
/// are opaque: the wire has only a generic failure.
pub(crate) fn sign(key: &PrivateKey, message: &[u8], flags: u32) -> Option<Signature> {
    match key.key_data() {
        KeypairData::Ed25519(_) if flags == 0 => key.try_sign(message).ok(),
        // The flags are read before the kernel is asked for anything, so a
        // request this agent refuses costs no descriptor.
        KeypairData::Rsa(_) if rsa_hash(flags).is_some() => {
            sign_rsa(key, message, flags, &mut KernelRandom::open()?)
        }
        _ => None,
    }
}

/// `rsa-sha2-256` or `rsa-sha2-512`, by the request's flags. Flags 0 would be
/// `ssh-rsa` (SHA-1), which this agent does not sign.
fn rsa_hash(flags: u32) -> Option<HashAlg> {
    match flags {
        2 => Some(HashAlg::Sha256),
        4 => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// An RSA SHA-2 signature, blinded from `rng`; `None` for any other key.
///
/// `rsa` applies the private exponent to the padded digest itself unless it
/// is given a random source (`Signer::try_sign` passes none). With one
/// (`RandomizedSigner::try_sign_with_rng`) it multiplies the digest by a
/// fresh random factor first and divides it out after, so the time the
/// private operation takes is not a function of the digest and the key alone
/// (RUSTSEC-2023-0071). PKCS#1 v1.5 is deterministic, so the signature is the
/// same bytes either way.
fn sign_rsa(
    key: &PrivateKey,
    message: &[u8],
    flags: u32,
    rng: &mut impl CryptoRngCore,
) -> Option<Signature> {
    let KeypairData::Rsa(keypair) = key.key_data() else {
        return None;
    };
    let hash = rsa_hash(flags)?;
    let bytes = match rsa_keys::sha2_signing_key(keypair, hash).ok()? {
        rsa_keys::Sha2SigningKey::Sha256(signing) => {
            signing.try_sign_with_rng(rng, message).ok()?.to_vec()
        }
        rsa_keys::Sha2SigningKey::Sha512(signing) => {
            signing.try_sign_with_rng(rng, message).ok()?.to_vec()
        }
    };
    Signature::new(Algorithm::Rsa { hash: Some(hash) }, bytes).ok()
}

/// The kernel's random source, read from `/dev/urandom`: the blinding factor
/// of one RSA signature. Opened per signature and closed with it. `std` only:
/// `rand_core`'s own `OsRng` needs its `getrandom` feature, which nothing in
/// this crate's release graph turns on.
struct KernelRandom(File);

impl KernelRandom {
    /// `None` when the device cannot be opened; the request then fails like
    /// any other, unsigned.
    fn open() -> Option<Self> {
        File::open("/dev/urandom").ok().map(Self)
    }
}

impl RngCore for KernelRandom {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_ne_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_ne_bytes(bytes)
    }

    /// The trait cannot report a failure here, and a short or untouched
    /// buffer would be a blinding factor a server could guess. A read that
    /// fails ends the helper instead (release builds abort on panic), which
    /// drops every key.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.0.read_exact(dest).is_err() {
            panic!("the kernel random source could not be read");
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for KernelRandom {}

#[cfg(test)]
mod tests {
    use super::{sign, sign_rsa, KernelRandom};
    use crate::rsa_keys;
    use rand_core::{CryptoRng, OsRng, RngCore};
    use signature::{SignatureEncoding, Signer, Verifier};
    use ssh_key::private::RsaKeypair;
    use ssh_key::{Algorithm, HashAlg, PrivateKey};

    const MESSAGE: &[u8] = b"agent sign request";

    /// A throwaway 2048-bit key, generated here; none is committed.
    fn rsa_key() -> (RsaKeypair, PrivateKey) {
        let keypair = RsaKeypair::random(&mut OsRng, rsa_keys::MIN_RSA_KEY_BITS).unwrap();
        let key = PrivateKey::from(keypair.clone());
        (keypair, key)
    }

    /// The kernel source, counting what is drawn from it.
    struct Counting {
        inner: KernelRandom,
        bytes: usize,
    }

    impl Counting {
        fn new() -> Self {
            Self {
                inner: KernelRandom::open().expect("/dev/urandom opens"),
                bytes: 0,
            }
        }
    }

    impl RngCore for Counting {
        fn next_u32(&mut self) -> u32 {
            self.bytes += 4;
            self.inner.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            self.bytes += 8;
            self.inner.next_u64()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.bytes += dest.len();
            self.inner.fill_bytes(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for Counting {}

    /// What the agent hands a client verifies under the key it advertises,
    /// for both RSA SHA-2 algorithms, and names the algorithm asked for.
    #[test]
    fn a_blinded_rsa_signature_verifies_for_both_sha2_flags() {
        let (_, key) = rsa_key();
        for (flags, hash) in [(2, HashAlg::Sha256), (4, HashAlg::Sha512)] {
            let signature = sign(&key, MESSAGE, flags).expect("an RSA SHA-2 request is signed");
            assert_eq!(
                signature.algorithm(),
                Algorithm::Rsa { hash: Some(hash) },
                "flags {flags}"
            );
            Verifier::verify(key.public_key(), MESSAGE, &signature)
                .unwrap_or_else(|_| panic!("flags {flags}: the signature must verify"));
            assert!(
                Verifier::verify(key.public_key(), b"a different payload", &signature).is_err(),
                "flags {flags}"
            );
        }
    }

    /// Blinding changes how the signature is computed, not the signature: a
    /// client sees the bytes the unblinded path gave, every time.
    #[test]
    fn a_blinded_rsa_signature_is_the_bytes_of_an_unblinded_one() {
        let (keypair, key) = rsa_key();
        for (flags, hash) in [(2, HashAlg::Sha256), (4, HashAlg::Sha512)] {
            let unblinded = match rsa_keys::sha2_signing_key(&keypair, hash).unwrap() {
                rsa_keys::Sha2SigningKey::Sha256(signing) => {
                    signing.try_sign(MESSAGE).unwrap().to_vec()
                }
                rsa_keys::Sha2SigningKey::Sha512(signing) => {
                    signing.try_sign(MESSAGE).unwrap().to_vec()
                }
            };
            for round in 0..2 {
                let signature = sign(&key, MESSAGE, flags).unwrap();
                assert_eq!(
                    signature.as_bytes(),
                    unblinded.as_slice(),
                    "flags {flags}, round {round}"
                );
            }
        }
    }

    /// The point of the change: the locked `rsa` draws a blinding factor from
    /// the source it is handed. If it stops, signing is unblinded again and
    /// this fails.
    #[test]
    fn an_rsa_signature_draws_its_blinding_factor_from_the_random_source() {
        let (_, key) = rsa_key();
        for flags in [2, 4] {
            let mut rng = Counting::new();
            let signature = sign_rsa(&key, MESSAGE, flags, &mut rng).unwrap();
            Verifier::verify(key.public_key(), MESSAGE, &signature).unwrap();
            assert!(
                rng.bytes >= 128,
                "flags {flags}: {} random bytes is no blinding factor for a 2048-bit key",
                rng.bytes
            );
        }
    }

    /// `ssh-rsa` (flags 0, SHA-1) and unknown flags stay refused, before
    /// anything is drawn from the random source.
    #[test]
    fn rsa_requests_outside_the_two_sha2_flags_are_refused() {
        let (_, key) = rsa_key();
        for flags in [0, 1, 3, 6, 8, u32::MAX] {
            assert!(sign(&key, MESSAGE, flags).is_none(), "flags {flags}");
            let mut rng = Counting::new();
            assert!(
                sign_rsa(&key, MESSAGE, flags, &mut rng).is_none(),
                "flags {flags}"
            );
            assert_eq!(rng.bytes, 0, "flags {flags}");
        }
    }

    /// Ed25519 is untouched: the key's own signature, only for flags 0, and
    /// never through the RSA path.
    #[test]
    fn ed25519_signing_is_unchanged() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let signature = sign(&key, MESSAGE, 0).unwrap();
        assert_eq!(
            signature.as_bytes(),
            key.try_sign(MESSAGE).unwrap().as_bytes()
        );
        Verifier::verify(key.public_key(), MESSAGE, &signature).unwrap();
        assert!(sign(&key, MESSAGE, 2).is_none());
        assert!(sign(&key, MESSAGE, 4).is_none());
        let mut rng = Counting::new();
        assert!(sign_rsa(&key, MESSAGE, 2, &mut rng).is_none());
        assert_eq!(rng.bytes, 0);
    }

    /// The source is the kernel's, not a constant: two reads differ, and a
    /// buffer is filled whole.
    #[test]
    fn the_kernel_random_source_fills_buffers_differently() {
        let mut rng = KernelRandom::open().expect("/dev/urandom opens");
        let (mut first, mut second) = ([0_u8; 64], [0_u8; 64]);
        rng.fill_bytes(&mut first);
        rng.try_fill_bytes(&mut second).unwrap();
        assert_ne!(first, second);
        assert_ne!(first[..32], [0_u8; 32]);
        assert_ne!(first[32..], [0_u8; 32]);
        assert_ne!(rng.next_u64(), rng.next_u64());
    }
}
