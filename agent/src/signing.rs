//! The two signing paths allowed by the v1 agent protocol.

use crate::rsa_keys;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::rand_core::CryptoRngCore;
use rsa::signature::RandomizedSigner;
use signature::{SignatureEncoding, Signer};
use ssh_key::{private::KeypairData, Algorithm, HashAlg, PrivateKey, Signature};
use std::fs::File;
use std::io::Read;
use zeroize::Zeroizing;

/// Sign `message` with the algorithm the agent-protocol flags select. Errors
/// are opaque: the wire has only a generic failure.
pub(crate) fn sign(key: &PrivateKey, message: &[u8], flags: u32) -> Option<Signature> {
    sign_with(key, message, flags, blinding_rng)
}

/// `sign`, with where an RSA signature's blinding randomness comes from
/// handed in, so a test can see that the signature drew on it. `random` is
/// asked only for an RSA request this agent signs, and before any private-key
/// work: if it has nothing to give, that one request fails.
fn sign_with<R: CryptoRngCore>(
    key: &PrivateKey,
    message: &[u8],
    flags: u32,
    random: impl FnOnce() -> Option<R>,
) -> Option<Signature> {
    match key.key_data() {
        KeypairData::Ed25519(_) if flags == 0 => key.try_sign(message).ok(),
        KeypairData::Rsa(_) if rsa_hash(flags).is_some() => {
            sign_rsa(key, message, flags, &mut random()?)
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

/// The blinding randomness of one RSA signature: ChaCha20, keyed with 32
/// bytes read from the kernel (`/dev/urandom`) before the private key is
/// touched. `None` when the device cannot be opened or read in full; the
/// request then fails like any other, unsigned.
///
/// Why not hand `rsa` the device itself: it draws through `rand`, whose
/// `fill` cannot report a failure (it panics on one, and release builds abort
/// on panic), and it draws an unbounded amount. Here the only read is the
/// seed, up front, where failing it fails one request; the generator cannot
/// fail after that. Read with `std`: `rand_core`'s `OsRng` needs its
/// `getrandom` feature, which nothing in this crate's release graph turns on.
fn blinding_rng() -> Option<ChaCha20Rng> {
    seeded(File::open("/dev/urandom").ok()?)
}

/// The seed is read whole or not at all (`read_exact` retries an interrupted
/// read and refuses a short one), and the buffer it is read into is wiped on
/// return. `rand_chacha` 0.3 has no wipe of its own: the generator's copy of
/// the key lasts until the memory of the signature it served is reused.
fn seeded(mut source: impl Read) -> Option<ChaCha20Rng> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    source.read_exact(&mut seed[..]).ok()?;
    Some(ChaCha20Rng::from_seed(*seed))
}

#[cfg(test)]
mod tests {
    use super::{blinding_rng, seeded, sign, sign_with};
    use crate::rsa_keys;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{CryptoRng, OsRng, RngCore};
    use signature::{SignatureEncoding, Signer, Verifier};
    use ssh_key::private::RsaKeypair;
    use ssh_key::{Algorithm, HashAlg, PrivateKey};
    use std::cell::Cell;

    const MESSAGE: &[u8] = b"agent sign request";

    /// A throwaway 2048-bit key, generated here; none is committed.
    fn rsa_key() -> (RsaKeypair, PrivateKey) {
        let keypair = RsaKeypair::random(&mut OsRng, rsa_keys::MIN_RSA_KEY_BITS).unwrap();
        let key = PrivateKey::from(keypair.clone());
        (keypair, key)
    }

    /// The real generator, adding what is drawn from it to `drawn`.
    struct Counting<'a> {
        inner: ChaCha20Rng,
        drawn: &'a Cell<usize>,
    }

    impl RngCore for Counting<'_> {
        fn next_u32(&mut self) -> u32 {
            self.drawn.set(self.drawn.get() + 4);
            self.inner.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            self.drawn.set(self.drawn.get() + 8);
            self.inner.next_u64()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.drawn.set(self.drawn.get() + dest.len());
            self.inner.fill_bytes(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for Counting<'_> {}

    /// `sign_with`, as `sign` calls it, reporting how often the random
    /// source was asked for and how many bytes the signature drew from it.
    fn sign_counting(key: &PrivateKey, flags: u32) -> (Option<ssh_key::Signature>, usize, usize) {
        let (asked, drawn) = (Cell::new(0), Cell::new(0));
        let signature = sign_with(key, MESSAGE, flags, || {
            asked.set(asked.get() + 1);
            blinding_rng().map(|inner| Counting {
                inner,
                drawn: &drawn,
            })
        });
        (signature, asked.get(), drawn.get())
    }

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

    /// The point of the change, at the function `sign` itself runs: for both
    /// RSA algorithms the random source is asked for once and the signature
    /// draws a blinding factor from it. If that path goes back to
    /// `Signer::try_sign`, or the locked `rsa` stops blinding, nothing is
    /// drawn and this fails; the bytes on the wire would not show it.
    #[test]
    fn signing_draws_an_rsa_blinding_factor_from_the_source_it_is_given() {
        let (_, key) = rsa_key();
        for flags in [2, 4] {
            let (signature, asked, drawn) = sign_counting(&key, flags);
            let signature = signature.expect("signed");
            Verifier::verify(key.public_key(), MESSAGE, &signature).unwrap();
            assert_eq!(sign(&key, MESSAGE, flags).unwrap(), signature);
            assert_eq!(asked, 1, "flags {flags}");
            assert!(
                drawn >= 128,
                "flags {flags}: {drawn} random bytes is no blinding factor for a 2048-bit key"
            );
        }
    }

    /// No seed, no RSA signature: with a random source that ends before the
    /// seed is whole, the one request fails, without a panic, and the private
    /// key is not used unblinded or under a constant seed instead.
    #[test]
    fn an_rsa_request_fails_when_the_seed_cannot_be_read() {
        let (_, key) = rsa_key();
        let asked = Cell::new(0);
        let signature = sign_with(&key, MESSAGE, 2, || {
            asked.set(asked.get() + 1);
            seeded(&[0xa5_u8; 31][..])
        });
        assert!(signature.is_none());
        assert_eq!(asked.get(), 1);
    }

    /// `ssh-rsa` (flags 0, SHA-1) and unknown flags stay refused, before the
    /// random source is asked for anything.
    #[test]
    fn rsa_requests_outside_the_two_sha2_flags_are_refused() {
        let (_, key) = rsa_key();
        for flags in [0, 1, 3, 6, 8, u32::MAX] {
            assert!(sign(&key, MESSAGE, flags).is_none(), "flags {flags}");
            let (signature, asked, drawn) = sign_counting(&key, flags);
            assert!(signature.is_none(), "flags {flags}");
            assert_eq!((asked, drawn), (0, 0), "flags {flags}");
        }
    }

    /// Ed25519 is untouched: the key's own signature, only for flags 0, and
    /// the random source is never asked.
    #[test]
    fn ed25519_signing_is_unchanged() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let signature = sign(&key, MESSAGE, 0).unwrap();
        assert_eq!(
            signature.as_bytes(),
            key.try_sign(MESSAGE).unwrap().as_bytes()
        );
        Verifier::verify(key.public_key(), MESSAGE, &signature).unwrap();
        for flags in [0, 2, 4] {
            let (signed, asked, drawn) = sign_counting(&key, flags);
            assert_eq!(signed.is_some(), flags == 0, "flags {flags}");
            assert_eq!((asked, drawn), (0, 0), "flags {flags}");
        }
    }
}
