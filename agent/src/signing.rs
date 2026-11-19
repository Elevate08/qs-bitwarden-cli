//! The two signing paths allowed by the v1 agent protocol.

use crate::rsa_keys;
use rsa::rand_core::{CryptoRng, CryptoRngCore, Error as RngError, RngCore};
use rsa::signature::RandomizedSigner;
use sha2::{Digest, Sha256};
use signature::{SignatureEncoding, Signer};
use ssh_key::{private::KeypairData, Algorithm, HashAlg, PrivateKey, Signature};
use std::fs::File;
use std::io::Read;
use zeroize::Zeroize;

/// Sign `message` with the algorithm the agent-protocol flags select. Errors
/// are opaque: the wire has only a generic failure.
pub(crate) fn sign(key: &PrivateKey, message: &[u8], flags: u32) -> Option<Signature> {
    sign_with(key, message, flags, BlindingRandom::from_kernel)
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

/// Bytes read from the kernel for one signature.
const SEED_LEN: usize = 64;

/// The blinding randomness of one RSA signature: a seed read from the
/// kernel (`/dev/urandom`) before the private key is touched, stretched as
/// SHA-256(label, seed, block number), block after block.
///
/// Why not read the device as `rsa` asks: it draws through `rand`, whose
/// `fill` cannot report a failure (it panics on one, and release builds abort
/// on panic), and it draws an unbounded amount, a modulus' worth again each
/// time its candidate is not below the modulus. A read failing in the middle
/// would have to end the helper, every key with it. Here the only read is
/// the seed, up front, where failing it fails one request; after that
/// nothing can fail: there is no panic path in this type. The block number
/// is 64 bits and a signature draws a few kilobytes.
///
/// `std` and `sha2` only: `rand_core`'s `OsRng` needs its `getrandom`
/// feature, which nothing in this crate's release graph turns on, and the
/// ChaCha generator in the graph is not a dependency of this crate.
struct BlindingRandom {
    seed: [u8; SEED_LEN],
    block: [u8; 32],
    /// Bytes of `block` already handed out; 32 when a new one is due.
    used: usize,
    next_block: u64,
}

impl BlindingRandom {
    /// `None` when the device cannot be opened or read in full; the request
    /// then fails like any other, unsigned.
    fn from_kernel() -> Option<Self> {
        Self::from_reader(File::open("/dev/urandom").ok()?)
    }

    /// The seed is read whole or not at all (`read_exact` retries an
    /// interrupted read and refuses a short one).
    fn from_reader(mut source: impl Read) -> Option<Self> {
        let mut random = Self {
            seed: [0; SEED_LEN],
            block: [0; 32],
            used: 32,
            next_block: 0,
        };
        source.read_exact(&mut random.seed).ok()?;
        Some(random)
    }
}

impl RngCore for BlindingRandom {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            if self.used == self.block.len() {
                let mut hash = Sha256::new();
                hash.update(b"qs-bitwarden-ssh-agent rsa blinding v1");
                hash.update(self.seed);
                hash.update(self.next_block.to_le_bytes());
                self.block = hash.finalize().into();
                self.next_block = self.next_block.wrapping_add(1);
                self.used = 0;
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for BlindingRandom {}

/// The seed gives every blinding factor of its signature, so it is wiped
/// with the block in hand when the signature is done (or was not made).
impl Drop for BlindingRandom {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.block.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{sign, sign_with, BlindingRandom, SEED_LEN};
    use crate::rsa_keys;
    use rand_core::{CryptoRng, OsRng, RngCore};
    use signature::{SignatureEncoding, Signer, Verifier};
    use ssh_key::private::RsaKeypair;
    use ssh_key::{Algorithm, HashAlg, PrivateKey};
    use std::cell::Cell;
    use std::io::{self, Read};

    const MESSAGE: &[u8] = b"agent sign request";

    /// A throwaway 2048-bit key, generated here; none is committed.
    fn rsa_key() -> (RsaKeypair, PrivateKey) {
        let keypair = RsaKeypair::random(&mut OsRng, rsa_keys::MIN_RSA_KEY_BITS).unwrap();
        let key = PrivateKey::from(keypair.clone());
        (keypair, key)
    }

    /// The real generator, adding what is drawn from it to `drawn`.
    struct Counting<'a> {
        inner: BlindingRandom,
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
            BlindingRandom::from_kernel().map(|inner| Counting {
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

    /// No randomness, no RSA signature: the one request fails, without a
    /// panic, and the private key is not used unblinded instead.
    #[test]
    fn an_rsa_request_fails_when_the_random_source_has_nothing() {
        let (_, key) = rsa_key();
        for flags in [2, 4] {
            let asked = Cell::new(0);
            let signature = sign_with(&key, MESSAGE, flags, || {
                asked.set(asked.get() + 1);
                None::<BlindingRandom>
            });
            assert!(signature.is_none(), "flags {flags}");
            assert_eq!(asked.get(), 1, "flags {flags}");
        }
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

    /// A reader that fails or ends after `good` bytes, optionally reporting
    /// one interrupted read first.
    struct Flaky {
        good: usize,
        interrupt: bool,
        error: bool,
    }

    impl Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.good == 0 {
                return if self.error {
                    Err(io::ErrorKind::Other.into())
                } else {
                    Ok(0)
                };
            }
            // One byte at a time: short reads are the rule, not the exception.
            buf[0] = 0xa5;
            self.good -= 1;
            Ok(1)
        }
    }

    /// The seed is read before any signing and whole or not at all: an
    /// error or an end of input part-way gives no generator (and so no
    /// signature), where the read used to be made mid-signature and a
    /// failure ended the helper. Short and interrupted reads are carried on
    /// from.
    #[test]
    fn a_seed_that_cannot_be_read_whole_gives_no_generator() {
        let source = |good, interrupt, error| Flaky {
            good,
            interrupt,
            error,
        };
        assert!(BlindingRandom::from_reader(source(SEED_LEN, true, false)).is_some());
        assert!(BlindingRandom::from_reader(source(SEED_LEN, false, true)).is_some());
        for good in [0, 1, SEED_LEN - 1] {
            assert!(BlindingRandom::from_reader(source(good, false, false)).is_none());
            assert!(BlindingRandom::from_reader(source(good, true, true)).is_none());
        }
        assert!(BlindingRandom::from_reader(io::empty()).is_none());

        // And a signature asked for with such a source fails, alone.
        let (_, key) = rsa_key();
        let failed = sign_with(&key, MESSAGE, 2, || {
            BlindingRandom::from_reader(source(SEED_LEN - 1, false, true))
        });
        assert!(failed.is_none());
        assert!(sign(&key, MESSAGE, 2).is_some());
    }

    /// The generator: the kernel's seed decides everything, two seeds give
    /// two streams, a stream does not repeat from block to block, and how it
    /// is drawn (bytes, words, across block ends) does not change it.
    #[test]
    fn the_blinding_generator_stretches_its_seed_into_one_stream() {
        let seeded = |seed: [u8; SEED_LEN]| BlindingRandom::from_reader(&seed[..]).unwrap();
        let mut whole = [0_u8; 200];
        seeded([7; SEED_LEN]).fill_bytes(&mut whole);

        let mut again = seeded([7; SEED_LEN]);
        let mut pieces = Vec::new();
        for len in [1, 31, 1, 32, 33, 0, 64] {
            let mut piece = vec![0_u8; len];
            again.try_fill_bytes(&mut piece).unwrap();
            pieces.extend(piece);
        }
        pieces.extend(again.next_u32().to_le_bytes());
        pieces.extend(again.next_u64().to_le_bytes());
        let mut rest = vec![0_u8; whole.len() - pieces.len()];
        again.fill_bytes(&mut rest);
        pieces.extend(rest);
        assert_eq!(pieces, whole);

        let mut other = [0_u8; 200];
        let mut seed = [7; SEED_LEN];
        seed[SEED_LEN - 1] = 8;
        seeded(seed).fill_bytes(&mut other);
        assert_ne!(other, whole);
        for block in 1..6 {
            assert_ne!(whole[..32], whole[block * 32..block * 32 + 32]);
        }
        assert_ne!(whole[..32], [0_u8; 32]);

        // From the kernel, two generators differ.
        let (mut first, mut second) = ([0_u8; 64], [0_u8; 64]);
        BlindingRandom::from_kernel()
            .expect("/dev/urandom opens")
            .fill_bytes(&mut first);
        BlindingRandom::from_kernel()
            .unwrap()
            .fill_bytes(&mut second);
        assert_ne!(first, second);
    }
}
