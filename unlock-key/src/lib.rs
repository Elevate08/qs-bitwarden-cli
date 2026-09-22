//! The quick-unlock envelope: the master password encrypted once, and the key
//! that encrypts it wrapped separately for each way of unlocking.
//!
//! This is the one piece of quick unlock the operating system cannot do. The
//! panel composes the rest from system tools -- `systemd-creds` seals the whole
//! envelope to this machine and user, `argon2` derives a key from the master
//! password or the PIN, `fido2-assert` gets an `hmac-secret` from the key the
//! user touches, `secret-tool` stores the result -- and hands this code only
//! the derived key material, through the environment. Nothing here reads a
//! file, opens a socket, or runs a key derivation that takes a password.
//!
//! Layout, as JSON inside the systemd-creds seal:
//!
//! ```text
//! account   { id, server }                     bound into every AEAD below
//! stale     the password was changed elsewhere and not yet rotated in
//! ct        AEAD(DEK, master password)
//! wraps
//!   master       Argon2id(master password) -> KEK -> AEAD(KEK, DEK)
//!   pin          Argon2id(PIN)             -> KEK -> AEAD(KEK, DEK)
//!   fingerprint  the DEK itself: a finger releases no secret to wrap it with
//!   fido[]       hmac-secret               -> KEK -> AEAD(KEK, DEK)
//! ```
//!
//! The `master` wrap always exists: it is written the first time `bw` accepts
//! a typed password, and opening it is how every later change is authorized.

use base64ct::{Base64, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;
use zeroize::Zeroizing;

/// RLIMIT_CORE=0 and PR_SET_DUMPABLE=0, before the first secret is read, so a
/// crash leaves no core file and no same-UID process can ptrace this one.
/// The same hardening the SSH helper applies to itself.
pub fn harden_process() -> Result<()> {
    use rustix::process::{self, DumpableBehavior, Resource, Rlimit};
    process::setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| Error::Internal)?;
    process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|_| Error::Internal)
}

/// Compile-time proof that a type wipes its own memory when dropped. If a
/// call to this stops compiling, a secret buffer here has become a plain
/// allocation.
pub fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

/// Envelope format version.
pub const VERSION: u8 = 1;
/// Every key in the envelope, derived or random.
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Largest master password accepted. Bitwarden sets no hard limit; this is a
/// bound on what a caller can make this process allocate, far above any
/// password a person types.
pub const MAX_PASSWORD_BYTES: usize = 4096;
/// Largest envelope accepted on stdin.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
/// FIDO2 keys that can each hold a wrap. One per registered key is the
/// expected shape; this only stops the envelope growing without bound.
pub const MAX_FIDO_WRAPS: usize = 16;
/// Account id, server URL, relying party and similar text fields.
pub const MAX_TEXT_CHARS: usize = 1024;

/// Argon2id floor for any wrap this code will open or create: Bitwarden's own
/// Argon2 default (64 MiB, 3 passes), so a wrap of the master password is
/// never a cheaper place to guess it than the account itself.
pub const ARGON2_MIN_MEMORY_KIB: u32 = 64 * 1024;
pub const ARGON2_MIN_ITERATIONS: u32 = 3;
/// Ceilings, so a hostile envelope cannot make the panel's `argon2` run
/// consume the machine.
pub const ARGON2_MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
pub const ARGON2_MAX_ITERATIONS: u32 = 64;
pub const ARGON2_MAX_PARALLELISM: u32 = 16;
/// The Argon2 salt is the literal argument given to the `argon2` CLI, so it is
/// stored as that text. Base64 of 16-48 random bytes.
const ARGON2_SALT_MIN_CHARS: usize = 22;
const ARGON2_SALT_MAX_CHARS: usize = 64;
/// FIDO2 hmac-secret salts and outputs are exactly 32 bytes.
pub const FIDO_SALT_LEN: usize = 32;
/// A credential id from the pam-u2f authfile.
const MAX_CREDENTIAL_BYTES: usize = 1024;

const DOMAIN: &[u8] = b"qs-bitwarden-unlock-v1";

/// Opaque failures. Nothing here carries key material or parser detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Not an envelope this version understands.
    Malformed,
    /// Well-formed, but outside the limits above.
    Policy,
    /// Bound to a different Bitwarden account or server.
    AccountMismatch,
    /// The key supplied does not open what it was asked to open.
    WrongKey,
    /// No wrap of the kind asked for.
    Missing,
    /// The kernel random source or the cipher failed.
    Internal,
}

pub type Result<T> = std::result::Result<T, Error>;

type Key = Zeroizing<[u8; KEY_LEN]>;

/// Which Bitwarden account and server an envelope belongs to.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub id: String,
    pub server: String,
}

impl Account {
    pub fn new(id: &str, server: &str) -> Result<Self> {
        let account = Self {
            id: id.to_owned(),
            server: server.to_owned(),
        };
        account.validate()?;
        Ok(account)
    }

    fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(Error::Policy);
        }
        text_ok(&self.id)?;
        text_ok(&self.server)
    }
}

/// Argon2id parameters exactly as the `argon2` CLI was run with them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Argon2Params {
    pub alg: String,
    pub salt: String,
    /// Memory in KiB.
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Argon2Params {
    pub fn new(salt: &str, m: u32, t: u32, p: u32) -> Result<Self> {
        let params = Self {
            alg: "argon2id".to_owned(),
            salt: salt.to_owned(),
            m,
            t,
            p,
        };
        params.validate()?;
        Ok(params)
    }

    fn validate(&self) -> Result<()> {
        if self.alg != "argon2id" {
            return Err(Error::Malformed);
        }
        let salt_ok = (ARGON2_SALT_MIN_CHARS..=ARGON2_SALT_MAX_CHARS).contains(&self.salt.len())
            && self
                .salt
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        let cost_ok = (ARGON2_MIN_MEMORY_KIB..=ARGON2_MAX_MEMORY_KIB).contains(&self.m)
            && (ARGON2_MIN_ITERATIONS..=ARGON2_MAX_ITERATIONS).contains(&self.t)
            && (1..=ARGON2_MAX_PARALLELISM).contains(&self.p);
        if salt_ok && cost_ok {
            Ok(())
        } else {
            Err(Error::Policy)
        }
    }

    fn bind(&self) -> [Vec<u8>; 5] {
        [
            self.alg.as_bytes().to_vec(),
            self.salt.as_bytes().to_vec(),
            self.m.to_string().into_bytes(),
            self.t.to_string().into_bytes(),
            self.p.to_string().into_bytes(),
        ]
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sealed {
    n: String,
    c: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PasswordWrap {
    kdf: Argon2Params,
    n: String,
    c: String,
}

/// The DEK in the clear, protected only by the systemd-creds seal around the
/// whole envelope. Held in a buffer that wipes itself, and never printed.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FingerprintWrap {
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    k: Zeroizing<String>,
}

impl std::fmt::Debug for FingerprintWrap {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FingerprintWrap { k: <redacted> }")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FidoWrap {
    /// Credential id, base64, as the pam-u2f authfile records it.
    cred: String,
    /// Relying party the credential was registered for (`pam://<hostname>`).
    rp: String,
    /// hmac-secret salt, base64 of 32 bytes.
    salt: String,
    n: String,
    c: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Wraps {
    master: PasswordWrap,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pin: Option<PasswordWrap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<FingerprintWrap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fido: Vec<FidoWrap>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    v: u8,
    account: Account,
    #[serde(default)]
    stale: bool,
    ct: Sealed,
    wraps: Wraps,
}

/// How the DEK is reached for one operation.
pub enum Via<'a> {
    /// Argon2id output for the master password, 32 bytes.
    Master(&'a [u8; KEY_LEN]),
    /// Argon2id output for the PIN, 32 bytes.
    Pin(&'a [u8; KEY_LEN]),
    /// No secret: the DEK sits in the envelope.
    Fingerprint,
    /// The hmac-secret output from the key holding `credential`.
    Fido {
        credential: &'a str,
        hmac: &'a [u8; KEY_LEN],
    },
}

/// A quick-unlock method, named for removal.
pub enum Method<'a> {
    Pin,
    Fingerprint,
    Fido { credential: &'a str },
}

/// Everything about an envelope that is not secret: what the panel needs to
/// run `argon2` or `fido2-assert` before it can open anything.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct Summary {
    pub v: u8,
    pub account: Account,
    pub stale: bool,
    pub master: Argon2Params,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin: Option<Argon2Params>,
    pub fingerprint: bool,
    pub fido: Vec<FidoSummary>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct FidoSummary {
    pub cred: String,
    pub rp: String,
    pub salt: String,
}

impl Envelope {
    /// A new envelope for a password `bw` has just accepted: a fresh DEK, the
    /// password sealed under it, and the `master` wrap. No quick-unlock
    /// method is enabled yet.
    pub fn create(
        account: Account,
        password: &[u8],
        master: Argon2Params,
        master_key: &[u8; KEY_LEN],
    ) -> Result<Self> {
        account.validate()?;
        master.validate()?;
        password_ok(password)?;
        let dek = random_key()?;
        let ct = seal(&dek, password, &ct_aad(&account))?;
        let wrap = password_wrap(&account, "master", master, master_key, &dek)?;
        Ok(Self {
            v: VERSION,
            account,
            stale: false,
            ct,
            wraps: Wraps {
                master: wrap,
                pin: None,
                fingerprint: None,
                fido: Vec::new(),
            },
        })
    }

    /// Parse and fully validate. Anything that would be refused later is
    /// refused here.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Error::Policy);
        }
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> Result<()> {
        if self.v != VERSION {
            return Err(Error::Malformed);
        }
        self.account.validate()?;
        sealed_ok(&self.ct.n, &self.ct.c)?;
        password_wrap_ok(&self.wraps.master)?;
        if let Some(pin) = &self.wraps.pin {
            password_wrap_ok(pin)?;
        }
        if let Some(fingerprint) = &self.wraps.fingerprint {
            decode_key(&fingerprint.k)?;
        }
        if self.wraps.fido.len() > MAX_FIDO_WRAPS {
            return Err(Error::Policy);
        }
        for (index, wrap) in self.wraps.fido.iter().enumerate() {
            fido_fields_ok(&wrap.cred, &wrap.rp, &wrap.salt)?;
            sealed_ok(&wrap.n, &wrap.c)?;
            if self.wraps.fido[..index].iter().any(|w| w.cred == wrap.cred) {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| Error::Internal)
    }

    /// Refuse an envelope written for another account or server.
    pub fn check_account(&self, expected: &Account) -> Result<()> {
        if &self.account == expected {
            Ok(())
        } else {
            Err(Error::AccountMismatch)
        }
    }

    pub fn summary(&self) -> Summary {
        Summary {
            v: self.v,
            account: self.account.clone(),
            stale: self.stale,
            master: self.wraps.master.kdf.clone(),
            pin: self.wraps.pin.as_ref().map(|w| w.kdf.clone()),
            fingerprint: self.wraps.fingerprint.is_some(),
            fido: self
                .wraps
                .fido
                .iter()
                .map(|w| FidoSummary {
                    cred: w.cred.clone(),
                    rp: w.rp.clone(),
                    salt: w.salt.clone(),
                })
                .collect(),
        }
    }

    /// The master password, through one method.
    pub fn open(&self, via: &Via) -> Result<Zeroizing<Vec<u8>>> {
        let dek = self.dek(via)?;
        open(&dek, &self.ct.n, &self.ct.c, &ct_aad(&self.account))
    }

    fn dek(&self, via: &Via) -> Result<Key> {
        let account = &self.account;
        let opened = match via {
            Via::Master(input) => {
                let wrap = &self.wraps.master;
                let kek = derive_kek(input, "master")?;
                open(
                    &kek,
                    &wrap.n,
                    &wrap.c,
                    &wrap_aad(account, "master", &wrap.kdf),
                )?
            }
            Via::Pin(input) => {
                let wrap = self.wraps.pin.as_ref().ok_or(Error::Missing)?;
                let kek = derive_kek(input, "pin")?;
                open(&kek, &wrap.n, &wrap.c, &wrap_aad(account, "pin", &wrap.kdf))?
            }
            Via::Fingerprint => {
                let wrap = self.wraps.fingerprint.as_ref().ok_or(Error::Missing)?;
                return decode_key(&wrap.k);
            }
            Via::Fido { credential, hmac } => {
                let wrap = self
                    .wraps
                    .fido
                    .iter()
                    .find(|w| w.cred == *credential)
                    .ok_or(Error::Missing)?;
                let kek = derive_kek(hmac, "fido")?;
                open(&kek, &wrap.n, &wrap.c, &fido_aad(account, wrap))?
            }
        };
        key_from(&opened)
    }

    /// Enable or replace the PIN, authorized by `auth`.
    pub fn add_pin(
        &mut self,
        auth: &Via,
        params: Argon2Params,
        pin_key: &[u8; KEY_LEN],
    ) -> Result<()> {
        params.validate()?;
        let dek = self.dek(auth)?;
        self.wraps.pin = Some(password_wrap(&self.account, "pin", params, pin_key, &dek)?);
        Ok(())
    }

    /// Enable fingerprint unlock, authorized by `auth`.
    pub fn add_fingerprint(&mut self, auth: &Via) -> Result<()> {
        let dek = self.dek(auth)?;
        self.wraps.fingerprint = Some(FingerprintWrap {
            k: Zeroizing::new(Base64::encode_string(dek.as_ref())),
        });
        Ok(())
    }

    /// Enable or replace one FIDO2 credential, authorized by `auth`. `salt` is
    /// the one `hmac` was obtained with.
    pub fn add_fido(
        &mut self,
        auth: &Via,
        credential: &str,
        rp: &str,
        salt: &str,
        hmac: &[u8; KEY_LEN],
    ) -> Result<()> {
        fido_fields_ok(credential, rp, salt)?;
        let dek = self.dek(auth)?;
        let replacing = self.wraps.fido.iter().position(|w| w.cred == credential);
        if replacing.is_none() && self.wraps.fido.len() >= MAX_FIDO_WRAPS {
            return Err(Error::Policy);
        }
        let mut wrap = FidoWrap {
            cred: credential.to_owned(),
            rp: rp.to_owned(),
            salt: salt.to_owned(),
            n: String::new(),
            c: String::new(),
        };
        let kek = derive_kek(hmac, "fido")?;
        let sealed = seal(&kek, dek.as_ref(), &fido_aad(&self.account, &wrap))?;
        wrap.n = sealed.n;
        wrap.c = sealed.c;
        match replacing {
            Some(index) => self.wraps.fido[index] = wrap,
            None => self.wraps.fido.push(wrap),
        }
        Ok(())
    }

    /// Disable one method. Needs no secret: removing a way in cannot open
    /// anything. The `master` wrap is not a method and cannot be removed.
    pub fn remove(&mut self, method: &Method) -> Result<()> {
        match method {
            Method::Pin => self.wraps.pin.take().map(drop).ok_or(Error::Missing),
            Method::Fingerprint => self
                .wraps
                .fingerprint
                .take()
                .map(drop)
                .ok_or(Error::Missing),
            Method::Fido { credential } => {
                let index = self
                    .wraps
                    .fido
                    .iter()
                    .position(|w| w.cred == *credential)
                    .ok_or(Error::Missing)?;
                self.wraps.fido.remove(index);
                Ok(())
            }
        }
    }

    /// The password was changed elsewhere and a method has not yet supplied
    /// the DEK to rotate with.
    pub fn mark_stale(&mut self) {
        self.stale = true;
    }

    /// Re-seal for a new master password. `auth` reaches the unchanged DEK --
    /// the old password through `master`, or any method -- so every method's
    /// wrap stays valid.
    pub fn rotate(
        &mut self,
        auth: &Via,
        new_password: &[u8],
        master: Argon2Params,
        master_key: &[u8; KEY_LEN],
    ) -> Result<()> {
        password_ok(new_password)?;
        master.validate()?;
        let dek = self.dek(auth)?;
        self.ct = seal(&dek, new_password, &ct_aad(&self.account))?;
        self.wraps.master = password_wrap(&self.account, "master", master, master_key, &dek)?;
        self.stale = false;
        Ok(())
    }
}

fn password_wrap(
    account: &Account,
    purpose: &str,
    kdf: Argon2Params,
    input: &[u8; KEY_LEN],
    dek: &Key,
) -> Result<PasswordWrap> {
    let kek = derive_kek(input, purpose)?;
    let sealed = seal(&kek, dek.as_ref(), &wrap_aad(account, purpose, &kdf))?;
    Ok(PasswordWrap {
        kdf,
        n: sealed.n,
        c: sealed.c,
    })
}

/// One KEK per purpose, so an Argon2 output for the PIN can never open the
/// master wrap even if the two were somehow derived alike.
fn derive_kek(input: &[u8; KEY_LEN], purpose: &str) -> Result<Key> {
    let mut info = DOMAIN.to_vec();
    info.extend_from_slice(b" kek ");
    info.extend_from_slice(purpose.as_bytes());
    let mut kek = Zeroizing::new([0_u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, input)
        .expand(&info, kek.as_mut())
        .map_err(|_| Error::Internal)?;
    Ok(kek)
}

/// Associated data: the domain and each part, length-prefixed so no two
/// different lists of parts encode the same.
fn aad(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    for part in parts {
        out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn ct_aad(account: &Account) -> Vec<u8> {
    aad(&[
        b"password",
        account.id.as_bytes(),
        account.server.as_bytes(),
    ])
}

fn wrap_aad(account: &Account, purpose: &str, kdf: &Argon2Params) -> Vec<u8> {
    let bound = kdf.bind();
    let mut parts: Vec<&[u8]> = vec![
        b"wrap",
        purpose.as_bytes(),
        account.id.as_bytes(),
        account.server.as_bytes(),
    ];
    parts.extend(bound.iter().map(Vec::as_slice));
    aad(&parts)
}

fn fido_aad(account: &Account, wrap: &FidoWrap) -> Vec<u8> {
    aad(&[
        b"wrap",
        b"fido",
        account.id.as_bytes(),
        account.server.as_bytes(),
        wrap.cred.as_bytes(),
        wrap.rp.as_bytes(),
        wrap.salt.as_bytes(),
    ])
}

fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Internal)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Internal)?;
    let c = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Internal)?;
    Ok(Sealed {
        n: Base64::encode_string(&nonce),
        c: Base64::encode_string(&c),
    })
}

fn open(key: &Key, n: &str, c: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let nonce = Base64::decode_vec(n).map_err(|_| Error::Malformed)?;
    let c = Base64::decode_vec(c).map_err(|_| Error::Malformed)?;
    if nonce.len() != NONCE_LEN {
        return Err(Error::Malformed);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Internal)?;
    cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &c, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::WrongKey)
}

fn random_key() -> Result<Key> {
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    getrandom::getrandom(key.as_mut()).map_err(|_| Error::Internal)?;
    Ok(key)
}

fn key_from(bytes: &[u8]) -> Result<Key> {
    let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::Malformed)?;
    Ok(Zeroizing::new(array))
}

fn decode_key(text: &str) -> Result<Key> {
    let bytes = Zeroizing::new(Base64::decode_vec(text).map_err(|_| Error::Malformed)?);
    key_from(&bytes)
}

fn password_ok(password: &[u8]) -> Result<()> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        Err(Error::Policy)
    } else {
        Ok(())
    }
}

fn text_ok(text: &str) -> Result<()> {
    if text.chars().count() > MAX_TEXT_CHARS || text.chars().any(char::is_control) {
        Err(Error::Policy)
    } else {
        Ok(())
    }
}

fn sealed_ok(n: &str, c: &str) -> Result<()> {
    let nonce = Base64::decode_vec(n).map_err(|_| Error::Malformed)?;
    Base64::decode_vec(c).map_err(|_| Error::Malformed)?;
    if nonce.len() == NONCE_LEN {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

fn password_wrap_ok(wrap: &PasswordWrap) -> Result<()> {
    wrap.kdf.validate()?;
    sealed_ok(&wrap.n, &wrap.c)
}

fn fido_fields_ok(credential: &str, rp: &str, salt: &str) -> Result<()> {
    let cred = Base64::decode_vec(credential).map_err(|_| Error::Malformed)?;
    if cred.is_empty() || cred.len() > MAX_CREDENTIAL_BYTES {
        return Err(Error::Policy);
    }
    if rp.is_empty() {
        return Err(Error::Policy);
    }
    text_ok(rp)?;
    let salt = Base64::decode_vec(salt).map_err(|_| Error::Malformed)?;
    if salt.len() != FIDO_SALT_LEN {
        return Err(Error::Policy);
    }
    Ok(())
}

fn serialize_secret<S: Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

fn deserialize_secret<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// 32 bytes of key material from the environment, as hex -- the way
/// `argon2 -r` prints it.
pub fn key_from_hex(text: &str) -> Result<Key> {
    let text = text.trim();
    if text.len() != KEY_LEN * 2 {
        return Err(Error::Malformed);
    }
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

/// 32 bytes of key material from the environment, as base64 -- the way
/// `fido2-assert` prints an hmac-secret.
pub fn key_from_base64(text: &str) -> Result<Key> {
    decode_key(text.trim())
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> Account {
        Account::new("user-1", "https://vault.bitwarden.com").unwrap()
    }

    fn params(salt: &str) -> Argon2Params {
        Argon2Params::new(salt, ARGON2_MIN_MEMORY_KIB, ARGON2_MIN_ITERATIONS, 1).unwrap()
    }

    fn key(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    const SALT_A: &str = "c2FsdHNhbHRzYWx0c2FsdA==";
    const SALT_B: &str = "b3RoZXJzYWx0b3RoZXJzYWx0";
    const FIDO_SALT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const CRED: &str = "Y3JlZGVudGlhbC1pZA==";

    fn envelope() -> Envelope {
        Envelope::create(account(), b"correct horse", params(SALT_A), &key(1)).unwrap()
    }

    fn reparse(envelope: &Envelope) -> Envelope {
        Envelope::parse(&envelope.to_json().unwrap()).unwrap()
    }

    #[test]
    fn every_method_opens_the_one_stored_password() {
        let mut env = envelope();
        env.add_pin(&Via::Master(&key(1)), params(SALT_B), &key(2))
            .unwrap();
        env.add_fingerprint(&Via::Master(&key(1))).unwrap();
        env.add_fido(
            &Via::Master(&key(1)),
            CRED,
            "pam://host",
            FIDO_SALT,
            &key(3),
        )
        .unwrap();
        let env = reparse(&env);
        for via in [
            Via::Master(&key(1)),
            Via::Pin(&key(2)),
            Via::Fingerprint,
            Via::Fido {
                credential: CRED,
                hmac: &key(3),
            },
        ] {
            assert_eq!(env.open(&via).unwrap().as_slice(), b"correct horse");
        }
    }

    #[test]
    fn a_wrong_key_never_opens_anything() {
        let mut env = envelope();
        env.add_pin(&Via::Master(&key(1)), params(SALT_B), &key(2))
            .unwrap();
        env.add_fido(
            &Via::Master(&key(1)),
            CRED,
            "pam://host",
            FIDO_SALT,
            &key(3),
        )
        .unwrap();
        let mut wrong = [0_u8; KEY_LEN];
        for _ in 0..10_000 {
            getrandom::getrandom(&mut wrong).unwrap();
            assert_eq!(env.open(&Via::Master(&wrong)).unwrap_err(), Error::WrongKey);
            assert_eq!(env.open(&Via::Pin(&wrong)).unwrap_err(), Error::WrongKey);
            assert_eq!(
                env.open(&Via::Fido {
                    credential: CRED,
                    hmac: &wrong
                })
                .unwrap_err(),
                Error::WrongKey
            );
        }
        // Each purpose has its own KEK: the master password's Argon2 output
        // does not open the PIN wrap, nor the other way round.
        assert_eq!(env.open(&Via::Pin(&key(1))).unwrap_err(), Error::WrongKey);
        assert_eq!(
            env.open(&Via::Master(&key(2))).unwrap_err(),
            Error::WrongKey
        );
    }

    #[test]
    fn a_missing_method_is_missing_not_wrong() {
        let env = envelope();
        assert_eq!(env.open(&Via::Pin(&key(2))).unwrap_err(), Error::Missing);
        assert_eq!(env.open(&Via::Fingerprint).unwrap_err(), Error::Missing);
        assert_eq!(
            env.open(&Via::Fido {
                credential: CRED,
                hmac: &key(3)
            })
            .unwrap_err(),
            Error::Missing
        );
    }

    #[test]
    fn adding_a_method_needs_a_key_that_opens_the_envelope() {
        let mut env = envelope();
        assert_eq!(
            env.add_pin(&Via::Master(&key(9)), params(SALT_B), &key(2))
                .unwrap_err(),
            Error::WrongKey
        );
        assert_eq!(
            env.add_fingerprint(&Via::Master(&key(9))).unwrap_err(),
            Error::WrongKey
        );
        assert!(env.summary().pin.is_none());
        assert!(!env.summary().fingerprint);
    }

    #[test]
    fn a_flipped_byte_anywhere_fails() {
        let mut env = envelope();
        env.add_pin(&Via::Master(&key(1)), params(SALT_B), &key(2))
            .unwrap();
        env.add_fido(
            &Via::Master(&key(1)),
            CRED,
            "pam://host",
            FIDO_SALT,
            &key(3),
        )
        .unwrap();
        let fields = [
            env.ct.c.clone(),
            env.ct.n.clone(),
            env.wraps.master.c.clone(),
            env.wraps.pin.as_ref().unwrap().c.clone(),
            env.wraps.fido[0].c.clone(),
        ];
        for (index, field) in fields.iter().enumerate() {
            let mut raw = Base64::decode_vec(field).unwrap();
            for position in [0, raw.len() / 2, raw.len() - 1] {
                raw[position] ^= 1;
                let mut bad = env.clone();
                let text = Base64::encode_string(&raw);
                match index {
                    0 => bad.ct.c = text,
                    1 => bad.ct.n = text,
                    2 => bad.wraps.master.c = text,
                    3 => bad.wraps.pin.as_mut().unwrap().c = text,
                    _ => bad.wraps.fido[0].c = text,
                }
                raw[position] ^= 1;
                let via = match index {
                    3 => Via::Pin(&key(2)),
                    4 => Via::Fido {
                        credential: CRED,
                        hmac: &key(3),
                    },
                    _ => Via::Master(&key(1)),
                };
                assert_eq!(
                    bad.open(&via).unwrap_err(),
                    Error::WrongKey,
                    "field {index} @{position}"
                );
            }
        }
    }

    #[test]
    fn bound_fields_cannot_be_swapped() {
        let mut env = envelope();
        env.add_fido(
            &Via::Master(&key(1)),
            CRED,
            "pam://host",
            FIDO_SALT,
            &key(3),
        )
        .unwrap();

        // Another account or server: the AEAD fails even if the check below
        // were skipped.
        let mut other = env.clone();
        other.account.id = "user-2".into();
        assert_eq!(
            other.open(&Via::Master(&key(1))).unwrap_err(),
            Error::WrongKey
        );
        let mut other = env.clone();
        other.account.server = "https://vault.bitwarden.eu".into();
        assert_eq!(
            other.open(&Via::Master(&key(1))).unwrap_err(),
            Error::WrongKey
        );
        assert_eq!(
            env.check_account(&Account::new("user-2", "https://vault.bitwarden.com").unwrap()),
            Err(Error::AccountMismatch)
        );

        // Recorded Argon2 cost cannot be edited down behind the wrap's back.
        let mut weaker = env.clone();
        weaker.wraps.master.kdf.t = ARGON2_MIN_ITERATIONS + 1;
        assert_eq!(
            weaker.open(&Via::Master(&key(1))).unwrap_err(),
            Error::WrongKey
        );

        // Nor can a FIDO wrap be pointed at another relying party.
        let mut moved = env.clone();
        moved.wraps.fido[0].rp = "pam://elsewhere".into();
        assert_eq!(
            moved
                .open(&Via::Fido {
                    credential: CRED,
                    hmac: &key(3)
                })
                .unwrap_err(),
            Error::WrongKey
        );
    }

    #[test]
    fn rotation_keeps_every_method() {
        let mut env = envelope();
        env.add_pin(&Via::Master(&key(1)), params(SALT_B), &key(2))
            .unwrap();
        env.add_fido(
            &Via::Master(&key(1)),
            CRED,
            "pam://host",
            FIDO_SALT,
            &key(3),
        )
        .unwrap();
        env.mark_stale();
        assert!(reparse(&env).summary().stale);

        // A PIN unlock just produced the old password, which `bw` refused; the
        // user typed the new one. The PIN reaches the DEK.
        env.rotate(&Via::Pin(&key(2)), b"new password", params(SALT_B), &key(4))
            .unwrap();
        let env = reparse(&env);
        assert!(!env.summary().stale);
        assert_eq!(
            env.open(&Via::Master(&key(4))).unwrap().as_slice(),
            b"new password"
        );
        assert_eq!(
            env.open(&Via::Pin(&key(2))).unwrap().as_slice(),
            b"new password"
        );
        assert_eq!(
            env.open(&Via::Fido {
                credential: CRED,
                hmac: &key(3)
            })
            .unwrap()
            .as_slice(),
            b"new password"
        );
        assert_eq!(
            env.open(&Via::Master(&key(1))).unwrap_err(),
            Error::WrongKey
        );
    }

    #[test]
    fn removing_methods_leaves_the_master_wrap() {
        let mut env = envelope();
        env.add_pin(&Via::Master(&key(1)), params(SALT_B), &key(2))
            .unwrap();
        env.add_fingerprint(&Via::Master(&key(1))).unwrap();
        env.add_fido(
            &Via::Master(&key(1)),
            CRED,
            "pam://host",
            FIDO_SALT,
            &key(3),
        )
        .unwrap();
        env.remove(&Method::Pin).unwrap();
        env.remove(&Method::Fingerprint).unwrap();
        env.remove(&Method::Fido { credential: CRED }).unwrap();
        assert_eq!(env.remove(&Method::Pin).unwrap_err(), Error::Missing);
        let env = reparse(&env);
        let summary = env.summary();
        assert!(summary.pin.is_none() && !summary.fingerprint && summary.fido.is_empty());
        assert_eq!(
            env.open(&Via::Master(&key(1))).unwrap().as_slice(),
            b"correct horse"
        );
    }

    #[test]
    fn re_adding_a_fido_credential_replaces_it() {
        let mut env = envelope();
        env.add_fido(
            &Via::Master(&key(1)),
            CRED,
            "pam://host",
            FIDO_SALT,
            &key(3),
        )
        .unwrap();
        env.add_fido(
            &Via::Master(&key(1)),
            CRED,
            "pam://host",
            FIDO_SALT,
            &key(5),
        )
        .unwrap();
        assert_eq!(env.summary().fido.len(), 1);
        let old = Via::Fido {
            credential: CRED,
            hmac: &key(3),
        };
        assert_eq!(env.open(&old).unwrap_err(), Error::WrongKey);
    }

    #[test]
    fn limits_are_enforced() {
        assert_eq!(
            Argon2Params::new(SALT_A, ARGON2_MIN_MEMORY_KIB - 1, 3, 1).unwrap_err(),
            Error::Policy
        );
        assert_eq!(
            Argon2Params::new(SALT_A, ARGON2_MIN_MEMORY_KIB, 2, 1).unwrap_err(),
            Error::Policy
        );
        assert_eq!(
            Argon2Params::new("short", ARGON2_MIN_MEMORY_KIB, 3, 1).unwrap_err(),
            Error::Policy
        );
        assert_eq!(
            Argon2Params::new("has a space in it, not base64", ARGON2_MIN_MEMORY_KIB, 3, 1)
                .unwrap_err(),
            Error::Policy
        );
        assert_eq!(
            Envelope::create(account(), b"", params(SALT_A), &key(1)).unwrap_err(),
            Error::Policy
        );
        assert_eq!(
            Envelope::create(
                account(),
                &[b'x'; MAX_PASSWORD_BYTES + 1],
                params(SALT_A),
                &key(1)
            )
            .unwrap_err(),
            Error::Policy
        );
        assert_eq!(Account::new("", "x").unwrap_err(), Error::Policy);
        assert_eq!(Account::new("id\n", "x").unwrap_err(), Error::Policy);

        let mut env = envelope();
        assert_eq!(
            env.add_fido(
                &Via::Master(&key(1)),
                CRED,
                "pam://host",
                "c2hvcnQ=",
                &key(3)
            )
            .unwrap_err(),
            Error::Policy
        );

        // A recorded cost below the floor is refused at parse time, so the
        // panel never runs a weakened argon2 for it.
        let mut json: serde_json::Value = serde_json::from_slice(&env.to_json().unwrap()).unwrap();
        json["wraps"]["master"]["kdf"]["m"] = serde_json::json!(1024);
        assert_eq!(
            Envelope::parse(&serde_json::to_vec(&json).unwrap()).unwrap_err(),
            Error::Policy
        );

        for index in 0..MAX_FIDO_WRAPS {
            let cred = Base64::encode_string(format!("cred-{index}").as_bytes());
            env.add_fido(
                &Via::Master(&key(1)),
                &cred,
                "pam://host",
                FIDO_SALT,
                &key(3),
            )
            .unwrap();
        }
        assert_eq!(
            env.add_fido(
                &Via::Master(&key(1)),
                CRED,
                "pam://host",
                FIDO_SALT,
                &key(3)
            )
            .unwrap_err(),
            Error::Policy
        );
    }

    #[test]
    fn unknown_fields_and_versions_are_refused() {
        let env = envelope();
        let mut json: serde_json::Value = serde_json::from_slice(&env.to_json().unwrap()).unwrap();
        json["extra"] = serde_json::json!(1);
        assert_eq!(
            Envelope::parse(&serde_json::to_vec(&json).unwrap()).unwrap_err(),
            Error::Malformed
        );
        let mut json: serde_json::Value = serde_json::from_slice(&env.to_json().unwrap()).unwrap();
        json["v"] = serde_json::json!(2);
        assert_eq!(
            Envelope::parse(&serde_json::to_vec(&json).unwrap()).unwrap_err(),
            Error::Malformed
        );
        assert_eq!(Envelope::parse(b"not json").unwrap_err(), Error::Malformed);
        assert_eq!(
            Envelope::parse(&vec![b' '; MAX_ENVELOPE_BYTES + 1]).unwrap_err(),
            Error::Policy
        );
    }

    #[test]
    fn the_summary_carries_no_secret() {
        let mut env = envelope();
        env.add_fingerprint(&Via::Master(&key(1))).unwrap();
        let summary = serde_json::to_string(&env.summary()).unwrap();
        let dek = env.wraps.fingerprint.as_ref().unwrap().k.to_string();
        assert!(!summary.contains(&dek));
        assert!(!summary.contains(&env.ct.c));
        assert!(!summary.contains(&env.wraps.master.c));
    }

    #[test]
    fn key_material_decodes_from_what_the_tools_print() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF";
        let decoded = key_from_hex(hex).unwrap();
        assert_eq!(decoded[0..2], [0x00, 0x11]);
        assert_eq!(decoded[31], 0xff);
        assert!(key_from_hex(&hex[..62]).is_err());
        assert!(key_from_hex(&hex.replace('0', "g")).is_err());
        assert_eq!(*key_from_base64(FIDO_SALT).unwrap(), {
            let mut expected = [0_u8; KEY_LEN];
            for (index, byte) in expected.iter_mut().enumerate() {
                *byte = index as u8;
            }
            expected
        });
        assert!(key_from_base64("c2hvcnQ=").is_err());
    }

    #[test]
    fn debug_output_never_shows_the_fingerprint_key() {
        let mut env = envelope();
        env.add_fingerprint(&Via::Master(&key(1))).unwrap();
        let dek = env.wraps.fingerprint.as_ref().unwrap().k.to_string();
        assert!(!format!("{env:?}").contains(&dek));
    }

    #[test]
    fn secret_buffers_wipe_themselves() {
        crate::assert_zeroize_on_drop::<Key>();
        crate::assert_zeroize_on_drop::<Zeroizing<Vec<u8>>>();
        crate::assert_zeroize_on_drop::<Zeroizing<String>>();
    }
}
