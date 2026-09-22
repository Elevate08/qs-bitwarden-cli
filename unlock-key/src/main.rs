//! Command-line face of the quick-unlock envelope. See `lib.rs`.
//!
//! The panel runs this inside short shell pipelines, between `secret-tool`,
//! `systemd-creds`, `argon2` and `fido2-assert`. Every secret arrives in the
//! environment; the envelope arrives on stdin; the result -- an envelope, the
//! password, or a secret-free summary -- leaves on stdout. No argument ever
//! carries a secret, because `/proc/<pid>/cmdline` is readable by everyone.
//!
//! Environment:
//!   QSBW_UNLOCK_PASSWORD  create: the password `bw` accepted
//!                         rotate: the new password `bw` accepted
//!   QSBW_UNLOCK_KEY       the key for --via / --auth: `argon2 -r` hex for
//!                         master and pin, `fido2-assert` base64 for fido,
//!                         unset for fingerprint
//!   QSBW_UNLOCK_NEW_KEY   create/rotate: `argon2 -r` hex of the password
//!                         add pin: `argon2 -r` hex of the PIN
//!                         add fido: `fido2-assert` base64 hmac-secret
//!
//! Exit status: 0 done, 2 usage, 3 wrong key, 4 malformed envelope,
//! 5 outside limits, 6 another account, 7 no such method, 8 internal.

use qs_bitwarden_unlock_key::{
    harden_process, key_from_base64, key_from_hex, Account, Argon2Params, Envelope, Error, Method,
    Via, ARGON2_MIN_ITERATIONS, ARGON2_MIN_MEMORY_KIB, KEY_LEN, MAX_ENVELOPE_BYTES,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use zeroize::Zeroizing;

const NAME: &str = "qs-bitwarden-unlock-key";
const PASSWORD_ENV: &str = "QSBW_UNLOCK_PASSWORD";
const KEY_ENV: &str = "QSBW_UNLOCK_KEY";
const NEW_KEY_ENV: &str = "QSBW_UNLOCK_NEW_KEY";

const EXIT_USAGE: i32 = 2;

fn exit_code(error: Error) -> i32 {
    match error {
        Error::WrongKey => 3,
        Error::Malformed => 4,
        Error::Policy => 5,
        Error::AccountMismatch => 6,
        Error::Missing => 7,
        Error::Internal => 8,
    }
}

fn describe(error: Error) -> &'static str {
    match error {
        Error::WrongKey => "the key does not open this envelope",
        Error::Malformed => "malformed envelope or key",
        Error::Policy => "outside the accepted limits",
        Error::AccountMismatch => "the envelope belongs to another account",
        Error::Missing => "no such unlock method in the envelope",
        Error::Internal => "internal error",
    }
}

enum Failure {
    Usage(&'static str),
    Envelope(Error),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Envelope(error)
    }
}

type Outcome = Result<Zeroizing<Vec<u8>>, Failure>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None | Some("--help" | "-h") if args.len() <= 1 => {
            print_help();
            if args.is_empty() {
                EXIT_USAGE
            } else {
                0
            }
        }
        Some("--version") if args.len() == 1 => {
            println!("{NAME} {} (envelope v1)", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("--self-test") if args.len() == 1 => self_test(),
        Some(command) => match harden_process() {
            Err(_) => {
                eprintln!("{NAME}: could not harden the process");
                exit_code(Error::Internal)
            }
            Ok(()) => finish(run(command, &args[1..])),
        },
        None => EXIT_USAGE,
    };
    std::process::exit(code);
}

fn finish(outcome: Outcome) -> i32 {
    match outcome {
        Ok(bytes) => {
            let mut stdout = std::io::stdout().lock();
            if stdout
                .write_all(&bytes)
                .and_then(|()| stdout.flush())
                .is_err()
            {
                return exit_code(Error::Internal);
            }
            0
        }
        Err(Failure::Usage(message)) => {
            eprintln!("{NAME}: {message}");
            EXIT_USAGE
        }
        Err(Failure::Envelope(error)) => {
            eprintln!("{NAME}: {}", describe(error));
            exit_code(error)
        }
    }
}

fn run(command: &str, rest: &[String]) -> Outcome {
    let flags = Flags::parse(rest)?;
    match command {
        "create" => create(&flags),
        "open" => open(&flags),
        "add" => add(&flags),
        "remove" => remove(&flags),
        "rotate" => rotate(&flags),
        "mark-stale" => mark_stale(&flags),
        "inspect" => inspect(&flags),
        _ => Err(Failure::Usage("unknown command; see --help")),
    }
}

fn create(flags: &Flags) -> Outcome {
    flags.only(&["account-id", "server", "salt", "m", "t", "p"])?;
    let password = secret_env(PASSWORD_ENV)?;
    let master_key = hex_env(NEW_KEY_ENV)?;
    let envelope = Envelope::create(flags.account()?, &password, flags.argon2()?, &master_key)?;
    Ok(envelope.to_json()?)
}

fn open(flags: &Flags) -> Outcome {
    flags.only(&["account-id", "server", "via", "cred"])?;
    let envelope = read_envelope(Some(&flags.account()?))?;
    let key = ViaKey::from_env(flags.required("via")?, flags.optional("cred"))?;
    Ok(envelope.open(&key.via())?)
}

fn add(flags: &Flags) -> Outcome {
    flags.only(&[
        "account-id",
        "server",
        "auth",
        "auth-cred",
        "method",
        "salt",
        "m",
        "t",
        "p",
        "cred",
        "rp",
        "fido-salt",
    ])?;
    let mut envelope = read_envelope(Some(&flags.account()?))?;
    let auth = ViaKey::from_env(flags.required("auth")?, flags.optional("auth-cred"))?;
    match flags.required("method")? {
        "pin" => {
            let pin_key = hex_env(NEW_KEY_ENV)?;
            envelope.add_pin(&auth.via(), flags.argon2()?, &pin_key)?;
        }
        "fingerprint" => envelope.add_fingerprint(&auth.via())?,
        "fido" => {
            let hmac = base64_env(NEW_KEY_ENV)?;
            envelope.add_fido(
                &auth.via(),
                flags.required("cred")?,
                flags.required("rp")?,
                flags.required("fido-salt")?,
                &hmac,
            )?;
        }
        _ => return Err(Failure::Usage("--method must be pin, fingerprint or fido")),
    }
    Ok(envelope.to_json()?)
}

fn remove(flags: &Flags) -> Outcome {
    flags.only(&["method", "cred"])?;
    let mut envelope = read_envelope(None)?;
    let method = match flags.required("method")? {
        "pin" => Method::Pin,
        "fingerprint" => Method::Fingerprint,
        "fido" => Method::Fido {
            credential: flags.required("cred")?,
        },
        _ => return Err(Failure::Usage("--method must be pin, fingerprint or fido")),
    };
    envelope.remove(&method)?;
    Ok(envelope.to_json()?)
}

fn rotate(flags: &Flags) -> Outcome {
    flags.only(&[
        "account-id",
        "server",
        "auth",
        "auth-cred",
        "salt",
        "m",
        "t",
        "p",
    ])?;
    let mut envelope = read_envelope(Some(&flags.account()?))?;
    let auth = ViaKey::from_env(flags.required("auth")?, flags.optional("auth-cred"))?;
    let password = secret_env(PASSWORD_ENV)?;
    let master_key = hex_env(NEW_KEY_ENV)?;
    envelope.rotate(&auth.via(), &password, flags.argon2()?, &master_key)?;
    Ok(envelope.to_json()?)
}

fn mark_stale(flags: &Flags) -> Outcome {
    flags.only(&[])?;
    let mut envelope = read_envelope(None)?;
    envelope.mark_stale();
    Ok(envelope.to_json()?)
}

fn inspect(flags: &Flags) -> Outcome {
    flags.only(&[])?;
    let envelope = read_envelope(None)?;
    serde_json::to_vec(&envelope.summary())
        .map(Zeroizing::new)
        .map_err(|_| Failure::Envelope(Error::Internal))
}

/// The key material for one --via / --auth, read from the environment.
struct ViaKey<'a> {
    kind: &'a str,
    credential: Option<&'a str>,
    key: Option<Zeroizing<[u8; KEY_LEN]>>,
}

impl<'a> ViaKey<'a> {
    fn from_env(kind: &'a str, credential: Option<&'a str>) -> Result<Self, Failure> {
        let (key, credential) = match kind {
            "master" | "pin" => (Some(hex_env(KEY_ENV)?), None),
            "fingerprint" => (None, None),
            "fido" => {
                let credential =
                    credential.ok_or(Failure::Usage("fido needs the credential id"))?;
                (Some(base64_env(KEY_ENV)?), Some(credential))
            }
            _ => {
                return Err(Failure::Usage(
                    "method must be master, pin, fingerprint or fido",
                ))
            }
        };
        Ok(Self {
            kind,
            credential,
            key,
        })
    }

    fn via(&self) -> Via<'_> {
        match (self.kind, self.key.as_deref(), self.credential) {
            ("master", Some(key), _) => Via::Master(key),
            ("pin", Some(key), _) => Via::Pin(key),
            ("fido", Some(key), Some(credential)) => Via::Fido {
                credential,
                hmac: key,
            },
            _ => Via::Fingerprint,
        }
    }
}

/// `--name value` pairs, each at most once.
struct Flags<'a>(HashMap<&'a str, &'a str>);

impl<'a> Flags<'a> {
    fn parse(args: &'a [String]) -> Result<Self, Failure> {
        let mut map = HashMap::new();
        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let name = flag
                .strip_prefix("--")
                .ok_or(Failure::Usage("expected --flag value pairs"))?;
            let value = iter
                .next()
                .ok_or(Failure::Usage("a flag is missing its value"))?;
            if map.insert(name, value.as_str()).is_some() {
                return Err(Failure::Usage("a flag was given twice"));
            }
        }
        Ok(Self(map))
    }

    /// Refuse anything the command does not take, so a typo is an error
    /// rather than a silently ignored option.
    fn only(&self, allowed: &[&str]) -> Result<(), Failure> {
        if self.0.keys().all(|name| allowed.contains(name)) {
            Ok(())
        } else {
            Err(Failure::Usage("unknown flag for this command; see --help"))
        }
    }

    fn required(&self, name: &str) -> Result<&'a str, Failure> {
        self.0
            .get(name)
            .copied()
            .ok_or(Failure::Usage("a required flag is missing; see --help"))
    }

    fn optional(&self, name: &str) -> Option<&'a str> {
        self.0.get(name).copied()
    }

    fn number(&self, name: &str) -> Result<u32, Failure> {
        self.required(name)?
            .parse()
            .map_err(|_| Failure::Usage("--m, --t and --p take whole numbers"))
    }

    fn account(&self) -> Result<Account, Failure> {
        Ok(Account::new(
            self.required("account-id")?,
            self.required("server")?,
        )?)
    }

    fn argon2(&self) -> Result<Argon2Params, Failure> {
        Ok(Argon2Params::new(
            self.required("salt")?,
            self.number("m")?,
            self.number("t")?,
            self.number("p")?,
        )?)
    }
}

fn read_envelope(account: Option<&Account>) -> Result<Envelope, Failure> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(u64::try_from(MAX_ENVELOPE_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Envelope(Error::Internal))?;
    let envelope = Envelope::parse(&bytes)?;
    if let Some(account) = account {
        envelope.check_account(account)?;
    }
    Ok(envelope)
}

fn secret_env(name: &str) -> Result<Zeroizing<Vec<u8>>, Failure> {
    std::env::var_os(name)
        .map(|value| Zeroizing::new(value.into_vec()))
        .filter(|value| !value.is_empty())
        .ok_or(Failure::Usage(
            "a required secret is missing from the environment",
        ))
}

fn hex_env(name: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, Failure> {
    let text = secret_env(name)?;
    let text = std::str::from_utf8(&text).map_err(|_| Failure::Envelope(Error::Malformed))?;
    Ok(key_from_hex(text)?)
}

fn base64_env(name: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, Failure> {
    let text = secret_env(name)?;
    let text = std::str::from_utf8(&text).map_err(|_| Failure::Envelope(Error::Malformed))?;
    Ok(key_from_base64(text)?)
}

/// One named self-test check.
type Check = (&'static str, fn() -> bool);

/// What the panel runs before trusting this binary: the process can be
/// hardened, the cipher round-trips, and wrong keys and edits are refused.
/// Random keys only; nothing is read from or written to the system.
fn self_test() -> i32 {
    let checks: [Check; 4] = [
        (
            "process hardening (RLIMIT_CORE=0, PR_SET_DUMPABLE=0)",
            || harden_process().is_ok(),
        ),
        ("envelope round trip through every method", round_trip),
        ("wrong keys and edited envelopes refused", refusals),
        (
            "key material decodes from argon2 and fido2-assert output",
            decoding,
        ),
    ];
    let mut failed = 0;
    for (name, check) in checks {
        let ok = check();
        println!("{}   {name}", if ok { "ok" } else { "FAIL" });
        if !ok {
            failed += 1;
        }
    }
    if failed == 0 {
        println!("ok: {} checks passed", checks.len());
        0
    } else {
        println!("FAIL: {failed} of {} checks failed", checks.len());
        1
    }
}

const TEST_SALT: &str = "c2VsZi10ZXN0LXNhbHQtMDE=";
const TEST_FIDO_SALT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const TEST_CRED: &str = "c2VsZi10ZXN0";

fn test_envelope() -> Option<Envelope> {
    let account = Account::new("self-test", "https://example.invalid").ok()?;
    let params =
        Argon2Params::new(TEST_SALT, ARGON2_MIN_MEMORY_KIB, ARGON2_MIN_ITERATIONS, 1).ok()?;
    let mut envelope = Envelope::create(
        account,
        b"self-test password",
        params.clone(),
        &[1; KEY_LEN],
    )
    .ok()?;
    envelope
        .add_pin(&Via::Master(&[1; KEY_LEN]), params, &[2; KEY_LEN])
        .ok()?;
    envelope.add_fingerprint(&Via::Master(&[1; KEY_LEN])).ok()?;
    envelope
        .add_fido(
            &Via::Master(&[1; KEY_LEN]),
            TEST_CRED,
            "pam://self-test",
            TEST_FIDO_SALT,
            &[3; KEY_LEN],
        )
        .ok()?;
    Envelope::parse(&envelope.to_json().ok()?).ok()
}

fn round_trip() -> bool {
    let Some(envelope) = test_envelope() else {
        return false;
    };
    [
        Via::Master(&[1; KEY_LEN]),
        Via::Pin(&[2; KEY_LEN]),
        Via::Fingerprint,
        Via::Fido {
            credential: TEST_CRED,
            hmac: &[3; KEY_LEN],
        },
    ]
    .iter()
    .all(|via| {
        envelope
            .open(via)
            .is_ok_and(|p| p.as_slice() == b"self-test password")
    })
}

fn refusals() -> bool {
    let Some(envelope) = test_envelope() else {
        return false;
    };
    let wrong = envelope.open(&Via::Master(&[9; KEY_LEN])) == Err(Error::WrongKey)
        && envelope.open(&Via::Pin(&[1; KEY_LEN])) == Err(Error::WrongKey);
    let Ok(json) = envelope.to_json() else {
        return false;
    };
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&json) else {
        return false;
    };
    value["account"]["id"] = serde_json::json!("someone-else");
    let edited = serde_json::to_vec(&value)
        .ok()
        .and_then(|bytes| Envelope::parse(&bytes).ok())
        .is_some_and(|e| e.open(&Via::Master(&[1; KEY_LEN])) == Err(Error::WrongKey));
    wrong && edited
}

fn decoding() -> bool {
    key_from_hex(&"ab".repeat(KEY_LEN)).is_ok_and(|k| k.iter().all(|b| *b == 0xab))
        && key_from_base64(TEST_FIDO_SALT).is_ok_and(|k| k[31] == 31)
        && key_from_hex("not hex").is_err()
}

fn print_help() {
    println!(
        "{NAME} <command> [--flag value]...

The master password encrypted once, for the Bitwarden panel's quick unlock.
Secrets come only from the environment; the envelope comes on stdin.

  create      --account-id --server --salt --m --t --p
  open        --account-id --server --via master|pin|fingerprint|fido [--cred]
  add         --account-id --server --auth <method> [--auth-cred] --method pin
                  --salt --m --t --p
              ... --method fingerprint
              ... --method fido --cred --rp --fido-salt
  remove      --method pin|fingerprint|fido [--cred]
  rotate      --account-id --server --auth <method> [--auth-cred] --salt --m --t --p
  mark-stale
  inspect
  --version | --self-test | --help"
    );
}
