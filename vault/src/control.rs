//! The panel's requests, one JSON object per line on stdin. Strict: unknown
//! fields, types and versions are refused.

use serde::Deserialize;
use std::collections::BTreeMap;

pub const PROTOCOL: u8 = 1;
/// A save carries the item in `env`, and the list read's filter is the
/// longest script; 4 MiB is far past both.
pub const MAX_LINE: usize = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum Request {
    Hello {
        v: u8,
    },
    /// Run `argv` as the panel would, with `BW_SESSION` or a held secret
    /// added to its environment by name (`inject`), and deal with its stdout
    /// as `capture` says.
    Exec {
        v: u8,
        id: u64,
        argv: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, Option<String>>,
        #[serde(default)]
        inject: BTreeMap<String, String>,
        #[serde(default)]
        capture: Option<String>,
        #[serde(default)]
        stdin: Option<String>,
        /// Not tracked and not killed: outlives this helper (an unload's
        /// `bw lock`).
        #[serde(default)]
        detach: bool,
    },
    Kill {
        v: u8,
        id: u64,
    },
    /// Drop the session key, every item, and every held secret except those
    /// named in `keep` (a lock still running with its own copy of the key).
    Forget {
        v: u8,
        #[serde(default)]
        keep: Vec<String>,
    },
    /// Copy the session key into a named secret, so a run queued now (a
    /// lock) uses this key even after `forget` or a newer unlock.
    HoldSession {
        v: u8,
        name: String,
    },
    ForgetSecret {
        v: u8,
        name: String,
    },
    /// One item in full, for the detail and edit views.
    Item {
        v: u8,
        q: u64,
        id: String,
    },
    /// Put a login's password on the clipboard without it reaching the panel.
    CopyPassword {
        v: u8,
        q: u64,
        id: String,
        #[serde(rename = "clearSec")]
        clear_sec: u32,
    },
    Totp {
        v: u8,
        q: u64,
        id: String,
    },
    Search {
        v: u8,
        q: u64,
        query: String,
    },
    Shutdown {
        v: u8,
    },
}

impl Request {
    pub fn version(&self) -> u8 {
        match self {
            Self::Hello { v }
            | Self::Exec { v, .. }
            | Self::Kill { v, .. }
            | Self::Forget { v, .. }
            | Self::HoldSession { v, .. }
            | Self::ForgetSecret { v, .. }
            | Self::Item { v, .. }
            | Self::CopyPassword { v, .. }
            | Self::Totp { v, .. }
            | Self::Search { v, .. }
            | Self::Shutdown { v } => *v,
        }
    }
}

/// What to do with a run's stdout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Capture {
    /// Hand it to the panel.
    Plain,
    /// A session key (`bw unlock`, `bw login`, a remembered session): keep
    /// it; the panel learns only that there is one.
    Session,
    /// A vault read: keep the items, hand over the rest. Replaces the store.
    Vault,
    /// A saved item: as `Vault`, but updates only the items it names.
    VaultMerge,
    /// Keep stdout as a named secret.
    Secret(String),
}

impl Capture {
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value.unwrap_or("plain") {
            "plain" => Some(Self::Plain),
            "session" => Some(Self::Session),
            "vault" => Some(Self::Vault),
            "vaultMerge" => Some(Self::VaultMerge),
            other => other
                .strip_prefix("secret:")
                .filter(|name| valid_name(name))
                .map(|name| Self::Secret(name.to_owned())),
        }
    }
}

/// A held value an `inject` entry names: `session` or `secret:<name>`.
pub enum Source<'a> {
    Session,
    Secret(&'a str),
}

pub fn parse_source(value: &str) -> Option<Source<'_>> {
    if value == "session" {
        return Some(Source::Session);
    }
    value
        .strip_prefix("secret:")
        .filter(|name| valid_name(name))
        .map(Source::Secret)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.as_bytes()[0].is_ascii_digit()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn parse(line: &str) -> Result<Request, &'static str> {
    if line.len() > MAX_LINE {
        return Err("line too long");
    }
    let request: Request = serde_json::from_str(line).map_err(|_| "malformed request")?;
    if request.version() != PROTOCOL {
        return Err("wrong protocol version");
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_strict() {
        assert!(matches!(
            parse(r#"{"type":"hello","v":1}"#),
            Ok(Request::Hello { .. })
        ));
        assert!(parse(r#"{"type":"hello","v":2}"#).is_err());
        assert!(parse(r#"{"type":"hello","v":1,"extra":true}"#).is_err());
        assert!(parse(r#"{"type":"unknown","v":1}"#).is_err());
        let exec = parse(
            r#"{"type":"exec","v":1,"id":3,"argv":["bw","status"],"inject":{"BW_SESSION":"session"},"env":{"A":"b","C":null}}"#,
        );
        assert!(matches!(exec, Ok(Request::Exec { id: 3, .. })));
    }

    #[test]
    fn captures_and_sources() {
        assert_eq!(Capture::parse(None), Some(Capture::Plain));
        assert_eq!(
            Capture::parse(Some("secret:master")),
            Some(Capture::Secret("master".into()))
        );
        assert_eq!(Capture::parse(Some("secret:")), None);
        assert_eq!(Capture::parse(Some("secret:a b")), None);
        assert_eq!(Capture::parse(Some("other")), None);
        assert!(matches!(parse_source("session"), Some(Source::Session)));
        assert!(matches!(
            parse_source("secret:pw"),
            Some(Source::Secret("pw"))
        ));
        assert!(parse_source("pw").is_none());
        assert!(valid_env_name("BW_SESSION") && !valid_env_name("1A") && !valid_env_name("A=B"));
    }
}
