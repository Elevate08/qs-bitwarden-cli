//! The unlocked vault as the panel must not hold it: the session key, named
//! secrets (a password on its way to `bw unlock` or a re-seal), and every
//! item in full. The panel gets each item with its secrets removed
//! (`strip_vault`) and asks for them one at a time.

use serde_json::{Map, Value};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Fields removed from every item before the panel sees it. Paths are
/// object keys from the item root.
const SECRET_PATHS: &[&[&str]] = &[
    &["login", "password"],
    &["login", "totp"],
    &["login", "fido2Credentials"],
    &["passwordHistory"],
    &["notes"],
    &["card", "code"],
    &["identity", "ssn"],
    &["identity", "passportNumber"],
    &["identity", "licenseNumber"],
];

/// A session key as `bw` prints one (BitwardenModel.js SESSION_TOKEN_RE).
pub fn is_session_token(value: &str) -> bool {
    value.len() >= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
}

/// The session key in `bw unlock`/`login` output, as extractSessionToken():
/// `export BW_SESSION="..."`, else the first line that is a key.
pub fn extract_session(raw: &str) -> Option<Zeroizing<String>> {
    let text = raw.trim();
    if let Some(at) = text.find("BW_SESSION=") {
        let rest = text[at + "BW_SESSION=".len()..].trim_start_matches('"');
        let value = rest.split(['"', '\n', '\r']).next().unwrap_or("").trim();
        if is_session_token(value) {
            return Some(Zeroizing::new(value.to_owned()));
        }
    }
    text.lines()
        .map(str::trim)
        .find(|line| is_session_token(line))
        .map(|line| Zeroizing::new(line.to_owned()))
}

struct Held {
    id: String,
    /// The item exactly as `bw` returned it (sanitized), for the detail and
    /// edit views and for copying.
    full: Zeroizing<String>,
    /// Lowercased search text, fields separated by NUL.
    haystack: Zeroizing<String>,
    /// A card number's digits, for the last-four search rule.
    card_digits: Zeroizing<String>,
}

#[derive(Default)]
pub struct Store {
    session: Option<Zeroizing<String>>,
    secrets: HashMap<String, Zeroizing<String>>,
    items: Vec<Held>,
    index: HashMap<String, usize>,
    /// Counts `forget`s. A run remembers the count it started under, and
    /// what it captured is dropped if the count has moved on: it belongs to
    /// a vault the panel has since locked, logged out of or switched away
    /// from.
    generation: u64,
}

impl Store {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn session(&self) -> Option<&str> {
        self.session.as_deref().map(String::as_str)
    }

    pub fn set_session(&mut self, key: Zeroizing<String>) {
        self.session = Some(key);
    }

    pub fn secret(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(|value| value.as_str())
    }

    pub fn set_secret(&mut self, name: String, value: Zeroizing<String>) {
        self.secrets.insert(name, value);
    }

    pub fn forget_secret(&mut self, name: &str) {
        self.secrets.remove(name);
    }

    /// Drops everything but the secrets named in `keep`: a lock, a logout
    /// or an account switch.
    pub fn forget(&mut self, keep: &[String]) {
        self.generation = self.generation.wrapping_add(1);
        self.session = None;
        self.secrets.retain(|name, _| keep.contains(name));
        self.items.clear();
        self.index.clear();
    }

    /// Drops one item, from search as well as from `item`.
    pub fn forget_item(&mut self, id: &str) {
        let Some(at) = self.index.remove(id) else {
            return;
        };
        self.items.remove(at);
        for (position, held) in self.items.iter().enumerate().skip(at) {
            self.index.insert(held.id.clone(), position);
        }
    }

    /// Copies the session key into the secret `name`; false if there is none.
    pub fn hold_session(&mut self, name: String) -> bool {
        let Some(key) = self.session.clone() else {
            return false;
        };
        self.secrets.insert(name, key);
        true
    }

    pub fn item(&self, id: &str) -> Option<&str> {
        self.index.get(id).map(|at| self.items[*at].full.as_str())
    }

    /// Ids whose search text contains `query`, in load order. Mirrors
    /// matchesQuery() in BitwardenModel.js, notes included.
    pub fn search(&self, query: &str) -> Vec<&str> {
        let needle = Zeroizing::new(query.trim().to_lowercase());
        if needle.is_empty() {
            return self.items.iter().map(|held| held.id.as_str()).collect();
        }
        let digits: Zeroizing<String> =
            Zeroizing::new(needle.chars().filter(char::is_ascii_digit).collect());
        self.items
            .iter()
            .filter(|held| {
                held.haystack.contains(needle.as_str())
                    || (!digits.is_empty()
                        && held.card_digits.len() >= 4
                        && held.card_digits[held.card_digits.len() - 4..].contains(digits.as_str()))
            })
            .map(|held| held.id.as_str())
            .collect()
    }

    /// Takes a sanitized vault read (`{sshCapability, items, sshKeys}`, the
    /// panel's jq filter output) and returns it with every secret removed.
    /// `replace` swaps the whole store (a list read); otherwise the items are
    /// added or updated (a save). `None`: not a vault read, forward as is.
    pub fn strip_vault(&mut self, raw: &str, replace: bool) -> Option<Zeroizing<String>> {
        let mut vault: Value = serde_json::from_str(raw).ok()?;
        let object = vault.as_object_mut()?;
        if replace {
            self.items.clear();
            self.index.clear();
        }
        if let Some(Value::Array(items)) = object.get_mut("items") {
            for item in items.iter_mut() {
                if let Value::Object(map) = item {
                    self.hold(map);
                    strip_item(map);
                }
            }
        }
        if let Some(Value::Array(keys)) = object.get("sshKeys") {
            for key in keys {
                if let Value::Object(map) = key {
                    // Public records only: held for search, nothing to strip.
                    self.hold(&mut map.clone());
                }
            }
        }
        let out = Zeroizing::new(serde_json::to_string(&vault).ok()?);
        wipe_value(&mut vault);
        Some(out)
    }

    fn hold(&mut self, item: &mut Map<String, Value>) {
        let Some(id) = item.get("id").and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let Ok(full) = serde_json::to_string(item) else {
            return;
        };
        let held = Held {
            haystack: haystack(item),
            card_digits: Zeroizing::new(
                text(item, &["card", "number"])
                    .chars()
                    .filter(char::is_ascii_digit)
                    .collect(),
            ),
            full: Zeroizing::new(full),
            id: id.clone(),
        };
        match self.index.get(&id) {
            Some(at) => self.items[*at] = held,
            None => {
                self.index.insert(id, self.items.len());
                self.items.push(held);
            }
        }
    }
}

fn get<'a>(item: &'a Map<String, Value>, path: &[&str]) -> Option<&'a Value> {
    let (last, parents) = path.split_last()?;
    let mut map = item;
    for key in parents {
        map = map.get(*key)?.as_object()?;
    }
    map.get(*last)
}

fn text<'a>(item: &'a Map<String, Value>, path: &[&str]) -> &'a str {
    get(item, path).and_then(Value::as_str).unwrap_or("")
}

fn present(item: &Map<String, Value>, path: &[&str]) -> bool {
    match get(item, path) {
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Null) | None => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(_) => true,
    }
}

/// What matchesQuery() compares, lowercased: name, username, notes, the
/// public key and fingerprint of an SSH record, card brand and holder, an
/// identity's name, email, username and company, and every website.
fn haystack(item: &Map<String, Value>) -> Zeroizing<String> {
    let mut parts: Vec<&str> = vec![
        text(item, &["name"]),
        text(item, &["login", "username"]),
        text(item, &["notes"]),
        text(item, &["publicKey"]),
        text(item, &["fingerprint"]),
        text(item, &["card", "brand"]),
        text(item, &["card", "cardholderName"]),
        text(item, &["identity", "email"]),
        text(item, &["identity", "username"]),
        text(item, &["identity", "company"]),
    ];
    let name: Vec<&str> = ["title", "firstName", "middleName", "lastName"]
        .iter()
        .map(|key| text(item, &["identity", key]).trim())
        .filter(|part| !part.is_empty())
        .collect();
    let full_name = name.join(" ");
    parts.push(&full_name);
    if let Some(Value::Array(uris)) = get(item, &["login", "uris"]) {
        for entry in uris {
            if let Some(uri) = entry.get("uri").and_then(Value::as_str) {
                parts.push(uri);
            }
        }
    }
    Zeroizing::new(parts.join("\0").to_lowercase())
}

/// Removes the secrets and records which ones there were, for the panel's
/// "has a password" style flags. A card number keeps only its last four.
fn strip_item(item: &mut Map<String, Value>) {
    let mut held = Map::new();
    held.insert(
        "password".into(),
        Value::Bool(present(item, &["login", "password"])),
    );
    held.insert(
        "totp".into(),
        Value::Bool(present(item, &["login", "totp"])),
    );
    held.insert("notes".into(), Value::Bool(present(item, &["notes"])));
    for path in SECRET_PATHS {
        remove(item, path);
    }
    if let Some(Value::Object(card)) = item.get_mut("card") {
        if let Some(Value::String(number)) = card.get_mut("number") {
            let keep = number
                .chars()
                .rev()
                .take(4)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<String>();
            wipe_string(number);
            *number = keep;
        }
    }
    if let Some(Value::Array(fields)) = item.get_mut("fields") {
        for field in fields.iter_mut() {
            // Hidden custom fields (type 1) lose their value.
            if field.get("type").and_then(Value::as_u64) != Some(1) {
                continue;
            }
            if let Value::Object(map) = field {
                if let Some(mut value) = map.remove("value") {
                    wipe_value(&mut value);
                }
            }
        }
    }
    item.insert("qsbwHeld".into(), Value::Object(held));
}

fn remove(item: &mut Map<String, Value>, path: &[&str]) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut map = item;
    for key in parents {
        match map.get_mut(*key) {
            Some(Value::Object(next)) => map = next,
            _ => return,
        }
    }
    if let Some(mut value) = map.remove(*last) {
        wipe_value(&mut value);
    }
}

fn wipe_string(value: &mut String) {
    use zeroize::Zeroize;
    value.zeroize();
}

/// Best effort: wipes every string in a parsed value before it is dropped.
fn wipe_value(value: &mut Value) {
    match value {
        Value::String(s) => wipe_string(s),
        Value::Array(items) => items.iter_mut().for_each(wipe_value),
        Value::Object(map) => map.values_mut().for_each(wipe_value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/==";

    fn vault() -> String {
        serde_json::json!({
            "sshCapability": "confirmed",
            "items": [
                { "id": "a", "type": 1, "name": "Bank", "notes": "recovery words",
                  "passwordHistory": [{ "password": "old-pw" }],
                  "login": { "username": "me", "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP",
                             "uris": [{ "uri": "https://bank.example", "match": 3 }] },
                  "fields": [{ "name": "pin", "value": "4242", "type": 1 }, { "name": "note", "value": "plain", "type": 0 }] },
                { "id": "c", "type": 3, "name": "Card",
                  "card": { "brand": "Visa", "number": "4111111111111111", "code": "123", "cardholderName": "Me" } },
                { "id": "i", "type": 4, "name": "Me", "identity": { "firstName": "Ada", "lastName": "L", "ssn": "123-45-6789" } }
            ],
            "sshKeys": [{ "id": "s", "name": "Laptop", "type": 5, "publicKey": "ssh-ed25519 AAAA", "fingerprint": "SHA256:x" }]
        })
        .to_string()
    }

    #[test]
    fn the_panel_gets_no_secret() {
        let mut store = Store::default();
        let out = store.strip_vault(&vault(), true).unwrap();
        for secret in [
            "hunter2",
            "JBSWY3DPEHPK3PXP",
            "recovery words",
            "old-pw",
            "4242",
            "4111111111111111",
            "\"123\"",
            "123-45-6789",
        ] {
            assert!(
                !out.contains(secret),
                "{secret} reached the panel: {}",
                out.as_str()
            );
        }
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let bank = &parsed["items"][0];
        assert_eq!(
            bank["qsbwHeld"],
            serde_json::json!({ "password": true, "totp": true, "notes": true })
        );
        assert_eq!(bank["login"]["uris"][0]["match"], 3);
        assert_eq!(bank["fields"][1]["value"], "plain");
        assert_eq!(parsed["items"][1]["card"]["number"], "1111");
        assert_eq!(parsed["sshKeys"][0]["publicKey"], "ssh-ed25519 AAAA");
        // The full item stays in the helper.
        assert!(store.item("a").unwrap().contains("hunter2"));
    }

    #[test]
    fn search_covers_what_the_list_shows_and_notes() {
        let mut store = Store::default();
        store.strip_vault(&vault(), true).unwrap();
        assert_eq!(store.search("BANK.example"), ["a"]);
        assert_eq!(store.search("recovery"), ["a"]);
        assert_eq!(store.search("1111"), ["c"]);
        assert_eq!(store.search("ada l"), ["i"]);
        assert_eq!(store.search("sha256:x"), ["s"]);
        assert!(
            store.search("hunter2").is_empty(),
            "passwords are never searched"
        );
        assert!(store.search("4242").is_empty(), "nor hidden fields");
        assert_eq!(store.search("  ").len(), 4);
    }

    #[test]
    fn a_save_updates_one_item_and_a_read_replaces_all() {
        let mut store = Store::default();
        store.strip_vault(&vault(), true).unwrap();
        let saved = serde_json::json!({ "items": [{ "id": "a", "type": 1, "name": "Bank", "login": { "password": "new" } }], "sshKeys": [] });
        store.strip_vault(&saved.to_string(), false).unwrap();
        assert!(store.item("a").unwrap().contains("\"new\""));
        assert!(store.item("c").is_some());
        store.strip_vault(&saved.to_string(), true).unwrap();
        assert!(store.item("c").is_none());
        assert!(store.strip_vault("not json", true).is_none());
    }

    #[test]
    fn a_forgotten_item_is_gone_from_item_and_search() {
        let mut store = Store::default();
        store.strip_vault(&vault(), true).unwrap();
        store.forget_item("a");
        assert!(store.item("a").is_none());
        assert!(store.search("recovery").is_empty());
        assert_eq!(store.search("  ").len(), 3);
        // The ones after it are still found under their own ids.
        assert!(store.item("c").unwrap().contains("1111"));
        assert!(store.item("s").is_some());
        assert_eq!(store.search("ada l"), ["i"]);
        store.forget_item("a");
        store.forget_item("nope");
        assert_eq!(store.search("  ").len(), 3);
    }

    #[test]
    fn session_keys_are_found_as_the_panel_finds_them() {
        assert_eq!(
            extract_session(&format!("export BW_SESSION=\"{TOKEN}\"\n"))
                .unwrap()
                .as_str(),
            TOKEN
        );
        assert_eq!(
            extract_session(&format!("warning\n{TOKEN}\n"))
                .unwrap()
                .as_str(),
            TOKEN
        );
        assert!(extract_session("short").is_none());
        let mut store = Store::default();
        store.set_session(Zeroizing::new(TOKEN.into()));
        store.set_secret("pw".into(), Zeroizing::new("x".into()));
        store.hold_session("lock1".into());
        store.forget(&["lock1".into()]);
        assert!(store.session().is_none() && store.secret("pw").is_none());
        assert_eq!(store.secret("lock1"), Some(TOKEN));
        store.forget(&[]);
        assert!(store.secret("lock1").is_none());
    }
}
