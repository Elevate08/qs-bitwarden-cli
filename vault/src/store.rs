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

/// An SSH private key, wherever `bw` or the panel's filter has put one. No
/// request reads it back, so it is removed before an item is held as well:
/// the SSH agent gets its keys from the vault read's other branch, never
/// from here.
const SSH_PRIVATE_KEY_PATHS: &[&[&str]] = &[&["sshKey", "privateKey"], &["privateKey"]];

/// The whole of a vault read, and of one `sshKeys` record in it: what the
/// panel's jq filter (BitwardenModel.js SANITIZED_ITEMS_FILTER) writes.
const VAULT_KEYS: &[&str] = &["sshCapability", "items", "sshKeys"];
const SSH_RECORD_KEYS: &[&str] = &[
    "id",
    "name",
    "type",
    "organizationId",
    "folderId",
    "favorite",
    "reprompt",
    "publicKey",
    "fingerprint",
];

/// What the panel reads of an attachment (BitwardenModel.js
/// parseAttachments). A download names the item and the attachment by id, so
/// the rest (a signed download `url`, the attachment's `key`) stays here.
const ATTACHMENT_KEYS: &[&str] = &["id", "fileName", "size", "sizeName"];

/// A value the panel may ask for one at a time (`field`, `copyField`): the
/// secrets of `SECRET_PATHS` it shows or copies, and hidden custom fields. The
/// TOTP key and passkeys are not on the list: the code is computed here, and
/// the rest are not shown.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretField {
    Password,
    Notes,
    CardNumber,
    CardCode,
    Ssn,
    PassportNumber,
    LicenseNumber,
    /// The custom field at this position in the item's `fields`.
    Custom(usize),
    /// The previous password at this position in the item's `passwordHistory`.
    History(usize),
}

impl SecretField {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "password" => Self::Password,
            "notes" => Self::Notes,
            "cardNumber" => Self::CardNumber,
            "cardCode" => Self::CardCode,
            "ssn" => Self::Ssn,
            "passportNumber" => Self::PassportNumber,
            "licenseNumber" => Self::LicenseNumber,
            other => {
                if let Some(index) = other.strip_prefix("customField:") {
                    Self::Custom(parse_index(index)?)
                } else {
                    Self::History(parse_index(other.strip_prefix("passwordHistory:")?)?)
                }
            }
        })
    }

    fn path(&self) -> Option<&'static [&'static str]> {
        Some(match self {
            Self::Password => &["login", "password"],
            Self::Notes => &["notes"],
            Self::CardNumber => &["card", "number"],
            Self::CardCode => &["card", "code"],
            Self::Ssn => &["identity", "ssn"],
            Self::PassportNumber => &["identity", "passportNumber"],
            Self::LicenseNumber => &["identity", "licenseNumber"],
            Self::Custom(_) | Self::History(_) => return None,
        })
    }
}

/// A list position as the panel names it: plain digits without a leading
/// zero, so an entry has one name.
fn parse_index(index: &str) -> Option<usize> {
    if index.is_empty()
        || index.len() > 4
        || !index.bytes().all(|b| b.is_ascii_digit())
        || (index.len() > 1 && index.starts_with('0'))
    {
        return None;
    }
    index.parse().ok()
}

/// The item field a linked custom field points at, for the linked fields the
/// panel treats as secret (BitwardenModel.js linkedCustomFieldIsSensitive).
fn linked_secret_path(linked_id: u64) -> Option<&'static [&'static str]> {
    Some(match linked_id {
        101 => &["login", "password"],
        303 => &["card", "code"],
        305 => &["card", "number"],
        412 => &["identity", "ssn"],
        414 => &["identity", "passportNumber"],
        415 => &["identity", "licenseNumber"],
        _ => return None,
    })
}

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
    /// The item as `bw` returned it (sanitized, and without an SSH private
    /// key), for the detail and edit views and for copying.
    full: Zeroizing<String>,
    /// Lowercased search text, fields separated by NUL.
    haystack: Zeroizing<String>,
    /// A card number's digits, for the last-four search rule.
    card_digits: Zeroizing<String>,
}

/// The items of a staged list read, wiped when dropped as `Held` is.
struct Staged {
    id: u64,
    items: Vec<Held>,
    index: HashMap<String, usize>,
}

#[derive(Default)]
pub struct Store {
    session: Option<Zeroizing<String>>,
    secrets: HashMap<String, Zeroizing<String>>,
    items: Vec<Held>,
    index: HashMap<String, usize>,
    /// A list read the panel has not accepted yet (`stage_vault`): at most
    /// one, and nothing is answered from it. It becomes `items` only when
    /// the panel commits it by its id.
    staged: Option<Staged>,
    /// The last id given to a staged read. Never reset, so an id is not
    /// reused after a `forget`.
    stage_seq: u64,
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
        self.staged = None;
    }

    /// Drops one item, from search as well as from `item`, and from a
    /// staged read, which may be from before the delete. An id neither holds
    /// (a delete that finished after its vault was closed) changes nothing:
    /// the staged read stays as it is, and can still be committed.
    pub fn forget_item(&mut self, id: &str) {
        remove_held(&mut self.items, &mut self.index, id);
        if let Some(staged) = self.staged.as_mut() {
            remove_held(&mut staged.items, &mut staged.index, id);
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

    /// One string at `path` of a held item.
    pub fn value_at(&self, id: &str, path: &[&str]) -> Option<Zeroizing<String>> {
        let mut item: Value = serde_json::from_str(self.item(id)?).ok()?;
        let value = get_value(&item, path)
            .and_then(Value::as_str)
            .map(|s| Zeroizing::new(s.to_owned()));
        wipe_value(&mut item);
        value
    }

    /// The value `field` names; `None` if the item or the value is absent. A
    /// custom field answers only if it is hidden (type 1) or links to a secret.
    pub fn item_secret(&self, id: &str, field: &SecretField) -> Option<Zeroizing<String>> {
        if let Some(path) = field.path() {
            return self.value_at(id, path);
        }
        let mut item: Value = serde_json::from_str(self.item(id)?).ok()?;
        if let SecretField::History(index) = field {
            let value = item
                .get("passwordHistory")
                .and_then(Value::as_array)
                .and_then(|history| history.get(*index))
                .and_then(|entry| entry.get("password"))
                .and_then(Value::as_str)
                .map(|s| Zeroizing::new(s.to_owned()));
            wipe_value(&mut item);
            return value;
        }
        let SecretField::Custom(index) = field else {
            return None;
        };
        let value = (|| {
            let custom = item.get("fields")?.as_array()?.get(*index)?;
            let text = |node: &Value| node.as_str().map(|s| Zeroizing::new(s.to_owned()));
            match custom.get("type").and_then(Value::as_u64)? {
                1 => text(custom.get("value")?),
                3 => {
                    let path = linked_secret_path(custom.get("linkedId")?.as_u64()?)?;
                    text(get_value(&item, path)?)
                }
                _ => None,
            }
        })();
        wipe_value(&mut item);
        value
    }

    /// Ids whose search text contains `query`, in load order. Mirrors
    /// matchesQuery() in BitwardenModel.js, notes included unless the item
    /// asks for the master password.
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
    /// `replace` swaps the whole store (a list read taken at once, as a
    /// panel from before staging asks); otherwise the items are added or
    /// updated (a save). `None`: not a vault read of that shape. Nothing of
    /// it may be forwarded, and the store is left as it was. Either way a
    /// staged read is dropped: it is from before this one.
    pub fn strip_vault(&mut self, raw: &str, replace: bool) -> Option<Zeroizing<String>> {
        self.staged = None;
        if replace {
            let (mut items, mut index) = (Vec::new(), HashMap::new());
            let out = strip_into(raw, &mut items, &mut index)?;
            self.items = items;
            self.index = index;
            Some(out)
        } else {
            strip_into(raw, &mut self.items, &mut self.index)
        }
    }

    /// As a replacing `strip_vault`, but the items are set aside under the
    /// id returned, and the store answers from what it held until
    /// `commit_staged` is given that id. One read is staged at a time: this
    /// drops the one before, whether or not this read is understood.
    pub fn stage_vault(&mut self, raw: &str) -> Option<(u64, Zeroizing<String>)> {
        self.staged = None;
        let (mut items, mut index) = (Vec::new(), HashMap::new());
        let out = strip_into(raw, &mut items, &mut index)?;
        self.stage_seq = self.stage_seq.wrapping_add(1).max(1);
        let id = self.stage_seq;
        self.staged = Some(Staged { id, items, index });
        Some((id, out))
    }

    /// The staged read `id` becomes the store's items. False, and nothing
    /// changes, when that is not the read staged now (it was replaced,
    /// discarded, or dropped by a lock, a save or a delete).
    pub fn commit_staged(&mut self, id: u64) -> bool {
        match self.staged.take() {
            Some(staged) if staged.id == id => {
                self.items = staged.items;
                self.index = staged.index;
                true
            }
            other => {
                self.staged = other;
                false
            }
        }
    }

    /// Drops the staged read `id`, if it is the one staged now.
    pub fn discard_staged(&mut self, id: u64) {
        if self.staged.as_ref().is_some_and(|staged| staged.id == id) {
            self.staged = None;
        }
    }

    /// Drops whatever is staged (another staged read has been asked for).
    pub fn unstage(&mut self) {
        self.staged = None;
    }
}

/// Parses a vault read into `items`/`index` and returns it without secrets
/// (`Store::strip_vault`). Nothing is added unless the shape is right.
fn strip_into(
    raw: &str,
    held: &mut Vec<Held>,
    index: &mut HashMap<String, usize>,
) -> Option<Zeroizing<String>> {
    let mut vault: Value = serde_json::from_str(raw).ok()?;
    if !is_vault_read(&vault) {
        wipe_value(&mut vault);
        return None;
    }
    if let Some(Value::Array(items)) = vault.get_mut("items") {
        for item in items.iter_mut() {
            if let Value::Object(map) = item {
                for path in SSH_PRIVATE_KEY_PATHS {
                    remove(map, path);
                }
                hold(held, index, map);
                strip_item(map);
            }
        }
    }
    if let Some(Value::Array(keys)) = vault.get_mut("sshKeys") {
        for key in keys.iter_mut() {
            if let Value::Object(map) = key {
                // Public records: cut down to that, then held for search.
                public_ssh_record(map);
                hold(held, index, map);
            }
        }
    }
    let out = serde_json::to_string(&vault).ok().map(Zeroizing::new);
    wipe_value(&mut vault);
    out
}

fn remove_held(items: &mut Vec<Held>, index: &mut HashMap<String, usize>, id: &str) {
    let Some(at) = index.remove(id) else {
        return;
    };
    items.remove(at);
    for (position, held) in items.iter().enumerate().skip(at) {
        index.insert(held.id.clone(), position);
    }
}

fn hold(items: &mut Vec<Held>, index: &mut HashMap<String, usize>, item: &mut Map<String, Value>) {
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
    match index.get(&id) {
        Some(at) => items[*at] = held,
        None => {
            index.insert(id, items.len());
            items.push(held);
        }
    }
}

/// Exactly the shape of a vault read: the three keys and no other, `items`
/// an array of objects, `sshKeys` (if there) the same, `sshCapability` (if
/// there) a string. Anything else may be decrypted items in a form
/// `strip_item` would not recognise.
fn is_vault_read(vault: &Value) -> bool {
    let objects = |value: &Value| {
        value
            .as_array()
            .is_some_and(|list| list.iter().all(Value::is_object))
    };
    let Some(object) = vault.as_object() else {
        return false;
    };
    object.keys().all(|key| VAULT_KEYS.contains(&key.as_str()))
        && object.get("items").is_some_and(objects)
        && object.get("sshKeys").is_none_or(objects)
        && object.get("sshCapability").is_none_or(Value::is_string)
}

/// Keeps the public fields of an `sshKeys` record, and those only as plain
/// values: a record that came with more (a whole SSH item, say) loses it.
fn public_ssh_record(record: &mut Map<String, Value>) {
    record.retain(|key, value| {
        let keep =
            SSH_RECORD_KEYS.contains(&key.as_str()) && !value.is_object() && !value.is_array();
        if !keep {
            wipe_value(value);
        }
        keep
    });
}

fn get<'a>(item: &'a Map<String, Value>, path: &[&str]) -> Option<&'a Value> {
    let (last, parents) = path.split_last()?;
    let mut map = item;
    for key in parents {
        map = map.get(*key)?.as_object()?;
    }
    map.get(*last)
}

fn get_value<'a>(item: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(item, |node, key| node.get(*key))
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

/// Whether the item is to be treated as one that asks for the master
/// password. Only a plain "no" says it is not: absent, null, 0 or "0". The
/// panel reads "1" as a yes (BitwardenModel.js repromptValue), and anything
/// less clear is taken as a yes here too.
fn asks_for_master_password(item: &Map<String, Value>) -> bool {
    match item.get("reprompt") {
        Some(Value::Null) | None => false,
        Some(Value::Number(number)) => number.as_u64() != Some(0),
        Some(Value::String(text)) => text != "0",
        Some(_) => true,
    }
}

/// A date and time as `bw` writes one (RFC 3339): `2024-05-01T10:00:00Z`,
/// with or without a fraction of a second, ending in `Z` or an offset, and
/// a moment that exists: no 30 February, no 25 o'clock, no second 60. RFC
/// 3339 allows a 60 for a leap second, but `bw` writes these dates from a
/// JavaScript `Date`, which has none and cannot read one back, so the panel
/// could not show it as a date either.
fn is_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    let shape = |part: &[u8], pattern: &[u8]| {
        part.len() == pattern.len()
            && part
                .iter()
                .zip(pattern)
                .all(|(byte, expected)| match expected {
                    b'0' => byte.is_ascii_digit(),
                    other => byte == other,
                })
    };
    if bytes.len() < 20 || !shape(&bytes[..19], b"0000-00-00T00:00:00") {
        return false;
    }
    // Digits, as `shape` has just checked.
    let number = |at: usize, len: usize| {
        bytes[at..at + len]
            .iter()
            .fold(0u32, |sum, byte| sum * 10 + u32::from(byte - b'0'))
    };
    let (year, month, day) = (number(0, 4), number(5, 2), number(8, 2));
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days || number(11, 2) > 23 || number(14, 2) > 59 || number(17, 2) > 59 {
        return false;
    }
    let mut rest = &bytes[19..];
    if let [b'.', tail @ ..] = rest {
        let digits = tail.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if digits == 0 || digits > 9 {
            return false;
        }
        rest = &tail[digits..];
    }
    if rest == b"Z" {
        return true;
    }
    let at = bytes.len() - rest.len();
    (shape(rest, b"+00:00") || shape(rest, b"-00:00"))
        && number(at + 1, 2) <= 23
        && number(at + 4, 2) <= 59
}

/// What matchesQuery() compares, lowercased: name, username, notes (not for an
/// item that asks for the master password, whose notes the detail view hides
/// behind that prompt), the public key and fingerprint of an SSH record, card
/// brand and holder, an identity's name, email, username and company, and
/// every website.
fn haystack(item: &Map<String, Value>) -> Zeroizing<String> {
    let mut parts: Vec<&str> = vec![
        text(item, &["name"]),
        text(item, &["login", "username"]),
        if asks_for_master_password(item) {
            ""
        } else {
            text(item, &["notes"])
        },
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
    // Which of the other secrets there were, so the panel draws a row for
    // each and asks for its value only when it is revealed or copied.
    for (flag, path) in [
        ("cardCode", &["card", "code"][..]),
        ("ssn", &["identity", "ssn"][..]),
        ("passportNumber", &["identity", "passportNumber"][..]),
        ("licenseNumber", &["identity", "licenseNumber"][..]),
    ] {
        held.insert(flag.into(), Value::Bool(present(item, path)));
    }
    // Previous passwords stay behind; their dates (not secret) tell the panel
    // how many there were and when each was last used, in the same order.
    if let Some(Value::Array(history)) = item.get("passwordHistory") {
        let dates = history
            .iter()
            .map(|entry| {
                // Anything but a date is blanked, not skipped: the position
                // is what `passwordHistory:<n>` names.
                Value::String(
                    entry
                        .get("lastUsedDate")
                        .and_then(Value::as_str)
                        .filter(|date| is_timestamp(date))
                        .unwrap_or("")
                        .to_owned(),
                )
            })
            .collect();
        held.insert("passwordHistory".into(), Value::Array(dates));
    }
    for path in SECRET_PATHS {
        remove(item, path);
    }
    match get(item, &["card", "number"]) {
        Some(Value::String(_)) => {
            if let Some(Value::String(number)) =
                item.get_mut("card").and_then(|card| card.get_mut("number"))
            {
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
        Some(Value::Null) | None => {}
        // A number that is not text cannot be cut to its last four.
        Some(_) => remove(item, &["card", "number"]),
    }
    match item.get_mut("fields") {
        Some(Value::Array(fields)) => fields.iter_mut().for_each(strip_field),
        Some(Value::Null) | None => {}
        // Not a list of fields, so nothing says which of it is hidden.
        Some(_) => remove(item, &["fields"]),
    }
    match item.get_mut("attachments") {
        Some(Value::Array(attachments)) => attachments.iter_mut().for_each(strip_attachment),
        Some(Value::Null) | None => {}
        Some(_) => remove(item, &["attachments"]),
    }
    item.insert("qsbwHeld".into(), Value::Object(held));
}

/// An attachment keeps `ATTACHMENT_KEYS`, as plain values. An entry that is
/// not an attachment is blanked in place, as a custom field is.
fn strip_attachment(attachment: &mut Value) {
    let Value::Object(map) = attachment else {
        wipe_value(attachment);
        *attachment = Value::Null;
        return;
    };
    map.retain(|key, value| {
        let keep =
            ATTACHMENT_KEYS.contains(&key.as_str()) && !value.is_object() && !value.is_array();
        if !keep {
            wipe_value(value);
        }
        keep
    });
}

/// A custom field keeps its value only if it is plainly text (type 0) or a
/// boolean (2), and the value is text or null: `bw` writes both kinds as
/// text. A hidden one (1) loses it, and so does a linked one (3), whose value
/// the panel works out from `linkedId`, and one whose type is missing or
/// written any other way. An entry that is not a field at all is blanked in
/// place, so the ones after it keep the positions `customField:<n>` names.
fn strip_field(field: &mut Value) {
    let Value::Object(map) = field else {
        wipe_value(field);
        *field = Value::Null;
        return;
    };
    if matches!(map.get("type").and_then(Value::as_u64), Some(0 | 2))
        && matches!(
            map.get("value"),
            Some(Value::String(_) | Value::Null) | None
        )
    {
        return;
    }
    if let Some(mut value) = map.remove("value") {
        wipe_value(&mut value);
    }
}

/// Removes what is at `path`. A parent that is there but is not an object
/// goes whole: the secret could be anywhere in it.
fn remove(item: &mut Map<String, Value>, path: &[&str]) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut map = item;
    for key in parents {
        match map.get(*key) {
            Some(Value::Object(_)) => {}
            Some(Value::Null) | None => return,
            Some(_) => {
                if let Some(mut value) = map.remove(*key) {
                    wipe_value(&mut value);
                }
                return;
            }
        }
        let Some(Value::Object(next)) = map.get_mut(*key) else {
            return;
        };
        map = next;
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
                  "passwordHistory": [{ "password": "old-pw", "lastUsedDate": "2024-05-01T10:00:00.000Z" }],
                  "login": { "username": "me", "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP",
                             "uris": [{ "uri": "https://bank.example", "match": 3 }] },
                  "fields": [{ "name": "pin", "value": "4242", "type": 1 }, { "name": "note", "value": "plain", "type": 0 }] },
                { "id": "c", "type": 3, "name": "Card",
                  "card": { "brand": "Visa", "number": "4111111111111111", "code": "123", "cardholderName": "Me" } },
                { "id": "i", "type": 4, "name": "Me", "identity": { "firstName": "Ada", "lastName": "L", "ssn": "123-45-6789" } },
                { "id": "r", "type": 2, "name": "Guarded", "reprompt": 1, "notes": "BEGIN OPENSSH" }
            ],
            "sshKeys": [{ "id": "s", "name": "Laptop", "type": 5, "publicKey": "ssh-ed25519 AAAA", "fingerprint": "SHA256:x" }]
        })
        .to_string()
    }

    #[test]
    fn a_previous_password_is_read_by_position() {
        let mut store = Store::default();
        store.strip_vault(&vault(), true).unwrap();
        let read = |id: &str, name: &str| {
            let field = SecretField::parse(name)?;
            store.item_secret(id, &field).map(|v| v.as_str().to_owned())
        };
        assert_eq!(read("a", "passwordHistory:0").as_deref(), Some("old-pw"));
        assert_eq!(read("a", "passwordHistory:1"), None);
        assert_eq!(read("c", "passwordHistory:0"), None);
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
            serde_json::json!({ "password": true, "totp": true, "notes": true, "cardCode": false,
                                "ssn": false, "passportNumber": false, "licenseNumber": false,
                                "passwordHistory": ["2024-05-01T10:00:00.000Z"] })
        );
        assert_eq!(parsed["items"][1]["qsbwHeld"]["cardCode"], true);
        assert_eq!(parsed["items"][2]["qsbwHeld"]["ssn"], true);
        assert_eq!(parsed["items"][2]["qsbwHeld"]["passportNumber"], false);
        assert_eq!(bank["login"]["uris"][0]["match"], 3);
        assert_eq!(bank["fields"][1]["value"], "plain");
        assert_eq!(parsed["items"][1]["card"]["number"], "1111");
        assert_eq!(parsed["sshKeys"][0]["publicKey"], "ssh-ed25519 AAAA");
        // The full item stays in the helper.
        assert!(store.item("a").unwrap().contains("hunter2"));
    }

    #[test]
    fn secret_fields_have_a_fixed_set_of_names() {
        for (name, field) in [
            ("password", SecretField::Password),
            ("notes", SecretField::Notes),
            ("cardNumber", SecretField::CardNumber),
            ("cardCode", SecretField::CardCode),
            ("ssn", SecretField::Ssn),
            ("passportNumber", SecretField::PassportNumber),
            ("licenseNumber", SecretField::LicenseNumber),
            ("customField:0", SecretField::Custom(0)),
            ("customField:12", SecretField::Custom(12)),
            ("passwordHistory:0", SecretField::History(0)),
            ("passwordHistory:12", SecretField::History(12)),
        ] {
            assert_eq!(SecretField::parse(name), Some(field), "{name}");
        }
        for name in [
            "",
            "totp",
            "login.password",
            "fido2Credentials",
            "passwordHistory",
            "Password",
            "passport",
            "customField:",
            "customField:-1",
            "customField:+1",
            "customField:01",
            "customField:1 ",
            "customField:a",
            "customField:12345",
            "customField:99999999999999999999",
            "customfield:1",
            "passwordHistory:",
            "passwordHistory:01",
            "passwordHistory:-1",
            "passwordHistory:a",
        ] {
            assert_eq!(SecretField::parse(name), None, "{name:?}");
        }
    }

    #[test]
    fn one_secret_is_looked_up_at_a_time() {
        let mut store = Store::default();
        let vault = serde_json::json!({ "items": [
            { "id": "a", "type": 1, "name": "Bank", "notes": "recovery words",
              "login": { "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP" },
              "fields": [{ "name": "label", "value": "plain", "type": 0 },
                         { "name": "pin", "value": "4242", "type": 1 },
                         { "name": "flag", "value": "true", "type": 2 },
                         { "name": "pw", "type": 3, "linkedId": 101 },
                         { "name": "user", "type": 3, "linkedId": 100 }] },
            { "id": "c", "type": 3, "name": "Card",
              "card": { "number": "4111111111111111", "code": "123" },
              "fields": [{ "name": "code", "type": 3, "linkedId": 303 }] },
            { "id": "i", "type": 4, "name": "Me",
              "identity": { "ssn": "123-45-6789", "passportNumber": "P1", "licenseNumber": "L1" } }
        ], "sshKeys": [] });
        store.strip_vault(&vault.to_string(), true).unwrap();
        let get = |id: &str, field: &str| {
            store
                .item_secret(id, &SecretField::parse(field).unwrap())
                .map(|value| String::from(&**value))
        };
        assert_eq!(get("a", "password").as_deref(), Some("hunter2"));
        assert_eq!(get("a", "notes").as_deref(), Some("recovery words"));
        assert_eq!(get("c", "cardNumber").as_deref(), Some("4111111111111111"));
        assert_eq!(get("c", "cardCode").as_deref(), Some("123"));
        assert_eq!(get("i", "ssn").as_deref(), Some("123-45-6789"));
        assert_eq!(get("i", "passportNumber").as_deref(), Some("P1"));
        assert_eq!(get("i", "licenseNumber").as_deref(), Some("L1"));
        // Custom fields count from the first, whatever their type.
        assert_eq!(get("a", "customField:1").as_deref(), Some("4242"));
        assert_eq!(get("a", "customField:3").as_deref(), Some("hunter2"));
        assert_eq!(get("c", "customField:0").as_deref(), Some("123"));
        assert_eq!(
            get("a", "customField:0"),
            None,
            "a plain field is not a secret"
        );
        assert_eq!(get("a", "customField:2"), None);
        assert_eq!(
            get("a", "customField:4"),
            None,
            "a linked username is not a secret"
        );
        assert_eq!(get("a", "customField:9"), None);
        // Absent values and items.
        assert_eq!(get("a", "cardCode"), None);
        assert_eq!(get("nope", "password"), None);
        // The key of a TOTP is not a field.
        assert_eq!(
            store
                .value_at("a", &["login", "totp"])
                .as_deref()
                .map(String::as_str),
            Some("JBSWY3DPEHPK3PXP")
        );
        store.forget_item("a");
        assert!(store.item_secret("a", &SecretField::Password).is_none());
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
        assert!(
            store.search("openssh").is_empty(),
            "a note behind the master-password prompt is not searchable"
        );
        assert_eq!(store.search("guarded"), ["r"], "though the item is");
        assert_eq!(store.search("  ").len(), 5);
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
    fn a_staged_read_answers_nothing_until_its_own_id_is_committed() {
        let read = |password: &str| {
            serde_json::json!({ "items": [{ "id": "a", "type": 1, "name": "Bank", "login": { "password": password } }], "sshKeys": [] }).to_string()
        };
        let holds = |store: &Store, password: &str| {
            store.item("a").is_some_and(|item| item.contains(password))
        };
        let mut store = Store::default();
        store.strip_vault(&vault(), true).unwrap();

        // Staged: handed on without secrets, and not answered from.
        let (first, shown) = store.stage_vault(&read("staged-1")).unwrap();
        assert!(!shown.contains("staged-1"));
        assert!(holds(&store, "hunter2") && store.search("  ").len() == 5);
        assert_eq!(
            store
                .value_at("a", &["login", "password"])
                .unwrap()
                .as_str(),
            "hunter2"
        );
        // A newer read takes its place: the older id commits nothing, and
        // neither does a discarded one.
        let (second, _) = store.stage_vault(&read("staged-2")).unwrap();
        assert!(second != first && !store.commit_staged(first));
        store.discard_staged(first);
        assert!(holds(&store, "hunter2"));
        assert!(store.commit_staged(second) && holds(&store, "staged-2"));
        assert!(store.item("c").is_none() && !store.commit_staged(second));

        // A save lands in the committed items and ends a read staged before it.
        let (stale, _) = store.stage_vault(&read("staged-3")).unwrap();
        store.strip_vault(&read("saved"), false).unwrap();
        assert!(!store.commit_staged(stale) && holds(&store, "saved"));
        // A delete takes its item out of a staged read too, and one for an
        // item of a vault since closed leaves the read committable.
        let (kept, _) = store.stage_vault(&vault()).unwrap();
        store.forget_item("a");
        store.forget_item("not-in-this-vault");
        assert!(store.commit_staged(kept) && store.item("a").is_none());
        assert!(store.item("c").is_some());
        // A lock ends a staged read, and the next id is a new one.
        let (locked, _) = store.stage_vault(&read("staged-4")).unwrap();
        store.forget(&[]);
        assert!(!store.commit_staged(locked) && store.item("a").is_none());
        let (next, _) = store.stage_vault(&read("staged-5")).unwrap();
        assert!(next != locked);
        // A read that is refused still ends the one staged before it.
        assert!(store.stage_vault("not json").is_none() && !store.commit_staged(next));
    }

    #[test]
    fn a_read_of_another_shape_is_refused_and_empties_nothing() {
        let mut store = Store::default();
        store.strip_vault(&vault(), true).unwrap();
        for raw in [
            r#"{"id":"x","login":{"password":"SECRET"}}"#,
            r#"{"items":{"id":"x","login":{"password":"SECRET"}}}"#,
            r#"{"items":[[{"id":"x","notes":"SECRET"}]],"sshKeys":[]}"#,
            r#"{"items":[],"sshKeys":[],"data":[{"login":{"password":"SECRET"}}]}"#,
            r#"{"items":[],"sshKeys":{"id":"s","privateKey":"SECRET"}}"#,
            r#"{"items":[],"sshKeys":["SECRET"]}"#,
            r#"{"items":[],"sshCapability":{"notes":"SECRET"}}"#,
            r#"{"sshKeys":[]}"#,
            r#"[{"id":"x","login":{"password":"SECRET"}}]"#,
            r#""SECRET""#,
        ] {
            for replace in [true, false] {
                assert!(store.strip_vault(raw, replace).is_none(), "{raw}");
            }
        }
        // A refused read is not a vault: what was held stays held.
        assert!(store.item("a").unwrap().contains("hunter2"));
        assert_eq!(store.search("  ").len(), 5);
    }

    #[test]
    fn an_ssh_private_key_reaches_neither_the_panel_nor_the_store() {
        let mut store = Store::default();
        let read = serde_json::json!({
            "items": [
                { "id": "x", "type": 5, "name": "Stray", "privateKey": "SECRET-TOP",
                  "sshKey": { "privateKey": "SECRET-E", "publicKey": "ssh-ed25519 BBBB" } },
                { "id": "y", "type": 1, "name": "Odd", "sshKey": ["SECRET-LIST"] }
            ],
            "sshKeys": [
                { "id": "s", "name": "Laptop", "type": 5, "organizationId": null, "folderId": null,
                  "favorite": true, "reprompt": 0, "publicKey": "ssh-ed25519 AAAA", "fingerprint": "SHA256:x",
                  "notes": "SECRET-NOTES", "privateKey": "SECRET-RAW",
                  "sshKey": { "privateKey": "SECRET-NESTED" } },
                { "id": "t", "name": { "privateKey": "SECRET-NAME" }, "type": 5 }
            ]
        })
        .to_string();
        let out = store.strip_vault(&read, true).unwrap();
        assert!(
            !out.contains("SECRET"),
            "reached the panel: {}",
            out.as_str()
        );
        // `item` hands the held copy to the panel, so it is gone there too.
        for id in ["x", "y", "s", "t"] {
            let held = store.item(id).unwrap();
            assert!(!held.contains("SECRET"), "{id} is held as {held}");
        }
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed["items"][0]["sshKey"]["publicKey"],
            "ssh-ed25519 BBBB"
        );
        assert_eq!(
            parsed["sshKeys"][0],
            serde_json::json!({ "id": "s", "name": "Laptop", "type": 5, "organizationId": null,
                                "folderId": null, "favorite": true, "reprompt": 0,
                                "publicKey": "ssh-ed25519 AAAA", "fingerprint": "SHA256:x" })
        );
        assert_eq!(
            parsed["sshKeys"][1],
            serde_json::json!({ "id": "t", "type": 5 })
        );
        assert_eq!(store.search("sha256:x"), ["s"]);
    }

    #[test]
    fn a_secret_in_an_unexpected_place_inside_an_item_is_dropped() {
        let mut store = Store::default();
        let read = serde_json::json!({ "items": [
            { "id": "l", "type": 1, "name": "List login", "login": [{ "password": "SECRET-LOGIN" }] },
            { "id": "c", "type": 3, "name": "Card", "card": { "number": 4111111111111111u64, "code": 123 } },
            { "id": "d", "type": 3, "name": "Card text", "card": "SECRET-CARD" },
            { "id": "i", "type": 4, "name": "Me", "identity": ["SECRET-IDENTITY"] },
            { "id": "f", "type": 1, "name": "Fields", "fields": [
                { "name": "text", "value": "plain", "type": 0 },
                { "name": "flag", "value": "true", "type": 2 },
                { "name": "hidden as text", "value": "SECRET-STRING-TYPE", "type": "1" },
                { "name": "hidden as float", "value": "SECRET-FLOAT-TYPE", "type": 1.0 },
                { "name": "untyped", "value": "SECRET-UNTYPED" },
                "SECRET-BARE",
                { "name": "linked", "type": 3, "linkedId": 101, "value": "SECRET-LINKED" },
                { "name": "nested", "type": 2, "value": { "password": "SECRET-NESTED" } },
                { "name": "listed", "type": 0, "value": ["SECRET-LISTED"] },
                { "name": "empty", "type": 0, "value": null }
            ] },
            { "id": "g", "type": 1, "name": "Field map",
              "fields": { "0": { "name": "pin", "value": "SECRET-MAP", "type": 1 } } },
            { "id": "n", "type": 2, "name": "Empty", "login": null, "card": null, "identity": null,
              "fields": null, "sshKey": null },
            { "id": "e", "type": 3, "name": "Blank card", "card": { "number": null, "code": null } }
        ], "sshKeys": [] })
        .to_string();
        let out = store.strip_vault(&read, true).unwrap();
        assert!(
            !out.contains("SECRET") && !out.contains("4111111111111111") && !out.contains("123"),
            "reached the panel: {}",
            out.as_str()
        );
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let fields = &parsed["items"][4]["fields"];
        // Positions hold, since `customField:<n>` counts them.
        assert_eq!(fields.as_array().unwrap().len(), 10);
        assert_eq!(fields[7]["name"], "nested");
        assert_eq!(fields[9]["value"], Value::Null);
        assert_eq!(fields[0]["value"], "plain");
        assert_eq!(fields[1]["value"], "true");
        assert_eq!(fields[2]["name"], "hidden as text");
        assert_eq!(fields[5], Value::Null);
        assert_eq!(fields[6]["linkedId"], 101);
        // Nulls are what `bw` writes for the parts an item does not have.
        assert_eq!(parsed["items"][6]["login"], Value::Null);
        assert_eq!(parsed["items"][6]["qsbwHeld"]["password"], false);
        assert!(parsed["items"][7]["card"]
            .as_object()
            .unwrap()
            .contains_key("number"));
    }

    #[test]
    fn an_attachment_keeps_only_what_the_panel_shows() {
        let mut store = Store::default();
        let read = serde_json::json!({ "items": [
            { "id": "a", "type": 1, "name": "Files", "attachments": [
                { "id": "att1", "fileName": "scan.pdf", "size": "1024", "sizeName": "1 KB",
                  "url": "https://vault.example/attachments/a/att1?token=SECRET-URL", "key": "SECRET-KEY",
                  "extra": { "nested": "SECRET-EXTRA" } },
                "SECRET-BARE",
                { "id": "att2", "fileName": { "name": "SECRET-NAME" }, "size": 7 }
            ] },
            { "id": "b", "type": 1, "name": "Odd", "attachments": { "url": "SECRET-MAP" } },
            { "id": "n", "type": 1, "name": "None", "attachments": null }
        ] })
        .to_string();
        let out = store.strip_vault(&read, true).unwrap();
        assert!(
            !out.contains("SECRET"),
            "reached the panel: {}",
            out.as_str()
        );
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed["items"][0]["attachments"],
            serde_json::json!([
                { "id": "att1", "fileName": "scan.pdf", "size": "1024", "sizeName": "1 KB" },
                null,
                { "id": "att2", "size": 7 }
            ])
        );
        assert!(parsed["items"][1].get("attachments").is_none());
        assert_eq!(parsed["items"][2]["attachments"], Value::Null);
        // An edit sends the whole item back to `bw`, so the held copy keeps it.
        assert!(store.item("a").unwrap().contains("SECRET-KEY"));
    }

    #[test]
    fn a_history_date_that_is_not_a_date_is_blanked_in_place() {
        for (date, ok) in [
            ("2024-05-01T10:00:00.000Z", true),
            ("2024-05-01T10:00:00Z", true),
            ("2024-05-01T10:00:00.123456789+02:00", true),
            ("2024-05-01T10:00:00-05:30", true),
            ("2024-02-29T23:59:59Z", true),
            ("2024-12-31T23:59:59.999999999+23:59", true),
            ("2000-02-29T00:00:00Z", true),
            ("2024-12-31T00:00:00+23:59", true),
            ("2024-02-30T03:04:05.678Z", false),
            ("2023-02-29T03:04:05Z", false),
            ("1900-02-29T03:04:05Z", false),
            ("2024-04-31T03:04:05Z", false),
            ("2024-00-10T03:04:05Z", false),
            ("2024-13-10T03:04:05Z", false),
            ("2024-05-00T03:04:05Z", false),
            ("2024-05-32T03:04:05Z", false),
            ("2024-05-01T24:00:00Z", false),
            ("2024-05-01T10:60:00Z", false),
            ("2024-05-01T10:00:61Z", false),
            // A leap second, real (the end of 2016) or not, with or
            // without a fraction or an offset: `bw` never writes one.
            ("2016-12-31T23:59:60Z", false),
            ("2024-02-29T23:59:60Z", false),
            ("2024-05-01T10:00:60Z", false),
            ("2024-05-01T10:00:60.000Z", false),
            ("2024-05-01T10:00:60+02:00", false),
            ("2024-05-01T10:00:99Z", false),
            ("2024-05-01T10:00:00+24:00", false),
            ("2024-05-01T10:00:00-05:60", false),
            ("", false),
            ("2024-05-01", false),
            ("2024-05-01 10:00:00Z", false),
            ("2024-05-01T10:00:00", false),
            ("2024-05-01T10:00:00.Z", false),
            ("2024-05-01T10:00:00.000Zhunter2", false),
            ("2024-05-01T10:00:00+0200", false),
            ("hunter2", false),
            ("２０２４-05-01T10:00:00Z", false),
        ] {
            assert_eq!(is_timestamp(date), ok, "{date:?}");
        }
        let mut store = Store::default();
        let read = serde_json::json!({ "items": [{ "id": "a", "type": 1, "name": "Bank",
            "passwordHistory": [
                { "password": "one", "lastUsedDate": "SECRET-DATE" },
                { "password": "two", "lastUsedDate": "2024-05-01T10:00:00.000Z" },
                { "password": "three", "lastUsedDate": { "password": "SECRET-NESTED" } },
                "SECRET-BARE",
                { "password": "five", "lastUsedDate": "2024-02-30T03:04:05.678Z" },
                { "password": "six", "lastUsedDate": "2016-12-31T23:59:60Z" }
            ] }] })
        .to_string();
        let out = store.strip_vault(&read, true).unwrap();
        assert!(
            !out.contains("SECRET"),
            "reached the panel: {}",
            out.as_str()
        );
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed["items"][0]["qsbwHeld"]["passwordHistory"],
            serde_json::json!(["", "2024-05-01T10:00:00.000Z", "", "", "", ""])
        );
        let second = store.item_secret("a", &SecretField::History(1)).unwrap();
        assert_eq!(second.as_str(), "two");
        let fifth = store.item_secret("a", &SecretField::History(4)).unwrap();
        assert_eq!(fifth.as_str(), "five");
        assert!(!out.contains("2024-02-30"));
        // A blanked date takes nothing else with it.
        assert!(!out.contains("23:59:60"));
        let sixth = store.item_secret("a", &SecretField::History(5)).unwrap();
        assert_eq!(sixth.as_str(), "six");
    }

    #[test]
    fn notes_are_searched_only_when_the_item_plainly_asks_for_no_password() {
        let item = |id: &str, reprompt: Value| {
            let mut item =
                serde_json::json!({ "id": id, "type": 2, "name": id, "notes": "findme" });
            if !reprompt.is_null() || id == "null" {
                item["reprompt"] = reprompt;
            }
            item
        };
        let read = serde_json::json!({ "items": [
            item("absent", Value::Null),
            item("null", Value::Null),
            item("zero", serde_json::json!(0)),
            item("zero-text", serde_json::json!("0")),
            item("one", serde_json::json!(1)),
            item("one-text", serde_json::json!("1")),
            item("one-float", serde_json::json!(1.0)),
            item("two", serde_json::json!(2)),
            item("true", serde_json::json!(true)),
            item("false", serde_json::json!(false)),
            item("text", serde_json::json!("no")),
            item("list", serde_json::json!([0])),
        ] })
        .to_string();
        let mut store = Store::default();
        store.strip_vault(&read, true).unwrap();
        assert_eq!(
            store.search("findme"),
            ["absent", "null", "zero", "zero-text"]
        );
        assert_eq!(store.search("one-text"), ["one-text"]);
    }

    #[test]
    fn a_forgotten_item_is_gone_from_item_and_search() {
        let mut store = Store::default();
        store.strip_vault(&vault(), true).unwrap();
        let held = store.search("  ").len();
        store.forget_item("a");
        assert!(store.item("a").is_none());
        assert!(store.search("recovery").is_empty());
        assert_eq!(store.search("  ").len(), held - 1);
        // The ones after it are still found under their own ids.
        assert!(store.item("c").unwrap().contains("1111"));
        assert!(store.item("s").is_some());
        assert_eq!(store.search("ada l"), ["i"]);
        store.forget_item("a");
        store.forget_item("nope");
        assert_eq!(store.search("  ").len(), held - 1);
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
