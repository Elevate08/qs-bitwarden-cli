mod common;

use qs_bitwarden_ssh_agent::keystore::{
    KeyStore, LoadError, MAX_FILTERED_BYTES, MAX_METADATA_BYTES,
};
use qs_bitwarden_ssh_agent::load::{LoadWindow, PayloadError, PayloadFilter};
use qs_bitwarden_ssh_agent::runtime::{read_payload_async, Runtime, RuntimeError};
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

const NONCE: &str = "0123456789abcdef0123456789abcdef";
/// Another load's nonce: what a payload left over from an earlier load names.
const STALE: &str = "ffffffffffffffffffffffffffffffff";

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "qsbw-{label}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut OsRng)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn item_json(id: &str, key: &PrivateKey) -> serde_json::Value {
    serde_json::json!({
        "itemId": id,
        "name": format!("key {id}"),
        "privateKeyB64": common::base64(key.to_openssh(Default::default()).unwrap().as_bytes()),
        "publicKey": key.public_key().to_openssh().unwrap(),
        "fingerprint": key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        "requiresReprompt": false
    })
}

fn payload(nonce: &str, items: Vec<serde_json::Value>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"loadId": nonce, "items": items})).unwrap()
}

/// A payload laid out as the panel's `jq -c` filter writes it: `loadId`
/// first. (`serde_json::json!` sorts keys, so `payload` puts it last.)
fn jq_payload(nonce: &str, items: Vec<serde_json::Value>) -> Vec<u8> {
    format!(
        "{{\"loadId\":\"{nonce}\",\"items\":{}}}",
        serde_json::to_string(&items).unwrap()
    )
    .into_bytes()
}

fn filter(nonce: &str) -> PayloadFilter {
    LoadWindow::new(1, nonce).unwrap().filter().unwrap()
}

fn line(bytes: &[u8]) -> Vec<u8> {
    let mut line = bytes.to_vec();
    line.push(b'\n');
    line
}

#[test]
fn creates_private_runtime_and_fifo_and_holds_both_fifo_ends() {
    let temp = TempDir::new("runtime");
    let runtime = Runtime::create(&temp.0).unwrap();
    let dir = fs::metadata(runtime.directory()).unwrap();
    let fifo = fs::symlink_metadata(runtime.fifo_path()).unwrap();

    assert_eq!(dir.mode() & 0o777, 0o700);
    assert_eq!(fifo.mode() & 0o777, 0o600);
    assert!(fifo.file_type().is_fifo());
    assert_eq!(dir.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(fifo.uid(), rustix::process::geteuid().as_raw());
    assert!(runtime.fifo().metadata().unwrap().file_type().is_fifo());
}

#[test]
fn refuses_stale_wrong_type_symlink_and_insecure_directory() {
    let stale = TempDir::new("stale");
    let runtime_dir = stale.0.join("qs-bitwarden-cli");
    fs::create_dir(&runtime_dir).unwrap();
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(runtime_dir.join("ssh-keys.fifo"), b"stale").unwrap();
    assert_eq!(
        Runtime::create(&stale.0).unwrap_err(),
        RuntimeError::UnsafeFifo
    );

    let insecure = TempDir::new("insecure");
    let dir = insecure.0.join("qs-bitwarden-cli");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        Runtime::create(&insecure.0).unwrap_err(),
        RuntimeError::UnsafeDirectory
    );

    let linked = TempDir::new("linked");
    let target = linked.0.join("target");
    fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, linked.0.join("qs-bitwarden-cli")).unwrap();
    assert_eq!(
        Runtime::create(&linked.0).unwrap_err(),
        RuntimeError::UnsafeDirectory
    );
}

#[test]
fn a_wrong_nonce_does_not_wipe_the_live_private_set() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_blob = key.public_key().to_bytes().unwrap();
    let bytes = payload(NONCE, vec![item_json("one", &key)]);
    let mut window = LoadWindow::new(7, NONCE).unwrap();
    let mut store = KeyStore::new();
    let candidate = window.decode(Zeroizing::new(bytes), &mut store).unwrap();
    assert_eq!(store.publish(candidate).unwrap().loaded, 1);
    assert!(store.authorize(&public_blob).is_some());

    let mut rejected = LoadWindow::new(8, NONCE).unwrap();
    assert_eq!(
        rejected
            .decode(
                Zeroizing::new(payload("ffffffffffffffffffffffffffffffff", vec![])),
                &mut store
            )
            .unwrap_err(),
        PayloadError::NonceMismatch
    );
    assert!(
        store.authorize(&public_blob).is_some(),
        "a rejected payload must not drop the live private set"
    );
}

#[test]
fn valid_nonce_payload_publishes_disposable_keys_once() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let bytes = payload(NONCE, vec![item_json("one", &key)]);
    let mut window = LoadWindow::new(7, NONCE).unwrap();
    let mut store = KeyStore::new();
    let candidate = window.decode(Zeroizing::new(bytes), &mut store).unwrap();
    assert_eq!(store.publish(candidate).unwrap().loaded, 1);
    assert_eq!(store.public_identities().len(), 1);
    assert_eq!(
        window
            .decode(Zeroizing::new(payload(NONCE, vec![])), &mut store)
            .unwrap_err(),
        PayloadError::Closed
    );
}

#[test]
fn a_payload_in_the_old_escaped_format_fails_the_whole_load() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut old = item_json("one", &key);
    let pem = key.to_openssh(Default::default()).unwrap();
    let object = old.as_object_mut().unwrap();
    object.remove("privateKeyB64");
    object.insert("privateKey".into(), pem.as_str().into());
    let mut store = KeyStore::new();
    let mut window = LoadWindow::new(7, NONCE).unwrap();
    assert_eq!(
        window
            .decode(Zeroizing::new(payload(NONCE, vec![old])), &mut store)
            .unwrap_err(),
        PayloadError::Malformed
    );

    // The new field carrying the PEM itself (newlines escaped) is no better.
    let mut raw = item_json("two", &key);
    raw.as_object_mut()
        .unwrap()
        .insert("privateKeyB64".into(), pem.as_str().into());
    let mut window = LoadWindow::new(8, NONCE).unwrap();
    assert_eq!(
        window
            .decode(Zeroizing::new(payload(NONCE, vec![raw])), &mut store)
            .unwrap_err(),
        PayloadError::Malformed
    );
}

#[test]
fn nonce_schema_truncation_and_size_fail_the_whole_load() {
    let mut store = KeyStore::new();
    for (index, (nonce, bytes, expected)) in [
        (
            NONCE,
            payload("ffffffffffffffffffffffffffffffff", vec![]),
            PayloadError::NonceMismatch,
        ),
        (
            NONCE,
            br#"{"loadId":"0123456789abcdef0123456789abcdef","items":["#.to_vec(),
            PayloadError::Malformed,
        ),
        (
            NONCE,
            br#"{"loadId":"0123456789abcdef0123456789abcdef","items":[],"extra":1}"#.to_vec(),
            PayloadError::Malformed,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut window = LoadWindow::new(10 + index as u64, nonce).unwrap();
        assert_eq!(
            window
                .decode(Zeroizing::new(bytes), &mut store)
                .unwrap_err(),
            expected
        );
    }

    let mut window = LoadWindow::new(20, NONCE).unwrap();
    assert_eq!(
        window
            .decode(
                Zeroizing::new(vec![b'x'; MAX_FILTERED_BYTES + 1]),
                &mut store
            )
            .unwrap_err(),
        PayloadError::Load(LoadError::FilteredPayloadTooLarge)
    );
}

#[test]
fn fifo_reader_keeps_only_this_loads_line_and_is_deadline_limited() {
    use std::io::Write;

    let temp = TempDir::new("drain");
    let mut runtime = Runtime::create(&temp.0).unwrap();
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .open(runtime.fifo_path())
        .unwrap();
    let own = payload(NONCE, vec![]);
    // Another load's payload, a line that is not JSON and a blank line all
    // come ahead of this load's own in one write, and are all passed over.
    let mut stream = line(&payload(STALE, vec![]));
    stream.extend(line(b"{not json}"));
    stream.extend(line(b""));
    stream.extend(line(&own));
    writer.write_all(&stream).unwrap();
    assert_eq!(
        runtime
            .read_payload(Duration::from_secs(5), &filter(NONCE))
            .unwrap()
            .as_slice(),
        own.as_slice()
    );

    // Nothing for this load is left, so the read ends at its deadline.
    writer.write_all(&line(&payload(STALE, vec![]))).unwrap();
    assert_eq!(
        runtime
            .read_payload(Duration::from_millis(10), &filter(NONCE))
            .unwrap_err(),
        RuntimeError::ReadTimeout
    );
}

/// A line past the eight mebibyte cap is dropped up to its newline, never
/// buffered whole, and this load's payload behind it still arrives.
#[test]
fn a_line_past_the_full_eight_mibibyte_cap_is_dropped_and_the_payload_behind_it_read() {
    use std::io::Write;

    let temp = TempDir::new("full-cap");
    let mut runtime = Runtime::create(&temp.0).unwrap();
    let fifo_path = runtime.fifo_path().to_owned();
    let own = payload(NONCE, vec![]);
    let written = own.clone();
    let writer = std::thread::spawn(move || {
        let mut fifo = fs::OpenOptions::new().write(true).open(fifo_path).unwrap();
        let mut oversized = vec![b'x'; MAX_FILTERED_BYTES + 2];
        oversized.push(b'\n');
        fifo.write_all(&oversized).unwrap();
        fifo.write_all(&line(&written)).unwrap();
    });

    assert_eq!(
        runtime
            .read_payload(Duration::from_secs(30), &filter(NONCE))
            .unwrap()
            .as_slice(),
        own.as_slice()
    );
    writer.join().unwrap();
}

/// A payload written for an earlier load (one a lock cancelled) sits in the
/// long-lived FIFO ahead of the next load's own. It must not be taken for it.
#[tokio::test(flavor = "current_thread")]
async fn a_stale_payload_ahead_of_this_loads_own_is_skipped() {
    use std::io::Write;

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let temp = TempDir::new("stale-payload");
    let runtime = Runtime::create(&temp.0).unwrap();
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .open(runtime.fifo_path())
        .unwrap();
    writer
        .write_all(&line(&jq_payload(STALE, vec![item_json("old", &key)])))
        .unwrap();
    let own = jq_payload(NONCE, vec![item_json("one", &key)]);
    writer.write_all(&line(&own)).unwrap();

    let mut window = LoadWindow::new(7, NONCE).unwrap();
    let read = read_payload_async(
        runtime.fifo_reader().unwrap(),
        Duration::from_secs(5),
        window.filter().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(read.as_slice(), own.as_slice());
    let mut store = KeyStore::new();
    let candidate = window.decode(read, &mut store).unwrap();
    assert_eq!(store.publish(candidate).unwrap().loaded, 1);
}

/// A writer stopped mid-payload (a lock reaps the panel's vault read) leaves
/// a fragment with no newline, and the next payload lands on the same line.
/// The payload is found where it names its nonce, as the panel's jq writes it.
#[tokio::test(flavor = "current_thread")]
async fn a_fragment_left_by_a_stopped_writer_does_not_cost_the_next_load() {
    use std::io::Write;

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let temp = TempDir::new("fragment");
    let runtime = Runtime::create(&temp.0).unwrap();
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .open(runtime.fifo_path())
        .unwrap();
    let stale = jq_payload(STALE, vec![item_json("old", &key)]);
    writer.write_all(&stale[..stale.len() / 2]).unwrap();
    let own = jq_payload(NONCE, vec![item_json("one", &key)]);
    writer.write_all(&line(&own)).unwrap();

    let mut window = LoadWindow::new(7, NONCE).unwrap();
    let read = read_payload_async(
        runtime.fifo_reader().unwrap(),
        Duration::from_secs(5),
        window.filter().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(read.as_slice(), own.as_slice(), "only this load's payload");
    let mut store = KeyStore::new();
    let candidate = window.decode(read, &mut store).unwrap();
    assert_eq!(store.publish(candidate).unwrap().loaded, 1);
}

#[test]
fn the_filter_matches_only_its_own_nonce() {
    let own = jq_payload(NONCE, vec![]);
    let mine = filter(NONCE);
    assert_eq!(mine.locate(&own), Some(0));
    assert_eq!(
        mine.locate(&payload(NONCE, vec![])),
        Some(0),
        "any key order"
    );
    assert_eq!(mine.locate(&jq_payload(STALE, vec![])), None);
    assert_eq!(mine.locate(b"{not json}"), None);
    assert_eq!(mine.locate(b""), None);
    // A nonce named inside a string is escaped, so it does not count.
    let quoted = serde_json::to_vec(&serde_json::json!({
        "loadId": STALE,
        "items": [format!("{{\"loadId\":\"{NONCE}\"}}")]
    }))
    .unwrap();
    assert_eq!(mine.locate(&quoted), None);
    // A load whose window was consumed has no filter to hand out.
    let mut window = LoadWindow::new(1, NONCE).unwrap();
    let mut store = KeyStore::new();
    window
        .decode(Zeroizing::new(own.clone()), &mut store)
        .unwrap();
    assert_eq!(window.filter().unwrap_err(), PayloadError::Closed);
}

#[test]
fn discarding_empties_the_fifo_without_waiting() {
    use std::io::Write;

    let temp = TempDir::new("discard");
    let mut runtime = Runtime::create(&temp.0).unwrap();
    // Empty: returns at once rather than blocking.
    runtime.discard_buffered();
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .open(runtime.fifo_path())
        .unwrap();
    writer.write_all(&line(&payload(NONCE, vec![]))).unwrap();
    runtime.discard_buffered();
    assert_eq!(
        runtime
            .read_payload(Duration::from_millis(20), &filter(NONCE))
            .unwrap_err(),
        RuntimeError::ReadTimeout,
        "a discarded payload must not be read by a later load"
    );
}

#[test]
fn invalid_nonce_is_never_armed() {
    assert_eq!(
        LoadWindow::new(1, "short").unwrap_err(),
        PayloadError::InvalidNonce
    );
    assert_eq!(
        LoadWindow::new(1, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").unwrap_err(),
        PayloadError::InvalidNonce
    );
}

#[test]
fn an_item_id_past_the_metadata_cap_fails_the_candidate() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut item = item_json("one", &key);
    // Real ones are 36-character UUIDs, and this is what the key is known by,
    // so it cannot be shortened to fit the way a display name can.
    item["itemId"] = serde_json::Value::String("i".repeat(65 * 1024));
    let mut window = LoadWindow::new(30, NONCE).unwrap();
    let mut store = KeyStore::new();
    assert_eq!(
        window
            .decode(Zeroizing::new(payload(NONCE, vec![item])), &mut store)
            .unwrap_err(),
        PayloadError::Load(LoadError::MetadataTooLarge)
    );
}

#[test]
fn a_long_item_name_is_truncated_rather_than_losing_the_whole_load() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut item = item_json("one", &key);
    // Multibyte on purpose. 200 of these is 400 bytes, so the cut lands in the
    // middle of a character unless the boundary is respected -- and a name is
    // a String, which cannot hold half of one.
    let name = "é".repeat(200);
    item["name"] = serde_json::Value::String(name.clone());
    let mut window = LoadWindow::new(30, NONCE).unwrap();
    let mut store = KeyStore::new();
    let candidate = window
        .decode(Zeroizing::new(payload(NONCE, vec![item])), &mut store)
        .expect("a descriptively named key is an ordinary key");
    store.publish(candidate).unwrap();

    let identities = store.public_identities();
    assert_eq!(identities.len(), 1, "the key still loaded");
    let stored = &identities[0].name;
    assert!(stored.len() <= MAX_METADATA_BYTES);
    assert!(name.starts_with(stored.as_str()));
    assert!(!stored.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn a_producer_that_closes_without_a_newline_times_out() {
    use std::io::Write;

    let temp = TempDir::new("eof");
    let runtime = Runtime::create(&temp.0).unwrap();
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .open(runtime.fifo_path())
        .unwrap();
    writer.write_all(b"{\"loadId\":\"unfinished\"").unwrap();
    drop(writer);

    // The reader keeps its own write end open, so this is a producer that gave
    // up rather than a true end-of-stream -- but the read still has to end at
    // its deadline rather than spinning on a descriptor that stays readable.
    assert_eq!(
        read_payload_async(
            runtime.fifo_reader().unwrap(),
            Duration::from_millis(150),
            filter(NONCE)
        )
        .await
        .unwrap_err(),
        RuntimeError::ReadTimeout
    );
}
