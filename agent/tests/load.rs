use qs_bitwarden_ssh_agent::keystore::{KeyStore, LoadError, MAX_FILTERED_BYTES};
use qs_bitwarden_ssh_agent::load::{LoadWindow, PayloadError};
use qs_bitwarden_ssh_agent::runtime::{Runtime, RuntimeError};
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

const NONCE: &str = "0123456789abcdef0123456789abcdef";

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
        "privateKey": key.to_openssh(Default::default()).unwrap().as_str(),
        "publicKey": key.public_key().to_openssh().unwrap(),
        "fingerprint": key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        "requiresReprompt": false
    })
}

fn payload(nonce: &str, items: Vec<serde_json::Value>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"loadId": nonce, "items": items})).unwrap()
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
fn fifo_drain_is_newline_framed_and_deadline_limited() {
    use std::io::Write;

    let temp = TempDir::new("drain");
    let mut runtime = Runtime::create(&temp.0).unwrap();
    let mut writer = fs::OpenOptions::new()
        .write(true)
        .open(runtime.fifo_path())
        .unwrap();
    writer.write_all(b"{\"loadId\":\"ok\"}\n").unwrap();
    assert_eq!(
        runtime
            .read_payload(Duration::from_secs(1))
            .unwrap()
            .as_slice(),
        b"{\"loadId\":\"ok\"}"
    );

    writer.write_all(b"{}\n{}\n").unwrap();
    assert_eq!(
        runtime.read_payload(Duration::from_secs(1)).unwrap_err(),
        RuntimeError::MultiplePayloads
    );
    assert_eq!(
        runtime.read_payload(Duration::from_millis(10)).unwrap_err(),
        RuntimeError::ReadTimeout
    );
}

#[test]
fn fifo_drain_rejects_a_stream_beyond_the_full_eight_mibibyte_cap() {
    use std::io::Write;

    let temp = TempDir::new("full-cap");
    let mut runtime = Runtime::create(&temp.0).unwrap();
    let fifo_path = runtime.fifo_path().to_owned();
    let writer = std::thread::spawn(move || {
        let mut fifo = fs::OpenOptions::new().write(true).open(fifo_path).unwrap();
        let oversized = vec![b'x'; MAX_FILTERED_BYTES + 2];
        let _ = fifo.write_all(&oversized);
    });

    assert_eq!(
        runtime.read_payload(Duration::from_secs(30)).unwrap_err(),
        RuntimeError::PayloadTooLarge
    );
    writer.join().unwrap();
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
