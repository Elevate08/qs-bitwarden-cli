use qs_bitwarden_ssh_agent::control::{
    parse_control_line, ControlError, ControlMessage, LoadStatus, MAX_CONTROL_LINE,
};
use qs_bitwarden_ssh_agent::runtime::{RuntimeError, ServiceRuntime};
use rand_core::{OsRng, RngCore};
use signature::Verifier;
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qsbw-lifecycle-{}-{}",
            std::process::id(),
            OsRng.next_u64()
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

#[test]
fn control_contract_accepts_every_allowlisted_message() {
    let messages = [
        r#"{"v":1,"type":"hello"}"#,
        r#"{"v":1,"type":"key_load_begin","epoch":7,"loadId":"00112233445566778899aabbccddeeff"}"#,
        r#"{"v":1,"type":"key_load_end","epoch":7,"status":"ok"}"#,
        r#"{"v":1,"type":"vault_locked","epoch":8}"#,
        r#"{"v":1,"type":"vault_logged_out"}"#,
        r#"{"v":1,"type":"approve","requestId":42,"grantSeconds":120}"#,
        r#"{"v":1,"type":"deny","requestId":42}"#,
        r#"{"v":1,"type":"unlock_cancelled","requestId":41,"reason":"user-cancelled"}"#,
        r#"{"v":1,"type":"revoke_grants"}"#,
        r#"{"v":1,"type":"shutdown"}"#,
    ];
    for message in messages {
        parse_control_line(message.as_bytes()).unwrap();
    }
    assert!(matches!(
        parse_control_line(messages[2].as_bytes()),
        Ok(ControlMessage::KeyLoadEnd {
            status: LoadStatus::Ok,
            ..
        })
    ));
}

#[test]
fn control_contract_rejects_untrusted_shapes_and_versions() {
    assert_eq!(parse_control_line(b""), Err(ControlError::Empty));
    assert_eq!(
        parse_control_line(b"{not json}"),
        Err(ControlError::Malformed)
    );
    assert_eq!(
        parse_control_line(br#"{"v":2,"type":"hello"}"#),
        Err(ControlError::WrongVersion)
    );
    assert_eq!(
        parse_control_line(br#"{"v":1,"type":"unknown"}"#),
        Err(ControlError::Malformed)
    );
    assert_eq!(
        parse_control_line(br#"{"v":1,"type":"hello","extra":true}"#),
        Err(ControlError::Malformed)
    );
    let oversized = vec![b'x'; MAX_CONTROL_LINE + 1];
    assert_eq!(parse_control_line(&oversized), Err(ControlError::TooLong));
}

#[tokio::test(flavor = "current_thread")]
async fn singleton_owns_private_socket_and_cleans_runtime_paths() {
    let temp = TempDir::new();
    let owner = ServiceRuntime::acquire(&temp.0).unwrap();
    let listener = owner.bind_socket().unwrap();
    let socket_path = owner.socket_path().to_path_buf();
    let fifo_path = owner.runtime().fifo_path().to_path_buf();
    let metadata = fs::symlink_metadata(&socket_path).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    assert!(matches!(
        ServiceRuntime::acquire(&temp.0),
        Err(RuntimeError::AlreadyRunning)
    ));
    drop(listener);
    drop(owner);
    assert!(!socket_path.exists());
    assert!(!fifo_path.exists());

    let restarted = ServiceRuntime::acquire(&temp.0).unwrap();
    assert!(restarted.runtime().fifo_path().exists());
}

#[test]
fn executable_handshake_is_private_singleton_and_eof_supervised() {
    let temp = TempDir::new();
    let executable = env!("CARGO_BIN_EXE_qs-bitwarden-ssh-agent");
    let mut child = Command::new(executable)
        .env_clear()
        .env("XDG_RUNTIME_DIR", &temp.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"v\":1,\"type\":\"hello\"}\n")
        .unwrap();
    let mut ready_line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready_line)
        .unwrap();
    let ready: serde_json::Value = serde_json::from_str(&ready_line).unwrap();
    assert_eq!(ready["v"], 1);
    assert_eq!(ready["type"], "ready");
    let socket = PathBuf::from(ready["socketPath"].as_str().unwrap());
    let fifo = PathBuf::from(ready["fifoPath"].as_str().unwrap());
    assert_eq!(
        fs::symlink_metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let status = Command::new(executable)
        .env_clear()
        .env("XDG_RUNTIME_DIR", &temp.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());

    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    assert!(!socket.exists());
    assert!(!fifo.exists());
    assert!(!temp.0.join("qs-bitwarden-cli").exists());
}

#[test]
fn disposable_key_load_identity_and_approved_sign_cross_the_real_socket() {
    let temp = TempDir::new();
    let executable = env!("CARGO_BIN_EXE_qs-bitwarden-ssh-agent");
    let mut child = Command::new(executable)
        .env_clear()
        .env("XDG_RUNTIME_DIR", &temp.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    input.write_all(b"{\"v\":1,\"type\":\"hello\"}\n").unwrap();
    input.flush().unwrap();
    let ready = read_json_line(&mut output);
    let socket = PathBuf::from(ready["socketPath"].as_str().unwrap());
    let fifo = PathBuf::from(ready["fifoPath"].as_str().unwrap());

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_blob = key.public_key().to_bytes().unwrap();
    let nonce = "0123456789abcdef0123456789abcdef";
    writeln!(
        input,
        "{{\"v\":1,\"type\":\"key_load_begin\",\"epoch\":1,\"loadId\":\"{nonce}\"}}"
    )
    .unwrap();
    input.flush().unwrap();
    let payload = serde_json::json!({"loadId": nonce, "items": [{
        "itemId": "disposable", "name": "Disposable test key",
        "privateKey": key.to_openssh(Default::default()).unwrap().as_str(),
        "publicKey": key.public_key().to_openssh().unwrap(),
        "fingerprint": key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        "requiresReprompt": false
    }]});
    let mut writer = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
    writer
        .write_all(&serde_json::to_vec(&payload).unwrap())
        .unwrap();
    writer.write_all(b"\n").unwrap();
    drop(writer);
    input
        .write_all(b"{\"v\":1,\"type\":\"key_load_end\",\"epoch\":1,\"status\":\"ok\"}\n")
        .unwrap();
    input.flush().unwrap();
    let mut loaded = read_json_line(&mut output);
    while loaded["type"] == "public_key" {
        loaded = read_json_line(&mut output);
    }
    assert_eq!(loaded["type"], "keys_loaded");
    assert_eq!(loaded["keyCount"], 1);

    let mut client = UnixStream::connect(&socket).unwrap();
    let mut slow_client = UnixStream::connect(&socket).unwrap();
    slow_client.write_all(&100_u32.to_be_bytes()).unwrap();
    client.write_all(&[0, 0, 0, 1, 11]).unwrap();
    let identities = read_agent_frame(&mut client);
    assert_eq!(identities[4], 12);
    assert!(identities
        .windows(public_blob.len())
        .any(|part| part == public_blob));

    let message = b"task nine approved signing";
    let mut request = vec![13];
    public_blob.encode(&mut request).unwrap();
    message.as_slice().encode(&mut request).unwrap();
    0_u32.encode(&mut request).unwrap();
    let mut frame = Vec::new();
    u32::try_from(request.len())
        .unwrap()
        .encode(&mut frame)
        .unwrap();
    frame.extend_from_slice(&request);
    client.write_all(&frame).unwrap();
    let approval = read_json_line(&mut output);
    assert_eq!(approval["type"], "approval_required");
    let request_id = approval["requestId"].as_u64().unwrap();
    writeln!(
        input,
        "{{\"v\":1,\"type\":\"approve\",\"requestId\":{request_id},\"grantSeconds\":0}}"
    )
    .unwrap();
    input.flush().unwrap();

    let response = read_agent_frame(&mut client);
    assert_eq!(response[4], 14);
    let mut fields = &response[5..];
    let encoded = Vec::<u8>::decode(&mut fields).unwrap();
    let signature = Signature::try_from(encoded.as_slice()).unwrap();
    Verifier::verify(key.public_key(), message, &signature).unwrap();

    // Exercise the real OpenSSH signing client with only a public key file;
    // the disposable private key remains solely in the helper keystore.
    let public_path = temp.0.join("disposable.pub");
    let message_path = temp.0.join("commit.txt");
    fs::write(&public_path, key.public_key().to_openssh().unwrap()).unwrap();
    fs::write(&message_path, b"disposable commit object").unwrap();
    let mut ssh_keygen = Command::new("/usr/bin/ssh-keygen")
        .env_clear()
        .env("SSH_AUTH_SOCK", &socket)
        .args(["-Y", "sign", "-f"])
        .arg(&public_path)
        .args(["-n", "git"])
        .arg(&message_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let approval = read_json_line(&mut output);
    let request_id = approval["requestId"].as_u64().unwrap();
    writeln!(
        input,
        "{{\"v\":1,\"type\":\"approve\",\"requestId\":{request_id},\"grantSeconds\":0}}"
    )
    .unwrap();
    input.flush().unwrap();
    assert!(ssh_keygen.wait().unwrap().success());
    assert!(message_path.with_extension("txt.sig").exists());

    input
        .write_all(b"{\"v\":1,\"type\":\"shutdown\"}\n")
        .unwrap();
    input.flush().unwrap();
    assert!(child.wait().unwrap().success());
}

/// A lock drops the private set but keeps the public projection, and the
/// design's state table says a locked-with-cache agent still lists identities:
/// otherwise every `ssh` after a lock raises an unlock prompt, including the
/// ones authenticating with an on-disk key. Signing is what the lock denies.
#[test]
fn a_locked_vault_still_lists_identities_but_refuses_to_sign() {
    let temp = TempDir::new();
    let executable = env!("CARGO_BIN_EXE_qs-bitwarden-ssh-agent");
    let mut child = Command::new(executable)
        .env_clear()
        .env("XDG_RUNTIME_DIR", &temp.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    input.write_all(b"{\"v\":1,\"type\":\"hello\"}\n").unwrap();
    input.flush().unwrap();
    let ready = read_json_line(&mut output);
    let socket = PathBuf::from(ready["socketPath"].as_str().unwrap());
    let fifo = PathBuf::from(ready["fifoPath"].as_str().unwrap());

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_blob = key.public_key().to_bytes().unwrap();
    let nonce = "0123456789abcdef0123456789abcdef";
    writeln!(
        input,
        "{{\"v\":1,\"type\":\"key_load_begin\",\"epoch\":1,\"loadId\":\"{nonce}\"}}"
    )
    .unwrap();
    input.flush().unwrap();
    let payload = serde_json::json!({"loadId": nonce, "items": [{
        "itemId": "disposable", "name": "Disposable test key",
        "privateKey": key.to_openssh(Default::default()).unwrap().as_str(),
        "publicKey": key.public_key().to_openssh().unwrap(),
        "fingerprint": key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        "requiresReprompt": false
    }]});
    let mut writer = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
    writer
        .write_all(&serde_json::to_vec(&payload).unwrap())
        .unwrap();
    writer.write_all(b"\n").unwrap();
    drop(writer);
    input
        .write_all(b"{\"v\":1,\"type\":\"key_load_end\",\"epoch\":1,\"status\":\"ok\"}\n")
        .unwrap();
    input.flush().unwrap();
    let mut loaded = read_json_line(&mut output);
    while loaded["type"] == "public_key" {
        loaded = read_json_line(&mut output);
    }
    assert_eq!(loaded["type"], "keys_loaded");
    assert_eq!(loaded["keyCount"], 1);

    // Unlocked: the identity is offered.
    assert_eq!(identity_count(&socket), 1);

    input
        .write_all(b"{\"v\":1,\"type\":\"vault_locked\",\"epoch\":1}\n")
        .unwrap();
    input.flush().unwrap();
    let locked = read_json_line(&mut output);
    assert_eq!(locked["type"], "locked");

    // Locked with a cache: still listed, because public keys are not secret.
    assert_eq!(identity_count(&socket), 1);

    // The private set is gone, so signing cannot proceed. The request is held
    // and an unlock is asked for rather than failed outright -- refusing a
    // client that has no way to retry is worse than asking. Dismissing that
    // unlock is what turns it into a refusal, and it must do so at once
    // rather than leaving the client to wait out the deadline.
    let socket_for_client = socket.clone();
    let blob = public_blob.clone();
    let client = std::thread::spawn(move || {
        let mut stream = UnixStream::connect(&socket_for_client).unwrap();
        let mut request = Vec::new();
        13_u8.encode(&mut request).unwrap();
        blob.as_slice().encode(&mut request).unwrap();
        b"payload".as_slice().encode(&mut request).unwrap();
        0_u32.encode(&mut request).unwrap();
        let mut framed = u32::try_from(request.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&request);
        stream.write_all(&framed).unwrap();
        read_agent_frame(&mut stream)
    });

    let unlock = read_json_line(&mut output);
    assert_eq!(unlock["type"], "unlock_required");
    let request_id = unlock["requestId"].as_u64().unwrap();
    let started = std::time::Instant::now();
    writeln!(
        input,
        "{{\"v\":1,\"type\":\"unlock_cancelled\",\"requestId\":{request_id},\"reason\":\"user-cancelled\"}}"
    )
    .unwrap();
    input.flush().unwrap();
    let response = client.join().unwrap();
    assert_eq!(
        response[4], 5,
        "a dismissed unlock must refuse the signature"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "a dismissed unlock must refuse at once, not at the deadline"
    );

    // Logout takes the public projection with it.
    input
        .write_all(b"{\"v\":1,\"type\":\"vault_logged_out\"}\n")
        .unwrap();
    input.flush().unwrap();
    assert_eq!(identity_count(&socket), 0);

    input
        .write_all(b"{\"v\":1,\"type\":\"shutdown\"}\n")
        .unwrap();
    input.flush().unwrap();
    assert!(child.wait().unwrap().success());
}

/// A sign request against a locked-but-cached vault must not simply fail: the
/// design has it raise an unlock, hold the request across the load, and then
/// ask for approval. The unlock and the approval carry different request ids,
/// because they are different decisions.
#[test]
fn a_locked_sign_request_raises_unlock_then_approval() {
    let mut agent = TestAgent::start();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_blob = key.public_key().to_bytes().unwrap();
    agent.load_key(&key, 1, "0123456789abcdef0123456789abcdef");
    assert_eq!(identity_count(&agent.socket), 1);

    agent.send("{\"v\":1,\"type\":\"vault_locked\",\"epoch\":1}");
    assert_eq!(agent.read()["type"], "locked");

    // The client blocks on its request while the panel is asked to unlock.
    let socket = agent.socket.clone();
    let blob = public_blob.clone();
    let client = std::thread::spawn(move || {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(&sign_request(&blob)).unwrap();
        read_agent_frame(&mut stream)
    });

    let unlock = agent.read();
    assert_eq!(unlock["type"], "unlock_required");
    assert_eq!(unlock["reason"], "sign");
    let unlock_id = unlock["requestId"].as_u64().unwrap();

    // Unlocking is a fresh load at a new epoch, and it releases the request.
    agent.load_key(&key, 2, "fedcba9876543210fedcba9876543210");
    // The unlock prompt is withdrawn before the approval prompt replaces it,
    // so the panel is never left showing a question that has been answered.
    let withdrawn = agent.read();
    assert_eq!(withdrawn["type"], "request_cancelled");
    assert_eq!(withdrawn["requestId"].as_u64().unwrap(), unlock_id);
    assert_eq!(withdrawn["reason"], "released");
    let approval = agent.read();
    assert_eq!(approval["type"], "approval_required");
    let approval_id = approval["requestId"].as_u64().unwrap();
    assert_ne!(
        unlock_id, approval_id,
        "unlock and approval are separate decisions"
    );

    agent.send(&format!(
        "{{\"v\":1,\"type\":\"approve\",\"requestId\":{approval_id},\"grantSeconds\":0}}"
    ));
    let response = client.join().unwrap();
    assert_eq!(
        response[4], 14,
        "an approved request must return a signature"
    );
    agent.shutdown();
}

/// The approval decision needs the key's identity and the requesting program,
/// both of which come from the public cache. None of it depends on the vault
/// read finishing, so a user may approve while keys are still loading and the
/// signature is produced the moment they arrive -- rather than being made to
/// wait several seconds and only then be asked.
#[test]
fn an_approval_given_during_a_load_is_honoured_when_keys_arrive() {
    let mut agent = TestAgent::start();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_blob = key.public_key().to_bytes().unwrap();
    agent.load_key(&key, 1, "0123456789abcdef0123456789abcdef");
    agent.send("{\"v\":1,\"type\":\"vault_locked\",\"epoch\":1}");
    assert_eq!(agent.read()["type"], "locked");

    let socket = agent.socket.clone();
    let blob = public_blob.clone();
    let client = std::thread::spawn(move || {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(&sign_request(&blob)).unwrap();
        read_agent_frame(&mut stream)
    });

    let unlock = agent.read();
    assert_eq!(unlock["type"], "unlock_required");
    let request_id = unlock["requestId"].as_u64().unwrap();

    // Approved against the held request, before any load has been started.
    agent.send(&format!(
        "{{\"v\":1,\"type\":\"approve\",\"requestId\":{request_id},\"grantSeconds\":0}}"
    ));

    // The load lands afterwards and releases the request without asking again.
    agent.load_key(&key, 2, "fedcba9876543210fedcba9876543210");
    let response = client.join().unwrap();
    assert_eq!(
        response[4], 14,
        "an approval given while keys were loading must produce a signature"
    );
    agent.shutdown();
}

/// The same path must still refuse when the key that comes back is not the
/// one that was approved. The approval names a key; the load decides whether
/// that key is actually present.
#[test]
fn an_approval_given_during_a_load_still_requires_the_approved_key() {
    let mut agent = TestAgent::start();
    let approved = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_blob = approved.public_key().to_bytes().unwrap();
    agent.load_key(&approved, 1, "0123456789abcdef0123456789abcdef");
    agent.send("{\"v\":1,\"type\":\"vault_locked\",\"epoch\":1}");
    assert_eq!(agent.read()["type"], "locked");

    let socket = agent.socket.clone();
    let blob = public_blob.clone();
    let client = std::thread::spawn(move || {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(&sign_request(&blob)).unwrap();
        read_agent_frame(&mut stream)
    });

    let unlock = agent.read();
    let request_id = unlock["requestId"].as_u64().unwrap();
    agent.send(&format!(
        "{{\"v\":1,\"type\":\"approve\",\"requestId\":{request_id},\"grantSeconds\":0}}"
    ));

    // A vault that now holds a different key entirely.
    agent.load_key(&other, 2, "fedcba9876543210fedcba9876543210");
    let response = client.join().unwrap();
    assert_eq!(
        response[4], 5,
        "the approved key is gone, so the signature must fail closed"
    );
    agent.shutdown();
}

/// A freshly started companion has no public cache, so `ssh-add -L` is empty
/// and no client will ever offer a vault key -- which means no sign request,
/// and no way to ask for an unlock. Unlock-on-demand exists for exactly that
/// cliff, and it has to begin at the identity listing rather than at signing.
#[test]
fn unlock_on_demand_raises_an_unlock_for_an_empty_identity_listing() {
    let mut agent = TestAgent::start();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();

    // Off by default: an empty cache answers empty and asks for nothing.
    assert_eq!(identity_count(&agent.socket), 0);

    agent.send("{\"v\":1,\"type\":\"options\",\"unlockOnDemand\":true}");

    let socket = agent.socket.clone();
    let client = std::thread::spawn(move || {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(&[0_u8, 0, 0, 1, 11]).unwrap();
        read_agent_frame(&mut stream)
    });

    let unlock = agent.read();
    assert_eq!(unlock["type"], "unlock_required");
    assert_eq!(unlock["reason"], "list-identities");

    // The load releases the waiting listing with the real identities.
    agent.load_key(&key, 1, "0123456789abcdef0123456789abcdef");
    let frame = client.join().unwrap();
    assert_eq!(frame[4], 12, "expected an identities answer");
    let mut body = &frame[5..];
    assert_eq!(u32::decode(&mut body).unwrap(), 1);
    agent.shutdown();
}

/// Several clients starting at once must not produce several unlock prompts.
#[test]
fn concurrent_identity_listings_coalesce_into_one_unlock() {
    let mut agent = TestAgent::start();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    agent.send("{\"v\":1,\"type\":\"options\",\"unlockOnDemand\":true}");

    let mut clients = Vec::new();
    for _ in 0..3 {
        let socket = agent.socket.clone();
        clients.push(std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&socket).unwrap();
            stream.write_all(&[0_u8, 0, 0, 1, 11]).unwrap();
            read_agent_frame(&mut stream)
        }));
        std::thread::sleep(std::time::Duration::from_millis(120));
    }

    let unlock = agent.read();
    assert_eq!(unlock["type"], "unlock_required");

    agent.load_key(&key, 1, "0123456789abcdef0123456789abcdef");
    for client in clients {
        let frame = client.join().unwrap();
        assert_eq!(frame[4], 12, "every waiting listing gets its answer");
    }
    // Exactly one unlock was asked for; the next line is the keys_loaded that
    // load_key already consumed, so nothing else is queued behind it.
    agent.shutdown();
}

/// A client that walks away leaves a prompt on screen with nothing behind it.
/// The companion says so rather than letting it sit until its deadline.
#[test]
fn a_disconnected_client_withdraws_its_prompt() {
    let mut agent = TestAgent::start();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_blob = key.public_key().to_bytes().unwrap();
    agent.load_key(&key, 1, "0123456789abcdef0123456789abcdef");

    let mut stream = UnixStream::connect(&agent.socket).unwrap();
    stream.write_all(&sign_request(&public_blob)).unwrap();
    let approval = agent.read();
    assert_eq!(approval["type"], "approval_required");
    let request_id = approval["requestId"].as_u64().unwrap();

    drop(stream);
    let cancelled = agent.read();
    assert_eq!(cancelled["type"], "request_cancelled");
    assert_eq!(cancelled["requestId"], request_id);
    agent.shutdown();
}

/// Grants are only useful if the panel can see and revoke them, so every
/// change to the set is announced with its remaining time.
#[test]
fn granting_and_revoking_announce_the_live_set() {
    let mut agent = TestAgent::start();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_blob = key.public_key().to_bytes().unwrap();
    agent.load_key(&key, 1, "0123456789abcdef0123456789abcdef");

    let socket = agent.socket.clone();
    let blob = public_blob.clone();
    let client = std::thread::spawn(move || {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(&sign_request(&blob)).unwrap();
        let first = read_agent_frame(&mut stream);
        // A second signature on the same connection rides the grant, with no
        // further prompt -- which is the whole point of offering one.
        stream.write_all(&sign_request(&blob)).unwrap();
        (first, read_agent_frame(&mut stream))
    });

    let approval = agent.read();
    let request_id = approval["requestId"].as_u64().unwrap();
    assert_eq!(approval["grantOffered"], true);
    agent.send(&format!(
        "{{\"v\":1,\"type\":\"approve\",\"requestId\":{request_id},\"grantSeconds\":120}}"
    ));

    let changed = agent.read();
    assert_eq!(changed["type"], "grants_changed");
    let grants = changed["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert!(grants[0]["expiresInSec"].as_u64().unwrap() <= 120);
    assert!(grants[0]["expiresInSec"].as_u64().unwrap() > 0);
    let grant_id = grants[0]["grantId"].as_u64().unwrap();
    assert!(
        grants[0].get("privateKey").is_none(),
        "a grant must carry no key material"
    );

    let (first, second) = client.join().unwrap();
    assert_eq!(first[4], 14);
    assert_eq!(second[4], 14, "a live grant signs without prompting again");

    agent.send(&format!(
        "{{\"v\":1,\"type\":\"revoke_grant\",\"grantId\":{grant_id}}}"
    ));
    let revoked = agent.read();
    assert_eq!(revoked["type"], "grants_changed");
    assert_eq!(revoked["grants"].as_array().unwrap().len(), 0);
    agent.shutdown();
}

/// The panel validates the bundled helper before it trusts it, and needs the
/// helper's own answers to do that: what version it is, what protocol it
/// speaks, and whether its crypto actually works on this machine. Both must
/// answer without touching the filesystem, opening a socket, or needing a
/// runtime directory -- they run before any of that exists.
#[test]
fn version_and_self_test_answer_without_touching_the_system() {
    let executable = env!("CARGO_BIN_EXE_qs-bitwarden-ssh-agent");
    let temp = TempDir::new();

    let version = Command::new(executable)
        .arg("--version")
        .env_clear()
        .output()
        .unwrap();
    assert!(version.status.success(), "--version must succeed");
    let text = String::from_utf8(version.stdout).unwrap();
    assert!(
        text.contains(env!("CARGO_PKG_VERSION")),
        "--version must report the crate version, got {text:?}"
    );
    assert!(
        text.contains("protocol 1"),
        "--version must report the control protocol version, got {text:?}"
    );

    // No XDG_RUNTIME_DIR at all: neither mode may depend on one.
    let selftest = Command::new(executable)
        .arg("--self-test")
        .env_clear()
        .output()
        .unwrap();
    assert!(
        selftest.status.success(),
        "--self-test failed: {}",
        String::from_utf8_lossy(&selftest.stderr)
    );
    let report = String::from_utf8(selftest.stdout).unwrap();
    assert!(
        report.contains("ok"),
        "self-test should say so, got {report:?}"
    );

    // Nothing was created anywhere it could have been.
    let runtime = std::path::Path::new(&temp.0).join("qs-bitwarden-cli");
    assert!(
        !runtime.exists(),
        "a self-test must not create a runtime directory"
    );

    // Neither mode may leak key material to either stream.
    let combined = format!("{report}{}", String::from_utf8_lossy(&selftest.stderr));
    assert!(
        !combined.contains("PRIVATE"),
        "the self-test must not print key material"
    );
}

/// An unknown flag must not be mistaken for "run as the agent". The panel
/// launches this binary with no arguments; anything else is a mistake worth
/// reporting rather than silently starting a key-holding daemon.
#[test]
fn an_unknown_argument_is_refused() {
    let executable = env!("CARGO_BIN_EXE_qs-bitwarden-ssh-agent");
    let out = Command::new(executable)
        .arg("--not-a-real-flag")
        .env_clear()
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an unknown flag must not start the agent"
    );
}

/// A running agent with its control channel, for tests that drive several
/// messages in sequence.
struct TestAgent {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: BufReader<std::process::ChildStdout>,
    socket: PathBuf,
    fifo: PathBuf,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    _temp: TempDir,
}

impl TestAgent {
    fn start() -> Self {
        let temp = TempDir::new();
        let executable = env!("CARGO_BIN_EXE_qs-bitwarden-ssh-agent");
        let mut child = Command::new(executable)
            .env_clear()
            .env("XDG_RUNTIME_DIR", &temp.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        input.write_all(b"{\"v\":1,\"type\":\"hello\"}\n").unwrap();
        input.flush().unwrap();
        let ready = read_json_line(&mut output);
        let socket = PathBuf::from(ready["socketPath"].as_str().unwrap());
        let fifo = PathBuf::from(ready["fifoPath"].as_str().unwrap());

        // Every read below blocks on the agent's stdout, so a message the
        // agent never sends would hang the whole suite instead of failing it.
        // The watchdog kills the child, which closes stdout and turns that
        // hang into an EOF the assertions report.
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let watching = alive.clone();
        let pid = child.id();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while std::time::Instant::now() < deadline {
                if !watching.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
        });

        Self {
            child,
            input,
            output,
            socket,
            fifo,
            alive,
            _temp: temp,
        }
    }

    fn send(&mut self, line: &str) {
        writeln!(self.input, "{line}").unwrap();
        self.input.flush().unwrap();
    }

    fn read(&mut self) -> serde_json::Value {
        let mut line = String::new();
        self.output.read_line(&mut line).unwrap();
        assert!(
            !line.is_empty(),
            "the agent closed its control channel without answering"
        );
        serde_json::from_str(&line).unwrap()
    }

    fn load_key(&mut self, key: &PrivateKey, epoch: u64, nonce: &str) {
        self.send(&format!(
            "{{\"v\":1,\"type\":\"key_load_begin\",\"epoch\":{epoch},\"loadId\":\"{nonce}\"}}"
        ));
        let payload = serde_json::json!({"loadId": nonce, "items": [{
            "itemId": "disposable", "name": "Disposable test key",
            "privateKey": key.to_openssh(Default::default()).unwrap().as_str(),
            "publicKey": key.public_key().to_openssh().unwrap(),
            "fingerprint": key.public_key().fingerprint(HashAlg::Sha256).to_string(),
            "requiresReprompt": false
        }]});
        let mut writer = fs::OpenOptions::new().write(true).open(&self.fifo).unwrap();
        writer
            .write_all(&serde_json::to_vec(&payload).unwrap())
            .unwrap();
        writer.write_all(b"\n").unwrap();
        drop(writer);
        self.send(&format!(
            "{{\"v\":1,\"type\":\"key_load_end\",\"epoch\":{epoch},\"status\":\"ok\"}}"
        ));
        // The validated public set arrives one message per key ahead of
        // keys_loaded, so the panel holds the whole projection before it is
        // told the load finished. Skip past them to the completion.
        loop {
            let message = self.read();
            if message["type"] == "keys_loaded" {
                break;
            }
            assert_eq!(
                message["type"], "public_key",
                "only public keys may precede keys_loaded"
            );
            assert!(
                !message["publicKey"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("PRIVATE"),
                "a public_key message must never carry private material"
            );
        }
    }

    fn shutdown(&mut self) {
        self.send("{\"v\":1,\"type\":\"shutdown\"}");
        let status = self.child.wait().unwrap();
        self.alive
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(status.success());
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        self.alive
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let _ = self.child.kill();
    }
}

/// A framed SSH_AGENTC_SIGN_REQUEST for one public blob.
fn sign_request(public_blob: &[u8]) -> Vec<u8> {
    let mut request = Vec::new();
    13_u8.encode(&mut request).unwrap();
    public_blob.encode(&mut request).unwrap();
    b"payload".as_slice().encode(&mut request).unwrap();
    0_u32.encode(&mut request).unwrap();
    let mut framed = u32::try_from(request.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&request);
    framed
}

/// Number of identities the agent offers over its real socket.
fn identity_count(socket: &PathBuf) -> usize {
    let mut stream = UnixStream::connect(socket).unwrap();
    let request = [0_u8, 0, 0, 1, 11];
    stream.write_all(&request).unwrap();
    let frame = read_agent_frame(&mut stream);
    assert_eq!(frame[4], 12, "expected an identities answer, not a failure");
    let mut body = &frame[5..];
    usize::try_from(u32::decode(&mut body).unwrap()).unwrap()
}

fn read_json_line(reader: &mut BufReader<std::process::ChildStdout>) -> serde_json::Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn read_agent_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).unwrap();
    let length = usize::try_from(u32::from_be_bytes(header)).unwrap();
    let mut frame = header.to_vec();
    frame.resize(length + 4, 0);
    stream.read_exact(&mut frame[4..]).unwrap();
    frame
}
