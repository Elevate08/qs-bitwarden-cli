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
    let loaded = read_json_line(&mut output);
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
