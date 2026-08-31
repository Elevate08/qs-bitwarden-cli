use qs_bitwarden_ssh_agent::approvals::{ApprovalError, ApprovalManager, Submit};
use qs_bitwarden_ssh_agent::keystore::{CandidateItem, KeyStore};
use qs_bitwarden_ssh_agent::peer::PeerContext;
use rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use zeroize::Zeroizing;

fn peer(pid: u32, start: u64, executable: &str) -> PeerContext {
    PeerContext::new(rustix::process::geteuid().as_raw(), pid, start, executable).unwrap()
}

fn loaded_store(epoch: u64) -> (KeyStore, Vec<u8>) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let blob = key.public_key().to_bytes().unwrap();
    let mut store = KeyStore::new();
    let mut load = store.begin_load(epoch, 4096).unwrap();
    load.add(CandidateItem {
        item_id: "item".into(),
        name: "Work".into(),
        private_key_pem: Zeroizing::new(
            key.to_openssh(Default::default())
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
        public_key: key.public_key().to_openssh().unwrap(),
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        requires_reprompt: false,
    })
    .unwrap();
    store.publish(load).unwrap();
    (store, blob)
}

/// Two clocks bound one wait, and they are not independent. The companion's
/// request deadline is the human's time to answer; the server's reply wait is
/// how long a client blocks for that answer. If the second is shorter, the
/// first is decorative -- which it was, with both set to thirty seconds.
#[test]
fn a_client_waits_longer_than_the_human_is_given_to_answer() {
    assert!(
        qs_bitwarden_ssh_agent::server::RESPONSE_TIMEOUT
            > std::time::Duration::from_millis(
                qs_bitwarden_ssh_agent::approvals::REQUEST_LIFETIME_MS
            ),
        "a client must not give up before the request it is waiting on expires"
    );
    // Reading a frame or writing a reply is machine-speed and stays short;
    // only the wait on a person is long.
    assert!(
        qs_bitwarden_ssh_agent::server::CLIENT_IO_TIMEOUT
            < qs_bitwarden_ssh_agent::server::RESPONSE_TIMEOUT,
        "socket I/O should not inherit the human-scale timeout"
    );
    // The number itself, so raising it stays a deliberate act.
    assert_eq!(
        qs_bitwarden_ssh_agent::approvals::REQUEST_LIFETIME_MS,
        120_000,
        "see docs/decisions/0003-request-deadline.md"
    );
}

#[test]
fn queue_is_bounded_expires_and_disconnect_cancels() {
    let (_, key) = loaded_store(1);
    let mut approvals = ApprovalManager::new(rustix::process::geteuid().as_raw());
    let client = peer(100, 10, "/usr/bin/ssh");
    let mut ids = Vec::new();
    for _ in 0..4 {
        match approvals.submit(1, &key, client.clone(), 1_000).unwrap() {
            Submit::Pending(id) => ids.push(id),
            Submit::Granted(_) => panic!("no grant exists"),
        }
    }
    assert_eq!(
        approvals.submit(1, &key, client.clone(), 1_000),
        Err(ApprovalError::QueueFull)
    );
    approvals.disconnect(ids[0]);
    assert_eq!(
        approvals.approve(ids[0], 0, 1_001),
        Err(ApprovalError::UnknownRequest)
    );
    // Derived from the lifetime rather than hardcoded, so changing the
    // deadline cannot leave this test asserting the old one.
    let past_deadline = qs_bitwarden_ssh_agent::approvals::REQUEST_LIFETIME_MS + 1_001;
    approvals.expire(past_deadline - 1_001 - 1);
    assert_ne!(
        approvals.pending_count(),
        0,
        "a request must survive right up to its deadline"
    );
    approvals.expire(past_deadline);
    assert_eq!(approvals.pending_count(), 0);
    assert_eq!(
        approvals.approve(ids[1], 0, past_deadline),
        Err(ApprovalError::UnknownRequest)
    );
}

#[test]
fn approval_is_single_use_and_old_epoch_fails_at_final_check() {
    let (mut store, key) = loaded_store(7);
    let mut approvals = ApprovalManager::new(rustix::process::geteuid().as_raw());
    let id = match approvals
        .submit(7, &key, peer(101, 20, "/usr/bin/ssh"), 0)
        .unwrap()
    {
        Submit::Pending(id) => id,
        _ => unreachable!(),
    };
    let authorization = approvals.approve(id, 0, 1).unwrap();
    assert_eq!(
        approvals.approve(id, 0, 1),
        Err(ApprovalError::UnknownRequest)
    );
    assert!(authorization.finalize(&store).is_some());
    let second = match approvals
        .submit(7, &key, peer(101, 20, "/usr/bin/ssh"), 2)
        .unwrap()
    {
        Submit::Pending(id) => approvals.approve(id, 0, 2).unwrap(),
        _ => unreachable!(),
    };
    store.lock(8);
    assert!(second.finalize(&store).is_none());
}

/// A grant covers one key and one program, not one process. Git spawns a
/// fresh `ssh-keygen` for every commit it signs, so a grant tied to a PID
/// never matches the case grants exist for -- a rebase would prompt once per
/// commit regardless. Scoping to the executable path is what makes the
/// feature do its job; see docs/decisions/0002-grant-scope.md for the
/// exposure this accepts.
#[test]
fn grants_are_capped_and_bound_to_key_and_executable() {
    let (_, key) = loaded_store(3);
    let mut approvals = ApprovalManager::new(rustix::process::geteuid().as_raw());
    let original = peer(200, 50, "/usr/bin/git");
    let id = match approvals.submit(3, &key, original.clone(), 0).unwrap() {
        Submit::Pending(id) => id,
        _ => unreachable!(),
    };
    approvals.approve(id, 10_000, 10).unwrap();
    assert_eq!(approvals.grants()[0].expires_at_ms, 900_010);
    assert!(matches!(
        approvals.submit(3, &key, original.clone(), 20).unwrap(),
        Submit::Granted(_)
    ));

    // The case that matters: a different process, same program. Every commit
    // in a rebase looks like this.
    assert!(
        matches!(
            approvals
                .submit(3, &key, peer(9001, 7777, "/usr/bin/git"), 20)
                .unwrap(),
            Submit::Granted(_)
        ),
        "a fresh process running the same program must ride the grant"
    );

    // A different program does not, even from the same process identity.
    assert!(matches!(
        approvals
            .submit(3, &key, peer(200, 50, "/usr/bin/ssh"), 20)
            .unwrap(),
        Submit::Pending(_)
    ));
    // Nor does a different key.
    assert!(matches!(
        approvals.submit(3, b"different key", original, 20).unwrap(),
        Submit::Pending(_)
    ));
}

/// Widening the scope to a program must not widen it across users. The peer
/// UID is the one thing the companion actually verifies.
#[test]
fn a_grant_never_crosses_to_another_user() {
    let (_, key) = loaded_store(3);
    let expected = rustix::process::geteuid().as_raw();
    let mut approvals = ApprovalManager::new(expected);
    let mine = peer(200, 50, "/usr/bin/git");
    let id = match approvals.submit(3, &key, mine, 0).unwrap() {
        Submit::Pending(id) => id,
        _ => unreachable!(),
    };
    approvals.approve(id, 120, 10).unwrap();

    let theirs = PeerContext::new(expected.wrapping_add(1), 201, 51, "/usr/bin/git").unwrap();
    assert!(
        approvals.submit(3, &key, theirs, 20).is_err(),
        "another user must not reach a grant, whatever program they run"
    );
}

#[test]
fn wrong_uid_and_lifecycle_revocation_fail_closed() {
    let (_, key) = loaded_store(5);
    let expected = rustix::process::geteuid().as_raw();
    let mut approvals = ApprovalManager::new(expected);
    let wrong = PeerContext::new(expected.wrapping_add(1), 1, 1, "/usr/bin/ssh").unwrap();
    assert_eq!(
        approvals.submit(5, &key, wrong, 0),
        Err(ApprovalError::WrongUid)
    );

    let p = peer(300, 60, "/usr/bin/ssh");
    let id = match approvals.submit(5, &key, p.clone(), 0).unwrap() {
        Submit::Pending(id) => id,
        _ => unreachable!(),
    };
    approvals.approve(id, 120, 0).unwrap();
    let grant_id = approvals.grants()[0].id;
    approvals.revoke_grant(grant_id);
    assert!(approvals.grants().is_empty());
    let id = match approvals.submit(5, &key, p.clone(), 0).unwrap() {
        Submit::Pending(id) => id,
        _ => unreachable!(),
    };
    approvals.approve(id, 120, 0).unwrap();
    approvals.revoke_peer(&p);
    assert!(approvals.grants().is_empty());
    let id = match approvals.submit(5, &key, p.clone(), 0).unwrap() {
        Submit::Pending(id) => id,
        _ => unreachable!(),
    };
    approvals.approve(id, 120, 0).unwrap();
    approvals.invalidate_all();
    assert!(approvals.grants().is_empty());
    assert_eq!(approvals.pending_count(), 0);
    assert!(matches!(
        approvals.submit(5, &key, p, 1).unwrap(),
        Submit::Pending(_)
    ));
}

#[test]
fn peer_snapshot_comes_from_proc_without_trusting_display_metadata() {
    let pid = std::process::id();
    let snapshot = PeerContext::capture(rustix::process::geteuid().as_raw(), pid).unwrap();
    assert_eq!(snapshot.pid, pid);
    assert!(snapshot.start_time_ticks > 0);
    assert!(snapshot.executable.is_absolute());
}
