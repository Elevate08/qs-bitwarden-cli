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
    approvals.expire(31_001);
    assert_eq!(approvals.pending_count(), 0);
    assert_eq!(
        approvals.approve(ids[1], 0, 31_001),
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

#[test]
fn grants_are_capped_and_bound_to_key_pid_start_time_and_executable() {
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
    assert!(matches!(
        approvals
            .submit(3, &key, peer(200, 51, "/usr/bin/git"), 20)
            .unwrap(),
        Submit::Pending(_)
    ));
    assert!(matches!(
        approvals
            .submit(3, &key, peer(200, 50, "/usr/bin/ssh"), 20)
            .unwrap(),
        Submit::Pending(_)
    ));
    assert!(matches!(
        approvals.submit(3, b"different key", original, 20).unwrap(),
        Submit::Pending(_)
    ));
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
