use qs_bitwarden_ssh_agent::keystore::{
    CandidateItem, KeyStore, LoadError, SkipCode, MAX_FILTERED_BYTES, MAX_KEYS, MAX_PEM_BYTES,
};
use qs_bitwarden_ssh_agent::state::VaultState;
use rand_core::OsRng;
use signature::Verifier;
use ssh_key::private::RsaKeypair;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use zeroize::Zeroizing;

fn item(id: &str, key: &PrivateKey) -> CandidateItem {
    CandidateItem {
        item_id: id.to_owned(),
        name: format!("key {id}"),
        private_key_pem: Zeroizing::new(
            key.to_openssh(Default::default())
                .unwrap()
                .as_bytes()
                .to_vec(),
        ),
        public_key: key.public_key().to_openssh().unwrap(),
        fingerprint: key.public_key().fingerprint(HashAlg::Sha256).to_string(),
        requires_reprompt: false,
    }
}

fn ed25519() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}

#[test]
fn candidate_skips_bad_mismatched_reprompt_and_duplicate_items() {
    let valid = ed25519();
    let other = ed25519();
    let mut store = KeyStore::new();
    let mut load = store.begin_load(1, 4096).unwrap();

    assert_eq!(load.add(item("valid", &valid)).unwrap(), None);
    assert_eq!(
        load.add(CandidateItem {
            private_key_pem: Zeroizing::new(b"not a private key".to_vec()),
            ..item("malformed", &other)
        })
        .unwrap(),
        Some(SkipCode::MalformedPrivateKey)
    );
    assert_eq!(
        load.add(CandidateItem {
            public_key: other.public_key().to_openssh().unwrap(),
            ..item("public-mismatch", &valid)
        })
        .unwrap(),
        Some(SkipCode::PublicKeyMismatch)
    );
    assert_eq!(
        load.add(CandidateItem {
            fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            ..item("fingerprint-mismatch", &valid)
        })
        .unwrap(),
        Some(SkipCode::FingerprintMismatch)
    );
    assert_eq!(
        load.add(CandidateItem {
            requires_reprompt: true,
            ..item("reprompt", &other)
        })
        .unwrap(),
        Some(SkipCode::RequiresReprompt)
    );
    assert_eq!(
        load.add(item("duplicate", &valid)).unwrap(),
        Some(SkipCode::Duplicate)
    );

    let report = store.publish(load).unwrap();
    assert_eq!(report.loaded, 1);
    assert_eq!(report.skipped.len(), 5);
    assert_eq!(store.state(), VaultState::Unlocked);
    assert_eq!(store.public_identities().len(), 1);
    assert_eq!(store.public_identities()[0].item_id, "valid");
}

#[test]
fn global_limits_reject_the_whole_candidate_and_leave_no_private_set() {
    let key = ed25519();
    let mut store = KeyStore::new();
    let mut initial = store.begin_load(1, 4096).unwrap();
    initial.add(item("old", &key)).unwrap();
    store.publish(initial).unwrap();
    assert!(store
        .authorize(store.public_identities()[0].public_blob())
        .is_some());

    assert_eq!(
        store.begin_load(2, MAX_FILTERED_BYTES + 1).unwrap_err(),
        LoadError::FilteredPayloadTooLarge
    );
    assert_eq!(store.state(), VaultState::Loading);
    assert!(store
        .authorize(key.public_key().to_bytes().unwrap().as_slice())
        .is_none());

    let mut too_many = store.begin_load(3, 4096).unwrap();
    for index in 0..MAX_KEYS {
        let unique = ed25519();
        assert_eq!(
            too_many.add(item(&index.to_string(), &unique)).unwrap(),
            None
        );
    }
    assert_eq!(
        too_many.add(item("overflow", &ed25519())).unwrap_err(),
        LoadError::TooManyKeys
    );

    let mut oversized = store.begin_load(4, MAX_PEM_BYTES).unwrap();
    let mut huge = item("huge", &key);
    huge.private_key_pem = Zeroizing::new(vec![b'x'; MAX_PEM_BYTES + 1]);
    assert_eq!(oversized.add(huge).unwrap_err(), LoadError::PemTooLarge);
}

#[test]
fn publish_is_atomic_and_stale_or_failed_loads_cannot_mix_epochs() {
    let first = ed25519();
    let second = ed25519();
    let mut store = KeyStore::new();
    let mut load = store.begin_load(7, 4096).unwrap();
    load.add(item("first", &first)).unwrap();

    store.lock(8);
    assert_eq!(store.publish(load).unwrap_err(), LoadError::StaleEpoch);
    assert!(store.public_identities().is_empty());

    let mut replacement = store.begin_load(9, 4096).unwrap();
    replacement.add(item("second", &second)).unwrap();
    store.publish(replacement).unwrap();
    assert_eq!(store.public_identities().len(), 1);
    assert_eq!(store.public_identities()[0].item_id, "second");
}

#[test]
fn lock_invalidates_authorization_before_dropping_keys_and_keeps_public_cache() {
    let key = ed25519();
    let public_blob = key.public_key().to_bytes().unwrap();
    let mut store = KeyStore::new();
    let mut load = store.begin_load(11, 4096).unwrap();
    load.add(item("work", &key)).unwrap();
    store.publish(load).unwrap();

    let permit = store.authorize(&public_blob).unwrap();
    store.lock(12);

    assert_eq!(store.state(), VaultState::LockedCached);
    assert_eq!(store.public_identities().len(), 1);
    assert!(store.sign(&permit, b"must not sign", 0).is_none());
    assert!(store.authorize(&public_blob).is_none());
}

#[test]
fn current_epoch_permit_signs_without_cloning_private_keys() {
    let key = ed25519();
    let public_blob = key.public_key().to_bytes().unwrap();
    let mut store = KeyStore::new();
    let mut load = store.begin_load(21, 4096).unwrap();
    load.add(item("work", &key)).unwrap();
    store.publish(load).unwrap();

    let permit = store.authorize(&public_blob).unwrap();
    let signature = store.sign(&permit, b"authorized payload", 0).unwrap();
    Verifier::verify(key.public_key(), b"authorized payload", &signature).unwrap();
}

#[test]
fn undersized_rsa_is_rejected_during_load() {
    let weak_rsa = rsa::RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
    let weak = PrivateKey::from(RsaKeypair::try_from(weak_rsa).unwrap());
    let mut store = KeyStore::new();
    let mut load = store.begin_load(31, 4096).unwrap();
    assert_eq!(
        load.add(item("weak-rsa", &weak)).unwrap(),
        Some(SkipCode::InvalidPrivateKey)
    );
    assert_eq!(store.publish(load).unwrap().loaded, 0);
}

#[test]
fn logout_invalidates_permits_and_clears_public_and_private_sets() {
    let key = ed25519();
    let public_blob = key.public_key().to_bytes().unwrap();
    let mut store = KeyStore::new();
    let mut load = store.begin_load(41, 4096).unwrap();
    load.add(item("work", &key)).unwrap();
    store.publish(load).unwrap();
    let permit = store.authorize(&public_blob).unwrap();

    store.logout(42);

    assert_eq!(store.state(), VaultState::LoggedOut);
    assert!(store.public_identities().is_empty());
    assert!(store.sign(&permit, b"must not sign", 0).is_none());
}
