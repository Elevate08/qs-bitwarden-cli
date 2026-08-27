use qs_bitwarden_ssh_agent::protocol::{handle_frame, Identity, MAX_FRAME_LEN};
use rand_core::OsRng;
use signature::Verifier;
use ssh_encoding::{Decode, Encode};
use ssh_key::private::RsaKeypair;
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(payload.len() + 4);
    u32::try_from(payload.len())
        .unwrap()
        .encode(&mut encoded)
        .unwrap();
    encoded.extend_from_slice(payload);
    encoded
}

fn string(value: &[u8], out: &mut Vec<u8>) {
    value.encode(out).unwrap();
}

fn response_payload(response: &[u8]) -> &[u8] {
    let declared = u32::from_be_bytes(response[..4].try_into().unwrap()) as usize;
    assert_eq!(declared, response.len() - 4);
    &response[4..]
}

fn sign_request(key_blob: &[u8], message: &[u8], flags: u32) -> Vec<u8> {
    let mut payload = vec![SIGN_REQUEST];
    string(key_blob, &mut payload);
    string(message, &mut payload);
    flags.encode(&mut payload).unwrap();
    frame(&payload)
}

fn signature(response: &[u8]) -> Signature {
    let payload = response_payload(response);
    assert_eq!(payload[0], SIGN_RESPONSE);
    let mut encoded = &payload[1..];
    let signature_bytes = Vec::<u8>::decode(&mut encoded).unwrap();
    assert!(encoded.is_empty());
    Signature::try_from(signature_bytes.as_slice()).unwrap()
}

#[test]
fn lists_openssh_encoded_identities() {
    let ed25519 = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let rsa = PrivateKey::from(RsaKeypair::random(&mut OsRng, 2048).unwrap());
    let identities = [
        Identity::new(ed25519, "vault ed25519").unwrap(),
        Identity::new(rsa, "vault rsa").unwrap(),
    ];

    let response = handle_frame(&frame(&[REQUEST_IDENTITIES]), &identities);
    let payload = response_payload(&response);
    assert_eq!(payload[0], IDENTITIES_ANSWER);
    let mut fields = &payload[1..];
    assert_eq!(u32::decode(&mut fields).unwrap(), 2);
    for identity in identities.iter() {
        assert_eq!(
            Vec::<u8>::decode(&mut fields).unwrap(),
            identity.public_blob()
        );
        assert_eq!(String::decode(&mut fields).unwrap(), identity.comment());
    }
    assert!(fields.is_empty());
}

#[test]
fn signs_ed25519_requests_and_rejects_nonzero_flags() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let identity = Identity::new(key, "ed25519").unwrap();
    let message = b"bounded agent protocol vector";

    let signed = signature(&handle_frame(
        &sign_request(identity.public_blob(), message, 0),
        std::slice::from_ref(&identity),
    ));
    assert_eq!(signed.algorithm(), Algorithm::Ed25519);
    Verifier::verify(identity.public_key(), message, &signed).unwrap();

    let rejected = handle_frame(
        &sign_request(identity.public_blob(), message, RSA_SHA2_256),
        &[identity],
    );
    assert_eq!(response_payload(&rejected), &[FAILURE]);
}

#[test]
fn signs_rsa_with_exactly_the_requested_sha2_algorithm() {
    let key = PrivateKey::from(RsaKeypair::random(&mut OsRng, 2048).unwrap());
    let identity = Identity::new(key, "rsa").unwrap();
    let message = b"rsa protocol vector";

    for (flags, hash) in [
        (RSA_SHA2_256, HashAlg::Sha256),
        (RSA_SHA2_512, HashAlg::Sha512),
    ] {
        let signed = signature(&handle_frame(
            &sign_request(identity.public_blob(), message, flags),
            std::slice::from_ref(&identity),
        ));
        assert_eq!(signed.algorithm(), Algorithm::Rsa { hash: Some(hash) });
        Verifier::verify(identity.public_key(), message, &signed).unwrap();
    }

    for flags in [0, RSA_SHA2_256 | RSA_SHA2_512, 8] {
        let rejected = handle_frame(
            &sign_request(identity.public_blob(), message, flags),
            std::slice::from_ref(&identity),
        );
        assert_eq!(response_payload(&rejected), &[FAILURE]);
    }
}

#[test]
fn malformed_and_disallowed_requests_receive_only_bounded_failure() {
    let cases = [
        Vec::new(),
        vec![0, 0, 0, 2, REQUEST_IDENTITIES],
        frame(&[REQUEST_IDENTITIES, 0]),
        frame(&[17]),
        frame(&[18]),
        frame(&[19]),
        frame(&[20]),
        frame(&[21]),
        frame(&[22]),
        frame(&[23]),
        frame(&[25]),
        frame(&[26]),
        frame(&[27, 0, 0, 0, 1, 0xff]),
        frame(&[255]),
    ];

    for request in cases {
        assert_eq!(response_payload(&handle_frame(&request, &[])), &[FAILURE]);
    }
}

#[test]
fn lengths_are_rejected_before_body_allocation_or_parsing() {
    let oversized_header = u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_be_bytes();
    assert_eq!(
        response_payload(&handle_frame(&oversized_header, &[])),
        &[FAILURE]
    );

    let mut invalid_string = vec![SIGN_REQUEST];
    invalid_string.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        response_payload(&handle_frame(&frame(&invalid_string), &[])),
        &[FAILURE]
    );

    let mut unknown_key = vec![SIGN_REQUEST];
    string(b"not an advertised public key", &mut unknown_key);
    string(b"message", &mut unknown_key);
    0_u32.encode(&mut unknown_key).unwrap();
    assert_eq!(
        response_payload(&handle_frame(&frame(&unknown_key), &[])),
        &[FAILURE]
    );

    unknown_key.push(0);
    assert_eq!(
        response_payload(&handle_frame(&frame(&unknown_key), &[])),
        &[FAILURE]
    );
}
