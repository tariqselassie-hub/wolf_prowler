//! PQC verification integration tests.
//!
//! This module tests the post-quantum cryptography verification logic.

use fips204::ml_dsa_87; // FIPS 204 crate
use fips204::traits::{KeyGen, Signer};
use sentinel::{parse_wire_format, verify_signature}; // Use new API

#[test]
fn test_valid_signature_verification() {
    let (pk, sk) = ml_dsa_87::KG::try_keygen().unwrap();
    let command = "sudo reboot";
    let seq = 42u64;
    let ts = 100u64;

    // Create valid package: Seq || Ts || Cmd
    let mut payload = Vec::new();
    payload.extend_from_slice(&seq.to_le_bytes());
    payload.extend_from_slice(&ts.to_le_bytes());
    payload.extend_from_slice(command.as_bytes());

    let sig_bytes = sk.try_sign(&payload, b"tersec").unwrap();

    // Construct Wire: Count(1) || Sig || Body
    let mut data = Vec::new();
    data.push(1);
    data.extend_from_slice(&sig_bytes);
    data.extend_from_slice(&payload);

    let (sigs, body) = parse_wire_format(&data).expect("Parsing failed");

    assert_eq!(sigs.len(), 1);
    assert_eq!(body, payload);
    assert!(verify_signature(&body, &sigs[0], &pk));
}

#[test]
fn test_invalid_signature_verification() {
    let (pk, _sk) = ml_dsa_87::KG::try_keygen().unwrap();
    let (_pk_bad, sk_bad) = ml_dsa_87::KG::try_keygen().unwrap();

    let payload = b"data";
    let sig_bad = sk_bad.try_sign(payload, b"tersec").unwrap();

    let mut data = Vec::new();
    data.push(1);
    data.extend_from_slice(&sig_bad);
    data.extend_from_slice(payload);

    let (sigs, body) = parse_wire_format(&data).unwrap();
    assert!(!verify_signature(&body, &sigs[0], &pk));
}
