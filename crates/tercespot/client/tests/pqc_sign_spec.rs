//! PQC signature integration tests.
//!
//! This module tests the post-quantum cryptography signing logic.

use fips204::ml_dsa_44; // FIPS 204 crate
use fips204::traits::{KeyGen, Verifier};
use submitter::{package_payload, sign_data}; // Need KeyGen for test keys, Verifier for check

#[test]
fn test_pqc_signature_correctness() {
    // 1. Generate Valid Keys (independent of client logic, using crate directly)
    let (pk, sk) = ml_dsa_44::KG::try_keygen().expect("Keygen failed");

    // 2. Sign a command using Submitter's function
    let command = "exec --do-evil";
    // We sign bytes now. Let's pretend it's just command for this isolated test,
    // or simulate full payload? The test checks `sign_data` output size.
    let sig_array = sign_data(&sk, command.as_bytes()); // Returns [u8; 2420]

    // 3. Verify size
    assert_eq!(
        sig_array.len(),
        2420,
        "Signature size must match ML-DSA-44 spec"
    );

    // 4. Verify independently
    // Note: client uses b"tersec" context
    let valid = pk.verify(command.as_bytes(), &sig_array, b"tersec");
    assert!(valid, "Generated signature failed independent verification");
}

#[test]
fn test_package_format() {
    let (_pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
    let command = "ls -la";
    let seq = 1u64;
    let ts = 1000u64;

    // Construct payload manually for signing
    let mut payload = Vec::new();
    payload.extend_from_slice(&seq.to_le_bytes());
    payload.extend_from_slice(&ts.to_le_bytes());
    payload.extend_from_slice(command.as_bytes());

    let sig_array = sign_data(&sk, &payload);

    let signatures = vec![sig_array];
    let packaged = package_payload(&signatures, &payload);

    // Format: Count(1) + Signature (2420) || Body
    let expected_len = 1 + 2420 + payload.len();
    assert_eq!(packaged.len(), expected_len);

    // Check count
    assert_eq!(packaged[0], 1);
    // Check prefix (Offset 1)
    assert_eq!(&packaged[1..2421], &sig_array);
    // Check suffix
    assert_eq!(&packaged[2421..], payload.as_slice());
}
