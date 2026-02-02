use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer};
use sentinel::{parse_wire_format, verify_signature};
use shared::{evaluate_policies, Policy, PolicyConfig, Role};
use std::collections::HashMap;
use submitter::{append_signature_to_partial, create_partial_command, partial_to_signed};

#[test]
fn test_signature_verification_rejects_invalid_signatures() {
    let (pk, _sk) = ml_dsa_44::KG::try_keygen().unwrap();
    let (_pk2, sk2) = ml_dsa_44::KG::try_keygen().unwrap();

    let payload = b"important command";
    let valid_sig = sk2.try_sign(payload, b"tersec").unwrap();

    // Wrong key should fail
    assert!(!verify_signature(payload, &valid_sig, &pk));

    // Tampered payload should fail
    let tampered_payload = b"evil command";
    assert!(!verify_signature(tampered_payload, &valid_sig, &pk));

    // Valid should pass
    let valid_sig_correct = sk2.try_sign(payload, b"tersec").unwrap();
    assert!(verify_signature(payload, &valid_sig_correct, &pk));
}

#[test]
fn test_policy_bypass_attempts() {
    // Test attempting to bypass policies with insufficient signatures
    let policy_config = PolicyConfig {
        policies: vec![Policy {
            name: "secure_restart".to_string(),
            roles: vec!["admin".to_string()],
            operations: vec!["restart".to_string()],
            resources: vec!["critical_service".to_string()],
            threshold: 2,
            time_windows: None,
            conditions: vec![],
            approval_expression: Some("Role:DevOps AND Role:ComplianceManager".to_string()),
        }],
        role_mappings: HashMap::from([
            ("key1".to_string(), vec!["DevOps".to_string()]),
            ("key2".to_string(), vec!["ComplianceManager".to_string()]),
        ]),
    };

    let cmd = "#TERSEC_META:{\"role\":\"admin\",\"operation\":\"restart\",\"resource\":\"critical_service\"}\nsystemctl restart critical";

    // Test with insufficient signatures
    let insufficient_keys = vec!["key1".to_string()];
    let result = evaluate_policies(cmd, &insufficient_keys, &policy_config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("threshold not met"));

    // Test with wrong roles
    let wrong_role_keys = vec!["key1".to_string(), "key1".to_string()]; // Duplicate wrong role
    let result = evaluate_policies(cmd, &wrong_role_keys, &policy_config);
    assert!(result.is_err());

    // Test with correct signatures
    let correct_keys = vec!["key1".to_string(), "key2".to_string()];
    let result = evaluate_policies(cmd, &correct_keys, &policy_config);
    assert!(result.is_ok());
}

#[test]
fn test_memory_security_no_leaks() {
    // Test that sensitive data is properly handled
    use zeroize::Zeroize;

    let mut sensitive_key = vec![1u8, 2, 3, 4, 5, 42, 99];
    let original = sensitive_key.clone();

    // Simulate zeroization
    sensitive_key.zeroize();

    // Verify all bytes are zero
    assert!(sensitive_key.iter().all(|&b| b == 0));
    assert_ne!(sensitive_key, original);

    // Test with keypair
    let (_pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
    let mut sk_bytes = sk.into_bytes();
    let sk_copy = sk_bytes.clone();

    sk_bytes.zeroize();
    assert!(sk_bytes.iter().all(|&b| b == 0));
    assert_ne!(sk_bytes, sk_copy);
}

#[test]
fn test_air_gapped_operation_validation() {
    // Test that operations work without network dependencies
    // This is more of a conceptual test since we can't easily test air-gapping

    // Generate keys offline
    let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();

    // Sign offline
    let payload = b"air-gapped command";
    let sig = sk.try_sign(payload, b"tersec").unwrap();

    // Verify offline
    assert!(pk.verify(payload, &sig, b"tersec"));

    // Test partial signing workflow offline
    let encrypted_payload = vec![10, 20, 30, 40];
    let mut partial =
        create_partial_command("test cmd".to_string(), encrypted_payload.clone(), 1).unwrap();

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), pk.into_bytes()).unwrap();

    partial = append_signature_to_partial(
        partial,
        sig,
        Role::DevOps,
        &temp_file.path().to_string_lossy(),
    )
    .unwrap();

    let signed = partial_to_signed(&partial).unwrap();

    // Parse and verify the signed data
    let (sigs, body) = parse_wire_format(&signed).unwrap();
    assert_eq!(body, encrypted_payload);
    assert!(verify_signature(&body, &sigs[0], &pk));
}

#[test]
fn test_tampering_detection() {
    // Test detection of tampered signatures or data
    let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
    let payload = b"original command";
    let sig = sk.try_sign(payload, b"tersec").unwrap();

    // Tamper with signature
    let mut tampered_sig = sig;
    tampered_sig[0] ^= 1; // Flip a bit
    assert!(!verify_signature(payload, &tampered_sig, &pk));

    // Tamper with payload
    let tampered_payload = b"modified command";
    assert!(!verify_signature(tampered_payload, &sig, &pk));

    // Test with partial command tampering
    let encrypted_payload = vec![1, 2, 3];
    let mut partial =
        create_partial_command("cmd".to_string(), encrypted_payload.clone(), 1).unwrap();

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), pk.into_bytes()).unwrap();

    partial = append_signature_to_partial(
        partial,
        sig,
        Role::DevOps,
        &temp_file.path().to_string_lossy(),
    )
    .unwrap();

    // Tamper with the partial command's payload
    partial.encrypted_payload[0] ^= 1;

    // Should fail when converting to signed
    let result = partial_to_signed(&partial);
    assert!(result.is_err()); // Signature verification should fail
}

#[test]
fn test_role_authorization_boundaries() {
    // Test that roles are properly enforced
    let policy_config = PolicyConfig {
        policies: vec![
            Policy {
                name: "dev_only".to_string(),
                roles: vec!["dev".to_string()],
                operations: vec!["deploy".to_string()],
                resources: vec!["staging".to_string()],
                threshold: 1,
                time_windows: None,
                conditions: vec![],
                approval_expression: Some("Role:DevOps".to_string()),
            },
            Policy {
                name: "compliance_only".to_string(),
                roles: vec!["compliance".to_string()],
                operations: vec!["audit".to_string()],
                resources: vec!["logs".to_string()],
                threshold: 1,
                time_windows: None,
                conditions: vec![],
                approval_expression: Some("Role:ComplianceManager".to_string()),
            },
        ],
        role_mappings: HashMap::from([
            ("dev_key".to_string(), vec!["DevOps".to_string()]),
            (
                "comp_key".to_string(),
                vec!["ComplianceManager".to_string()],
            ),
        ]),
    };

    // Dev operation with dev key should pass
    let dev_cmd = "#TERSEC_META:{\"role\":\"dev\",\"operation\":\"deploy\",\"resource\":\"staging\"}\ndeploy staging";
    let result = evaluate_policies(dev_cmd, &vec!["dev_key".to_string()], &policy_config);
    assert!(result.is_ok());

    // Dev operation with compliance key should fail
    let result = evaluate_policies(dev_cmd, &vec!["comp_key".to_string()], &policy_config);
    assert!(result.is_err());

    // Compliance operation with compliance key should pass
    let comp_cmd = "#TERSEC_META:{\"role\":\"compliance\",\"operation\":\"audit\",\"resource\":\"logs\"}\naudit logs";
    let result = evaluate_policies(comp_cmd, &vec!["comp_key".to_string()], &policy_config);
    assert!(result.is_ok());

    // Compliance operation with dev key should fail
    let result = evaluate_policies(comp_cmd, &vec!["dev_key".to_string()], &policy_config);
    assert!(result.is_err());
}
