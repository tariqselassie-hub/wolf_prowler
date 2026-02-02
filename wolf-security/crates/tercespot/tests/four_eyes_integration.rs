use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer};
use sentinel::{load_authorized_keys, parse_wire_format, verify_signature};
use shared::{evaluate_policies, parse_and_evaluate, PartialSignature, Policy, PolicyConfig, Role};
use std::collections::HashMap;
use std::fs;
use submitter::{
    append_signature_to_partial, create_partial_command, is_partial_complete, partial_to_signed,
};
use tempfile::TempDir;

#[test]
fn test_full_four_eyes_flow() {
    // Simulate the full four-eyes vault flow

    // 1. Ceremony: Generate keys for 3 officers
    let roles = vec![Role::DevOps, Role::ComplianceManager, Role::SecurityOfficer];
    let mut officer_keys = Vec::new();
    let mut public_keys = Vec::new();

    for role in &roles {
        let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
        let pk_hex = hex::encode(pk.into_bytes());
        officer_keys.push((sk, pk));
        public_keys.push((*role, pk_hex));
    }

    // 2. Create authorized_keys
    let temp_dir = TempDir::new().unwrap();
    let auth_keys_path = temp_dir.path().join("authorized_keys.json");

    use serde::{Deserialize, Serialize};
    #[derive(Serialize, Deserialize)]
    struct AuthorizedKeys {
        ceremony_id: String,
        timestamp: u64,
        officers: Vec<OfficerKey>,
    }
    #[derive(Serialize, Deserialize)]
    struct OfficerKey {
        role: Role,
        public_key_hex: String,
    }

    let officers: Vec<OfficerKey> = public_keys
        .into_iter()
        .map(|(role, pk_hex)| OfficerKey {
            role,
            public_key_hex: pk_hex,
        })
        .collect();

    let auth_keys = AuthorizedKeys {
        ceremony_id: "integration_test".to_string(),
        timestamp: 1234567890,
        officers,
    };

    let json = serde_json::to_string_pretty(&auth_keys).unwrap();
    fs::write(&auth_keys_path, &json).unwrap();

    // 3. Daemon loads authorized keys
    let (loaded_keys, role_mappings) = load_authorized_keys(&auth_keys_path).unwrap();
    assert_eq!(loaded_keys.len(), 3);

    // 4. Create policy config
    let policy_config = PolicyConfig {
        policies: vec![Policy {
            name: "restart_service".to_string(),
            roles: vec!["DevOps".to_string(), "ComplianceManager".to_string()],
            operations: vec!["restart".to_string()],
            resources: vec!["apache".to_string()],
            threshold: 2,
            time_windows: None,
            conditions: vec![],
            approval_expression: Some("Role:DevOps AND Role:ComplianceManager".to_string()),
        }],
        role_mappings,
    };

    // 5. Client creates partial command
    let encrypted_payload = vec![1, 2, 3, 4, 5]; // Mock encrypted data
    let mut partial =
        create_partial_command("restart apache".to_string(), encrypted_payload.clone(), 2).unwrap();

    // 6. Officers sign the partial command
    let pk_files = vec![temp_dir.path().join("pk0"), temp_dir.path().join("pk1")];

    // Save public keys for verification
    for (i, (_, pk)) in officer_keys.iter().enumerate().take(2) {
        fs::write(&pk_files[i], pk.into_bytes()).unwrap();
    }

    // First signature
    partial = append_signature_to_partial(
        partial,
        officer_keys[0]
            .0
            .try_sign(&encrypted_payload, b"tersec")
            .unwrap(),
        Role::DevOps,
        &pk_files[0].to_string_lossy(),
    )
    .unwrap();

    // Second signature
    partial = append_signature_to_partial(
        partial,
        officer_keys[1]
            .0
            .try_sign(&encrypted_payload, b"tersec")
            .unwrap(),
        Role::ComplianceManager,
        &pk_files[1].to_string_lossy(),
    )
    .unwrap();

    assert!(is_partial_complete(&partial));

    // 7. Convert to signed binary format
    let signed_data = partial_to_signed(&partial).unwrap();

    // 8. Daemon verifies the signatures
    let (sigs, body) = parse_wire_format(&signed_data).unwrap();
    assert_eq!(sigs.len(), 2);
    assert_eq!(body, encrypted_payload);

    // Verify each signature
    for (i, sig) in sigs.iter().enumerate() {
        assert!(verify_signature(&body, sig, &loaded_keys[i]));
    }

    // 9. Evaluate policies
    let verified_keys: Vec<String> = officer_keys
        .iter()
        .take(2)
        .enumerate()
        .map(|(i, _)| hex::encode(loaded_keys[i].into_bytes()))
        .collect();

    let cmd = "#TERSEC_META:{\"role\":\"admin\",\"operation\":\"restart\",\"resource\":\"apache\"}\nsystemctl restart apache2";
    let result = evaluate_policies(cmd, &verified_keys, &policy_config);
    assert!(result.is_ok(), "Policy evaluation failed: {:?}", result);
}

#[test]
fn test_multi_party_signing_edge_cases() {
    // Test insufficient signatures
    let payload = vec![1, 2, 3];
    let mut partial = create_partial_command("test".to_string(), payload.clone(), 3).unwrap();

    let (pk, sk) = ml_dsa_44::KG::try_keygen().unwrap();
    let sig = sk.try_sign(&payload, b"tersec").unwrap();

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), pk.into_bytes()).unwrap();

    // Add only 2 signatures for required 3
    partial = append_signature_to_partial(
        partial,
        sig,
        Role::DevOps,
        &temp_file.path().to_string_lossy(),
    )
    .unwrap();

    let (pk2, sk2) = ml_dsa_44::KG::try_keygen().unwrap();
    let sig2 = sk2.try_sign(&payload, b"tersec").unwrap();

    let temp_file2 = tempfile::NamedTempFile::new().unwrap();
    fs::write(temp_file2.path(), pk2.into_bytes()).unwrap();

    partial = append_signature_to_partial(
        partial,
        sig2,
        Role::ComplianceManager,
        &temp_file2.path().to_string_lossy(),
    )
    .unwrap();

    assert!(!is_partial_complete(&partial));

    // Test partial_to_signed fails
    let result = partial_to_signed(&partial);
    assert!(result.is_err());
}

#[test]
fn test_policy_enforcement_scenarios() {
    // Test policy with time windows (mock)
    let policy_config = PolicyConfig {
        policies: vec![Policy {
            name: "time_restricted".to_string(),
            roles: vec!["admin".to_string()],
            operations: vec!["restart".to_string()],
            resources: vec!["service".to_string()],
            threshold: 1,
            time_windows: Some(shared::TimeWindow {
                start_hour: 9,
                end_hour: 17,
                days: vec!["monday".to_string(), "tuesday".to_string()],
            }),
            conditions: vec![],
            approval_expression: None,
        }],
        role_mappings: HashMap::new(),
    };

    // For now, since time conditions are not implemented, it should pass
    let verified_keys = vec!["dummy".to_string()];
    let cmd =
        "#TERSEC_META:{\"role\":\"admin\",\"operation\":\"restart\",\"resource\":\"service\"}\ncmd";
    let result = evaluate_policies(cmd, &verified_keys, &policy_config);
    // Since conditions are not checked, it should pass
    assert!(result.is_ok());
}
