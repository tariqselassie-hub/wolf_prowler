use fips203::ml_kem_1024;
use fips203::traits::{KeyGen as KemKeyGen, SerDes as KemSerDes};
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes};
use shared::*;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_role_enum_serialization() {
    // Test serialization/deserialization of Role enum
    let role = Role::DevOps;
    let serialized = serde_json::to_string(&role).unwrap();
    let deserialized: Role = serde_json::from_str(&serialized).unwrap();
    assert_eq!(role, deserialized);

    let role = Role::ComplianceManager;
    let serialized = serde_json::to_string(&role).unwrap();
    let deserialized: Role = serde_json::from_str(&serialized).unwrap();
    assert_eq!(role, deserialized);

    let role = Role::SecurityOfficer;
    let serialized = serde_json::to_string(&role).unwrap();
    let deserialized: Role = serde_json::from_str(&serialized).unwrap();
    assert_eq!(role, deserialized);
}

#[test]
fn test_partial_signature_creation() {
    // Test PartialSignature struct creation and serialization
    let signature = vec![1u8; 2420]; // Mock signature
    let partial_sig = PartialSignature {
        signer_role: Role::DevOps,
        signature: signature.clone(),
        timestamp: 1234567890,
    };

    // Test serialization
    let json = serde_json::to_string(&partial_sig).unwrap();
    let deserialized: PartialSignature = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.signer_role, Role::DevOps);
    assert_eq!(deserialized.signature, signature);
    assert_eq!(deserialized.timestamp, 1234567890);
}

#[test]
fn test_policy_parsing_edge_cases() {
    // Test policy config loading with invalid TOML
    let invalid_toml = "invalid toml content";
    let result = toml::from_str::<PolicyConfig>(invalid_toml);
    assert!(result.is_err());

    // Test with valid but empty config
    let empty_config = PolicyConfig {
        policies: vec![],
        role_mappings: std::collections::HashMap::new(),
    };
    let toml_str = toml::to_string(&empty_config).unwrap();
    let parsed: PolicyConfig = toml::from_str(&toml_str).unwrap();
    assert!(parsed.policies.is_empty());
    assert!(parsed.role_mappings.is_empty());
}

#[test]
fn test_parse_command_metadata_edge_cases() {
    // Test with no metadata
    let cmd = "systemctl restart apache2";
    assert!(parse_command_metadata(cmd).is_none());

    // Test with malformed JSON
    let cmd = "#TERSEC_META:{\"role\":\"admin\",\"operation\":\"restart\",\"resource\":\"apache\",\"parameters\":{}}\nsystemctl restart apache2";
    let meta = parse_command_metadata(cmd).unwrap();
    assert_eq!(meta.role, "admin");
    assert_eq!(meta.operation, "restart");
    assert_eq!(meta.resource, "apache");

    // Test with metadata at end
    let cmd = "systemctl restart apache2#TERSEC_META:{\"role\":\"admin\"}";
    assert!(parse_command_metadata(cmd).is_none());

    // Test with valid metadata in middle
    let cmd = "some text#TERSEC_META:{\"role\":\"admin\",\"operation\":\"restart\",\"resource\":\"apache\",\"parameters\":{}}\nmore text";
    let meta = parse_command_metadata(cmd).unwrap();
    assert_eq!(meta.role, "admin");
    assert_eq!(meta.operation, "restart");
    assert_eq!(meta.resource, "apache");
}

#[test]
fn test_load_policy_config_from_file() {
    // Create a temp file with policy config
    let config = PolicyConfig {
        policies: vec![Policy {
            name: "test_policy".to_string(),
            roles: vec!["admin".to_string()],
            operations: vec!["restart".to_string()],
            resources: vec!["apache".to_string()],
            threshold: 1,
            time_windows: None,
            conditions: vec![],
            approval_expression: Some("Role:DevOps".to_string()),
        }],
        role_mappings: std::collections::HashMap::new(),
    };

    let toml_str = toml::to_string(&config).unwrap();
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file
        .as_file_mut()
        .write_all(toml_str.as_bytes())
        .unwrap();

    // Load and verify
    let loaded_config = load_policy_config(temp_file.path()).unwrap();
    assert_eq!(loaded_config.policies.len(), 1);
    assert_eq!(loaded_config.policies[0].name, "test_policy");
}

#[test]
fn test_encrypt_decrypt_for_sentinel() {
    // Generate KEM keypair
    let (pk, sk) = ml_kem_1024::KG::try_keygen().unwrap();

    let data = b"secret data to encrypt";
    let encrypted = encrypt_for_sentinel(data, &pk);

    // Verify structure: CT (1568) + Nonce (12) + AES_CT
    assert!(encrypted.len() > KEM_CT_SIZE + NONCE_SIZE);

    // Decrypt
    let decrypted = decrypt_from_client(&encrypted, &sk).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn test_encrypt_decrypt_invalid_data() {
    let (_pk, sk) = ml_kem_1024::KG::try_keygen().unwrap();

    // Test with too short data
    let short_data = vec![0u8; 10];
    assert!(decrypt_from_client(&short_data, &sk).is_none());

    // Test with invalid ciphertext
    let invalid_data = vec![0u8; KEM_CT_SIZE + NONCE_SIZE + TAG_SIZE];
    assert!(decrypt_from_client(&invalid_data, &sk).is_none());
}

#[test]
fn test_load_kem_public_key() {
    let (pk, _sk) = ml_kem_1024::KG::try_keygen().unwrap();
    let pk_bytes = pk.into_bytes();

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.as_file_mut().write_all(&pk_bytes).unwrap();

    let loaded_pk = load_kem_public_key(temp_file.path().to_str().unwrap()).unwrap();
    assert_eq!(loaded_pk.into_bytes(), pk_bytes);
}

#[test]
fn test_load_kem_public_key_invalid() {
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file
        .as_file_mut()
        .write_all(b"invalid key data")
        .unwrap();

    let result = load_kem_public_key(temp_file.path().to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn test_parse_and_evaluate_complex_expressions() {
    let mut roles = HashSet::new();
    roles.insert(Role::DevOps);
    roles.insert(Role::ComplianceManager);
    roles.insert(Role::SecurityOfficer);

    // Test complex AND/OR combinations
    assert!(parse_and_evaluate(
        "Role:DevOps AND (Role:ComplianceManager OR Role:SecurityOfficer)",
        &roles
    )
    .unwrap());

    // Test nested expressions
    assert!(parse_and_evaluate(
        "(Role:DevOps AND Role:ComplianceManager) OR Role:SecurityOfficer",
        &roles
    )
    .unwrap());

    // Test false complex
    let mut roles2 = HashSet::new();
    roles2.insert(Role::DevOps);
    assert!(!parse_and_evaluate(
        "Role:DevOps AND Role:ComplianceManager AND Role:SecurityOfficer",
        &roles2
    )
    .unwrap());
}

#[test]
fn test_parse_expr_invalid_input() {
    let mut roles = HashSet::new();
    roles.insert(Role::DevOps);

    // Test invalid role
    assert!(parse_and_evaluate("Role:InvalidRole", &roles).is_err());

    // Test malformed expression (this should fail)
    assert!(parse_and_evaluate("Role:DevOps AND", &roles).is_err());

    // Test empty expression
    assert!(parse_and_evaluate("", &roles).is_err());
}
