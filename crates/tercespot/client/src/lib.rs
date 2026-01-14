//! # Submitter Library
//!
//! This library provides functionality for creating, signing, and managing partial commands
//! in a multi-signature system, typically used for secure command execution requiring
//! approval from multiple roles.

use fips204::ml_dsa_87;
use fips204::traits::{Signer, Verifier};
pub use shared::{create_partial_command, is_partial_complete, package_payload, PartialCommand};
use shared::{load_public_key, PartialSignature, Role};
use std::fs;
use std::path::Path;

/// Signs a byte slice with the given PQC key
///
/// # Panics
/// Panics if the signing operation fails.
#[must_use]
pub fn sign_data(signing_key: &ml_dsa_87::PrivateKey, data: &[u8]) -> [u8; 4627] {
    signing_key
        .try_sign(data, b"tersec")
        .unwrap_or_else(|e| panic!("Signing failed: {e}"))
}

/// Loads a `PartialCommand` from a .partial file
///
/// # Errors
/// Returns an error if the file cannot be read or deserialized.
pub fn load_partial_command<P: AsRef<Path>>(path: P) -> Result<PartialCommand, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

/// Saves a `PartialCommand` to a .partial file
///
/// # Errors
/// Returns an error if the command cannot be serialized or written to the file.
pub fn save_partial_command<P: AsRef<Path>>(
    path: P,
    partial: &PartialCommand,
) -> Result<(), String> {
    let content = serde_json::to_string_pretty(partial).map_err(|e| e.to_string())?;
    fs::write(path, content).map_err(|e| e.to_string())
}

/// Appends a signature to a `PartialCommand`
///
/// # Errors
/// Returns an error if signature verification fails or if the role has already signed.
pub fn append_signature_to_partial(
    mut partial: PartialCommand,
    signature: [u8; 4627],
    role: Role,
    public_key_path: &str,
) -> Result<PartialCommand, String> {
    // Verify signature first
    let pk =
        load_public_key(public_key_path).map_err(|e| format!("Failed to load public key: {e}"))?;
    let payload = &partial.encrypted_payload;
    if !pk.verify(payload, &signature, b"tersec") {
        return Err("Signature verification failed".to_string());
    }

    // Check for duplicate roles
    for sig in partial.signatures.iter().flatten() {
        if sig.signer_role == role {
            return Err(format!("Duplicate signature from role {role:?}"));
        }
    }

    // Find empty slot
    let slot = partial
        .signatures
        .iter()
        .position(Option::is_none)
        .ok_or_else(|| "No available signature slots".to_string())?;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    if let Some(s) = partial.signatures.get_mut(slot) {
        *s = Some(PartialSignature {
            signer_role: role,
            signature: signature.to_vec(),
            timestamp: ts,
        });
    }

    Ok(partial)
}

/// Converts a completed `PartialCommand` to the signed binary format
///
/// # Errors
/// Returns an error if the partial command is not complete.
pub fn partial_to_signed(partial: &PartialCommand) -> Result<Vec<u8>, String> {
    if !is_partial_complete(partial) {
        return Err("Partial command is not complete".to_string());
    }

    let mut signatures = Vec::new();
    for sig in partial.signatures.iter().flatten() {
        let mut sig_array = [0u8; 4627];
        sig_array.copy_from_slice(&sig.signature);
        signatures.push(sig_array);
    }

    Ok(package_payload(&signatures, &partial.encrypted_payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::ml_dsa_87;
    use fips204::traits::{KeyGen, SerDes, Verifier};
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sign_and_verify() {
        let (pk, sk) = ml_dsa_87::KG::try_keygen().unwrap();
        let payload = b"seq_ts_cmd";
        let sig = sign_data(&sk, payload);

        assert!(pk.verify(payload, &sig, b"tersec"));
    }

    #[test]
    fn test_package_structure() {
        let (_pk, sk) = ml_dsa_87::KG::try_keygen().unwrap();
        let cmd = "test";
        let seq = 42u64;
        let ts = 1234567890u64;

        // Payload = Seq || Ts || Cmd
        let mut payload = Vec::new();
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.extend_from_slice(&ts.to_le_bytes());
        payload.extend_from_slice(cmd.as_bytes());

        let sig = sign_data(&sk, &payload);

        // Package with 1 signature
        let signatures = vec![sig];
        let data = package_payload(&signatures, &payload);

        // Check size: Count(1) + Sig(4627) + Body
        let expected_len = 1 + 4627 + payload.len();
        assert_eq!(data.len(), expected_len);

        // Check contents
        assert_eq!(data[0], 1); // Count
        assert_eq!(&data[1..4628], sig.as_slice());
        assert_eq!(&data[4628..], payload.as_slice());
    }

    #[test]
    fn test_partial_command_creation() {
        let payload = vec![1, 2, 3];
        let partial = create_partial_command("test cmd".to_string(), payload.clone(), 2).unwrap();

        assert_eq!(partial.command, "test cmd");
        assert_eq!(partial.encrypted_payload, payload);
        assert_eq!(partial.required_signers, 2);
        assert_eq!(partial.signatures.len(), 2);
        assert!(partial.signatures.iter().all(|s| s.is_none()));
    }

    #[test]
    fn test_partial_save_load() {
        let payload = vec![1, 2, 3];
        let partial = create_partial_command("test cmd".to_string(), payload, 2).unwrap();

        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        save_partial_command(path, &partial).unwrap();
        let loaded = load_partial_command(path).unwrap();

        assert_eq!(loaded.command, partial.command);
        assert_eq!(loaded.signatures.len(), 2);
    }

    #[test]
    fn test_append_signature() {
        let payload = vec![1, 2, 3];
        let mut partial = create_partial_command("test".to_string(), payload.clone(), 2).unwrap();

        let (pk, sk) = ml_dsa_87::KG::try_keygen().unwrap();
        let sig = sign_data(&sk, &payload);

        // Save pk to temp file
        let pk_file = NamedTempFile::new().unwrap();
        fs::write(pk_file.path(), pk.into_bytes()).unwrap();

        partial = append_signature_to_partial(
            partial,
            sig,
            Role::DevOps,
            &pk_file.path().to_string_lossy(),
        )
        .unwrap();

        assert!(partial.signatures[0].is_some());
        assert!(partial.signatures[1].is_none());
        assert_eq!(
            partial.signatures[0].as_ref().unwrap().signer_role,
            Role::DevOps
        );
    }

    #[test]
    fn test_duplicate_role_rejection() {
        let payload = vec![1, 2, 3];
        let mut partial = create_partial_command("test".to_string(), payload.clone(), 2).unwrap();

        let (pk, sk) = ml_dsa_87::KG::try_keygen().unwrap();
        let sig = sign_data(&sk, &payload);

        let pk_file = NamedTempFile::new().unwrap();
        fs::write(pk_file.path(), pk.into_bytes()).unwrap();

        partial = append_signature_to_partial(
            partial.clone(),
            sig,
            Role::DevOps,
            &pk_file.path().to_string_lossy(),
        )
        .unwrap();

        // Try to append same role again
        let result = append_signature_to_partial(
            partial,
            sig,
            Role::DevOps,
            &pk_file.path().to_string_lossy(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Duplicate signature"));
    }

    #[test]
    fn test_partial_completion() {
        let payload = vec![1, 2, 3];
        let mut partial = create_partial_command("test".to_string(), payload.clone(), 2).unwrap();

        assert!(!is_partial_complete(&partial));

        let (pk1, sk1) = ml_dsa_87::KG::try_keygen().unwrap();
        let (pk2, sk2) = ml_dsa_87::KG::try_keygen().unwrap();
        let sig1 = sign_data(&sk1, &payload);
        let sig2 = sign_data(&sk2, &payload);

        let pk_file1 = NamedTempFile::new().unwrap();
        let pk_file2 = NamedTempFile::new().unwrap();
        fs::write(pk_file1.path(), pk1.into_bytes()).unwrap();
        fs::write(pk_file2.path(), pk2.into_bytes()).unwrap();

        partial = append_signature_to_partial(
            partial,
            sig1,
            Role::DevOps,
            &pk_file1.path().to_string_lossy(),
        )
        .unwrap();
        assert!(!is_partial_complete(&partial));

        partial = append_signature_to_partial(
            partial,
            sig2,
            Role::ComplianceManager,
            &pk_file2.path().to_string_lossy(),
        )
        .unwrap();
        assert!(is_partial_complete(&partial));
    }

    #[test]
    fn test_partial_to_signed() {
        let payload = vec![1, 2, 3];
        let mut partial = create_partial_command("test".to_string(), payload.clone(), 1).unwrap();

        let (pk, sk) = ml_dsa_87::KG::try_keygen().unwrap();
        let sig = sign_data(&sk, &payload);

        let pk_file = NamedTempFile::new().unwrap();
        fs::write(pk_file.path(), pk.into_bytes()).unwrap();

        partial = append_signature_to_partial(
            partial,
            sig,
            Role::DevOps,
            &pk_file.path().to_string_lossy(),
        )
        .unwrap();

        let signed = partial_to_signed(&partial).unwrap();
        assert_eq!(signed[0], 1); // 1 signature
        assert_eq!(&signed[1..4628], sig.as_slice());
        assert_eq!(&signed[4628..], payload.as_slice());
    }
}
