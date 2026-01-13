use anyhow::{Context, Result};
use fips204::ml_dsa_44; // Using the re-export from shared if possible, or direct dep
use fips204::traits::{SerDes, Signer};
use std::fs;
use std::path::Path;
use tersec_shared::{
    encrypt_for_sentinel, load_kem_public_key, package_payload, postbox_path, Role,
};
use tracing::{info, instrument};

/// A client for interacting with the TersecPot security system.
pub struct TersecClient {
    /// Directory used for command relay.
    pub postbox_dir: String,
    /// Public KEM key for encryption.
    pub kem_pk: fips203::ml_kem_1024::EncapsKey,
    /// Private ML-DSA key for signing.
    pub signing_key: ml_dsa_44::PrivateKey,
}

impl TersecClient {
    #[instrument(skip(signing_key_bytes))]
    pub fn new(signing_key_bytes: &[u8]) -> Result<Self> {
        let postbox = postbox_path();
        let kem_pk_path = format!("{}/kem_public_key", postbox);

        if !Path::new(&kem_pk_path).exists() {
            return Err(anyhow::anyhow!(
                "TersecPot KEM Public Key not found at {}. Is the Daemon running?",
                kem_pk_path
            ));
        }

        let kem_pk =
            load_kem_public_key(&kem_pk_path).context("Failed to load TersecPot KEM public key")?;

        let signing_key = ml_dsa_44::PrivateKey::try_from_bytes(signing_key_bytes.try_into()?)
            .map_err(|_| anyhow::anyhow!("Invalid signing key bytes"))?;

        Ok(Self {
            postbox_dir: postbox,
            kem_pk,
            signing_key,
        })
    }

    #[instrument(skip(self))]
    pub async fn submit_command(
        &self,
        command: &str,
        role: Role,
        operation: &str,
    ) -> Result<String> {
        // 1. Construct Metadata + Command
        // Using the format expected by parse_command_metadata in shared lib
        // #TERSEC_META:{"role":"...","operation":"...","resource":"wolf_prowler","parameters":{}}
        let meta = serde_json::json!({
            "role": format!("{:?}", role), // e.g. "DevOps"
            "operation": operation,
            "resource": "wolf_network",
            "parameters": {}
        });

        let full_payload = format!("#TERSEC_META:{}\n{}", meta.to_string(), command);
        let payload_bytes = full_payload.as_bytes();

        // 2. Encrypt
        let encrypted_blob = encrypt_for_sentinel(payload_bytes, &self.kem_pk);

        // 3. Sign the ciphertext (NOT the plaintext, as per `daemon/src/main.rs` lines 303/314: verify_signature(&ciphertext, sig, pk))
        // Wait, let me double check daemon main.rs line 314: verify_signature(&ciphertext, sig, pk)
        // Yes, it signs the ciphertext.

        let signature = self
            .signing_key
            .try_sign(&encrypted_blob, &[])
            .map_err(|e| anyhow::anyhow!("Signing failed: {:?}", e))?;

        // 4. Package
        // daemon expects [[u8; 2420]] signatures.
        let sig_vec = signature.to_vec();
        let mut sig_array = [0u8; 2420];
        if sig_vec.len() != 2420 {
            return Err(anyhow::anyhow!(
                "Invalid signature length: {}",
                sig_vec.len()
            ));
        }
        sig_array.copy_from_slice(&sig_vec);

        let wired_data = package_payload(&[sig_array], &encrypted_blob);

        // 5. Write to Postbox
        // file pattern: cmd_<random>
        let filename = format!("cmd_{}", uuid::Uuid::new_v4());
        let path = format!("{}/{}", self.postbox_dir, filename);

        fs::write(&path, wired_data).context("Failed to write to postbox")?;

        info!("Submitted secured command to TersecPot: {}", filename);
        Ok(filename)
    }
}
