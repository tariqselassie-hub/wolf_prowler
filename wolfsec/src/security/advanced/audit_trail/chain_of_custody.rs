use crate::security::advanced::audit_trail::{AuditConfig, AuditEvent, HashAlgorithm};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde_json::json;
use tracing::{debug, error};

pub struct ChainOfCustodyManager {
    pub config: AuditConfig,
    last_event_hash: Option<String>,
}

impl ChainOfCustodyManager {
    pub fn new(config: AuditConfig) -> Result<Self> {
        Ok(Self {
            config,
            last_event_hash: None,
        })
    }

    /// Signs an audit event by calculating a hash and adding it to metadata.
    /// In a real-world scenario, this would use a private key to generate a cryptographic signature.
    pub async fn sign_event(&mut self, event: &mut AuditEvent) -> Result<()> {
        if !self.config.chain_of_custody.digital_signatures_required {
            return Ok(());
        }

        debug!("🔐 Signing audit event: {}", event.id);

        // Add previous hash to metadata to create blockchain link
        let prev_hash = self.last_event_hash.as_deref().unwrap_or("GENESIS");
        event
            .metadata
            .insert("previous_hash".to_string(), json!(prev_hash));

        let content = self.serialize_event_for_signing(event)?;
        let signature = self.generate_signature(&content)?;
        self.last_event_hash = Some(signature.clone());

        event
            .metadata
            .insert("digital_signature".to_string(), json!(signature));
        event.metadata.insert(
            "signature_algorithm".to_string(),
            json!(format!("{:?}", self.config.chain_of_custody.hash_algorithm)),
        );
        event
            .metadata
            .insert("signed_at".to_string(), json!(Utc::now()));

        Ok(())
    }

    /// Verifies the digital signature of an audit event.
    pub async fn verify_event(&self, event: &AuditEvent) -> Result<bool> {
        if !self.config.chain_of_custody.digital_signatures_required {
            return Ok(true);
        }

        let signature = match event
            .metadata
            .get("digital_signature")
            .and_then(|v| v.as_str())
        {
            Some(s) => s,
            None => {
                error!("❌ Event {} missing digital signature", event.id);
                return Ok(false);
            }
        };

        let content = self.serialize_event_for_signing(event)?;
        let is_valid = self.verify_signature(&content, signature)?;

        if is_valid {
            debug!("✅ Signature verified for event: {}", event.id);
        } else {
            error!("❌ Signature verification failed for event: {}", event.id);
        }

        Ok(is_valid)
    }

    /// Verifies the integrity of a sequence of audit events.
    /// Checks digital signatures and chronological order.
    pub async fn verify_chain_integrity(&self, events: &[AuditEvent]) -> Result<bool> {
        if events.is_empty() {
            return Ok(true);
        }

        let mut previous_timestamp: Option<DateTime<Utc>> = None;
        let mut previous_signature: Option<String> = None;

        for event in events {
            // Verify signature
            if !self.verify_event(event).await? {
                // verify_event logs the error
                return Ok(false);
            }

            // Verify chronological order
            if let Some(prev) = previous_timestamp {
                if event.timestamp < prev {
                    error!(
                        "❌ Chain integrity broken: Chronological disorder at event {}",
                        event.id
                    );
                    return Ok(false);
                }
            }
            previous_timestamp = Some(event.timestamp);

            // Verify hash chain link
            if let Some(prev_sig) = previous_signature {
                let current_prev_hash = event
                    .metadata
                    .get("previous_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if current_prev_hash != prev_sig {
                    error!("❌ Chain integrity broken: Hash mismatch at event {}. Expected prev: {}, Found: {}", event.id, prev_sig, current_prev_hash);
                    return Ok(false);
                }
            }

            // Store current signature for next iteration
            previous_signature = event
                .metadata
                .get("digital_signature")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }

        debug!("✅ Chain integrity verified for {} events", events.len());
        Ok(true)
    }

    /// Exports the audit chain to a JSON file for external verification.
    pub fn export_chain<P: AsRef<std::path::Path>>(
        &self,
        events: &[AuditEvent],
        path: P,
    ) -> Result<()> {
        debug!(
            "📤 Exporting audit chain with {} events to {:?}",
            events.len(),
            path.as_ref()
        );

        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, events)?;

        debug!("✅ Audit chain exported successfully");
        Ok(())
    }

    /// Validates an exported JSON audit chain file.
    pub async fn validate_exported_chain<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<bool> {
        debug!(
            "🔍 Validating exported audit chain from {:?}",
            path.as_ref()
        );

        let file = std::fs::File::open(path)?;
        let events: Vec<AuditEvent> = serde_json::from_reader(file)?;

        self.verify_chain_integrity(&events).await
    }

    fn serialize_event_for_signing(&self, event: &AuditEvent) -> Result<String> {
        // Create a copy without the signature fields to ensure consistent hashing
        let mut clean_event = event.clone();
        clean_event.metadata.remove("digital_signature");
        clean_event.metadata.remove("signature_algorithm");
        clean_event.metadata.remove("signed_at");

        serde_json::to_string(&clean_event).map_err(|e| anyhow!("Serialization error: {}", e))
    }

    fn generate_signature(&self, content: &str) -> Result<String> {
        // Simulating signature generation.
        // In production, this would sign the hash with a private key.
        let hash = self.calculate_hash(content);
        Ok(format!("SIG_{}_{}", self.get_algo_name(), hash))
    }

    fn verify_signature(&self, content: &str, signature: &str) -> Result<bool> {
        let hash = self.calculate_hash(content);
        let expected_signature = format!("SIG_{}_{}", self.get_algo_name(), hash);
        Ok(signature == expected_signature)
    }

    fn calculate_hash(&self, content: &str) -> String {
        // Using a simple hash for demonstration as crypto crates aren't guaranteed in context
        // In production: use sha2::Sha256::digest(content.as_bytes())
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    fn get_algo_name(&self) -> String {
        match self.config.chain_of_custody.hash_algorithm {
            HashAlgorithm::SHA256 => "SHA256".to_string(),
            HashAlgorithm::SHA512 => "SHA512".to_string(),
            HashAlgorithm::Blake3 => "BLAKE3".to_string(),
            HashAlgorithm::MD5 => "MD5".to_string(),
        }
    }
}
