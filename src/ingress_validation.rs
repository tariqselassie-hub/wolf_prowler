use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Invalid Peer Identity: {0}")]
    InvalidIdentity(String),
    #[error("Malicious Payload Detected: {0}")]
    MaliciousPayload(String),
    #[error("Schema Violation: {0}")]
    SchemaViolation(String),
    #[error("Protocol Violation")]
    ProtocolViolation,
}

/// Trait representing the minimal interface required to validate a network event.
/// This allows decoupling from the specific `wolf_net` structs during validation.
pub trait ValidatableEvent {
    fn source_peer(&self) -> &str;
    fn payload(&self) -> &[u8];
    fn metadata(&self) -> &str;
}

/// Core validator for incoming network events.
pub trait EventValidator {
    fn validate_ingress<E: ValidatableEvent>(&self, event: &E) -> Result<(), SecurityError>;
}

pub struct WolfEventValidator;

impl WolfEventValidator {
    pub fn new() -> Self {
        Self
    }

    /// Sanitize string fields to prevent log injection or buffer overflows.
    fn sanitize_string(input: &str, max_len: usize, field_name: &str) -> Result<(), SecurityError> {
        if input.len() > max_len {
            return Err(SecurityError::SchemaViolation(format!(
                "{} length {} exceeds maximum {}",
                field_name,
                input.len(),
                max_len
            )));
        }

        if input.chars().any(|c| c.is_control()) {
            return Err(SecurityError::MaliciousPayload(format!(
                "Control characters detected in {}",
                field_name
            )));
        }
        Ok(())
    }
}

impl EventValidator for WolfEventValidator {
    fn validate_ingress<E: ValidatableEvent>(&self, event: &E) -> Result<(), SecurityError> {
        // 1. Source Authenticity
        // Ensure PeerID is not empty or obviously malformed
        let peer_id = event.source_peer();
        if peer_id.is_empty() {
            return Err(SecurityError::InvalidIdentity("Empty Peer ID".into()));
        }
        Self::sanitize_string(peer_id, 128, "PeerID")?;

        // 2. Metadata Sanitization (e.g. User-Agent, Headers)
        Self::sanitize_string(event.metadata(), 1024, "Metadata")?;

        // 3. Payload Size Enforcement (DoS Prevention)
        let payload_len = event.payload().len();
        const MAX_PAYLOAD_SIZE: usize = 1024 * 1024; // 1MB

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(SecurityError::SchemaViolation(format!(
                "Payload size {} exceeds limit",
                payload_len
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEvent {
        peer: String,
        payload: Vec<u8>,
        meta: String,
    }

    impl ValidatableEvent for MockEvent {
        fn source_peer(&self) -> &str {
            &self.peer
        }
        fn payload(&self) -> &[u8] {
            &self.payload
        }
        fn metadata(&self) -> &str {
            &self.meta
        }
    }

    #[test]
    fn test_valid_event() {
        let validator = WolfEventValidator::new();
        let event = MockEvent {
            peer: "valid_peer_id".to_string(),
            payload: vec![1, 2, 3, 4],
            meta: "User-Agent: WolfClient/1.0".to_string(),
        };
        assert!(validator.validate_ingress(&event).is_ok());
    }

    #[test]
    fn test_empty_peer_id() {
        let validator = WolfEventValidator::new();
        let event = MockEvent {
            peer: "".to_string(),
            payload: vec![],
            meta: "".to_string(),
        };
        assert!(matches!(
            validator.validate_ingress(&event),
            Err(SecurityError::InvalidIdentity(_))
        ));
    }

    #[test]
    fn test_malicious_metadata() {
        let validator = WolfEventValidator::new();
        let event = MockEvent {
            peer: "valid_peer".to_string(),
            payload: vec![],
            meta: "User-Agent: \x00\x1FBadStuff".to_string(), // Control characters
        };
        assert!(matches!(
            validator.validate_ingress(&event),
            Err(SecurityError::MaliciousPayload(_))
        ));
    }

    #[test]
    fn test_oversized_payload() {
        let validator = WolfEventValidator::new();
        let event = MockEvent {
            peer: "valid_peer".to_string(),
            payload: vec![0u8; 1024 * 1024 + 10], // > 1MB
            meta: "".to_string(),
        };
        assert!(matches!(
            validator.validate_ingress(&event),
            Err(SecurityError::SchemaViolation(_))
        ));
    }
}
