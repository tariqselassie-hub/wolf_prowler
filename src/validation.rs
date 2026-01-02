//! Request Validation Utilities
//!
//! Provides comprehensive input validation for API requests,
//! preventing invalid data from entering the system.

use serde::Deserialize;
use std::net::IpAddr;
use validator::{Validate, ValidationError};

/// Validate IP address format
pub fn validate_ip(ip: &str) -> Result<(), ValidationError> {
    ip.parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| ValidationError::new("invalid_ip_address"))
}

/// Validate CIDR subnet notation (e.g., "192.168.1.0/24")
pub fn validate_subnet(subnet: &str) -> Result<(), ValidationError> {
    let parts: Vec<&str> = subnet.split('/').collect();

    if parts.len() != 2 {
        return Err(ValidationError::new("invalid_subnet_format"));
    }

    // Validate IP part
    parts[0]
        .parse::<IpAddr>()
        .map_err(|_| ValidationError::new("invalid_subnet_ip"))?;

    // Validate prefix length
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| ValidationError::new("invalid_prefix_length"))?;

    if prefix > 32 {
        return Err(ValidationError::new("prefix_too_large"));
    }

    Ok(())
}

/// Validate port number (must be > 1024 to avoid privileged ports)
pub fn validate_port(port: u16) -> Result<(), ValidationError> {
    if port < 1024 {
        return Err(ValidationError::new("privileged_port"));
    }
    Ok(())
}

/// Validate port range
pub fn validate_port_range(port: u16) -> Result<(), ValidationError> {
    if port == 0 || port > 65535 {
        return Err(ValidationError::new("invalid_port_range"));
    }
    Ok(())
}

/// Validate hostname format
pub fn validate_hostname(hostname: &str) -> Result<(), ValidationError> {
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(ValidationError::new("invalid_hostname_length"));
    }

    // Basic hostname validation (alphanumeric, hyphens, dots)
    let valid_chars = hostname
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '.');

    if !valid_chars {
        return Err(ValidationError::new("invalid_hostname_chars"));
    }

    Ok(())
}

/// Validate peer ID format
pub fn validate_peer_id(peer_id: &str) -> Result<(), ValidationError> {
    if peer_id.is_empty() || peer_id.len() > 128 {
        return Err(ValidationError::new("invalid_peer_id_length"));
    }

    // Peer IDs should be alphanumeric with hyphens
    let valid_chars = peer_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_');

    if !valid_chars {
        return Err(ValidationError::new("invalid_peer_id_chars"));
    }

    Ok(())
}

/// Validate message content (prevent injection attacks)
pub fn validate_message_content(content: &str) -> Result<(), ValidationError> {
    if content.is_empty() {
        return Err(ValidationError::new("empty_message"));
    }

    if content.len() > 10_000 {
        return Err(ValidationError::new("message_too_long"));
    }

    // Check for potential injection patterns
    let dangerous_patterns = ["<script", "javascript:", "onerror=", "onclick="];
    for pattern in &dangerous_patterns {
        if content.to_lowercase().contains(pattern) {
            return Err(ValidationError::new("potential_injection"));
        }
    }

    Ok(())
}

/// Validate file path (prevent directory traversal)
pub fn validate_file_path(path: &str) -> Result<(), ValidationError> {
    if path.contains("..") {
        return Err(ValidationError::new("directory_traversal"));
    }

    if path.starts_with('/') {
        return Err(ValidationError::new("absolute_path_not_allowed"));
    }

    Ok(())
}

/// Common validation request types

#[derive(Debug, Deserialize, Validate)]
pub struct IpAddressRequest {
    #[validate(custom = "validate_ip")]
    pub ip: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SubnetRequest {
    #[validate(custom = "validate_subnet")]
    pub subnet: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PortRequest {
    #[validate(custom = "validate_port")]
    pub port: u16,
}

#[derive(Debug, Deserialize, Validate)]
pub struct MessageRequest {
    #[validate(length(min = 1, max = 128))]
    pub to: String,

    #[validate(custom = "validate_message_content")]
    pub content: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PeerIdRequest {
    #[validate(custom = "validate_peer_id")]
    pub peer_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip() {
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("invalid").is_err());
    }

    #[test]
    fn test_validate_subnet() {
        assert!(validate_subnet("192.168.1.0/24").is_ok());
        assert!(validate_subnet("10.0.0.0/8").is_ok());
        assert!(validate_subnet("192.168.1.0").is_err());
        assert!(validate_subnet("192.168.1.0/33").is_err());
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(1024).is_ok());
        assert!(validate_port(80).is_err()); // Privileged
    }

    #[test]
    fn test_validate_message_content() {
        assert!(validate_message_content("Hello, world!").is_ok());
        assert!(validate_message_content("").is_err());
        assert!(validate_message_content("<script>alert('xss')</script>").is_err());
    }

    #[test]
    fn test_validate_file_path() {
        assert!(validate_file_path("data/file.txt").is_ok());
        assert!(validate_file_path("../etc/passwd").is_err());
        assert!(validate_file_path("/etc/passwd").is_err());
    }
}
