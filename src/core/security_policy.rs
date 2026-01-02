//! Security Policy Module
//!
//! Provides unified security level management across wolf_den and wolfsec modules.
//! Maps high-level security stances (Low/Medium/High) to module-specific configurations.

use serde::{Deserialize, Serialize};
use wolf_den::SecurityLevel as WolfDenSecurityLevel;
use wolfsec::network_security::{
    SecurityLevel as WolfsecSecurityLevel, HIGH_SECURITY, LOW_SECURITY, MEDIUM_SECURITY,
};

/// User-facing security stance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityStance {
    /// Low security - for testing and development
    /// - Faster operations, longer sessions
    /// - Less strict threat detection
    Low,

    /// Medium security - recommended for production
    /// - Balanced security and performance
    /// - Standard threat detection
    Medium,

    /// High security - maximum protection
    /// - Strongest cryptography, short sessions
    /// - Aggressive threat detection
    High,

    /// Paranoid security - complete lockdown
    /// - Maximum restrictions
    /// - Manual approval for many actions
    Paranoid,

    /// Custom security - user-defined parameters
    /// - Allows granular control over sensitivity and limits
    Custom,
}

impl SecurityStance {
    /// Returns a list of all available security stances.
    pub fn all_stances() -> Vec<Self> {
        vec![
            Self::Low,
            Self::Medium,
            Self::High,
            Self::Paranoid,
            Self::Custom,
        ]
    }
}

impl Default for SecurityStance {
    fn default() -> Self {
        Self::Medium
    }
}

impl std::fmt::Display for SecurityStance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Paranoid => write!(f, "Paranoid"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

impl std::str::FromStr for SecurityStance {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "paranoid" => Ok(Self::Paranoid),
            "custom" => Ok(Self::Custom),
            _ => Err(format!("Invalid security stance: {}", s)),
        }
    }
}

/// Unified security policy that controls behavior across all modules
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Current security stance
    pub stance: SecurityStance,

    /// Wolf Den (crypto) security level
    pub wolf_den_level: WolfDenSecurityLevel,

    /// Wolfsec (network) security level
    pub wolfsec_level: WolfsecSecurityLevel,

    /// Threat detection sensitivity (0.0 - 1.0)
    /// Higher = more sensitive, flags more potential threats
    pub threat_sensitivity: f64,

    /// Rate limit strictness (requests per minute)
    /// Lower = more strict
    pub rate_limit_strictness: u32,

    /// Minimum password length
    pub min_password_length: usize,

    /// Require multi-factor authentication
    pub require_mfa: bool,

    /// Audit logging level
    pub audit_level: AuditLevel,

    /// Peer trust mode
    pub peer_trust_mode: PeerTrustMode,
}

/// Audit logging level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditLevel {
    /// Only log errors
    ErrorsOnly,
    /// Log important security events
    Important,
    /// Log everything
    Verbose,
}

/// Peer trust mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerTrustMode {
    /// Trust peers by default, flag suspicious behavior
    Optimistic,
    /// Balanced trust and verification
    Balanced,
    /// Verify everything, trust nothing
    Paranoid,
}

impl SecurityPolicy {
    /// Create a security policy from a stance
    pub fn from_stance(stance: SecurityStance) -> Self {
        match stance {
            SecurityStance::Low => Self {
                stance,
                wolf_den_level: WolfDenSecurityLevel::Minimum,
                wolfsec_level: LOW_SECURITY,
                threat_sensitivity: 0.3,
                rate_limit_strictness: 1000,
                min_password_length: 8,
                require_mfa: false,
                audit_level: AuditLevel::ErrorsOnly,
                peer_trust_mode: PeerTrustMode::Optimistic,
            },
            SecurityStance::Medium => Self {
                stance,
                wolf_den_level: WolfDenSecurityLevel::Standard,
                wolfsec_level: MEDIUM_SECURITY,
                threat_sensitivity: 0.6,
                rate_limit_strictness: 100,
                min_password_length: 12,
                require_mfa: false,
                audit_level: AuditLevel::Important,
                peer_trust_mode: PeerTrustMode::Balanced,
            },
            SecurityStance::High => Self {
                stance,
                wolf_den_level: WolfDenSecurityLevel::Maximum,
                wolfsec_level: HIGH_SECURITY,
                threat_sensitivity: 0.9,
                rate_limit_strictness: 10,
                min_password_length: 16,
                require_mfa: true,
                audit_level: AuditLevel::Verbose,
                peer_trust_mode: PeerTrustMode::Paranoid,
            },
            SecurityStance::Paranoid => Self {
                stance,
                wolf_den_level: WolfDenSecurityLevel::Maximum,
                wolfsec_level: HIGH_SECURITY,
                threat_sensitivity: 1.0,
                rate_limit_strictness: 1,
                min_password_length: 20,
                require_mfa: true,
                audit_level: AuditLevel::Verbose,
                peer_trust_mode: PeerTrustMode::Paranoid,
            },
            // Custom defaults to Medium baseline before user overrides
            SecurityStance::Custom => Self::from_stance(SecurityStance::Medium),
        }
    }

    /// Get a description of the current security policy
    pub fn description(&self) -> String {
        format!(
            "{} Security: {}-bit crypto, {} sessions, {}% threat sensitivity",
            self.stance,
            self.wolf_den_level as u16,
            match self.stance {
                SecurityStance::Low => "2-hour",
                SecurityStance::Medium => "1-hour",
                SecurityStance::High => "30-minute",
                SecurityStance::Paranoid => "5-minute",
                SecurityStance::Custom => "Variable",
            },
            (self.threat_sensitivity * 100.0) as u8
        )
    }

    /// Get key size in bits
    pub fn key_size_bits(&self) -> u16 {
        self.wolf_den_level as u16
    }

    /// Get session timeout in seconds
    pub fn session_timeout_secs(&self) -> u64 {
        self.wolfsec_level.session_timeout
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::from_stance(SecurityStance::Medium)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_stance_from_str() {
        assert_eq!(
            "low".parse::<SecurityStance>().unwrap(),
            SecurityStance::Low
        );
        assert_eq!(
            "MEDIUM".parse::<SecurityStance>().unwrap(),
            SecurityStance::Medium
        );
        assert_eq!(
            "High".parse::<SecurityStance>().unwrap(),
            SecurityStance::High
        );
        assert_eq!(
            "Paranoid".parse::<SecurityStance>().unwrap(),
            SecurityStance::Paranoid
        );
        assert!("invalid".parse::<SecurityStance>().is_err());
    }

    #[test]
    fn test_security_policy_low() {
        let policy = SecurityPolicy::from_stance(SecurityStance::Low);
        assert_eq!(policy.key_size_bits(), 128);
        assert_eq!(policy.session_timeout_secs(), 7200);
        assert_eq!(policy.threat_sensitivity, 0.3);
        assert_eq!(policy.min_password_length, 8);
        assert!(!policy.require_mfa);
    }

    #[test]
    fn test_security_policy_medium() {
        let policy = SecurityPolicy::from_stance(SecurityStance::Medium);
        assert_eq!(policy.key_size_bits(), 192);
        assert_eq!(policy.session_timeout_secs(), 3600);
        assert_eq!(policy.threat_sensitivity, 0.6);
        assert_eq!(policy.min_password_length, 12);
        assert!(!policy.require_mfa);
    }

    #[test]
    fn test_security_policy_high() {
        let policy = SecurityPolicy::from_stance(SecurityStance::High);
        assert_eq!(policy.key_size_bits(), 256);
        assert_eq!(policy.session_timeout_secs(), 1800);
        assert_eq!(policy.threat_sensitivity, 0.9);
        assert_eq!(policy.min_password_length, 16);
        assert!(policy.require_mfa);
    }

    #[test]
    fn test_security_policy_paranoid() {
        let policy = SecurityPolicy::from_stance(SecurityStance::Paranoid);
        assert_eq!(policy.key_size_bits(), 256);
        assert_eq!(policy.session_timeout_secs(), 1800); // Matches HIGH_SECURITY
        assert_eq!(policy.threat_sensitivity, 1.0);
        assert_eq!(policy.min_password_length, 20);
        assert!(policy.require_mfa);
    }

    #[test]
    fn test_default_is_medium() {
        let policy = SecurityPolicy::default();
        assert_eq!(policy.stance, SecurityStance::Medium);
    }
}
