//! Protection Module
//!
//! Active protection, threat detection, and security enforcement for Wolf Prowler.
//!
//! # Core Components
//!
//! - **Network Security**: Firewall policies, encrypted communications, transport protection
//! - **Threat Detection**: Real-time threat analysis and vulnerability scanning  
//! - **Reputation Management**: IP/peer reputation tracking and filtering
//! - **Anomaly Detection**: ML-based anomaly detection and behavioral analysis
//! - **Container Security**: Docker/Kubernetes security scanning and runtime protection
//! - **Cloud Security**: Multi-cloud security posture management
//! - **DevSecOps**: CI/CD security integration and policy enforcement
//! - **Risk Assessment**: Continuous risk assessment and gap analysis
//! - **Threat Intelligence**: External threat feed integration and correlation
//! - **Threat Hunting**: Proactive threat hunting and investigation
//!
//! # Example
//!
//! ```rust
//! use wolfsec::protection::threat_detection::{ThreatDetector, ThreatDetectionConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = ThreatDetectionConfig::default();
//! let detector = ThreatDetector::new(config).await?;
//! # Ok(())
//! # }
//! ```

pub mod network_security;
pub mod reputation;
pub mod sbom_validation;
pub mod threat_detection;

// Advanced Protection
pub mod anomaly_detection;
pub mod cloud_security;
pub mod container_security;
pub mod devsecops;
pub mod infrastructure_security;
pub mod ml_security;
pub mod network_security_advanced;
pub mod risk_assessment;
pub mod threat_detection_advanced;
pub mod threat_hunting;
pub mod threat_intelligence;
