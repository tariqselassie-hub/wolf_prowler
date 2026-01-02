use crate::security::advanced::compliance::ComplianceFramework;
use crate::security::advanced::risk_assessment::GapAnalysisConfig;
use crate::security::advanced::SecurityConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Compliance Gap Analyzer
pub struct ComplianceGapAnalyzer {
    /// Configuration
    config: GapAnalysisConfig,
    /// Standard requirements library
    requirements_library: HashMap<String, Requirement>,
}

/// A specific security requirement/control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    /// Unique ID (e.g., "SOC2-CC6.1-MFA")
    pub id: String,
    /// Human readable name
    pub name: String,
    /// Description of the control
    pub description: String,
    /// Framework this belongs to
    pub framework: ComplianceFramework,
    /// Severity if missing
    pub severity: GapSeverity,
    /// Category
    pub category: ControlCategory,
    /// Remediation steps
    pub remediation: String,
}

/// Categories of controls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ControlCategory {
    AccessControl,
    NetworkSecurity,
    Encryption,
    Monitoring,
    IncidentResponse,
    Availability,
    ConfigurationManagement,
}

/// Severity of a gap
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Finding of a gap analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapFinding {
    /// Associated requirement
    pub requirement: Requirement,
    /// Current status
    pub status: ComplianceStatus,
    /// Evidence or reason for failure
    pub evidence: String,
    /// Detection timestamp
    pub detected_at: DateTime<Utc>,
}

/// Status of a compliance check
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    NotApplicable,
    ManualCheckRequired,
}

/// Result of a gap analysis run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceGapAnalysisResult {
    /// Analysis ID
    pub id: uuid::Uuid,
    /// Target framework
    pub framework: ComplianceFramework,
    /// Findings
    pub findings: Vec<GapFinding>,
    /// Summary statistics
    pub total_requirements: usize,
    pub compliant_count: usize,
    pub non_compliant_count: usize,
    /// Compliance score (0.0 - 1.0)
    pub score: f64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl ComplianceGapAnalyzer {
    pub fn new(config: GapAnalysisConfig) -> Result<Self> {
        let mut library = HashMap::new();
        Self::populate_soc2_requirements(&mut library);

        Ok(Self {
            config,
            requirements_library: library,
        })
    }

    /// Analyze configuration for gaps against a framework
    pub fn analyze_gaps(
        &self,
        framework: ComplianceFramework,
        security_config: &SecurityConfig,
    ) -> Result<ComplianceGapAnalysisResult> {
        let mut findings = Vec::new();
        let mut compliant_count = 0;
        let mut non_compliant_count = 0;
        let mut total_checked = 0;

        // Filter requirements for the target framework
        let relevant_reqs: Vec<&Requirement> = self
            .requirements_library
            .values()
            .filter(|r| r.framework == framework)
            .collect();

        for req in relevant_reqs {
            let (status, evidence) = self.check_requirement(req, security_config);

            match status {
                ComplianceStatus::Compliant => compliant_count += 1,
                ComplianceStatus::NonCompliant => non_compliant_count += 1,
                _ => {}
            }
            total_checked += 1;

            findings.push(GapFinding {
                requirement: req.clone(),
                status,
                evidence,
                detected_at: Utc::now(),
            });
        }

        let score = if total_checked > 0 {
            compliant_count as f64 / total_checked as f64
        } else {
            0.0
        };

        Ok(ComplianceGapAnalysisResult {
            id: uuid::Uuid::new_v4(),
            framework,
            findings,
            total_requirements: total_checked,
            compliant_count,
            non_compliant_count,
            score,
            timestamp: Utc::now(),
        })
    }

    /// Check a single requirement against the config
    fn check_requirement(
        &self,
        req: &Requirement,
        config: &SecurityConfig,
    ) -> (ComplianceStatus, String) {
        match req.id.as_str() {
            "SOC2-CC6.1-MFA" => {
                if config.iam_config.mfa_requirements.enabled {
                    (
                        ComplianceStatus::Compliant,
                        "MFA is enabled in IAM configuration".to_string(),
                    )
                } else {
                    (
                        ComplianceStatus::NonCompliant,
                        "IAM MFA requirements are disabled".to_string(),
                    )
                }
            }
            "SOC2-CC6.1-RBAC" => {
                if config.iam_config.access_control.rbac_enabled {
                    (
                        ComplianceStatus::Compliant,
                        "RBAC is enabled in IAM configuration".to_string(),
                    )
                } else {
                    (
                        ComplianceStatus::NonCompliant,
                        "IAM RBAC is disabled".to_string(),
                    )
                }
            }
            "SOC2-CC2.2-Audit" => {
                if config.audit_trail_config.logging_enabled {
                    (
                        ComplianceStatus::Compliant,
                        "Audit logging is enabled".to_string(),
                    )
                } else {
                    (
                        ComplianceStatus::NonCompliant,
                        "Audit logging is disabled in configuration".to_string(),
                    )
                }
            }
            "SOC2-CC7.1-Monitor" => {
                // Check if any integration endpoint is configured as a proxy for monitoring being active
                if !config.siem_config.integration_endpoints.is_empty() {
                    (
                        ComplianceStatus::Compliant,
                        "SIEM integration endpoints are configured".to_string(),
                    )
                } else {
                    (
                        ComplianceStatus::NonCompliant,
                        "No SIEM integration endpoints configured".to_string(),
                    )
                }
            }
            "SOC2-CC6.8-Malware" => {
                // Check threat sharing as proxy for active threat program
                if config.threat_intel_config.sharing_config.enabled {
                    (
                        ComplianceStatus::Compliant,
                        "Threat Intelligence sharing is enabled".to_string(),
                    )
                } else {
                    // If sharing is disabled, check if feeds are configured (implicit check via default)
                    // Falling back to NonCompliant if sharing is off for strictness
                    (
                        ComplianceStatus::NonCompliant,
                        "Threat Intelligence sharing is disabled".to_string(),
                    )
                }
            }
            // Manual Checks for items not explicitly in config structs yet
            "SOC2-CC6.7-EncTrans" => (
                ComplianceStatus::ManualCheckRequired,
                "Encryption configuration not found in SecurityConfig".to_string(),
            ),
            "SOC2-CC6.7-EncRest" => (
                ComplianceStatus::ManualCheckRequired,
                "Storage encryption configuration not found".to_string(),
            ),
            "SOC2-A1.2-Backup" => (
                ComplianceStatus::ManualCheckRequired,
                "Backup configuration not found".to_string(),
            ),
            _ => (
                ComplianceStatus::ManualCheckRequired,
                "Automated check not implemented for this control".to_string(),
            ),
        }
    }

    /// Populate the library with standard SOC2 requirements
    fn populate_soc2_requirements(library: &mut HashMap<String, Requirement>) {
        let reqs = vec![
            Requirement {
                id: "SOC2-CC6.1-MFA".to_string(),
                name: "Multi-Factor Authentication".to_string(),
                description: "Implement MFA for all remote network access and privileged users.".to_string(),
                framework: ComplianceFramework::SOC2,
                severity: GapSeverity::Critical,
                category: ControlCategory::AccessControl,
                remediation: "Enable 'mfa_requirements.enabled' in IAM configuration settings.".to_string(),
            },
            Requirement {
                id: "SOC2-CC6.1-RBAC".to_string(),
                name: "Role-Based Access Control".to_string(),
                description: "Restrict access to sensitive data and systems based on roles and responsibilities.".to_string(),
                framework: ComplianceFramework::SOC2,
                severity: GapSeverity::High,
                category: ControlCategory::AccessControl,
                remediation: "Enable 'access_control.rbac_enabled' in IAM configuration settings.".to_string(),
            },
            Requirement {
                id: "SOC2-CC6.7-EncTrans".to_string(),
                name: "Encryption in Transit".to_string(),
                description: "Encrypt data in transit to safeguard sensitive information.".to_string(),
                framework: ComplianceFramework::SOC2,
                severity: GapSeverity::High,
                category: ControlCategory::Encryption,
                remediation: "Ensure TLS 1.2+ is enabled for all network listeners.".to_string(),
            },
            Requirement {
                id: "SOC2-CC6.7-EncRest".to_string(),
                name: "Encryption at Rest".to_string(),
                description: "Encrypt data at rest to safeguard sensitive information.".to_string(),
                framework: ComplianceFramework::SOC2,
                severity: GapSeverity::High,
                category: ControlCategory::Encryption,
                remediation: "Enable volume encryption or database encryption in storage settings.".to_string(),
            },
            Requirement {
                id: "SOC2-CC2.2-Audit".to_string(),
                name: "Audit Logging".to_string(),
                description: "System processing execution events are logged and monitored.".to_string(),
                framework: ComplianceFramework::SOC2,
                severity: GapSeverity::High,
                category: ControlCategory::Monitoring,
                remediation: "Set 'logging_enabled' to true in Audit Configuration.".to_string(),
            },
            Requirement {
                id: "SOC2-CC7.1-Monitor".to_string(),
                name: "System Monitoring".to_string(),
                description: "Infrastructure and network performance are monitored for anomalies.".to_string(),
                framework: ComplianceFramework::SOC2,
                severity: GapSeverity::Medium,
                category: ControlCategory::Monitoring,
                remediation: "Configure at least one SIEM integration endpoint.".to_string(),
            },
             Requirement {
                id: "SOC2-CC6.8-Malware".to_string(),
                name: "Malware Detection".to_string(),
                description: "Implement software to protect systems from malicious threats.".to_string(),
                framework: ComplianceFramework::SOC2,
                severity: GapSeverity::Medium,
                category: ControlCategory::IncidentResponse,
                remediation: "Enable Threat Intelligence modules.".to_string(),
            },
             Requirement {
                id: "SOC2-A1.2-Backup".to_string(),
                name: "Data Backup".to_string(),
                description: "Regular backup procedures for data and systems.".to_string(),
                framework: ComplianceFramework::SOC2,
                severity: GapSeverity::High,
                category: ControlCategory::Availability,
                remediation: "Configure automated daily backups with offsite storage.".to_string(),
            },
        ];

        for r in reqs {
            library.insert(r.id.clone(), r);
        }
    }
}
