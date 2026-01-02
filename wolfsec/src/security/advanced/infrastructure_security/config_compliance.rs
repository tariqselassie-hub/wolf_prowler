use super::{
    ComplianceCheckResult, ComplianceStatusLevel, FrameworkCompliance,
    InfrastructureComplianceViolation, InfrastructureResource, InfrastructureSecurityConfig,
    ViolationSeverity,
};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

pub struct ConfigComplianceManager {
    config: InfrastructureSecurityConfig,
}

impl ConfigComplianceManager {
    pub fn new(config: InfrastructureSecurityConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn check_compliance(
        &self,
        resources: &[InfrastructureResource],
    ) -> Result<ComplianceCheckResult> {
        let mut violations = Vec::new();
        let mut framework_compliance = HashMap::new();

        // Initialize framework compliance stats based on config
        for framework in &self.config.config_compliance_settings.compliance_frameworks {
            let framework_name = format!("{:?}", framework);
            framework_compliance.insert(
                framework_name.clone(),
                FrameworkCompliance {
                    framework: framework_name,
                    score: 100.0,
                    status: ComplianceStatusLevel::Compliant,
                    requirements_met: 0,
                    total_requirements: 0,
                },
            );
        }

        for resource in resources {
            // Check 1: Encryption
            if !resource.configuration.security_settings.encryption_enabled {
                violations.push(InfrastructureComplianceViolation {
                    id: Uuid::new_v4(),
                    framework: "NIST".to_string(),
                    requirement: "Data Protection".to_string(),
                    severity: ViolationSeverity::High,
                    description: format!("Encryption disabled for {}", resource.name),
                    resource_affected: resource.id.to_string(),
                    remediation_steps: vec!["Enable encryption".to_string()],
                });
            }

            // Check 2: Access Control
            if !resource
                .configuration
                .security_settings
                .access_control_enabled
            {
                violations.push(InfrastructureComplianceViolation {
                    id: Uuid::new_v4(),
                    framework: "CIS".to_string(),
                    requirement: "Access Control".to_string(),
                    severity: ViolationSeverity::Critical,
                    description: format!("Access control disabled for {}", resource.name),
                    resource_affected: resource.id.to_string(),
                    remediation_steps: vec!["Enable access control".to_string()],
                });
            }

            // Check 3: Backup
            if !resource.configuration.security_settings.backup_enabled {
                violations.push(InfrastructureComplianceViolation {
                    id: Uuid::new_v4(),
                    framework: "SOC2".to_string(),
                    requirement: "Availability".to_string(),
                    severity: ViolationSeverity::Medium,
                    description: format!("Backup disabled for {}", resource.name),
                    resource_affected: resource.id.to_string(),
                    remediation_steps: vec!["Enable backups".to_string()],
                });
            }
        }

        // Calculate scores
        let total_violations = violations.len();
        let overall_score = if resources.is_empty() {
            100.0
        } else {
            (100.0 - (total_violations as f64 * 5.0)).max(0.0)
        };

        // Update framework scores
        for compliance in framework_compliance.values_mut() {
            let count = violations
                .iter()
                .filter(|v| v.framework == compliance.framework)
                .count();

            if count > 0 {
                compliance.score = (100.0 - (count as f64 * 10.0)).max(0.0);
                compliance.status = if compliance.score < 50.0 {
                    ComplianceStatusLevel::NonCompliant
                } else {
                    ComplianceStatusLevel::PartiallyCompliant
                };
            }
        }

        Ok(ComplianceCheckResult {
            check_id: Uuid::new_v4(),
            overall_score,
            framework_compliance,
            violations,
            check_timestamp: Utc::now(),
        })
    }
}
