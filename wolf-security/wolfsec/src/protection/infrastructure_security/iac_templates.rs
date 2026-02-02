use super::{
    FindingSeverity, IaCTemplate, InfrastructureSecurityConfig, TemplateFindingType,
    TemplateSecurityFinding, TemplateValidationResult, ValidationError, ValidationErrorType,
    ValidationStatus,
};
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

pub struct IaCTemplateManager {
    config: InfrastructureSecurityConfig,
}

impl IaCTemplateManager {
    pub fn new(config: InfrastructureSecurityConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn validate_template(
        &self,
        template: &IaCTemplate,
    ) -> Result<TemplateValidationResult> {
        let mut validation_errors = Vec::new();
        let mut security_findings = Vec::new();
        let mut status = ValidationStatus::Valid;

        if !self
            .config
            .iac_template_settings
            .template_validation_enabled
        {
            return Ok(TemplateValidationResult {
                template_id: template.id,
                status: ValidationStatus::Valid,
                validation_errors: Vec::new(),
                security_findings: Vec::new(),
                validation_timestamp: Utc::now(),
            });
        }

        // 1. Check for hardcoded secrets (Basic check)
        if self.config.iac_template_settings.security_scanning_enabled {
            if template.content.contains("password = \"")
                || template.content.contains("secret = \"")
                || template.content.contains("private_key = \"")
            {
                security_findings.push(TemplateSecurityFinding {
                    id: Uuid::new_v4(),
                    finding_type: TemplateFindingType::HardcodedSecret,
                    severity: FindingSeverity::Critical,
                    description: "Potential hardcoded secret detected in template content"
                        .to_string(),
                    recommendation: "Use a secrets manager or template parameters".to_string(),
                });
                status = ValidationStatus::Invalid;
            }
        }

        // 2. Check required parameters
        for (name, param) in &template.parameters {
            if param.description.is_empty() {
                validation_errors.push(ValidationError {
                    id: Uuid::new_v4(),
                    error_type: ValidationErrorType::SemanticError,
                    message: format!("Parameter '{}' is missing a description", name),
                    line_number: None,
                    column_number: None,
                });
                if status != ValidationStatus::Invalid {
                    status = ValidationStatus::Warning;
                }
            }
        }

        // 3. Check security controls
        for control in &template.security_controls {
            if control.status == super::SecurityControlStatus::NotImplemented {
                security_findings.push(TemplateSecurityFinding {
                    id: Uuid::new_v4(),
                    finding_type: TemplateFindingType::InsecureConfiguration,
                    severity: FindingSeverity::Medium,
                    description: format!("Security control '{}' is not implemented", control.name),
                    recommendation: format!("Implement control: {}", control.name),
                });
                if status != ValidationStatus::Invalid {
                    status = ValidationStatus::Warning;
                }
            }
        }

        Ok(TemplateValidationResult {
            template_id: template.id,
            status,
            validation_errors,
            security_findings,
            validation_timestamp: Utc::now(),
        })
    }
}
