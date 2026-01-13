use crate::protection::devsecops::{
    CICDPipeline, DevSecOpsConfig, FindingLocation, FindingSeverity, FindingStatus, FindingType,
    SecuredPipeline, SecurityFinding,
};
use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use uuid::Uuid;

pub struct CICDSecurityManager {
    config: DevSecOpsConfig,
    secret_patterns: Vec<(String, Regex)>,
    misconfig_patterns: Vec<(String, Regex)>,
}

impl CICDSecurityManager {
    pub fn new(config: DevSecOpsConfig) -> Result<Self> {
        // Compile regexes once for performance
        let secret_patterns = vec![
            (
                "AWS Access Key".to_string(),
                Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            ),
            (
                "AWS Secret Key".to_string(),
                Regex::new(r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}").unwrap(),
            ),
            (
                "Private Key".to_string(),
                Regex::new(r"BEGIN RSA PRIVATE KEY").unwrap(),
            ),
            (
                "Generic API Key".to_string(),
                Regex::new(r#"(?i)api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]"#).unwrap(),
            ),
            (
                "Generic Password".to_string(),
                Regex::new(r#"(?i)password\s*[:=]\s*['"][a-zA-Z0-9@#$%^&*()_\-+]{8,}['"]"#)
                    .unwrap(),
            ),
        ];

        let misconfig_patterns = vec![
            (
                "Privileged Mode".to_string(),
                Regex::new(r"(?i)privileged\s*[:=]\s*true").unwrap(),
            ),
            (
                "Docker Privileged Flag".to_string(),
                Regex::new(r"--privileged").unwrap(),
            ),
            (
                "Root User".to_string(),
                Regex::new(r"(?i)user\s+root").unwrap(),
            ),
            (
                "Root Login Permit".to_string(),
                Regex::new(r"(?i)PermitRootLogin\s+yes").unwrap(),
            ),
            (
                "Debug Mode".to_string(),
                Regex::new(r"(?i)debug\s*[:=]\s*true").unwrap(),
            ),
        ];

        Ok(Self {
            config,
            secret_patterns,
            misconfig_patterns,
        })
    }

    pub async fn secure_pipeline(&self, pipeline: &CICDPipeline) -> Result<SecuredPipeline> {
        // Placeholder for full pipeline securing logic using the pipeline struct
        Ok(SecuredPipeline {
            id: pipeline.id,
            name: pipeline.name.clone(),
            security_controls: Vec::new(),
            security_gates: pipeline.security_gates.clone(),
            status: pipeline.status.clone(),
            security_score: 1.0,
            secured_at: Utc::now(),
        })
    }

    /// Scan pipeline configuration content for security issues
    pub fn scan_pipeline_config(&self, content: &str, file_path: &str) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = (line_idx + 1) as u32;

            // Check for secrets
            for (name, regex) in &self.secret_patterns {
                if regex.is_match(line) {
                    findings.push(self.create_finding(
                        name,
                        "Potential hardcoded secret detected in pipeline configuration.",
                        FindingType::Secret,
                        FindingSeverity::Critical,
                        file_path,
                        line_num,
                        line,
                        "Remove the hardcoded secret and use a secrets manager or environment variables."
                    ));
                }
            }

            // Check for misconfigurations
            for (name, regex) in &self.misconfig_patterns {
                if regex.is_match(line) {
                    findings.push(self.create_finding(
                        name,
                        "Insecure configuration detected.",
                        FindingType::Misconfiguration,
                        FindingSeverity::High,
                        file_path,
                        line_num,
                        line,
                        "Review the configuration and ensure least privilege principles are followed."
                    ));
                }
            }
        }

        findings
    }

    fn create_finding(
        &self,
        title: &str,
        description: &str,
        finding_type: FindingType,
        severity: FindingSeverity,
        file_path: &str,
        line_number: u32,
        code_snippet: &str,
        recommendation: &str,
    ) -> SecurityFinding {
        SecurityFinding {
            id: Uuid::new_v4(),
            finding_type,
            severity,
            title: title.to_string(),
            description: description.to_string(),
            location: FindingLocation {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                column_number: None,
                code_snippet: Some(code_snippet.trim().to_string()),
            },
            recommendation: recommendation.to_string(),
            detected_at: Utc::now(),
            status: FindingStatus::Open,
        }
    }
}
