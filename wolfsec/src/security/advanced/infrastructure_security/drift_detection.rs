use super::{
    DriftDetail, DriftDetectionResult, DriftSeverity, DriftType, InfrastructureResource,
    InfrastructureSecurityConfig,
};
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

pub struct DriftDetectionManager {
    config: InfrastructureSecurityConfig,
}

impl DriftDetectionManager {
    pub fn new(config: InfrastructureSecurityConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn detect_drift(
        &self,
        resources: &[InfrastructureResource],
    ) -> Result<DriftDetectionResult> {
        let mut drift_details = Vec::new();
        let mut drift_detected = false;
        let mut max_severity = DriftSeverity::None;

        if !self
            .config
            .drift_detection_settings
            .automated_drift_detection
        {
            return Ok(DriftDetectionResult::default());
        }

        for resource in resources {
            // Check 1: Version mismatch between resource config and template
            if let Some(template) = &resource.iac_template {
                if resource.configuration.version != template.version {
                    drift_detected = true;
                    if max_severity < DriftSeverity::Medium {
                        max_severity = DriftSeverity::Medium;
                    }

                    drift_details.push(DriftDetail {
                        property_name: format!("{}.version", resource.name),
                        expected_value: serde_json::json!(template.version),
                        actual_value: serde_json::json!(resource.configuration.version),
                        drift_type: DriftType::Modified,
                    });
                }
            }

            // Check 2: Aggregate existing drift status from resource
            if resource.drift_status.drift_detected {
                drift_detected = true;
                if resource.drift_status.drift_severity > max_severity {
                    max_severity = resource.drift_status.drift_severity.clone();
                }

                for detail in &resource.drift_status.drift_details {
                    let mut new_detail = detail.clone();
                    new_detail.property_name =
                        format!("{}.{}", resource.name, detail.property_name);
                    drift_details.push(new_detail);
                }
            }
        }

        Ok(DriftDetectionResult {
            detection_id: Uuid::new_v4(),
            drift_detected,
            drift_severity: max_severity,
            drift_details,
            detection_timestamp: Utc::now(),
        })
    }
}
