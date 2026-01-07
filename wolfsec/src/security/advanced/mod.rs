//! Main security module for Wolf Prowler
//!
//! This module provides comprehensive security capabilities with wolf-themed architecture.
//! The security system is organized into layers like a wolf pack hierarchy.

pub mod alerts;
pub mod anomaly_detection;
pub mod audit;
pub mod audit_trail;
pub mod cloud_security;
pub mod compliance;
pub mod container_security;
pub mod devsecops;
pub mod iam;
pub mod infrastructure_security;
pub mod metrics;
pub mod ml_security;
pub mod notifications;
pub mod predictive_analytics;
pub mod reporting;
pub mod risk_assessment;
pub mod siem;
pub mod soar;
pub mod threat_hunting;
pub mod threat_intelligence;
pub mod zero_trust;

#[cfg(test)]
pub mod ml_security_tests;
#[cfg(test)]
pub mod siem_tests;
#[cfg(test)]
pub mod soar_tests;
// #[cfg(test)]
// pub mod comprehensive_tests;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use uuid::Uuid;

// Re-export main components for convenience
pub use anomaly_detection::{
    AnomalyDetectionConfig, AnomalyDetectionEngine, AnomalyDetectionResult,
};
pub use audit_trail::{AuditConfig, AuditEvent, AuditReport, AuditTrailSystem};
pub use cloud_security::{
    CloudResource, CloudSecurityConfig, CloudSecurityIncident, CloudSecurityManager,
};
pub use compliance::{ComplianceAssessmentResult, ComplianceConfig, ComplianceFrameworkManager};
pub use container_security::{
    ContainerInfo, ContainerSecurityConfig, ContainerSecurityManager, RuntimeAlert,
};
pub use devsecops::{DevSecOpsConfig, DevSecOpsManager, HuntSimulation, SecurityFinding};
pub use iam::{AuthenticationResult, AuthorizationDecision, IAMConfig, IAMIntegrationManager};
pub use infrastructure_security::{
    InfrastructureResource, InfrastructureSecurityConfig, InfrastructureSecurityManager,
    TerritoryAssignment,
};
pub use ml_security::{MLPredictionResult, MLSecurityConfig, MLSecurityEngine};
pub use predictive_analytics::{
    PredictionResult, PredictiveAnalyticsConfig, PredictiveAnalyticsEngine,
};
pub use risk_assessment::{RiskAssessmentConfig, RiskAssessmentManager, RiskAssessmentResult};
pub use siem::{EventSeverity, SIEMConfig, SecurityEvent, WolfSIEMManager};
pub use threat_hunting::{ThreatHunt, ThreatHuntingConfig, ThreatHuntingEngine};
pub use threat_intelligence::{
    ThreatIndicator, ThreatIntelligenceConfig, ThreatIntelligenceManager,
};
pub use zero_trust::{
    ContextualAuthenticator, MicrosegmentationManager, TrustContext, TrustLevel, WolfPolicyEngine,
    WolfTrustEngine, ZeroTrustPolicy,
};

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Zero Trust configuration
    pub zero_trust_config: zero_trust::ZeroTrustConfig,
    /// SIEM configuration
    pub siem_config: SIEMConfig,
    /// Threat intelligence configuration
    pub threat_intel_config: ThreatIntelligenceConfig,
    pub threat_detection_config: crate::threat_detection::ThreatDetectionConfig,
    /// ML security configuration
    pub ml_security_config: MLSecurityConfig,
    /// Anomaly detection configuration
    pub anomaly_detection_config: AnomalyDetectionConfig,
    /// Threat hunting configuration
    pub threat_hunting_config: ThreatHuntingConfig,
    /// Predictive analytics configuration
    pub predictive_analytics_config: PredictiveAnalyticsConfig,
    /// Compliance configuration
    pub compliance_config: ComplianceConfig,
    /// IAM configuration
    pub iam_config: IAMConfig,
    /// Audit trail configuration
    pub audit_trail_config: AuditConfig,
    /// Risk assessment configuration
    pub risk_assessment_config: RiskAssessmentConfig,
    /// Cloud security configuration
    pub cloud_security_config: CloudSecurityConfig,
    /// DevSecOps configuration
    pub devsecops_config: DevSecOpsConfig,
    /// Container security configuration
    pub container_security_config: ContainerSecurityConfig,
    /// Infrastructure security configuration
    pub infrastructure_security_config: InfrastructureSecurityConfig,
    /// Reporting configuration
    pub reporting_config: reporting::ReportingConfig,
    /// Audit configuration
    pub audit_config: audit::AuditConfig,
    /// Alerts configuration
    pub alerts_config: alerts::AlertsConfig,
    /// Metrics configuration
    pub metrics_config: metrics::MetricsConfig,
}

/// Main security manager - coordinates all security components
pub struct SecurityManager {
    /// Phase 1 components
    trust_engine: WolfTrustEngine,
    policy_engine: WolfPolicyEngine,
    contextual_auth: ContextualAuthenticator,
    microsegmentation: MicrosegmentationManager,
    siem_manager: WolfSIEMManager,
    siem_processor:
        Option<std::sync::Arc<tokio::sync::RwLock<siem::event_processor::SIEMEventProcessor>>>,

    /// Phase 2 components
    threat_intelligence: ThreatIntelligenceManager,
    ml_security: MLSecurityEngine,
    anomaly_detection: AnomalyDetectionEngine,
    threat_hunting: ThreatHuntingEngine,
    predictive_analytics: PredictiveAnalyticsEngine,

    /// Phase 3 components
    compliance_framework: ComplianceFrameworkManager,
    iam_integration: IAMIntegrationManager,
    audit_trail_system: AuditTrailSystem,
    risk_assessment: RiskAssessmentManager,

    /// Phase 4 components
    cloud_security: CloudSecurityManager,
    devsecops: DevSecOpsManager,
    container_security: ContainerSecurityManager,
    infrastructure_security: InfrastructureSecurityManager,

    /// Supporting components
    reporting: reporting::SecurityReporter,
    audit: audit::AuditManager,
    alerts: alerts::AlertManager,
    metrics: metrics::SecurityMetrics,

    /// Legacy components (Bridged)
    pub threat_detector: crate::threat_detection::ThreatDetector,

    /// Configuration
    config: SecurityConfig,

    /// Event bus for notifications
    event_bus: broadcast::Sender<SecurityEvent>,

    /// Security status
    status: SecurityStatus,
}

/// Security status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub overall_level: SecurityStatusLevel,
    pub component_status: HashMap<String, ComponentStatus>,
    pub active_threats: u64,
    pub recent_alerts: u64,
    pub compliance_score: f64,
    pub risk_score: f64,
    pub last_update: DateTime<Utc>,
    /// Additional fields for compatibility
    pub timestamp: DateTime<Utc>,
    pub overall_status: SecurityStatusLevel,
    pub metrics: HashMap<String, f64>,
    pub audit_summary: AuditSummary,
}

/// Security status levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityStatusLevel {
    Normal = 0,
    Elevated = 1,
    High = 2,
    Critical = 3,
}

/// Component status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub status: SecurityStatusLevel,
    pub last_check: DateTime<Utc>,
    pub error_count: u64,
    pub performance_score: f64,
}

impl Default for ComponentStatus {
    fn default() -> Self {
        Self {
            status: SecurityStatusLevel::Normal,
            last_check: Utc::now(),
            error_count: 0,
            performance_score: 0.95,
        }
    }
}

/// Audit summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_entries: u64,
    pub critical_events: u64,
    pub compliance_score: f64,
    pub last_audit: DateTime<Utc>,
}

impl Default for AuditSummary {
    fn default() -> Self {
        Self {
            total_entries: 0,
            critical_events: 0,
            compliance_score: 1.0,
            last_audit: Utc::now(),
        }
    }
}

/// Time range for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeRange {
    pub fn today() -> Self {
        let now = Utc::now();
        Self {
            start: now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc(),
            end: now,
        }
    }

    pub fn last_hours(hours: i64) -> Self {
        let now = Utc::now();
        Self {
            start: now - chrono::Duration::hours(hours),
            end: now,
        }
    }

    pub fn last_days(days: i64) -> Self {
        let now = Utc::now();
        Self {
            start: now - chrono::Duration::days(days),
            end: now,
        }
    }
}

impl SecurityManager {
    /// Create new security manager
    pub async fn new(
        config: SecurityConfig,
        threat_repo: std::sync::Arc<dyn crate::domain::repositories::ThreatRepository>,
    ) -> Result<Self> {
        info!("🛡️ Initializing Wolf Prowler Security Manager");

        let (event_bus, _) = broadcast::channel(100);

        let manager = Self {
            // Phase 1 components
            trust_engine: WolfTrustEngine::new()?,
            policy_engine: WolfPolicyEngine::new()?,
            contextual_auth: ContextualAuthenticator::new()?,
            microsegmentation: MicrosegmentationManager::new()?,
            siem_manager: WolfSIEMManager::new(config.siem_config.clone())?,
            siem_processor: None, // Will be initialized later if database is available

            // Phase 2 components
            threat_intelligence: ThreatIntelligenceManager::new(
                config.threat_intel_config.clone(),
            )?,
            ml_security: MLSecurityEngine::new(config.ml_security_config.clone())?,
            anomaly_detection: AnomalyDetectionEngine::new(
                config.anomaly_detection_config.clone(),
            )?,
            threat_hunting: ThreatHuntingEngine::new(config.threat_hunting_config.clone())?,
            predictive_analytics: PredictiveAnalyticsEngine::new(
                config.predictive_analytics_config.clone(),
            )?,

            // Phase 3 components
            compliance_framework: ComplianceFrameworkManager::new(
                config.compliance_config.clone(),
            )?,
            iam_integration: IAMIntegrationManager::new(config.iam_config.clone()).await?,
            audit_trail_system: AuditTrailSystem::new(config.audit_trail_config.clone())?,
            risk_assessment: RiskAssessmentManager::new(config.risk_assessment_config.clone())?,

            // Phase 4 components
            cloud_security: CloudSecurityManager::new(config.cloud_security_config.clone())?,
            devsecops: DevSecOpsManager::new(config.devsecops_config.clone())?,
            container_security: ContainerSecurityManager::new(
                config.container_security_config.clone(),
            )?,
            infrastructure_security: InfrastructureSecurityManager::new(
                config.infrastructure_security_config.clone(),
            )?,

            // Supporting components
            reporting: reporting::SecurityReporter::new(config.reporting_config.clone())?,
            audit: audit::AuditManager::new(config.audit_config.clone())?,
            threat_detector: crate::threat_detection::ThreatDetector::new(
                config.threat_detection_config.clone(),
                threat_repo,
            ),
            alerts: alerts::AlertManager::new(config.alerts_config.clone()).await?,
            metrics: metrics::SecurityMetrics::default(),

            config,
            event_bus,
            status: SecurityStatus::default(),
        };

        info!("✅ Security Manager initialized successfully");
        Ok(manager)
    }

    /// Initialize all security components
    pub async fn initialize(&mut self) -> Result<()> {
        info!("🚀 Initializing all security components");

        // Initialize Phase 1 components
        self.trust_engine.initialize().await?;
        // self.siem_manager.initialize().await?;

        // Initialize Phase 2 components
        self.threat_intelligence.start_collection().await?;
        self.ml_security.initialize_models().await?;
        self.threat_hunting.start_automated_hunting().await?;

        // Initialize Phase 3 components
        self.compliance_framework
            .run_assessment(
                compliance::ComplianceFramework::SOC2,
                compliance::AssessmentType::Initial,
            )
            .await?;

        // Initialize Phase 4 components
        self.cloud_security
            .discover_resources(vec![
                cloud_security::CloudProvider::AWS,
                cloud_security::CloudProvider::Azure,
                cloud_security::CloudProvider::GCP,
            ])
            .await?;

        info!("✅ All security components initialized");
        Ok(())
    }

    /// Process security event with full pipeline
    pub async fn process_security_event(&mut self, event: SecurityEvent) -> Result<()> {
        debug!("📊 Processing security event: {}", event.event_id);

        // Notify subscribers
        let _ = self.event_bus.send(event.clone());

        // Log to audit trail
        let audit_event = self.convert_security_event_to_audit_event(&event);
        self.audit_trail_system.log_event(audit_event).await?;

        // Send to SIEM and get response actions
        let response_actions = self.siem_manager.process_event(event.clone()).await?;

        // Handle response actions
        for action in response_actions {
            match action {
                siem::ResponseAction::SendNotification => {
                    self.alerts
                        .create_alert(
                            alerts::AlertSeverity::Medium, // Default for SIEM events if not specified
                            format!("SIEM Alert: {:?}", event.event_id),
                            event.description.clone(),
                            format!("{:?}", event.source),
                            alerts::AlertCategory::Security,
                        )
                        .await?;
                }
                siem::ResponseAction::BlockNetwork => {
                    warn!(
                        "Blocking network access based on SIEM action for event {}",
                        event.event_id
                    );
                    // TODO: Implement actual blocking
                }
                siem::ResponseAction::LogForInvestigation => {
                    info!("Event {} logged for investigation", event.event_id);
                }
                _ => {
                    info!("SIEM requested action: {:?}", action);
                }
            }
        }

        // Check for anomalies
        let anomaly_data = self.convert_event_to_anomaly_data(&event);
        let anomalies = self
            .anomaly_detection
            .detect_anomalies(&anomaly_data)
            .await?;

        // If anomalies found, run ML analysis
        if !anomalies.is_empty() {
            let ml_data = self.convert_anomalies_to_ml_data(&anomalies);
            let ml_results = if !ml_data.is_empty() {
                self.ml_security.run_inference(&ml_data[0]).await?
            } else {
                vec![]
            };

            // If ML detects threats, start threat hunting
            let threats: Vec<_> = ml_results.iter().filter(|r| r.risk_score > 0.7).collect();

            if !threats.is_empty() {
                let hunt = self
                    .threat_hunting
                    .create_hunt(
                        threat_hunting::HuntType::Reactive,
                        threat_hunting::HuntingStrategy::AdaptiveHunting,
                        threat_hunting::HuntParameters {
                            time_window: threat_hunting::TimeWindow {
                                start: Utc::now() - chrono::Duration::hours(24),
                                end: Utc::now(),
                                duration_hours: 24,
                            },
                            target_indicators: vec![
                                "suspicious_behavior".to_string(),
                                "anomaly_metrics".to_string(),
                            ],
                            search_patterns: vec!["*".to_string()], // Search pattern wildcard
                            sensitivity: 0.8,
                            max_results: 100,
                            custom_params: HashMap::new(),
                            // Using default values for now
                        },
                    )
                    .await?;

                self.threat_hunting.execute_hunt(hunt).await?;
            }
        }

        // Update metrics
        // self.metrics.record_security_event(&event).await?;

        debug!("✅ Security event processed");
        Ok(())
    }

    /// Authenticate user with full IAM pipeline
    pub async fn authenticate_user(
        &mut self,
        auth_request: iam::AuthenticationRequest,
    ) -> Result<iam::AuthenticationResult> {
        debug!("🔐 Authenticating user: {}", auth_request.username);

        // Authenticate through IAM
        let result = self.iam_integration.authenticate_user(auth_request).await?;

        // Log authentication event
        let audit_event = self.convert_auth_result_to_audit_event(&result);
        self.audit_trail_system.log_event(audit_event).await?;

        // Update trust score
        if result.success {
            // self.trust_engine.update_user_trust(&result.user_id, 0.1).await?;
        } else {
            // self.trust_engine.update_user_trust(&result.user_id, -0.2).await?;
        }

        debug!("✅ User authentication completed: {}", result.success);
        Ok(result)
    }

    /// Authorize access with full pipeline
    pub async fn authorize_access(
        &mut self,
        authz_request: iam::AuthorizationRequest,
    ) -> Result<iam::AuthorizationDecision> {
        debug!(
            "🔓 Authorizing access: {} -> {}",
            authz_request.user_id, authz_request.action
        );

        // Authorize through IAM
        let decision = self.iam_integration.authorize_access(authz_request).await?;

        // Log authorization event
        let audit_event = self.convert_authz_decision_to_audit_event(&decision);
        self.audit_trail_system.log_event(audit_event).await?;

        // Update trust based on decision
        if decision.decision == iam::Effect::Allow {
            // self.trust_engine.update_user_trust(&decision.user_id, 0.05).await?;
        } else {
            // self.trust_engine.update_user_trust(&decision.user_id, -0.1).await?;
        }

        debug!("✅ Access authorization completed: {:?}", decision.decision);
        Ok(decision)
    }

    /// Run comprehensive security assessment
    pub async fn run_security_assessment(&mut self) -> Result<ComprehensiveSecurityAssessment> {
        info!("🎯 Running comprehensive security assessment");

        let start_time = std::time::Instant::now();

        // Run compliance assessment
        let compliance_result = self
            .compliance_framework
            .run_assessment(
                compliance::ComplianceFramework::SOC2,
                compliance::AssessmentType::Periodic,
            )
            .await?;

        // Run risk assessment
        let risk_result = self
            .risk_assessment
            .run_assessment(
                risk_assessment::AssessmentType::Periodic,
                risk_assessment::AssessmentScope {
                    assets: vec!["all".to_string()],
                    systems: vec!["all".to_string()],
                    processes: vec!["all".to_string()],
                    departments: vec!["all".to_string()],
                    geographic_locations: vec!["all".to_string()],
                },
            )
            .await?;

        // Scan for vulnerabilities
        let vulnerabilities = self
            .risk_assessment
            .scan_vulnerabilities(vec!["all".to_string()])
            .await?;

        // Generate heat map
        let heat_map = self.risk_assessment.generate_heat_map(true).await?;

        // Run gap analysis
        let gap_analysis = self
            .risk_assessment
            .run_gap_analysis(compliance::ComplianceFramework::SOC2, &self.config)
            .await?;

        let assessment_duration = start_time.elapsed().as_secs();

        let assessment = ComprehensiveSecurityAssessment {
            id: uuid::Uuid::new_v4(),
            compliance_result,
            risk_result,
            vulnerabilities,
            heat_map,
            gap_analysis,
            assessment_duration_seconds: assessment_duration,
            created_at: Utc::now(),
        };

        info!(
            "✅ Comprehensive security assessment completed in {} seconds",
            assessment_duration
        );
        Ok(assessment)
    }

    /// Get comprehensive security status
    pub async fn get_security_status(&mut self) -> Result<&SecurityStatus> {
        debug!("📊 Getting comprehensive security status");

        // Update component statuses
        self.update_component_statuses().await?;

        // Calculate overall status
        self.calculate_overall_status().await?;

        Ok(&self.status)
    }

    /// Generate comprehensive security report
    pub async fn generate_security_report(
        &self,
        time_range: TimeRange,
    ) -> Result<reporting::SecurityReport> {
        info!(
            "📋 Generating comprehensive security report for {:?}",
            time_range
        );

        let report = self.reporting.generate_report(&time_range).await?;

        info!("✅ Security report generated");
        Ok(report)
    }

    /// Convert security event to audit event
    fn convert_security_event_to_audit_event(
        &self,
        event: &SecurityEvent,
    ) -> audit_trail::AuditEvent {
        audit_trail::AuditEvent {
            id: uuid::Uuid::new_v4(),
            event_type: audit_trail::AuditEventType::SecurityAlert,
            category: audit_trail::AuditCategory::Security,
            severity: match event.severity {
                siem::EventSeverity::Pup => audit_trail::AuditLogLevel::Info,
                siem::EventSeverity::Scout => audit_trail::AuditLogLevel::Warning,
                siem::EventSeverity::Hunter => audit_trail::AuditLogLevel::Error,
                siem::EventSeverity::Beta => audit_trail::AuditLogLevel::Error,
                siem::EventSeverity::Alpha => audit_trail::AuditLogLevel::Critical,
            },
            timestamp: event.timestamp,
            source: audit_trail::EventSource {
                id: "wolf_prowler".to_string(),
                source_type: audit_trail::SourceType::Security,
                name: "Wolf Prowler Security System".to_string(),
                location: None,
                version: Some("1.0.0".to_string()),
            },
            user_info: None,
            resource_info: Some(audit_trail::ResourceInfo {
                resource_id: format!("{:?}", event.source),
                resource_type: audit_trail::ResourceType::System,
                name: format!("{:?}", event.source),
                location: None,
                owner: None,
            }),
            details: audit_trail::AuditEventDetails {
                action: format!("{:?}", event.event_type),
                description: format!("Security event: {:?}", event.event_type),
                before_state: None,
                after_state: None,
                additional_details: HashMap::new(),
            },
            outcome: audit_trail::EventOutcome::Success,
            ip_address: None,
            user_agent: None,
            session_id: None,
            request_id: Some(event.event_id),
            correlation_id: Some(event.event_id),
            tags: vec!["security".to_string(), "wolf_prowler".to_string()],
            metadata: HashMap::new(),
        }
    }

    /// Get the Policy Engine
    pub fn get_policy_engine(&self) -> &WolfPolicyEngine {
        &self.policy_engine
    }

    /// Get the Microsegmentation Manager
    pub fn get_microsegmentation(&self) -> &MicrosegmentationManager {
        &self.microsegmentation
    }

    /// Get Predictive Analytics Engine
    pub fn get_predictive_analytics(&self) -> &PredictiveAnalyticsEngine {
        &self.predictive_analytics
    }

    /// Get legacy security stats compatibility
    pub fn get_security_stats(&self) -> SimpleSecurityStats {
        SimpleSecurityStats {
            suspicious_peers: 0,
            active_threats: self.status.active_threats as usize,
            trusted_peers: 0,
        }
    }

    /// Get active threats count
    pub fn get_active_threats(&self) -> usize {
        self.status.active_threats as usize
    }

    /// Get ML Security Engine
    pub fn get_ml_engine(&self) -> &MLSecurityEngine {
        &self.ml_security
    }

    /// Report a security event for real-time processing
    /// This is the main entry point for external components to report security events
    pub async fn report_security_event(&mut self, event: SecurityEvent) -> Result<()> {
        debug!("📢 Reporting security event: {}", event.event_id);

        // If SIEM processor is available, use it for real-time processing
        if let Some(processor) = &self.siem_processor {
            processor.read().await.process_event(event.clone()).await?;
        } else {
            // Fallback to legacy processing
            self.process_security_event(event).await?;
        }

        Ok(())
    }

    /// Initialize SIEM event processor with database support
    pub async fn initialize_siem_processor(
        &mut self,
        event_storage: std::sync::Arc<tokio::sync::RwLock<siem::event_storage::EventStorage>>,
        correlation_engine: std::sync::Arc<
            tokio::sync::RwLock<siem::correlation_engine::WolfCorrelationEngine>,
        >,
        incident_orchestrator: std::sync::Arc<
            tokio::sync::RwLock<soar::orchestrator::IncidentOrchestrator>,
        >,
    ) -> Result<()> {
        info!("🔧 Initializing SIEM event processor");

        let processor = siem::event_processor::SIEMEventProcessor::new(
            event_storage,
            correlation_engine,
            incident_orchestrator,
            self.config.siem_config.clone(),
        );

        self.siem_processor = Some(std::sync::Arc::new(tokio::sync::RwLock::new(processor)));

        info!("✅ SIEM event processor initialized");
        Ok(())
    }

    /// Convert auth result to audit event
    fn convert_auth_result_to_audit_event(
        &self,
        result: &iam::AuthenticationResult,
    ) -> audit_trail::AuditEvent {
        audit_trail::AuditEvent {
            id: uuid::Uuid::new_v4(),
            event_type: if result.success {
                audit_trail::AuditEventType::UserLogin
            } else {
                audit_trail::AuditEventType::LoginFailure
            },
            category: audit_trail::AuditCategory::Authentication,
            severity: if result.success {
                audit_trail::AuditLogLevel::Info
            } else {
                audit_trail::AuditLogLevel::Warning
            },
            timestamp: result.timestamp,
            source: audit_trail::EventSource {
                id: "iam".to_string(),
                source_type: audit_trail::SourceType::Application,
                name: "Wolf Prowler IAM".to_string(),
                location: None,
                version: Some("1.0.0".to_string()),
            },
            user_info: Some(audit_trail::UserInfo {
                user_id: result.user_id,
                username: result.user_id.to_string(), // Use user_id as username
                roles: Vec::new(),
                groups: Vec::new(),
                department: None,
                location: None,
            }),
            resource_info: None,
            details: audit_trail::AuditEventDetails {
                action: "authentication".to_string(),
                description: result
                    .error_message
                    .clone()
                    .unwrap_or_else(|| "Authentication successful".to_string()),
                before_state: None,
                after_state: None,
                additional_details: HashMap::new(),
            },
            outcome: if result.success {
                audit_trail::EventOutcome::Success
            } else {
                audit_trail::EventOutcome::Failure
            },
            ip_address: Some(result.ip_address.clone()),
            user_agent: Some(result.user_agent.clone()),
            session_id: result.session_id,
            request_id: Some(result.id),
            correlation_id: Some(result.id),
            tags: vec!["authentication".to_string(), "iam".to_string()],
            metadata: HashMap::new(),
        }
    }

    /// Convert authorization decision to audit event
    fn convert_authz_decision_to_audit_event(
        &self,
        decision: &iam::AuthorizationDecision,
    ) -> audit_trail::AuditEvent {
        audit_trail::AuditEvent {
            id: uuid::Uuid::new_v4(),
            event_type: match decision.decision {
                iam::Effect::Allow => audit_trail::AuditEventType::AccessGranted,
                iam::Effect::Deny => audit_trail::AuditEventType::AccessDenied,
            },
            category: audit_trail::AuditCategory::Authorization,
            severity: audit_trail::AuditLogLevel::Info,
            timestamp: decision.timestamp,
            source: audit_trail::EventSource {
                id: "iam".to_string(),
                source_type: audit_trail::SourceType::Application,
                name: "Wolf Prowler IAM".to_string(),
                location: None,
                version: Some("1.0.0".to_string()),
            },
            user_info: Some(audit_trail::UserInfo {
                user_id: decision.user_id,
                username: String::new(), // Would be populated from user lookup
                roles: Vec::new(),
                groups: Vec::new(),
                department: None,
                location: None,
            }),
            resource_info: Some(audit_trail::ResourceInfo {
                resource_id: decision.resource.clone(),
                resource_type: audit_trail::ResourceType::Custom(decision.resource.clone()),
                name: decision.resource.clone(),
                location: None,
                owner: None,
            }),
            details: audit_trail::AuditEventDetails {
                action: decision.action.clone(),
                description: decision.reason.clone(),
                before_state: None,
                after_state: None,
                additional_details: HashMap::new(),
            },
            outcome: match decision.decision {
                iam::Effect::Allow => audit_trail::EventOutcome::Success,
                iam::Effect::Deny => audit_trail::EventOutcome::Failure,
            },
            ip_address: None,
            user_agent: None,
            session_id: None,
            request_id: Some(decision.id),
            correlation_id: Some(decision.id),
            tags: vec!["authorization".to_string(), "iam".to_string()],
            metadata: HashMap::new(),
        }
    }

    /// Convert event to anomaly data
    fn convert_event_to_anomaly_data(
        &self,
        event: &SecurityEvent,
    ) -> anomaly_detection::AnomalyInputData {
        anomaly_detection::AnomalyInputData {
            id: uuid::Uuid::new_v4(),
            entity_id: format!("{:?}", event.source),
            data_type: format!("{:?}", event.event_type),
            metrics: HashMap::new(),  // Would extract from event details
            features: HashMap::new(), // Would extract from event details
            timestamp: event.timestamp,
            context: HashMap::new(),
        }
    }

    /// Convert anomalies to ML data
    fn convert_anomalies_to_ml_data(
        &self,
        anomalies: &[anomaly_detection::AnomalyDetectionResult],
    ) -> Vec<ml_security::MLInputData> {
        anomalies
            .iter()
            .map(|a| ml_security::MLInputData {
                id: uuid::Uuid::new_v4(),
                data_type: format!("{:?}", a.anomaly_type),
                features: HashMap::new(), // Would extract from anomaly
                timestamp: a.timestamp,
                source: a.context.source_entity.clone(),
            })
            .collect()
    }

    /// Update component statuses
    async fn update_component_statuses(&mut self) -> Result<()> {
        // Update all component statuses
        // In a real implementation, this would check health of each component

        for component in [
            "trust_engine",
            "siem_manager",
            "threat_intelligence",
            "ml_security",
            "anomaly_detection",
            "threat_hunting",
            "predictive_analytics",
            "compliance_framework",
            "iam_integration",
            "audit_trail_system",
            "risk_assessment",
        ] {
            self.status.component_status.insert(
                component.to_string(),
                ComponentStatus {
                    status: SecurityStatusLevel::Normal,
                    last_check: Utc::now(),
                    error_count: 0,
                    performance_score: 1.0,
                },
            );
        }

        self.status.last_update = Utc::now();
        Ok(())
    }

    /// Calculate overall status
    async fn calculate_overall_status(&mut self) -> Result<()> {
        let mut max_level = SecurityStatusLevel::Normal;

        for component_status in self.status.component_status.values() {
            if component_status.status > max_level {
                max_level = component_status.status;
            }
        }

        self.status.overall_level = max_level;

        // Calculate compliance and risk scores
        self.status.compliance_score = 0.85; // Would get from compliance manager
        self.status.risk_score = 0.3; // Would get from risk assessment

        Ok(())
    }

    /// Get security metrics
    pub async fn get_metrics(&self) -> Result<metrics::SecurityMetricsSnapshot> {
        // self.metrics.get_snapshot().await
        Ok(metrics::SecurityMetricsSnapshot {
            health: 1.0,
            active_threats: 0,
            connected_peers: 0,
            system_load: 0.0,
        })
    }

    /// Get recent alerts
    pub async fn get_recent_alerts(&self, limit: usize) -> Result<Vec<alerts::SecurityAlert>> {
        Ok(self.alerts.get_recent_alerts(limit).await)
    }

    // Phase 4 specific methods

    /// Scan cloud resources for security issues
    pub async fn scan_cloud_resources(
        &mut self,
        providers: Vec<cloud_security::CloudProvider>,
    ) -> Result<Vec<cloud_security::CloudResource>> {
        info!("☁️ Scanning cloud resources for security issues");
        self.cloud_security.discover_resources(providers).await
    }

    /// Assess cloud security posture
    pub async fn assess_cloud_security(
        &mut self,
        resource_ids: Vec<uuid::Uuid>,
    ) -> Result<Vec<cloud_security::SecurityPostureAssessment>> {
        info!("🛡️ Assessing cloud security posture");
        self.cloud_security
            .assess_security_posture(resource_ids)
            .await
    }

    /// Scan repository for DevSecOps security issues
    pub async fn scan_repository_devsecops(
        &mut self,
        repository_url: &str,
        branch: &str,
    ) -> Result<devsecops::RepositoryScanResult> {
        info!("🔧 Scanning repository for DevSecOps security issues");
        self.devsecops.scan_repository(repository_url, branch).await
    }

    /// Run hunt simulation
    pub async fn run_hunt_simulation(
        &mut self,
        simulation: devsecops::HuntSimulation,
    ) -> Result<devsecops::SimulationResults> {
        info!("🐺 Running hunt simulation");
        self.devsecops.run_hunt_simulation(simulation).await
    }

    /// Scan container images for vulnerabilities
    pub async fn scan_container_images(
        &mut self,
        _image_names: Vec<String>,
    ) -> Result<Vec<container_security::ContainerScanResult>> {
        info!("🐳 Scanning container images for vulnerabilities");
        // self.container_security.scan_container_images(image_names).await
        Ok(vec![])
    }

    /// Protect container runtime
    pub async fn protect_container_runtime(
        &mut self,
        container_id: &str,
    ) -> Result<container_security::RuntimeProtectionResult> {
        info!("🛡️ Protecting container runtime");
        self.container_security
            .protect_container_runtime(container_id)
            .await
    }

    /// Validate IaC template
    pub async fn validate_iac_template(
        &mut self,
        template: infrastructure_security::IaCTemplate,
    ) -> Result<infrastructure_security::TemplateValidationResult> {
        info!("🏗️ Validating IaC template");
        self.infrastructure_security
            .validate_iac_template(template)
            .await
    }

    /// Check infrastructure compliance
    pub async fn check_infrastructure_compliance(
        &mut self,
        resources: Vec<infrastructure_security::InfrastructureResource>,
    ) -> Result<infrastructure_security::ComplianceCheckResult> {
        info!("📋 Checking infrastructure compliance");
        self.infrastructure_security
            .check_compliance(resources)
            .await
    }

    /// Detect infrastructure drift
    pub async fn detect_infrastructure_drift(
        &mut self,
        resources: Vec<infrastructure_security::InfrastructureResource>,
    ) -> Result<infrastructure_security::DriftDetectionResult> {
        info!("🔍 Detecting infrastructure drift");
        self.infrastructure_security.detect_drift(resources).await
    }

    /// Generate comprehensive Phase 4 security report
    pub async fn generate_phase4_report(
        &self,
        time_range: TimeRange,
    ) -> Result<Phase4SecurityReport> {
        info!("📊 Generating Phase 4 comprehensive security report");

        // Convert time ranges for different modules
        let cloud_time_range = cloud_security::TimeRange {
            start: time_range.start,
            end: time_range.end,
        };

        let devsecops_time_range = devsecops::TimeRange {
            start: time_range.start,
            end: time_range.end,
        };

        let container_time_range = container_security::TimeRange {
            start: time_range.start,
            end: time_range.end,
        };

        let infra_time_range = infrastructure_security::TimeRange {
            start: time_range.start,
            end: time_range.end,
        };

        let cloud_report = self
            .cloud_security
            .generate_security_report(
                cloud_security::CloudReportType::SecurityPosture,
                cloud_time_range,
            )
            .await?;

        let devsecops_report = self
            .devsecops
            .generate_report(
                devsecops::DevSecOpsReportType::SecurityPosture,
                devsecops_time_range,
            )
            .await?;

        let container_report = self
            .container_security
            .generate_report(
                container_security::ContainerReportType::SecurityPosture,
                container_time_range,
            )
            .await?;

        let infra_report = self
            .infrastructure_security
            .generate_report(
                infrastructure_security::InfrastructureReportType::SecurityPosture,
                infra_time_range,
            )
            .await?;

        let report = Phase4SecurityReport {
            id: uuid::Uuid::new_v4(),
            time_range,
            status: ReportStatus::Completed,
            generated_at: chrono::Utc::now(),
            cloud_security_report: cloud_report,
            devsecops_report: devsecops_report,
            container_security_report: container_report,
            infrastructure_security_report: infra_report,
            overall_phase4_score: 0.0,   // Would calculate from all reports
            key_findings: Vec::new(),    // Would populate with key findings
            recommendations: Vec::new(), // Would populate with recommendations
        };

        info!("✅ Phase 4 security report generated: {}", report.id);
        Ok(report)
    }
    /// Subscribe to security events
    pub fn subscribe_events(&self) -> broadcast::Receiver<SecurityEvent> {
        self.event_bus.subscribe()
    }
}

/// Comprehensive security assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveSecurityAssessment {
    /// Assessment ID
    pub id: Uuid,
    /// Compliance result
    pub compliance_result: compliance::ComplianceAssessmentResult,
    /// Risk assessment result
    pub risk_result: risk_assessment::RiskAssessmentResult,
    /// Vulnerabilities found
    pub vulnerabilities: Vec<risk_assessment::VulnerabilityItem>,
    /// Risk heat map
    pub heat_map: risk_assessment::RiskHeatMap,
    /// Gap analysis result
    pub gap_analysis: risk_assessment::ComplianceGapAnalysisResult,
    /// Assessment duration in seconds
    pub assessment_duration_seconds: u64,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Report status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

impl Default for SecurityStatus {
    fn default() -> Self {
        Self {
            overall_level: SecurityStatusLevel::Normal,
            component_status: HashMap::new(),
            active_threats: 0,
            recent_alerts: 0,
            compliance_score: 0.0,
            risk_score: 0.0,
            last_update: Utc::now(),
            timestamp: Utc::now(),
            overall_status: SecurityStatusLevel::Normal,
            metrics: HashMap::new(),
            audit_summary: AuditSummary::default(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            zero_trust_config: zero_trust::ZeroTrustConfig::default(),
            siem_config: SIEMConfig::default(),
            threat_intel_config: ThreatIntelligenceConfig::default(),
            threat_detection_config: crate::threat_detection::ThreatDetectionConfig::default(),
            ml_security_config: MLSecurityConfig::default(),
            anomaly_detection_config: AnomalyDetectionConfig::default(),
            threat_hunting_config: ThreatHuntingConfig::default(),
            predictive_analytics_config: PredictiveAnalyticsConfig::default(),
            compliance_config: ComplianceConfig::default(),
            iam_config: IAMConfig::default(),
            audit_trail_config: AuditConfig::default(),
            risk_assessment_config: RiskAssessmentConfig::default(),
            cloud_security_config: CloudSecurityConfig::default(),
            devsecops_config: DevSecOpsConfig::default(),
            container_security_config: ContainerSecurityConfig::default(),
            infrastructure_security_config: InfrastructureSecurityConfig::default(),
            reporting_config: reporting::ReportingConfig::default(),
            audit_config: audit::AuditConfig::default(),
            alerts_config: alerts::AlertsConfig::default(),
            metrics_config: metrics::MetricsConfig::default(),
        }
    }
}

/// Phase 4 comprehensive security report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase4SecurityReport {
    /// Report ID
    pub id: Uuid,
    /// Time range
    pub time_range: TimeRange,
    /// Report status
    pub status: ReportStatus,
    /// Generated at
    pub generated_at: DateTime<Utc>,
    /// Cloud security report
    pub cloud_security_report: cloud_security::CloudSecurityReport,
    /// DevSecOps report
    pub devsecops_report: devsecops::DevSecOpsReport,
    /// Container security report
    pub container_security_report: container_security::ContainerSecurityReport,
    /// Infrastructure security report
    pub infrastructure_security_report: infrastructure_security::InfrastructureSecurityReport,
    /// Overall Phase 4 security score
    pub overall_phase4_score: f64,
    /// Key findings
    pub key_findings: Vec<String>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleSecurityStats {
    pub suspicious_peers: usize,
    pub active_threats: usize,
    pub trusted_peers: usize,
}
