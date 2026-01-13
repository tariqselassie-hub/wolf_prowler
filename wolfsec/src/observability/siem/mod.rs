//! SIEM Integration Module
//!
//! Security Information and Event Management integration with wolf-themed monitoring.
//! Wolves monitor their territory constantly, detecting threats and coordinating responses.

pub mod alert_manager;
pub mod compliance_reporter;
pub mod correlation_engine;
pub mod event_collector;
pub mod event_processor;
pub mod event_storage;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid; // Use libp2p's PeerId directly

pub use alert_manager::WolfAlertManager;
pub use compliance_reporter::ComplianceReporter;
pub use correlation_engine::{CorrelationResult, WolfCorrelationEngine};
/// Re-export main components
pub use event_collector::WolfSIEMCollector;

/// SIEM event severity levels with wolf-themed classifications
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventSeverity {
    /// Pup level - Informational only
    Pup = 0,
    /// Scout level - Low priority
    Scout = 1,
    /// Hunter level - Medium priority
    Hunter = 2,
    /// Beta level - High priority
    Beta = 3,
    /// Alpha level - Critical priority
    Alpha = 4,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    /// Authentication events
    AuthEvent(AuthEventType),
    /// Network events
    NetworkEvent(NetworkEventType),
    /// System events
    SystemEvent(SystemEventType),
    /// Threat detection events
    ThreatEvent(ThreatEventType),
    /// Compliance events
    ComplianceEvent(ComplianceEventType),
}

/// Authentication event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthEventType {
    LoginSuccess,
    LoginFailure,
    Logout,
    PasswordChange,
    MFAChallenge,
    AccountLockout,
    PrivilegeEscalation,
}

/// Network event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkEventType {
    ConnectionEstablished,
    ConnectionTerminated,
    PortScan,
    UnusualTraffic,
    DDoSAttempt,
    DataExfiltration,
    SuspiciousProtocol,
}

/// System event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemEventType {
    ServiceStart,
    ServiceStop,
    ConfigurationChange,
    ResourceExhaustion,
    FileSystemAccess,
    ProcessExecution,
    SystemUpdate,
}

/// Threat event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatEventType {
    MalwareDetected,
    IntrusionAttempt,
    AnomalyDetected,
    DataBreach,
    InsiderThreat,
    AdvancedPersistentThreat,
    ZeroDayExploit,
}

/// Compliance event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceEventType {
    PolicyViolation,
    RegulationBreach,
    AuditFailure,
    DataPrivacyViolation,
    AccessControlViolation,
    DocumentationMissing,
}

/// Main security event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event identifier
    pub event_id: Uuid,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event severity
    pub severity: EventSeverity,
    /// Event type
    pub event_type: SecurityEventType,
    /// Source of the event
    pub source: EventSource,
    /// Affected assets
    pub affected_assets: Vec<Asset>,
    /// Event details
    pub details: EventDetails,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<MitreTactic>,
    /// Event correlation data
    pub correlation_data: CorrelationData,
    /// Response actions taken
    pub response_actions: Vec<ResponseAction>,
    pub target: Option<String>,
    pub description: String,
    pub metadata: HashMap<String, String>,
}

/// Event source information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSource {
    pub source_type: SourceType,
    pub source_id: String,
    pub location: String,
    pub credibility: f64,
}

/// Event source types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceType {
    /// Wolf pack member (internal)
    PackMember,
    /// Territory sensor
    TerritorySensor,
    /// External threat feed
    ThreatFeed,
    /// System logs
    SystemLogs,
    /// Network monitoring
    NetworkMonitor,
    /// User report
    UserReport,
}

/// Asset information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub asset_id: String,
    pub asset_type: AssetType,
    pub owner: Option<String>,
    pub location: String,
    pub criticality: AssetCriticality,
    pub current_status: AssetStatus,
}

/// Asset types with wolf-themed classifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetType {
    /// Alpha asset - Critical system
    Alpha,
    /// Beta asset - Important system
    Beta,
    /// Gamma asset - Standard system
    Gamma,
    /// Delta asset - Supporting system
    Delta,
    /// Omega asset - Non-critical system
    Omega,
}

/// Asset criticality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetCriticality {
    Critical,
    High,
    Medium,
    Low,
}

/// Asset status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetStatus {
    Operational,
    Degraded,
    Compromised,
    Offline,
    Maintenance,
}

/// Event details
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventDetails {
    pub title: String,
    pub description: String,
    pub technical_details: HashMap<String, serde_json::Value>,
    pub user_context: Option<UserContext>,
    pub system_context: Option<SystemContext>,
}

/// User context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub department: String,
    pub session_id: Option<String>,
}

/// System context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemContext {
    pub hostname: String,
    pub ip_address: String,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
}

/// MITRE ATT&CK tactics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum MitreTactic {
    #[default]
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

/// Correlation data for event relationships
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorrelationData {
    pub related_events: Vec<Uuid>,
    pub correlation_score: f64,
    pub correlation_rules: Vec<String>,
    pub attack_chain: Option<AttackChain>,
}

/// Attack chain representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub chain_id: Uuid,
    pub current_stage: AttackStage,
    pub completed_stages: Vec<AttackStage>,
    pub predicted_stages: Vec<AttackStage>,
    pub confidence: f64,
}

impl Default for AttackChain {
    fn default() -> Self {
        Self {
            chain_id: Uuid::new_v4(),
            current_stage: AttackStage::default(),
            completed_stages: Vec::new(),
            predicted_stages: Vec::new(),
            confidence: 0.0,
        }
    }
}

/// Attack stage
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackStage {
    pub stage_name: String,
    pub mitre_tactic: MitreTactic,
    pub completed: bool,
    pub timestamp: Option<DateTime<Utc>>,
}

/// Response actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseAction {
    /// Block network access
    BlockNetwork,
    /// Isolate system
    IsolateSystem,
    /// Require additional authentication
    RequireMFA,
    /// Increase monitoring
    IncreaseMonitoring,
    /// Send notification
    SendNotification,
    /// Log for investigation
    LogForInvestigation,
    /// Quarantine system
    QuarantineSystem,
    /// Revoke access
    RevokeAccess,
}

/// SIEM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMConfig {
    pub event_retention_days: u32,
    pub correlation_window_minutes: u32,
    pub alert_thresholds: HashMap<String, f64>,
    pub integration_endpoints: Vec<IntegrationEndpoint>,
    pub compliance_requirements: Vec<ComplianceRequirement>,
}

/// Integration endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationEndpoint {
    pub endpoint_type: EndpointType,
    pub url: String,
    pub authentication: AuthenticationMethod,
    pub enabled: bool,
}

/// Endpoint types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndpointType {
    /// Splunk integration
    Splunk,
    /// ELK Stack integration
    ELKStack,
    /// QRadar integration
    QRadar,
    /// Custom API endpoint
    CustomAPI,
    /// Email notification
    Email,
    /// Slack webhook
    Slack,
}

/// Authentication methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationMethod {
    APIKey(String),
    BearerToken(String),
    BasicAuth(String, String),
    Certificate(String),
    None,
}

/// Compliance requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirement {
    pub standard: ComplianceStandard,
    pub requirement_id: String,
    pub description: String,
    pub monitoring_rules: Vec<String>,
    pub reporting_frequency: ReportingFrequency,
}

/// Compliance standards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStandard {
    SOC2,
    ISO27001,
    GDPR,
    HIPAA,
    PciDss,
    NIST,
}

/// Reporting frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportingFrequency {
    RealTime,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Quarterly,
}

/// SIEM statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMStatistics {
    pub total_events_processed: u64,
    pub events_by_severity: HashMap<EventSeverity, u64>,
    pub events_by_type: HashMap<String, u64>,
    pub alerts_generated: u64,
    pub false_positive_rate: f64,
    pub average_processing_time_ms: f64,
    pub storage_usage_mb: f64,
}

impl Default for SIEMConfig {
    fn default() -> Self {
        Self {
            event_retention_days: 30,
            correlation_window_minutes: 60,
            alert_thresholds: HashMap::new(),
            integration_endpoints: Vec::new(),
            compliance_requirements: Vec::new(),
        }
    }
}

/// Main SIEM manager
pub struct WolfSIEMManager {
    pub collector: WolfSIEMCollector,
    pub correlation_engine: WolfCorrelationEngine,
    pub alert_manager: WolfAlertManager,
    pub compliance_reporter: ComplianceReporter,
    pub config: SIEMConfig,
    pub statistics: SIEMStatistics,
}

impl WolfSIEMManager {
    /// Create new SIEM manager
    pub fn new(config: SIEMConfig) -> Result<Self> {
        info!("🐺 Initializing Wolf SIEM Manager");

        let manager = Self {
            collector: WolfSIEMCollector::new()?,
            correlation_engine: WolfCorrelationEngine::new()?,
            alert_manager: WolfAlertManager::new()?,
            compliance_reporter: ComplianceReporter::new()?,
            config,
            statistics: SIEMStatistics::default(),
        };

        info!("✅ Wolf SIEM Manager initialized successfully");
        Ok(manager)
    }

    /// Process a security event
    pub async fn process_event(&mut self, event: SecurityEvent) -> Result<Vec<ResponseAction>> {
        debug!("📊 Processing security event: {}", event.event_id);

        // Update statistics
        self.update_statistics(&event);

        // Collect and enrich event
        let enriched_event = self.collector.collect_event(event).await?;

        // Correlate with other events
        let correlation_result = self
            .correlation_engine
            .correlate_event(&enriched_event)
            .await?;

        // Generate alerts if needed
        let alerts = self
            .alert_manager
            .evaluate_alerts(&enriched_event, &correlation_result)
            .await?;

        // Generate response actions
        let mut response_actions = Vec::new();

        for alert in alerts {
            let actions = self.alert_manager.generate_response_actions(&alert).await?;
            response_actions.extend(actions);
        }

        // Check compliance requirements
        let compliance_issues = self
            .compliance_reporter
            .check_compliance(&enriched_event)
            .await?;

        if !compliance_issues.is_empty() {
            warn!("⚠️ Compliance issues detected: {:?}", compliance_issues);
            response_actions.push(ResponseAction::LogForInvestigation);
        }

        info!(
            "🎯 Event processing completed: {} actions generated",
            response_actions.len()
        );
        Ok(response_actions)
    }

    /// Get SIEM statistics
    pub fn get_statistics(&self) -> &SIEMStatistics {
        &self.statistics
    }

    /// Generate compliance report
    pub async fn generate_compliance_report(
        &self,
        standard: ComplianceStandard,
    ) -> Result<ComplianceReport> {
        self.compliance_reporter.generate_report(standard).await
    }

    /// Update statistics
    fn update_statistics(&mut self, event: &SecurityEvent) {
        self.statistics.total_events_processed += 1;

        *self
            .statistics
            .events_by_severity
            .entry(event.severity.clone())
            .or_insert(0) += 1;

        let event_type_key = format!("{:?}", event.event_type);
        *self
            .statistics
            .events_by_type
            .entry(event_type_key)
            .or_insert(0) += 1;
    }
}

/// Compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub standard: ComplianceStandard,
    pub report_period: ReportPeriod,
    pub overall_score: f64,
    pub requirement_results: Vec<RequirementResult>,
    pub violations: Vec<ComplianceViolation>,
    pub recommendations: Vec<String>,
    pub generated_at: DateTime<Utc>,
}

/// Report period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPeriod {
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
}

/// Requirement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementResult {
    pub requirement_id: String,
    pub compliant: bool,
    pub score: f64,
    pub evidence: Vec<String>,
    pub issues: Vec<String>,
}

/// Compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub violation_id: Uuid,
    pub requirement_id: String,
    pub severity: EventSeverity,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub affected_assets: Vec<String>,
    pub remediation_steps: Vec<String>,
}

impl Default for SIEMStatistics {
    fn default() -> Self {
        Self {
            total_events_processed: 0,
            events_by_severity: HashMap::new(),
            events_by_type: HashMap::new(),
            alerts_generated: 0,
            false_positive_rate: 0.0,
            average_processing_time_ms: 0.0,
            storage_usage_mb: 0.0,
        }
    }
}
