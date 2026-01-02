//! Audit Trail System Module
//!
//! Comprehensive audit logging with wolf pack tracking principles.
//! Wolves maintain detailed pack records for accountability and historical analysis.

pub mod chain_of_custody;
// pub mod cli; // Requires clap dependency
pub mod forensic;
pub mod logging;
pub mod reporting;
pub mod retention;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

pub use chain_of_custody::ChainOfCustodyManager;
pub use forensic::ForensicAnalyzer;
/// Re-export main components
pub use logging::AuditLogger;
pub use reporting::AuditReporter;
pub use retention::RetentionManager;

/// Main audit trail system manager
pub struct AuditTrailSystem {
    /// Audit logger
    logger: AuditLogger,
    /// Retention manager
    retention: RetentionManager,
    /// Forensic analyzer
    forensic: ForensicAnalyzer,
    /// Audit reporter
    reporting: AuditReporter,
    /// Chain of custody manager
    chain_of_custody: ChainOfCustodyManager,
    /// Configuration
    config: AuditConfig,
    /// Statistics
    statistics: AuditStats,
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Audit logging enabled
    pub logging_enabled: bool,
    /// Log levels
    pub log_levels: Vec<AuditLogLevel>,
    /// Retention settings
    pub retention: RetentionConfig,
    /// Forensic settings
    pub forensic: ForensicConfig,
    /// Reporting settings
    pub reporting: ReportingConfig,
    /// Chain of custody settings
    pub chain_of_custody: ChainOfCustodyConfig,
    /// Performance settings
    pub performance: PerformanceConfig,
}

/// Audit log levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuditLogLevel {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4,
}

/// Retention configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Default retention period in days
    pub default_retention_days: u32,
    /// Retention by category
    pub category_retention: HashMap<AuditCategory, u32>,
    /// Auto-cleanup enabled
    pub auto_cleanup_enabled: bool,
    /// Cleanup frequency in hours
    pub cleanup_frequency_hours: u32,
    /// Archive before deletion
    pub archive_before_deletion: bool,
}

/// Forensic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicConfig {
    /// Forensic analysis enabled
    pub enabled: bool,
    /// Auto-analysis enabled
    pub auto_analysis_enabled: bool,
    /// Analysis frequency in hours
    pub analysis_frequency_hours: u32,
    /// Suspicious pattern detection
    pub suspicious_pattern_detection: bool,
    /// Anomaly detection threshold
    pub anomaly_threshold: f64,
}

/// Reporting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    /// Automated reporting enabled
    pub automated_reports_enabled: bool,
    /// Report frequency in days
    pub report_frequency_days: u32,
    /// Report recipients
    pub report_recipients: Vec<String>,
    /// Include sensitive data
    pub include_sensitive_data: bool,
    /// Report formats
    pub report_formats: Vec<ReportFormat>,
}

/// Chain of custody configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyConfig {
    /// Chain of custody enabled
    pub enabled: bool,
    /// Digital signatures required
    pub digital_signatures_required: bool,
    /// Hash algorithm
    pub hash_algorithm: HashAlgorithm,
    /// Blockchain storage enabled
    pub blockchain_storage_enabled: bool,
    /// Legal adhesion requirements
    pub legal_adhesion_requirements: bool,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Batch size for processing
    pub batch_size: usize,
    /// Maximum concurrent operations
    pub max_concurrent_operations: usize,
    /// Cache size
    pub cache_size: usize,
    /// Compression enabled
    pub compression_enabled: bool,
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total audit events
    pub total_events: u64,
    /// Events by category
    pub events_by_category: HashMap<AuditCategory, u64>,
    /// Events by severity
    pub events_by_severity: HashMap<AuditLogLevel, u64>,
    /// Storage usage in MB
    pub storage_usage_mb: f64,
    /// Forensic findings
    pub forensic_findings: u64,
    /// Generated reports
    pub generated_reports: u64,
    /// Last cleanup timestamp
    pub last_cleanup: DateTime<Utc>,
    /// Last analysis timestamp
    pub last_analysis: DateTime<Utc>,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event ID
    pub id: Uuid,
    /// Event type
    pub event_type: AuditEventType,
    /// Event category
    pub category: AuditCategory,
    /// Severity level
    pub severity: AuditLogLevel,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Source
    pub source: EventSource,
    /// User information
    pub user_info: Option<UserInfo>,
    /// Resource information
    pub resource_info: Option<ResourceInfo>,
    /// Event details
    pub details: AuditEventDetails,
    /// Outcome
    pub outcome: EventOutcome,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Session ID
    pub session_id: Option<Uuid>,
    /// Request ID
    pub request_id: Option<Uuid>,
    /// Correlation ID
    pub correlation_id: Option<Uuid>,
    /// Tags
    pub tags: Vec<String>,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditEventType {
    // Authentication events
    UserLogin,
    UserLogout,
    LoginFailure,
    PasswordChange,
    MFAChallenge,
    MFASuccess,
    MFAFailure,

    // Authorization events
    AccessGranted,
    AccessDenied,
    PrivilegeEscalation,
    RoleAssignment,
    RoleRevocation,

    // User management events
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserSuspended,
    UserReactivated,

    // System events
    SystemStart,
    SystemStop,
    ConfigurationChange,
    PolicyUpdate,

    // Security events
    SecurityAlert,
    ThreatDetected,
    IncidentDeclared,
    IncidentResolved,

    // Data events
    DataAccess,
    DataModification,
    DataExport,
    DataDeletion,

    // Compliance events
    ComplianceCheck,
    AuditTriggered,
    ReportGenerated,

    // Custom events
    Custom(String),
}

/// Audit categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    Authentication,
    Authorization,
    UserManagement,
    System,
    Security,
    Data,
    Compliance,
    Network,
    Application,
    Custom(String),
}

/// Event source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSource {
    /// Source ID
    pub id: String,
    /// Source type
    pub source_type: SourceType,
    /// Source name
    pub name: String,
    /// Source location
    pub location: Option<String>,
    /// Source version
    pub version: Option<String>,
}

/// Source types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceType {
    Application,
    Service,
    System,
    Network,
    Database,
    Security,
    User,
    External,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// User ID
    pub user_id: Uuid,
    /// Username
    pub username: String,
    /// User roles
    pub roles: Vec<String>,
    /// User groups
    pub groups: Vec<String>,
    /// User department
    pub department: Option<String>,
    /// User location
    pub location: Option<String>,
}

/// Resource information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Resource ID
    pub resource_id: String,
    /// Resource type
    pub resource_type: ResourceType,
    /// Resource name
    pub name: String,
    /// Resource location
    pub location: Option<String>,
    /// Resource owner
    pub owner: Option<String>,
}

/// Resource types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    File,
    Directory,
    Database,
    Table,
    Application,
    Service,
    Network,
    System,
    API,
    Custom(String),
}

/// Audit event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventDetails {
    /// Action performed
    pub action: String,
    /// Description
    pub description: String,
    /// Before state
    pub before_state: Option<serde_json::Value>,
    /// After state
    pub after_state: Option<serde_json::Value>,
    /// Additional details
    pub additional_details: HashMap<String, serde_json::Value>,
}

/// Event outcome
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventOutcome {
    Success,
    Failure,
    Partial,
    Unknown,
}

/// Forensic finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicFinding {
    /// Finding ID
    pub id: Uuid,
    /// Finding type
    pub finding_type: ForensicFindingType,
    /// Severity level
    pub severity: ForensicSeverity,
    /// Description
    pub description: String,
    /// Related events
    pub related_events: Vec<Uuid>,
    /// Evidence
    pub evidence: Vec<EvidenceItem>,
    /// Timeline
    pub timeline: ForensicTimeline,
    /// Analysis results
    pub analysis_results: AnalysisResults,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Status
    pub status: FindingStatus,
}

/// Forensic finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForensicFindingType {
    SuspiciousPattern,
    AnomalyDetected,
    PolicyViolation,
    SecurityIncident,
    DataBreach,
    UnauthorizedAccess,
    SystemCompromise,
    InsiderThreat,
}

/// Forensic severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ForensicSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Evidence item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Evidence ID
    pub id: Uuid,
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Evidence content
    pub content: serde_json::Value,
    /// Hash for integrity
    pub hash: String,
    /// Collection timestamp
    pub collected_at: DateTime<Utc>,
    /// Collected by
    pub collected_by: String,
    /// Chain of custody
    pub chain_of_custody: Vec<CustodyEntry>,
}

/// Evidence types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    LogEntry,
    Screenshot,
    NetworkCapture,
    FileHash,
    SystemState,
    Configuration,
    UserAction,
    SystemEvent,
}

/// Custody entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Custodian
    pub custodian: String,
    /// Action
    pub action: String,
    /// Location
    pub location: String,
    /// Signature
    pub signature: String,
}

/// Forensic timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicTimeline {
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    pub end_time: DateTime<Utc>,
    /// Timeline events
    pub events: Vec<TimelineEvent>,
}

/// Timeline event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event description
    pub description: String,
    /// Event type
    pub event_type: String,
    /// Event source
    pub source: String,
    /// Significance
    pub significance: f64,
}

/// Analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResults {
    /// Confidence score
    pub confidence_score: f64,
    /// Risk score
    pub risk_score: f64,
    /// Patterns detected
    pub patterns_detected: Vec<String>,
    /// Anomalies found
    pub anomalies_found: Vec<String>,
    /// Correlations
    pub correlations: Vec<Correlation>,
    /// Summary
    pub summary: String,
}

/// Correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    /// Correlation type
    pub correlation_type: String,
    /// Correlation strength
    pub strength: f64,
    /// Related entities
    pub related_entities: Vec<String>,
    /// Description
    pub description: String,
}

/// Finding status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingStatus {
    Open,
    InProgress,
    Investigating,
    Resolved,
    Closed,
    FalsePositive,
}

/// Audit report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// Report ID
    pub id: Uuid,
    /// Report type
    pub report_type: ReportType,
    /// Report period
    pub period: ReportPeriod,
    /// Generated at
    pub generated_at: DateTime<Utc>,
    /// Generated by
    pub generated_by: String,
    /// Executive summary
    pub executive_summary: String,
    /// Key findings
    pub key_findings: Vec<ForensicFinding>,
    /// Statistics
    pub statistics: ReportStatistics,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Appendices
    pub appendices: Vec<ReportAppendix>,
}

/// Report types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportType {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Annual,
    Incident,
    Compliance,
    Forensic,
    Custom(String),
}

/// Report period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportPeriod {
    /// Start date
    pub start_date: DateTime<Utc>,
    /// End date
    pub end_date: DateTime<Utc>,
}

/// Report statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStatistics {
    /// Total events
    pub total_events: u64,
    /// Events by category
    pub events_by_category: HashMap<AuditCategory, u64>,
    /// Events by severity
    pub events_by_severity: HashMap<AuditLogLevel, u64>,
    /// Unique users
    pub unique_users: u64,
    /// Unique resources
    pub unique_resources: u64,
    /// Top events
    pub top_events: Vec<EventStatistic>,
}

/// Event statistic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStatistic {
    /// Event type
    pub event_type: String,
    /// Count
    pub count: u64,
    /// Percentage
    pub percentage: f64,
}

/// Report appendix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportAppendix {
    /// Appendix title
    pub title: String,
    /// Appendix content
    pub content: String,
    /// Appendix type
    pub appendix_type: AppendixType,
}

/// Appendix types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppendixType {
    Text,
    Table,
    Chart,
    Image,
    Document,
}

/// Report formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportFormat {
    PDF,
    HTML,
    JSON,
    CSV,
    XML,
}

/// Hash algorithms
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum HashAlgorithm {
    #[default]
    SHA256,
    SHA512,
    Blake3,
    MD5, // Not recommended for security
}

impl AuditTrailSystem {
    /// Create new audit trail system
    pub fn new(config: AuditConfig) -> Result<Self> {
        info!("📋 Initializing Audit Trail System");

        let system = Self {
            logger: AuditLogger::new(config.clone())?,
            retention: RetentionManager::new(config.clone())?,
            forensic: ForensicAnalyzer::new(config.clone())?,
            reporting: AuditReporter::new(config.clone())?,
            chain_of_custody: ChainOfCustodyManager::new(config.clone())?,
            config,
            statistics: AuditStats::default(),
        };

        info!("✅ Audit Trail System initialized successfully");
        Ok(system)
    }

    /// Log audit event
    pub async fn log_event(&mut self, mut event: AuditEvent) -> Result<()> {
        debug!("📝 Logging audit event: {:?}", event.event_type);

        // Sign the event for chain of custody
        self.chain_of_custody.sign_event(&mut event).await?;

        // Log the event
        self.logger.log_event(event.clone()).await?;

        // Update statistics
        self.update_event_statistics(&event);

        // Check for forensic analysis triggers
        if self.config.forensic.auto_analysis_enabled {
            self.trigger_forensic_analysis(&event).await?;
        }

        debug!("✅ Audit event logged: {}", event.id);
        Ok(())
    }

    /// Query audit events
    pub async fn query_events(&self, query: AuditQuery) -> Result<Vec<AuditEvent>> {
        debug!("🔍 Querying audit events");

        let events = self.logger.query_events(query).await?;

        info!("✅ Found {} audit events", events.len());
        Ok(events)
    }

    /// Run forensic analysis
    pub async fn run_forensic_analysis(
        &mut self,
        time_range: ReportPeriod,
    ) -> Result<Vec<ForensicFinding>> {
        info!("🔍 Running forensic analysis for period: {:?}", time_range);

        let findings = self.forensic.analyze_period(time_range).await?;

        // Update statistics
        self.statistics.forensic_findings += findings.len() as u64;
        self.statistics.last_analysis = Utc::now();

        info!(
            "✅ Forensic analysis completed: {} findings",
            findings.len()
        );
        Ok(findings)
    }

    /// Generate audit report
    pub async fn generate_report(
        &mut self,
        report_type: ReportType,
        period: ReportPeriod,
    ) -> Result<AuditReport> {
        info!(
            "📊 Generating audit report: {:?} for period: {:?}",
            report_type, period
        );

        // Query events for the period
        let query = AuditQuery {
            time_range: Some(period.clone()),
            event_types: None,
            categories: None,
            severity_levels: None,
            user_id: None,
            resource_id: None,
            ip_address: None,
            text_search: None,
            limit: None,
            offset: None,
            sort_by: None,
            sort_order: None,
        };

        let events = self.logger.query_events(query).await?;

        // Generate report with retrieved events
        let report = self.reporting.generate_report(&events, report_type, period).await?;

        // Update statistics
        self.statistics.generated_reports += 1;

        info!("✅ Audit report generated: {}", report.id);
        Ok(report)
    }

    /// Validate an exported audit chain file
    pub async fn validate_chain_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<bool> {
        info!("🔍 Validating audit chain file: {:?}", path.as_ref());
        self.chain_of_custody.validate_exported_chain(path).await
    }

    /// Cleanup old audit events
    pub async fn cleanup_old_events(&mut self) -> Result<CleanupResult> {
        info!("🧹 Cleaning up old audit events");

        let result = self.retention.cleanup_old_events().await?;

        // Update statistics
        self.statistics.last_cleanup = Utc::now();
        self.statistics.storage_usage_mb = result.remaining_storage_mb;

        info!(
            "✅ Cleanup completed: {} events removed",
            result.events_removed
        );
        Ok(result)
    }

    /// Get audit statistics
    pub fn get_statistics(&self) -> &AuditStats {
        &self.statistics
    }

    /// Update event statistics
    fn update_event_statistics(&mut self, event: &AuditEvent) {
        self.statistics.total_events += 1;

        *self
            .statistics
            .events_by_category
            .entry(event.category.clone())
            .or_insert(0) += 1;

        *self
            .statistics
            .events_by_severity
            .entry(event.severity.clone())
            .or_insert(0) += 1;

        self.statistics.last_update = Utc::now();
    }

    /// Trigger forensic analysis
    async fn trigger_forensic_analysis(&mut self, event: &AuditEvent) -> Result<()> {
        // Check if event meets analysis criteria
        if event.severity >= AuditLogLevel::Error {
            debug!("🔍 Triggering forensic analysis for high-severity event");

            // In a real implementation, this would trigger background analysis
            // For now, we'll just log the trigger
        }

        Ok(())
    }
}

/// Audit query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Event types filter
    pub event_types: Option<Vec<AuditEventType>>,
    /// Categories filter
    pub categories: Option<Vec<AuditCategory>>,
    /// Severity filter
    pub severity_levels: Option<Vec<AuditLogLevel>>,
    /// Time range
    pub time_range: Option<ReportPeriod>,
    /// User filter
    pub user_id: Option<Uuid>,
    /// Resource filter
    pub resource_id: Option<String>,
    /// IP address filter
    pub ip_address: Option<String>,
    /// Text search
    pub text_search: Option<String>,
    /// Limit
    pub limit: Option<usize>,
    /// Offset
    pub offset: Option<usize>,
    /// Sort by
    pub sort_by: Option<SortField>,
    /// Sort order
    pub sort_order: Option<SortOrder>,
}

/// Sort fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortField {
    Timestamp,
    EventType,
    Category,
    Severity,
    Username,
    Resource,
}

/// Sort order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOrder {
    Ascending,
    Descending,
}

/// Cleanup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupResult {
    /// Events removed
    pub events_removed: u64,
    /// Storage freed in MB
    pub storage_freed_mb: f64,
    /// Remaining storage in MB
    pub remaining_storage_mb: f64,
    /// Cleanup duration in seconds
    pub cleanup_duration_seconds: u64,
    /// Errors encountered
    pub errors: Vec<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            logging_enabled: true,
            log_levels: vec![
                AuditLogLevel::Info,
                AuditLogLevel::Warning,
                AuditLogLevel::Error,
                AuditLogLevel::Critical,
            ],
            retention: RetentionConfig::default(),
            forensic: ForensicConfig::default(),
            reporting: ReportingConfig::default(),
            chain_of_custody: ChainOfCustodyConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        let mut category_retention = HashMap::new();
        category_retention.insert(AuditCategory::Security, 2555); // 7 years
        category_retention.insert(AuditCategory::Compliance, 2555); // 7 years
        category_retention.insert(AuditCategory::Authentication, 1095); // 3 years
        category_retention.insert(AuditCategory::Authorization, 1095); // 3 years
        category_retention.insert(AuditCategory::UserManagement, 1825); // 5 years
        category_retention.insert(AuditCategory::System, 365); // 1 year
        category_retention.insert(AuditCategory::Data, 1825); // 5 years
        category_retention.insert(AuditCategory::Network, 90); // 3 months
        category_retention.insert(AuditCategory::Application, 365); // 1 year

        Self {
            default_retention_days: 365,
            category_retention,
            auto_cleanup_enabled: true,
            cleanup_frequency_hours: 24,
            archive_before_deletion: true,
        }
    }
}

impl Default for ForensicConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_analysis_enabled: true,
            analysis_frequency_hours: 6,
            suspicious_pattern_detection: true,
            anomaly_threshold: 0.8,
        }
    }
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            automated_reports_enabled: true,
            report_frequency_days: 7,
            report_recipients: vec!["security@example.com".to_string()],
            include_sensitive_data: false,
            report_formats: vec![ReportFormat::PDF, ReportFormat::HTML],
        }
    }
}

impl Default for ChainOfCustodyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            digital_signatures_required: true,
            hash_algorithm: HashAlgorithm::SHA256,
            blockchain_storage_enabled: false,
            legal_adhesion_requirements: false,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            batch_size: 1000,
            max_concurrent_operations: 10,
            cache_size: 10000,
            compression_enabled: true,
        }
    }
}

impl Default for AuditStats {
    fn default() -> Self {
        Self {
            total_events: 0,
            events_by_category: HashMap::new(),
            events_by_severity: HashMap::new(),
            storage_usage_mb: 0.0,
            forensic_findings: 0,
            generated_reports: 0,
            last_cleanup: Utc::now(),
            last_analysis: Utc::now(),
            last_update: Utc::now(),
        }
    }
}
