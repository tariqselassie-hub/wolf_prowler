//! Cloud Security Module
//!
//! Multi-cloud security management with wolf pack territory expansion principles.
//! Wolves expand their territories across different hunting grounds while maintaining security.

pub mod config_management;
pub mod data_protection;
pub mod identity_federation;
pub mod multi_cloud;
pub mod network_security;
pub mod territory_expansion;
pub mod workload_protection;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub use config_management::CloudConfigManager;
pub use data_protection::CloudDataProtectionManager;
pub use identity_federation::CloudIdentityFederationManager;
/// Re-export main components
pub use multi_cloud::MultiCloudSecurityManager;
pub use network_security::CloudNetworkSecurityManager;
pub use territory_expansion::TerritoryExpansionManager;
pub use workload_protection::WorkloadProtectionManager;

/// Main cloud security manager
pub struct CloudSecurityManager {
    /// Multi-cloud security
    multi_cloud: MultiCloudSecurityManager,
    /// Workload protection
    workload_protection: WorkloadProtectionManager,
    /// Configuration management
    config_management: CloudConfigManager,
    /// Identity federation
    identity_federation: CloudIdentityFederationManager,
    /// Network security
    network_security: CloudNetworkSecurityManager,
    /// Data protection
    data_protection: CloudDataProtectionManager,
    /// Territory expansion
    territory_expansion: TerritoryExpansionManager,
    /// Configuration
    config: CloudSecurityConfig,
    /// Statistics
    statistics: CloudSecurityStats,
}

/// Cloud security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSecurityConfig {
    /// Enabled cloud providers
    pub enabled_providers: Vec<CloudProvider>,
    /// Multi-cloud settings
    pub multi_cloud_settings: MultiCloudSettings,
    /// Workload protection settings
    pub workload_protection_settings: WorkloadProtectionSettings,
    /// Configuration management settings
    pub config_management_settings: ConfigManagementSettings,
    /// Identity federation settings
    pub identity_federation_settings: IdentityFederationSettings,
    /// Network security settings
    pub network_security_settings: NetworkSecuritySettings,
    /// Data protection settings
    pub data_protection_settings: DataProtectionSettings,
    /// Territory expansion settings
    pub territory_expansion_settings: TerritoryExpansionSettings,
}

/// Cloud providers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub enum CloudProvider {
    #[default]
    AWS,
    Azure,
    GCP,
    OracleCloud,
    IBMCloud,
    AlibabaCloud,
    PrivateCloud(String),
    Hybrid,
}

/// Multi-cloud settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiCloudSettings {
    /// Cross-cloud security policies enabled
    pub cross_cloud_policies_enabled: bool,
    /// Centralized security management
    pub centralized_management: bool,
    /// Cloud-to-cloud authentication
    pub cloud_to_cloud_auth: bool,
    /// Unified threat intelligence
    pub unified_threat_intel: bool,
    /// Consistent security posture
    pub consistent_security_posture: bool,
}

/// Workload protection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadProtectionSettings {
    /// Container security enabled
    pub container_security_enabled: bool,
    /// Serverless security enabled
    pub serverless_security_enabled: bool,
    /// VM security enabled
    pub vm_security_enabled: bool,
    /// Real-time monitoring
    pub real_time_monitoring: bool,
    /// Automated threat response
    pub auto_threat_response: bool,
}

/// Configuration management settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigManagementSettings {
    /// Configuration scanning enabled
    pub config_scanning_enabled: bool,
    /// Compliance checking enabled
    pub compliance_checking_enabled: bool,
    /// Drift detection enabled
    pub drift_detection_enabled: bool,
    /// Auto-remediation enabled
    pub auto_remediation_enabled: bool,
    /// Configuration backup enabled
    pub config_backup_enabled: bool,
}

/// Identity federation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityFederationSettings {
    /// Cross-cloud identity federation enabled
    pub cross_cloud_federation_enabled: bool,
    /// Single sign-on enabled
    pub sso_enabled: bool,
    /// Multi-factor authentication required
    pub mfa_required: bool,
    /// Just-in-time access enabled
    pub jit_access_enabled: bool,
    /// Privileged access management
    pub privileged_access_management: bool,
}

/// Network security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecuritySettings {
    /// Network segmentation enabled
    pub network_segmentation_enabled: bool,
    /// Micro-segmentation enabled
    pub microsegmentation_enabled: bool,
    /// Network monitoring enabled
    pub network_monitoring_enabled: bool,
    /// DDoS protection enabled
    pub ddos_protection_enabled: bool,
    /// Firewall management enabled
    pub firewall_management_enabled: bool,
}

/// Data protection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProtectionSettings {
    /// Encryption at rest enabled
    pub encryption_at_rest_enabled: bool,
    /// Encryption in transit enabled
    pub encryption_in_transit_enabled: bool,
    /// Data classification enabled
    pub data_classification_enabled: bool,
    /// Data loss prevention enabled
    pub dlp_enabled: bool,
    /// Key management enabled
    pub key_management_enabled: bool,
}

/// Territory expansion settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerritoryExpansionSettings {
    /// Automatic territory discovery enabled
    pub auto_territory_discovery_enabled: bool,
    /// Territory mapping enabled
    pub territory_mapping_enabled: bool,
    /// Cross-territory policies enabled
    pub cross_territory_policies_enabled: bool,
    /// Territory health monitoring
    pub territory_health_monitoring: bool,
    /// Wolf pack coordination enabled
    pub wolf_pack_coordination_enabled: bool,
}

/// Cloud security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSecurityStats {
    /// Total cloud resources
    pub total_cloud_resources: u64,
    /// Resources by provider
    pub resources_by_provider: HashMap<CloudProvider, u64>,
    /// Security incidents
    pub security_incidents: u64,
    /// Configuration violations
    pub config_violations: u64,
    /// Data breaches prevented
    pub data_breaches_prevented: u64,
    /// Threats detected
    pub threats_detected: u64,
    /// Compliance score
    pub compliance_score: f64,
    /// Last scan timestamp
    pub last_scan: DateTime<Utc>,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Cloud resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudResource {
    /// Resource ID
    pub id: Uuid,
    /// Resource name
    pub name: String,
    /// Resource type
    pub resource_type: CloudResourceType,
    /// Cloud provider
    pub provider: CloudProvider,
    /// Resource region
    pub region: String,
    /// Resource status
    pub status: CloudResourceStatus,
    /// Security posture
    pub security_posture: SecurityPosture,
    /// Compliance status
    pub compliance_status: ComplianceStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub last_updated: DateTime<Utc>,
    /// Resource tags
    pub tags: HashMap<String, String>,
    /// Security controls
    pub security_controls: Vec<SecurityControl>,
}

/// Cloud resource types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloudResourceType {
    VirtualMachine,
    Container,
    ServerlessFunction,
    StorageBucket,
    Database,
    Network,
    LoadBalancer,
    Firewall,
    VPN,
    DNS,
    APIGateway,
    MessageQueue,
    KubernetesCluster,
    Custom(String),
}

/// Cloud resource status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CloudResourceStatus {
    Running,
    Stopped,
    Pending,
    Terminating,
    Error,
    Unknown,
}

/// Security posture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    /// Overall security score
    pub overall_score: f64,
    /// Security level
    pub security_level: SecurityLevel,
    /// Critical findings
    pub critical_findings: u64,
    /// High findings
    pub high_findings: u64,
    /// Medium findings
    pub medium_findings: u64,
    /// Low findings
    pub low_findings: u64,
    /// Last assessment
    pub last_assessment: DateTime<Utc>,
}

/// Security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Secure = 4,
}

/// Compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    /// Overall compliance score
    pub overall_score: f64,
    /// Compliance frameworks
    pub frameworks: HashMap<String, FrameworkCompliance>,
    /// Last compliance check
    pub last_check: DateTime<Utc>,
}

/// Framework compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkCompliance {
    /// Framework name
    pub framework: String,
    /// Compliance score
    pub score: f64,
    /// Compliance status
    pub status: ComplianceStatusLevel,
    /// Violations
    pub violations: Vec<ComplianceViolation>,
}

/// Compliance status levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatusLevel {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotApplicable,
}

/// Compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    /// Violation ID
    pub id: Uuid,
    /// Violation title
    pub title: String,
    /// Violation description
    pub description: String,
    /// Severity level
    pub severity: ViolationSeverity,
    /// Control requirement
    pub control_requirement: String,
    /// Remediation steps
    pub remediation_steps: Vec<String>,
}

/// Violation severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ViolationSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Security control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityControl {
    /// Control ID
    pub id: String,
    /// Control name
    pub name: String,
    /// Control type
    pub control_type: SecurityControlType,
    /// Control status
    pub status: SecurityControlStatus,
    /// Control effectiveness
    pub effectiveness: f64,
    /// Last assessment
    pub last_assessment: DateTime<Utc>,
}

/// Security control types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityControlType {
    Preventive,
    Detective,
    Corrective,
    Compensating,
    Deterrent,
}

/// Security control status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityControlStatus {
    Active,
    Inactive,
    Failed,
    Unknown,
}

/// Cloud security incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSecurityIncident {
    /// Incident ID
    pub id: Uuid,
    /// Incident title
    pub title: String,
    /// Incident description
    pub description: String,
    /// Incident severity
    pub severity: IncidentSeverity,
    /// Incident type
    pub incident_type: CloudIncidentType,
    /// Affected resources
    pub affected_resources: Vec<Uuid>,
    /// Cloud provider
    pub provider: CloudProvider,
    /// Detection timestamp
    pub detected_at: DateTime<Utc>,
    /// Incident status
    pub status: IncidentStatus,
    /// Response actions
    pub response_actions: Vec<ResponseAction>,
    /// Investigation notes
    pub investigation_notes: Vec<String>,
}

/// Incident severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IncidentSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Cloud incident types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloudIncidentType {
    DataBreach,
    UnauthorizedAccess,
    ConfigurationError,
    Malware,
    DDoS,
    InsiderThreat,
    ServiceDisruption,
    ComplianceViolation,
    Custom(String),
}

/// Incident status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IncidentStatus {
    New,
    Investigating,
    Contained,
    Resolved,
    Closed,
    FalsePositive,
}

/// Response action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    /// Action ID
    pub id: Uuid,
    /// Action type
    pub action_type: ResponseActionType,
    /// Action description
    pub description: String,
    /// Action timestamp
    pub timestamp: DateTime<Utc>,
    /// Action result
    pub result: ActionResult,
}

/// Response action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseActionType {
    IsolateResource,
    BlockAccess,
    RevokeCredentials,
    UpdateConfiguration,
    EnableAdditionalControls,
    NotifyTeam,
    Custom(String),
}

/// Action results
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionResult {
    Success,
    Failed,
    Partial,
    NotApplicable,
}

/// Cloud territory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTerritory {
    /// Territory ID
    pub id: Uuid,
    /// Territory name
    pub name: String,
    /// Territory type
    pub territory_type: TerritoryType,
    /// Cloud provider
    pub provider: CloudProvider,
    /// Territory region
    pub region: String,
    /// Territory resources
    pub resources: Vec<Uuid>,
    /// Security policies
    pub security_policies: Vec<String>,
    /// Wolf pack assignment
    pub wolf_pack_assignment: Option<WolfPackAssignment>,
    /// Territory health
    pub territory_health: TerritoryHealth,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub last_updated: DateTime<Utc>,
}

/// Territory types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TerritoryType {
    AlphaTerritory,  // Most critical resources
    BetaTerritory,   // High importance resources
    GammaTerritory,  // Medium importance resources
    DeltaTerritory,  // Standard resources
    OmegaTerritory,  // Development/testing resources
    HuntingGrounds,  // External-facing resources
    DenTerritory,    // Internal resources
    PatrolTerritory, // Monitoring resources
}

/// Wolf pack assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfPackAssignment {
    /// Pack ID
    pub pack_id: Uuid,
    /// Pack name
    pub pack_name: String,
    /// Pack role
    pub pack_role: WolfPackRole,
    /// Assigned wolves
    pub assigned_wolves: Vec<String>,
    /// Patrol schedule
    pub patrol_schedule: PatrolSchedule,
}

/// Wolf pack roles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WolfPackRole {
    AlphaPack,    // Lead security team
    BetaPack,     // High-priority security
    GammaPack,    // Standard security
    DeltaPack,    // Monitoring team
    OmegaPack,    // Support team
    ScoutPack,    // Reconnaissance team
    HunterPack,   // Threat hunting team
    GuardianPack, // Protection team
}

/// Patrol schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatrolSchedule {
    /// Frequency
    pub frequency: PatrolFrequency,
    /// Next patrol
    pub next_patrol: DateTime<Utc>,
    /// Last patrol
    pub last_patrol: Option<DateTime<Utc>>,
    /// Patrol duration in minutes
    pub patrol_duration_minutes: u32,
}

/// Patrol frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatrolFrequency {
    Continuous,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Custom(String),
}

/// Territory health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerritoryHealth {
    /// Overall health score
    pub overall_score: f64,
    /// Security health
    pub security_health: f64,
    /// Performance health
    pub performance_health: f64,
    /// Compliance health
    pub compliance_health: f64,
    /// Last health check
    pub last_check: DateTime<Utc>,
    /// Health issues
    pub health_issues: Vec<HealthIssue>,
}

/// Health issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthIssue {
    /// Issue ID
    pub id: Uuid,
    /// Issue type
    pub issue_type: HealthIssueType,
    /// Issue severity
    pub severity: IssueSeverity,
    /// Issue description
    pub description: String,
    /// Recommended action
    pub recommended_action: String,
    /// Detected timestamp
    pub detected_at: DateTime<Utc>,
}

/// Health issue types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthIssueType {
    SecurityVulnerability,
    ConfigurationError,
    PerformanceIssue,
    ComplianceViolation,
    ResourceExhaustion,
    NetworkIssue,
    Custom(String),
}

/// Issue severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl CloudSecurityManager {
    /// Create new cloud security manager
    pub fn new(config: CloudSecurityConfig) -> Result<Self> {
        info!("☁️ Initializing Cloud Security Manager");

        let manager = Self {
            multi_cloud: MultiCloudSecurityManager::new(config.clone())?,
            workload_protection: WorkloadProtectionManager::new(config.clone())?,
            config_management: CloudConfigManager::new(config.clone())?,
            identity_federation: CloudIdentityFederationManager::new(config.clone())?,
            network_security: CloudNetworkSecurityManager::new(config.clone())?,
            data_protection: CloudDataProtectionManager::new(config.clone())?,
            territory_expansion: TerritoryExpansionManager::new(config.clone())?,
            config,
            statistics: CloudSecurityStats::default(),
        };

        info!("✅ Cloud Security Manager initialized successfully");
        Ok(manager)
    }

    /// Discover cloud resources
    pub async fn discover_resources(
        &mut self,
        providers: Vec<CloudProvider>,
    ) -> Result<Vec<CloudResource>> {
        info!(
            "🔍 Discovering cloud resources for providers: {:?}",
            providers
        );

        let mut all_resources = Vec::new();

        for provider in providers {
            let resources = self
                .multi_cloud
                .discover_resources(provider.clone())
                .await?;
            all_resources.extend(resources);

            // Update statistics
            *self
                .statistics
                .resources_by_provider
                .entry(provider)
                .or_insert(0) += all_resources.len() as u64;
        }

        self.statistics.total_cloud_resources += all_resources.len() as u64;
        self.statistics.last_scan = Utc::now();

        info!("✅ Discovered {} cloud resources", all_resources.len());
        Ok(all_resources)
    }

    /// Assess security posture
    pub async fn assess_security_posture(
        &mut self,
        resource_ids: Vec<Uuid>,
    ) -> Result<Vec<SecurityPostureAssessment>> {
        info!(
            "🛡️ Assessing security posture for {} resources",
            resource_ids.len()
        );

        let mut assessments = Vec::new();

        for resource_id in resource_ids {
            let assessment = self
                .workload_protection
                .assess_security_posture(resource_id)
                .await?;
            assessments.push(assessment);
        }

        info!(
            "✅ Security posture assessment completed for {} resources",
            assessments.len()
        );
        Ok(assessments)
    }

    /// Scan configurations for compliance
    pub async fn scan_configurations(
        &mut self,
        provider: CloudProvider,
    ) -> Result<Vec<ComplianceViolation>> {
        info!("🔍 Scanning configurations for provider: {:?}", provider);

        let violations = self.config_management.scan_configurations(provider).await?;

        // Update statistics
        self.statistics.config_violations += violations.len() as u64;

        info!(
            "✅ Configuration scan completed: {} violations found",
            violations.len()
        );
        Ok(violations)
    }

    /// Monitor cloud workloads
    pub async fn monitor_workloads(
        &mut self,
        workload_types: Vec<CloudResourceType>,
    ) -> Result<Vec<WorkloadAlert>> {
        debug!("👁️ Monitoring cloud workloads: {:?}", workload_types);

        let alerts = self
            .workload_protection
            .monitor_workloads(workload_types)
            .await?;

        // Update statistics
        self.statistics.threats_detected += alerts.len() as u64;

        debug!("✅ Workload monitoring completed: {} alerts", alerts.len());
        Ok(alerts)
    }

    /// Expand wolf pack territories
    pub async fn expand_territories(
        &mut self,
        expansion_strategy: TerritoryExpansionStrategy,
    ) -> Result<Vec<CloudTerritory>> {
        info!(
            "🌍 Expanding wolf pack territories with strategy: {:?}",
            expansion_strategy
        );

        let territories = self
            .territory_expansion
            .expand_territories(expansion_strategy)
            .await?;

        info!(
            "✅ Territory expansion completed: {} new territories",
            territories.len()
        );
        Ok(territories)
    }

    /// Handle security incident
    pub async fn handle_security_incident(
        &mut self,
        incident: CloudSecurityIncident,
    ) -> Result<IncidentResponse> {
        warn!("🚨 Handling security incident: {}", incident.id);

        let response = self.multi_cloud.handle_incident(incident.clone()).await?;

        // Update statistics
        self.statistics.security_incidents += 1;

        info!("✅ Security incident handled: {}", response.incident_id);
        Ok(response)
    }

    /// Get cloud security statistics
    pub fn get_statistics(&self) -> &CloudSecurityStats {
        &self.statistics
    }

    /// Generate cloud security report
    pub async fn generate_security_report(
        &self,
        report_type: CloudReportType,
        time_range: TimeRange,
    ) -> Result<CloudSecurityReport> {
        info!(
            "📊 Generating cloud security report: {:?} for {:?}",
            report_type, time_range
        );

        let report = CloudSecurityReport {
            id: Uuid::new_v4(),
            report_type,
            time_range,
            generated_at: Utc::now(),
            total_resources: self.statistics.total_cloud_resources,
            security_incidents: self.statistics.security_incidents,
            compliance_score: self.statistics.compliance_score,
            resources_by_provider: self.statistics.resources_by_provider.clone(),
            key_findings: Vec::new(), // Would be populated with actual findings
            recommendations: Vec::new(), // Would be populated with actual recommendations
        };

        info!("✅ Cloud security report generated: {}", report.id);
        Ok(report)
    }
}

// Duplicate definitions removed - functionality provided by definitions at lines 927+

/// Security posture assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPostureAssessment {
    /// Resource ID
    pub resource_id: Uuid,
    /// Assessment timestamp
    pub timestamp: DateTime<Utc>,
    /// Security posture
    pub security_posture: SecurityPosture,
    /// Recommendations
    pub recommendations: Vec<SecurityRecommendation>,
}

/// Security recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    /// Recommendation ID
    pub id: Uuid,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Priority
    pub priority: RecommendationPriority,
    /// Implementation effort
    pub implementation_effort: ImplementationEffort,
    /// Expected impact
    pub expected_impact: String,
}

/// Recommendation priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecommendationPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Implementation effort
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplementationEffort {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Workload alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadAlert {
    /// Alert ID
    pub id: Uuid,
    /// Alert type
    pub alert_type: WorkloadAlertType,
    /// Severity
    pub severity: AlertSeverity,
    /// Resource ID
    pub resource_id: Uuid,
    /// Alert message
    pub message: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Recommended actions
    pub recommended_actions: Vec<String>,
}

/// Workload alert types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkloadAlertType {
    SuspiciousActivity,
    ConfigurationChange,
    PerformanceIssue,
    SecurityVulnerability,
    ComplianceViolation,
    ResourceExhaustion,
    Custom(String),
}

/// Alert severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info = 0,
    Warning = 1,
    Error = 2,
    Critical = 3,
}

/// Territory expansion strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TerritoryExpansionStrategy {
    Automatic,
    Manual,
    RiskBased,
    PerformanceBased,
    ComplianceBased,
    WolfPackBased,
}

/// Incident response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentResponse {
    /// Incident ID
    pub incident_id: Uuid,
    /// Response actions taken
    pub actions_taken: Vec<ResponseAction>,
    /// Response status
    pub status: ResponseStatus,
    /// Resolution time in minutes
    pub resolution_time_minutes: Option<u64>,
    /// Lessons learned
    pub lessons_learned: Vec<String>,
}

/// Response status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseStatus {
    InProgress,
    Contained,
    Resolved,
    Escalated,
}

/// Cloud report types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloudReportType {
    SecurityPosture,
    Compliance,
    IncidentSummary,
    ResourceInventory,
    ThreatLandscape,
    Custom(String),
}

/// Time range for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Cloud security report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSecurityReport {
    /// Report ID
    pub id: Uuid,
    /// Report type
    pub report_type: CloudReportType,
    /// Time range
    pub time_range: TimeRange,
    /// Generated at
    pub generated_at: DateTime<Utc>,
    /// Total resources
    pub total_resources: u64,
    /// Security incidents
    pub security_incidents: u64,
    /// Compliance score
    pub compliance_score: f64,
    /// Resources by provider
    pub resources_by_provider: HashMap<CloudProvider, u64>,
    /// Key findings
    pub key_findings: Vec<String>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

impl Default for CloudSecurityConfig {
    fn default() -> Self {
        Self {
            enabled_providers: vec![CloudProvider::AWS, CloudProvider::Azure, CloudProvider::GCP],
            multi_cloud_settings: MultiCloudSettings::default(),
            workload_protection_settings: WorkloadProtectionSettings::default(),
            config_management_settings: ConfigManagementSettings::default(),
            identity_federation_settings: IdentityFederationSettings::default(),
            network_security_settings: NetworkSecuritySettings::default(),
            data_protection_settings: DataProtectionSettings::default(),
            territory_expansion_settings: TerritoryExpansionSettings::default(),
        }
    }
}

impl Default for MultiCloudSettings {
    fn default() -> Self {
        Self {
            cross_cloud_policies_enabled: true,
            centralized_management: true,
            cloud_to_cloud_auth: true,
            unified_threat_intel: true,
            consistent_security_posture: true,
        }
    }
}

impl Default for WorkloadProtectionSettings {
    fn default() -> Self {
        Self {
            container_security_enabled: true,
            serverless_security_enabled: true,
            vm_security_enabled: true,
            real_time_monitoring: true,
            auto_threat_response: true,
        }
    }
}

impl Default for ConfigManagementSettings {
    fn default() -> Self {
        Self {
            config_scanning_enabled: true,
            compliance_checking_enabled: true,
            drift_detection_enabled: true,
            auto_remediation_enabled: false,
            config_backup_enabled: true,
        }
    }
}

impl Default for IdentityFederationSettings {
    fn default() -> Self {
        Self {
            cross_cloud_federation_enabled: true,
            sso_enabled: true,
            mfa_required: true,
            jit_access_enabled: true,
            privileged_access_management: true,
        }
    }
}

impl Default for NetworkSecuritySettings {
    fn default() -> Self {
        Self {
            network_segmentation_enabled: true,
            microsegmentation_enabled: true,
            network_monitoring_enabled: true,
            ddos_protection_enabled: true,
            firewall_management_enabled: true,
        }
    }
}

impl Default for DataProtectionSettings {
    fn default() -> Self {
        Self {
            encryption_at_rest_enabled: true,
            encryption_in_transit_enabled: true,
            data_classification_enabled: true,
            dlp_enabled: true,
            key_management_enabled: true,
        }
    }
}

impl Default for TerritoryExpansionSettings {
    fn default() -> Self {
        Self {
            auto_territory_discovery_enabled: true,
            territory_mapping_enabled: true,
            cross_territory_policies_enabled: true,
            territory_health_monitoring: true,
            wolf_pack_coordination_enabled: true,
        }
    }
}

impl Default for CloudSecurityStats {
    fn default() -> Self {
        Self {
            total_cloud_resources: 0,
            resources_by_provider: HashMap::new(),
            security_incidents: 0,
            config_violations: 0,
            data_breaches_prevented: 0,
            threats_detected: 0,
            compliance_score: 0.0,
            last_scan: Utc::now(),
            last_update: Utc::now(),
        }
    }
}
