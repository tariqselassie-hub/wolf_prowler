//! Infrastructure Security Module
//!
//! Infrastructure as Code security with wolf pack infrastructure patterns.
//! Wolves build and maintain their dens with secure, coordinated construction.

pub mod auto_remediation;
pub mod config_compliance;
pub mod drift_detection;
pub mod iac_templates;
pub mod territory_mapping;
pub mod wolf_pack_infra;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

pub use auto_remediation::AutoRemediationManager;
pub use config_compliance::ConfigComplianceManager;
pub use drift_detection::DriftDetectionManager;
/// Re-export main components
pub use iac_templates::IaCTemplateManager;
pub use territory_mapping::TerritoryMappingManager;
pub use wolf_pack_infra::WolfPackInfrastructureManager;

/// Main infrastructure security manager
pub struct InfrastructureSecurityManager {
    /// IaC template manager
    iac_templates: IaCTemplateManager,
    /// Configuration compliance manager
    config_compliance: ConfigComplianceManager,
    /// Drift detection manager
    drift_detection: DriftDetectionManager,
    /// Auto-remediation manager
    auto_remediation: AutoRemediationManager,
    /// Territory mapping manager
    territory_mapping: TerritoryMappingManager,
    /// Wolf pack infrastructure manager
    wolf_pack_infra: WolfPackInfrastructureManager,
    /// Configuration
    config: InfrastructureSecurityConfig,
    /// Statistics
    statistics: InfrastructureSecurityStats,
}

/// Infrastructure security configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InfrastructureSecurityConfig {
    /// IaC template settings
    pub iac_template_settings: IaCTemplateSettings,
    /// Configuration compliance settings
    pub config_compliance_settings: ConfigComplianceSettings,
    /// Drift detection settings
    pub drift_detection_settings: DriftDetectionSettings,
    /// Auto-remediation settings
    pub auto_remediation_settings: AutoRemediationSettings,
    /// Territory mapping settings
    pub territory_mapping_settings: TerritoryMappingSettings,
    /// Wolf pack infrastructure settings
    pub wolf_pack_infra_settings: WolfPackInfraSettings,
}

/// IaC template settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IaCTemplateSettings {
    /// Template validation enabled
    pub template_validation_enabled: bool,
    /// Security scanning enabled
    pub security_scanning_enabled: bool,
    /// Custom templates enabled
    pub custom_templates_enabled: bool,
    /// Template versioning enabled
    pub template_versioning_enabled: bool,
    /// Template approval workflow
    pub template_approval_workflow: bool,
}

/// Configuration compliance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigComplianceSettings {
    /// Continuous compliance checking
    pub continuous_compliance_checking: bool,
    /// Compliance frameworks
    pub compliance_frameworks: Vec<ComplianceFramework>,
    /// Automated remediation
    pub automated_remediation: bool,
    /// Compliance reporting
    pub compliance_reporting: bool,
    /// Real-time monitoring
    pub real_time_monitoring: bool,
}

/// Drift detection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDetectionSettings {
    /// Automated drift detection
    pub automated_drift_detection: bool,
    /// Detection frequency in hours
    pub detection_frequency_hours: u32,
    /// Critical drift alerts
    pub critical_drift_alerts: bool,
    /// Drift prevention
    pub drift_prevention: bool,
    /// Historical tracking
    pub historical_tracking: bool,
}

/// Auto-remediation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRemediationSettings {
    /// Auto-remediation enabled
    pub auto_remediation_enabled: bool,
    /// Remediation policies
    pub remediation_policies: Vec<RemediationPolicy>,
    /// Approval required for critical changes
    pub approval_required_for_critical: bool,
    /// Rollback capability
    pub rollback_capability: bool,
    /// Remediation logging
    pub remediation_logging: bool,
}

/// Territory mapping settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerritoryMappingSettings {
    /// Automatic territory discovery
    pub automatic_territory_discovery: bool,
    /// Territory classification
    pub territory_classification: bool,
    /// Cross-territory policies
    pub cross_territory_policies: bool,
    /// Territory health monitoring
    pub territory_health_monitoring: bool,
    /// Territory optimization
    pub territory_optimization: bool,
}

/// Wolf pack infrastructure settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfPackInfraSettings {
    /// Pack coordination enabled
    pub pack_coordination_enabled: bool,
    /// Infrastructure patterns
    pub infrastructure_patterns: Vec<WolfPackPattern>,
    /// Den construction guidelines
    pub den_construction_guidelines: bool,
    /// Territory patrol routes
    pub territory_patrol_routes: bool,
    /// Pack resource sharing
    pub pack_resource_sharing: bool,
}

/// Infrastructure security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureSecurityStats {
    /// Total infrastructure resources
    pub total_resources: u64,
    /// IaC templates validated
    pub iac_templates_validated: u64,
    /// Compliance checks performed
    pub compliance_checks_performed: u64,
    /// Drift incidents detected
    pub drift_incidents_detected: u64,
    /// Auto-remediations performed
    pub auto_remediations_performed: u64,
    /// Territories mapped
    pub territories_mapped: u64,
    /// Security violations found
    pub security_violations_found: u64,
    /// Critical violations
    pub critical_violations: u64,
    /// Last check timestamp
    pub last_check: DateTime<Utc>,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Infrastructure resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureResource {
    /// Resource ID
    pub id: Uuid,
    /// Resource name
    pub name: String,
    /// Resource type
    pub resource_type: InfrastructureResourceType,
    /// IaC template
    pub iac_template: Option<IaCTemplate>,
    /// Resource configuration
    pub configuration: InfrastructureConfiguration,
    /// Compliance status
    pub compliance_status: InfrastructureComplianceStatus,
    /// Drift status
    pub drift_status: DriftStatus,
    /// Security posture
    pub security_posture: InfrastructureSecurityPosture,
    /// Territory assignment
    pub territory_assignment: Option<TerritoryAssignment>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub last_updated: DateTime<Utc>,
}

/// Infrastructure resource types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InfrastructureResourceType {
    VirtualMachine,
    Network,
    Storage,
    Database,
    LoadBalancer,
    Firewall,
    VPN,
    DNS,
    Container,
    KubernetesCluster,
    ServerlessFunction,
    Custom(String),
}

/// IaC template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IaCTemplate {
    /// Template ID
    pub id: Uuid,
    /// Template name
    pub name: String,
    /// Template type
    pub template_type: IaCTemplateType,
    /// Template version
    pub version: String,
    /// Template content
    pub content: String,
    /// Template parameters
    pub parameters: HashMap<String, TemplateParameter>,
    /// Security controls
    pub security_controls: Vec<SecurityControl>,
    /// Validation status
    pub validation_status: ValidationStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// IaC template types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IaCTemplateType {
    Terraform,
    CloudFormation,
    ARM,
    Bicep,
    Pulumi,
    Ansible,
    Kubernetes,
    DockerCompose,
    Custom(String),
}

/// Template parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateParameter {
    /// Parameter name
    pub name: String,
    /// Parameter type
    pub parameter_type: ParameterType,
    /// Default value
    pub default_value: Option<serde_json::Value>,
    /// Required
    pub required: bool,
    /// Description
    pub description: String,
    /// Security constraints
    pub security_constraints: Vec<SecurityConstraint>,
}

/// Parameter types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterType {
    String,
    Number,
    Boolean,
    Array,
    Object,
    SecureString,
    Custom(String),
}

/// Security constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConstraint {
    /// Constraint type
    pub constraint_type: ConstraintType,
    /// Constraint value
    pub constraint_value: serde_json::Value,
    /// Description
    pub description: String,
}

/// Constraint types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintType {
    MinLength,
    MaxLength,
    Pattern,
    AllowedValues,
    Encrypted,
    Custom(String),
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
    /// Control implementation
    pub implementation: String,
    /// Control status
    pub status: SecurityControlStatus,
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
    Implemented,
    PartiallyImplemented,
    NotImplemented,
    NotApplicable,
}

/// Validation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    Valid,
    Invalid,
    Warning,
    Pending,
}

/// Infrastructure configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureConfiguration {
    /// Configuration version
    pub version: String,
    /// Configuration parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Security settings
    pub security_settings: SecuritySettings,
    /// Network settings
    pub network_settings: NetworkSettings,
    /// Storage settings
    pub storage_settings: StorageSettings,
}

/// Security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Encryption enabled
    pub encryption_enabled: bool,
    /// Access control enabled
    pub access_control_enabled: bool,
    /// Monitoring enabled
    pub monitoring_enabled: bool,
    /// Backup enabled
    pub backup_enabled: bool,
    /// Security groups
    pub security_groups: Vec<SecurityGroup>,
}

/// Security group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroup {
    /// Group ID
    pub id: String,
    /// Group name
    pub name: String,
    /// Inbound rules
    pub inbound_rules: Vec<SecurityRule>,
    /// Outbound rules
    pub outbound_rules: Vec<SecurityRule>,
}

/// Security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    /// Rule ID
    pub id: String,
    /// Protocol
    pub protocol: String,
    /// Port range
    pub port_range: String,
    /// Source/destination
    pub source_destination: String,
    /// Action
    pub action: SecurityRuleAction,
}

/// Security rule actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityRuleAction {
    Allow,
    Deny,
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// VPC configuration
    pub vpc_configuration: VPCConfiguration,
    /// Subnet configuration
    pub subnet_configuration: SubnetConfiguration,
    /// Route tables
    pub route_tables: Vec<RouteTable>,
}

/// VPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VPCConfiguration {
    /// VPC ID
    pub id: String,
    /// CIDR block
    pub cidr_block: String,
    /// DNS support
    pub dns_support: bool,
    /// DNS hostnames
    pub dns_hostnames: bool,
}

/// Subnet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetConfiguration {
    /// Subnet ID
    pub id: String,
    /// CIDR block
    pub cidr_block: String,
    /// Availability zone
    pub availability_zone: String,
    /// Public subnet
    pub public: bool,
    /// Route table association
    pub route_table_association: Option<String>,
}

/// Route table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTable {
    /// Table ID
    pub id: String,
    /// Routes
    pub routes: Vec<Route>,
}

/// Route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    /// Destination CIDR
    pub destination_cidr: String,
    /// Target
    pub target: String,
    /// Route type
    pub route_type: RouteType,
}

/// Route types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RouteType {
    InternetGateway,
    NATGateway,
    VPCPeering,
    VPNConnection,
    Custom(String),
}

/// Storage settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSettings {
    /// Storage type
    pub storage_type: StorageType,
    /// Encryption settings
    pub encryption_settings: EncryptionSettings,
    /// Backup settings
    pub backup_settings: BackupSettings,
    /// Access settings
    pub access_settings: AccessSettings,
}

/// Storage types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    Standard,
    Premium,
    SSD,
    HDD,
    Archive,
    Custom(String),
}

/// Encryption settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionSettings {
    /// Encryption enabled
    pub enabled: bool,
    /// Encryption algorithm
    pub algorithm: String,
    /// Key management
    pub key_management: KeyManagement,
}

/// Key management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyManagement {
    AWSKMS,
    AzureKeyVault,
    GoogleKMS,
    Custom(String),
}

/// Backup settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSettings {
    /// Backup enabled
    pub enabled: bool,
    /// Backup frequency
    pub frequency: BackupFrequency,
    /// Retention period in days
    pub retention_days: u32,
}

/// Backup frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupFrequency {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Custom(String),
}

/// Access settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessSettings {
    /// Access control list
    pub access_control_list: Vec<AccessControlEntry>,
    /// Role-based access
    pub role_based_access: bool,
    /// Multi-factor authentication
    pub multi_factor_authentication: bool,
}

/// Access control entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlEntry {
    /// Principal
    pub principal: String,
    /// Effect
    pub effect: AccessEffect,
    /// Actions
    pub actions: Vec<String>,
    /// Resources
    pub resources: Vec<String>,
}

/// Access effects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessEffect {
    Allow,
    Deny,
}

/// Infrastructure compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureComplianceStatus {
    /// Overall compliance score
    pub overall_score: f64,
    /// Framework compliance
    pub framework_compliance: HashMap<String, FrameworkCompliance>,
    /// Compliance violations
    pub violations: Vec<InfrastructureComplianceViolation>,
    /// Last compliance check
    pub last_compliance_check: DateTime<Utc>,
}

/// Framework compliance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkCompliance {
    /// Framework name
    pub framework: String,
    /// Compliance score
    pub score: f64,
    /// Status
    pub status: ComplianceStatusLevel,
    /// Requirements met
    pub requirements_met: u32,
    /// Total requirements
    pub total_requirements: u32,
}

/// Compliance status levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComplianceStatusLevel {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotApplicable,
}

/// Infrastructure compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureComplianceViolation {
    /// Violation ID
    pub id: Uuid,
    /// Framework
    pub framework: String,
    /// Requirement
    pub requirement: String,
    /// Severity
    pub severity: ViolationSeverity,
    /// Description
    pub description: String,
    /// Resource affected
    pub resource_affected: String,
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

/// Drift status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftStatus {
    /// Drift detected
    pub drift_detected: bool,
    /// Drift severity
    pub drift_severity: DriftSeverity,
    /// Drift details
    pub drift_details: Vec<DriftDetail>,
    /// Last drift check
    pub last_drift_check: DateTime<Utc>,
}

/// Drift severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftSeverity {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Drift detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDetail {
    /// Property name
    pub property_name: String,
    /// Expected value
    pub expected_value: serde_json::Value,
    /// Actual value
    pub actual_value: serde_json::Value,
    /// Drift type
    pub drift_type: DriftType,
}

/// Drift types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriftType {
    Added,
    Removed,
    Modified,
    TypeChange,
    Custom(String),
}

/// Infrastructure security posture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureSecurityPosture {
    /// Overall security score
    pub overall_score: f64,
    /// Security level
    pub security_level: InfrastructureSecurityLevel,
    /// Security findings
    pub security_findings: Vec<InfrastructureSecurityFinding>,
    /// Risk assessment
    pub risk_assessment: RiskAssessment,
    /// Last assessment
    pub last_assessment: DateTime<Utc>,
}

/// Infrastructure security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum InfrastructureSecurityLevel {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Secure = 4,
}

/// Infrastructure security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureSecurityFinding {
    /// Finding ID
    pub id: Uuid,
    /// Finding type
    pub finding_type: InfrastructureFindingType,
    /// Severity
    pub severity: FindingSeverity,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Resource affected
    pub resource_affected: String,
    /// Recommendation
    pub recommendation: String,
    /// Detected timestamp
    pub detected_at: DateTime<Utc>,
}

/// Infrastructure finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InfrastructureFindingType {
    Misconfiguration,
    Vulnerability,
    ComplianceViolation,
    SecurityGap,
    BestPracticeViolation,
    Custom(String),
}

/// Finding severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Overall risk score
    pub overall_risk_score: f64,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Risk factors
    pub risk_factors: Vec<RiskFactor>,
    /// Mitigation recommendations
    pub mitigation_recommendations: Vec<String>,
}

/// Risk levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor name
    pub name: String,
    /// Factor weight
    pub weight: f64,
    /// Factor score
    pub score: f64,
    /// Factor description
    pub description: String,
}

/// Territory assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerritoryAssignment {
    /// Territory ID
    pub territory_id: Uuid,
    /// Territory name
    pub name: String,
    /// Territory type
    pub territory_type: InfrastructureTerritoryType,
    /// Security level
    pub security_level: TerritorySecurityLevel,
    /// Wolf pack assignment
    pub wolf_pack_assignment: Option<InfrastructureWolfPackAssignment>,
    /// Assigned timestamp
    pub assigned_at: DateTime<Utc>,
}

/// Infrastructure territory types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InfrastructureTerritoryType {
    AlphaTerritory,    // Most critical infrastructure
    BetaTerritory,     // High-priority infrastructure
    GammaTerritory,    // Standard infrastructure
    DeltaTerritory,    // Development infrastructure
    OmegaTerritory,    // Testing infrastructure
    ScoutTerritory,    // Edge infrastructure
    HunterTerritory,   // Security infrastructure
    GuardianTerritory, // Monitoring infrastructure
}

/// Territory security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TerritorySecurityLevel {
    Maximum = 0,
    High = 1,
    Medium = 2,
    Standard = 3,
    Basic = 4,
}

/// Infrastructure wolf pack assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureWolfPackAssignment {
    /// Pack ID
    pub pack_id: Uuid,
    /// Pack name
    pub pack_name: String,
    /// Pack role
    pub pack_role: InfrastructurePackRole,
    /// Wolves assigned
    pub wolves_assigned: u32,
    /// Patrol schedule
    pub patrol_schedule: InfrastructurePatrolSchedule,
}

/// Infrastructure pack roles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InfrastructurePackRole {
    AlphaArchitect,   // Lead infrastructure design
    BetaBuilder,      // High-priority construction
    GammaConstructor, // Standard construction
    DeltaDeveloper,   // Development infrastructure
    OmegaTester,      // Testing infrastructure
    ScoutExplorer,    // Edge infrastructure
    HunterProtector,  // Security infrastructure
    GuardianMonitor,  // Monitoring infrastructure
}

/// Infrastructure patrol schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructurePatrolSchedule {
    /// Frequency
    pub frequency: InfrastructurePatrolFrequency,
    /// Next patrol
    pub next_patrol: DateTime<Utc>,
    /// Last patrol
    pub last_patrol: Option<DateTime<Utc>>,
    /// Patrol duration in minutes
    pub patrol_duration_minutes: u32,
    /// Patrol routes
    pub patrol_routes: Vec<String>,
}

/// Infrastructure patrol frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InfrastructurePatrolFrequency {
    Continuous,
    Hourly,
    Every2Hours,
    Every4Hours,
    Every6Hours,
    Daily,
    Weekly,
    Monthly,
}

/// Compliance frameworks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFramework {
    NIST,
    ISO27001,
    SOC2,
    PciDss,
    HIPAA,
    GDPR,
    CIS,
    Custom(String),
}

/// Remediation policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationPolicy {
    Automatic,
    ManualApproval,
    Scheduled,
    Emergency,
    Custom(String),
}

/// Wolf pack patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WolfPackPattern {
    DenConstruction,    // Secure infrastructure patterns
    TerritoryExpansion, // Scalable infrastructure
    PackCoordination,   // Coordinated infrastructure
    HuntingGrounds,     // Edge infrastructure
    PatrolRoutes,       // Monitoring infrastructure
    Custom(String),
}

impl InfrastructureSecurityManager {
    /// Create new infrastructure security manager
    pub fn new(config: InfrastructureSecurityConfig) -> Result<Self> {
        info!("🏗️ Initializing Infrastructure Security Manager");

        let manager = Self {
            iac_templates: IaCTemplateManager::new(config.clone())?,
            config_compliance: ConfigComplianceManager::new(config.clone())?,
            drift_detection: DriftDetectionManager::new(config.clone())?,
            auto_remediation: AutoRemediationManager::new(config.clone())?,
            territory_mapping: TerritoryMappingManager::new(config.clone())?,
            wolf_pack_infra: WolfPackInfrastructureManager::new(config.clone())?,
            config,
            statistics: InfrastructureSecurityStats::default(),
        };

        info!("✅ Infrastructure Security Manager initialized successfully");
        Ok(manager)
    }

    /// Validate IaC template
    pub async fn validate_iac_template(
        &mut self,
        template: IaCTemplate,
    ) -> Result<TemplateValidationResult> {
        info!("🔍 Validating IaC template: {}", template.name);

        let validation_result = self.iac_templates.validate_template(&template).await?;

        // Update statistics
        self.statistics.iac_templates_validated += 1;

        info!(
            "✅ IaC template validation completed: {:?}",
            validation_result.status
        );
        Ok(validation_result)
    }

    /// Check infrastructure compliance
    pub async fn check_compliance(
        &mut self,
        resources: Vec<InfrastructureResource>,
    ) -> Result<ComplianceCheckResult> {
        info!(
            "📋 Checking infrastructure compliance for {} resources",
            resources.len()
        );

        let compliance_result = self.config_compliance.check_compliance(&resources).await?;

        // Update statistics
        self.statistics.compliance_checks_performed += 1;
        self.statistics.security_violations_found += compliance_result.violations.len() as u64;
        self.statistics.critical_violations += compliance_result
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Critical)
            .count() as u64;

        info!(
            "✅ Compliance check completed: {} violations",
            compliance_result.violations.len()
        );
        Ok(compliance_result)
    }

    /// Detect configuration drift
    pub async fn detect_drift(
        &mut self,
        resources: Vec<InfrastructureResource>,
    ) -> Result<DriftDetectionResult> {
        info!(
            "🔍 Detecting configuration drift for {} resources",
            resources.len()
        );

        let drift_result = self.drift_detection.detect_drift(&resources).await?;

        // Update statistics
        if drift_result.drift_detected {
            self.statistics.drift_incidents_detected += 1;
        }

        info!(
            "✅ Drift detection completed: drift={}",
            drift_result.drift_detected
        );
        Ok(drift_result)
    }

    /// Perform auto-remediation
    pub async fn perform_auto_remediation(
        &mut self,
        violations: Vec<InfrastructureComplianceViolation>,
    ) -> Result<RemediationResult> {
        info!(
            "🔧 Performing auto-remediation for {} violations",
            violations.len()
        );

        let remediation_result = self
            .auto_remediation
            .remediate_violations(violations)
            .await?;

        // Update statistics
        self.statistics.auto_remediations_performed += remediation_result.remediations_performed;

        info!(
            "✅ Auto-remediation completed: {} remediations",
            remediation_result.remediations_performed
        );
        Ok(remediation_result)
    }

    /// Map infrastructure territories
    pub async fn map_territories(
        &mut self,
        resources: Vec<InfrastructureResource>,
    ) -> Result<TerritoryMappingResult> {
        info!(
            "🗺️ Mapping infrastructure territories for {} resources",
            resources.len()
        );

        let mapping_result = self.territory_mapping.map_territories(&resources).await?;

        // Update statistics
        self.statistics.territories_mapped += mapping_result.territories_mapped;

        info!(
            "✅ Territory mapping completed: {} territories",
            mapping_result.territories_mapped
        );
        Ok(mapping_result)
    }

    /// Deploy wolf pack infrastructure
    pub async fn deploy_wolf_pack_infra(
        &mut self,
        pattern: WolfPackPattern,
        resources: Vec<InfrastructureResource>,
    ) -> Result<WolfPackDeploymentResult> {
        info!(
            "🐺 Deploying wolf pack infrastructure pattern: {:?}",
            pattern
        );

        let deployment_result = self
            .wolf_pack_infra
            .deploy_pattern(&pattern, &resources)
            .await?;

        info!(
            "✅ Wolf pack infrastructure deployed: {} resources",
            deployment_result.resources_deployed
        );
        Ok(deployment_result)
    }

    /// Get infrastructure security statistics
    pub fn get_statistics(&self) -> &InfrastructureSecurityStats {
        &self.statistics
    }

    /// Generate infrastructure security report
    pub async fn generate_report(
        &self,
        report_type: InfrastructureReportType,
        time_range: TimeRange,
    ) -> Result<InfrastructureSecurityReport> {
        info!(
            "📊 Generating infrastructure security report: {:?} for {:?}",
            report_type, time_range
        );

        let report = InfrastructureSecurityReport {
            id: Uuid::new_v4(),
            report_type,
            time_range,
            generated_at: Utc::now(),
            total_resources: self.statistics.total_resources,
            iac_templates_validated: self.statistics.iac_templates_validated,
            compliance_checks_performed: self.statistics.compliance_checks_performed,
            drift_incidents_detected: self.statistics.drift_incidents_detected,
            auto_remediations_performed: self.statistics.auto_remediations_performed,
            territories_mapped: self.statistics.territories_mapped,
            security_violations_found: self.statistics.security_violations_found,
            critical_violations: self.statistics.critical_violations,
            key_metrics: HashMap::new(), // Would be populated with actual metrics
            recommendations: Vec::new(), // Would be populated with actual recommendations
        };

        info!("✅ Infrastructure security report generated: {}", report.id);
        Ok(report)
    }
}

/// Template validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateValidationResult {
    /// Template ID
    pub template_id: Uuid,
    /// Validation status
    pub status: ValidationStatus,
    /// Validation errors
    pub validation_errors: Vec<ValidationError>,
    /// Security findings
    pub security_findings: Vec<TemplateSecurityFinding>,
    /// Validation timestamp
    pub validation_timestamp: DateTime<Utc>,
}

/// Validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Error ID
    pub id: Uuid,
    /// Error type
    pub error_type: ValidationErrorType,
    /// Error message
    pub message: String,
    /// Line number
    pub line_number: Option<u32>,
    /// Column number
    pub column_number: Option<u32>,
}

/// Validation error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationErrorType {
    SyntaxError,
    SemanticError,
    SecurityError,
    ComplianceError,
    Custom(String),
}

/// Template security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSecurityFinding {
    /// Finding ID
    pub id: Uuid,
    /// Finding type
    pub finding_type: TemplateFindingType,
    /// Severity
    pub severity: FindingSeverity,
    /// Description
    pub description: String,
    /// Recommendation
    pub recommendation: String,
}

/// Template finding types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemplateFindingType {
    HardcodedSecret,
    InsecureConfiguration,
    MissingEncryption,
    OpenPort,
    WeakPassword,
    Custom(String),
}

/// Compliance check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheckResult {
    /// Check ID
    pub check_id: Uuid,
    /// Overall compliance score
    pub overall_score: f64,
    /// Framework compliance
    pub framework_compliance: HashMap<String, FrameworkCompliance>,
    /// Violations
    pub violations: Vec<InfrastructureComplianceViolation>,
    /// Check timestamp
    pub check_timestamp: DateTime<Utc>,
}

/// Drift detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDetectionResult {
    /// Detection ID
    pub detection_id: Uuid,
    /// Drift detected
    pub drift_detected: bool,
    /// Drift severity
    pub drift_severity: DriftSeverity,
    /// Drift details
    pub drift_details: Vec<DriftDetail>,
    /// Detection timestamp
    pub detection_timestamp: DateTime<Utc>,
}

/// Remediation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    /// Remediation ID
    pub remediation_id: Uuid,
    /// Remediations performed
    pub remediations_performed: u64,
    /// Successful remediations
    pub successful_remediations: u64,
    /// Failed remediations
    pub failed_remediations: u64,
    /// Remediation details
    pub remediation_details: Vec<RemediationDetail>,
    /// Remediation timestamp
    pub remediation_timestamp: DateTime<Utc>,
}

impl Default for RemediationResult {
    fn default() -> Self {
        Self {
            remediation_id: Uuid::new_v4(),
            remediations_performed: 0,
            successful_remediations: 0,
            failed_remediations: 0,
            remediation_details: Vec::new(),
            remediation_timestamp: Utc::now(),
        }
    }
}

/// Remediation detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationDetail {
    /// Violation ID
    pub violation_id: Uuid,
    /// Remediation action
    pub remediation_action: String,
    /// Remediation status
    pub status: RemediationStatus,
    /// Remediation result
    pub result: RemediationResultType,
}

/// Remediation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Remediation result types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationResultType {
    Success,
    Failed,
    Partial,
    NotApplicable,
}

/// Territory mapping result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerritoryMappingResult {
    /// Mapping ID
    pub mapping_id: Uuid,
    /// Territories mapped
    pub territories_mapped: u64,
    /// Territory assignments
    pub territory_assignments: Vec<TerritoryAssignment>,
    /// Mapping timestamp
    pub mapping_timestamp: DateTime<Utc>,
}

/// Wolf pack deployment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfPackDeploymentResult {
    /// Deployment ID
    pub deployment_id: Uuid,
    /// Pattern deployed
    pub pattern: WolfPackPattern,
    /// Resources deployed
    pub resources_deployed: u64,
    /// Deployment status
    pub status: DeploymentStatus,
    /// Deployment details
    pub deployment_details: Vec<DeploymentDetail>,
    /// Deployment timestamp
    pub deployment_timestamp: DateTime<Utc>,
}

/// Deployment status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeploymentStatus {
    InProgress,
    Completed,
    Failed,
    Partial,
    Cancelled,
}

/// Deployment detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentDetail {
    /// Resource ID
    pub resource_id: Uuid,
    /// Resource name
    pub resource_name: String,
    /// Deployment status
    pub status: DeploymentStatus,
    /// Deployment message
    pub message: String,
}

/// Infrastructure report types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InfrastructureReportType {
    SecurityPosture,
    Compliance,
    DriftAnalysis,
    RemediationSummary,
    TerritoryStatus,
    WolfPackInfrastructure,
    Custom(String),
}

/// Infrastructure security report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureSecurityReport {
    /// Report ID
    pub id: Uuid,
    /// Report type
    pub report_type: InfrastructureReportType,
    /// Time range
    pub time_range: TimeRange,
    /// Generated at
    pub generated_at: DateTime<Utc>,
    /// Total resources
    pub total_resources: u64,
    /// IaC templates validated
    pub iac_templates_validated: u64,
    /// Compliance checks performed
    pub compliance_checks_performed: u64,
    /// Drift incidents detected
    pub drift_incidents_detected: u64,
    /// Auto-remediations performed
    pub auto_remediations_performed: u64,
    /// Territories mapped
    pub territories_mapped: u64,
    /// Security violations found
    pub security_violations_found: u64,
    /// Critical violations
    pub critical_violations: u64,
    /// Key metrics
    pub key_metrics: HashMap<String, serde_json::Value>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Time range for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl Default for IaCTemplateSettings {
    fn default() -> Self {
        Self {
            template_validation_enabled: true,
            security_scanning_enabled: true,
            custom_templates_enabled: true,
            template_versioning_enabled: true,
            template_approval_workflow: true,
        }
    }
}

impl Default for ConfigComplianceSettings {
    fn default() -> Self {
        Self {
            continuous_compliance_checking: true,
            compliance_frameworks: vec![ComplianceFramework::NIST, ComplianceFramework::CIS],
            automated_remediation: false,
            compliance_reporting: true,
            real_time_monitoring: true,
        }
    }
}

impl Default for DriftDetectionSettings {
    fn default() -> Self {
        Self {
            automated_drift_detection: true,
            detection_frequency_hours: 24,
            critical_drift_alerts: true,
            drift_prevention: false,
            historical_tracking: true,
        }
    }
}

impl Default for AutoRemediationSettings {
    fn default() -> Self {
        Self {
            auto_remediation_enabled: false,
            remediation_policies: vec![RemediationPolicy::ManualApproval],
            approval_required_for_critical: true,
            rollback_capability: true,
            remediation_logging: true,
        }
    }
}

impl Default for TerritoryMappingSettings {
    fn default() -> Self {
        Self {
            automatic_territory_discovery: true,
            territory_classification: true,
            cross_territory_policies: true,
            territory_health_monitoring: true,
            territory_optimization: false,
        }
    }
}

impl Default for WolfPackInfraSettings {
    fn default() -> Self {
        Self {
            pack_coordination_enabled: true,
            infrastructure_patterns: vec![
                WolfPackPattern::DenConstruction,
                WolfPackPattern::TerritoryExpansion,
            ],
            den_construction_guidelines: true,
            territory_patrol_routes: true,
            pack_resource_sharing: true,
        }
    }
}

impl Default for InfrastructureSecurityStats {
    fn default() -> Self {
        Self {
            total_resources: 0,
            iac_templates_validated: 0,
            compliance_checks_performed: 0,
            drift_incidents_detected: 0,
            auto_remediations_performed: 0,
            territories_mapped: 0,
            security_violations_found: 0,
            critical_violations: 0,
            last_check: Utc::now(),
            last_update: Utc::now(),
        }
    }
}

impl Default for TemplateValidationResult {
    fn default() -> Self {
        Self {
            template_id: Uuid::new_v4(),
            status: ValidationStatus::Pending,
            validation_errors: Vec::new(),
            security_findings: Vec::new(),
            validation_timestamp: Utc::now(),
        }
    }
}

impl Default for ComplianceCheckResult {
    fn default() -> Self {
        Self {
            check_id: Uuid::new_v4(),
            overall_score: 0.0,
            framework_compliance: HashMap::new(),
            violations: Vec::new(),
            check_timestamp: Utc::now(),
        }
    }
}

impl Default for DriftDetectionResult {
    fn default() -> Self {
        Self {
            detection_id: Uuid::new_v4(),
            drift_detected: false,
            drift_severity: DriftSeverity::Low,
            drift_details: Vec::new(),
            detection_timestamp: Utc::now(),
        }
    }
}

impl Default for TerritoryMappingResult {
    fn default() -> Self {
        Self {
            mapping_id: Uuid::new_v4(),
            territories_mapped: 0,
            territory_assignments: Vec::new(),
            mapping_timestamp: Utc::now(),
        }
    }
}
