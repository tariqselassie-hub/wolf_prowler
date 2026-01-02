//! Container Security Module
//!
//! Container runtime protection with wolf den security principles.
//! Wolves protect their dens with layered security and vigilant monitoring.

pub mod image_scanning;
pub mod network_policies;
pub mod orchestration_security;
pub mod resource_limits;
pub mod runtime_protection;
pub mod wolf_den_containers;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

// Import wolf-themed configurations
use crate::wolf_pack::hierarchy::{PackRank, WolfDenConfig};

/// Container scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerScanResult {
    pub image_name: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_time: DateTime<Utc>,
    pub overall_risk: RiskLevel,
}

/// Vulnerability found in container scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: RiskLevel,
    pub description: String,
}

/// Risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Container security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityPolicy {
    pub name: String,
    pub allowed_images: Vec<String>,
    pub resource_limits: ResourceLimits,
    pub network_policies: Vec<String>,
    pub security_level: PackRank,
}

/// Resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_limit: String,
    pub memory_limit: String,
    pub storage_limit: String,
}

/// Re-export main components
pub use image_scanning::ContainerImageScanner;
pub use network_policies::ContainerNetworkPolicyManager;
pub use orchestration_security::OrchestrationSecurityManager;
pub use resource_limits::ContainerResourceLimitManager;
pub use runtime_protection::ContainerRuntimeProtector;
pub use wolf_den_containers::WolfDenContainerManager;

/// Main container security manager
pub struct ContainerSecurityManager {
    /// Image scanner
    image_scanner: ContainerImageScanner,
    /// Runtime protector
    runtime_protector: ContainerRuntimeProtector,
    /// Orchestration security
    orchestration_security: OrchestrationSecurityManager,
    /// Network policies
    network_policies: ContainerNetworkPolicyManager,
    /// Resource limits
    resource_limits: ContainerResourceLimitManager,
    /// Wolf den containers
    wolf_den_containers: WolfDenContainerManager,
    /// Configuration
    config: ContainerSecurityConfig,
    /// Statistics
    statistics: ContainerSecurityStats,
}

/// Container security configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerSecurityConfig {
    /// Image scanning settings
    pub image_scanning_settings: ImageScanningSettings,
    /// Runtime protection settings
    pub runtime_protection_settings: RuntimeProtectionSettings,
    /// Orchestration security settings
    pub orchestration_security_settings: OrchestrationSecuritySettings,
    /// Network policy settings
    pub network_policy_settings: NetworkPolicySettings,
    /// Resource limit settings
    pub resource_limit_settings: ResourceLimitSettings,
    /// Wolf den settings
    pub wolf_den_settings: WolfDenSettings,
}

/// Image scanning settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageScanningSettings {
    /// Automated scanning enabled
    pub automated_scanning_enabled: bool,
    /// Scan on pull enabled
    pub scan_on_pull_enabled: bool,
    /// Vulnerability databases
    pub vulnerability_databases: Vec<VulnerabilityDatabase>,
    /// Severity threshold
    pub severity_threshold: VulnerabilitySeverity,
    /// Custom rules enabled
    pub custom_rules_enabled: bool,
}

/// Runtime protection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeProtectionSettings {
    /// Runtime monitoring enabled
    pub runtime_monitoring_enabled: bool,
    /// Anomaly detection enabled
    pub anomaly_detection_enabled: bool,
    /// Process monitoring enabled
    pub process_monitoring_enabled: bool,
    /// File system monitoring enabled
    pub file_system_monitoring_enabled: bool,
    /// Network monitoring enabled
    pub network_monitoring_enabled: bool,
    /// Auto-quarantine enabled
    pub auto_quarantine_enabled: bool,
}

/// Orchestration security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OrchestrationSecuritySettings {
    /// Kubernetes security enabled
    pub kubernetes_security_enabled: bool,
    /// Docker security enabled
    pub docker_security_enabled: bool,
    /// Pod security policies enabled
    pub pod_security_policies_enabled: bool,
    /// RBAC enforcement enabled
    pub rbac_enforcement_enabled: bool,
    /// Network policies enforced
    pub network_policies_enforced: bool,
    /// Admission control enabled
    pub admission_control_enabled: bool,
}

/// Network policy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkPolicySettings {
    /// Default deny policy enabled
    pub default_deny_enabled: bool,
    /// Microsegmentation enabled
    pub microsegmentation_enabled: bool,
    /// Egress filtering enabled
    pub egress_filtering_enabled: bool,
    /// Ingress filtering enabled
    pub ingress_filtering_enabled: bool,
    /// Service mesh integration enabled
    pub service_mesh_integration_enabled: bool,
}

/// Resource limit settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceLimitSettings {
    /// CPU limits enforced
    pub cpu_limits_enforced: bool,
    /// Memory limits enforced
    pub memory_limits_enforced: bool,
    /// Storage limits enforced
    pub storage_limits_enforced: bool,
    /// Network limits enforced
    pub network_limits_enforced: bool,
    /// Resource monitoring enabled
    pub resource_monitoring_enabled: bool,
}

/// Wolf den settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WolfDenSettings {
    /// Wolf den isolation enabled
    pub wolf_den_isolation_enabled: bool,
    /// Pack coordination enabled
    pub pack_coordination_enabled: bool,
    /// Den patrol enabled
    pub den_patrol_enabled: bool,
    /// Territory marking enabled
    pub territory_marking_enabled: bool,
    /// Den hierarchy enforced
    pub den_hierarchy_enforced: bool,
}

/// Container security statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityStats {
    /// Total containers
    pub total_containers: u64,
    /// Running containers
    pub running_containers: u64,
    /// Scanned images
    pub scanned_images: u64,
    /// Vulnerabilities found
    pub vulnerabilities_found: u64,
    /// Critical vulnerabilities
    pub critical_vulnerabilities: u64,
    /// Security incidents
    pub security_incidents: u64,
    /// Containers quarantined
    pub containers_quarantined: u64,
    /// Network violations
    pub network_violations: u64,
    /// Last scan timestamp
    pub last_scan: DateTime<Utc>,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Container information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    /// Container ID
    pub id: String,
    /// Container name
    pub name: String,
    /// Image name
    pub image_name: String,
    /// Image digest
    pub image_digest: String,
    /// Container status
    pub status: ContainerStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Started timestamp
    pub started_at: Option<DateTime<Utc>>,
    /// Container labels
    pub labels: HashMap<String, String>,
    /// Container annotations
    pub annotations: HashMap<String, String>,
    /// Security posture
    pub security_posture: ContainerSecurityPosture,
    /// Wolf den assignment
    pub wolf_den_assignment: Option<WolfDenAssignment>,
}

/// Container status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerStatus {
    Created,
    Running,
    Paused,
    Restarting,
    Removing,
    Exited,
    Dead,
    Unknown,
}

/// Container security posture
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityPosture {
    /// Overall security score
    pub overall_score: f64,
    /// Security level
    pub security_level: ContainerSecurityLevel,
    /// Vulnerability count
    pub vulnerability_count: u64,
    /// Compliance status
    pub compliance_status: ContainerComplianceStatus,
    /// Runtime alerts
    pub runtime_alerts: Vec<RuntimeAlert>,
    /// Last assessment
    pub last_assessment: DateTime<Utc>,
}

impl Default for ContainerSecurityPosture {
    fn default() -> Self {
        Self {
            overall_score: 0.0,
            security_level: ContainerSecurityLevel::Low,
            vulnerability_count: 0,
            compliance_status: ContainerComplianceStatus::default(),
            runtime_alerts: Vec::new(),
            last_assessment: Utc::now(),
        }
    }
}

/// Container security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContainerSecurityLevel {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Secure = 4,
}

/// Container compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerComplianceStatus {
    /// Overall compliance score
    pub overall_score: f64,
    /// Compliance frameworks
    pub frameworks: HashMap<String, FrameworkCompliance>,
    /// Violations
    pub violations: Vec<ContainerComplianceViolation>,
}

impl Default for ContainerComplianceStatus {
    fn default() -> Self {
        Self {
            overall_score: 0.0,
            frameworks: HashMap::new(),
            violations: Vec::new(),
        }
    }
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

/// Container compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerComplianceViolation {
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
    /// Remediation
    pub remediation: String,
}

/// Violation severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ViolationSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Runtime alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAlert {
    /// Alert ID
    pub id: Uuid,
    /// Alert type
    pub alert_type: RuntimeAlertType,
    /// Severity
    pub severity: AlertSeverity,
    /// Container ID
    pub container_id: String,
    /// Alert message
    pub message: String,
    /// Process information
    pub process_info: Option<ProcessInfo>,
    /// Network information
    pub network_info: Option<NetworkInfo>,
    /// File system information
    pub file_system_info: Option<FileSystemInfo>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Status
    pub status: AlertStatus,
}

/// Runtime alert types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuntimeAlertType {
    SuspiciousProcess,
    UnauthorizedNetworkConnection,
    FileSystemAnomaly,
    PrivilegeEscalation,
    ResourceAnomaly,
    ConfigurationChange,
    MalwareDetected,
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

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Command line
    pub command_line: String,
    /// Parent process ID
    pub parent_pid: Option<u32>,
    /// User ID
    pub user_id: u32,
    /// Group ID
    pub group_id: u32,
    /// Executable path
    pub executable_path: String,
    /// Working directory
    pub working_directory: String,
}

/// Network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Source IP
    pub source_ip: String,
    /// Source port
    pub source_port: u16,
    /// Destination IP
    pub destination_ip: String,
    /// Destination port
    pub destination_port: u16,
    /// Protocol
    pub protocol: NetworkProtocol,
    /// Connection state
    pub connection_state: ConnectionState,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
}

/// Network protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    Custom(String),
}

/// Connection states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    Established,
    Listening,
    TimeWait,
    CloseWait,
    Unknown,
}

/// File system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemInfo {
    /// File path
    pub file_path: String,
    /// Operation type
    pub operation_type: FileSystemOperation,
    /// File permissions
    pub file_permissions: String,
    /// File owner
    pub file_owner: String,
    /// File size
    pub file_size: u64,
    /// File hash
    pub file_hash: Option<String>,
}

/// File system operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileSystemOperation {
    Read,
    Write,
    Execute,
    Delete,
    Create,
    Modify,
    Custom(String),
}

/// Alert status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertStatus {
    New,
    Investigating,
    Contained,
    Resolved,
    FalsePositive,
}

/// Wolf den assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfDenAssignment {
    /// Den ID
    pub den_id: Uuid,
    /// Den name
    pub den_name: String,
    /// Den type
    pub den_type: WolfDenType,
    /// Security level
    pub security_level: DenSecurityLevel,
    /// Pack assignment
    pub pack_assignment: Option<DenPackAssignment>,
    /// Assigned timestamp
    pub assigned_at: DateTime<Utc>,
}

/// Wolf den types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WolfDenType {
    AlphaDen,    // Most critical containers
    BetaDen,     // High-priority containers
    GammaDen,    // Standard containers
    DeltaDen,    // Development containers
    OmegaDen,    // Testing containers
    ScoutDen,    // Reconnaissance containers
    HunterDen,   // Attack simulation containers
    GuardianDen, // Security monitoring containers
}

/// Den security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DenSecurityLevel {
    Maximum = 0,
    High = 1,
    Medium = 2,
    Standard = 3,
    Basic = 4,
}

/// Den pack assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenPackAssignment {
    /// Pack ID
    pub pack_id: Uuid,
    /// Pack name
    pub pack_name: String,
    /// Pack role
    pub pack_role: DenPackRole,
    /// Wolves assigned
    pub wolves_assigned: u32,
    /// Patrol frequency
    pub patrol_frequency: DenPatrolFrequency,
}

/// Den pack roles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DenPackRole {
    AlphaGuard,    // Lead den protection
    BetaGuard,     // High-priority den protection
    GammaGuard,    // Standard den protection
    DeltaGuard,    // Development den protection
    OmegaGuard,    // Testing den protection
    ScoutGuard,    // Den reconnaissance
    HunterGuard,   // Den threat hunting
    GuardianGuard, // Den monitoring
}

/// Den patrol frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DenPatrolFrequency {
    Continuous,
    Hourly,
    Every2Hours,
    Every4Hours,
    Every6Hours,
    Daily,
    Weekly,
}

/// Container vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerVulnerability {
    /// Vulnerability ID
    pub id: String,
    /// Vulnerability name
    pub name: String,
    /// Severity
    pub severity: VulnerabilitySeverity,
    /// CVSS score
    pub cvss_score: Option<f64>,
    /// Package name
    pub package_name: String,
    /// Package version
    pub package_version: String,
    /// Fixed version
    pub fixed_version: Option<String>,
    /// Description
    pub description: String,
    /// References
    pub references: Vec<String>,
    /// Discovered timestamp
    pub discovered_at: DateTime<Utc>,
}

/// Vulnerability severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum VulnerabilitySeverity {
    #[default]
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Vulnerability databases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilityDatabase {
    NVD,
    CVE,
    GitHubAdvisories,
    OSV,
    Custom(String),
}

/// Container network policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerNetworkPolicy {
    /// Policy ID
    pub id: Uuid,
    /// Policy name
    pub name: String,
    /// Policy type
    pub policy_type: NetworkPolicyType,
    /// Source selectors
    pub source_selectors: Vec<NetworkSelector>,
    /// Destination selectors
    pub destination_selectors: Vec<NetworkSelector>,
    /// Allowed ports
    pub allowed_ports: Vec<PortRange>,
    /// Denied ports
    pub denied_ports: Vec<PortRange>,
    /// Action
    pub action: NetworkPolicyAction,
    /// Priority
    pub priority: u32,
    /// Enabled
    pub enabled: bool,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Network policy types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPolicyType {
    Ingress,
    Egress,
    Both,
}

/// Network selector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSelector {
    /// Selector type
    pub selector_type: SelectorType,
    /// Selector values
    pub values: Vec<String>,
    /// Labels
    pub labels: HashMap<String, String>,
}

/// Selector types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelectorType {
    Label,
    Namespace,
    Pod,
    IPRange,
    Custom(String),
}

/// Port range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    /// Start port
    pub start_port: u16,
    /// End port
    pub end_port: u16,
    /// Protocol
    pub protocol: NetworkProtocol,
}

/// Network policy actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPolicyAction {
    Allow,
    Deny,
    Log,
}

/// Container resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResourceLimits {
    /// Container ID
    pub container_id: String,
    /// CPU limits
    pub cpu_limits: CPULimits,
    /// Memory limits
    pub memory_limits: MemoryLimits,
    /// Storage limits
    pub storage_limits: StorageLimits,
    /// Network limits
    pub network_limits: NetworkLimits,
    /// Enforcement enabled
    pub enforcement_enabled: bool,
    /// Last updated
    pub last_updated: DateTime<Utc>,
}

/// CPU limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPULimits {
    /// CPU request
    pub cpu_request: f64,
    /// CPU limit
    pub cpu_limit: f64,
    /// CPU shares
    pub cpu_shares: Option<u32>,
}

/// Memory limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLimits {
    /// Memory request
    pub memory_request: u64,
    /// Memory limit
    pub memory_limit: u64,
    /// Swap limit
    pub swap_limit: Option<u64>,
}

/// Storage limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageLimits {
    /// Storage request
    pub storage_request: u64,
    /// Storage limit
    pub storage_limit: u64,
    /// Read IOPS
    pub read_iops: Option<u32>,
    /// Write IOPS
    pub write_iops: Option<u32>,
}

/// Network limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLimits {
    /// Bandwidth limit
    pub bandwidth_limit: Option<u64>,
    /// Packet rate limit
    pub packet_rate_limit: Option<u32>,
    /// Connection limit
    pub connection_limit: Option<u32>,
}

impl ContainerSecurityManager {
    /// Create new container security manager
    pub fn new(config: ContainerSecurityConfig) -> Result<Self> {
        info!("🐳 Initializing Container Security Manager");

        let manager = Self {
            image_scanner: ContainerImageScanner::new(config.clone())?,
            runtime_protector: ContainerRuntimeProtector::new(config.clone())?,
            orchestration_security: OrchestrationSecurityManager::new(config.clone())?,
            network_policies: ContainerNetworkPolicyManager::new(config.clone())?,
            resource_limits: ContainerResourceLimitManager::new(config.clone())?,
            wolf_den_containers: WolfDenContainerManager::new(WolfDenConfig::default()),
            config,
            statistics: ContainerSecurityStats::default(),
        };

        info!("✅ Container Security Manager initialized successfully");
        Ok(manager)
    }

    /// Scan container image for vulnerabilities
    pub async fn scan_image(&mut self, image_name: &str) -> Result<ImageScanResult> {
        info!("🔍 Scanning container image: {}", image_name);

        let scan_result = self.image_scanner.scan_image(image_name).await?;

        // Update statistics
        self.statistics.scanned_images += 1;
        self.statistics.vulnerabilities_found += scan_result.vulnerabilities.len() as u64;
        self.statistics.critical_vulnerabilities += scan_result
            .vulnerabilities
            .iter()
            .filter(|v| v.severity == VulnerabilitySeverity::Critical)
            .count() as u64;

        info!(
            "✅ Image scan completed: {} vulnerabilities found",
            scan_result.vulnerabilities.len()
        );
        Ok(scan_result)
    }

    /// Protect container runtime
    pub async fn protect_container_runtime(
        &mut self,
        container_id: &str,
    ) -> Result<RuntimeProtectionResult> {
        info!("🛡️ Protecting container runtime: {}", container_id);

        let protection_result = self
            .runtime_protector
            .protect_container(container_id)
            .await?;

        // Update statistics
        self.statistics.security_incidents += protection_result.alerts.len() as u64;

        info!(
            "✅ Runtime protection enabled: {} alerts",
            protection_result.alerts.len()
        );
        Ok(protection_result)
    }

    /// Enforce network policies
    pub async fn enforce_network_policies(
        &mut self,
        policies: Vec<ContainerNetworkPolicy>,
    ) -> Result<PolicyEnforcementResult> {
        info!("🌐 Enforcing network policies: {} policies", policies.len());

        let enforcement_result = self.network_policies.enforce_policies(policies).await?;

        // Update statistics
        self.statistics.network_violations += enforcement_result.violations.len() as u64;

        info!(
            "✅ Network policies enforced: {} violations",
            enforcement_result.violations.len()
        );
        Ok(enforcement_result)
    }

    /// Apply resource limits
    pub async fn apply_resource_limits(
        &mut self,
        limits: Vec<ContainerResourceLimits>,
    ) -> Result<ResourceLimitResult> {
        info!("⚡ Applying resource limits: {} containers", limits.len());

        let limit_result = self.resource_limits.apply_limits(limits).await?;

        info!(
            "✅ Resource limits applied: {} containers",
            limit_result.containers_updated
        );
        Ok(limit_result)
    }

    /// Assign container to wolf den
    pub async fn assign_to_wolf_den(
        &mut self,
        container_id: &str,
        den_type: WolfDenType,
    ) -> Result<WolfDenAssignment> {
        info!(
            "🐺 Assigning container {} to wolf den: {:?}",
            container_id, den_type
        );

        let assignment = self
            .wolf_den_containers
            .assign_container(container_id, den_type)
            .await?;

        info!("✅ Container assigned to wolf den: {}", assignment.den_name);
        Ok(assignment)
    }

    /// Get container security posture
    pub async fn get_container_security_posture(
        &self,
        container_id: &str,
    ) -> Result<Option<ContainerSecurityPosture>> {
        debug!(
            "📊 Getting security posture for container: {}",
            container_id
        );

        let posture = self
            .runtime_protector
            .get_security_posture(container_id)
            .await?;

        Ok(posture)
    }

    /// Get container security statistics
    pub fn get_statistics(&self) -> &ContainerSecurityStats {
        &self.statistics
    }

    /// Generate container security report
    pub async fn generate_report(
        &self,
        report_type: ContainerReportType,
        time_range: TimeRange,
    ) -> Result<ContainerSecurityReport> {
        info!(
            "📊 Generating container security report: {:?} for {:?}",
            report_type, time_range
        );

        let report = ContainerSecurityReport {
            id: Uuid::new_v4(),
            report_type,
            time_range,
            generated_at: Utc::now(),
            total_containers: self.statistics.total_containers,
            running_containers: self.statistics.running_containers,
            scanned_images: self.statistics.scanned_images,
            vulnerabilities_found: self.statistics.vulnerabilities_found,
            critical_vulnerabilities: self.statistics.critical_vulnerabilities,
            security_incidents: self.statistics.security_incidents,
            containers_quarantined: self.statistics.containers_quarantined,
            network_violations: self.statistics.network_violations,
            key_metrics: HashMap::new(), // Would be populated with actual metrics
            recommendations: Vec::new(), // Would be populated with actual recommendations
        };

        info!("✅ Container security report generated: {}", report.id);
        Ok(report)
    }

    /// Process network event
    pub async fn process_network_event(&mut self, event_type: &str, source: &str, _details: &str) {
        info!(
            "Container Security processing network event: {} from {}",
            event_type, source
        );
        // Future integration: Check against network policies or trigger automated scans
    }
}

/// Image scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageScanResult {
    /// Image name
    pub image_name: String,
    /// Image digest
    pub image_digest: String,
    /// Scan timestamp
    pub scan_timestamp: DateTime<Utc>,
    /// Vulnerabilities found
    pub vulnerabilities: Vec<ContainerVulnerability>,
    /// Security score
    pub security_score: f64,
    /// Scan duration in seconds
    pub scan_duration_seconds: u64,
}

/// Runtime protection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeProtectionResult {
    /// Container ID
    pub container_id: String,
    /// Protection enabled
    pub protection_enabled: bool,
    /// Runtime alerts
    pub alerts: Vec<RuntimeAlert>,
    /// Protection timestamp
    pub protection_timestamp: DateTime<Utc>,
}

/// Policy enforcement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnforcementResult {
    /// Policies enforced
    pub policies_enforced: u64,
    /// Violations detected
    pub violations: Vec<NetworkPolicyViolation>,
    /// Enforcement timestamp
    pub enforcement_timestamp: DateTime<Utc>,
}

/// Network policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicyViolation {
    /// Violation ID
    pub id: Uuid,
    /// Container ID
    pub container_id: String,
    /// Policy ID
    pub policy_id: Uuid,
    /// Violation type
    pub violation_type: ViolationType,
    /// Description
    pub description: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Violation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    DeniedConnection,
    UnauthorizedPort,
    PolicyBreach,
    Custom(String),
}

/// Resource limit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitResult {
    /// Containers updated
    pub containers_updated: u64,
    /// Limits applied
    pub limits_applied: u64,
    /// Violations detected
    pub violations: Vec<ResourceLimitViolation>,
    /// Application timestamp
    pub application_timestamp: DateTime<Utc>,
}

/// Resource limit violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitViolation {
    /// Violation ID
    pub id: Uuid,
    /// Container ID
    pub container_id: String,
    /// Resource type
    pub resource_type: ResourceType,
    /// Current usage
    pub current_usage: f64,
    /// Limit value
    pub limit_value: f64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Resource types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    CPU,
    Memory,
    Storage,
    Network,
    Custom(String),
}

/// Container report types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainerReportType {
    SecurityPosture,
    VulnerabilityAssessment,
    RuntimeProtection,
    NetworkSecurity,
    ResourceUsage,
    WolfDenStatus,
    Custom(String),
}

/// Container security report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityReport {
    /// Report ID
    pub id: Uuid,
    /// Report type
    pub report_type: ContainerReportType,
    /// Time range
    pub time_range: TimeRange,
    /// Generated at
    pub generated_at: DateTime<Utc>,
    /// Total containers
    pub total_containers: u64,
    /// Running containers
    pub running_containers: u64,
    /// Scanned images
    pub scanned_images: u64,
    /// Vulnerabilities found
    pub vulnerabilities_found: u64,
    /// Critical vulnerabilities
    pub critical_vulnerabilities: u64,
    /// Security incidents
    pub security_incidents: u64,
    /// Containers quarantined
    pub containers_quarantined: u64,
    /// Network violations
    pub network_violations: u64,
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

impl Default for ImageScanningSettings {
    fn default() -> Self {
        Self {
            automated_scanning_enabled: true,
            scan_on_pull_enabled: true,
            vulnerability_databases: vec![VulnerabilityDatabase::NVD, VulnerabilityDatabase::CVE],
            severity_threshold: VulnerabilitySeverity::Medium,
            custom_rules_enabled: true,
        }
    }
}

impl Default for RuntimeProtectionSettings {
    fn default() -> Self {
        Self {
            runtime_monitoring_enabled: true,
            anomaly_detection_enabled: true,
            process_monitoring_enabled: true,
            file_system_monitoring_enabled: true,
            network_monitoring_enabled: true,
            auto_quarantine_enabled: false,
        }
    }
}

impl Default for OrchestrationSecuritySettings {
    fn default() -> Self {
        Self {
            kubernetes_security_enabled: true,
            docker_security_enabled: true,
            pod_security_policies_enabled: true,
            rbac_enforcement_enabled: true,
            network_policies_enforced: true,
            admission_control_enabled: true,
        }
    }
}

impl Default for NetworkPolicySettings {
    fn default() -> Self {
        Self {
            default_deny_enabled: true,
            microsegmentation_enabled: true,
            egress_filtering_enabled: true,
            ingress_filtering_enabled: true,
            service_mesh_integration_enabled: false,
        }
    }
}

impl Default for ResourceLimitSettings {
    fn default() -> Self {
        Self {
            cpu_limits_enforced: true,
            memory_limits_enforced: true,
            storage_limits_enforced: false,
            network_limits_enforced: false,
            resource_monitoring_enabled: true,
        }
    }
}

impl Default for WolfDenSettings {
    fn default() -> Self {
        Self {
            wolf_den_isolation_enabled: true,
            pack_coordination_enabled: true,
            den_patrol_enabled: true,
            territory_marking_enabled: true,
            den_hierarchy_enforced: true,
        }
    }
}

impl Default for ContainerSecurityStats {
    fn default() -> Self {
        Self {
            total_containers: 0,
            running_containers: 0,
            scanned_images: 0,
            vulnerabilities_found: 0,
            critical_vulnerabilities: 0,
            security_incidents: 0,
            containers_quarantined: 0,
            network_violations: 0,
            last_scan: Utc::now(),
            last_update: Utc::now(),
        }
    }
}
