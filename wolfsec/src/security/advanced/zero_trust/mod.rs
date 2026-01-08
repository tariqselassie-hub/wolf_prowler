//! Zero Trust Architecture Module
//!
//! Implements Zero Trust security principles with wolf-themed analogies:
//! - Never trust, always verify (wolves verify all outsiders)
//! - Microsegmentation (territory zones)
//! - Contextual authentication (context-aware access)
//! - Continuous monitoring (constant patrol)

pub mod contextual_auth;
pub mod microsegmentation;
pub mod policy_engine;
pub mod trust_engine;

use anyhow::Result;
use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
 // Use libp2p's PeerId directly

// Import wolf-themed configurations
// Local definitions for configuration to ensure self-containment
/// Configuration for a wolf pack (security group).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfPackConfig {
    /// Name of the wolf pack.
    pub name: String,
}

/// Configuration for a wolf den (secure storage or node).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfDenConfig {
    /// Physical or logical location of the wolf den.
    pub location: String,
}

/// Rules governing communication within the wolf pack.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfCommunicationRules {
    /// Whether communication must be secure and encrypted.
    pub secure: bool,
}

/// Metrics representing the health and status of the wolf ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WolfEcosystemMetrics {
    /// Overall health score (0.0 to 1.0).
    pub health: f64,
}

/// Represents a security operation or task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolfOperation {
    /// Unique identifier for the operation.
    pub id: String,
}

/// Status of a security operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperationStatus {
    /// Operation has been created but not yet started.
    Created,
    /// Operation is currently active.
    Active,
    /// Operation has finished successfully.
    Completed,
    /// Operation has failed.
    Failed,
    /// Operation is temporarily paused.
    Paused,
}

/// Represents the rank of a node or entity within the pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackRank {
    /// Numeric rank value.
    pub rank: u32,
}

/// Trigger for a "hunt" or proactive security investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntTrigger {
    /// The reason for triggering the hunt.
    pub reason: String,
}

/// Recommendation generated after a hunt investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntRecommendation {
    /// Recommended security action.
    pub action: String,
}

pub use contextual_auth::ContextualAuthenticator;
pub use microsegmentation::MicrosegmentationManager;
pub use policy_engine::WolfPolicyEngine;
pub use trust_engine::TrustAnalytics;
/// Re-export main components
pub use trust_engine::WolfTrustEngine;

/// Wolf-themed Zero Trust configuration
pub type ZeroTrustConfig = WolfPackConfig;

/// Wolf-themed audit configuration
pub type AuditConfig = WolfDenConfig;

/// Wolf-themed alerts configuration
pub type AlertsConfig = WolfCommunicationRules;

/// Wolf-themed security controls
pub type SecurityControl = WolfOperation;

/// Wolf-themed pipeline status
pub type PipelineStatus = OperationStatus;

/// Wolf-themed compliance status
pub type ComplianceStatus = PackRank;

/// Wolf-themed security metrics
pub type SecurityMetricsSnapshot = WolfEcosystemMetrics;

/// Wolf-themed segmentation result type alias
pub type SegmentationResultType = SegmentationResult;

/// Wolf-themed configuration violation type alias
pub type ConfigurationViolation = HuntTrigger;

/// Wolf-themed policy evaluation result type alias
pub type PolicyEvaluationResultType = PolicyEvaluationResult;

/// Wolf-themed contextual requirement type alias
pub type ContextualRequirementType = ContextualRequirement;

/// Wolf-themed adaptive control type alias
pub type AdaptiveControlType = AdaptiveControl;

/// Granular trust tiers based on continuous verification and behavior analysis
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// No trust has been established or identity is verify-pending
    Unknown = 0,
    /// Anomalous behavior detected, restricted to essential monitoring only
    Suspicious = 1,
    /// Fails basic identity or security posture requirements
    Untrusted = 2,
    /// Minimal verification successful, restricted access to low-risk resources
    PartiallyTrusted = 3,
    /// Standard corporate-level trust after successful multi-factor verification
    Trusted = 4,
    /// Verified high-compliance device with multi-factor and clean history
    HighlyTrusted = 5,
    /// Root or Administrative level trust for highly sensitive operations
    AlphaTrusted = 6,
}

/// Aggregate collection of contextual signals used to calculate real-time trust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustContext {
    /// Unique identity of the entity being evaluated
    pub peer_id: PeerId,
    /// Point in time when the context was captured
    pub timestamp: DateTime<Utc>,
    /// Network and geographic origin metadata
    pub location: LocationContext,
    /// Hardware and software security status of the requester
    pub device_info: DeviceContext,
    /// Derived score from historical and real-time behavioral patterns
    pub behavioral_score: f64,
    /// Longitudinal trust history and interaction patterns
    pub historical_trust: HistoricalTrust,
    /// External factors such as time of day and global threat environment
    pub environmental_factors: EnvironmentalContext,
}

/// Detailed network and geographic origin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationContext {
    /// Current IP address of the requester
    pub ip_address: std::net::IpAddr,
    /// Resolved geographic coordinates and administrative regions
    pub geographic_location: Option<GeoLocation>,
    /// Logical network identifier or VLAN
    pub network_segment: String,
    /// True if the location matches a previously verified and safe territory
    pub is_known_territory: bool,
}

/// Geographic coordinates and risk metadata for a location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// ISO country code
    pub country: String,
    /// State, Province, or Administrative Region
    pub region: String,
    /// Resolved city name
    pub city: String,
    /// GPS Latitude
    pub latitude: f64,
    /// GPS Longitude
    pub longitude: f64,
    /// Indicates if the location is associated with high fraud or threat volatility
    pub is_high_risk_location: bool,
}

/// Hardware and software metadata for assessing endpoint security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceContext {
    /// Unique hardware or platform identifier
    pub device_id: String,
    /// Classification of the device (Alpha, Beta, etc.)
    pub device_type: DeviceType,
    /// Snapshot of local security controls and configurations
    pub security_posture: SecurityPosture,
    /// Metadata from local hardware or platform certificates
    pub certificate_info: Option<CertificateInfo>,
    /// Aggregate health score based on patching and security status
    pub health_score: f64,
}

/// Categorization of devices using wolf-themed hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceType {
    /// High-value, rigorously protected primary workstation
    Alpha,
    /// Standard managed corporate endpoint
    Beta,
    /// Externally owned guest or temporary device
    Gamma,
    /// Unmanaged, unknown, or unverified device
    Delta,
    /// Flagged as compromised or fundamentally insecure
    Omega,
}

/// Detailed configuration of local security controls on an endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPosture {
    /// Operating system version and build identifier
    pub os_version: String,
    /// Current point-release or security update level
    pub patch_level: String,
    /// Status of the local malware protection engine
    pub antivirus_status: AVStatus,
    /// True if the local network filtering is active
    pub firewall_enabled: bool,
    /// True if the system drive is encrypted at rest
    pub disk_encryption: bool,
    /// True if the platform boot chain is cryptographically verified
    pub secure_boot_enabled: bool,
    /// Point in time of the most recent local compliance check
    pub last_security_scan: DateTime<Utc>,
}

/// Status of the local antivirus engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AVStatus {
    /// Antivirus is active and running.
    Active,
    /// Antivirus is currently disabled or inactive.
    Inactive,
    /// Antivirus signatures are out of date.
    Outdated,
    /// Antivirus software is not installed.
    NotInstalled,
}

/// Information about a hardware or platform certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// The entity that issued the certificate.
    pub issuer: String,
    /// Unique serial number of the certificate.
    pub serial_number: String,
    /// Timestamp when the certificate was issued.
    pub issued_at: DateTime<Utc>,
    /// Timestamp when the certificate expires.
    pub expires_at: DateTime<Utc>,
    /// True if the certificate has been revoked.
    pub is_revoked: bool,
    /// The chain of trust for this certificate.
    pub trust_chain: Vec<String>,
}

/// Longitudinal record of trust and interaction patterns for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalTrust {
    /// Point in time when the peer was first observed
    pub first_seen: DateTime<Utc>,
    /// Point in time of the most recent interaction
    pub last_seen: DateTime<Utc>,
    /// Total aggregate interactions (successful or failed)
    pub total_interactions: u64,
    /// Count of interactions matching policy requirements
    pub successful_interactions: u64,
    /// Count of interactions failing security verification
    pub failed_interactions: u64,
    /// Total number of security anomalies or violations linked to this peer
    pub security_incidents: u64,
    /// Long-term rolling average trust score
    pub average_trust_score: f64,
}

/// Global and external signals influencing the trust calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentalContext {
    /// Categorization of the current local time
    pub time_of_day: TimeContext,
    /// Binary classification of working vs non-working days
    pub day_of_week: DayContext,
    /// True if the request falls within authorized operational hours
    pub business_hours: bool,
    /// Global threat landscape indicator (Low to Critical)
    pub current_threat_level: ThreatLevel,
    /// Current network utilization and pressure
    pub network_load: NetworkLoad,
    /// List of active, unmitigated incidents relevant to the request
    pub active_incidents: Vec<String>,
}

/// Contextual classification of time for security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeContext {
    /// Within normal operating hours.
    Normal,
    /// Outside of normal operating hours.
    AfterHours,
    /// Occurring during a weekend.
    Weekend,
    /// Occurring during a recognized holiday.
    Holiday,
}

/// Contextual classification of the day for security analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DayContext {
    /// A standard working day (Monday-Friday).
    Weekday,
    /// A weekend day (Saturday or Sunday).
    Weekend,
    /// A recognized holiday.
    Holiday,
}

/// Current threat level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Normal operating conditions, no active threats.
    Low,
    /// Elevated vigilance required, potential threats detected.
    Medium,
    /// Confirmed threats present, active defense required.
    High,
    /// Imminent or active breach, maximum security posture.
    Critical,
}

/// Assessment of the current network utilization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkLoad {
    /// Network load is low.
    Low,
    /// Network load is normal/moderate.
    Medium,
    /// Network load is high.
    High,
    /// Network is currently overloaded.
    Overloaded,
}

/// Defined policy for enforcing Zero Trust access requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustPolicy {
    /// Unique identifier for the policy definition
    pub id: String,
    /// Human-readable display name for the policy
    pub name: String,
    /// Narrative detailing the policy purpose and scope
    pub description: String,
    /// The minimum trust tier required to satisfy this policy
    pub trust_level_required: TrustLevel,
    /// Set of contextual prerequisites that must be met
    pub contextual_requirements: Vec<ContextualRequirement>,
    /// Controls that dynamically adjust based on risk transitions
    pub adaptive_controls: Vec<AdaptiveControl>,
    /// Authorized deviations for specific identities or conditions
    pub exceptions: Vec<PolicyException>,
    /// When the policy was initially defined
    pub created_at: DateTime<Utc>,
    /// Point in time of the most recent policy amendment
    pub updated_at: DateTime<Utc>,
}

/// A specific contextual predicate within a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualRequirement {
    /// The type of factor being evaluated (Location, Behavioral, etc.)
    pub requirement_type: RequirementType,
    /// The logical operation for comparison
    pub operator: ComparisonOperator,
    /// The target value for the requirement
    pub value: serde_json::Value,
    /// The relative importance of this requirement in the overall decision
    pub weight: f64,
}

/// Types of contextual requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequirementType {
    /// Requirement based on geographic or network location.
    Location,
    /// Requirement based on the type of device.
    DeviceType,
    /// Requirement based on the device's security status.
    SecurityPosture,
    /// Requirement based on the time of the request.
    TimeContext,
    /// Requirement based on the subject's behavioral score.
    BehavioralScore,
    /// Requirement based on historical trust patterns.
    HistoricalTrust,
    /// Requirement based on the current global threat level.
    ThreatLevel,
    /// Requirement based on current network load.
    NetworkLoad,
}

/// Comparison operators for requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    /// Values must be exactly equal.
    Equals,
    /// Values must not be equal.
    NotEquals,
    /// Value must be strictly greater than target.
    GreaterThan,
    /// Value must be strictly less than target.
    LessThan,
    /// Value must be greater than or equal to target.
    GreaterThanOrEqual,
    /// Value must be less than or equal to target.
    LessThanOrEqual,
    /// Text value must contain the target substring.
    Contains,
    /// Text value must not contain the target substring.
    NotContains,
    /// Value must be present in the target list.
    In,
    /// Value must not be present in the target list.
    NotIn,
}

/// Security control that modifies behavior based on real-time risk transitions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveControl {
    /// The nature of the control being enforced
    pub control_type: ControlType,
    /// Conditions that trigger the activation of this control
    pub trigger_conditions: Vec<TriggerCondition>,
    /// Remediation or restriction actions to execute
    pub actions: Vec<SecurityAction>,
    /// True if the control is currently being evaluated and enforced
    pub is_active: bool,
}

/// Types of controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlType {
    /// Restrict or grant permissions to resources.
    AccessControl,
    /// Throttle request frequency.
    RateLimiting,
    /// Enhanced observation of activities.
    Monitoring,
    /// Notify administrators of events.
    Alerting,
    /// Prevent access entirely.
    Blocking,
    /// Isolate entity from network.
    Quarantine,
}

/// Condition that triggers an adaptive control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCondition {
    /// The type of condition to monitor.
    pub condition_type: ConditionType,
    /// The value that triggers the control when reached.
    pub threshold: serde_json::Value,
    /// Optional time window for evaluating the condition (e.g., failed attempts in 5 mins).
    pub time_window: Option<std::time::Duration>,
}

/// Types of conditions that can trigger security controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionType {
    /// Excessive number of failed authentication or access attempts.
    FailedAttempts,
    /// Detection of abnormal behavioral patterns.
    AnomalousBehavior,
    /// Direct detection of a known threat.
    ThreatDetected,
    /// Access attempt from a known high-risk geographic or network location.
    HighRiskLocation,
    /// Evidence that an endpoint device has been compromised.
    DeviceCompromised,
    /// An explicit violation of security policy.
    PolicyViolation,
}

/// Security actions that can be executed as part of an enforcement policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityAction {
    /// Explicitly block all access from the subject.
    BlockAccess,
    /// Require additional multi-factor authentication.
    RequireMFA,
    /// Permit access but with reduced privileges or scope.
    LimitAccess,
    /// Increase the granularity and frequency of security monitoring.
    IncreaseMonitoring,
    /// Dispatch a high-priority alert to the security operations center.
    SendAlert,
    /// Isolate the device from the rest of the network.
    QuarantineDevice,
    /// Immediately revoke all active sessions and tokens.
    RevokeAccess,
    /// Document the event in the security incident log.
    LogIncident,
}

/// authorized exception to a security policy for a specific subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyException {
    /// Unique identifier for the exception.
    pub id: String,
    /// Identifier of the peer granted the exception.
    pub peer_id: PeerId,
    /// Detailed justification for the exception.
    pub reason: String,
    /// Identity of the administrator who approved the exception.
    pub approved_by: String,
    /// Optional timestamp when the exception expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// Specific conditions that must be met for the exception to remain valid.
    pub conditions: Vec<String>,
}

/// Comprehensive outcome of a Zero Trust trust and policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvaluationResult {
    /// Identifier of the peer evaluated
    pub peer_id: PeerId,
    /// The final trust tier assigned
    pub trust_level: TrustLevel,
    /// Statistical certainty of the evaluation (0-1.0)
    pub confidence_score: f64,
    /// Calculated probability and impact of threat (0-1.0)
    pub risk_score: f64,
    /// Specific factors that drove the final result
    pub contextual_factors: Vec<ContextualFactor>,
    /// List of recommended security mitigations or actions
    pub recommended_actions: Vec<SecurityAction>,
    /// Point in time when the assessment was performed
    pub evaluation_timestamp: DateTime<Utc>,
    /// Point in time when this result should be refreshed or discarded
    pub expires_at: DateTime<Utc>,
}

/// A single contextual signal contributing to a trust decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualFactor {
    /// The type of factor (e.g., "Network", "Biometric").
    pub factor_type: String,
    /// The value of the factor.
    pub value: serde_json::Value,
    /// Mathematical impact of this factor on the final trust score (-1.0 to 1.0).
    pub impact_on_trust: f64,
    /// Statistical certainty of this specific signal (0-1.0).
    pub confidence: f64,
}

/// Central orchestrator for the Wolf Prowler Zero Trust security architecture.
///
/// Coordinates trust evaluation, policy enforcement, contextual authentication,
/// and microsegmentation using wolf pack behavioral principles.
pub struct ZeroTrustManager {
    /// Engine for calculating and tracking peer trust scores
    pub trust_engine: WolfTrustEngine,
    /// Evaluates access requests against defined security policies
    pub policy_engine: WolfPolicyEngine,
    /// Performs environment-aware identity verification
    pub authenticator: ContextualAuthenticator,
    /// Enforces dynamic isolation zones and access boundaries
    pub segmentation: MicrosegmentationManager,
}

impl ZeroTrustManager {
    /// Initializes a new `ZeroTrustManager` and its associated sub-engines.
    ///
    /// # Errors
    /// Returns an error if any of the sub-engines (trust, policy, auth, segmentation) fail to initialize.
    pub fn new() -> Result<Self> {
        Ok(Self {
            trust_engine: WolfTrustEngine::new()?,
            policy_engine: WolfPolicyEngine::new()?,
            authenticator: ContextualAuthenticator::new()?,
            segmentation: MicrosegmentationManager::new()?,
        })
    }

    /// Performs a comprehensive Zero Trust assessment for a given trust context.
    ///
    /// Coordinates evaluation across trust, policy, authentication, and segmentation engines.
    ///
    /// # Errors
    /// Returns an error if any of the sub-engines fail to complete their assessment.
    pub async fn evaluate_trust(&mut self, context: TrustContext) -> Result<TrustEvaluationResult> {
        // Get base trust level
        let base_trust = self.trust_engine.evaluate_base_trust(&context).await?;

        // Apply policy evaluations
        let policy_result = self
            .policy_engine
            .evaluate_policies(&context, &base_trust.trust_level)
            .await?;

        // Perform contextual authentication
        let auth_result = self.authenticator.authenticate(&context).await?;

        // Apply segmentation rules
        let segmentation_result = self.segmentation.evaluate_access(&context).await?;

        // Combine all results
        let combined_result =
            self.combine_evaluations(base_trust, policy_result, auth_result, segmentation_result)?;

        Ok(combined_result)
    }

    /// Combines the individual evaluations from various sub-engines into a final decision.
    ///
    /// # Errors
    /// Returns an error if the results cannot be logically aggregated.
    fn combine_evaluations(
        &self,
        trust: TrustEvaluationResult,
        policy: PolicyEvaluationResult,
        auth: AuthResult,
        segmentation: SegmentationResult,
    ) -> Result<TrustEvaluationResult> {
        // Weighted combination of all factors
        let mut combined = trust;

        // Apply policy adjustments
        combined.trust_level = std::cmp::min(combined.trust_level, policy.required_trust_level);
        combined.confidence_score = (combined.confidence_score * 0.4
            + policy.confidence * 0.3
            + auth.confidence * 0.2
            + segmentation.confidence * 0.1)
            .min(1.0);
        combined.risk_score = (combined.risk_score * 0.4
            + policy.risk_score * 0.3
            + auth.risk_score * 0.2
            + segmentation.risk_score * 0.1)
            .min(1.0);

        // Combine recommended actions
        combined
            .recommended_actions
            .extend(policy.recommended_actions);
        combined
            .recommended_actions
            .extend(auth.recommended_actions);
        combined
            .recommended_actions
            .extend(segmentation.recommended_actions);

        Ok(combined)
    }

    /// Aggregates trust telemetry and historical trends from the trust engine.
    pub fn get_trust_analytics(&self) -> TrustAnalytics {
        self.trust_engine.get_analytics()
    }
}

/// Detailed outcome of a policy engine evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    /// The calculated trust level required for the requested access
    pub required_trust_level: TrustLevel,
    /// Confidence in the policy match (0-1.0)
    pub confidence: f64,
    /// Calculated risk of the policy compliance (0-1.0)
    pub risk_score: f64,
    /// Actions recommended by the matching policies
    pub recommended_actions: Vec<SecurityAction>,
    /// List of specific policies that were evaluated and applied
    pub applied_policies: Vec<String>,
}

/// Outcome of a contextual authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// True if identity and context were successfully verified
    pub success: bool,
    /// Verification certainty (0-1.0)
    pub confidence: f64,
    /// Calculated risk of the authentication event (0-1.0)
    pub risk_score: f64,
    /// Actions recommended by the authenticator
    pub recommended_actions: Vec<SecurityAction>,
    /// List of authentication factors considered during the event
    pub auth_methods_used: Vec<String>,
}

/// Outcome of a microsegmentation access check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationResult {
    /// True if network/segment access is authorized
    pub access_granted: bool,
    /// Confidence in the segment isolation (0-1.0)
    pub confidence: f64,
    /// Calculated risk of crossing the segment boundary (0-1.0)
    pub risk_score: f64,
    /// Actions recommended to maintain segment integrity
    pub recommended_actions: Vec<SecurityAction>,
    /// List of infrastructure segments accessible under current trust
    pub accessible_segments: Vec<String>,
}
