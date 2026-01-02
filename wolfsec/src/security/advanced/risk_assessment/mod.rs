//! Risk Assessment Tools Module
//!
//! Comprehensive risk assessment with wolf pack threat analysis principles.
//! Wolves assess pack risks through collective intelligence and experience.

pub mod gap_analysis;
pub mod heat_maps;
pub mod mitigation;
pub mod scoring;
pub mod vulnerability;

use crate::security::advanced::compliance::ComplianceFramework;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

pub use gap_analysis::ComplianceGapAnalysisResult;
pub use gap_analysis::ComplianceGapAnalyzer;
pub use heat_maps::RiskHeatMapGenerator;
pub use mitigation::RiskMitigationPlanner;
/// Re-export main components
pub use scoring::RiskScoringEngine;
pub use vulnerability::VulnerabilityManager;

/// Main risk assessment manager
pub struct RiskAssessmentManager {
    /// Risk scoring engine
    scoring_engine: RiskScoringEngine,
    /// Vulnerability manager
    vulnerability_manager: VulnerabilityManager,
    /// Heat map generator
    heat_map_generator: RiskHeatMapGenerator,
    /// Mitigation planner
    mitigation_planner: RiskMitigationPlanner,
    /// Gap analyzer
    gap_analyzer: ComplianceGapAnalyzer,
    /// Configuration
    config: RiskAssessmentConfig,
    /// Statistics
    statistics: RiskAssessmentStats,
}

/// Risk assessment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentConfig {
    /// Assessment frequency in days
    pub assessment_frequency_days: u32,
    /// Risk scoring methodology
    pub scoring_methodology: ScoringMethodology,
    /// Vulnerability management
    pub vulnerability_management: VulnerabilityConfig,
    /// Heat map settings
    pub heat_map_settings: HeatMapConfig,
    /// Mitigation settings
    pub mitigation_settings: MitigationConfig,
    /// Gap analysis settings
    pub gap_analysis_settings: GapAnalysisConfig,
}

/// Scoring methodology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringMethodology {
    /// Risk framework
    pub framework: RiskFramework,
    /// Impact weights
    pub impact_weights: ImpactWeights,
    /// Likelihood weights
    pub likelihood_weights: LikelihoodWeights,
    /// Custom factors
    pub custom_factors: Vec<CustomRiskFactor>,
}

/// Risk frameworks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskFramework {
    CVSS,
    DREAD,
    OWASP,
    NIST,
    ISO27005,
    Custom(String),
}

/// Impact weights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactWeights {
    pub confidentiality: f64,
    pub integrity: f64,
    pub availability: f64,
    pub financial: f64,
    pub reputational: f64,
    pub operational: f64,
    pub legal: f64,
}

/// Likelihood weights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LikelihoodWeights {
    pub threat_source: f64,
    pub vulnerability: f64,
    pub current_controls: f64,
    pub threat_motivation: f64,
    pub threat_capability: f64,
}

/// Custom risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRiskFactor {
    pub name: String,
    pub weight: f64,
    pub description: String,
    pub category: String,
}

/// Vulnerability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityConfig {
    /// Scan frequency in hours
    pub scan_frequency_hours: u32,
    /// Vulnerability sources
    pub sources: Vec<VulnerabilitySource>,
    /// CVSS minimum version
    pub cvss_min_version: f64,
    /// Auto-remediation enabled
    pub auto_remediation_enabled: bool,
    /// Exclusion list
    pub exclusion_list: Vec<String>,
}

/// Vulnerability sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilitySource {
    NVD,
    CVE,
    Nessus,
    OpenVAS,
    Qualys,
    Custom(String),
}

/// Heat map configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatMapConfig {
    /// Grid size
    pub grid_size: HeatMapGridSize,
    /// Color scheme
    pub color_scheme: ColorScheme,
    /// Update frequency in hours
    pub update_frequency_hours: u32,
    /// Include trends
    pub include_trends: bool,
}

/// Heat map grid sizes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum HeatMapGridSize {
    Small5x5,
    #[default]
    Medium10x10,
    Large20x20,
    Custom {
        rows: u32,
        cols: u32,
    },
}

/// Color schemes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ColorScheme {
    #[default]
    Standard,
    WolfPack,
    Corporate,
    HighContrast,
    Custom(Vec<String>),
}

/// Mitigation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationConfig {
    /// Auto-planning enabled
    pub auto_planning_enabled: bool,
    /// Planning methodology
    pub planning_methodology: PlanningMethodology,
    /// Priority weights
    pub priority_weights: PriorityWeights,
    /// Resource constraints
    pub resource_constraints: ResourceConstraints,
}

/// Planning methodology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlanningMethodology {
    RiskBased,
    CostBenefit,
    TimeBased,
    ResourceBased,
    Hybrid,
}

/// Priority weights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityWeights {
    pub risk_score: f64,
    pub implementation_cost: f64,
    pub implementation_time: f64,
    pub business_impact: f64,
    pub regulatory_requirement: f64,
}

/// Resource constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConstraints {
    pub budget_limit: f64,
    pub person_hours_limit: u32,
    pub technical_resources: u32,
    pub time_constraints: Vec<TimeConstraint>,
}

/// Time constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConstraint {
    pub constraint_type: String,
    pub deadline: DateTime<Utc>,
    pub description: String,
}

/// Gap analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapAnalysisConfig {
    /// Analysis frequency in days
    pub analysis_frequency_days: u32,
    /// Compliance frameworks
    pub compliance_frameworks: Vec<ComplianceFramework>,
    /// Include recommendations
    pub include_recommendations: bool,
    /// Risk tolerance levels
    pub risk_tolerance_levels: RiskToleranceLevels,
}

/// Risk tolerance levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskToleranceLevels {
    pub low_risk_tolerance: f64,
    pub medium_risk_tolerance: f64,
    pub high_risk_tolerance: f64,
    pub critical_risk_tolerance: f64,
}

/// Risk assessment statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentStats {
    /// Total assessments performed
    pub total_assessments: u64,
    /// Average risk score
    pub avg_risk_score: f64,
    /// High risk items count
    pub high_risk_items: u64,
    /// Critical risk items count
    pub critical_risk_items: u64,
    /// Vulnerabilities found
    pub vulnerabilities_found: u64,
    /// Vulnerabilities remediated
    pub vulnerabilities_remediated: u64,
    /// Mitigation plans created
    pub mitigation_plans_created: u64,
    /// Gap analyses performed
    pub gap_analyses_performed: u64,
    /// Last assessment timestamp
    pub last_assessment: DateTime<Utc>,
    /// Last update timestamp
    pub last_update: DateTime<Utc>,
}

/// Risk assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessmentResult {
    /// Assessment ID
    pub id: Uuid,
    /// Assessment type
    pub assessment_type: AssessmentType,
    /// Assessment scope
    pub scope: AssessmentScope,
    /// Overall risk score
    pub overall_risk_score: f64,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Risk items
    pub risk_items: Vec<RiskItem>,
    /// Vulnerabilities
    pub vulnerabilities: Vec<VulnerabilityItem>,
    /// Recommendations
    pub recommendations: Vec<RiskRecommendation>,
    /// Assessment period
    pub assessment_period: AssessmentPeriod,
    /// Assessor information
    pub assessor: AssessorInfo,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Assessment types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssessmentType {
    Initial,
    Periodic,
    AdHoc,
    IncidentResponse,
    Compliance,
    Vulnerability,
    Custom(String),
}

/// Assessment scope
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AssessmentScope {
    /// Assets included
    pub assets: Vec<String>,
    /// Systems included
    pub systems: Vec<String>,
    /// Processes included
    pub processes: Vec<String>,
    /// Departments included
    pub departments: Vec<String>,
    /// Geographic locations
    pub geographic_locations: Vec<String>,
}

/// Risk levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Risk item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskItem {
    /// Risk ID
    pub id: Uuid,
    /// Risk title
    pub title: String,
    /// Risk description
    pub description: String,
    /// Risk category
    pub category: RiskCategory,
    /// Risk score
    pub risk_score: f64,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Impact score
    pub impact_score: f64,
    /// Likelihood score
    pub likelihood_score: f64,
    /// Affected assets
    pub affected_assets: Vec<String>,
    /// Threat sources
    pub threat_sources: Vec<ThreatSource>,
    /// Existing controls
    pub existing_controls: Vec<Control>,
    /// Risk owner
    pub risk_owner: Option<String>,
    /// Risk status
    pub status: RiskStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Risk categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskCategory {
    Strategic,
    Operational,
    Financial,
    Compliance,
    Reputational,
    Security,
    Technology,
    Environmental,
    Custom(String),
}

/// Threat source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSource {
    /// Source type
    pub source_type: ThreatSourceType,
    /// Source description
    pub description: String,
    /// Capability level
    pub capability_level: CapabilityLevel,
    /// Motivation level
    pub motivation_level: MotivationLevel,
}

/// Threat source types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSourceType {
    Human,
    Natural,
    Environmental,
    Technical,
    Process,
    External,
    Internal,
    Custom(String),
}

/// Capability levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Advanced = 3,
}

/// Motivation levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MotivationLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    VeryHigh = 3,
}

/// Control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    /// Control ID
    pub id: String,
    /// Control name
    pub name: String,
    /// Control type
    pub control_type: ControlType,
    /// Control effectiveness
    pub effectiveness: f64,
    /// Control description
    pub description: String,
}

/// Control types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlType {
    Preventive,
    Detective,
    Corrective,
    Compensating,
    Deterrent,
    Directive,
}

/// Risk status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskStatus {
    Identified,
    Analyzed,
    Monitored,
    Mitigated,
    Accepted,
    Transferred,
    Closed,
}

/// Vulnerability item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityItem {
    /// Vulnerability ID
    pub id: String,
    /// Vulnerability title
    pub title: String,
    /// Vulnerability description
    pub description: String,
    /// CVSS score
    pub cvss_score: Option<f64>,
    /// Severity level
    pub severity: VulnerabilitySeverity,
    /// Affected systems
    pub affected_systems: Vec<String>,
    /// Exploitability
    pub exploitability: Exploitability,
    /// Impact
    pub impact: VulnerabilityImpact,
    /// Available patches
    pub available_patches: Vec<Patch>,
    /// Remediation status
    pub remediation_status: RemediationStatus,
    /// Discovered timestamp
    pub discovered_at: DateTime<Utc>,
    /// Published timestamp
    pub published_at: Option<DateTime<Utc>>,
}

/// Vulnerability severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnerabilitySeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Exploitability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exploitability {
    /// Exploit maturity
    pub exploit_maturity: ExploitMaturity,
    /// Exploit complexity
    pub exploit_complexity: ExploitComplexity,
    /// Available exploits
    pub available_exploits: Vec<Exploit>,
}

/// Exploit maturity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExploitMaturity {
    None,
    ProofOfConcept,
    Functional,
    High,
    Weaponized,
}

/// Exploit complexity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExploitComplexity {
    Low,
    Medium,
    High,
}

/// Exploit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exploit {
    /// Exploit ID
    pub id: String,
    /// Exploit name
    pub name: String,
    /// Exploit description
    pub description: String,
    /// Exploit source
    pub source: String,
    /// Exploit reliability
    pub reliability: f64,
}

/// Vulnerability impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityImpact {
    /// Confidentiality impact
    pub confidentiality: ImpactLevel,
    /// Integrity impact
    pub integrity: ImpactLevel,
    /// Availability impact
    pub availability: ImpactLevel,
}

/// Impact levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImpactLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

/// Patch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    /// Patch ID
    pub id: String,
    /// Patch version
    pub version: String,
    /// Patch release date
    pub release_date: DateTime<Utc>,
    /// Patch description
    pub description: String,
    /// Patch availability
    pub availability: PatchAvailability,
}

/// Patch availability
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatchAvailability {
    Available,
    Scheduled,
    NotAvailable,
    Custom(String),
}

/// Remediation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationStatus {
    NotStarted,
    InProgress,
    Completed,
    Accepted,
    NotApplicable,
}

/// Risk recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskRecommendation {
    /// Recommendation ID
    pub id: Uuid,
    /// Recommendation title
    pub title: String,
    /// Recommendation description
    pub description: String,
    /// Recommendation type
    pub recommendation_type: RecommendationType,
    /// Priority level
    pub priority: PriorityLevel,
    /// Implementation effort
    pub implementation_effort: EffortLevel,
    /// Estimated cost
    pub estimated_cost: Option<f64>,
    /// Timeline
    pub timeline: String,
    /// Expected risk reduction
    pub expected_risk_reduction: f64,
    /// Dependencies
    pub dependencies: Vec<String>,
    /// Responsible party
    pub responsible_party: Option<String>,
}

/// Recommendation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationType {
    ControlImplementation,
    ProcessImprovement,
    TechnologyUpgrade,
    PolicyChange,
    Training,
    MonitoringEnhancement,
    Custom(String),
}

/// Priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Effort levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Assessment period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentPeriod {
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
}

/// Assessor information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AssessorInfo {
    pub assessor_id: String,
    pub assessor_name: String,
    pub assessor_role: String,
    pub assessor_organization: String,
    pub certifications: Vec<String>,
    pub experience_years: u32,
}

/// Risk heat map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskHeatMap {
    /// Heat map ID
    pub id: Uuid,
    /// Grid data
    pub grid_data: Vec<HeatMapCell>,
    /// Grid size
    pub grid_size: HeatMapGridSize,
    /// Color scheme
    pub color_scheme: ColorScheme,
    /// Generated timestamp
    pub generated_at: DateTime<Utc>,
    /// Trends data
    pub trends: Option<HeatMapTrends>,
}

/// Heat map cell
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatMapCell {
    /// Row index
    pub row: u32,
    /// Column index
    pub col: u32,
    /// Risk score
    pub risk_score: f64,
    /// Risk count
    pub risk_count: u64,
    /// Color code
    pub color_code: String,
    /// Risk items
    pub risk_items: Vec<Uuid>,
}

/// Heat map trends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatMapTrends {
    /// Trend direction
    pub direction: TrendDirection,
    /// Trend percentage
    pub percentage_change: f64,
    /// Historical data points
    pub historical_data: Vec<HistoricalDataPoint>,
}

/// Trend direction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Improving,
    Stable,
    Deteriorating,
}

/// Historical data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalDataPoint {
    pub timestamp: DateTime<Utc>,
    pub risk_score: f64,
    pub risk_count: u64,
}

/// Mitigation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationPlan {
    /// Plan ID
    pub id: Uuid,
    /// Plan name
    pub name: String,
    /// Plan description
    pub description: String,
    /// Target risks
    pub target_risks: Vec<Uuid>,
    /// Mitigation actions
    pub mitigation_actions: Vec<MitigationAction>,
    /// Resource requirements
    pub resource_requirements: ResourceRequirements,
    /// Timeline
    pub timeline: MitigationTimeline,
    /// Success criteria
    pub success_criteria: Vec<String>,
    /// Monitoring plan
    pub monitoring_plan: MonitoringPlan,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub last_updated: DateTime<Utc>,
}

/// Mitigation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationAction {
    /// Action ID
    pub id: Uuid,
    /// Action title
    pub title: String,
    /// Action description
    pub description: String,
    /// Action type
    pub action_type: MitigationActionType,
    /// Priority
    pub priority: PriorityLevel,
    /// Status
    pub status: ActionStatus,
    /// Assigned to
    pub assigned_to: Option<String>,
    /// Due date
    pub due_date: Option<DateTime<Utc>>,
    /// Estimated cost
    pub estimated_cost: Option<f64>,
    /// Actual cost
    pub actual_cost: Option<f64>,
    /// Dependencies
    pub dependencies: Vec<Uuid>,
}

/// Mitigation action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationActionType {
    ControlImplementation,
    ProcessChange,
    TechnologyUpgrade,
    PolicyUpdate,
    TrainingProgram,
    MonitoringEnhancement,
    Custom(String),
}

/// Action status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionStatus {
    NotStarted,
    InProgress,
    Completed,
    OnHold,
    Cancelled,
}

/// Resource requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// Budget required
    pub budget_required: f64,
    /// Person hours required
    pub person_hours_required: u32,
    /// Technical resources required
    pub technical_resources_required: u32,
    /// External resources required
    pub external_resources_required: bool,
}

/// Mitigation timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationTimeline {
    /// Start date
    pub start_date: DateTime<Utc>,
    /// End date
    pub end_date: DateTime<Utc>,
    /// Milestones
    pub milestones: Vec<Milestone>,
}

/// Milestone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Milestone {
    /// Milestone ID
    pub id: Uuid,
    /// Milestone name
    pub name: String,
    /// Milestone description
    pub description: String,
    /// Target date
    pub target_date: DateTime<Utc>,
    /// Status
    pub status: MilestoneStatus,
}

/// Milestone status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MilestoneStatus {
    NotStarted,
    InProgress,
    Completed,
    Overdue,
}

/// Monitoring plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringPlan {
    /// Monitoring frequency
    pub frequency: MonitoringFrequency,
    /// Key metrics
    pub key_metrics: Vec<String>,
    /// Reporting requirements
    pub reporting_requirements: Vec<String>,
    /// Alert thresholds
    pub alert_thresholds: Vec<AlertThreshold>,
}

/// Monitoring frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitoringFrequency {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Custom(String),
}

/// Alert threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThreshold {
    /// Metric name
    pub metric_name: String,
    /// Threshold value
    pub threshold_value: f64,
    /// Threshold type
    pub threshold_type: ThresholdType,
    /// Alert action
    pub alert_action: AlertAction,
}

/// Threshold types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThresholdType {
    GreaterThan,
    LessThan,
    Equals,
    NotEquals,
}

/// Alert actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertAction {
    Email,
    SMS,
    Dashboard,
    Custom(String),
}

/*
// Moved to gap_analysis.rs
/// Compliance gap analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceGapAnalysisResult {
    /// Analysis ID
    pub id: Uuid,
    /// Compliance framework
    pub framework: ComplianceFramework,
    /// Overall compliance score
    pub overall_compliance_score: f64,
    /// Gap items
    pub gap_items: Vec<GapItem>,
    /// Recommendations
    pub recommendations: Vec<ComplianceRecommendation>,
    /// Analysis period
    pub analysis_period: AssessmentPeriod,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Gap item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapItem {
    /// Gap ID
    pub id: Uuid,
    /// Control requirement
    pub control_requirement: String,
    /// Current state
    pub current_state: String,
    /// Gap description
    pub gap_description: String,
    /// Gap severity
    pub gap_severity: GapSeverity,
    /// Business impact
    pub business_impact: String,
    /// Remediation effort
    pub remediation_effort: EffortLevel,
    /// Priority
    pub priority: PriorityLevel,
}

/// Gap severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Compliance recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRecommendation {
    /// Recommendation ID
    pub id: Uuid,
    /// Recommendation title
    pub title: String,
    /// Recommendation description
    pub description: String,
    /// Target gap items
    pub target_gap_items: Vec<Uuid>,
    /// Implementation timeline
    pub implementation_timeline: String,
    /// Estimated cost
    pub estimated_cost: Option<f64>,
    /// Regulatory impact
    pub regulatory_impact: String,
}
*/

impl RiskAssessmentManager {
    /// Create new risk assessment manager
    pub fn new(config: RiskAssessmentConfig) -> Result<Self> {
        info!("🎯 Initializing Risk Assessment Manager");

        let manager = Self {
            scoring_engine: RiskScoringEngine::new(RiskAssessmentConfig::default())?,
            vulnerability_manager: VulnerabilityManager::new(VulnerabilityConfig::default())?,
            heat_map_generator: RiskHeatMapGenerator::new(HeatMapConfig::default())?,
            mitigation_planner: RiskMitigationPlanner::new(MitigationConfig::default())?,
            gap_analyzer: ComplianceGapAnalyzer::new(config.gap_analysis_settings.clone())?,
            config,
            statistics: RiskAssessmentStats::default(),
        };

        info!("✅ Risk Assessment Manager initialized successfully");
        Ok(manager)
    }

    /// Run risk assessment
    pub async fn run_assessment(
        &mut self,
        assessment_type: AssessmentType,
        scope: AssessmentScope,
    ) -> Result<RiskAssessmentResult> {
        info!("🎯 Running risk assessment: {:?}", assessment_type);

        let result = self
            .scoring_engine
            .run_assessment(&format!("{:?}", assessment_type), &format!("{:?}", scope))?;

        // Update statistics
        self.update_assessment_statistics(&result);

        info!(
            "✅ Risk assessment completed: {:.1}% overall risk score",
            result.overall_risk_score
        );
        Ok(result)
    }

    /// Scan for vulnerabilities
    pub async fn scan_vulnerabilities(
        &mut self,
        scan_scope: Vec<String>,
    ) -> Result<Vec<VulnerabilityItem>> {
        info!(
            "🔍 Scanning for vulnerabilities in {} targets",
            scan_scope.len()
        );

        let vulnerabilities = self
            .vulnerability_manager
            .scan_targets(&scan_scope.join(","))?;

        // Update statistics
        self.statistics.vulnerabilities_found += vulnerabilities.len() as u64;

        info!(
            "✅ Vulnerability scan completed: {} vulnerabilities found",
            vulnerabilities.len()
        );
        Ok(vulnerabilities)
    }

    /// Generate risk heat map
    pub async fn generate_heat_map(&mut self, include_trends: bool) -> Result<RiskHeatMap> {
        debug!("🗺️ Generating risk heat map");

        let heat_map = self.heat_map_generator.generate(include_trends)?;

        info!("✅ Risk heat map generated: {}", heat_map.id);
        Ok(heat_map)
    }

    /// Create mitigation plan
    pub async fn create_mitigation_plan(
        &mut self,
        _target_risks: Vec<Uuid>,
        plan_name: String,
    ) -> Result<MitigationPlan> {
        info!("📋 Creating mitigation plan: {}", plan_name);

        let plan = self.mitigation_planner.create_plan(&[], &plan_name)?;

        // Update statistics
        self.statistics.mitigation_plans_created += 1;

        info!("✅ Mitigation plan created: {}", plan.id);
        Ok(plan)
    }

    /// Run compliance gap analysis
    pub async fn run_gap_analysis(
        &mut self,
        framework: ComplianceFramework,
        security_config: &crate::security::advanced::SecurityConfig,
    ) -> Result<ComplianceGapAnalysisResult> {
        info!("📊 Running compliance gap analysis: {:?}", framework);

        let result = self.gap_analyzer.analyze_gaps(framework, security_config)?;

        // Update statistics
        self.statistics.gap_analyses_performed += 1;

        info!(
            "✅ Gap analysis completed: {:.1}% compliance score",
            result.score * 100.0
        );
        Ok(result)
    }

    /// Get risk assessment statistics
    pub fn get_statistics(&self) -> &RiskAssessmentStats {
        &self.statistics
    }

    /// Update assessment statistics
    fn update_assessment_statistics(&mut self, result: &RiskAssessmentResult) {
        self.statistics.total_assessments += 1;
        self.statistics.avg_risk_score = (self.statistics.avg_risk_score
            * (self.statistics.total_assessments - 1) as f64
            + result.overall_risk_score)
            / self.statistics.total_assessments as f64;

        // Count high and critical risk items
        for risk_item in &result.risk_items {
            match risk_item.risk_level {
                RiskLevel::High => self.statistics.high_risk_items += 1,
                RiskLevel::Critical => self.statistics.critical_risk_items += 1,
                _ => {}
            }
        }

        self.statistics.last_assessment = result.created_at;
        self.statistics.last_update = Utc::now();
    }
}

impl Default for RiskAssessmentConfig {
    fn default() -> Self {
        Self {
            assessment_frequency_days: 30,
            scoring_methodology: ScoringMethodology::default(),
            vulnerability_management: VulnerabilityConfig::default(),
            heat_map_settings: HeatMapConfig::default(),
            mitigation_settings: MitigationConfig::default(),
            gap_analysis_settings: GapAnalysisConfig::default(),
        }
    }
}

impl Default for ScoringMethodology {
    fn default() -> Self {
        Self {
            framework: RiskFramework::NIST,
            impact_weights: ImpactWeights::default(),
            likelihood_weights: LikelihoodWeights::default(),
            custom_factors: Vec::new(),
        }
    }
}

impl Default for ImpactWeights {
    fn default() -> Self {
        Self {
            confidentiality: 0.3,
            integrity: 0.3,
            availability: 0.2,
            financial: 0.1,
            reputational: 0.05,
            operational: 0.03,
            legal: 0.02,
        }
    }
}

impl Default for LikelihoodWeights {
    fn default() -> Self {
        Self {
            threat_source: 0.3,
            vulnerability: 0.3,
            current_controls: 0.2,
            threat_motivation: 0.1,
            threat_capability: 0.1,
        }
    }
}

impl Default for VulnerabilityConfig {
    fn default() -> Self {
        Self {
            scan_frequency_hours: 24,
            sources: vec![VulnerabilitySource::NVD, VulnerabilitySource::CVE],
            cvss_min_version: 3.0,
            auto_remediation_enabled: false,
            exclusion_list: Vec::new(),
        }
    }
}

impl Default for HeatMapConfig {
    fn default() -> Self {
        Self {
            grid_size: HeatMapGridSize::Medium10x10,
            color_scheme: ColorScheme::WolfPack,
            update_frequency_hours: 12,
            include_trends: true,
        }
    }
}

impl Default for MitigationConfig {
    fn default() -> Self {
        Self {
            auto_planning_enabled: true,
            planning_methodology: PlanningMethodology::RiskBased,
            priority_weights: PriorityWeights::default(),
            resource_constraints: ResourceConstraints::default(),
        }
    }
}

impl Default for PriorityWeights {
    fn default() -> Self {
        Self {
            risk_score: 0.4,
            implementation_cost: 0.2,
            implementation_time: 0.2,
            business_impact: 0.15,
            regulatory_requirement: 0.05,
        }
    }
}

impl Default for ResourceConstraints {
    fn default() -> Self {
        Self {
            budget_limit: 100000.0,
            person_hours_limit: 2000,
            technical_resources: 10,
            time_constraints: Vec::new(),
        }
    }
}

impl Default for GapAnalysisConfig {
    fn default() -> Self {
        Self {
            analysis_frequency_days: 90,
            compliance_frameworks: vec![ComplianceFramework::SOC2, ComplianceFramework::ISO27001],
            include_recommendations: true,
            risk_tolerance_levels: RiskToleranceLevels::default(),
        }
    }
}

impl Default for RiskToleranceLevels {
    fn default() -> Self {
        Self {
            low_risk_tolerance: 0.3,
            medium_risk_tolerance: 0.6,
            high_risk_tolerance: 0.8,
            critical_risk_tolerance: 0.9,
        }
    }
}

impl Default for RiskAssessmentStats {
    fn default() -> Self {
        Self {
            total_assessments: 0,
            avg_risk_score: 0.0,
            high_risk_items: 0,
            critical_risk_items: 0,
            vulnerabilities_found: 0,
            vulnerabilities_remediated: 0,
            mitigation_plans_created: 0,
            gap_analyses_performed: 0,
            last_assessment: Utc::now(),
            last_update: Utc::now(),
        }
    }
}

impl Default for RiskAssessmentResult {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            assessment_type: AssessmentType::Initial,
            scope: AssessmentScope::default(),
            overall_risk_score: 0.0,
            risk_level: RiskLevel::Low,
            risk_items: Vec::new(),
            vulnerabilities: Vec::new(),
            recommendations: Vec::new(),
            assessment_period: AssessmentPeriod::default(),
            assessor: AssessorInfo::default(),
            created_at: Utc::now(),
        }
    }
}

impl Default for RiskHeatMap {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            grid_data: Vec::new(),
            grid_size: HeatMapGridSize::default(),
            color_scheme: ColorScheme::default(),
            generated_at: Utc::now(),
            trends: None,
        }
    }
}

impl Default for MitigationPlan {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            description: String::new(),
            target_risks: Vec::new(),
            mitigation_actions: Vec::new(),
            resource_requirements: ResourceRequirements::default(),
            timeline: MitigationTimeline::default(),
            success_criteria: Vec::new(),
            monitoring_plan: MonitoringPlan::default(),
            created_at: Utc::now(),
            last_updated: Utc::now(),
        }
    }
}

/*
impl Default for ComplianceGapAnalysisResult {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            framework: ComplianceFramework::SOC2,
            overall_compliance_score: 0.0,
            gap_items: Vec::new(),
            recommendations: Vec::new(),
            analysis_period: AssessmentPeriod::default(),
            created_at: Utc::now(),
        }
    }
}
*/

impl Default for AssessmentPeriod {
    fn default() -> Self {
        Self {
            start_date: Utc::now(),
            end_date: Utc::now(),
        }
    }
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            budget_required: 0.0,
            person_hours_required: 0,
            technical_resources_required: 0,
            external_resources_required: false,
        }
    }
}

impl Default for MitigationTimeline {
    fn default() -> Self {
        Self {
            start_date: Utc::now(),
            end_date: Utc::now(),
            milestones: Vec::new(),
        }
    }
}

impl Default for MonitoringPlan {
    fn default() -> Self {
        Self {
            frequency: MonitoringFrequency::Monthly,
            key_metrics: Vec::new(),
            reporting_requirements: Vec::new(),
            alert_thresholds: Vec::new(),
        }
    }
}
