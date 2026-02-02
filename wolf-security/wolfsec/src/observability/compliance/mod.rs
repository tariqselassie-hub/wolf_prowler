//! Compliance Framework Module
//!
//! Enterprise compliance management with wolf pack governance principles.
//! Wolves maintain pack order through established rules and hierarchical compliance.

pub mod gdpr;
pub mod hipaa;
pub mod iso27001;
pub mod nist;
pub mod pci_dss;
pub mod reporting;
pub mod soc2;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub use gdpr::GDPRComplianceManager;
pub use hipaa::HIPAAComplianceManager;
pub use iso27001::ISO27001ComplianceManager;
pub use nist::NISTComplianceManager;
pub use pci_dss::PCIDSSComplianceManager;
pub use reporting::ComplianceReporter;
/// Re-export main components
pub use soc2::SOC2ComplianceManager;

/// Main compliance framework manager
pub struct ComplianceFrameworkManager {
    /// SOC2 compliance
    soc2_manager: SOC2ComplianceManager,
    /// ISO27001 compliance
    iso27001_manager: ISO27001ComplianceManager,
    /// GDPR compliance
    gdpr_manager: GDPRComplianceManager,
    /// HIPAA compliance
    hipaa_manager: HIPAAComplianceManager,
    /// PCI DSS compliance
    pci_dss_manager: PCIDSSComplianceManager,
    /// NIST framework
    nist_manager: NISTComplianceManager,
    /// Compliance reporting
    reporting: ComplianceReporter,
    /// Configuration
    config: ComplianceConfig,
    /// Statistics
    statistics: ComplianceStats,
}

/// Compliance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Enabled compliance frameworks
    pub enabled_frameworks: Vec<ComplianceFramework>,
    /// Assessment frequency in days
    pub assessment_frequency_days: u32,
    /// Report generation frequency in days
    pub reporting_frequency_days: u32,
    /// Evidence retention period in days
    pub evidence_retention_days: u32,
    /// Auto-remediation enabled
    pub auto_remediation_enabled: bool,
    /// Alert thresholds
    pub alert_thresholds: ComplianceAlertThresholds,
}

/// Compliance frameworks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComplianceFramework {
    SOC2,
    ISO27001,
    GDPR,
    HIPAA,
    PCIDSS,
    NIST,
    Custom(String),
}

impl Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplianceFramework::SOC2 => write!(f, "SOC2"),
            ComplianceFramework::ISO27001 => write!(f, "ISO27001"),
            ComplianceFramework::GDPR => write!(f, "GDPR"),
            ComplianceFramework::HIPAA => write!(f, "HIPAA"),
            ComplianceFramework::PCIDSS => write!(f, "PCI DSS"),
            ComplianceFramework::NIST => write!(f, "NIST"),
            ComplianceFramework::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// Compliance alert thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAlertThresholds {
    /// Non-compliance threshold
    pub non_compliance_threshold: f64,
    /// Critical control failure threshold
    pub critical_control_threshold: f64,
    /// Evidence missing threshold
    pub evidence_missing_threshold: f64,
    /// Policy violation threshold
    pub policy_violation_threshold: f64,
}

/// Compliance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStats {
    /// Total assessments performed
    pub total_assessments: u64,
    /// Compliance score by framework
    pub compliance_scores: HashMap<ComplianceFramework, f64>,
    /// Open findings by severity
    pub open_findings: HashMap<FindingSeverity, u64>,
    /// Remediation statistics
    pub remediation_stats: RemediationStats,
    /// Last assessment timestamp
    pub last_assessment: DateTime<Utc>,
    /// Last report generation
    pub last_report: DateTime<Utc>,
}

/// Remediation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStats {
    /// Total findings
    pub total_findings: u64,
    /// Remediated findings
    pub remediated_findings: u64,
    /// Open findings
    pub open_findings: u64,
    /// Average remediation time in days
    pub avg_remediation_time_days: f64,
    /// Overdue findings
    pub overdue_findings: u64,
}

/// Compliance assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAssessmentResult {
    /// Assessment ID
    pub id: Uuid,
    /// Framework being assessed
    pub framework: ComplianceFramework,
    /// Assessment type
    pub assessment_type: AssessmentType,
    /// Overall compliance score
    pub compliance_score: f64,
    /// Control results
    pub control_results: Vec<ControlResult>,
    /// Findings
    pub findings: Vec<ComplianceFinding>,
    /// Evidence collected
    pub evidence_collected: Vec<EvidenceItem>,
    /// Recommendations
    pub recommendations: Vec<Recommendation>,
    /// Assessment period
    pub assessment_period: AssessmentPeriod,
    /// Assessor information
    pub assessor: AssessorInfo,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Assessment types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssessmentType {
    Initial,
    Periodic,
    AdHoc,
    IncidentResponse,
    FollowUp,
}

/// Control result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    /// Control ID
    pub control_id: String,
    /// Control name
    pub control_name: String,
    /// Control category
    pub control_category: String,
    /// Control status
    pub status: ControlStatus,
    /// Compliance score
    pub compliance_score: f64,
    /// Evidence references
    pub evidence_refs: Vec<String>,
    /// Findings
    pub findings: Vec<String>,
    /// Last tested
    pub last_tested: DateTime<Utc>,
    /// Next test due
    pub next_test_due: DateTime<Utc>,
}

/// Control status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotApplicable,
    NotTested,
}

/// Compliance finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Finding ID
    pub id: Uuid,
    /// Finding title
    pub title: String,
    /// Finding description
    pub description: String,
    /// Finding severity
    pub severity: FindingSeverity,
    /// Finding category
    pub category: FindingCategory,
    /// Affected controls
    pub affected_controls: Vec<String>,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Evidence references
    pub evidence_refs: Vec<String>,
    /// Due date
    pub due_date: DateTime<Utc>,
    /// Assigned to
    pub assigned_to: Option<String>,
    /// Status
    pub status: FindingStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Finding severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Finding categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingCategory {
    PolicyViolation,
    ControlFailure,
    ProcessGap,
    TechnicalIssue,
    DocumentationIssue,
    AccessControl,
    DataProtection,
    IncidentResponse,
}

/// Risk levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Finding status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
    InProgress,
    Remediated,
    Verified,
    Closed,
    Accepted,
}

/// Evidence item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Evidence ID
    pub id: Uuid,
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Evidence description
    pub description: String,
    /// Evidence location
    pub location: String,
    /// Collection timestamp
    pub collected_at: DateTime<Utc>,
    /// Collected by
    pub collected_by: String,
    /// Hash for integrity
    pub hash: String,
    /// Valid until
    pub valid_until: DateTime<Utc>,
    /// Associated controls
    pub associated_controls: Vec<String>,
}

/// Evidence types
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum EvidenceType {
    Screenshot,
    LogFile,
    Configuration,
    PolicyDocument,
    ProcedureDocument,
    InterviewNotes,
    SystemOutput,
    NetworkCapture,
    TestResult,
    Certification,
}

/// Recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Recommendation ID
    pub id: Uuid,
    /// Recommendation title
    pub title: String,
    /// Recommendation description
    pub description: String,
    /// Priority
    pub priority: RecommendationPriority,
    /// Effort required
    pub effort: EffortLevel,
    /// Expected impact
    pub expected_impact: String,
    /// Dependencies
    pub dependencies: Vec<String>,
    /// Timeline
    pub timeline: String,
    /// Cost estimate
    pub cost_estimate: Option<String>,
}

/// Recommendation priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecommendationPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Effort level
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
    pub duration_days: u32,
}

/// Assessor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessorInfo {
    pub assessor_id: String,
    pub assessor_name: String,
    pub assessor_role: String,
    pub assessor_organization: String,
    pub certifications: Vec<String>,
    pub experience_years: u32,
}

impl ComplianceFrameworkManager {
    /// Create new compliance framework manager
    pub fn new(config: ComplianceConfig) -> Result<Self> {
        info!("📋 Initializing Compliance Framework Manager");

        let manager = Self {
            soc2_manager: SOC2ComplianceManager::new(config.clone())?,
            iso27001_manager: ISO27001ComplianceManager::new(config.clone())?,
            gdpr_manager: GDPRComplianceManager::new(config.clone())?,
            hipaa_manager: HIPAAComplianceManager::new(config.clone())?,
            pci_dss_manager: PCIDSSComplianceManager::new(config.clone())?,
            nist_manager: NISTComplianceManager::new(config.clone())?,
            reporting: ComplianceReporter::new(config.clone())?,
            config,
            statistics: ComplianceStats::default(),
        };

        info!("✅ Compliance Framework Manager initialized successfully");
        Ok(manager)
    }

    /// Run compliance assessment
    pub async fn run_assessment(
        &mut self,
        framework: ComplianceFramework,
        assessment_type: AssessmentType,
    ) -> Result<ComplianceAssessmentResult> {
        info!(
            "🔍 Running {} compliance assessment: {:?}",
            framework, assessment_type
        );

        let result = match framework {
            ComplianceFramework::SOC2 => self.soc2_manager.run_assessment(assessment_type).await?,
            ComplianceFramework::ISO27001 => {
                self.iso27001_manager
                    .run_assessment(assessment_type)
                    .await?
            }
            ComplianceFramework::GDPR => self.gdpr_manager.run_assessment(assessment_type).await?,
            ComplianceFramework::HIPAA => {
                self.hipaa_manager.run_assessment(assessment_type).await?
            }
            ComplianceFramework::PCIDSS => {
                self.pci_dss_manager.run_assessment(assessment_type).await?
            }
            ComplianceFramework::NIST => self.nist_manager.run_assessment(assessment_type).await?,
            ComplianceFramework::Custom(_) => {
                // Mock implementation for custom framework
                ComplianceAssessmentResult {
                    id: Uuid::new_v4(),
                    framework: framework.clone(),
                    assessment_type: assessment_type.clone(),
                    timestamp: Utc::now(),
                    compliance_score: 0.0,
                    control_results: Vec::new(),
                    findings: Vec::new(),
                    evidence_collected: Vec::new(),
                    recommendations: Vec::new(),
                    assessment_period: AssessmentPeriod {
                        start_date: Utc::now() - chrono::Duration::days(30),
                        end_date: Utc::now(),
                        duration_days: 30,
                    },
                    assessor: AssessorInfo {
                        assessor_id: "automated-wolf".to_string(),
                        assessor_name: "Automated Wolf".to_string(),
                        assessor_role: "Security System".to_string(),
                        assessor_organization: "Wolf Prowler".to_string(),
                        certifications: Vec::new(),
                        experience_years: 0,
                    },
                }
            }
        };

        // Update statistics
        self.update_assessment_statistics(&result);

        // Generate alerts if needed
        self.check_compliance_alerts(&result).await?;

        info!(
            "✅ Compliance assessment completed: {:.1}% compliance score",
            result.compliance_score
        );
        Ok(result)
    }

    /// Generate compliance report
    pub async fn generate_report(
        &mut self,
        framework: ComplianceFramework,
        report_type: ReportType,
    ) -> Result<ComplianceReport> {
        debug!(
            "📊 Generating {} compliance report: {:?}",
            framework, report_type
        );

        let report = self
            .reporting
            .generate_report(framework, report_type)
            .await?;

        self.statistics.last_report = Utc::now();

        info!("✅ Compliance report generated: {}", report.id);
        Ok(report)
    }

    /// Get compliance status
    pub async fn get_compliance_status(&mut self) -> Result<ComplianceStatus> {
        debug!("📊 Getting overall compliance status");

        let mut framework_scores = HashMap::new();

        for framework in &self.config.enabled_frameworks {
            let score = self.get_framework_compliance_score(framework).await?;
            framework_scores.insert(framework.clone(), score);
        }

        let overall_score = framework_scores.values().sum::<f64>() / framework_scores.len() as f64;

        Ok(ComplianceStatus {
            overall_score,
            framework_scores,
            total_findings: self.get_total_findings().await?,
            critical_findings: self.get_critical_findings().await?,
            overdue_findings: self.get_overdue_findings().await?,
            last_assessment: self.statistics.last_assessment,
            next_assessment: self.calculate_next_assessment(),
        })
    }

    /// Remediate finding
    pub async fn remediate_finding(
        &mut self,
        finding_id: Uuid,
        remediation_evidence: Vec<EvidenceItem>,
    ) -> Result<()> {
        info!("🔧 Remediating compliance finding: {}", finding_id);

        // Update finding status across all frameworks
        self.soc2_manager
            .remediate_finding(finding_id, remediation_evidence.clone())
            .await?;
        self.iso27001_manager
            .remediate_finding(finding_id, remediation_evidence.clone())
            .await?;
        self.gdpr_manager
            .remediate_finding(finding_id, remediation_evidence.clone())
            .await?;
        self.hipaa_manager
            .remediate_finding(finding_id, remediation_evidence.clone())
            .await?;
        self.pci_dss_manager
            .remediate_finding(finding_id, remediation_evidence.clone())
            .await?;
        self.nist_manager
            .remediate_finding(finding_id, remediation_evidence)
            .await?;

        // Update statistics
        self.statistics.remediation_stats.remediated_findings += 1;
        self.statistics.remediation_stats.open_findings = self
            .statistics
            .remediation_stats
            .open_findings
            .saturating_sub(1);

        info!("✅ Compliance finding remediated: {}", finding_id);
        Ok(())
    }

    /// Collect evidence
    pub async fn collect_evidence(
        &mut self,
        evidence_request: EvidenceRequest,
    ) -> Result<Vec<EvidenceItem>> {
        debug!("🔍 Collecting compliance evidence");

        let mut evidence = Vec::new();

        // Collect evidence from all enabled frameworks
        for framework in &self.config.enabled_frameworks {
            let framework_evidence = match framework {
                ComplianceFramework::SOC2 => {
                    self.soc2_manager
                        .collect_evidence(&evidence_request)
                        .await?
                }
                ComplianceFramework::ISO27001 => {
                    self.iso27001_manager
                        .collect_evidence(&evidence_request)
                        .await?
                }
                ComplianceFramework::GDPR => {
                    self.gdpr_manager
                        .collect_evidence(&evidence_request)
                        .await?
                }
                ComplianceFramework::HIPAA => {
                    self.hipaa_manager
                        .collect_evidence(&evidence_request)
                        .await?
                }
                ComplianceFramework::PCIDSS => {
                    self.pci_dss_manager
                        .collect_evidence(&evidence_request)
                        .await?
                }
                ComplianceFramework::NIST => {
                    self.nist_manager
                        .collect_evidence(&evidence_request)
                        .await?
                }
                ComplianceFramework::Custom(_) => Vec::new(),
            };

            evidence.extend(framework_evidence);
        }

        info!("✅ Collected {} evidence items", evidence.len());
        Ok(evidence)
    }

    /// Get compliance statistics
    pub fn get_statistics(&self) -> &ComplianceStats {
        &self.statistics
    }

    /// Update assessment statistics
    fn update_assessment_statistics(&mut self, result: &ComplianceAssessmentResult) {
        self.statistics.total_assessments += 1;
        self.statistics
            .compliance_scores
            .insert(result.framework.clone(), result.compliance_score);
        self.statistics.last_assessment = result.timestamp;

        // Update finding statistics
        for finding in &result.findings {
            *self
                .statistics
                .open_findings
                .entry(finding.severity.clone())
                .or_insert(0) += 1;
        }
    }

    /// Check compliance alerts
    async fn check_compliance_alerts(&mut self, result: &ComplianceAssessmentResult) -> Result<()> {
        if result.compliance_score < self.config.alert_thresholds.non_compliance_threshold {
            warn!(
                "⚠️ Compliance score below threshold: {:.1}%",
                result.compliance_score
            );
            // In a real implementation, this would trigger alerts
        }

        let critical_findings = result
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Critical)
            .count();

        if critical_findings as f64 > self.config.alert_thresholds.critical_control_threshold {
            warn!(
                "⚠️ Critical findings exceed threshold: {}",
                critical_findings
            );
            // In a real implementation, this would trigger alerts
        }

        Ok(())
    }

    /// Get framework compliance score
    async fn get_framework_compliance_score(&self, framework: &ComplianceFramework) -> Result<f64> {
        Ok(self
            .statistics
            .compliance_scores
            .get(framework)
            .copied()
            .unwrap_or(0.0))
    }

    /// Get total findings
    async fn get_total_findings(&self) -> Result<u64> {
        Ok(self.statistics.open_findings.values().sum())
    }

    /// Get critical findings
    async fn get_critical_findings(&self) -> Result<u64> {
        Ok(self
            .statistics
            .open_findings
            .get(&FindingSeverity::Critical)
            .copied()
            .unwrap_or(0))
    }

    /// Get overdue findings
    async fn get_overdue_findings(&self) -> Result<u64> {
        Ok(self.statistics.remediation_stats.overdue_findings)
    }

    /// Calculate next assessment date
    fn calculate_next_assessment(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::days(self.config.assessment_frequency_days as i64)
    }
}

/// Compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub overall_score: f64,
    pub framework_scores: HashMap<ComplianceFramework, f64>,
    pub total_findings: u64,
    pub critical_findings: u64,
    pub overdue_findings: u64,
    pub last_assessment: DateTime<Utc>,
    pub next_assessment: DateTime<Utc>,
}

/// Compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub id: Uuid,
    pub framework: ComplianceFramework,
    pub report_type: ReportType,
    pub generated_at: DateTime<Utc>,
    pub report_period: AssessmentPeriod,
    pub executive_summary: String,
    pub compliance_score: f64,
    pub key_findings: Vec<ComplianceFinding>,
    pub recommendations: Vec<Recommendation>,
    pub evidence_summary: EvidenceSummary,
    pub trend_analysis: TrendAnalysis,
}

/// Report types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportType {
    Executive,
    Detailed,
    Technical,
    Management,
    Auditor,
}

/// Evidence summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub total_evidence_items: u64,
    pub evidence_by_type: HashMap<EvidenceType, u64>,
    pub coverage_percentage: f64,
    pub quality_score: f64,
}

/// Trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub compliance_trend: TrendDirection,
    pub findings_trend: TrendDirection,
    pub remediation_trend: TrendDirection,
    pub trend_period_days: u32,
}

/// Trend direction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Improving,
    Stable,
    Declining,
}

/// Evidence request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRequest {
    pub control_ids: Vec<String>,
    pub evidence_types: Vec<EvidenceType>,
    pub date_range: AssessmentPeriod,
    pub collection_method: CollectionMethod,
}

/// Collection method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CollectionMethod {
    Automated,
    Manual,
    Hybrid,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            enabled_frameworks: vec![
                ComplianceFramework::SOC2,
                ComplianceFramework::ISO27001,
                ComplianceFramework::NIST,
            ],
            assessment_frequency_days: 90,
            reporting_frequency_days: 30,
            evidence_retention_days: 2555, // 7 years
            auto_remediation_enabled: false,
            alert_thresholds: ComplianceAlertThresholds::default(),
        }
    }
}

impl Default for ComplianceAlertThresholds {
    fn default() -> Self {
        Self {
            non_compliance_threshold: 0.8,
            critical_control_threshold: 5.0,
            evidence_missing_threshold: 10.0,
            policy_violation_threshold: 3.0,
        }
    }
}

impl Default for ComplianceStats {
    fn default() -> Self {
        Self {
            total_assessments: 0,
            compliance_scores: HashMap::new(),
            open_findings: HashMap::new(),
            remediation_stats: RemediationStats::default(),
            last_assessment: Utc::now(),
            last_report: Utc::now(),
        }
    }
}

impl Default for RemediationStats {
    fn default() -> Self {
        Self {
            total_findings: 0,
            remediated_findings: 0,
            open_findings: 0,
            avg_remediation_time_days: 0.0,
            overdue_findings: 0,
        }
    }
}
