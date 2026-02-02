use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Clone, Debug)]
pub struct ComplianceHistoryEntry {
    pub date: DateTime<Utc>,
    pub score: f64,
}

#[derive(Serialize, Clone, Debug)]
pub struct ComplianceFinding {
    pub severity: String,
    pub framework: String,
    pub control: String,
    pub status: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct ComplianceStatus {
    pub overall_score: f64,
    pub critical_findings: u32,
    pub total_findings: u32,
    pub last_assessment: DateTime<Utc>,
    pub framework_scores: HashMap<String, f64>,
    pub recent_findings: Vec<ComplianceFinding>,
    pub history: Vec<ComplianceHistoryEntry>,
    pub timestamp: DateTime<Utc>,
}

/// Service to handle compliance data retrieval and assessment logic.
pub struct ComplianceService;

impl ComplianceService {
    /// Fetches the current compliance status, including historical data for trends.
    pub async fn get_status() -> ComplianceStatus {
        let mut framework_scores = HashMap::new();

        let timestamp = Utc::now();

        framework_scores.insert("SOC2".to_string(), 94.2);
        framework_scores.insert("GDPR".to_string(), 89.5);
        framework_scores.insert("ISO27001".to_string(), 91.0);
        framework_scores.insert("NIST".to_string(), 85.4);

        // Mocking historical data for the trend chart
        let history = vec![
            ComplianceHistoryEntry {
                date: Utc::now() - Duration::days(30),
                score: 78.5,
            },
            ComplianceHistoryEntry {
                date: Utc::now() - Duration::days(20),
                score: 82.1,
            },
            ComplianceHistoryEntry {
                date: Utc::now() - Duration::days(10),
                score: 85.9,
            },
            ComplianceHistoryEntry {
                date: Utc::now() - Duration::days(5),
                score: 89.2,
            },
            ComplianceHistoryEntry {
                date: Utc::now(),
                score: 91.5,
            },
        ];

        let recent_findings = vec![
            ComplianceFinding {
                severity: "High".to_string(),
                framework: "SOC2".to_string(),
                control: "CC6.1 Logical Access".to_string(),
                status: "Failed".to_string(),
            },
            ComplianceFinding {
                severity: "Medium".to_string(),
                framework: "GDPR".to_string(),
                control: "Article 32 Security".to_string(),
                status: "Warning".to_string(),
            },
        ];

        ComplianceStatus {
            timestamp,
            overall_score: 91.5,
            critical_findings: 2,
            total_findings: 14,
            last_assessment: Utc::now(),
            framework_scores,
            recent_findings,
            history,
        }
    }
}
