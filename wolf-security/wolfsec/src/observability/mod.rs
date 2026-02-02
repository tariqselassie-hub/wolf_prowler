//! Observability Module
//!
//! Comprehensive security monitoring, alerting, and compliance reporting for Wolf Prowler.
//!
//! # Core Components
//!
//! - **Alerts**: Real-time security alert generation and management
//! - **Audit**: Comprehensive audit logging and trail management
//! - **Dashboard**: Security dashboards and visualization
//! - **Metrics**: Security metrics collection and analysis
//! - **Monitoring**: Continuous security monitoring and health checks
//! - **Reporting**: Compliance and security reporting
//! - **SIEM**: Security Information and Event Management integration
//! - **SOAR**: Security Orchestration, Automation and Response
//! - **Compliance**: Compliance framework support (SOC2, GDPR, etc.)
//! - **Predictive Analytics**: ML-based predictive security analytics
//!
//! # Example
//!
//! ```rust
//! use wolfsec::observability::{
//!     metrics::SecurityMetrics,
//!     alerts::AlertManager,
//! };
//!
//! # async fn example() -> anyhow::Result<()> {
//! let metrics = SecurityMetrics::new();
//! let alert_manager = AlertManager::new().await?;
//! # Ok(())
//! # }
//! ```

pub mod alerts;
pub mod audit;
pub mod dashboard;
pub mod metrics;
pub mod monitoring;
pub mod reporting;

// Advanced Observability
pub mod adv_alerts;
pub mod adv_audit;
pub mod adv_dashboard;
pub mod adv_metrics;
pub mod adv_reporting;
pub mod audit_trail;
pub mod compliance;
pub mod notifications;
pub mod predictive_analytics;
pub mod siem;
pub mod soar;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standardized security status levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityStatusLevel {
    Normal,
    Elevated,
    High,
    Critical,
}

impl SecurityStatusLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityStatusLevel::Normal => "normal",
            SecurityStatusLevel::Elevated => "elevated",
            SecurityStatusLevel::High => "high",
            SecurityStatusLevel::Critical => "critical",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            SecurityStatusLevel::Normal => "#4CAF50",
            SecurityStatusLevel::Elevated => "#FFC107",
            SecurityStatusLevel::High => "#FF9800",
            SecurityStatusLevel::Critical => "#F44336",
        }
    }
}

/// Core security status representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub timestamp: DateTime<Utc>,
    pub overall_status: SecurityStatusLevel,
    pub overall_level: SecurityStatusLevel, // For backwards compatibility
    pub overall_score: f64,
    pub risk_score: f64,
    pub compliance_score: f64,
    pub active_threats: usize,
    pub recent_alerts: usize,
    pub last_update: DateTime<Utc>,
    pub metrics: metrics::SecurityMetrics,
    pub component_status: HashMap<String, SecurityStatusLevel>,
    pub audit_summary: audit::AuditSummary,
}

impl Default for SecurityStatus {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            overall_status: SecurityStatusLevel::Normal,
            overall_level: SecurityStatusLevel::Normal,
            overall_score: 1.0,
            risk_score: 0.0,
            compliance_score: 1.0,
            active_threats: 0,
            recent_alerts: 0,
            last_update: Utc::now(),
            metrics: metrics::SecurityMetrics::default(),
            component_status: HashMap::new(),
            audit_summary: audit::AuditSummary::default(),
        }
    }
}

/// Time range for security queries and reports
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
