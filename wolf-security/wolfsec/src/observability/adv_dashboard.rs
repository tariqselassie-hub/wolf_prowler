//! Security Dashboard
//!
//! Real-time security visibility dashboard with metrics, alerts, and monitoring

#![allow(unused_imports)]
#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use super::{SecurityStatus, SecurityStatusLevel, TimeRange};
use anyhow::Error;

/// Security dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDashboardConfig {
    /// Refresh interval in seconds
    pub refresh_interval_secs: u64,
    /// Maximum number of alerts to display
    pub max_alerts_displayed: usize,
    /// Enable real-time updates
    pub enable_real_time_updates: bool,
    /// Dashboard theme
    pub theme: DashboardTheme,
    /// Widget configuration
    pub widgets: WidgetConfig,
}

impl Default for SecurityDashboardConfig {
    fn default() -> Self {
        Self {
            refresh_interval_secs: 5,
            max_alerts_displayed: 50,
            enable_real_time_updates: true,
            theme: DashboardTheme::Dark,
            widgets: WidgetConfig::default(),
        }
    }
}

/// Dashboard theme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DashboardTheme {
    Light,
    Dark,
    Auto,
}

/// Widget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetConfig {
    /// Show security status widget
    pub show_security_status: bool,
    /// Show metrics widget
    pub show_metrics: bool,
    /// Show alerts widget
    pub show_alerts: bool,
    /// Show audit trail widget
    pub show_audit_trail: bool,
    /// Show performance widget
    pub show_performance: bool,
    /// Show network security widget
    pub show_network_security: bool,
}

impl Default for WidgetConfig {
    fn default() -> Self {
        Self {
            show_security_status: true,
            show_metrics: true,
            show_alerts: true,
            show_audit_trail: true,
            show_performance: true,
            show_network_security: true,
        }
    }
}

/// Security dashboard data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDashboardData {
    pub timestamp: DateTime<Utc>,
    pub security_status: SecurityStatus,
    pub widgets: HashMap<String, WidgetData>,
    pub alerts: Vec<super::alerts::SecurityAlert>,
    pub performance_metrics: PerformanceMetrics,
    pub network_security: NetworkSecurityMetrics,
}

/// Widget data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WidgetData {
    SecurityStatus(SecurityStatusWidget),
    Metrics(MetricsWidget),
    Alerts(AlertsWidget),
    AuditTrail(AuditTrailWidget),
    Performance(PerformanceWidget),
    NetworkSecurity(NetworkSecurityWidget),
}

/// Security status widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatusWidget {
    pub status: SecurityStatusLevel,
    pub status_text: String,
    pub color_code: String,
    pub last_updated: DateTime<Utc>,
    pub uptime_percentage: f64,
    pub threat_level: ThreatLevel,
}

/// Metrics widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsWidget {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub success_rate: f64,
    pub anomaly_score: f64,
    pub security_score: f64,
    pub last_updated: DateTime<Utc>,
}

/// Alerts widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsWidget {
    pub total_alerts: usize,
    pub critical_alerts: usize,
    pub high_alerts: usize,
    pub medium_alerts: usize,
    pub low_alerts: usize,
    pub recent_alerts: Vec<super::alerts::SecurityAlert>,
    pub last_updated: DateTime<Utc>,
}

/// Audit trail widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrailWidget {
    pub total_audits: u64,
    pub recent_audits: Vec<super::audit::AuditEntry>,
    pub audit_frequency: HashMap<String, u64>,
    pub last_updated: DateTime<Utc>,
}

/// Performance widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceWidget {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub network_io: NetworkIO,
    pub response_times: ResponseTimeMetrics,
    pub last_updated: DateTime<Utc>,
}

/// Network security widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityWidget {
    pub total_connections: u64,
    pub active_connections: u64,
    pub blocked_connections: u64,
    pub security_events: Vec<SecurityEvent>,
    pub threat_indicators: Vec<ThreatIndicator>,
    pub last_updated: DateTime<Utc>,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub disk_usage_percent: f64,
    pub network_io_bytes_per_second: f64,
    pub response_time_ms: f64,
    pub throughput_operations_per_second: f64,
}

/// Network security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityMetrics {
    pub total_peers: u64,
    pub trusted_peers: u64,
    pub suspicious_peers: u64,
    pub blocked_peers: u64,
    pub encrypted_connections: u64,
    pub authentication_success_rate: f64,
}

/// Network I/O metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIO {
    pub bytes_in_per_second: f64,
    pub bytes_out_per_second: f64,
    pub packets_in_per_second: f64,
    pub packets_out_per_second: f64,
}

/// Response time metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTimeMetrics {
    pub average_ms: f64,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

/// Security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub severity: super::alerts::AlertSeverity,
    pub source: String,
    pub description: String,
    pub metadata: HashMap<String, String>,
}

/// Security event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    AuthenticationFailure,
    UnauthorizedAccess,
    SuspiciousActivity,
    AnomalyDetected,
    ConfigurationChange,
    SecurityPolicyViolation,
    NetworkIntrusion,
    DataBreach,
}

/// Threat level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatLevel::Low => "low",
            ThreatLevel::Medium => "medium",
            ThreatLevel::High => "high",
            ThreatLevel::Critical => "critical",
        }
    }

    pub fn color_code(&self) -> &'static str {
        match self {
            ThreatLevel::Low => "#4CAF50",      // Green
            ThreatLevel::Medium => "#FFC107",   // Yellow
            ThreatLevel::High => "#FF9800",     // Orange
            ThreatLevel::Critical => "#F44336", // Red
        }
    }
}

/// Threat indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: ThreatIndicatorType,
    pub severity: super::alerts::AlertSeverity,
    pub confidence: f64,
    pub source: String,
    pub description: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Threat indicator type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatIndicatorType {
    SuspiciousIP,
    MaliciousDomain,
    UnusualTrafficPattern,
    AuthenticationAnomaly,
    ConfigurationAnomaly,
    PerformanceAnomaly,
}

/// Security dashboard
pub struct SecurityDashboard {
    config: SecurityDashboardConfig,
    data: Arc<RwLock<SecurityDashboardData>>,
    is_running: Arc<RwLock<bool>>,
}

impl SecurityDashboard {
    /// Create a new security dashboard
    pub async fn new(config: SecurityDashboardConfig) -> Result<Self, Error> {
        info!("Initializing security dashboard");

        let dashboard = Self {
            config: config.clone(),
            data: Arc::new(RwLock::new(SecurityDashboardData {
                timestamp: Utc::now(),
                security_status: SecurityStatus {
                    timestamp: Utc::now(),
                    overall_status: SecurityStatusLevel::Normal,
                    overall_level: SecurityStatusLevel::Normal,
                    overall_score: 1.0,
                    risk_score: 0.0,
                    compliance_score: 1.0,
                    active_threats: 0,
                    recent_alerts: 0,
                    last_update: Utc::now(),
                    metrics: super::metrics::SecurityMetrics::default(),
                    component_status: HashMap::new(),
                    audit_summary: super::audit::AuditSummary::default(),
                },
                widgets: HashMap::new(),
                alerts: Vec::new(),
                performance_metrics: PerformanceMetrics::default(),
                network_security: NetworkSecurityMetrics::default(),
            })),
            is_running: Arc::new(RwLock::new(false)),
        };

        // Initialize widgets
        dashboard.initialize_widgets().await?;

        info!("Security dashboard initialized successfully");
        Ok(dashboard)
    }

    /// Initialize dashboard widgets
    async fn initialize_widgets(&self) -> Result<(), Error> {
        let mut data = self.data.write().await;

        if self.config.widgets.show_security_status {
            data.widgets.insert(
                "security_status".to_string(),
                WidgetData::SecurityStatus(SecurityStatusWidget {
                    status: SecurityStatusLevel::Normal,
                    status_text: "All systems operational".to_string(),
                    color_code: SecurityStatusLevel::Normal.color_code().to_string(),
                    last_updated: Utc::now(),
                    uptime_percentage: 100.0,
                    threat_level: ThreatLevel::Low,
                }),
            );
        }

        if self.config.widgets.show_metrics {
            data.widgets.insert(
                "metrics".to_string(),
                WidgetData::Metrics(MetricsWidget {
                    total_operations: 0,
                    successful_operations: 0,
                    failed_operations: 0,
                    success_rate: 100.0,
                    anomaly_score: 0.0,
                    security_score: 100.0,
                    last_updated: Utc::now(),
                }),
            );
        }

        if self.config.widgets.show_alerts {
            data.widgets.insert(
                "alerts".to_string(),
                WidgetData::Alerts(AlertsWidget {
                    total_alerts: 0,
                    critical_alerts: 0,
                    high_alerts: 0,
                    medium_alerts: 0,
                    low_alerts: 0,
                    recent_alerts: Vec::new(),
                    last_updated: Utc::now(),
                }),
            );
        }

        if self.config.widgets.show_audit_trail {
            data.widgets.insert(
                "audit_trail".to_string(),
                WidgetData::AuditTrail(AuditTrailWidget {
                    total_audits: 0,
                    recent_audits: Vec::new(),
                    audit_frequency: HashMap::new(),
                    last_updated: Utc::now(),
                }),
            );
        }

        if self.config.widgets.show_performance {
            data.widgets.insert(
                "performance".to_string(),
                WidgetData::Performance(PerformanceWidget {
                    cpu_usage: 0.0,
                    memory_usage: 0.0,
                    network_io: NetworkIO {
                        bytes_in_per_second: 0.0,
                        bytes_out_per_second: 0.0,
                        packets_in_per_second: 0.0,
                        packets_out_per_second: 0.0,
                    },
                    response_times: ResponseTimeMetrics {
                        average_ms: 0.0,
                        median_ms: 0.0,
                        p95_ms: 0.0,
                        p99_ms: 0.0,
                        max_ms: 0.0,
                    },
                    last_updated: Utc::now(),
                }),
            );
        }

        if self.config.widgets.show_network_security {
            data.widgets.insert(
                "network_security".to_string(),
                WidgetData::NetworkSecurity(NetworkSecurityWidget {
                    total_connections: 0,
                    active_connections: 0,
                    blocked_connections: 0,
                    security_events: Vec::new(),
                    threat_indicators: Vec::new(),
                    last_updated: Utc::now(),
                }),
            );
        }

        Ok(())
    }

    /// Get current dashboard data
    #[instrument(skip(self))]
    pub async fn get_dashboard_data(&self) -> SecurityDashboardData {
        self.data.read().await.clone()
    }

    /// Update dashboard data
    #[instrument(skip(self))]
    pub async fn update_dashboard_data(
        &self,
        new_data: SecurityDashboardData,
    ) -> Result<(), Error> {
        let mut data = self.data.write().await;
        *data = new_data;
        Ok(())
    }

    /// Get real-time metrics
    #[instrument(skip(self))]
    pub async fn get_realtime_metrics(&self) -> super::metrics::SecurityMetrics {
        let data = self.data.read().await;
        data.security_status.metrics.clone()
    }

    /// Get recent alerts
    #[instrument(skip(self))]
    pub async fn get_recent_alerts(&self, limit: usize) -> Vec<super::alerts::SecurityAlert> {
        let data = self.data.read().await;
        data.alerts.iter().take(limit).cloned().collect()
    }

    /// Get security status
    #[instrument(skip(self))]
    pub async fn get_security_status(&self) -> SecurityStatus {
        let data = self.data.read().await;
        data.security_status.clone()
    }

    /// Update security status
    #[instrument(skip(self))]
    pub async fn update_security_status(&self, status: SecurityStatus) -> Result<(), Error> {
        let mut data = self.data.write().await;
        data.security_status = status;
        data.timestamp = Utc::now();
        Ok(())
    }

    /// Add security alert
    #[instrument(skip(self))]
    pub async fn add_alert(&self, alert: super::alerts::SecurityAlert) -> Result<(), Error> {
        let mut data = self.data.write().await;

        // Add alert to the list
        data.alerts.push(alert.clone());

        // Sort alerts by timestamp (newest first)
        data.alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Limit number of alerts
        if data.alerts.len() > self.config.max_alerts_displayed {
            data.alerts.truncate(self.config.max_alerts_displayed);
        }

        // Pre-calculate data to avoid borrow checker issues
        let total_alerts = data.alerts.len();
        let critical_alerts = data
            .alerts
            .iter()
            .filter(|a| a.severity == super::alerts::AlertSeverity::Critical)
            .count();
        let high_alerts = data
            .alerts
            .iter()
            .filter(|a| a.severity == super::alerts::AlertSeverity::High)
            .count();
        let medium_alerts = data
            .alerts
            .iter()
            .filter(|a| a.severity == super::alerts::AlertSeverity::Medium)
            .count();
        let low_alerts = data
            .alerts
            .iter()
            .filter(|a| a.severity == super::alerts::AlertSeverity::Low)
            .count();
        let recent_alerts: Vec<_> = data.alerts.iter().take(10).cloned().collect();

        // Update alerts widget
        if let Some(WidgetData::Alerts(alerts_widget)) = data.widgets.get_mut("alerts") {
            alerts_widget.total_alerts = total_alerts;
            alerts_widget.critical_alerts = critical_alerts;
            alerts_widget.high_alerts = high_alerts;
            alerts_widget.medium_alerts = medium_alerts;
            alerts_widget.low_alerts = low_alerts;
            alerts_widget.recent_alerts = recent_alerts;
            alerts_widget.last_updated = Utc::now();
        }

        data.timestamp = Utc::now();
        Ok(())
    }

    /// Update performance metrics
    #[instrument(skip(self))]
    pub async fn update_performance_metrics(
        &self,
        metrics: PerformanceMetrics,
    ) -> Result<(), Error> {
        let mut data = self.data.write().await;
        data.performance_metrics = metrics.clone();

        // Update performance widget
        if let Some(WidgetData::Performance(performance_widget)) =
            data.widgets.get_mut("performance")
        {
            performance_widget.cpu_usage = metrics.cpu_usage_percent;
            performance_widget.memory_usage = metrics.memory_usage_percent;
            performance_widget.network_io = NetworkIO {
                bytes_in_per_second: metrics.network_io_bytes_per_second,
                bytes_out_per_second: metrics.network_io_bytes_per_second,
                packets_in_per_second: 0.0, // Would need separate tracking
                packets_out_per_second: 0.0, // Would need separate tracking
            };
            performance_widget.response_times = ResponseTimeMetrics {
                average_ms: metrics.response_time_ms,
                median_ms: metrics.response_time_ms, // Simplified
                p95_ms: metrics.response_time_ms,    // Simplified
                p99_ms: metrics.response_time_ms,    // Simplified
                max_ms: metrics.response_time_ms,    // Simplified
            };
            performance_widget.last_updated = Utc::now();
        }

        data.timestamp = Utc::now();
        Ok(())
    }

    /// Update network security metrics
    #[instrument(skip(self))]
    pub async fn update_network_security_metrics(
        &self,
        metrics: NetworkSecurityMetrics,
    ) -> Result<(), Error> {
        let mut data = self.data.write().await;
        data.network_security = metrics.clone();

        // Update network security widget
        if let Some(WidgetData::NetworkSecurity(network_widget)) =
            data.widgets.get_mut("network_security")
        {
            network_widget.total_connections = metrics.total_peers;
            network_widget.active_connections = metrics.trusted_peers;
            network_widget.blocked_connections = metrics.blocked_peers;
            network_widget.last_updated = Utc::now();
        }

        data.timestamp = Utc::now();
        Ok(())
    }

    /// Start dashboard updates
    #[instrument(skip(self))]
    pub async fn start_updates(&self) -> Result<(), Error> {
        let mut is_running = self.is_running.write().await;

        if *is_running {
            warn!("Dashboard updates are already running");
            return Ok(());
        }

        *is_running = true;
        info!("Starting dashboard updates");

        if self.config.enable_real_time_updates {
            let config = self.config.clone();
            let data = Arc::clone(&self.data);
            let is_running = Arc::clone(&self.is_running);

            tokio::spawn(async move {
                while *is_running.read().await {
                    // Update dashboard data
                    if let Err(e) = Self::refresh_dashboard_data(&data, &config).await {
                        error!("Failed to refresh dashboard data: {}", e);
                    }

                    // Wait for next update
                    tokio::time::sleep(tokio::time::Duration::from_secs(
                        config.refresh_interval_secs,
                    ))
                    .await;
                }
            });
        }

        Ok(())
    }

    /// Stop dashboard updates
    #[instrument(skip(self))]
    pub async fn stop_updates(&self) -> Result<(), Error> {
        let mut is_running = self.is_running.write().await;

        if !*is_running {
            warn!("Dashboard updates are not running");
            return Ok(());
        }

        *is_running = false;
        info!("Stopping dashboard updates");
        Ok(())
    }

    /// Refresh dashboard data
    async fn refresh_dashboard_data(
        data: &Arc<RwLock<SecurityDashboardData>>,
        _config: &SecurityDashboardConfig,
    ) -> Result<(), Error> {
        let mut dashboard_data = data.write().await;

        // Update timestamp
        dashboard_data.timestamp = Utc::now();

        // Here you would normally fetch real data from various sources
        // For now, we'll simulate some updates

        // Simulate performance metrics
        dashboard_data.performance_metrics = PerformanceMetrics {
            cpu_usage_percent: (rand::random::<f64>() * 100.0).round(),
            memory_usage_percent: (rand::random::<f64>() * 100.0).round(),
            disk_usage_percent: (rand::random::<f64>() * 100.0).round(),
            network_io_bytes_per_second: rand::random::<f64>() * 1000.0,
            response_time_ms: rand::random::<f64>() * 100.0,
            throughput_operations_per_second: rand::random::<f64>() * 100.0,
        };

        // Pre-calculate to avoid borrow checker issues
        let cpu_usage = dashboard_data.performance_metrics.cpu_usage_percent;
        let memory_usage = dashboard_data.performance_metrics.memory_usage_percent;

        // Update performance widget
        if let Some(WidgetData::Performance(performance_widget)) =
            dashboard_data.widgets.get_mut("performance")
        {
            performance_widget.cpu_usage = cpu_usage;
            performance_widget.memory_usage = memory_usage;
            performance_widget.last_updated = Utc::now();
        }

        Ok(())
    }

    /// Generate dashboard HTML
    pub async fn generate_dashboard_html(&self) -> Result<String, Error> {
        let data = self.get_dashboard_data().await;

        let html = format!(
            r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wolf Prowler Security Dashboard</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #ffffff;
            min-height: 100vh;
        }}
        .dashboard-container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .dashboard-header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }}
        .dashboard-title {{
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .status-indicator {{
            display: inline-block;
            width: 15px;
            height: 15px;
            border-radius: 50%;
            margin-right: 10px;
        }}
        .status-normal {{ background: #4CAF50; }}
        .status-medium {{ background: #FFC107; }}
        .status-high {{ background: #FF9800; }}
        .status-critical {{ background: #F44336; }}
        .widgets-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .widget {{
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease;
        }}
        .widget:hover {{
            transform: translateY(-5px);
        }}
        .widget-title {{
            font-size: 1.3em;
            margin-bottom: 15px;
            color: #667eea;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .metric-label {{
            opacity: 0.8;
            font-size: 0.9em;
        }}
        .alert-item {{
            background: rgba(255,255,255,0.05);
            padding: 10px;
            margin: 5px 0;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .alert-critical {{ border-left-color: #F44336; }}
        .alert-high {{ border-left-color: #FF9800; }}
        .alert-medium {{ border-left-color: #FFC107; }}
        .alert-low {{ border-left-color: #4CAF50; }}
        .refresh-info {{
            text-align: center;
            opacity: 0.7;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="dashboard-container">
        <div class="dashboard-header">
            <h1 class="dashboard-title">🛡️ Security Dashboard</h1>
            <div>
                <span class="status-indicator status-{}"></span>
                <strong>Status:</strong> {} | 
                <strong>Last Updated:</strong> {} |
                <strong>Threat Level:</strong> {}
            </div>
        </div>

        <div class="widgets-grid">
            <div class="widget">
                <h3 class="widget-title">📊 Security Status</h3>
                <div class="metric-value">{:.1}%</div>
                <div class="metric-label">Security Score</div>
                <div class="metric-value">{:.1}%</div>
                <div class="metric-label">Success Rate</div>
                <div class="metric-value">{:.2}</div>
                <div class="metric-label">Anomaly Score</div>
            </div>

            <div class="widget">
                <h3 class="widget-title">🚨 Alerts</h3>
                <div class="metric-value">{}</div>
                <div class="metric-label">Total Alerts</div>
                <div class="metric-value">{}</div>
                <div class="metric-label">Critical Alerts</div>
                <div class="metric-value">{}</div>
                <div class="metric-label">High Alerts</div>
            </div>

            <div class="widget">
                <h3 class="widget-title">⚡ Performance</h3>
                <div class="metric-value">{:.1}%</div>
                <div class="metric-label">CPU Usage</div>
                <div class="metric-value">{:.1}%</div>
                <div class="metric-label">Memory Usage</div>
                <div class="metric-value">{:.1}ms</div>
                <div class="metric-label">Response Time</div>
            </div>

            <div class="widget">
                <h3 class="widget-title">🌐 Network Security</h3>
                <div class="metric-value">{}</div>
                <div class="metric-label">Total Peers</div>
                <div class="metric-value">{}</div>
                <div class="metric-label">Trusted Peers</div>
                <div class="metric-value">{}</div>
                <div class="metric-label">Blocked Peers</div>
            </div>
        </div>

        <div class="widget">
            <h3 class="widget-title">📋 Recent Alerts</h3>
            {}
        </div>

        <div class="refresh-info">
            <p>Auto-refresh every {} seconds | Last update: {}</p>
        </div>
    </div>

    <script>
        // Auto-refresh dashboard
        setTimeout(() => {{
            window.location.reload();
        }}, {} * 1000);
    </script>
</body>
</html>
        "#,
            data.security_status.overall_status.as_str(),
            data.security_status.overall_status.as_str().to_uppercase(),
            data.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            "Low", // Would come from threat level
            data.security_status.metrics.derived_metrics.security_score,
            data.security_status
                .metrics
                .operation_metrics
                .operation_success_rate
                * 100.0,
            data.security_status.metrics.anomaly_metrics.anomaly_score,
            data.alerts.len(),
            data.alerts
                .iter()
                .filter(|a| a.severity == super::alerts::AlertSeverity::Critical)
                .count(),
            data.alerts
                .iter()
                .filter(|a| a.severity == super::alerts::AlertSeverity::High)
                .count(),
            data.performance_metrics.cpu_usage_percent,
            data.performance_metrics.memory_usage_percent,
            data.performance_metrics.response_time_ms,
            data.network_security.total_peers,
            data.network_security.trusted_peers,
            data.network_security.blocked_peers,
            self.format_recent_alerts(&data.alerts),
            self.config.refresh_interval_secs,
            data.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            self.config.refresh_interval_secs
        );

        Ok(html)
    }

    /// Format recent alerts for HTML display
    fn format_recent_alerts(&self, alerts: &[super::alerts::SecurityAlert]) -> String {
        if alerts.is_empty() {
            return "<p>No recent alerts</p>".to_string();
        }

        alerts
            .iter()
            .take(10)
            .map(|alert| {
                format!(
                    r#"<div class="alert-item alert-{}">
                        <strong>{}</strong> - {} 
                        <small>{}</small>
                    </div>"#,
                    alert.severity.as_str(),
                    alert.severity.as_str().to_uppercase(),
                    alert.message,
                    alert.timestamp.format("%H:%M:%S")
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            cpu_usage_percent: 0.0,
            memory_usage_percent: 0.0,
            disk_usage_percent: 0.0,
            network_io_bytes_per_second: 0.0,
            response_time_ms: 0.0,
            throughput_operations_per_second: 0.0,
        }
    }
}

impl Default for NetworkSecurityMetrics {
    fn default() -> Self {
        Self {
            total_peers: 0,
            trusted_peers: 0,
            suspicious_peers: 0,
            blocked_peers: 0,
            encrypted_connections: 0,
            authentication_success_rate: 100.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_dashboard_config_default() {
        let config = SecurityDashboardConfig::default();
        assert_eq!(config.refresh_interval_secs, 5);
        assert_eq!(config.max_alerts_displayed, 50);
        assert!(config.enable_real_time_updates);
    }

    #[test]
    fn test_threat_level() {
        assert_eq!(ThreatLevel::Low.as_str(), "low");
        assert_eq!(ThreatLevel::Critical.color_code(), "#F44336");
    }

    #[tokio::test]
    async fn test_security_dashboard_creation() {
        let config = SecurityDashboardConfig::default();
        let dashboard = SecurityDashboard::new(config).await;
        assert!(dashboard.is_ok());
    }

    #[tokio::test]
    async fn test_dashboard_data_management() {
        let dashboard = SecurityDashboard::new(SecurityDashboardConfig::default())
            .await
            .unwrap();

        // Test getting initial data
        let data = dashboard.get_dashboard_data().await;
        assert!(data.widgets.contains_key("security_status"));

        // Test adding alert
        let alert = crate::observability::alerts::SecurityAlert {
            id: "test-alert".to_string(),
            timestamp: Utc::now(),
            severity: crate::observability::alerts::AlertSeverity::Medium,
            status: crate::observability::alerts::AlertStatus::Active,
            title: "Test Alert".to_string(),
            message: "Test alert".to_string(),
            source: "test".to_string(),
            category: crate::observability::alerts::AlertCategory::Security,
            metadata: HashMap::new(),
            escalation_level: 0,
            acknowledged_by: None,
            acknowledged_at: None,
            resolved_by: None,
            resolved_at: None,
        };

        let result = dashboard.add_alert(alert).await;
        assert!(result.is_ok());

        // Verify alert was added
        let updated_data = dashboard.get_dashboard_data().await;
        assert_eq!(updated_data.alerts.len(), 1);
    }

    #[tokio::test]
    async fn test_dashboard_lifecycle() {
        let dashboard = SecurityDashboard::new(SecurityDashboardConfig::default())
            .await
            .unwrap();

        // Start updates
        let start_result = dashboard.start_updates().await;
        assert!(start_result.is_ok());

        // Give it a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Stop updates
        let stop_result = dashboard.stop_updates().await;
        assert!(stop_result.is_ok());
    }

    #[tokio::test]
    async fn test_dashboard_html_generation() {
        let dashboard = SecurityDashboard::new(SecurityDashboardConfig::default())
            .await
            .unwrap();

        let html = dashboard.generate_dashboard_html().await;
        assert!(html.is_ok());

        let html_content = html.unwrap();
        assert!(html_content.contains("Security Dashboard"));
        assert!(html_content.contains("🛡️"));
    }
}
