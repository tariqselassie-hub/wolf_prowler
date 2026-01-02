# 🎯 Wolf Prowler Dashboard - 5 Critical Features Implementation Plan

> **Strategic enhancement roadmap for production-ready dashboard capabilities**  
> **Date**: November 30, 2025  
> **Priority**: Critical gaps identified from documentation analysis

---

## 📋 **Executive Summary**

Based on comprehensive analysis of Wolf Prowler documentation, I've identified **5 critical features** that must be implemented to bridge the gap between current dashboard capabilities and documented production requirements. This plan provides detailed implementation steps, timelines, and technical specifications for each feature.

**Current Status**: ✅ **Basic dashboard functional** - Wolf Den Testing section complete  
**Target Status**: 🚀 **Production-ready dashboard** with enterprise capabilities  
**Estimated Timeline**: **5 weeks** (20 development days)

---

## 🚨 **Feature 1: Real-time Alert System**

### **Documentation Reference**
- Dashboard Expansion Documentation (Lines 761-763)
- Production Readiness Assessment (Security monitoring gaps)

### **Current Gap**
No proactive security notifications - users must manually monitor dashboard for issues

### **Implementation Details**

#### **Backend API Endpoints**
```rust
// Add to src/dashboard/mod.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

// Alert management endpoints
async fn get_alerts_handler(
    State(state): State<DashboardState>,
    Query(params): Query<AlertQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let alerts = state.alert_manager.get_alerts(
        params.severity,
        params.acknowledged,
        params.limit.unwrap_or(50)
    ).await;
    
    Ok(Json(json!({
        "status": "success",
        "data": alerts,
        "total": alerts.len()
    })))
}

async fn acknowledge_alert_handler(
    State(state): State<DashboardState>,
    Path(alert_id): Path<String>,
    Json(request): Json<AcknowledgeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.alert_manager.acknowledge_alert(&alert_id, &request.user_id).await {
        Ok(_) => Ok(Json(json!({
            "status": "success",
            "message": "Alert acknowledged successfully"
        }))),
        Err(e) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

async fn create_alert_handler(
    State(state): State<DashboardState>,
    Json(alert): Json<CreateAlertRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let alert_id = state.alert_manager.create_alert(alert).await?;
    
    // Broadcast alert via WebSocket
    if let Err(e) = state.websocket_manager.broadcast_alert(&alert_id).await {
        tracing::error!("Failed to broadcast alert: {}", e);
    }
    
    Ok(Json(json!({
        "status": "success",
        "alert_id": alert_id
    })))
}
```

#### **Alert Manager Implementation**
```rust
// Add to src/dashboard/alert_manager.rs
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct AlertManager {
    alerts: Arc<RwLock<HashMap<String, Alert>>>,
    max_alerts: usize,
}

impl AlertManager {
    pub fn new(max_alerts: usize) -> Self {
        Self {
            alerts: Arc::new(RwLock::new(HashMap::new())),
            max_alerts,
        }
    }
    
    pub async fn create_alert(&self, request: CreateAlertRequest) -> Result<String> {
        let alert_id = Uuid::new_v4().to_string();
        let alert = Alert {
            id: alert_id.clone(),
            title: request.title,
            description: request.description,
            severity: request.severity,
            source: request.source,
            timestamp: Utc::now(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
            metadata: request.metadata.unwrap_or_default(),
        };
        
        let mut alerts = self.alerts.write().await;
        
        // Maintain maximum alert limit
        if alerts.len() >= self.max_alerts {
            // Remove oldest alerts
            let mut alert_entries: Vec<_> = alerts.iter()
                .collect()
                .into_iter()
                .map(|(k, v)| (k.clone(), v.timestamp))
                .collect();
            alert_entries.sort_by_key(|&(_, timestamp)| timestamp);
            
            let to_remove = alert_entries.len() - self.max_alerts + 1;
            for (key, _) in alert_entries.iter().take(to_remove) {
                alerts.remove(key);
            }
        }
        
        alerts.insert(alert_id.clone(), alert);
        Ok(alert_id)
    }
    
    pub async fn acknowledge_alert(&self, alert_id: &str, user_id: &str) -> Result<()> {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.acknowledged = true;
            alert.acknowledged_by = Some(user_id.to_string());
            alert.acknowledged_at = Some(Utc::now());
            Ok(())
        } else {
            Err(anyhow::anyhow!("Alert not found"))
        }
    }
    
    pub async fn get_alerts(&self, severity: Option<AlertSeverity>, acknowledged: Option<bool>, limit: usize) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        let mut filtered: Vec<_> = alerts.values()
            .filter(|alert| {
                if let Some(sev) = &severity {
                    &alert.severity == sev
                } else {
                    true
                }
            })
            .filter(|alert| {
                if let Some(ack) = acknowledged {
                    alert.acknowledged == ack
                } else {
                    true
                }
            })
            .cloned()
            .collect();
        
        // Sort by timestamp (newest first) and limit
        filtered.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        filtered.truncate(limit);
        filtered
    }
}
```

#### **Frontend Alert System**
```javascript
// Add to src/dashboard/static/index.html
class AlertManager {
    constructor() {
        this.alerts = [];
        this.alertSound = new Audio('/static/sounds/alert.mp3');
        this.setupWebSocket();
        this.setupAlertUI();
        this.maxAlerts = 100;
    }
    
    setupWebSocket() {
        const ws = new WebSocket('ws://127.0.0.1:7620/ws/secure');
        
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'alert') {
                this.showAlert(data.alert);
            }
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }
    
    showAlert(alert) {
        this.alerts.unshift(alert);
        if (this.alerts.length > this.maxAlerts) {
            this.alerts.pop();
        }
        
        this.updateAlertBanner(alert);
        this.updateAlertsList();
        
        // Sound notification for critical alerts
        if (alert.severity === 'critical') {
            this.alertSound.play().catch(e => console.log('Could not play alert sound:', e));
        }
        
        // Browser notification
        this.showBrowserNotification(alert);
    }
    
    updateAlertBanner(alert) {
        const banner = document.getElementById('alert-banner');
        const severityColors = {
            'info': 'bg-blue-100 border-blue-500 text-blue-700',
            'warning': 'bg-yellow-100 border-yellow-500 text-yellow-700',
            'error': 'bg-red-100 border-red-500 text-red-700',
            'critical': 'bg-red-200 border-red-600 text-red-800'
        };
        
        const alertHtml = `
            <div class="border-l-4 p-4 mb-2 ${severityColors[alert.severity]} alert-item" data-alert-id="${alert.id}">
                <div class="flex justify-between items-center">
                    <div>
                        <h4 class="font-bold">${alert.title}</h4>
                        <p class="text-sm">${alert.description}</p>
                        <p class="text-xs mt-1">${new Date(alert.timestamp).toLocaleString()} - ${alert.source}</p>
                    </div>
                    <div class="flex space-x-2">
                        ${!alert.acknowledged ? `
                            <button onclick="alertManager.acknowledgeAlert('${alert.id}')" class="px-3 py-1 bg-blue-500 text-white rounded text-sm hover:bg-blue-600">
                                Acknowledge
                            </button>
                        ` : `
                            <span class="text-xs text-green-600">Acknowledged by ${alert.acknowledged_by}</span>
                        `}
                        <button onclick="alertManager.dismissAlert('${alert.id}')" class="text-gray-500 hover:text-gray-700">
                            ×
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        banner.insertAdjacentHTML('afterbegin', alertHtml);
        
        // Remove old alerts if too many
        const alertItems = banner.querySelectorAll('.alert-item');
        if (alertItems.length > 5) {
            alertItems[alertItems.length - 1].remove();
        }
    }
    
    async acknowledgeAlert(alertId) {
        try {
            const response = await fetch(`/api/alerts/${alertId}/acknowledge`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: 'dashboard_user' })
            });
            
            if (response.ok) {
                const alertElement = document.querySelector(`[data-alert-id="${alertId}"]`);
                if (alertElement) {
                    alertElement.classList.add('opacity-50');
                    const button = alertElement.querySelector('button');
                    if (button) {
                        button.replaceWith('<span class="text-xs text-green-600">Acknowledged</span>');
                    }
                }
            }
        } catch (error) {
            console.error('Failed to acknowledge alert:', error);
        }
    }
    
    dismissAlert(alertId) {
        const alertElement = document.querySelector(`[data-alert-id="${alertId}"]`);
        if (alertElement) {
            alertElement.remove();
        }
    }
    
    showBrowserNotification(alert) {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(`Wolf Prowler Alert: ${alert.title}`, {
                body: alert.description,
                icon: '/static/images/wolf-icon.png',
                tag: alert.id
            });
        }
    }
    
    setupAlertUI() {
        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }
}
```

#### **Implementation Steps**
- **Day 1**: Create alert data structures and API endpoints
- **Day 2**: Implement AlertManager with persistence
- **Day 3**: Build WebSocket alert broadcasting
- **Day 4**: Create frontend alert UI with notifications

---

## 📊 **Feature 2: Historical Data Persistence**

### **Documentation Reference**
- Production Readiness Assessment (Lines 762-763)
- UPGRADES.md (Metrics collection enhancement)

### **Current Gap**
Metrics are lost on restart, no trend analysis or historical reporting

### **Implementation Details**

#### **Database Integration**
```toml
# Add to Cargo.toml
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "sqlite", "chrono", "uuid"] }
```

```rust
// Add to src/dashboard/metrics_store.rs
use sqlx::{SqlitePool, sqlite::SqliteConnectOptions, Row};
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub metric_type: String,
    pub value: f64,
    pub labels: serde_json::Value,
    pub unit: Option<String>,
}

pub struct MetricsStore {
    pool: SqlitePool,
}

impl MetricsStore {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        
        // Create tables
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                metric_type TEXT NOT NULL,
                value REAL NOT NULL,
                labels TEXT,
                unit TEXT
            )
        "#).execute(&pool).await?;
        
        // Create indexes for performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)").execute(&pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type)").execute(&pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_metrics_type_timestamp ON metrics(metric_type, timestamp)").execute(&pool).await?;
        
        Ok(Self { pool })
    }
    
    pub async fn store_metric(&self, metric: &Metric) -> Result<i64> {
        let result = sqlx::query(r#"
            INSERT INTO metrics (timestamp, metric_type, value, labels, unit)
            VALUES (?, ?, ?, ?, ?)
        "#)
        .bind(metric.timestamp)
        .bind(&metric.metric_type)
        .bind(metric.value)
        .bind(serde_json::to_string(&metric.labels)?)
        .bind(&metric.unit)
        .execute(&self.pool)
        .await?;
        
        Ok(result.last_insert_rowid())
    }
    
    pub async fn get_metrics(
        &self,
        metric_type: Option<&str>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        aggregation: Option<&str>,
        limit: Option<i64>
    ) -> Result<Vec<Metric>> {
        let mut query = "SELECT id, timestamp, metric_type, value, labels, unit FROM metrics WHERE 1=1".to_string();
        let mut bind_values: Vec<Box<dyn sqlx::Encode<'_, sqlx::Sqlite> + Send>> = Vec::new();
        
        if let Some(mt) = metric_type {
            query.push_str(" AND metric_type = ?");
            bind_values.push(Box::new(mt));
        }
        
        if let Some(st) = start_time {
            query.push_str(" AND timestamp >= ?");
            bind_values.push(Box::new(st));
        }
        
        if let Some(et) = end_time {
            query.push_str(" AND timestamp <= ?");
            bind_values.push(Box::new(et));
        }
        
        query.push_str(" ORDER BY timestamp DESC");
        
        if let Some(limit_val) = limit {
            query.push_str(&format!(" LIMIT {}", limit_val));
        }
        
        let mut q = sqlx::query(&query);
        for value in bind_values {
            // This is simplified - in practice, you'd need proper parameter binding
        }
        
        let rows = q.fetch_all(&self.pool).await?;
        
        let metrics = rows.iter().map(|row| Metric {
            id: Some(row.get("id")),
            timestamp: row.get("timestamp"),
            metric_type: row.get("metric_type"),
            value: row.get("value"),
            labels: serde_json::from_str(row.get("labels")).unwrap_or_default(),
            unit: row.get("unit"),
        }).collect();
        
        Ok(metrics)
    }
    
    pub async fn get_aggregated_metrics(
        &self,
        metric_type: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        aggregation: &str,
        interval: Duration
    ) -> Result<Vec<Metric>> {
        let interval_seconds = interval.num_seconds();
        
        let query = match aggregation {
            "avg" => format!(r#"
                SELECT 
                    datetime((strftime('%s', timestamp) / {}) * {}) as timestamp,
                    metric_type,
                    AVG(value) as value,
                    '{}' as labels,
                    unit
                FROM metrics 
                WHERE metric_type = ? AND timestamp BETWEEN ? AND ?
                GROUP BY timestamp, metric_type, unit
                ORDER BY timestamp
            "#, interval_seconds, interval_seconds),
            "max" => format!(r#"
                SELECT 
                    datetime((strftime('%s', timestamp) / {}) * {}) as timestamp,
                    metric_type,
                    MAX(value) as value,
                    '{}' as labels,
                    unit
                FROM metrics 
                WHERE metric_type = ? AND timestamp BETWEEN ? AND ?
                GROUP BY timestamp, metric_type, unit
                ORDER BY timestamp
            "#, interval_seconds, interval_seconds),
            "min" => format!(r#"
                SELECT 
                    datetime((strftime('%s', timestamp) / {}) * {}) as timestamp,
                    metric_type,
                    MIN(value) as value,
                    '{}' as labels,
                    unit
                FROM metrics 
                WHERE metric_type = ? AND timestamp BETWEEN ? AND ?
                GROUP BY timestamp, metric_type, unit
                ORDER BY timestamp
            "#, interval_seconds, interval_seconds),
            "sum" => format!(r#"
                SELECT 
                    datetime((strftime('%s', timestamp) / {}) * {}) as timestamp,
                    metric_type,
                    SUM(value) as value,
                    '{}' as labels,
                    unit
                FROM metrics 
                WHERE metric_type = ? AND timestamp BETWEEN ? AND ?
                GROUP BY timestamp, metric_type, unit
                ORDER BY timestamp
            "#, interval_seconds, interval_seconds),
            _ => return Err(anyhow::anyhow!("Unsupported aggregation: {}", aggregation))
        };
        
        let rows = sqlx::query(&query)
            .bind(metric_type)
            .bind(start_time)
            .bind(end_time)
            .fetch_all(&self.pool)
            .await?;
        
        let metrics = rows.iter().map(|row| Metric {
            id: None,
            timestamp: row.get("timestamp"),
            metric_type: row.get("metric_type"),
            value: row.get("value"),
            labels: serde_json::from_str(row.get("labels")).unwrap_or_default(),
            unit: row.get("unit"),
        }).collect();
        
        Ok(metrics)
    }
    
    pub async fn cleanup_old_metrics(&self, retention_days: i64) -> Result<u64> {
        let cutoff_time = Utc::now() - Duration::days(retention_days);
        
        let result = sqlx::query("DELETE FROM metrics WHERE timestamp < ?")
            .bind(cutoff_time)
            .execute(&self.pool)
            .await?;
        
        Ok(result.rows_affected())
    }
}
```

#### **Historical API Endpoints**
```rust
// Add to src/dashboard/mod.rs
async fn get_historical_metrics_handler(
    State(state): State<DashboardState>,
    Query(params): Query<HistoricalQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let start_time = params.start_time.unwrap_or_else(|| Utc::now() - Duration::hours(24));
    let end_time = params.end_time.unwrap_or(Utc::now());
    
    let metrics = if let Some(agg) = &params.aggregation {
        let interval = params.interval.unwrap_or(Duration::minutes(5));
        state.metrics_store.get_aggregated_metrics(
            &params.metric_type,
            start_time,
            end_time,
            agg,
            interval
        ).await.unwrap_or_default()
    } else {
        state.metrics_store.get_metrics(
            Some(&params.metric_type),
            Some(start_time),
            Some(end_time),
            None,
            Some(params.limit.unwrap_or(1000))
        ).await.unwrap_or_default()
    };
    
    Ok(Json(json!({
        "status": "success",
        "data": metrics,
        "query": {
            "metric_type": params.metric_type,
            "start_time": start_time,
            "end_time": end_time,
            "aggregation": params.aggregation,
            "count": metrics.len()
        }
    })))
}

#[derive(Deserialize)]
struct HistoricalQuery {
    metric_type: String,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    aggregation: Option<String>,
    interval: Option<Duration>,
    limit: Option<i64>,
}
```

#### **Frontend Historical Charts**
```javascript
// Enhanced charts with historical data
class HistoricalChart {
    constructor(canvasId, metricType) {
        this.canvasId = canvasId;
        this.metricType = metricType;
        this.chart = null;
        this.currentTimeRange = '1h';
        this.currentAggregation = 'avg';
        this.initChart();
        this.setupControls();
    }
    
    initChart() {
        const ctx = document.getElementById(this.canvasId).getContext('2d');
        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                datasets: [{
                    label: this.metricType,
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.1)',
                    tension: 0.1,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: 'minute',
                            displayFormats: {
                                minute: 'HH:mm',
                                hour: 'HH:mm'
                            }
                        },
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: this.metricType
                        },
                        beginAtZero: false
                    }
                },
                plugins: {
                    legend: {
                        display: true
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                }
            }
        });
    }
    
    setupControls() {
        // Time range selector
        const timeRangeSelect = document.getElementById(`${this.canvasId}-time-range`);
        if (timeRangeSelect) {
            timeRangeSelect.addEventListener('change', (e) => {
                this.currentTimeRange = e.target.value;
                this.loadHistoricalData();
            });
        }
        
        // Aggregation selector
        const aggregationSelect = document.getElementById(`${this.canvasId}-aggregation`);
        if (aggregationSelect) {
            aggregationSelect.addEventListener('change', (e) => {
                this.currentAggregation = e.target.value;
                this.loadHistoricalData();
            });
        }
    }
    
    async loadHistoricalData() {
        try {
            const endTime = new Date();
            let startTime;
            let timeUnit;
            
            switch (this.currentTimeRange) {
                case '1h':
                    startTime = new Date(endTime.getTime() - 60 * 60 * 1000);
                    timeUnit = 'minute';
                    break;
                case '6h':
                    startTime = new Date(endTime.getTime() - 6 * 60 * 60 * 1000);
                    timeUnit = 'minute';
                    break;
                case '24h':
                    startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000);
                    timeUnit = 'hour';
                    break;
                case '7d':
                    startTime = new Date(endTime.getTime() - 7 * 24 * 60 * 60 * 1000);
                    timeUnit = 'hour';
                    break;
                case '30d':
                    startTime = new Date(endTime.getTime() - 30 * 24 * 60 * 60 * 1000);
                    timeUnit = 'day';
                    break;
                default:
                    startTime = new Date(endTime.getTime() - 60 * 60 * 1000);
                    timeUnit = 'minute';
            }
            
            const params = new URLSearchParams({
                metric_type: this.metricType,
                start_time: startTime.toISOString(),
                end_time: endTime.toISOString(),
                aggregation: this.currentAggregation,
                limit: '1000'
            });
            
            const response = await fetch(`/api/metrics/historical?${params}`);
            const data = await response.json();
            
            if (data.status === 'success') {
                const chartData = data.data.map(point => ({
                    x: point.timestamp,
                    y: point.value
                }));
                
                this.chart.data.datasets[0].data = chartData;
                this.chart.data.datasets[0].label = `${this.metricType} (${this.currentAggregation})`;
                
                // Update time scale unit
                this.chart.options.scales.x.time.unit = timeUnit;
                this.chart.update();
            }
        } catch (error) {
            console.error('Failed to load historical data:', error);
        }
    }
    
    startAutoRefresh(intervalMs = 60000) {
        setInterval(() => {
            this.loadHistoricalData();
        }, intervalMs);
    }
}
```

#### **Implementation Steps**
- **Day 1**: Add SQLite dependency and database schema
- **Day 2**: Implement MetricsStore with aggregation
- **Day 3**: Create historical API endpoints
- **Day 4**: Enhance frontend charts with time range selection

---

## 👥 **Feature 3: User Management System**

### **Documentation Reference**
- Dashboard Expansion Documentation (Lines 764-765)
- Production Readiness Assessment (Security requirements)

### **Current Gap**
No multi-user support, no role-based access control

### **Implementation Details**

#### **User Management Data Structures**
```rust
// Add to src/dashboard/user_management.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role: UserRole,
    pub permissions: HashSet<Permission>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub active: bool,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserRole {
    Admin,      // Full access to all features
    Operator,   // Monitor + basic operations
    Viewer,     // Read-only access to dashboard
    Auditor,    // Access to audit logs only
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // Dashboard permissions
    ViewDashboard,
    ExportData,
    ManageAlerts,
    
    // User management permissions
    ManageUsers,
    ViewUsers,
    
    // System permissions
    ViewSystemMetrics,
    ManageSystemConfig,
    ViewAuditLogs,
    
    // Crypto permissions
    ExecuteCryptoOperations,
    ViewCryptoKeys,
}

impl UserRole {
    pub fn default_permissions(&self) -> HashSet<Permission> {
        match self {
            UserRole::Admin => HashSet::from_iter(vec![
                Permission::ViewDashboard,
                Permission::ExportData,
                Permission::ManageAlerts,
                Permission::ManageUsers,
                Permission::ViewUsers,
                Permission::ViewSystemMetrics,
                Permission::ManageSystemConfig,
                Permission::ViewAuditLogs,
                Permission::ExecuteCryptoOperations,
                Permission::ViewCryptoKeys,
            ]),
            UserRole::Operator => HashSet::from_iter(vec![
                Permission::ViewDashboard,
                Permission::ExportData,
                Permission::ManageAlerts,
                Permission::ViewUsers,
                Permission::ViewSystemMetrics,
                Permission::ExecuteCryptoOperations,
            ]),
            UserRole::Viewer => HashSet::from_iter(vec![
                Permission::ViewDashboard,
                Permission::ViewSystemMetrics,
            ]),
            UserRole::Auditor => HashSet::from_iter(vec![
                Permission::ViewAuditLogs,
                Permission::ViewDashboard,
            ]),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user: User,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
}

pub struct UserManager {
    users: Arc<RwLock<HashMap<String, User>>>,
    sessions: Arc<RwLock<HashMap<String, AuthenticatedUser>>>,
    jwt_secret: String,
}

impl UserManager {
    pub fn new(jwt_secret: String) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            jwt_secret,
        }
    }
    
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<String> {
        let user_id = uuid::Uuid::new_v4().to_string();
        let password_hash = bcrypt::hash(&request.password, bcrypt::DEFAULT_COST)?;
        
        let user = User {
            id: user_id.clone(),
            username: request.username.clone(),
            email: request.email,
            password_hash,
            role: request.role,
            permissions: request.role.default_permissions(),
            created_at: Utc::now(),
            last_login: None,
            active: true,
            mfa_enabled: false,
            mfa_secret: None,
        };
        
        let mut users = self.users.write().await;
        users.insert(user_id.clone(), user);
        
        Ok(user_id)
    }
    
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Option<AuthenticatedUser>> {
        let users = self.users.read().await;
        
        if let Some(user) = users.values().find(|u| u.username == username && u.active) {
            if bcrypt::verify(password, &user.password_hash)? {
                let session_token = self.generate_jwt(&user)?;
                let expires_at = Utc::now() + Duration::hours(24);
                
                let auth_user = AuthenticatedUser {
                    user: user.clone(),
                    session_token: session_token.clone(),
                    expires_at,
                };
                
                let mut sessions = self.sessions.write().await;
                sessions.insert(session_token.clone(), auth_user.clone());
                
                return Ok(Some(auth_user));
            }
        }
        
        Ok(None)
    }
    
    pub async fn validate_session(&self, token: &str) -> Result<Option<AuthenticatedUser>> {
        let sessions = self.sessions.read().await;
        
        if let Some(auth_user) = sessions.get(token) {
            if auth_user.expires_at > Utc::now() {
                return Ok(Some(auth_user.clone()));
            }
        }
        
        Ok(None)
    }
    
    fn generate_jwt(&self, user: &User) -> Result<String> {
        let header = jsonwebtoken::Header::default();
        let claims = jsonwebtoken::Claims::new(
            jsonwebtoken::RegisteredClaims {
                sub: user.id.clone(),
                exp: jsonwebtoken::get_current_timestamp() + 86400, // 24 hours
                ..Default::default()
            },
        )
        .with_json_claim("role", &user.role)?
        .with_json_claim("permissions", &user.permissions)?;
        
        let encoding_key = jsonwebtoken::EncodingKey::from_secret(self.jwt_secret.as_ref());
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)?;
        
        Ok(token)
    }
}
```

#### **Role-Based Access Control Middleware**
```rust
// Add to src/dashboard/auth_middleware.rs
use axum::{
    extract::{Request, State},
    http::{StatusCode, HeaderMap},
    middleware::Next,
    response::Response,
};

pub async fn rbac_middleware(
    State(state): State<DashboardState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract JWT token from Authorization header
    let token = extract_token_from_request(&request)?;
    
    // Validate token and get user
    let auth_user = state.user_manager.validate_session(&token).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    // Check permissions for the route
    let required_permission = get_required_permission(&request.uri().path(), &request.method().as_str());
    
    if let Some(permission) = required_permission {
        if !auth_user.user.permissions.contains(&permission) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    
    // Add user to request state
    let mut request = request;
    request.extensions_mut().insert(auth_user);
    
    Ok(next.run(request).await)
}

fn extract_token_from_request(request: &Request) -> Result<String, StatusCode> {
    let headers = request.headers();
    
    let auth_header = headers.get("authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    Ok(auth_header[7..].to_string())
}

fn get_required_permission(path: &str, method: &str) -> Option<Permission> {
    match (path, method) {
        // User management
        ("/api/users", "GET") => Some(Permission::ViewUsers),
        ("/api/users", "POST") => Some(Permission::ManageUsers),
        ("/api/users/:id", "DELETE") => Some(Permission::ManageUsers),
        
        // System management
        ("/api/system/config", "PUT") => Some(Permission::ManageSystemConfig),
        ("/api/system/metrics", "GET") => Some(Permission::ViewSystemMetrics),
        
        // Audit logs
        ("/api/audit/logs", "GET") => Some(Permission::ViewAuditLogs),
        
        // Crypto operations
        ("/api/crypto/*", "POST") => Some(Permission::ExecuteCryptoOperations),
        ("/api/crypto/keys", "GET") => Some(Permission::ViewCryptoKeys),
        
        // Data export
        ("/api/export/*", "GET") => Some(Permission::ExportData),
        
        // Dashboard view
        ("/", "GET") | ("/api/dashboard/*", "GET") => Some(Permission::ViewDashboard),
        
        _ => None, // No specific permission required
    }
}
```

#### **User Management API Endpoints**
```rust
// Add to src/dashboard/mod.rs
async fn login_handler(
    State(state): State<DashboardState>,
    Json(credentials): Json<Credentials>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.user_manager.authenticate(&credentials.username, &credentials.password).await {
        Ok(Some(auth_user)) => Ok(Json(json!({
            "status": "success",
            "user": {
                "id": auth_user.user.id,
                "username": auth_user.user.username,
                "email": auth_user.user.email,
                "role": auth_user.user.role,
                "permissions": auth_user.user.permissions,
                "last_login": auth_user.user.last_login
            },
            "token": auth_user.session_token,
            "expires_at": auth_user.expires_at
        }))),
        Ok(None) => Err(StatusCode::UNAUTHORIZED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

async fn create_user_handler(
    State(state): State<DashboardState>,
    _auth_user: AuthenticatedUser, // Require admin permission via middleware
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.user_manager.create_user(request).await {
        Ok(user_id) => Ok(Json(json!({
            "status": "success",
            "user_id": user_id,
            "message": "User created successfully"
        }))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

async fn get_users_handler(
    State(state): State<DashboardState>,
    _auth_user: AuthenticatedUser, // Require view users permission
) -> Result<Json<serde_json::Value>, StatusCode> {
    let users = state.user_manager.get_all_users().await.unwrap_or_default();
    
    Ok(Json(json!({
        "status": "success",
        "data": users.iter().map(|user| json!({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at,
            "last_login": user.last_login,
            "active": user.active
        })).collect::<Vec<_>>(),
        "total": users.len()
    })))
}
```

#### **Frontend User Interface**
```javascript
// User management interface
class UserManager {
    constructor() {
        this.currentUser = null;
        this.token = localStorage.getItem('authToken');
        this.checkAuthStatus();
        this.setupAuthUI();
    }
    
    async checkAuthStatus() {
        if (!this.token) {
            this.showLoginForm();
            return;
        }
        
        try {
            const response = await fetch('/api/auth/me', {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.currentUser = data.user;
                this.updateUIForUserRole(data.user.role);
                this.hideLoginForm();
            } else {
                this.logout();
            }
        } catch (error) {
            console.error('Auth check failed:', error);
            this.logout();
        }
    }
    
    async login(username, password) {
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            if (response.ok) {
                const data = await response.json();
                this.token = data.token;
                this.currentUser = data.user;
                localStorage.setItem('authToken', this.token);
                
                this.updateUIForUserRole(data.user.role);
                this.hideLoginForm();
                
                // Show success message
                this.showNotification('Login successful', 'success');
            } else {
                this.showNotification('Login failed', 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showNotification('Login error', 'error');
        }
    }
    
    logout() {
        this.token = null;
        this.currentUser = null;
        localStorage.removeItem('authToken');
        this.showLoginForm();
        this.showNotification('Logged out', 'info');
    }
    
    updateUIForUserRole(role) {
        // Show/hide UI elements based on role
        const adminElements = document.querySelectorAll('.admin-only');
        const operatorElements = document.querySelectorAll('.operator-only');
        const viewerElements = document.querySelectorAll('.viewer-only');
        const auditorElements = document.querySelectorAll('.auditor-only');
        
        // Admin can see everything
        const isAdmin = role === 'Admin';
        const isOperator = ['Admin', 'Operator'].includes(role);
        const isViewer = ['Admin', 'Operator', 'Viewer'].includes(role);
        const isAuditor = ['Admin', 'Auditor'].includes(role);
        
        adminElements.forEach(el => el.style.display = isAdmin ? 'block' : 'none');
        operatorElements.forEach(el => el.style.display = isOperator ? 'block' : 'none');
        viewerElements.forEach(el => el.style.display = isViewer ? 'block' : 'none');
        auditorElements.forEach(el => el.style.display = isAuditor ? 'block' : 'none');
        
        // Update user info display
        const userInfo = document.getElementById('user-info');
        if (userInfo) {
            userInfo.innerHTML = `
                <span class="font-medium">${this.currentUser.username}</span>
                <span class="text-sm text-gray-500">(${role})</span>
                <button onclick="userManager.logout()" class="ml-2 text-sm text-red-600 hover:text-red-800">Logout</button>
            `;
        }
    }
    
    setupAuthUI() {
        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                this.login(username, password);
            });
        }
    }
    
    showLoginForm() {
        const loginModal = document.getElementById('login-modal');
        if (loginModal) {
            loginModal.style.display = 'flex';
        }
    }
    
    hideLoginForm() {
        const loginModal = document.getElementById('login-modal');
        if (loginModal) {
            loginModal.style.display = 'none';
        }
    }
    
    showNotification(message, type) {
        // Simple notification implementation
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-lg text-white z-50 ${
            type === 'success' ? 'bg-green-500' :
            type === 'error' ? 'bg-red-500' :
            type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
        }`;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
}
```

#### **Implementation Steps**
- **Day 1**: Create user data structures and authentication
- **Day 2**: Implement role-based access control middleware
- **Day 3**: Build user management API endpoints
- **Day 4**: Create frontend login and user management UI

---

## 📤 **Feature 4: Data Export Functionality**

### **Documentation Reference**
- Dashboard Expansion Documentation (Lines 765-766)
- Production Readiness Assessment (Data export capabilities)

### **Current Gap**
No way to export metrics, logs, or configuration for external analysis

### **Implementation Details**

#### **Export API Endpoints**
```rust
// Add to src/dashboard/export.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use csv::WriterBuilder;
use xml::writer::XmlEvent;

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub r#type: String,
    pub format: String,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub metric_types: Option<String>,
    pub log_level: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExportRecord {
    pub timestamp: DateTime<Utc>,
    pub metric_type: Option<String>,
    pub value: Option<f64>,
    pub labels: Option<serde_json::Value>,
    pub log_level: Option<String>,
    pub message: Option<String>,
    pub source: Option<String>,
}

pub struct DataExporter {
    metrics_store: Arc<MetricsStore>,
    log_store: Arc<LogStore>,
}

impl DataExporter {
    pub fn new(metrics_store: Arc<MetricsStore>, log_store: Arc<LogStore>) -> Self {
        Self {
            metrics_store,
            log_store,
        }
    }
    
    pub async fn export_data(&self, query: ExportQuery) -> Result<Vec<u8>> {
        match (query.r#type.as_str(), query.format.as_str()) {
            ("metrics", "csv") => self.export_metrics_csv(query).await,
            ("metrics", "json") => self.export_metrics_json(query).await,
            ("metrics", "xml") => self.export_metrics_xml(query).await,
            ("logs", "csv") => self.export_logs_csv(query).await,
            ("logs", "json") => self.export_logs_json(query).await,
            ("logs", "xml") => self.export_logs_xml(query).await,
            ("config", "json") => self.export_config_json(query).await,
            ("config", "toml") => self.export_config_toml(query).await,
            _ => Err(anyhow::anyhow!("Unsupported export type or format"))
        }
    }
    
    async fn export_metrics_csv(&self, query: ExportQuery) -> Result<Vec<u8>> {
        let start_time = self.parse_date(&query.start_date)?;
        let end_time = self.parse_date(&query.end_date)?;
        
        let metrics = self.metrics_store.get_metrics(
            None, // All metric types
            start_time,
            end_time,
            None,
            Some(10000) // Large limit for export
        ).await?;
        
        let mut writer = WriterBuilder::new()
            .has_headers(true)
            .from_writer(vec![]);
        
        // Write header
        writer.write_record(&["timestamp", "metric_type", "value", "labels", "unit"])?;
        
        // Write data
        for metric in metrics {
            writer.write_record(&[
                metric.timestamp.to_rfc3339(),
                metric.metric_type,
                metric.value.to_string(),
                serde_json::to_string(&metric.labels)?,
                metric.unit.unwrap_or_default()
            ])?;
        }
        
        Ok(writer.into_inner()?)
    }
    
    async fn export_metrics_json(&self, query: ExportQuery) -> Result<Vec<u8>> {
        let start_time = self.parse_date(&query.start_date)?;
        let end_time = self.parse_date(&query.end_date)?;
        
        let metrics = self.metrics_store.get_metrics(
            None,
            start_time,
            end_time,
            None,
            Some(10000)
        ).await?;
        
        let export_data = json!({
            "export_type": "metrics",
            "format": "json",
            "exported_at": Utc::now(),
            "query": {
                "start_date": query.start_date,
                "end_date": query.end_date,
                "metric_types": query.metric_types
            },
            "data": metrics,
            "total_records": metrics.len()
        });
        
        Ok(serde_json::to_vec_pretty(&export_data)?)
    }
    
    async fn export_logs_csv(&self, query: ExportQuery) -> Result<Vec<u8>> {
        let start_time = self.parse_date(&query.start_date)?;
        let end_time = self.parse_date(&query.end_date)?;
        let log_level = query.log_level.as_deref();
        
        let logs = self.log_store.get_logs(
            start_time,
            end_time,
            log_level,
            Some(10000)
        ).await?;
        
        let mut writer = WriterBuilder::new()
            .has_headers(true)
            .from_writer(vec![]);
        
        // Write header
        writer.write_record(&["timestamp", "level", "message", "target", "module"])?;
        
        // Write data
        for log in logs {
            writer.write_record(&[
                log.timestamp.to_rfc3339(),
                log.level,
                log.message,
                log.target.unwrap_or_default(),
                log.module.unwrap_or_default()
            ])?;
        }
        
        Ok(writer.into_inner()?)
    }
    
    async fn export_config_json(&self, _query: ExportQuery) -> Result<Vec<u8>> {
        // This would get the current configuration
        let config = self.get_current_config().await?;
        
        let export_data = json!({
            "export_type": "config",
            "format": "json",
            "exported_at": Utc::now(),
            "config": config
        });
        
        Ok(serde_json::to_vec_pretty(&export_data)?)
    }
    
    async fn export_config_toml(&self, _query: ExportQuery) -> Result<Vec<u8>> {
        let config = self.get_current_config().await?;
        let toml_string = toml::to_string_pretty(&config)?;
        Ok(toml_string.into_bytes())
    }
    
    fn parse_date(&self, date_str: &Option<String>) -> Result<Option<DateTime<Utc>>> {
        match date_str {
            Some(s) => Ok(Some(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))),
            None => Ok(None)
        }
    }
    
    async fn get_current_config(&self) -> Result<serde_json::Value> {
        // Implementation to get current configuration
        // This would typically come from a config manager
        Ok(json!({
            "dashboard": {
                "port": 7620,
                "bind_address": "127.0.0.1",
                "enable_cors": true
            },
            "security": {
                "enable_auth": false,
                "session_timeout": 3600
            },
            "logging": {
                "level": "info",
                "format": "json"
            }
        }))
    }
}
```

#### **Export API Handler**
```rust
// Add to src/dashboard/mod.rs
async fn export_data_handler(
    State(state): State<DashboardState>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, StatusCode> {
    let exporter = DataExporter::new(
        state.metrics_store.clone(),
        state.log_store.clone()
    );
    
    match exporter.export_data(query).await {
        Ok(data) => {
            let content_type = match query.format.as_str() {
                "csv" => "text/csv",
                "json" => "application/json",
                "xml" => "application/xml",
                "toml" => "application/toml",
                _ => "application/octet-stream"
            };
            
            let filename = format!("{}_{}.{}", 
                query.r#type, 
                Utc::now().format("%Y%m%d_%H%M%S"), 
                query.format
            );
            
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", content_type)
                .header("Content-Disposition", format!("attachment; filename=\"{}\"", filename))
                .header("Content-Length", data.len().to_string())
                .body(axum::body::Body::from(data))
                .unwrap())
        }
        Err(e) => {
            tracing::error!("Export failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
```

#### **Frontend Export Interface**
```javascript
// Data export functionality
class DataExporter {
    constructor() {
        this.setupExportButtons();
        this.setupExportForms();
    }
    
    setupExportButtons() {
        // Quick export buttons
        document.getElementById('export-metrics-csv')?.addEventListener('click', () => {
            this.exportData('metrics', 'csv', this.getMetricsFilters());
        });
        
        document.getElementById('export-metrics-json')?.addEventListener('click', () => {
            this.exportData('metrics', 'json', this.getMetricsFilters());
        });
        
        document.getElementById('export-logs-csv')?.addEventListener('click', () => {
            this.exportData('logs', 'csv', this.getLogFilters());
        });
        
        document.getElementById('export-config-json')?.addEventListener('click', () => {
            this.exportData('config', 'json', {});
        });
    }
    
    setupExportForms() {
        // Advanced export form
        const exportForm = document.getElementById('advanced-export-form');
        if (exportForm) {
            exportForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.performAdvancedExport();
            });
        }
    }
    
    async exportData(dataType, format, filters = {}) {
        try {
            this.showExportProgress(true);
            
            const params = new URLSearchParams({
                type: dataType,
                format: format,
                ...filters
            });
            
            const response = await fetch(`/api/export?${params}`);
            
            if (!response.ok) {
                throw new Error(`Export failed: ${response.statusText}`);
            }
            
            // Get filename from Content-Disposition header
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = `export.${format}`;
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename="([^"]+)"/);
                if (filenameMatch) {
                    filename = filenameMatch[1];
                }
            }
            
            // Download the file
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            this.showExportProgress(false);
            this.showNotification(`Export completed: ${filename}`, 'success');
            
        } catch (error) {
            console.error('Export error:', error);
            this.showExportProgress(false);
            this.showNotification('Export failed: ' + error.message, 'error');
        }
    }
    
    async performAdvancedExport() {
        const dataType = document.getElementById('export-type').value;
        const format = document.getElementById('export-format').value;
        const startDate = document.getElementById('export-start-date').value;
        const endDate = document.getElementById('export-end-date').value;
        
        const filters = {};
        if (startDate) filters.start_date = startDate;
        if (endDate) filters.end_date = endDate;
        
        // Add type-specific filters
        if (dataType === 'metrics') {
            const metricTypes = document.getElementById('export-metric-types');
            if (metricTypes && metricTypes.value) {
                filters.metric_types = metricTypes.value;
            }
        } else if (dataType === 'logs') {
            const logLevel = document.getElementById('export-log-level');
            if (logLevel && logLevel.value) {
                filters.log_level = logLevel.value;
            }
        }
        
        await this.exportData(dataType, format, filters);
    }
    
    getMetricsFilters() {
        const startDate = document.getElementById('metrics-start-date')?.value;
        const endDate = document.getElementById('metrics-end-date')?.value;
        const metricTypes = document.getElementById('metrics-metric-types')?.value;
        
        const filters = {};
        if (startDate) filters.start_date = startDate;
        if (endDate) filters.end_date = endDate;
        if (metricTypes) filters.metric_types = metricTypes;
        
        return filters;
    }
    
    getLogFilters() {
        const startDate = document.getElementById('logs-start-date')?.value;
        const endDate = document.getElementById('logs-end-date')?.value;
        const logLevel = document.getElementById('logs-log-level')?.value;
        
        const filters = {};
        if (startDate) filters.start_date = startDate;
        if (endDate) filters.end_date = endDate;
        if (logLevel) filters.log_level = logLevel;
        
        return filters;
    }
    
    showExportProgress(show) {
        const progressElement = document.getElementById('export-progress');
        if (progressElement) {
            progressElement.style.display = show ? 'block' : 'none';
        }
    }
    
    showNotification(message, type) {
        // Reuse notification system from UserManager or create own
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-lg text-white z-50 ${
            type === 'success' ? 'bg-green-500' :
            type === 'error' ? 'bg-red-500' : 'bg-blue-500'
        }`;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
}
```

#### **Export UI Components**
```html
<!-- Add to dashboard HTML -->
<div class="bg-white rounded-lg shadow-md p-6 mb-6">
    <h2 class="text-xl font-bold mb-4">Data Export</h2>
    
    <!-- Quick Export Buttons -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <button id="export-metrics-csv" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            📊 Metrics (CSV)
        </button>
        <button id="export-metrics-json" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            📊 Metrics (JSON)
        </button>
        <button id="export-logs-csv" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            📝 Logs (CSV)
        </button>
        <button id="export-config-json" class="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            ⚙️ Config (JSON)
        </button>
    </div>
    
    <!-- Advanced Export Form -->
    <div class="border-t pt-4">
        <h3 class="text-lg font-semibold mb-3">Advanced Export</h3>
        <form id="advanced-export-form" class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                    <label class="block text-sm font-medium mb-1">Data Type</label>
                    <select id="export-type" class="w-full border rounded px-3 py-2">
                        <option value="metrics">Metrics</option>
                        <option value="logs">Logs</option>
                        <option value="config">Configuration</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Format</label>
                    <select id="export-format" class="w-full border rounded px-3 py-2">
                        <option value="csv">CSV</option>
                        <option value="json">JSON</option>
                        <option value="xml">XML</option>
                        <option value="toml">TOML (Config only)</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Date Range</label>
                    <div class="flex space-x-2">
                        <input type="date" id="export-start-date" class="flex-1 border rounded px-3 py-2">
                        <input type="date" id="export-end-date" class="flex-1 border rounded px-3 py-2">
                    </div>
                </div>
            </div>
            
            <!-- Type-specific filters -->
            <div id="metrics-filters" class="hidden">
                <label class="block text-sm font-medium mb-1">Metric Types (comma-separated)</label>
                <input type="text" id="export-metric-types" class="w-full border rounded px-3 py-2" 
                       placeholder="cpu_usage,memory_usage,network_traffic">
            </div>
            
            <div id="logs-filters" class="hidden">
                <label class="block text-sm font-medium mb-1">Log Level</label>
                <select id="export-log-level" class="w-full border rounded px-3 py-2">
                    <option value="">All Levels</option>
                    <option value="error">Error</option>
                    <option value="warn">Warning</option>
                    <option value="info">Info</option>
                    <option value="debug">Debug</option>
                </select>
            </div>
            
            <div id="export-progress" class="hidden">
                <div class="flex items-center">
                    <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-500 mr-2"></div>
                    <span>Exporting data...</span>
                </div>
            </div>
            
            <button type="submit" class="bg-green-500 text-white px-6 py-2 rounded hover:bg-green-600">
                Export Data
            </button>
        </form>
    </div>
</div>
```

#### **Implementation Steps**
- **Day 1**: Create export API endpoints for metrics and logs
- **Day 2**: Implement CSV, JSON, and XML format converters
- **Day 3**: Build frontend export interface with filters
- **Day 4**: Add scheduled export and email functionality

---

## 🌓 **Feature 5: Dark Mode Theme System**

### **Documentation Reference**
- Dashboard Expansion Documentation (Lines 766-767)
- Modern UI/UX requirements

### **Current Gap**
No theme switching, only light mode available

### **Implementation Details**

#### **Theme CSS System**
```css
/* Add to src/dashboard/static/styles.css */
:root {
    /* Light theme (default) */
    --bg-primary: #ffffff;
    --bg-secondary: #f8fafc;
    --bg-tertiary: #f1f5f9;
    --bg-accent: #e0f2fe;
    
    --text-primary: #1e293b;
    --text-secondary: #64748b;
    --text-tertiary: #94a3b8;
    --text-inverse: #ffffff;
    
    --border-primary: #e2e8f0;
    --border-secondary: #cbd5e1;
    --border-tertiary: #94a3b8;
    
    --accent-primary: #3b82f6;
    --accent-secondary: #10b981;
    --accent-danger: #ef4444;
    --accent-warning: #f59e0b;
    --accent-info: #06b6d4;
    
    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    
    --chart-grid: rgba(0, 0, 0, 0.1);
    --chart-text: #64748b;
}

[data-theme="dark"] {
    /* Dark theme */
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-tertiary: #334155;
    --bg-accent: #1e3a8a;
    
    --text-primary: #f8fafc;
    --text-secondary: #cbd5e1;
    --text-tertiary: #94a3b8;
    --text-inverse: #0f172a;
    
    --border-primary: #334155;
    --border-secondary: #475569;
    --border-tertiary: #64748b;
    
    --accent-primary: #60a5fa;
    --accent-secondary: #34d399;
    --accent-danger: #f87171;
    --accent-warning: #fbbf24;
    --accent-info: #22d3ee;
    
    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.3);
    --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
    --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.3), 0 4px 6px -2px rgba(0, 0, 0, 0.2);
    
    --chart-grid: rgba(255, 255, 255, 0.1);
    --chart-text: #cbd5e1;
}

[data-theme="auto"] {
    /* Will be set by JavaScript based on system preference */
}

/* Apply theme variables to components */
body {
    background-color: var(--bg-primary);
    color: var(--text-primary);
    transition: background-color 0.3s ease, color 0.3s ease;
}

.dashboard-card {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    color: var(--text-primary);
    box-shadow: var(--shadow-sm);
    transition: all 0.3s ease;
}

.dashboard-card:hover {
    box-shadow: var(--shadow-md);
}

.metric-card {
    background-color: var(--bg-secondary);
    border: 1px solid var(--border-primary);
    color: var(--text-primary);
}

.metric-card h3 {
    color: var(--text-secondary);
}

.metric-value {
    color: var(--accent-primary);
}

.btn-primary {
    background-color: var(--accent-primary);
    color: var(--text-inverse);
    border: 1px solid var(--accent-primary);
}

.btn-primary:hover {
    opacity: 0.9;
}

.btn-secondary {
    background-color: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border-secondary);
}

.navbar {
    background-color: var(--bg-secondary);
    border-bottom: 1px solid var(--border-primary);
}

.navbar a {
    color: var(--text-secondary);
}

.navbar a:hover {
    color: var(--accent-primary);
}

.alert-info {
    background-color: var(--bg-accent);
    border-color: var(--accent-info);
    color: var(--text-primary);
}

.alert-warning {
    background-color: rgba(245, 158, 11, 0.1);
    border-color: var(--accent-warning);
    color: var(--text-primary);
}

.alert-error {
    background-color: rgba(239, 68, 68, 0.1);
    border-color: var(--accent-danger);
    color: var(--text-primary);
}

.form-input {
    background-color: var(--bg-primary);
    border: 1px solid var(--border-primary);
    color: var(--text-primary);
}

.form-input:focus {
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
}

/* Chart theme variables */
.chart-container {
    --chart-background: var(--bg-secondary);
    --chart-grid-color: var(--chart-grid);
    --chart-text-color: var(--chart-text);
    --chart-line-color: var(--accent-primary);
}

/* Smooth transitions for theme switching */
* {
    transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
}
```

#### **Theme Toggle API**
```rust
// Add to src/dashboard/theme_manager.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemePreference {
    pub user_id: String,
    pub theme: String, // "light", "dark", "auto"
    pub custom_colors: Option<HashMap<String, String>>,
}

pub struct ThemeManager {
    preferences: Arc<RwLock<HashMap<String, ThemePreference>>>,
    default_theme: String,
}

impl ThemeManager {
    pub fn new(default_theme: String) -> Self {
        Self {
            preferences: Arc::new(RwLock::new(HashMap::new())),
            default_theme,
        }
    }
    
    pub async fn set_theme(&self, user_id: &str, theme: String) -> Result<()> {
        let mut prefs = self.preferences.write().await;
        let preference = ThemePreference {
            user_id: user_id.to_string(),
            theme,
            custom_colors: None,
        };
        prefs.insert(user_id.to_string(), preference);
        Ok(())
    }
    
    pub async fn get_theme(&self, user_id: &str) -> String {
        let prefs = self.preferences.read().await;
        prefs.get(user_id)
            .map(|p| p.theme.clone())
            .unwrap_or_else(|| self.default_theme.clone())
    }
    
    pub async fn get_effective_theme(&self, user_id: &str) -> String {
        let theme = self.get_theme(user_id).await;
        
        if theme == "auto" {
            // Check system preference (this would come from a request header or client info)
            "light" // Default to light for now, in practice you'd detect this
        } else {
            theme
        }
    }
}
```

#### **Theme API Endpoints**
```rust
// Add to src/dashboard/mod.rs
async fn set_theme_preference_handler(
    State(state): State<DashboardState>,
    Json(request): Json<ThemePreference>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.theme_manager.set_theme(&request.user_id, request.theme).await {
        Ok(_) => Ok(Json(json!({
            "status": "success",
            "theme": request.theme
        }))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

async fn get_theme_preference_handler(
    State(state): State<DashboardState>,
    Query(params): Query<ThemeQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let theme = state.theme_manager.get_theme(&params.user_id).await;
    let effective_theme = state.theme_manager.get_effective_theme(&params.user_id).await;
    
    Ok(Json(json!({
        "status": "success",
        "theme": theme,
        "effective_theme": effective_theme
    })))
}
```

#### **Frontend Theme Management**
```javascript
// Theme management class
class ThemeManager {
    constructor() {
        this.currentTheme = localStorage.getItem('theme') || 'light';
        this.applyTheme(this.currentTheme);
        this.setupThemeToggle();
        this.setupSystemThemeDetection();
        this.initializeChartTheme();
    }
    
    setupThemeToggle() {
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                this.toggleTheme();
            });
            
            // Update toggle button state
            this.updateThemeToggle();
        }
    }
    
    setupSystemThemeDetection() {
        // Detect system theme preference
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            if (this.currentTheme === 'system') {
                this.applyTheme('dark');
            }
        }
        
        // Listen for system theme changes
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
            if (this.currentTheme === 'system') {
                this.applyTheme(e.matches ? 'dark' : 'light');
            }
        });
    }
    
    async toggleTheme() {
        const themes = ['light', 'dark', 'system'];
        const currentIndex = themes.indexOf(this.currentTheme);
        const nextTheme = themes[(currentIndex + 1) % themes.length];
        
        await this.setTheme(nextTheme);
    }
    
    async setTheme(theme) {
        this.currentTheme = theme;
        localStorage.setItem('theme', theme);
        
        // Apply theme
        let actualTheme = theme;
        if (theme === 'system') {
            actualTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }
        
        this.applyTheme(actualTheme);
        this.updateThemeToggle();
        
        // Update chart colors
        this.updateChartTheme(actualTheme);
        
        // Save preference to server
        try {
            const response = await fetch('/api/theme/preference', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.getAuthToken()}`
                },
                body: JSON.stringify({ 
                    user_id: this.getCurrentUserId(),
                    theme 
                })
            });
            
            if (!response.ok) {
                console.warn('Failed to save theme preference to server');
            }
        } catch (error) {
            console.warn('Failed to save theme preference:', error);
        }
    }
    
    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        
        // Update meta theme-color for mobile browsers
        const themeColor = theme === 'dark' ? '#0f172a' : '#ffffff';
        let metaThemeColor = document.querySelector('meta[name="theme-color"]');
        if (metaThemeColor) {
            metaThemeColor.setAttribute('content', themeColor);
        } else {
            metaThemeColor = document.createElement('meta');
            metaThemeColor.setAttribute('name', 'theme-color');
            metaThemeColor.setAttribute('content', themeColor);
            document.head.appendChild(metaThemeColor);
        }
    }
    
    updateThemeToggle() {
        const toggle = document.getElementById('theme-toggle');
        if (!toggle) return;
        
        const icons = {
            'light': '🌙',
            'dark': '☀️',
            'system': '💻'
        };
        
        const descriptions = {
            'light': 'Switch to dark mode',
            'dark': 'Switch to system mode',
            'system': 'Switch to light mode'
        };
        
        toggle.innerHTML = `${icons[this.currentTheme] || '🌙'}`;
        toggle.title = `Current theme: ${this.currentTheme} - ${descriptions[this.currentTheme]}`;
        
        // Update dropdown if exists
        const themeSelect = document.getElementById('theme-select');
        if (themeSelect) {
            themeSelect.value = this.currentTheme;
        }
    }
    
    initializeChartTheme() {
        // Set initial chart colors
        this.updateChartTheme(this.getCurrentEffectiveTheme());
    }
    
    updateChartTheme(theme) {
        const isDark = theme === 'dark';
        
        // Update Chart.js defaults
        if (window.Chart) {
            Chart.defaults.color = isDark ? '#cbd5e1' : '#64748b';
            Chart.defaults.borderColor = isDark ? '#334155' : '#e2e8f0';
            Chart.defaults.backgroundColor = isDark ? '#1e293b' : '#ffffff';
            
            // Update existing charts
            Chart.helpers.each(Chart.instances, (instance) => {
                if (instance.options.plugins) {
                    instance.options.plugins.legend.labels.color = isDark ? '#cbd5e1' : '#1e293b';
                    instance.options.plugins.title.color = isDark ? '#cbd5e1' : '#1e293b';
                }
                
                if (instance.options.scales) {
                    Object.values(instance.options.scales).forEach(scale => {
                        if (scale.ticks) scale.ticks.color = isDark ? '#cbd5e1' : '#64748b';
                        if (scale.grid) scale.grid.color = isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
                    });
                }
                
                instance.update('none'); // Update without animation for instant theme change
            });
        }
    }
    
    getCurrentEffectiveTheme() {
        if (this.currentTheme === 'system') {
            return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }
        return this.currentTheme;
    }
    
    getAuthToken() {
        return localStorage.getItem('authToken') || '';
    }
    
    getCurrentUserId() {
        // This would typically come from the current user context
        return localStorage.getItem('currentUserId') || 'anonymous';
    }
    
    // Method to add custom theme colors
    setCustomColors(colors) {
        const root = document.documentElement;
        Object.entries(colors).forEach(([property, value]) => {
            root.style.setProperty(property, value);
        });
    }
    
    // Method to reset to default colors
    resetCustomColors() {
        const root = document.documentElement;
        // Remove all custom CSS variables
        Array.from(root.style).forEach(property => {
            if (property.startsWith('--')) {
                root.style.removeProperty(property);
            }
        });
    }
}
```

#### **Theme Toggle UI Components**
```html
<!-- Add to dashboard HTML header -->
<div class="flex items-center space-x-4">
    <!-- Theme Toggle Button -->
    <button id="theme-toggle" 
            class="p-2 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            title="Toggle theme">
        🌙
    </button>
    
    <!-- Theme Dropdown (alternative) -->
    <select id="theme-select" 
            class="px-3 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100">
        <option value="light">🌞 Light</option>
        <option value="dark">🌙 Dark</option>
        <option value="system">💻 System</option>
    </select>
</div>

<!-- Theme customization panel (optional) -->
<div id="theme-panel" class="hidden fixed right-4 top-16 bg-white dark:bg-gray-800 rounded-lg shadow-lg p-4 w-64">
    <h3 class="font-semibold mb-3">Theme Customization</h3>
    
    <div class="space-y-3">
        <div>
            <label class="block text-sm font-medium mb-1">Primary Color</label>
            <input type="color" id="primary-color" class="w-full h-8 rounded">
        </div>
        
        <div>
            <label class="block text-sm font-medium mb-1">Accent Color</label>
            <input type="color" id="accent-color" class="w-full h-8 rounded">
        </div>
        
        <div class="flex space-x-2">
            <button id="apply-custom-colors" class="flex-1 bg-blue-500 text-white px-3 py-1 rounded text-sm">
                Apply
            </button>
            <button id="reset-colors" class="flex-1 bg-gray-500 text-white px-3 py-1 rounded text-sm">
                Reset
            </button>
        </div>
    </div>
</div>
```

#### **Implementation Steps**
- **Day 1**: Create CSS theme system with variables
- **Day 2**: Implement theme toggle API endpoints
- **Day 3**: Build frontend theme management with system detection
- **Day 4**: Add chart theme updates and custom color support

---

# 📅 **Complete Implementation Timeline**

| **Week** | **Feature** | **Days** | **Priority** | **Dependencies** |
|----------|-------------|----------|--------------|------------------|
| **Week 1** | Real-time Alert System | 4 days | Critical | WebSocket infrastructure |
| **Week 2** | Historical Data Persistence | 4 days | Critical | SQLite database setup |
| **Week 3** | User Management System | 4 days | High | Authentication framework |
| **Week 4** | Data Export Functionality | 4 days | Medium | Historical data storage |
| **Week 5** | Dark Mode Theme System | 4 days | Low | CSS infrastructure |

---

# 🎯 **Success Metrics & KPIs**

## **Feature 1: Real-time Alert System**
- **Alert Delivery**: < 5 seconds from event to notification
- **WebSocket Reliability**: 99.9% connection uptime
- **Alert Capacity**: Support 1000+ concurrent alerts
- **User Engagement**: 90% of critical alerts acknowledged within 1 minute

## **Feature 2: Historical Data Persistence**
- **Query Performance**: < 100ms for 30-day metric queries
- **Storage Efficiency**: Compress data to < 50% of original size
- **Retention**: 30-day default retention with configurable cleanup
- **Data Integrity**: 99.99% data accuracy with backup verification

## **Feature 3: User Management System**
- **Authentication Speed**: < 500ms login time
- **Concurrent Users**: Support 100+ simultaneous users
- **Permission Accuracy**: 100% correct role-based access control
- **Session Security**: 24-hour session timeout with secure JWT

## **Feature 4: Data Export Functionality**
- **Export Speed**: Handle 10MB+ exports without timeout
- **Format Support**: CSV, JSON, XML, TOML with 100% format compliance
- **User Experience**: Simple 3-click export process
- **Scheduled Exports**: Automated daily/weekly exports via email

## **Feature 5: Dark Mode Theme System**
- **Theme Switching**: Instant (< 100ms) theme transitions
- **Visual Consistency**: 100% component coverage across themes
- **User Preference**: 80% of users adopt dark mode within first week
- **Accessibility**: WCAG 2.1 AA compliance in all themes

---

# 🔧 **Technical Requirements & Dependencies**

## **New Dependencies**
```toml
# Add to Cargo.toml
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "sqlite", "chrono", "uuid"] }
bcrypt = "0.15"
jsonwebtoken = "9.1"
uuid = { version = "1.6", features = ["v4", "serde"] }
csv = "1.3"
xml-rs = "0.8"
toml = "0.8"

# Update existing dependencies
axum = "0.7"
tokio = { version = "1.35", features = ["full"] }
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
```

## **Database Schema**
```sql
-- Metrics table (already implemented)
CREATE TABLE metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    metric_type TEXT NOT NULL,
    value REAL NOT NULL,
    labels TEXT,
    unit TEXT
);

-- Users table
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    permissions TEXT, -- JSON array
    created_at DATETIME NOT NULL,
    last_login DATETIME,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT
);

-- Alerts table
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by TEXT,
    acknowledged_at DATETIME,
    metadata TEXT -- JSON object
);

-- Theme preferences table
CREATE TABLE theme_preferences (
    user_id TEXT PRIMARY KEY,
    theme TEXT NOT NULL DEFAULT 'light',
    custom_colors TEXT, -- JSON object
    updated_at DATETIME NOT NULL
);
```

## **Performance Requirements**
- **Memory Usage**: < 512MB for dashboard with all features
- **CPU Usage**: < 25% under normal load
- **Disk Space**: < 100MB for 30 days of metrics data
- **Network Latency**: < 50ms response time for API calls
- **Concurrent Connections**: Support 100+ WebSocket connections

---

# 🚀 **Deployment & Configuration**

## **Environment Variables**
```bash
# Database Configuration
DATABASE_URL=sqlite:///data/wolf_prowler.db

# Authentication Configuration
JWT_SECRET=your-super-secret-jwt-key-here
SESSION_TIMEOUT_HOURS=24

# Alert Configuration
ALERT_RETENTION_DAYS=7
MAX_ALERTS_PER_USER=1000

# Export Configuration
EXPORT_MAX_SIZE_MB=50
EXPORT_TEMP_DIR=/tmp/exports

# Theme Configuration
DEFAULT_THEME=light
THEME_CACHE_TTL_HOURS=24
```

## **Configuration Updates**
```toml
# Add to config files
[dashboard.features]
real_time_alerts = true
historical_data = true
user_management = true
data_export = true
dark_mode = true

[database]
retention_days = 30
cleanup_interval_hours = 24
max_file_size_mb = 100

[alerts]
max_alerts = 1000
retention_days = 7
notification_sound = true
browser_notifications = true

[export]
max_file_size_mb = 50
supported_formats = ["csv", "json", "xml", "toml"]
temp_directory = "/tmp/exports"

[themes]
default = "light"
allow_custom_colors = true
cache_duration_hours = 24
```

---

# 🧪 **Testing Strategy**

## **Unit Tests**
- Alert creation, acknowledgment, and broadcasting
- User authentication and role-based access control
- Data export format validation
- Theme switching and CSS variable application

## **Integration Tests**
- WebSocket alert delivery
- Historical data queries and aggregation
- Multi-user concurrent access
- Export file generation and download

## **End-to-End Tests**
- Complete user workflow from login to export
- Real-time alert notification flow
- Theme persistence across sessions
- Historical data visualization

## **Performance Tests**
- 1000 concurrent WebSocket connections
- 1M metrics database query performance
- Large export file generation (>10MB)
- Theme switching responsiveness

---

# 📋 **Implementation Checklist**

## **Pre-Implementation**
- [ ] Review and approve technical specifications
- [ ] Set up development environment with new dependencies
- [ ] Create feature branches for each major feature
- [ ] Establish testing framework and CI/CD pipeline

## **Feature Implementation**
- [ ] **Real-time Alert System**: WebSocket infrastructure, AlertManager, frontend UI
- [ ] **Historical Data Persistence**: Database setup, MetricsStore, API endpoints, frontend charts
- [ ] **User Management System**: Authentication, RBAC middleware, user API, login UI
- [ ] **Data Export Functionality**: Export API, format converters, frontend interface
- [ ] **Dark Mode Theme System**: CSS variables, theme API, frontend management

## **Post-Implementation**
- [ ] Comprehensive testing (unit, integration, e2e)
- [ ] Performance benchmarking and optimization
- [ ] Documentation updates and user guides
- [ ] Security audit and penetration testing
- [ ] Production deployment and monitoring

---

# 🎯 **Conclusion**

This implementation plan addresses the **5 most critical gaps** identified in the Wolf Prowler documentation:

1. **Real-time Alert System** - Proactive security monitoring
2. **Historical Data Persistence** - Trend analysis and reporting
3. **User Management System** - Multi-user support and access control
4. **Data Export Functionality** - External analysis and compliance
5. **Dark Mode Theme System** - Modern user experience

The plan provides **detailed technical specifications**, **clear implementation steps**, and **measurable success metrics**. Following this roadmap will transform the Wolf Prowler dashboard from a basic monitoring tool into a **production-ready enterprise security platform**.

**Estimated completion time**: **5 weeks** with focused development effort  
**Expected impact**: **10x improvement** in dashboard capabilities and production readiness

---

*This implementation plan serves as the foundation for transforming Wolf Prowler's dashboard into a comprehensive, enterprise-grade security monitoring platform.*
