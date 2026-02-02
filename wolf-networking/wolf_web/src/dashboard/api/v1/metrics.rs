//! System Metrics API Endpoints
//!
//! This module provides API endpoints for accessing system performance
//! metrics and monitoring data.

use axum::extract::State;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::dashboard::state::AppState;

/// System metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    /// API request count
    pub request_count: u64,
    /// System uptime (seconds)
    pub uptime_seconds: u64,
    /// Memory usage (MB)
    pub memory_usage_mb: f64,
    /// CPU usage (%)
    pub cpu_usage_percent: f64,
    /// Active connections
    pub active_connections: usize,
    /// Total processed messages
    pub total_messages: u64,
    /// Average response time (ms)
    pub avg_response_time: f64,
}

/// Detailed metrics response
#[derive(Debug, Serialize, Deserialize)]
pub struct DetailedMetricsResponse {
    /// System metrics
    pub system: SystemMetrics,
    /// Network metrics
    pub network: NetworkMetrics,
    /// Security metrics
    pub security: SecurityMetrics,
    /// Performance metrics
    pub performance: PerformanceMetrics,
}

/// System metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// Memory usage percentage
    pub memory_usage: f64,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Disk usage percentage
    pub disk_usage: f64,
    /// System uptime in seconds
    pub uptime: u64,
}

/// Network metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Number of active connections
    pub active_connections: usize,
    /// Total messages processed
    pub total_messages: u64,
    /// Inbound bandwidth in MB/s
    pub bandwidth_in: f64,
    /// Outbound bandwidth in MB/s
    pub bandwidth_out: f64,
}

/// Security metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Rate of threat detection per second
    pub threat_detection_rate: f64,
    /// Rate of anomaly detection per second
    pub anomaly_detection_rate: f64,
    /// Number of reputation updates
    pub reputation_updates: u64,
    /// Total security events
    pub security_events: u64,
}

/// Performance metrics
#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Average response time in milliseconds
    pub avg_response_time: f64,
    /// Maximum response time in milliseconds
    pub max_response_time: f64,
    /// Request rate per second
    pub request_rate: f64,
    /// Error rate as percentage
    pub error_rate: f64,
}

/// Create metrics router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(get_metrics))
        .route("/detailed", get(get_detailed_metrics))
        .route("/system", get(get_system_metrics))
        .route("/performance", get(get_performance_metrics))
        .with_state(state)
}

/// Get basic metrics
async fn get_metrics(State(state): State<Arc<AppState>>) -> Json<MetricsResponse> {
    state.increment_request_count().await;

    let request_count = state.get_request_count().await;

    // Get real metrics from threat engine
    let threat_engine = state.threat_engine.lock().await;
    let status = threat_engine.get_status().await;
    let metrics = status.metrics;

    Json(MetricsResponse {
        request_count,
        uptime_seconds: status.uptime,
        memory_usage_mb: metrics.system.memory_usage,
        cpu_usage_percent: metrics.system.cpu_usage,
        active_connections: metrics.active_connections,
        total_messages: metrics.total_messages,
        avg_response_time: metrics.avg_response_time,
    })
}

/// Get detailed metrics
async fn get_detailed_metrics(State(state): State<Arc<AppState>>) -> Json<DetailedMetricsResponse> {
    state.increment_request_count().await;

    let threat_engine = state.threat_engine.lock().await;
    let status = threat_engine.get_status().await;
    let stats = status.metrics;

    Json(DetailedMetricsResponse {
        system: SystemMetrics {
            memory_usage: stats.system.memory_usage,
            cpu_usage: stats.system.cpu_usage,
            disk_usage: stats.system.disk_usage,
            uptime: status.uptime,
        },
        network: NetworkMetrics {
            active_connections: stats.active_connections,
            total_messages: stats.total_messages,
            bandwidth_in: stats.bandwidth_in,
            bandwidth_out: stats.bandwidth_out,
        },
        security: SecurityMetrics {
            threat_detection_rate: stats.active_threats as f64 / status.uptime.max(1) as f64,
            anomaly_detection_rate: stats.anomaly_detection_rate,
            reputation_updates: stats.reputation_updates,
            security_events: stats.total_events as u64,
        },
        performance: PerformanceMetrics {
            avg_response_time: stats.avg_response_time,
            max_response_time: stats.max_response_time,
            request_rate: stats.request_rate,
            error_rate: stats.error_rate,
        },
    })
}

/// Get system metrics
async fn get_system_metrics(State(state): State<Arc<AppState>>) -> Json<SystemMetrics> {
    state.increment_request_count().await;

    let threat_engine = state.threat_engine.lock().await;
    let status = threat_engine.get_status().await;
    let metrics = status.metrics;

    Json(SystemMetrics {
        memory_usage: metrics.system.memory_usage,
        cpu_usage: metrics.system.cpu_usage,
        disk_usage: metrics.system.disk_usage,
        uptime: status.uptime,
    })
}

/// Get performance metrics
async fn get_performance_metrics(State(state): State<Arc<AppState>>) -> Json<PerformanceMetrics> {
    state.increment_request_count().await;

    let threat_engine = state.threat_engine.lock().await;
    let status = threat_engine.get_status().await;
    let metrics = status.metrics;

    Json(PerformanceMetrics {
        avg_response_time: metrics.avg_response_time,
        max_response_time: metrics.max_response_time,
        request_rate: metrics.request_rate,
        error_rate: metrics.error_rate,
    })
}
