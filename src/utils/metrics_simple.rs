//! Simplified metrics collection for Wolf Prowler

use crate::core::settings::WolfRole;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use sysinfo::System;
use uuid::Uuid;

lazy_static::lazy_static! {
    static ref SYSTEM: Mutex<System> = Mutex::new(System::new_all());
}

/// Simple metrics collector
pub struct MetricsCollector {
    /// Network metrics
    network: NetworkMetrics,
    /// Security metrics
    security: SecurityMetrics,
    /// Pack metrics
    pack: PackMetrics,
    /// Performance metrics
    performance: PerformanceMetrics,
    /// Collection start time
    pub start_time: DateTime<Utc>,
    /// Request count (legacy compatibility)
    pub request_count: u64,
    /// Error count (legacy compatibility)
    pub error_count: u64,
    /// Peer-specific metrics
    pub peer_metrics: HashMap<String, PeerMetrics>,
    /// Active connections (compatibility)
    pub active_connections: u32,
    /// Security events log
    pub security_events: Vec<SystemEvent>,
}

/// System event for the dashboard event log
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SystemEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub message: String,
    pub severity: String,
    pub source: String,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub metadata: HashMap<String, String>,
    pub correlation_id: Option<String>,
}

impl SystemEvent {
    pub fn security(
        event_type: impl Into<String>,
        message: impl Into<String>,
        severity: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: event_type.into(),
            message: message.into(),
            severity: severity.into(),
            source: "wolf_prowler".to_string(),
            user_id: None,
            ip_address: None,
            metadata: HashMap::new(),
            correlation_id: None,
        }
    }
}

/// Peer-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerMetrics {
    pub peer_id: String,
    pub last_seen: DateTime<Utc>,
    pub message_count: u64,
    pub error_count: u64,
    pub avg_response_time: f64,
    pub role: WolfRole,
}

/// Network metrics
#[derive(Debug, Clone, Default)]
pub struct NetworkMetrics {
    pub connections_total: u64,
    pub connections_active: u64,
    pub messages_sent_total: u64,
    pub messages_received_total: u64,
    pub bytes_transferred_total: u64,
    pub total_connection_duration_ms: u64,
    pub total_message_latency_ms: u64,
    pub latency_measurements_count: u64,
}

/// Security metrics
#[derive(Debug, Clone, Default)]
pub struct SecurityMetrics {
    pub security_events_total: u64,
    pub threats_detected_total: u64,
    pub auth_failures_total: u64,
    pub pack_coordinations_total: u64,
    pub howls_sent_total: u64,
    pub howls_received_total: u64,
}

/// Pack metrics
#[derive(Debug, Clone, Default)]
pub struct PackMetrics {
    pub pack_formations_total: u64,
    pub packs_active: u64,
    pub pack_members_total: u64,
    pub hunts_initiated_total: u64,
    pub hunts_completed_total: u64,
    pub territories_claimed_total: u64,
}

/// Performance metrics
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub avg_request_duration: f64,
    pub error_rate: f64,
}

/// Metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: String,
    pub network: NetworkMetricsSnapshot,
    pub security: SecurityMetricsSnapshot,
    pub pack: PackMetricsSnapshot,
    pub performance: PerformanceMetricsSnapshot,
    pub custom: std::collections::HashMap<String, f64>,
}

/// Network metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetricsSnapshot {
    pub connections_total: u64,
    pub connections_active: u64,
    pub messages_sent_total: u64,
    pub messages_received_total: u64,
    pub bytes_transferred_total: u64,
    pub avg_connection_duration: f64,
    pub avg_message_latency: f64,
}

/// Security metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetricsSnapshot {
    pub security_events_total: u64,
    pub threats_detected_total: u64,
    pub auth_failures_total: u64,
    pub pack_coordinations_total: u64,
    pub howls_sent_total: u64,
    pub howls_received_total: u64,
}

/// Pack metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackMetricsSnapshot {
    pub pack_formations_total: u64,
    pub packs_active: u64,
    pub pack_members_total: u64,
    pub hunts_initiated_total: u64,
    pub hunts_completed_total: u64,
    pub territories_claimed_total: u64,
}

/// Performance metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetricsSnapshot {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub avg_request_duration: f64,
    pub error_rate: f64,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            network: NetworkMetrics::default(),
            security: SecurityMetrics::default(),
            pack: PackMetrics::default(),
            performance: PerformanceMetrics::default(),
            start_time: Utc::now(),
            request_count: 0,
            error_count: 0,
            active_connections: 0,
            peer_metrics: HashMap::new(),
            security_events: Vec::new(),
        }
    }

    /// Record a new connection
    pub fn record_connection(&mut self) {
        self.network.connections_total += 1;
        self.network.connections_active += 1;
    }

    /// Record a connection closed with duration
    pub fn record_connection_closed(&mut self, duration: Duration) {
        if self.network.connections_active > 0 {
            self.network.connections_active -= 1;
        }
        self.network.total_connection_duration_ms += duration.as_millis() as u64;
    }

    /// Record a message sent
    pub fn record_message_sent(&mut self, bytes: usize) {
        self.network.messages_sent_total += 1;
        self.network.bytes_transferred_total += bytes as u64;
    }

    /// Record a message received with latency
    pub fn record_message_received(&mut self, bytes: usize, latency: Duration) {
        self.network.messages_received_total += 1;
        self.network.bytes_transferred_total += bytes as u64;
        self.network.total_message_latency_ms += latency.as_millis() as u64;
        self.network.latency_measurements_count += 1;
    }

    /// Record a security event
    pub fn record_security_event(&mut self) {
        self.security.security_events_total += 1;
    }

    /// Record a threat detected
    pub fn record_threat_detected(&mut self) {
        self.security.threats_detected_total += 1;
    }

    /// Record an authentication failure
    pub fn record_auth_failure(&mut self) {
        self.security.auth_failures_total += 1;
    }

    /// Record a pack coordination
    pub fn record_pack_coordination(&mut self) {
        self.security.pack_coordinations_total += 1;
    }

    /// Record a howl sent
    pub fn record_howl_sent(&mut self) {
        self.security.howls_sent_total += 1;
    }

    /// Record a howl received
    pub fn record_howl_received(&mut self) {
        self.security.howls_received_total += 1;
    }

    /// Record a pack formation
    pub fn record_pack_formation(&mut self) {
        self.pack.pack_formations_total += 1;
        self.pack.packs_active += 1;
    }

    /// Update pack member count
    pub fn update_pack_members(&mut self, count: u64) {
        self.pack.pack_members_total = count;
    }

    /// Record a hunt initiated
    pub fn record_hunt_initiated(&mut self) {
        self.pack.hunts_initiated_total += 1;
    }

    /// Record a hunt completed
    pub fn record_hunt_completed(&mut self) {
        self.pack.hunts_completed_total += 1;
    }

    /// Record a territory claimed
    pub fn record_territory_claimed(&mut self) {
        self.pack.territories_claimed_total += 1;
    }

    /// Update CPU usage
    pub fn update_cpu_usage(&mut self, usage: f64) {
        self.performance.cpu_usage = usage;
    }

    /// Update memory usage
    pub fn update_memory_usage(&mut self, usage: f64) {
        self.performance.memory_usage = usage;
    }

    /// Update disk usage
    pub fn update_disk_usage(&mut self, usage: f64) {
        self.performance.disk_usage = usage;
    }

    /// Update error rate
    pub fn update_error_rate(&mut self, rate: f64) {
        self.performance.error_rate = rate;
    }

    /// Update system metrics (CPU, Memory) using sysinfo
    pub fn update_system_metrics(&mut self) {
        if let Ok(mut sys) = SYSTEM.lock() {
            sys.refresh_cpu_all();
            sys.refresh_memory();

            self.performance.cpu_usage = sys.global_cpu_usage() as f64;

            let total_mem = sys.total_memory();
            let used_mem = sys.used_memory();
            if total_mem > 0 {
                self.performance.memory_usage = (used_mem as f64 / total_mem as f64) * 100.0;
            }
        }
    }

    /// Get network metrics snapshot
    pub fn get_network_snapshot(&self) -> NetworkMetricsSnapshot {
        let avg_conn_duration = if self.network.connections_total > self.network.connections_active
        {
            let closed_connections =
                self.network.connections_total - self.network.connections_active;
            if closed_connections > 0 {
                self.network.total_connection_duration_ms as f64 / closed_connections as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        let avg_latency = if self.network.latency_measurements_count > 0 {
            self.network.total_message_latency_ms as f64
                / self.network.latency_measurements_count as f64
        } else {
            0.0
        };

        NetworkMetricsSnapshot {
            connections_total: self.network.connections_total,
            connections_active: self.network.connections_active,
            messages_sent_total: self.network.messages_sent_total,
            messages_received_total: self.network.messages_received_total,
            bytes_transferred_total: self.network.bytes_transferred_total,
            avg_connection_duration: avg_conn_duration,
            avg_message_latency: avg_latency,
        }
    }

    /// Get performance/system metrics snapshot
    pub fn get_system_snapshot(&self) -> PerformanceMetricsSnapshot {
        PerformanceMetricsSnapshot {
            cpu_usage: self.performance.cpu_usage,
            memory_usage: self.performance.memory_usage,
            disk_usage: self.performance.disk_usage,
            avg_request_duration: self.performance.avg_request_duration,
            error_rate: self.performance.error_rate,
        }
    }

    /// Get metrics snapshot
    pub fn get_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp: chrono::Utc::now().to_rfc3339(),
            network: self.get_network_snapshot(),
            security: SecurityMetricsSnapshot {
                security_events_total: self.security.security_events_total,
                threats_detected_total: self.security.threats_detected_total,
                auth_failures_total: self.security.auth_failures_total,
                pack_coordinations_total: self.security.pack_coordinations_total,
                howls_sent_total: self.security.howls_sent_total,
                howls_received_total: self.security.howls_received_total,
            },
            pack: PackMetricsSnapshot {
                pack_formations_total: self.pack.pack_formations_total,
                packs_active: self.pack.packs_active,
                pack_members_total: self.pack.pack_members_total,
                hunts_initiated_total: self.pack.hunts_initiated_total,
                hunts_completed_total: self.pack.hunts_completed_total,
                territories_claimed_total: self.pack.territories_claimed_total,
            },
            performance: PerformanceMetricsSnapshot {
                cpu_usage: self.performance.cpu_usage,
                memory_usage: self.performance.memory_usage,
                disk_usage: self.performance.disk_usage,
                avg_request_duration: self.performance.avg_request_duration,
                error_rate: self.performance.error_rate,
            },
            custom: std::collections::HashMap::new(),
        }
    }

    /// Export metrics as JSON
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.get_snapshot())
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple metrics interface for easy access
pub trait Metrics {
    fn increment_counter(&mut self, name: &str);
    fn set_gauge(&mut self, name: &str, value: f64);
}

impl Metrics for MetricsCollector {
    fn increment_counter(&mut self, name: &str) {
        match name {
            "connections_total" => self.record_connection(),
            "security_events_total" => self.record_security_event(),
            "threats_detected_total" => self.record_threat_detected(),
            "pack_formations_total" => self.record_pack_formation(),
            "hunts_initiated_total" => self.record_hunt_initiated(),
            _ => {}
        }
    }

    fn set_gauge(&mut self, name: &str, value: f64) {
        match name {
            "cpu_usage" => self.update_cpu_usage(value),
            "memory_usage" => self.update_memory_usage(value),
            "disk_usage" => self.update_disk_usage(value),
            "error_rate" => self.update_error_rate(value),
            "pack_members" => self.update_pack_members(value as u64),
            _ => {}
        }
    }
}
