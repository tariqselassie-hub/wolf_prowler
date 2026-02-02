//! Metrics collection for Wolf Prowler

use anyhow::Result;
use prometheus::{Counter, Encoder, Gauge, Histogram, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Metrics collector for Wolf Prowler
pub struct MetricsCollector {
    /// Prometheus registry
    registry: Registry,
    /// Network metrics
    network: NetworkMetrics,
    /// Security metrics
    security: SecurityMetrics,
    /// Pack metrics
    pack: PackMetrics,
    /// Performance metrics
    performance: PerformanceMetrics,
    /// Custom metrics
    custom: HashMap<String, CustomMetric>,
}

/// Network metrics
#[derive(Debug)]
pub struct NetworkMetrics {
    /// Total connections
    pub connections_total: Counter,
    /// Active connections
    pub connections_active: Gauge,
    /// Messages sent
    pub messages_sent_total: Counter,
    /// Messages received
    pub messages_received_total: Counter,
    /// Bytes transferred
    pub bytes_transferred_total: Counter,
    /// Connection duration
    pub connection_duration: Histogram,
    /// Message latency
    pub message_latency: Histogram,
}

/// Security metrics
#[derive(Debug)]
pub struct SecurityMetrics {
    /// Security events
    pub security_events_total: Counter,
    /// Threats detected
    pub threats_detected_total: Counter,
    /// Authentication failures
    pub auth_failures_total: Counter,
    /// Pack coordinations
    pub pack_coordinations_total: Counter,
    /// Howls sent
    pub howls_sent_total: Counter,
    /// Howls received
    pub howls_received_total: Counter,
}

/// Pack metrics
#[derive(Debug)]
pub struct PackMetrics {
    /// Pack formations
    pub pack_formations_total: Counter,
    /// Active packs
    pub packs_active: Gauge,
    /// Pack members
    pub pack_members_total: Gauge,
    /// Hunts initiated
    pub hunts_initiated_total: Counter,
    /// Hunts completed
    pub hunts_completed_total: Counter,
    /// Territories claimed
    pub territories_claimed_total: Counter,
}

/// Performance metrics
#[derive(Debug)]
pub struct PerformanceMetrics {
    /// CPU usage
    pub cpu_usage: Gauge,
    /// Memory usage
    pub memory_usage: Gauge,
    /// Disk usage
    pub disk_usage: Gauge,
    /// Request duration
    pub request_duration: Histogram,
    /// Error rate
    pub error_rate: Gauge,
}

/// Custom metric
#[derive(Debug, Clone)]
pub struct CustomMetric {
    pub name: String,
    pub description: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub timestamp: Instant,
}

/// Metric types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Text,
}

/// Metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: String,
    pub network: NetworkMetricsSnapshot,
    pub security: SecurityMetricsSnapshot,
    pub pack: PackMetricsSnapshot,
    pub performance: PerformanceMetricsSnapshot,
    pub custom: HashMap<String, f64>,
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
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let network = NetworkMetrics {
            connections_total: Counter::new(
                "wolf_prowler_connections_total",
                "Total number of connections",
            )?,
            connections_active: Gauge::new(
                "wolf_prowler_connections_active",
                "Number of active connections",
            )?,
            messages_sent_total: Counter::new(
                "wolf_prowler_messages_sent_total",
                "Total number of messages sent",
            )?,
            messages_received_total: Counter::new(
                "wolf_prowler_messages_received_total",
                "Total number of messages received",
            )?,
            bytes_transferred_total: Counter::new(
                "wolf_prowler_bytes_transferred_total",
                "Total bytes transferred",
            )?,
            connection_duration: Histogram::with_opts(
                prometheus::HistogramOpts::new(
                    "wolf_prowler_connection_duration_seconds",
                    "Connection duration in seconds",
                )
                .buckets(vec![1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 600.0]),
            )?,
            message_latency: Histogram::with_opts(
                prometheus::HistogramOpts::new(
                    "wolf_prowler_message_latency_seconds",
                    "Message latency in seconds",
                )
                .buckets(vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0]),
            )?,
        };

        let security = SecurityMetrics {
            security_events_total: Counter::new(
                "wolf_prowler_security_events_total",
                "Total number of security events",
            )?,
            threats_detected_total: Counter::new(
                "wolf_prowler_threats_detected_total",
                "Total number of threats detected",
            )?,
            auth_failures_total: Counter::new(
                "wolf_prowler_auth_failures_total",
                "Total number of authentication failures",
            )?,
            pack_coordinations_total: Counter::new(
                "wolf_prowler_pack_coordinations_total",
                "Total number of pack coordinations",
            )?,
            howls_sent_total: Counter::new(
                "wolf_prowler_howls_sent_total",
                "Total number of howls sent",
            )?,
            howls_received_total: Counter::new(
                "wolf_prowler_howls_received_total",
                "Total number of howls received",
            )?,
        };

        let pack = PackMetrics {
            pack_formations_total: Counter::new(
                "wolf_prowler_pack_formations_total",
                "Total number of pack formations",
            )?,
            packs_active: Gauge::new("wolf_prowler_packs_active", "Number of active packs")?,
            pack_members_total: Gauge::new(
                "wolf_prowler_pack_members_total",
                "Total number of pack members",
            )?,
            hunts_initiated_total: Counter::new(
                "wolf_prowler_hunts_initiated_total",
                "Total number of hunts initiated",
            )?,
            hunts_completed_total: Counter::new(
                "wolf_prowler_hunts_completed_total",
                "Total number of hunts completed",
            )?,
            territories_claimed_total: Counter::new(
                "wolf_prowler_territories_claimed_total",
                "Total number of territories claimed",
            )?,
        };

        let performance = PerformanceMetrics {
            cpu_usage: Gauge::new("wolf_prowler_cpu_usage_percent", "CPU usage percentage")?,
            memory_usage: Gauge::new(
                "wolf_prowler_memory_usage_percent",
                "Memory usage percentage",
            )?,
            disk_usage: Gauge::new("wolf_prowler_disk_usage_percent", "Disk usage percentage")?,
            request_duration: Histogram::with_opts(
                prometheus::HistogramOpts::new(
                    "wolf_prowler_request_duration_seconds",
                    "Request duration in seconds",
                )
                .buckets(vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0]),
            )?,
            error_rate: Gauge::new("wolf_prowler_error_rate_percent", "Error rate percentage")?,
        };

        // Register all metrics
        registry.register(Box::new(network.connections_total.clone()))?;
        registry.register(Box::new(network.connections_active.clone()))?;
        registry.register(Box::new(network.messages_sent_total.clone()))?;
        registry.register(Box::new(network.messages_received_total.clone()))?;
        registry.register(Box::new(network.bytes_transferred_total.clone()))?;
        registry.register(Box::new(network.connection_duration.clone()))?;
        registry.register(Box::new(network.message_latency.clone()))?;

        registry.register(Box::new(security.security_events_total.clone()))?;
        registry.register(Box::new(security.threats_detected_total.clone()))?;
        registry.register(Box::new(security.auth_failures_total.clone()))?;
        registry.register(Box::new(security.pack_coordinations_total.clone()))?;
        registry.register(Box::new(security.howls_sent_total.clone()))?;
        registry.register(Box::new(security.howls_received_total.clone()))?;

        registry.register(Box::new(pack.pack_formations_total.clone()))?;
        registry.register(Box::new(pack.packs_active.clone()))?;
        registry.register(Box::new(pack.pack_members_total.clone()))?;
        registry.register(Box::new(pack.hunts_initiated_total.clone()))?;
        registry.register(Box::new(pack.hunts_completed_total.clone()))?;
        registry.register(Box::new(pack.territories_claimed_total.clone()))?;

        registry.register(Box::new(performance.cpu_usage.clone()))?;
        registry.register(Box::new(performance.memory_usage.clone()))?;
        registry.register(Box::new(performance.disk_usage.clone()))?;
        registry.register(Box::new(performance.request_duration.clone()))?;
        registry.register(Box::new(performance.error_rate.clone()))?;

        Ok(Self {
            registry,
            network,
            security,
            pack,
            performance,
            custom: HashMap::new(),
        })
    }

    /// Record a new connection
    pub fn record_connection(&self) {
        self.network.connections_total.inc();
        self.network.connections_active.inc();
    }

    /// Record a connection closed
    pub fn record_connection_closed(&self, duration: Duration) {
        self.network.connections_active.dec();
        self.network
            .connection_duration
            .observe(duration.as_secs_f64());
    }

    /// Record a message sent
    pub fn record_message_sent(&self, bytes: usize) {
        self.network.messages_sent_total.inc();
        self.network.bytes_transferred_total.inc_by(bytes as u64);
    }

    /// Record a message received
    pub fn record_message_received(&self, bytes: usize, latency: Duration) {
        self.network.messages_received_total.inc();
        self.network.bytes_transferred_total.inc_by(bytes as u64);
        self.network.message_latency.observe(latency.as_secs_f64());
    }

    /// Record a security event
    pub fn record_security_event(&self) {
        self.security.security_events_total.inc();
    }

    /// Record a threat detected
    pub fn record_threat_detected(&self) {
        self.security.threats_detected_total.inc();
    }

    /// Record an authentication failure
    pub fn record_auth_failure(&self) {
        self.security.auth_failures_total.inc();
    }

    /// Record a pack coordination
    pub fn record_pack_coordination(&self) {
        self.security.pack_coordinations_total.inc();
    }

    /// Record a howl sent
    pub fn record_howl_sent(&self) {
        self.security.howls_sent_total.inc();
    }

    /// Record a howl received
    pub fn record_howl_received(&self) {
        self.security.howls_received_total.inc();
    }

    /// Record a pack formation
    pub fn record_pack_formation(&self) {
        self.pack.pack_formations_total.inc();
        self.pack.packs_active.inc();
    }

    /// Update pack member count
    pub fn update_pack_members(&self, count: u64) {
        self.pack.pack_members_total.set(count as f64);
    }

    /// Record a hunt initiated
    pub fn record_hunt_initiated(&self) {
        self.pack.hunts_initiated_total.inc();
    }

    /// Record a hunt completed
    pub fn record_hunt_completed(&self) {
        self.pack.hunts_completed_total.inc();
    }

    /// Record a territory claimed
    pub fn record_territory_claimed(&self) {
        self.pack.territories_claimed_total.inc();
    }

    /// Update CPU usage
    pub fn update_cpu_usage(&self, usage: f64) {
        self.performance.cpu_usage.set(usage);
    }

    /// Update memory usage
    pub fn update_memory_usage(&self, usage: f64) {
        self.performance.memory_usage.set(usage);
    }

    /// Update disk usage
    pub fn update_disk_usage(&self, usage: f64) {
        self.performance.disk_usage.set(usage);
    }

    /// Record a request duration
    pub fn record_request_duration(&self, duration: Duration) {
        self.performance
            .request_duration
            .observe(duration.as_secs_f64());
    }

    /// Update error rate
    pub fn update_error_rate(&self, rate: f64) {
        self.performance.error_rate.set(rate);
    }

    /// Add a custom metric
    pub fn add_custom_metric(
        &mut self,
        name: String,
        description: String,
        metric_type: MetricType,
        value: f64,
    ) {
        let metric = CustomMetric {
            name: name.clone(),
            description,
            metric_type,
            value,
            timestamp: Instant::now(),
        };
        self.custom.insert(name, metric);
    }

    /// Update a custom metric
    pub fn update_custom_metric(&mut self, name: &str, value: f64) {
        if let Some(metric) = self.custom.get_mut(name) {
            metric.value = value;
            metric.timestamp = Instant::now();
        }
    }

    /// Get metrics snapshot
    pub fn get_snapshot(&self) -> MetricsSnapshot {
        let network_snapshot = NetworkMetricsSnapshot {
            connections_total: self.network.connections_total.get(),
            connections_active: self.network.connections_active.get() as u64,
            messages_sent_total: self.network.messages_sent_total.get(),
            messages_received_total: self.network.messages_received_total.get(),
            bytes_transferred_total: self.network.bytes_transferred_total.get(),
            avg_connection_duration: 0.0, // Calculate from histogram
            avg_message_latency: 0.0,     // Calculate from histogram
        };

        let security_snapshot = SecurityMetricsSnapshot {
            security_events_total: self.security.security_events_total.get(),
            threats_detected_total: self.security.threats_detected_total.get(),
            auth_failures_total: self.security.auth_failures_total.get(),
            pack_coordinations_total: self.security.pack_coordinations_total.get(),
            howls_sent_total: self.security.howls_sent_total.get(),
            howls_received_total: self.security.howls_received_total.get(),
        };

        let pack_snapshot = PackMetricsSnapshot {
            pack_formations_total: self.pack.pack_formations_total.get(),
            packs_active: self.pack.packs_active.get() as u64,
            pack_members_total: self.pack.pack_members_total.get() as u64,
            hunts_initiated_total: self.pack.hunts_initiated_total.get(),
            hunts_completed_total: self.pack.hunts_completed_total.get(),
            territories_claimed_total: self.pack.territories_claimed_total.get(),
        };

        let performance_snapshot = PerformanceMetricsSnapshot {
            cpu_usage: self.performance.cpu_usage.get(),
            memory_usage: self.performance.memory_usage.get(),
            disk_usage: self.performance.disk_usage.get(),
            avg_request_duration: 0.0, // Calculate from histogram
            error_rate: self.performance.error_rate.get(),
        };

        let custom: HashMap<String, f64> = self
            .custom
            .iter()
            .map(|(name, metric)| (name.clone(), metric.value))
            .collect();

        MetricsSnapshot {
            timestamp: chrono::Utc::now().to_rfc3339(),
            network: network_snapshot,
            security: security_snapshot,
            pack: pack_snapshot,
            performance: performance_snapshot,
            custom,
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }

    /// Get the Prometheus registry
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics collector")
    }
}

/// Simple metrics interface for easy access
pub trait Metrics {
    fn increment_counter(&self, name: &str);
    fn set_gauge(&self, name: &str, value: f64);
    fn observe_histogram(&self, name: &str, value: f64);
}

impl Metrics for MetricsCollector {
    fn increment_counter(&self, name: &str) {
        match name {
            "connections_total" => self.record_connection(),
            "security_events_total" => self.record_security_event(),
            "threats_detected_total" => self.record_threat_detected(),
            "pack_formations_total" => self.record_pack_formation(),
            "hunts_initiated_total" => self.record_hunt_initiated(),
            _ => {}
        }
    }

    fn set_gauge(&self, name: &str, value: f64) {
        match name {
            "cpu_usage" => self.update_cpu_usage(value),
            "memory_usage" => self.update_memory_usage(value),
            "disk_usage" => self.update_disk_usage(value),
            "error_rate" => self.update_error_rate(value),
            "pack_members" => self.update_pack_members(value as u64),
            _ => {}
        }
    }

    fn observe_histogram(&self, name: &str, value: f64) {
        let duration = Duration::from_secs_f64(value);
        match name {
            "connection_duration" => self.network.connection_duration.observe(value),
            "message_latency" => self.network.message_latency.observe(value),
            "request_duration" => self.record_request_duration(duration),
            _ => {}
        }
    }
}
