//! Health Monitoring System
//!
//! Provides comprehensive health checks for all Wolf Prowler components
//! and system metrics collection for observability.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use sysinfo::System;

/// Overall system health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Some non-critical issues
    Degraded,
    /// Critical issues present
    Unhealthy,
}

/// Health check result for a component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component status
    pub status: HealthStatus,
    /// Human-readable status message
    pub message: Option<String>,
    /// Component-specific metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<serde_json::Value>,
    /// Last check timestamp
    pub last_check: String,
}

impl ComponentHealth {
    pub fn healthy() -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: None,
            metrics: None,
            last_check: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn healthy_with_message(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Healthy,
            message: Some(message.into()),
            metrics: None,
            last_check: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Degraded,
            message: Some(message.into()),
            metrics: None,
            last_check: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
            metrics: None,
            last_check: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn with_metrics(mut self, metrics: serde_json::Value) -> Self {
        self.metrics = Some(metrics);
        self
    }
}

/// System-wide metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// CPU usage percentage (0-100)
    pub cpu_percent: f32,
    /// Memory usage in MB
    pub memory_mb: u64,
    /// Total memory in MB
    pub total_memory_mb: u64,
    /// Memory usage percentage
    pub memory_percent: f32,
    /// Disk free space in GB
    pub disk_free_gb: u64,
    /// Number of CPU cores
    pub cpu_cores: usize,
}

/// Complete health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    /// Overall system status
    pub status: HealthStatus,
    /// Application version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Individual component health
    pub components: std::collections::HashMap<String, ComponentHealth>,
    /// System metrics
    pub metrics: SystemMetrics,
    /// Timestamp of this health check
    pub timestamp: String,
}

/// Trait for components that can report health
#[async_trait::async_trait]
pub trait HealthCheck {
    /// Check the health of this component
    async fn check_health(&self) -> ComponentHealth;
}

/// Health monitor that aggregates component health
pub struct HealthMonitor {
    start_time: SystemTime,
    system: System,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            start_time: SystemTime::now(),
            system: System::new_all(),
        }
    }

    /// Get system uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    }

    /// Collect current system metrics
    pub fn collect_metrics(&mut self) -> SystemMetrics {
        // Refresh system information
        self.system.refresh_all();

        let total_memory = self.system.total_memory();
        let used_memory = self.system.used_memory();
        let memory_percent = if total_memory > 0 {
            (used_memory as f32 / total_memory as f32) * 100.0
        } else {
            0.0
        };

        // Get CPU usage (average across all cores)
        let cpu_percent = self.system.global_cpu_usage();

        // Get disk information (simplified - just report available space)
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let disk_free_gb =
            disks.iter().map(|disk| disk.available_space()).sum::<u64>() / 1024 / 1024 / 1024;

        SystemMetrics {
            cpu_percent,
            memory_mb: used_memory / 1024 / 1024, // sysinfo returns bytes, we want MB. Wait, previously it was / 1024?
            total_memory_mb: total_memory / 1024 / 1024,
            memory_percent,
            disk_free_gb,
            cpu_cores: self.system.cpus().len(),
        }
    }

    /// Determine overall status from component health
    pub fn aggregate_status(
        &self,
        components: &std::collections::HashMap<String, ComponentHealth>,
    ) -> HealthStatus {
        let mut has_unhealthy = false;
        let mut has_degraded = false;

        for health in components.values() {
            match health.status {
                HealthStatus::Unhealthy => has_unhealthy = true,
                HealthStatus::Degraded => has_degraded = true,
                HealthStatus::Healthy => {}
            }
        }

        if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_health_creation() {
        let health = ComponentHealth::healthy();
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(health.message.is_none());

        let health = ComponentHealth::degraded("Low memory");
        assert_eq!(health.status, HealthStatus::Degraded);
        assert_eq!(health.message, Some("Low memory".to_string()));
    }

    #[test]
    fn test_health_status_aggregation() {
        let monitor = HealthMonitor::new();
        let mut components = std::collections::HashMap::new();

        // All healthy
        components.insert("comp1".to_string(), ComponentHealth::healthy());
        components.insert("comp2".to_string(), ComponentHealth::healthy());
        assert_eq!(monitor.aggregate_status(&components), HealthStatus::Healthy);

        // One degraded
        components.insert("comp3".to_string(), ComponentHealth::degraded("Issue"));
        assert_eq!(
            monitor.aggregate_status(&components),
            HealthStatus::Degraded
        );

        // One unhealthy
        components.insert("comp4".to_string(), ComponentHealth::unhealthy("Critical"));
        assert_eq!(
            monitor.aggregate_status(&components),
            HealthStatus::Unhealthy
        );
    }

    #[test]
    fn test_metrics_collection() {
        let mut monitor = HealthMonitor::new();
        let metrics = monitor.collect_metrics();

        assert!(metrics.cpu_percent >= 0.0);
        assert!(metrics.memory_mb > 0);
        assert!(metrics.total_memory_mb > 0);
        assert!(metrics.cpu_cores > 0);
    }
}
