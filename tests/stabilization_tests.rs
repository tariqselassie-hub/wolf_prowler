//! Comprehensive Integration Tests for System Stabilization
//!
//! Tests error handling, health monitoring, and request validation.

use wolf_prowler::error::{WolfError, WolfResult};
use wolf_prowler::health::{ComponentHealth, HealthMonitor, HealthStatus};
use wolf_prowler::validated_json::ValidatedJson;
use wolf_prowler::validation::*;

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_error_types() {
        let network_err = WolfError::Network("Connection failed".to_string());
        assert_eq!(
            network_err.status_code(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );

        let security_err = WolfError::Security("Unauthorized access".to_string());
        assert_eq!(
            security_err.status_code(),
            axum::http::StatusCode::FORBIDDEN
        );

        let validation_err = WolfError::Validation("Invalid input".to_string());
        assert_eq!(
            validation_err.status_code(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn test_user_messages_no_leaks() {
        let internal_err = WolfError::Internal("Database password: secret123".to_string());
        let user_msg = internal_err.user_message();

        // Should NOT contain sensitive data
        assert!(!user_msg.contains("secret123"));
        assert!(!user_msg.contains("password"));
    }

    #[test]
    fn test_critical_error_identification() {
        assert!(WolfError::Security("test".to_string()).is_critical());
        assert!(WolfError::Crypto("test".to_string()).is_critical());
        assert!(WolfError::Database("test".to_string()).is_critical());
        assert!(!WolfError::NotFound("test".to_string()).is_critical());
    }

    #[test]
    fn test_error_conversions() {
        // From anyhow
        let anyhow_err = anyhow::anyhow!("test error");
        let wolf_err: WolfError = anyhow_err.into();
        assert!(matches!(wolf_err, WolfError::Internal(_)));

        // From io::Error
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let wolf_err: WolfError = io_err.into();
        assert!(matches!(wolf_err, WolfError::Internal(_)));
    }

    #[test]
    fn test_result_type_alias() {
        fn returns_result() -> WolfResult<i32> {
            Ok(42)
        }

        fn returns_error() -> WolfResult<i32> {
            Err(WolfError::NotFound("item".to_string()))
        }

        assert_eq!(returns_result().unwrap(), 42);
        assert!(returns_error().is_err());
    }
}

#[cfg(test)]
mod health_monitoring_tests {
    use super::*;

    #[test]
    fn test_health_status_levels() {
        let healthy = ComponentHealth::healthy();
        assert_eq!(healthy.status, HealthStatus::Healthy);

        let degraded = ComponentHealth::degraded("Low memory");
        assert_eq!(degraded.status, HealthStatus::Degraded);

        let unhealthy = ComponentHealth::unhealthy("Service down");
        assert_eq!(unhealthy.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_with_metrics() {
        let health = ComponentHealth::healthy().with_metrics(serde_json::json!({
            "connections": 10,
            "latency_ms": 50
        }));

        assert!(health.metrics.is_some());
        let metrics = health.metrics.unwrap();
        assert_eq!(metrics["connections"], 10);
    }

    #[test]
    fn test_health_monitor_uptime() {
        let monitor = HealthMonitor::new();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let uptime = monitor.uptime_seconds();
        assert!(uptime >= 0);
    }

    #[test]
    fn test_health_monitor_metrics() {
        let mut monitor = HealthMonitor::new();
        let metrics = monitor.collect_metrics();

        assert!(metrics.cpu_percent >= 0.0);
        assert!(metrics.memory_mb > 0);
        assert!(metrics.total_memory_mb > 0);
        assert!(metrics.cpu_cores > 0);
        assert!(metrics.memory_percent >= 0.0 && metrics.memory_percent <= 100.0);
    }

    #[test]
    fn test_status_aggregation() {
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

        // One unhealthy (takes precedence)
        components.insert("comp4".to_string(), ComponentHealth::unhealthy("Critical"));
        assert_eq!(
            monitor.aggregate_status(&components),
            HealthStatus::Unhealthy
        );
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn test_ip_validation() {
        // Valid IPs
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("2001:db8::1").is_ok());

        // Invalid IPs
        assert!(validate_ip("256.1.1.1").is_err());
        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("").is_err());
    }

    #[test]
    fn test_subnet_validation() {
        // Valid subnets
        assert!(validate_subnet("192.168.1.0/24").is_ok());
        assert!(validate_subnet("10.0.0.0/8").is_ok());
        assert!(validate_subnet("172.16.0.0/16").is_ok());

        // Invalid subnets
        assert!(validate_subnet("192.168.1.0").is_err()); // Missing prefix
        assert!(validate_subnet("192.168.1.0/33").is_err()); // Invalid prefix
        assert!(validate_subnet("invalid/24").is_err()); // Invalid IP
        assert!(validate_subnet("192.168.1.0/abc").is_err()); // Invalid prefix
    }

    #[test]
    fn test_port_validation() {
        // Valid ports (>1024)
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(3000).is_ok());
        assert!(validate_port(65535).is_ok());

        // Invalid ports (privileged)
        assert!(validate_port(80).is_err());
        assert!(validate_port(443).is_err());
        assert!(validate_port(22).is_err());
    }

    #[test]
    fn test_port_range_validation() {
        assert!(validate_port_range(1).is_ok());
        assert!(validate_port_range(65535).is_ok());
        assert!(validate_port_range(0).is_err());
    }

    #[test]
    fn test_hostname_validation() {
        // Valid hostnames
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("my-server").is_ok());

        // Invalid hostnames
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("a".repeat(254).as_str()).is_err()); // Too long
        assert!(validate_hostname("invalid@hostname").is_err());
    }

    #[test]
    fn test_message_content_validation() {
        // Valid messages
        assert!(validate_message_content("Hello, world!").is_ok());
        assert!(validate_message_content("Normal message").is_ok());

        // Invalid messages
        assert!(validate_message_content("").is_err()); // Empty
        assert!(validate_message_content(&"x".repeat(10001)).is_err()); // Too long

        // XSS attempts
        assert!(validate_message_content("<script>alert('xss')</script>").is_err());
        assert!(validate_message_content("javascript:alert(1)").is_err());
        assert!(validate_message_content("<img onerror='alert(1)'>").is_err());
    }

    #[test]
    fn test_file_path_validation() {
        // Valid paths
        assert!(validate_file_path("data/file.txt").is_ok());
        assert!(validate_file_path("logs/app.log").is_ok());

        // Invalid paths (directory traversal)
        assert!(validate_file_path("../etc/passwd").is_err());
        assert!(validate_file_path("../../secret").is_err());
        assert!(validate_file_path("/etc/passwd").is_err()); // Absolute path
    }

    #[test]
    fn test_peer_id_validation() {
        // Valid peer IDs
        assert!(validate_peer_id("wolf-node-1").is_ok());
        assert!(validate_peer_id("peer_123").is_ok());

        // Invalid peer IDs
        assert!(validate_peer_id("").is_err());
        assert!(validate_peer_id(&"x".repeat(129)).is_err()); // Too long
        assert!(validate_peer_id("invalid@peer").is_err());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_error_to_health_integration() {
        // Simulate error affecting health
        let error = WolfError::Security("Intrusion detected".to_string());

        // This should trigger unhealthy status
        let health = if error.is_critical() {
            ComponentHealth::unhealthy(error.user_message())
        } else {
            ComponentHealth::degraded(error.user_message())
        };

        assert_eq!(health.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_validation_prevents_errors() {
        // Invalid IP should be caught by validation
        let invalid_ip = "999.999.999.999";
        assert!(validate_ip(invalid_ip).is_err());

        // This prevents downstream errors
        let result: WolfResult<()> = if validate_ip(invalid_ip).is_ok() {
            Ok(())
        } else {
            Err(WolfError::Validation("Invalid IP address".to_string()))
        };

        assert!(result.is_err());
    }

    #[test]
    fn test_full_request_lifecycle() {
        // 1. Validate input
        let ip = "192.168.1.100";
        assert!(validate_ip(ip).is_ok());

        // 2. Process (simulate)
        let result: WolfResult<String> = Ok(format!("Processed {}", ip));

        // 3. Check health
        let health = if result.is_ok() {
            ComponentHealth::healthy()
        } else {
            ComponentHealth::unhealthy("Processing failed")
        };

        assert_eq!(health.status, HealthStatus::Healthy);
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;

    #[test]
    fn test_validation_performance() {
        let start = std::time::Instant::now();

        for _ in 0..1000 {
            let _ = validate_ip("192.168.1.1");
        }

        let duration = start.elapsed();
        assert!(
            duration.as_millis() < 100,
            "Validation too slow: {:?}",
            duration
        );
    }

    #[test]
    fn test_health_check_performance() {
        let mut monitor = HealthMonitor::new();
        let start = std::time::Instant::now();

        for _ in 0..10 {
            let _ = monitor.collect_metrics();
        }

        let duration = start.elapsed();
        assert!(
            duration.as_millis() < 1000,
            "Health checks too slow: {:?}",
            duration
        );
    }
}
