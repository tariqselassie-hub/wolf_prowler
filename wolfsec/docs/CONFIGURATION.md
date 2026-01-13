# Configuration Guide

## Overview

Wolfsec uses structured configuration with type-safe validation. This guide explains how to configure the security system for different environments.

## Configuration Sources

Configuration is loaded in the following priority order:

1. **Default values** (in code)
2. **Configuration files** (TOML/YAML)
3. **Environment variables**
4. **Runtime updates** (via API)

## Core Configuration Types

### SecurityConfig

Network security configuration:

```rust
use wolfsec::protection::network_security::{SecurityConfig, SecurityLevel};

let config = SecurityConfig {
    default_security_level: SecurityLevel::High,
    max_sessions_per_peer: 10,
    session_cleanup_interval: 3600,  // seconds
    token_ttl_hours: 24,
};
```

### IdentityConfig

Identity and authentication configuration:

```rust
use wolfsec::identity::IdentityConfig;

let config = IdentityConfig {
    identity_file: "/var/lib/wolfsec/identity.json".into(),
    auto_create: true,
    rotation_interval_days: 90,
};
```

### ThreatDetectionConfig

Threat detection configuration:

```rust
use wolfsec::protection::threat_detection::ThreatDetectionConfig;

let config = ThreatDetectionConfig {
    enable_ml_detection: true,
    enable_signature_detection: true,
    enable_behavioral_analysis: true,
    threat_threshold: 0.7,
    max_concurrent_scans: 10,
    scan_timeout_seconds: 30,
    enable_auto_response: false,
};
```

## Configuration Files

### TOML Example

`config.toml`:

```toml
[security]
default_level = "high"
max_sessions_per_peer = 10
session_cleanup_interval = 3600
token_ttl_hours = 24

[identity]
identity_file = "/var/lib/wolfsec/identity.json"
auto_create = true
rotation_interval_days = 90

[threat_detection]
enable_ml_detection = true
enable_signature_detection = true
enable_behavioral_analysis = true
threat_threshold = 0.7
max_concurrent_scans = 10
scan_timeout_seconds = 30
enable_auto_response = false

[observability]
enable_metrics = true
enable_audit_log = true
metrics_interval_seconds = 60
audit_log_path = "/var/log/wolfsec/audit.log"
```

### YAML Example

`config.yaml`:

```yaml
security:
  default_level: high
  max_sessions_per_peer: 10
  session_cleanup_interval: 3600
  token_ttl_hours: 24

identity:
  identity_file: /var/lib/wolfsec/identity.json
  auto_create: true
  rotation_interval_days: 90

threat_detection:
  enable_ml_detection: true
  enable_signature_detection: true
  enable_behavioral_analysis: true
  threat_threshold: 0.7
  max_concurrent_scans: 10
  scan_timeout_seconds: 30
  enable_auto_response: false

observability:
  enable_metrics: true
  enable_audit_log: true
  metrics_interval_seconds: 60
  audit_log_path: /var/log/wolfsec/audit.log
```

## Environment Variables

Override configuration with environment variables:

```bash
# Security
export WOLFSEC_SECURITY_LEVEL=high
export WOLFSEC_MAX_SESSIONS=10
export WOLFSEC_TOKEN_TTL=24

# Identity
export WOLFSEC_IDENTITY_FILE=/var/lib/wolfsec/identity.json
export WOLFSEC_AUTO_CREATE=true

# Threat Detection
export WOLFSEC_ML_DETECTION=true
export WOLFSEC_THREAT_THRESHOLD=0.7

# Observability
export WOLFSEC_METRICS_ENABLED=true
export WOLFSEC_AUDIT_LOG=/var/log/wolfsec/audit.log
```

## Environment-Specific Configurations

### Development

```toml
[security]
default_level = "medium"
max_sessions_per_peer = 100
session_cleanup_interval = 300

[threat_detection]
enable_ml_detection = false  # Faster startup
enable_auto_response = false  # Manual review
threat_threshold = 0.5  # More sensitive

[observability]
enable_metrics = true
metrics_interval_seconds = 10  # More frequent
```

### Production

```toml
[security]
default_level = "high"
max_sessions_per_peer = 10
session_cleanup_interval = 3600
token_ttl_hours = 24

[threat_detection]
enable_ml_detection = true
enable_signature_detection = true
enable_behavioral_analysis = true
enable_auto_response = true  # Automatic blocking
threat_threshold = 0.8  # Less false positives

[observability]
enable_metrics = true
enable_audit_log = true
metrics_interval_seconds = 60
audit_log_path = /var/log/wolfsec/audit.log
siem_integration = true
```

## Configuration Validation

All configurations are validated on load:

```rust
use wolfsec::protection::network_security::SecurityConfig;

let config = SecurityConfig {
    default_security_level: SecurityLevel::High,
    max_sessions_per_peer: 10,
    session_cleanup_interval: 3600,
    token_ttl_hours: 24,
};

// Validation happens automatically
// Invalid values will return an error
```

## Builder Pattern

For complex configurations, use the builder pattern:

```rust
use wolfsec::protection::threat_detection::ThreatDetectionConfigBuilder;

let config = ThreatDetectionConfigBuilder::new()
    .enable_ml_detection(true)
    .enable_signature_detection(true)
    .threat_threshold(0.7)
    .max_concurrent_scans(10)
    .build()?;
```

## Runtime Configuration Updates

Some configurations can be updated at runtime:

```rust
// Update threat threshold
detector.update_threshold(0.8)?;

// Update security level
security_manager.set_security_level(SecurityLevel::Critical)?;

// Enable/disable features
metrics_collector.set_enabled(true)?;
```

## Best Practices

1. **Use configuration files** for static settings
2. **Use environment variables** for secrets and deployment-specific values
3. **Validate early** - fail fast on invalid configuration
4. **Document defaults** - make defaults explicit in code
5. **Version configurations** - track configuration changes
6. **Test configurations** - include config validation in tests

## Security Considerations

- **Never commit secrets** to version control
- **Use environment variables** for sensitive data
- **Encrypt configuration files** containing secrets
- **Rotate credentials** regularly
- **Audit configuration changes**

## Troubleshooting

### Configuration Not Loading

Check:
1. File path is correct
2. File permissions allow reading
3. TOML/YAML syntax is valid
4. Environment variables are set

### Invalid Configuration

- Check validation error messages
- Verify all required fields are present
- Ensure values are within valid ranges
- Review type compatibility

### Performance Issues

- Reduce `metrics_interval_seconds` if too frequent
- Increase `session_cleanup_interval` if too aggressive
- Adjust `max_concurrent_scans` based on CPU cores
- Tune `threat_threshold` to reduce false positives

---

For more examples, see the `examples/` directory.
