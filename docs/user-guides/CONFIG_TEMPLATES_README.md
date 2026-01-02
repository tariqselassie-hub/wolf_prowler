# Wolf Prowler Configuration Templates

This directory contains pre-configured templates for different deployment scenarios of Wolf Prowler.

## Available Templates

### 🛠️ `development.toml`
**Use for**: Local development and testing
- Relaxed security settings
- Debug logging enabled
- Fast cryptographic operations
- Console logging
- Small peer limits

### 🚀 `production.toml`
**Use for**: Production deployments
- Balanced security and performance
- Structured logging
- Standard cryptographic settings
- Prometheus metrics enabled
- Backup support

### 🔒 `high-security.toml`
**Use for**: Maximum security deployments
- Strict security settings
- Maximum cryptographic security
- Limited metrics exposure
- Encrypted backups
- Secure memory protection

### 🧪 `testing.toml`
**Use for**: Automated testing and CI/CD
- Minimal configuration
- Random ports for parallel testing
- Fast operations
- No persistent state
- Debug logging

### 🐳 `docker.toml`
**Use for**: Docker container deployments
- Container-optimized settings
- Console logging
- Standard security
- Data directory configuration
- Health checks

### ☸️ `kubernetes.toml`
**Use for**: Kubernetes deployments
- Cluster-optimized settings
- Persistent volume support
- Full observability
- High availability settings
- Comprehensive monitoring

## How to Use Templates

### Quick Start
```bash
# Copy a template to your working directory
cp config/templates/development.toml wolf_prowler.toml

# Edit the configuration as needed
nano wolf_prowler.toml

# Start Wolf Prowler
cargo run --bin main
```

### Template Selection Guide

| Scenario | Recommended Template | Why |
|----------|-------------------|-----|
| Local Development | `development.toml` | Fast setup, debug info |
| Production Server | `production.toml` | Balanced security & performance |
| Government/Finance | `high-security.toml` | Maximum security |
| CI/CD Pipeline | `testing.toml` | Minimal, fast, parallelizable |
| Docker Container | `docker.toml` | Container-optimized |
| Kubernetes Cluster | `kubernetes.toml` | Cloud-native features |

### Environment Variable Override

All templates support environment variable overrides. This allows you to customize settings without modifying the configuration file:

```bash
# Override node name and web port
WOLF_NODE_NAME="my-special-node" WOLF_WEB_PORT="9090" cargo run --bin main

# Override security settings
WOLF_SECURITY_ENABLE_AUTH="true" WOLF_SECURITY_REQUIRE_ENCRYPTION="true" cargo run --bin main

# Override cryptographic settings
WOLF_CIPHER_SUITE="aes256gcm" WOLF_SECURITY_LEVEL="high" cargo run --bin main
```

### Docker Usage

```dockerfile
# Dockerfile example
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/wolf-prowler /usr/local/bin/
COPY config/templates/docker.toml /etc/wolf_prowler.toml

EXPOSE 8080 9000 9090 8081
CMD ["wolf-prowler"]
```

### Kubernetes Usage

```yaml
# ConfigMap example
apiVersion: v1
kind: ConfigMap
metadata:
  name: wolf-prowler-config
data:
  wolf_prowler.toml: |
    # Include kubernetes.toml content here or mount from configmap
```

## Configuration Sections

### Node Configuration
- `name`: Human-readable node name
- `web_port`: Web server port
- `log_level`: Logging level (trace, debug, info, warn, error)
- `enable_console_logging`: Console output
- `enable_file_logging`: File logging

### P2P Configuration
- `listen_port`: P2P listening port
- `max_peers`: Maximum peer connections
- `discovery_interval`: Peer discovery frequency
- `enable_mdns`: mDNS discovery
- `bootstrap_nodes`: Known peers to connect to

### Security Configuration
- `enable_auth`: Authentication requirement
- `require_encryption`: Encryption requirement
- `max_auth_attempts`: Maximum authentication attempts
- `session_timeout`: Session timeout in seconds

### Cryptographic Configuration
- `cipher_suite`: Encryption algorithm
- `hash_function`: Hash algorithm
- `security_level`: Security level (low, standard, high, maximum)
- `enable_metrics`: Cryptographic metrics
- `enable_audit_logging`: Audit logging
- `performance_optimization`: Performance optimizations

### State Configuration
- `save_state`: Enable state persistence
- `state_file`: State file location
- `auto_save_interval`: Auto-save frequency
- `backup_enabled`: Backup support
- `backup_directory`: Backup location
- `max_backups`: Maximum backup count

### Metrics Configuration
- `enable_prometheus`: Prometheus metrics
- `prometheus_port`: Metrics port
- `collect_interval`: Collection frequency
- `retention_days`: Data retention period

### Health Configuration
- `enable_health_check`: Health monitoring
- `health_check_port`: Health check port
- `check_interval`: Check frequency
- `detailed_logging`: Detailed health logging

## Security Considerations

1. **Never use development templates in production**
2. **Always change default passwords and certificates**
3. **Review network exposure in production settings**
4. **Enable audit logging for compliance**
5. **Regularly rotate cryptographic keys**
6. **Monitor health and metrics for anomalies**

## Customization

You can create custom templates by copying an existing template and modifying it:

```bash
# Create a custom template
cp config/templates/production.toml config/templates/custom.toml

# Edit as needed
nano config/templates/custom.toml
```

## Support

For configuration help:
1. Check the [ENVIRONMENT_VARIABLES.md](../ENVIRONMENT_VARIABLES.md) for all available environment variables
2. Review the [PROTOTYPE_STATUS.md](../PROTOTYPE_STATUS.md) for feature information
3. Check the [UPGRADES.md](../UPGRADES.md) for upgrade information
