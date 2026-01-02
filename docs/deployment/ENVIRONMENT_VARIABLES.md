# Wolf Prowler Environment Variables

This document describes all the environment variables that can be used to configure Wolf Prowler without modifying configuration files.

## 📋 Overview

Wolf Prowler supports flexible configuration through environment variables with the following precedence:

1. **Environment Variables** (highest priority)
2. **Configuration Files** (medium priority)  
3. **Default Values** (lowest priority)

## 🚀 Quick Start

```bash
# Basic configuration
export WOLF_NODE_NAME="my_wolf_node"
export WOLF_WEB_PORT=9090
export WOLF_LOG_LEVEL=debug

# P2P configuration
export WOLF_P2P_LISTEN_PORT=9000
export WOLF_P2P_MAX_PEERS=100

# Security configuration
export WOLF_SECURITY_ENABLE_AUTH=true
export WOLF_SECURITY_REQUIRE_ENCRYPTION=true

# Run Wolf Prowler
cargo run --bin main
```

## 📦 Configuration Categories

### 🔧 Node Configuration

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| `WOLF_NODE_NAME` | `wolf_prowler_node` | Node identifier/name | `my_wolf_node` |
| `WOLF_WEB_PORT` | `8080` | Web server port | `9090` |
| `WOLF_LOG_LEVEL` | `info` | Logging level | `debug` |
| `WOLF_STATE_FILE` | `wolf_prowler_state.json` | State file path | `/data/wolf_state.json` |
| `WOLF_SAVE_STATE` | `true` | Enable state persistence | `true` |

### 🌐 P2P Network Configuration

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| `WOLF_P2P_LISTEN_PORT` | `0` (random) | P2P listen port | `9000` |
| `WOLF_P2P_MAX_PEERS` | `50` | Maximum peer connections | `100` |
| `WOLF_P2P_DISCOVERY_INTERVAL` | `30` | Discovery interval (seconds) | `60` |
| `WOLF_P2P_ENABLE_MDNS` | `true` | Enable mDNS discovery | `false` |

### 🔒 Security Configuration

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| `WOLF_SECURITY_ENABLE_AUTH` | `false` | Enable authentication | `true` |
| `WOLF_SECURITY_REQUIRE_ENCRYPTION` | `false` | Require encryption | `true` |
| `WOLF_SECURITY_MAX_AUTH_ATTEMPTS` | `3` | Max authentication attempts | `5` |

### 🔐 Cryptographic Configuration

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| `WOLF_CIPHER_SUITE` | `chacha20poly1305` | Encryption cipher | `aes256gcm` |
| `WOLF_HASH_FUNCTION` | `blake3` | Hash algorithm | `sha256` |
| `WOLF_SECURITY_LEVEL` | `standard` | Security level | `high` |
| `WOLF_CRYPTO_ENABLE_METRICS` | `true` | Enable crypto metrics | `false` |
| `WOLF_CRYPTO_ENABLE_AUDIT` | `true` | Enable audit logging | `false` |
| `WOLF_CRYPTO_PERFORMANCE_OPT` | `true` | Performance optimizations | `false` |

## 🎯 Valid Values

### Log Levels
- `trace` - Most verbose logging
- `debug` - Debug information
- `info` - General information (default)
- `warn` - Warning messages
- `error` - Error messages only

### Cipher Suites
- `chacha20poly1305` - ChaCha20-Poly1305 AEAD (default)
- `aes256gcm` - AES-256-GCM AEAD
- `xchacha20poly1305` - XChaCha20-Poly1305 AEAD

### Hash Functions
- `blake3` - BLAKE3 hash function (default)
- `sha256` - SHA-256 hash function
- `sha512` - SHA-512 hash function

### Security Levels
- `low` - Minimal security, maximum performance
- `standard` - Balanced security and performance (default)
- `high` - Enhanced security settings
- `maximum` - Maximum security, reduced performance

## 🐳 Docker Usage

```dockerfile
# Dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/wolf_prowler /usr/local/bin/

# Environment variables will be set at runtime
CMD ["wolf_prowler"]
```

```bash
# docker-compose.yml
version: '3.8'
services:
  wolf-prowler:
    build: .
    environment:
      - WOLF_NODE_NAME=wolf_docker_node
      - WOLF_WEB_PORT=8080
      - WOLF_LOG_LEVEL=info
      - WOLF_P2P_LISTEN_PORT=9000
      - WOLF_P2P_MAX_PEERS=50
      - WOLF_SECURITY_ENABLE_AUTH=true
      - WOLF_SECURITY_REQUIRE_ENCRYPTION=true
      - WOLF_CIPHER_SUITE=chacha20poly1305
      - WOLF_SECURITY_LEVEL=standard
    ports:
      - "8080:8080"
      - "9000:9000"
    volumes:
      - wolf_data:/data
    restart: unless-stopped

volumes:
  wolf_data:
```

## ☸️ Kubernetes Usage

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wolf-prowler
spec:
  replicas: 3
  selector:
    matchLabels:
      app: wolf-prowler
  template:
    metadata:
      labels:
        app: wolf-prowler
    spec:
      containers:
      - name: wolf-prowler
        image: wolf-prowler:latest
        env:
        - name: WOLF_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: WOLF_WEB_PORT
          value: "8080"
        - name: WOLF_LOG_LEVEL
          value: "info"
        - name: WOLF_P2P_LISTEN_PORT
          value: "9000"
        - name: WOLF_P2P_MAX_PEERS
          value: "100"
        - name: WOLF_SECURITY_ENABLE_AUTH
          value: "true"
        - name: WOLF_SECURITY_REQUIRE_ENCRYPTION
          value: "true"
        - name: WOLF_CIPHER_SUITE
          value: "chacha20poly1305"
        - name: WOLF_SECURITY_LEVEL
          value: "high"
        ports:
        - containerPort: 8080
        - containerPort: 9000
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## 🔧 Development Examples

### Development Environment
```bash
# Enable debug logging and development features
export WOLF_LOG_LEVEL=debug
export WOLF_SECURITY_ENABLE_AUTH=false
export WOLF_SECURITY_REQUIRE_ENCRYPTION=false
export WOLF_P2P_ENABLE_MDNS=true
export WOLF_CRYPTO_ENABLE_METRICS=true
```

### Production Environment
```bash
# Production security settings
export WOLF_LOG_LEVEL=warn
export WOLF_SECURITY_ENABLE_AUTH=true
export WOLF_SECURITY_REQUIRE_ENCRYPTION=true
export WOLF_P2P_ENABLE_MDNS=false
export WOLF_SECURITY_LEVEL=high
export WOLF_CIPHER_SUITE=aes256gcm
export WOLF_HASH_FUNCTION=sha512
```

### Testing Environment
```bash
# Minimal configuration for testing
export WOLF_LOG_LEVEL=error
export WOLF_SAVE_STATE=false
export WOLF_CRYPTO_ENABLE_AUDIT=false
export WOLF_CRYPTO_PERFORMANCE_OPT=false
```

## 📝 Configuration Precedence Examples

### Example 1: File + Environment Override
```toml
# wolf_prowler.toml
node_name = "default_node"
web_port = 8080
log_level = "info"

[p2p]
max_peers = 50
enable_mdns = true

[security]
enable_auth = false
```

```bash
# Override specific settings
export WOLF_WEB_PORT=9090
export WOLF_P2P_MAX_PEERS=100
export WOLF_SECURITY_ENABLE_AUTH=true

# Result: node_name="default_node", web_port=9090, max_peers=100, enable_auth=true
```

### Example 2: Environment Only
```bash
# Complete configuration via environment
export WOLF_NODE_NAME="env_node"
export WOLF_WEB_PORT=8080
export WOLF_LOG_LEVEL=debug
export WOLF_P2P_LISTEN_PORT=9000
export WOLF_P2P_MAX_PEERS=75
export WOLF_SECURITY_ENABLE_AUTH=true

# No config file needed
```

## 🚨 Troubleshooting

### Common Issues

1. **Invalid port numbers**
   ```bash
   # Invalid (port > 65535)
   export WOLF_WEB_PORT=70000
   
   # Valid
   export WOLF_WEB_PORT=8080
   ```

2. **Invalid boolean values**
   ```bash
   # Invalid
   export WOLF_SAVE_STATE=yes
   
   # Valid
   export WOLF_SAVE_STATE=true
   ```

3. **Invalid cipher suite**
   ```bash
   # Invalid
   export WOLF_CIPHER_SUITE=invalid_cipher
   
   # Valid options: chacha20poly1305, aes256gcm, xchacha20poly1305
   ```

### Debug Environment Configuration

```bash
# Show all WOLF_ environment variables
env | grep WOLF_

# Test configuration loading
cargo run --bin main 2>&1 | grep -i "config"

# Enable debug logging to see configuration loading
export WOLF_LOG_LEVEL=debug
cargo run --bin main
```

## 📚 Best Practices

1. **Use .env files for development**
   ```bash
   # .env
   WOLF_NODE_NAME=dev_node
   WOLF_LOG_LEVEL=debug
   WOLF_WEB_PORT=8080
   ```

2. **Use secrets management in production**
   ```bash
   # Use Kubernetes secrets or Docker secrets
   export WOLF_SECURITY_ENABLE_AUTH=true
   export WOLF_SECURITY_REQUIRE_ENCRYPTION=true
   ```

3. **Document custom configurations**
   ```bash
   # Include environment documentation in deployment scripts
   echo "Wolf Prowler Configuration:"
   echo "Node: $WOLF_NODE_NAME"
   echo "Port: $WOLF_WEB_PORT"
   echo "Security: $WOLF_SECURITY_ENABLE_AUTH"
   ```

4. **Validate configuration before deployment**
   ```bash
   # Test configuration before production deployment
   docker run --rm -e WOLF_LOG_LEVEL=debug wolf-prowler:latest --config-test
   ```
