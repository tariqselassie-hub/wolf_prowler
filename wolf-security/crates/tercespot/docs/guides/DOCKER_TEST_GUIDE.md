# Docker Test Guide for Four-Eyes Vault

## Overview

This guide provides comprehensive instructions for running Docker-based tests to validate the TersecPot Four-Eyes Vault functionality with Post-Quantum Cryptography (PQC).

## Test Purpose

The Docker test validates the complete Four-Eyes Vault workflow:
1. **Sentinel Daemon**: Server-side command validation and execution
2. **Pulse Device**: Cryptographic key generation and challenge-response
3. **Submitter Client**: Multi-party command submission and signing
4. **Policy Enforcement**: Complex approval workflows with PQC security

## Prerequisites

### System Requirements
- **Docker**: Docker Engine 20.10+ installed
- **Memory**: Minimum 4GB RAM recommended
- **Storage**: 2GB free disk space for Docker images
- **Network**: Internet access for Docker image downloads

### Build Requirements
- **Rust Toolchain**: Included in Docker image
- **Dependencies**: All dependencies built within container

## Running the Docker Test

### 1. Build the Docker Image
```bash
cd tercespot
docker build -f Dockerfile.test -t tercespot-test .
```

### 2. Run the Test Container
```bash
docker run --rm tercespot-test
```

### 3. Run with Interactive Mode (for debugging)
```bash
docker run -it --rm tercespot-test /bin/bash
```

## Test Workflow

### Phase 1: Setup
- **Environment Variables**: Configure postbox, log, and PQC mode
- **Policy Configuration**: Create test policy with DevOps role requirement
- **Directory Creation**: Ensure required directories exist

### Phase 2: Daemon Startup
- **Sentinel Launch**: Start the server daemon in background
- **Pulse Device**: Start cryptographic key generation device
- **Key Generation**: ML-KEM-1024 and ML-DSA-44 key pair creation

### Phase 3: Command Submission
- **Partial Command**: Create encrypted command with metadata
- **Signature Appending**: Apply DevOps role signature
- **Command Submission**: Submit fully signed command to postbox

### Phase 4: Validation and Execution
- **Policy Evaluation**: Verify command matches policy requirements
- **Signature Verification**: Validate ML-DSA-44 signatures
- **Execution**: Execute command and log results

## Expected Output

### Success Case
```
=== STARTING DOCKER LIVE VALIDATION (FOUR-EYES VAULT PQC) ===
[SETUP] Ensuring directories exist...
[SETUP] Creating policy configuration...
[DAEMON] Starting Sentinel (Four-Eyes Vault Mode)...
[PULSE] Starting Pulse Device...
[CLIENT] Creating partial command...
[CLIENT] Appending signature...
[CLIENT] Submitting signed command...
[VERIFY] Checking for execution (polling for 30s)...
Found history log!
>>> SUCCESS: Four-Eyes Vault executed command!
=== Execution Log ===
[timestamp] Command executed: systemctl restart apache2
=== Test Summary ===
✅ Sentinel started successfully
✅ Pulse Device generated keys
✅ Partial command created
✅ Signature appended
✅ Command submitted and executed
✅ Post-Quantum Cryptography validated
✅ Four-Eyes principle enforced
```

### Failure Case
```
>>> FAILURE: Command not executed or log empty.
=== Debug Information ===
Postbox contents:
total 8
-rw-r--r-- 1 root root  45 Jan  3 23:30 policies.toml
-rw-r--r-- 1 root root 156 Jan  3 23:30 pulse_pk
=== Test Summary ===
❌ Four-Eyes Vault test failed
```

## Test Components Validated

### Cryptographic Security
- **ML-KEM-1024**: Key encapsulation for command encryption
- **ML-DSA-44**: Digital signatures for command authentication
- **AES-256-GCM**: Symmetric encryption with authentication
- **Key Generation**: Secure PQC key pair creation

### Multi-Party Security
- **Four-Eyes Principle**: Multi-party signing requirement
- **Role-Based Access**: DevOps role validation
- **Signature Aggregation**: Multiple signature collection
- **Threshold Enforcement**: Configurable signature requirements

### Policy Enforcement
- **Approval Expressions**: Complex policy logic validation
- **Role Mapping**: Public key to role assignment
- **Policy Matching**: Command metadata evaluation
- **Execution Control**: Policy-based command execution

## Troubleshooting

### Common Issues

#### 1. Build Failures
```bash
# Check Docker build logs
docker build -f Dockerfile.test -t tercespot-test . 2>&1 | tail -50

# Ensure all dependencies are available
docker run --rm tercespot-test cargo check --workspace
```

#### 2. Permission Issues
```bash
# Check file permissions in container
docker run -it --rm tercespot-test ls -la /tmp/postbox/

# Verify user permissions
docker run -it --rm tercespot-test id submitter
```

#### 3. Network Issues
```bash
# Test network connectivity
docker run -it --rm tercespot-test ping -c 3 google.com

# Check DNS resolution
docker run -it --rm tercespot-test nslookup google.com
```

#### 4. Cryptographic Failures
```bash
# Test key generation
docker run -it --rm tercespot-test /app/target/debug/pulse_device

# Test signature verification
docker run -it --rm tercespot-test /app/target/debug/submitter --help
```

### Debug Mode

#### Interactive Container
```bash
# Start container in interactive mode
docker run -it --rm tercespot-test /bin/bash

# Manually run test steps
/app/scripts/validate_docker.sh
```

#### Log Analysis
```bash
# Check Docker logs
docker logs <container_id>

# Mount volumes for log access
docker run -it --rm -v /tmp:/tmp tercespot-test tail -f /tmp/sentinel_history.log
```

## Performance Metrics

### Expected Performance
- **Build Time**: 5-10 minutes (first run)
- **Test Execution**: 30-60 seconds
- **Memory Usage**: 512MB-1GB during test
- **Disk Usage**: 200MB-500MB for container

### Benchmarking
```bash
# Time the complete test
time docker run --rm tercespot-test

# Monitor resource usage
docker stats <container_id>
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Docker Test

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  docker-test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Docker Image
      run: |
        cd tercespot
        docker build -f Dockerfile.test -t tercespot-test .
    
    - name: Run Docker Test
      run: docker run --rm tercespot-test
    
    - name: Cleanup
      run: docker rmi tercespot-test
```

### Local Development
```bash
# Quick test after code changes
docker build -f Dockerfile.test -t tercespot-test . && docker run --rm tercespot-test

# Test specific components
docker run -it --rm tercespot-test /app/target/debug/sentinel --help
docker run -it --rm tercespot-test /app/target/debug/pulse_device --help
```

## Security Considerations

### Container Security
- **Non-Root User**: Tests run as 'submitter' user where possible
- **File Permissions**: Proper permissions for cryptographic files
- **Network Isolation**: Container network isolation
- **Resource Limits**: Memory and CPU limits applied

### Cryptographic Security
- **Key Protection**: Secure key generation and storage
- **Signature Validation**: Proper cryptographic signature verification
- **Policy Enforcement**: Strict policy evaluation
- **Audit Logging**: Complete execution logging

## Maintenance

### Regular Updates
- **Base Image**: Update Ubuntu base image regularly
- **Dependencies**: Update Rust toolchain and dependencies
- **Security Patches**: Apply security updates promptly

### Test Maintenance
- **Policy Updates**: Update test policies as needed
- **Performance Monitoring**: Monitor test execution times
- **Error Handling**: Improve error messages and debugging

## Conclusion

The Docker test provides comprehensive validation of the Four-Eyes Vault functionality with Post-Quantum Cryptography. It ensures that all components work together correctly in an isolated environment that simulates real-world deployment conditions.

---

**Test Version**: 1.0  
**Last Updated**: January 3, 2026  
**Next Review**: April 3, 2026  
**Maintainer**: TersecPot Development Team