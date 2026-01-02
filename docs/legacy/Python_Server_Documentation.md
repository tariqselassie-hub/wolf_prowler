# Wolf Prowler Python Server Documentation

## Overview

The Wolf Prowler Python server is a comprehensive security monitoring and dashboard platform that provides real-time system monitoring, threat detection, and cryptographic services through a RESTful API. It integrates with the WolfSec cryptographic library for secure data handling.

## Architecture

### Core Components

- **APIHandler**: Main HTTP request handler with security middleware
- **WolfSec Integration**: Cryptographic services for data encryption/decryption
- **Real-time Monitoring**: System metrics and security event tracking
- **Threat Detection**: Automated security analysis and alerting

### Security Features

- **API Key Authentication**: Secure endpoint access control
- **Rate Limiting**: 60 requests per minute per IP
- **CORS Protection**: Cross-origin request validation
- **Input Validation**: Request sanitization and error handling

## API Endpoints

### Cryptographic Services

#### `/api/hash`
- **Method**: GET
- **Description**: Generate cryptographic hashes
- **Response**: BLAKE3 hash values
```json
{
  "success": true,
  "hash": "a1b2c3d4e5f67890...",
  "algorithm": "blake3"
}
```

#### `/api/kdf`
- **Method**: GET
- **Description**: Key derivation function
- **Response**: Argon2-derived keys
```json
{
  "success": true,
  "derived_key": "x9y8z7w6v5u4t3s2...",
  "algorithm": "argon2"
}
```

#### `/api/mac`
- **Method**: GET
- **Description**: Message authentication codes
- **Response**: HMAC-SHA256 values
```json
{
  "success": true,
  "mac": "m1n2o3p4q5r6s7t8...",
  "algorithm": "hmac-sha256"
}
```

### Security Monitoring

#### `/api/security/status`
- **Method**: GET
- **Description**: Real-time security status
- **Features**:
  - Firewall status detection
  - Active connection monitoring
  - Process counting
  - Security service detection
  - Open port scanning

#### `/api/security/events`
- **Method**: GET
- **Description**: Security event log
- **Features**:
  - Windows Event Log integration
  - Failed login detection
  - Network activity monitoring
  - Process alerting

#### `/api/security/threats`
- **Method**: GET
- **Description**: Active security threats
- **Features**:
  - Anomaly detection
  - Suspicious port monitoring
  - High resource usage alerts
  - Disk usage warnings

### Network Monitoring

#### `/api/network/status`
- **Method**: GET
- **Description**: Network health metrics
- **Features**:
  - Connection statistics
  - Bandwidth usage
  - Interface monitoring
  - Uptime tracking

#### `/api/peers`
- **Method**: GET
- **Description**: Network peer information
- **Features**:
  - Active connection details
  - System information
  - Network interface data
  - Latency measurements

### System Monitoring

#### `/api/system/status`
- **Method**: GET
- **Description**: System health overview
- **Features**:
  - CPU usage monitoring
  - Memory statistics
  - Disk usage analysis
  - System information

#### `/api/system/metrics`
- **Method**: GET
- **Description**: Real-time system metrics
- **Features**:
  - Live CPU usage
  - Memory consumption
  - Network I/O statistics
  - Process counting

### Advanced Security Features

#### `/api/threat/intelligence`
- **Method**: GET
- **Description**: AI-powered threat analysis
- **Features**:
  - Machine learning model status
  - Anomaly scoring
  - MITRE ATT&CK coverage
  - UEBA alerts

#### `/api/cve/feed`
- **Method**: GET
- **Description**: CVE intelligence feed
- **Features**:
  - Real-time CVE data
  - Severity classification
  - CVSS scoring
  - Affected system analysis

#### `/api/zero/trust`
- **Method**: GET
- **Description**: Zero Trust architecture status
- **Features**:
  - Network segmentation
  - Device trust scoring
  - Continuous authentication
  - Policy enforcement

#### `/api/siem/analytics`
- **Method**: GET/POST
- **Description**: SIEM analytics and metrics
- **Features**:
  - Log processing statistics
  - Incident response metrics
  - SOAR automation data
  - Threat hunting analytics

### WolfSec Integration

#### `/api/encrypted-packages`
- **Method**: POST
- **Description**: Encrypt system packages
- **Features**:
  - WolfSec AES-256-GCM encryption
  - System package discovery
  - Key management
  - Secure data handling

## Security Implementation

### Authentication
- **API Key**: `dev-key-12345` (development)
- **Header**: `X-API-Key`
- **Validation**: Constant-time comparison using `secrets.compare_digest()`

### Rate Limiting
- **Limit**: 60 requests per minute
- **Scope**: Per IP address
- **Reset**: Automatic after 60 seconds
- **Storage**: In-memory dictionary

### CORS Protection
- **Allowed Origins**: `http://localhost:8080`, `http://127.0.0.1:8080`
- **Methods**: GET, POST, OPTIONS
- **Headers**: X-API-Key, Content-Type

## WolfSec Cryptographic Integration

### Features
- **AES-256-GCM Encryption**: High-performance symmetric encryption
- **Key Generation**: Secure random key creation
- **Package Encryption**: System package data protection
- **CLI Integration**: Direct WolfSec binary interface

### Usage Example
```python
from wolfsec_integration import WolfSecCrypto

# Initialize crypto
crypto = WolfSecCrypto()

# Encrypt data
result = crypto.encrypt_data("sensitive data")
if result['success']:
    encrypted = result['encrypted_data']
    key = result['key']
    nonce = result['nonce']

# Decrypt data
decrypted = crypto.decrypt_data(encrypted, key, nonce)
```

## System Requirements

### Dependencies
- **Python 3.7+**
- **psutil**: System monitoring
- **wolfsec-python**: Cryptographic services
- **Standard library**: http.server, socketserver, json, etc.

### Platform Support
- **Windows**: Full support with Windows-specific features
- **Linux**: Full support with Unix-specific features
- **macOS**: Basic support

## Deployment

### Development Server
```bash
cd static
python server.py
```

### Production Configuration
- **Port**: 8080 (configurable)
- **Static Files**: Served from `./static`
- **API Base**: `/api/`
- **Security**: Enable production API keys

## Monitoring Capabilities

### Real-time Metrics
- CPU usage percentage
- Memory consumption
- Disk usage statistics
- Network I/O counters
- Process count
- System uptime

### Security Events
- Failed login attempts
- High network activity
- Process anomalies
- Suspicious port activity
- System event logs

### Threat Detection
- Anomaly scoring
- Behavioral analysis
- Pattern recognition
- Resource abuse detection

## API Response Format

### Success Response
```json
{
  "success": true,
  "data": {...},
  "timestamp": "2025-01-01T12:00:00Z"
}
```

### Error Response
```json
{
  "error": "Error description",
  "status_code": 400,
  "timestamp": "2025-01-01T12:00:00Z"
}
```

## Performance Considerations

### Optimization Features
- **Rate Limiting**: Prevents abuse
- **Connection Pooling**: Efficient resource use
- **Caching**: Reduces redundant computations
- **Async Operations**: Non-blocking I/O

### Resource Usage
- **Memory**: ~50MB baseline
- **CPU**: Low overhead monitoring
- **Disk**: Minimal logging
- **Network**: Efficient JSON responses

## Security Best Practices

### Implementation
- **Input Validation**: All user inputs sanitized
- **Error Handling**: Secure error responses
- **Logging**: Comprehensive audit trail
- **Encryption**: Sensitive data protection

### Recommendations
- **Production API Keys**: Use strong, unique keys
- **HTTPS**: Enable TLS in production
- **Firewall**: Restrict access to API endpoints
- **Monitoring**: Log all API access

## Troubleshooting

### Common Issues
1. **Port Already in Use**: Change PORT variable
2. **Permission Denied**: Run with appropriate privileges
3. **WolfSec Not Found**: Build WolfSec binary first
4. **High Memory Usage**: Monitor process count

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Future Enhancements

### Planned Features
- **WebSocket Support**: Real-time updates
- **Database Integration**: Persistent storage
- **Advanced Analytics**: Machine learning integration
- **Multi-tenant Support**: Isolated environments

### Scalability
- **Load Balancing**: Multiple server instances
- **Caching Layer**: Redis integration
- **Message Queue**: Async task processing
- **Microservices**: Modular architecture

---

**Version**: 1.0.0  
**Last Updated**: 2025-01-01  
**Author**: Wolf Prowler Team
