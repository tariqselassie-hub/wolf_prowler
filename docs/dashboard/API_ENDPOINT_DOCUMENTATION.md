# Dashboard API Endpoint Documentation

## Overview

This document provides comprehensive documentation for all API endpoints in the Wolf Prowler Enterprise SIEM/SOAR dashboard, including authentication, data models, and integration patterns.

## Authentication

### Authentication Methods

The dashboard supports multiple authentication methods:

1. **Session-based Authentication**
   - Use `X-Session-ID` header
   - Sessions are managed by the AuthenticationManager
   - Automatic session validation and expiration

2. **API Key Authentication**
   - Use `X-API-Key` header
   - API keys provide programmatic access
   - Support for different permission levels

3. **Combined Authentication**
   - System tries session auth first, then API key
   - Provides flexibility for different use cases

### Authentication Headers

```http
# Session Authentication
X-Session-ID: 123e4567-e89b-12d3-a456-426614174000

# API Key Authentication
X-API-Key: ak_live_1234567890abcdef

# Combined (system will try both)
X-Session-ID: 123e4567-e89b-12d3-a456-426614174000
X-API-Key: ak_live_1234567890abcdef
```

### Authentication Response Headers

Successful authentication adds these headers to responses:

```http
X-User-ID: 123e4567-e89b-12d3-a456-426614174000
X-Key-ID: 123e4567-e89b-12d3-a456-426614174000  # For API key auth
```

## API Endpoints

### 1. Authentication API

#### POST /api/v1/auth/login
Authenticate a user and create a session.

**Request Body:**
```json
{
  "username": "admin",
  "password": "password123",
  "remember_me": true
}
```

**Response:**
```json
{
  "success": true,
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "session_id": "123e4567-e89b-12d3-a456-426614174000",
  "token": "123e4567-e89b-12d3-a456-426614174000",
  "error": null,
  "mfa_required": false
}
```

#### POST /api/v1/auth/logout
Terminate a user session.

**Headers:**
```
X-Session-ID: 123e4567-e89b-12d3-a456-426614174000
```

**Response:**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

#### GET /api/v1/auth/validate-session
Validate an existing session.

**Headers:**
```
X-Session-ID: 123e4567-e89b-12d3-a456-426614174000
```

**Response:**
```json
{
  "valid": true,
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "expires_at": "2024-01-16T10:30:00Z",
  "error": null
}
```

#### GET /api/v1/auth/validate-api-key
Validate an API key.

**Headers:**
```
X-API-Key: ak_live_1234567890abcdef
```

**Response:**
```json
{
  "valid": true,
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "key_id": "123e4567-e89b-12d3-a456-426614174000",
  "permissions": ["read:threats", "write:responses"],
  "message": "API key is valid"
}
```

### 2. Behavioral Analysis API

#### GET /api/v1/behavioral
Get overall behavioral analysis statistics.

**Response:**
```json
{
  "peer_id": "overall",
  "behavioral_score": 0.75,
  "pattern_count": 150,
  "active_pattern_count": 23,
  "recent_detection_count": 5,
  "peer_score": 0.8
}
```

#### GET /api/v1/behavioral/{peer_id}
Get behavioral analysis for a specific peer.

**Response:**
```json
{
  "peer_id": "12D3KooWAbc123...",
  "behavioral_score": 0.85,
  "pattern_count": 150,
  "active_pattern_count": 23,
  "recent_detection_count": 5,
  "peer_score": 0.85
}
```

### 3. Compliance API

#### GET /api/v1/compliance/status
Get compliance status across various standards.

**Response:**
```json
{
  "soc2_status": 92.5,
  "last_soc2_audit": "2024-01-01",
  "gdpr_status": 88.3,
  "data_subjects": 1234,
  "audit_entries": 45678,
  "audit_retention": 2555
}
```

#### GET /api/v1/compliance/audit
Get audit trail entries.

**Response:**
```json
[
  {
    "entry_id": "audit-001",
    "event_type": "Authentication",
    "subject": "user@example.com",
    "action": "Login",
    "resource": "Dashboard",
    "timestamp": "2024-01-16T10:30:00Z",
    "ip_address": "192.168.1.100",
    "compliance_status": "Compliant"
  }
]
```

#### GET /api/v1/compliance/reports
Get compliance reports.

**Response:**
```json
[
  {
    "report_id": "report-001",
    "report_type": "SOC2 Type II",
    "period": "Q4 2024",
    "generated_date": "2024-01-01",
    "status": "Completed",
    "findings_count": 2,
    "compliance_score": 96.5
  }
]
```

#### GET /api/v1/compliance/automated
Get automated compliance reports.

**Response:**
```json
[
  {
    "name": "Weekly Security Report",
    "report_type": "Security Summary",
    "schedule": "Weekly",
    "recipients": ["security@example.com"],
    "last_run": "2024-01-14",
    "next_run": "2024-01-21",
    "status": "Active"
  }
]
```

### 4. Cryptographic Operations API

#### GET /api/v1/crypto
Get cryptographic operations statistics.

**Response:**
```json
{
  "total_operations": 1250,
  "encryption_count": 420,
  "decryption_count": 410,
  "signature_count": 210,
  "verification_count": 210,
  "avg_operation_time": 12.5,
  "error_rate": 0.001
}
```

#### GET /api/v1/crypto/operations
Get detailed cryptographic operations data.

**Response:**
```json
{
  "operations": [
    {
      "type": "encryption",
      "algorithm": "AES-256-GCM",
      "count": 420,
      "avg_time_ms": 15.2,
      "success_rate": 0.998
    }
  ],
  "security_level": "high",
  "compliance_status": "compliant"
}
```

### 5. Intelligence API

#### GET /api/v1/intelligence/status
Get threat intelligence status.

**Response:**
```json
{
  "critical_cves": 3,
  "cve_week": 12,
  "ai_predictions": 89,
  "prediction_accuracy": 94.2,
  "threat_indicators": 156,
  "active_indicators": 42,
  "intelligence_feeds": 8,
  "last_feed_update": "2 minutes ago"
}
```

#### GET /api/v1/intelligence/cves
Get recent CVEs.

**Response:**
```json
[
  {
    "cve_id": "CVE-2024-12345",
    "severity": "Critical",
    "cvss_score": 9.8,
    "description": "Remote code execution vulnerability in network stack",
    "published_date": "2024-01-15",
    "last_modified": "2024-01-16"
  }
]
```

#### GET /api/v1/intelligence/indicators
Get threat indicators.

**Response:**
```json
[
  {
    "indicator_id": "ind-001",
    "indicator_type": "IP Address",
    "value": "192.168.1.100",
    "confidence": 0.95,
    "source": "Internal Analysis",
    "last_seen": "2024-01-16T10:30:00Z"
  }
]
```

#### GET /api/v1/intelligence/predictions
Get AI threat predictions.

**Response:**
```json
[
  {
    "prediction_id": "pred-001",
    "threat_type": "DDoS Attack",
    "confidence": 0.92,
    "predicted_impact": "High",
    "time_to_impact": "2-4 hours",
    "timestamp": "2024-01-16T10:30:00Z"
  }
]
```

#### GET /api/v1/intelligence/feeds
Get intelligence feeds.

**Response:**
```json
[
  {
    "name": "NIST NVD",
    "feed_type": "CVE Database",
    "status": "Active",
    "last_update": "5 minutes ago",
    "indicators_count": 2341
  }
]
```

### 6. Metrics API

#### GET /api/v1/metrics
Get basic system metrics.

**Response:**
```json
{
  "request_count": 1500,
  "uptime_seconds": 3600,
  "memory_usage_mb": 256.5,
  "cpu_usage_percent": 12.8,
  "active_connections": 42,
  "total_messages": 1250,
  "avg_response_time": 45.2
}
```

#### GET /api/v1/metrics/detailed
Get detailed system metrics.

**Response:**
```json
{
  "system": {
    "memory_usage": 256.5,
    "cpu_usage": 12.8,
    "disk_usage": 45.2,
    "uptime": 3600
  },
  "network": {
    "active_connections": 42,
    "total_messages": 1250,
    "bandwidth_in": 1.2,
    "bandwidth_out": 0.8
  },
  "security": {
    "threat_detection_rate": 0.347,
    "anomaly_detection_rate": 0.5,
    "reputation_updates": 150,
    "security_events": 1250
  },
  "performance": {
    "avg_response_time": 45.2,
    "max_response_time": 120.5,
    "request_rate": 0.3,
    "error_rate": 0.001
  }
}
```

#### GET /api/v1/metrics/system
Get system-specific metrics.

**Response:**
```json
{
  "memory_usage": 256.5,
  "cpu_usage": 12.8,
  "disk_usage": 45.2,
  "uptime": 3600
}
```

#### GET /api/v1/metrics/performance
Get performance metrics.

**Response:**
```json
{
  "avg_response_time": 45.2,
  "max_response_time": 120.5,
  "request_rate": 0.3,
  "error_rate": 0.001
}
```

### 7. Network API

#### GET /api/v1/network/status
Get network status and statistics.

**Response:**
```json
{
  "connected_peers": 12,
  "total_peers": 45,
  "network_latency": 23.5,
  "average_latency": 18.2,
  "data_transfer": 2456.7,
  "transfer_rate": 1.2,
  "hyperpulse_status": "Active",
  "active_streams": 8,
  "network_health": 94.5
}
```

#### GET /api/v1/network/peers
Get peer information.

**Response:**
```json
[
  {
    "peer_id": "12D3KooWAbc123...",
    "status": "Connected",
    "latency": 15.2,
    "last_seen": "2024-01-16T10:30:00Z",
    "data_transferred": 123.4
  }
]
```

#### GET /api/v1/network/connections
Get connection metrics.

**Response:**
```json
{
  "total_connections": 156,
  "active_connections": 23,
  "failed_connections": 3,
  "success_rate": 98.1
}
```

#### GET /api/v1/network/topology
Get network topology data for visualization.

**Response:**
```json
{
  "nodes": [
    {"id": "local", "label": "Local Node", "group": "local"},
    {"id": "peer1", "label": "Peer 1", "group": "connected"}
  ],
  "edges": [
    {"from": "local", "to": "peer1", "value": 10}
  ]
}
```

### 8. Peers API

#### GET /api/v1/peers
Get peer network statistics.

**Response:**
```json
{
  "total_peers": 23,
  "active_peers": 18,
  "trusted_peers": 18,
  "suspicious_peers": 2,
  "average_reputation": 0.75,
  "network_health": 0.78
}
```

#### GET /api/v1/peers/{peer_id}
Get details for a specific peer.

**Response:**
```json
{
  "peer_id": "12D3KooWAbc123...",
  "reputation": 0.85,
  "connected": true,
  "last_seen": "2024-01-16T10:30:00Z",
  "message_count": 150,
  "threat_count": 2
}
```

#### GET /api/v1/peers/reputation
Get peer reputation data.

**Response:**
```json
{
  "reputation_trends": {
    "last_24h": 0.75,
    "last_7d": 0.78,
    "last_30d": 0.81
  },
  "average_reputation": 0.75,
  "peer_count": 23,
  "health_status": "healthy"
}
```

### 9. Security API

#### GET /api/v1/security/status
Get overall security status.

**Response:**
```json
{
  "security_score": 0.92,
  "threat_level": "Low",
  "compliance_status": "Compliant",
  "active_measures": [
    "Real-time threat detection",
    "Behavioral analysis",
    "Anomaly detection"
  ],
  "recent_events": [
    {
      "event_id": "event-001",
      "event_type": "ThreatDetection",
      "timestamp": "2024-01-16T10:30:00Z",
      "severity": "Medium",
      "description": "Detected 5 recent threats"
    }
  ],
  "recommendations": [
    "Maintain current security posture",
    "Continue regular monitoring"
  ]
}
```

#### GET /api/v1/security/score
Get security score only.

**Response:**
```json
0.92
```

#### GET /api/v1/security/compliance
Get compliance status details.

**Response:**
```json
{
  "compliance_status": "Compliant",
  "standards": [
    "ISO 27001",
    "NIST CSF",
    "GDPR",
    "HIPAA"
  ],
  "last_audit": "2024-01-15",
  "next_audit": "2024-07-15",
  "compliance_score": 0.95,
  "findings": []
}
```

### 10. System API

#### GET /api/v1/system/status
Get system administration status.

**Response:**
```json
{
  "pack_members": 23,
  "active_pack": 18,
  "prestige_pool": 1247,
  "decay_rate": 1.0,
  "omega_status": "Active",
  "omega_controls": 5
}
```

#### GET /api/v1/system/pack
Get pack member information.

**Response:**
```json
[
  {
    "peer_id": "12D3KooWAbc123...",
    "role": "Alpha",
    "prestige": 2500,
    "rank": 5,
    "last_activity": "2024-01-16T10:30:00Z"
  }
]
```

#### GET /api/v1/system/hierarchy
Get hierarchy distribution.

**Response:**
```json
{
  "stray": 5,
  "scout": 8,
  "hunter": 6,
  "beta": 3,
  "alpha": 1,
  "omega": 1
}
```

#### GET /api/v1/system/prestige
Get prestige metrics.

**Response:**
```json
{
  "total_prestige": 15420,
  "average_prestige": 672.2,
  "gained_today": 145,
  "decayed_today": 23
}
```

#### GET /api/v1/system/actions
Get administrative actions.

**Response:**
```json
[
  {
    "action_id": "action-001",
    "action_type": "Role Change",
    "target_peer": "12D3KooWAbc123...",
    "description": "Promoted to Alpha role",
    "timestamp": "2024-01-16T10:30:00Z",
    "status": "Completed"
  }
]
```

### 11. Threats API

#### GET /api/v1/threats
Get threat detection statistics.

**Response:**
```json
{
  "total_threats": 1250,
  "active_threats": 5,
  "critical_threats": 125,
  "high_threats": 250,
  "medium_threats": 375,
  "low_threats": 500,
  "average_confidence": 0.85,
  "detection_rate": 5.0
}
```

#### GET /api/v1/threats/recent
Get recent threats.

**Response:**
```json
[
  {
    "threat_id": "threat-001",
    "threat_type": "MaliciousPeer",
    "source_peer": "peer-12345",
    "severity": "High",
    "confidence": 0.85,
    "description": "Suspicious behavior pattern detected",
    "detected_at": "2024-01-16T10:30:00Z",
    "status": "Active"
  }
]
```

#### GET /api/v1/threats/{peer_id}
Get threats by specific peer.

**Response:**
```json
[
  {
    "threat_id": "threat-001",
    "threat_type": "MaliciousPeer",
    "source_peer": "peer-12345",
    "severity": "High",
    "confidence": 0.85,
    "description": "Suspicious behavior pattern detected",
    "detected_at": "2024-01-16T10:30:00Z",
    "status": "Active"
  }
]
```

### 12. WebSocket API

#### GET /ws/dashboard
WebSocket endpoint for real-time dashboard updates.

**Query Parameters:**
- `api_key`: API key for authentication
- `session_id`: Session ID for authentication

**Message Types:**

1. **System Metrics Update**
```json
{
  "type": "system_metrics",
  "cpu": 12.8,
  "memory": 256.5,
  "uptime": 3600
}
```

2. **Network Status Update**
```json
{
  "type": "network_status",
  "peers": 23,
  "connections": 42,
  "health": 94.5
}
```

3. **Security Alert**
```json
{
  "type": "security_alert",
  "severity": "High",
  "message": "Security alert: High threat detected",
  "timestamp": "2024-01-16T10:30:00Z"
}
```

4. **Threat Update**
```json
{
  "type": "threat_update",
  "threat_type": "DDoS Attack",
  "count": 5,
  "timestamp": "2024-01-16T10:30:00Z"
}
```

5. **General Notification**
```json
{
  "type": "notification",
  "title": "Connected",
  "message": "Welcome to Wolf Prowler Dashboard"
}
```

## Error Handling

### Error Response Format

All API endpoints return consistent error responses:

```json
{
  "error": "Error message describing what went wrong",
  "code": "ERROR_CODE",
  "details": {
    "field": "Additional error details"
  }
}
```

### Common Error Codes

- `UNAUTHORIZED`: Authentication required or failed
- `FORBIDDEN`: Insufficient permissions
- `NOT_FOUND`: Resource not found
- `VALIDATION_ERROR`: Invalid request data
- `INTERNAL_ERROR`: Server error
- `RATE_LIMITED`: Too many requests

### HTTP Status Codes

- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `422`: Unprocessable Entity
- `429`: Too Many Requests
- `500`: Internal Server Error

## Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Authentication endpoints**: 10 requests per minute per IP
- **Data endpoints**: 100 requests per minute per authenticated user
- **WebSocket connections**: 5 concurrent connections per user

Rate limit information is included in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642329600
```

## Data Models

### User Model
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "username": "admin",
  "email": "admin@example.com",
  "roles": ["admin", "security_analyst"],
  "created_at": "2024-01-01T00:00:00Z",
  "last_login": "2024-01-16T10:30:00Z"
}
```

### Session Model
```json
{
  "session_id": "123e4567-e89b-12d3-a456-426614174000",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "ip_address": "192.168.1.100",
  "user_agent": "Dashboard Client",
  "created_at": "2024-01-16T10:30:00Z",
  "expires_at": "2024-01-17T10:30:00Z",
  "remember_me": true
}
```

### Threat Model
```json
{
  "threat_id": "threat-001",
  "threat_type": "MaliciousPeer",
  "source_peer": "peer-12345",
  "severity": "High",
  "confidence": 0.85,
  "description": "Suspicious behavior pattern detected",
  "detected_at": "2024-01-16T10:30:00Z",
  "status": "Active",
  "resolved_at": null
}
```

### Peer Model
```json
{
  "peer_id": "12D3KooWAbc123...",
  "role": "Hunter",
  "reputation": 0.85,
  "connected": true,
  "last_seen": "2024-01-16T10:30:00Z",
  "message_count": 150,
  "threat_count": 2,
  "prestige": 1200,
  "rank": 3
}
```

This comprehensive API documentation provides all the information needed to integrate with the Wolf Prowler Enterprise SIEM/SOAR dashboard and leverage its revolutionary security capabilities.