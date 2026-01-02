# API Reference

## 📋 API Improvement Plan

### Current Issues

- ❌ Inconsistent versioning (some endpoints use `/api/v1`, others don't)
- ❌ Mixed response formats and error handling
- ❌ No authentication/authorization
- ❌ Missing rate limiting and security headers
- ❌ No API documentation generation
- ❌ Inconsistent pagination and filtering

### Proposed Improvements

## 🏠 System Endpoints (`/api/v1/system`)

**Endpoints:**

- `GET /api/v1/system/status` - System health and version info
- `GET /api/v1/system/metrics` - Real-time system metrics
- `GET /api/v1/system/config` - Current system configuration
- `PUT /api/v1/system/config` - Update system configuration
- `GET /api/v1/system/logs` - System logs with filtering

## 🌐 Network Endpoints (`/api/v1/network`)

**Endpoints:**

- `GET /api/v1/network/status` - Network health overview
- `GET /api/v1/network/peers` - List peers with pagination
- `GET /api/v1/network/peers/{id}` - Detailed peer information
- `POST /api/v1/network/peers/{id}/connect` - Connect to specific peer
- `DELETE /api/v1/network/peers/{id}` - Disconnect/block peer
- `GET /api/v1/network/metrics` - Network performance metrics

## 🛡️ Security Endpoints (`/api/v1/security`)

**Endpoints:**

- `GET /api/v1/security/status` - Security system status
- `GET /api/v1/security/alerts` - Security alerts with filtering
- `GET /api/v1/security/threats` - Active threats
- `POST /api/v1/security/scan` - Trigger security scan
- `GET /api/v1/security/policies` - Security policies
- `GET /api/v1/security/policies` - Security policies
- `PUT /api/v1/security/policies` - Update security policies
- `GET /api/v1/firewall/rules` - List active firewall rules
- `POST /api/v1/firewall/rules/add` - Add a new firewall rule
- `POST /api/v1/firewall/rules/delete` - Delete a firewall rule

## 📊 Analytics Endpoints (`/api/v1/analytics`)

**Endpoints:**

- `GET /api/v1/analytics/dashboard` - Dashboard metrics
- `GET /api/v1/analytics/metrics/{type}` - Specific metric data
- `GET /api/v1/analytics/reports` - Generate reports
- `POST /api/v1/analytics/export` - Export data

## 🔧 Management Endpoints (`/api/v1/management`)

**Endpoints:**

- `GET /api/v1/management/health` - Service health checks
- `POST /api/v1/management/restart` - Restart services
- `GET /api/v1/management/backup` - Create backups
- `POST /api/v1/management/restore` - Restore from backup

## 📋 Standard Response Format

### Success Response

```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "timestamp": "2025-12-23T10:00:00Z",
    "request_id": "req-12345",
    "version": "v1"
  }
}
```

### Error Response

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": { ... }
  },
  "meta": {
    "timestamp": "2025-12-23T10:00:00Z",
    "request_id": "req-12345"
  }
}
```

### Paginated Response

```json
{
  "success": true,
  "data": [ ... ],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 150,
    "total_pages": 3,
    "has_next": true,
    "has_prev": false
  },
  "meta": { ... }
}
```

## 🔐 Authentication & Authorization

### API Key Authentication

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
     -H "X-API-Key: YOUR_API_KEY" \
     https://api.wolf-prowler.com/api/v1/system/status
```

### Rate Limiting

- 1000 requests per hour for read operations
- 100 requests per hour for write operations
- Burst limit: 50 requests per minute

## 🛡️ Security Features

### Headers Added

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`
- `Content-Security-Policy: default-src 'self'`

### Request Validation

- JSON schema validation for all requests
- Input sanitization
- SQL injection prevention
- XSS protection

## 📚 API Documentation

### OpenAPI Specification

- Auto-generated from code annotations
- Available at `/api/v1/docs`
- Interactive Swagger UI at `/api/v1/docs/ui`

### SDK Generation

- TypeScript SDK available
- Python SDK available
- Go SDK available

## 🔄 Versioning Strategy

### URL Versioning

- `/api/v1/` - Current stable version
- `/api/v2/` - Next version (when ready)
- `/api/latest/` - Always points to latest stable

### Header Versioning

```bash
Accept: application/vnd.wolf-prowler.v1+json
```

## 📊 Monitoring & Analytics

### API Metrics

- Request/response times
- Error rates by endpoint
- Usage patterns
- Performance bottlenecks

### Health Checks

- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe
- `/health/deep` - Deep health check

## 🚀 Implementation Priority

### Phase 1 (Immediate)

- [ ] Standardize response formats
- [ ] Add proper error handling
- [ ] Implement consistent versioning
- [ ] Add basic authentication

### Phase 2 (Short-term)

- [ ] Add rate limiting
- [ ] Implement security headers
- [ ] Add request validation
- [ ] Create OpenAPI documentation

### Phase 3 (Medium-term)

- [ ] Add comprehensive monitoring
- [ ] Implement caching layer
- [ ] Add SDK generation
- [ ] Performance optimization

### Phase 4 (Long-term)

- [ ] GraphQL API support
- [ ] WebSocket real-time updates
- [ ] Advanced analytics
- [ ] Multi-region support
