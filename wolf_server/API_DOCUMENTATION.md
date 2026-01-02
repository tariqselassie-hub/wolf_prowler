# Wolf Server - Advanced API Endpoints

## Overview

Wolf Server now includes comprehensive API endpoints for querying historical data and exporting reports.

## API Endpoints

### Database Health & Stats

#### `GET /database/health`
Check database connectivity and health status.

**Response**:
```json
{
  "status": "healthy",
  "connected": true,
  "timestamp": "2024-12-20T23:57:00Z"
}
```

#### `GET /database/stats`
Get database statistics.

**Response**:
```json
{
  "active_peers": 5,
  "recent_alerts": 12,
  "recent_logs": 150,
  "timestamp": "2024-12-20T23:57:00Z"
}
```

### Historical Queries

#### `GET /api/v1/peers/history`
Get historical peer data with pagination.

**Query Parameters**:
- `limit` (optional, default: 100) - Number of records to return
- `offset` (optional, default: 0) - Number of records to skip

**Example**:
```bash
curl "http://localhost:3030/api/v1/peers/history?limit=50&offset=0"
```

**Response**:
```json
{
  "peers": [
    {
      "peer_id": "12D3KooW...",
      "service_type": "wolf_server",
      "system_type": "linux",
      "status": "online",
      "trust_score": 0.95,
      "last_seen": "2024-12-20T23:55:00Z"
    }
  ],
  "total": 5,
  "limit": 50,
  "offset": 0
}
```

#### `GET /api/v1/peers/:id/metrics`
Get metrics for a specific peer.

**Path Parameters**:
- `id` - Peer ID

**Query Parameters**:
- `limit` (optional, default: 100)
- `offset` (optional, default: 0)

**Example**:
```bash
curl "http://localhost:3030/api/v1/peers/12D3KooW.../metrics?limit=20"
```

**Response**:
```json
{
  "peer_id": "12D3KooW...",
  "metrics": [
    {
      "timestamp": "2024-12-20T23:55:00Z",
      "latency_ms": 45,
      "messages_sent": 1250,
      "messages_received": 1180,
      "health_score": 0.92
    }
  ],
  "count": 20
}
```

#### `GET /api/v1/alerts/history`
Get security alerts history.

**Query Parameters**:
- `limit` (optional, default: 100)

**Example**:
```bash
curl "http://localhost:3030/api/v1/alerts/history?limit=50"
```

**Response**:
```json
{
  "alerts": [
    {
      "timestamp": "2024-12-20T23:50:00Z",
      "severity": "high",
      "status": "active",
      "title": "Suspicious Activity Detected",
      "category": "intrusion_detection",
      "source": "wolfsec"
    }
  ],
  "count": 12
}
```

#### `GET /api/v1/audit/logs`
Get audit logs.

**Query Parameters**:
- `limit` (optional, default: 100)
- `offset` (optional, default: 0)

**Example**:
```bash
curl "http://localhost:3030/api/v1/audit/logs?limit=100"
```

**Response**:
```json
{
  "logs": [
    {
      "timestamp": "2024-12-20T23:55:00Z",
      "action": "peer_connected",
      "actor": "system",
      "resource": "12D3KooW...",
      "result": "success"
    }
  ],
  "count": 100
}
```

#### `GET /api/v1/metrics/timeline`
Get aggregated metrics timeline (last 24 hours).

**Query Parameters**:
- `limit` (optional, default: 100)

**Example**:
```bash
curl "http://localhost:3030/api/v1/metrics/timeline"
```

**Response**:
```json
{
  "timeline": [
    {
      "timestamp": "2024-12-20T23:00:00Z",
      "peer_count": 5,
      "avg_latency": 42.5,
      "total_messages_sent": 15000,
      "total_messages_received": 14500,
      "avg_health_score": 0.91
    }
  ],
  "count": 24
}
```

### Data Export

#### `GET /api/v1/export/peers/csv`
Export peer data as CSV.

**Example**:
```bash
curl "http://localhost:3030/api/v1/export/peers/csv" -o peers.csv
```

**Response**: CSV file with headers:
```
peer_id,service_type,system_type,status,trust_score,last_seen
```

#### `GET /api/v1/export/peers/json`
Export peer data as JSON.

**Example**:
```bash
curl "http://localhost:3030/api/v1/export/peers/json" -o peers.json
```

**Response**: JSON array of peer objects.

#### `GET /api/v1/export/alerts/csv`
Export security alerts as CSV.

**Example**:
```bash
curl "http://localhost:3030/api/v1/export/alerts/csv" -o alerts.csv
```

**Response**: CSV file with headers:
```
timestamp,severity,status,title,category,source
```

#### `GET /api/v1/export/metrics/csv`
Export peer metrics as CSV (last 10,000 records).

**Example**:
```bash
curl "http://localhost:3030/api/v1/export/metrics/csv" -o metrics.csv
```

**Response**: CSV file with headers:
```
peer_id,timestamp,latency_ms,messages_sent,messages_received,health_score
```

## Usage Examples

### Python

```python
import requests
import pandas as pd
from io import StringIO

# Get peer history
response = requests.get('http://localhost:3030/api/v1/peers/history?limit=100')
peers = response.json()
print(f"Found {peers['total']} peers")

# Get metrics for specific peer
peer_id = "12D3KooW..."
response = requests.get(f'http://localhost:3030/api/v1/peers/{peer_id}/metrics')
metrics = response.json()

# Export and analyze CSV data
response = requests.get('http://localhost:3030/api/v1/export/metrics/csv')
df = pd.read_csv(StringIO(response.text))
print(df.describe())
```

### Bash

```bash
#!/bin/bash

# Get database health
curl -s http://localhost:3030/database/health | jq .

# Get recent alerts
curl -s "http://localhost:3030/api/v1/alerts/history?limit=10" | jq '.alerts[]'

# Export all data
curl -o peers.csv http://localhost:3030/api/v1/export/peers/csv
curl -o alerts.csv http://localhost:3030/api/v1/export/alerts/csv
curl -o metrics.csv http://localhost:3030/api/v1/export/metrics/csv

# Analyze with csvkit
csvstat peers.csv
csvstat metrics.csv
```

### JavaScript/Node.js

```javascript
const axios = require('axios');

async function getPeerHistory() {
  const response = await axios.get('http://localhost:3030/api/v1/peers/history', {
    params: { limit: 50, offset: 0 }
  });
  
  console.log(`Total peers: ${response.data.total}`);
  response.data.peers.forEach(peer => {
    console.log(`${peer.peer_id}: ${peer.status} (trust: ${peer.trust_score})`);
  });
}

async function exportMetrics() {
  const response = await axios.get('http://localhost:3030/api/v1/export/metrics/csv');
  require('fs').writeFileSync('metrics.csv', response.data);
}

getPeerHistory();
exportMetrics();
```

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "Error message description"
}
```

Common errors:
- `"Persistence not enabled"` - Database feature not enabled
- `"Database connection failed"` - Cannot connect to database
- `"Invalid peer ID"` - Peer not found
- `"Query failed: <details>"` - Database query error

## Performance Considerations

- **Pagination**: Use `limit` and `offset` for large datasets
- **Caching**: Results are not cached, queries hit database directly
- **Rate Limiting**: No rate limiting currently implemented
- **Export Limits**: 
  - Peers: All active peers
  - Alerts: Last 1,000 alerts
  - Metrics: Last 10,000 records

## Security

- All endpoints require the server to be running with `advanced_reporting` feature
- No authentication currently implemented (add auth middleware as needed)
- CORS is permissive (configure as needed for production)

## Next Steps

1. Add authentication/authorization
2. Implement rate limiting
3. Add response caching
4. Add filtering by date range
5. Add aggregation endpoints
6. Add real-time WebSocket updates

---

**Feature Flag**: `advanced_reporting`  
**Base URL**: `http://localhost:3030`  
**Format**: JSON (default), CSV (export endpoints)
