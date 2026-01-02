# Wolf Server - Database Persistence Integration

## Overview

Wolf Server now includes full PostgreSQL persistence integration for storing peer data, metrics, and system logs.

## Features

### ✅ Implemented

1. **Persistence Manager Initialization**
   - Automatic initialization on startup if `DATABASE_URL` is set
   - Health check on startup
   - Graceful fallback if database is unavailable

2. **API Endpoints**
   - `GET /database/health` - Database health status
   - `GET /database/stats` - Database statistics (peer count, alerts, logs)

3. **Background Metrics Collection**
   - Runs every 60 seconds
   - Saves peer information to database
   - Saves peer metrics (latency, messages, bytes, health score)
   - Logs collection events

4. **Feature Flag**
   - Controlled by `advanced_reporting` feature
   - Compiles without database support if feature is disabled

## Configuration

### Environment Variables

```bash
# Required for database persistence
DATABASE_URL=postgresql://wolf_admin:wolf_secure_pass_2024@postgres:5432/wolf_prowler

# Standard wolf_server configuration
NODE_NAME=CAP
NODE_ID=cap-node-001
PORT=3031
API_PORT=3030
NETWORK_ID=wolf-testnet
BOOTSTRAP_NODES=omega:3031,ccj:3031
```

### Docker Compose

The `docker-compose.yml` is already configured with database support:

```yaml
environment:
  - DATABASE_URL=postgresql://wolf_admin:wolf_secure_pass_2024@postgres:5432/wolf_prowler
depends_on:
  postgres:
    condition: service_healthy
```

## Building

### With Database Support (Default)

```bash
# Build with persistence
cargo build --release --features advanced_reporting

# Or in Docker
docker-compose build
```

### Without Database Support

```bash
# Build without persistence
cargo build --release
```

## Running

### With Docker Compose (Recommended)

```bash
# Start database first
docker-compose up -d postgres

# Wait for health check
./scripts/db_manager.sh check

# Start all nodes
docker-compose up -d

# View logs
docker-compose logs -f cap
```

### Standalone

```bash
# Set environment variables
export DATABASE_URL="postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler"
export NODE_NAME="CAP"
export PORT="3031"
export API_PORT="3030"

# Run
cargo run --release --features advanced_reporting
```

## API Usage

### Check Database Health

```bash
curl http://localhost:3030/database/health
```

**Response**:
```json
{
  "status": "healthy",
  "connected": true,
  "timestamp": "2024-12-20T23:53:00Z"
}
```

### Get Database Statistics

```bash
curl http://localhost:3030/database/stats
```

**Response**:
```json
{
  "active_peers": 2,
  "recent_alerts": 0,
  "recent_logs": 15,
  "timestamp": "2024-12-20T23:53:00Z"
}
```

### Get Server Status

```bash
curl http://localhost:3030/status
```

**Response**:
```json
{
  "peer_id": "12D3KooW...",
  "version": "2.0.0",
  "uptime_seconds": 3600
}
```

## Metrics Collection

### What Gets Saved

Every 60 seconds, the server collects and saves:

1. **Peer Information** (`peers` table):
   - Peer ID, service type, system type
   - Status, trust score
   - Protocol and agent versions
   - Capabilities and metadata

2. **Peer Metrics** (`peer_metrics` table):
   - Latency, messages sent/received
   - Bytes sent/received
   - Request success/failure counts
   - Health score, uptime

3. **System Logs** (`system_logs` table):
   - Collection events
   - Peer counts
   - Connection status

### Viewing Collected Data

```bash
# Connect to database
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler

# View peers
SELECT peer_id, status, trust_score, last_seen FROM peers;

# View recent metrics
SELECT peer_id, latency_ms, health_score, timestamp 
FROM peer_metrics 
ORDER BY timestamp DESC 
LIMIT 10;

# View system logs
SELECT level, message, timestamp 
FROM system_logs 
ORDER BY timestamp DESC 
LIMIT 20;
```

## Startup Sequence

1. **Initialize Logging**
2. **Load Server Config**
3. **Initialize WolfSec**
4. **Initialize Persistence** (if DATABASE_URL is set)
   - Connect to database
   - Run health check
   - Log status
5. **Initialize Wolf Net**
6. **Bootstrap Peers**
7. **Initialize Wolf Pack**
8. **Start API Server**
9. **Start Metrics Collection** (background task)

## Logs

### Successful Initialization

```
🐺 Wolf Server v2.0 - Initializing...
🛡️ Initializing WolfSec...
💾 Initializing database persistence...
✓ Database persistence initialized
✓ Database health check passed
🌐 Initializing Wolf Net...
🚀 Wolf Server is running!
📡 API Server listening on 0.0.0.0:3030
📊 Starting periodic metrics collection (every 60s)
```

### Without Database

```
🐺 Wolf Server v2.0 - Initializing...
🛡️ Initializing WolfSec...
ℹ DATABASE_URL not set. Running without persistence.
🌐 Initializing Wolf Net...
🚀 Wolf Server is running!
📡 API Server listening on 0.0.0.0:3030
```

### Database Connection Failed

```
🐺 Wolf Server v2.0 - Initializing...
🛡️ Initializing WolfSec...
💾 Initializing database persistence...
⚠ Failed to initialize persistence: connection refused. Continuing without database.
🌐 Initializing Wolf Net...
🚀 Wolf Server is running!
📡 API Server listening on 0.0.0.0:3030
```

## Troubleshooting

### Database Not Connecting

```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Verify network connectivity
docker-compose exec cap ping postgres

# Test database connection
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler -c "SELECT 1;"
```

### Metrics Not Being Saved

```bash
# Check wolf_server logs
docker-compose logs -f cap | grep "metrics"

# Verify database is writable
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler -c "
  INSERT INTO system_logs (level, message, source) 
  VALUES ('info', 'test', 'manual');
"

# Check for errors
docker-compose logs cap | grep -i "failed to save"
```

### Feature Not Enabled

```bash
# Rebuild with feature flag
docker-compose build --build-arg CARGO_FEATURES="advanced_reporting"

# Or locally
cargo build --release --features advanced_reporting
```

## Performance

### Metrics Collection Impact

- **Frequency**: Every 60 seconds
- **Duration**: < 100ms for 10 peers
- **Database Load**: ~20 queries per collection cycle
- **Memory**: Minimal (async operations)

### Database Connection Pool

- **Min Connections**: 5
- **Max Connections**: 20
- **Idle Timeout**: 10 minutes
- **Max Lifetime**: 30 minutes

## Next Steps

### Planned Enhancements

1. **Historical Query Endpoints**
   - `GET /api/v1/peers/history/:id`
   - `GET /api/v1/metrics/timeline`
   - `GET /api/v1/alerts/history`

2. **Security Event Persistence**
   - Save security events from wolfsec
   - Store threat intelligence
   - Log compliance checks

3. **Advanced Analytics**
   - Peer behavior analysis
   - Network topology visualization
   - Anomaly detection

4. **Data Export**
   - CSV export for reports
   - JSON export for analysis
   - Grafana dashboard integration

## References

- **Database Setup**: `docs/DATABASE_SETUP.md`
- **Schema**: `migrations/001_initial_schema.sql`
- **Persistence API**: `src/persistence/mod.rs`
- **Integration Example**: `examples/persistence_integration.rs`

---

**Status**: ✅ Fully integrated and operational  
**Feature Flag**: `advanced_reporting`  
**Database**: PostgreSQL 16  
**Collection Interval**: 60 seconds
