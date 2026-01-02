# Wolf Prowler Database & Docker Network Setup

## Overview

Wolf Prowler uses PostgreSQL for persistent storage and a dedicated Docker network for secure service communication.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    wolf_prowler_network                      │
│                      (172.20.0.0/16)                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │   CAP    │  │  OMEGA   │  │   CCJ    │  │ PostgreSQL │  │
│  │ (Alpha)  │  │  (Beta)  │  │ (Delta)  │  │  Database  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬─────┘  │
│       │             │              │                │         │
│       └─────────────┴──────────────┴────────────────┘         │
│                   P2P + Database Access                       │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                   │
│  │ PgAdmin  │  │ Grafana  │  │Prometheus│                   │
│  │(Optional)│  │(Optional)│  │(Optional)│                   │
│  └──────────┘  └──────────┘  └──────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

## Database Schema

### Core Tables

1. **peers** - Peer information and status
2. **peer_metrics** - Time-series metrics for each peer
3. **peer_connections** - Connection history
4. **security_events** - Security events and incidents
5. **security_alerts** - Active security alerts
6. **threat_intelligence** - Threat indicators and IOCs
7. **audit_logs** - System audit trail
8. **compliance_checks** - Compliance validation results
9. **config** - System configuration
10. **security_policies** - Security policy definitions
11. **pack_members** - Wolf Pack hierarchy
12. **pack_hierarchy** - Pack leadership structure
13. **system_logs** - Application logs
14. **network_metrics** - Network-wide metrics

### Views

- `active_peers_with_metrics` - Active peers with latest metrics
- `recent_security_alerts` - Alerts from last 24 hours
- `pack_overview` - Pack statistics and health

## Docker Network Configuration

### Network Details

- **Name**: `wolf_prowler_network`
- **Driver**: `bridge`
- **Subnet**: `172.20.0.0/16`
- **Gateway**: `172.20.0.1`
- **Bridge Name**: `wolf_br0`

### Network Features

- **Inter-Container Communication (ICC)**: Enabled
- **IP Masquerading**: Enabled
- **Isolation**: Services are isolated from host network
- **DNS**: Automatic service discovery via container names

### Service Communication

All services communicate via the dedicated network:

```
cap:3031       → P2P communication
omega:3031     → P2P communication
ccj:3031       → P2P communication
postgres:5432  → Database access
```

## Quick Start

### 1. Start the Full Stack

```bash
# Start all services including database
docker-compose up -d

# Start with monitoring (Grafana + Prometheus)
docker-compose --profile monitoring up -d

# Start with database admin (PgAdmin)
docker-compose --profile admin up -d
```

### 2. Initialize Database

```bash
# Using the database manager script
./scripts/db_manager.sh setup

# Or manually
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler -f /docker-entrypoint-initdb.d/001_initial_schema.sql
```

### 3. Verify Network

```bash
# List networks
docker network ls | grep wolf

# Inspect network
docker network inspect wolf_prowler_network

# Check connectivity
docker-compose exec cap ping -c 3 postgres
docker-compose exec omega ping -c 3 cap
```

### 4. Access Services

- **CAP API**: http://localhost:3030
- **OMEGA API**: http://localhost:3034
- **CCJ API**: http://localhost:3036
- **PostgreSQL**: localhost:5432
- **PgAdmin**: http://localhost:5050 (with `--profile admin`)
- **Grafana**: http://localhost:3000 (with `--profile monitoring`)
- **Prometheus**: http://localhost:9090 (with `--profile monitoring`)

## Database Management

### Using the Management Script

```bash
# Interactive menu
./scripts/db_manager.sh

# Direct commands
./scripts/db_manager.sh check      # Check connection
./scripts/db_manager.sh migrate    # Run migrations
./scripts/db_manager.sh backup     # Backup database
./scripts/db_manager.sh stats      # Show statistics
./scripts/db_manager.sh clean      # Clean old data
```

### Manual Database Operations

```bash
# Connect to database
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler

# Run SQL file
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler -f /path/to/file.sql

# Backup
docker-compose exec postgres pg_dump -U wolf_admin wolf_prowler > backup.sql

# Restore
cat backup.sql | docker-compose exec -T postgres psql -U wolf_admin -d wolf_prowler
```

## Environment Variables

### Database Configuration

```bash
# PostgreSQL
POSTGRES_DB=wolf_prowler
POSTGRES_USER=wolf_admin
POSTGRES_PASSWORD=wolf_secure_pass_2024

# Application
DATABASE_URL=postgresql://wolf_admin:wolf_secure_pass_2024@postgres:5432/wolf_prowler
```

### Node Configuration

Each node requires:

```bash
NODE_NAME=CAP                    # Node identifier
NODE_ID=cap-node-001             # Unique node ID
PORT=3031                        # P2P port
API_PORT=3030                    # API port
NETWORK_ID=wolf-testnet          # Network identifier
BOOTSTRAP_NODES=omega:3031,ccj:3031  # Peer discovery
DATABASE_URL=postgresql://...    # Database connection
```

## Network Isolation

### Security Features

1. **Dedicated Network**: All Wolf Prowler services run on isolated network
2. **No External Access**: Database not exposed to host by default
3. **Service Discovery**: Automatic DNS resolution between containers
4. **Health Checks**: PostgreSQL health checks before service startup

### Network Commands

```bash
# Create network manually (if needed)
docker network create \
  --driver bridge \
  --subnet 172.20.0.0/16 \
  --gateway 172.20.0.1 \
  --opt com.docker.network.bridge.name=wolf_br0 \
  wolf_prowler_network

# Remove network
docker network rm wolf_prowler_network

# Connect container to network
docker network connect wolf_prowler_network <container_name>

# Disconnect container
docker network disconnect wolf_prowler_network <container_name>
```

## Persistence Layer Usage

### In Rust Code

```rust
use wolf_prowler::persistence::{PersistenceManager, DbPeer, DbSecurityAlert};

// Initialize
let db_url = std::env::var("DATABASE_URL")?;
let persistence = PersistenceManager::new(&db_url).await?;

// Save peer
let peer = DbPeer::from_entity_info(&entity_info);
persistence.save_peer(&peer).await?;

// Get active peers
let peers = persistence.get_active_peers().await?;

// Save security alert
let alert = DbSecurityAlert { /* ... */ };
persistence.save_security_alert(&alert).await?;

// Get recent alerts
let alerts = persistence.get_recent_alerts(100).await?;
```

## Data Retention

### Automatic Cleanup

The system automatically cleans old data:

- **Peer Metrics**: 30 days
- **Security Events** (resolved): 90 days
- **System Logs**: 7 days
- **Audit Logs**: Indefinite (manual cleanup required)

### Manual Cleanup

```bash
# Clean old data
./scripts/db_manager.sh clean

# Or via SQL
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler -c "
  DELETE FROM peer_metrics WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '30 days';
  VACUUM ANALYZE;
"
```

## Monitoring

### Database Metrics

```sql
-- Table sizes
SELECT 
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Row counts
SELECT 'peers' as table, COUNT(*) FROM peers
UNION ALL SELECT 'security_events', COUNT(*) FROM security_events
UNION ALL SELECT 'security_alerts', COUNT(*) FROM security_alerts;

-- Active connections
SELECT COUNT(*) FROM pg_stat_activity WHERE datname = 'wolf_prowler';
```

### Health Checks

```bash
# Database health
docker-compose exec postgres pg_isready -U wolf_admin

# Application health
curl http://localhost:3030/api/v1/status
curl http://localhost:3034/api/v1/status
curl http://localhost:3036/api/v1/status
```

## Backup & Recovery

### Automated Backups

```bash
# Create backup
./scripts/db_manager.sh backup

# Backups are stored in: backups/wolf_prowler_backup_YYYYMMDD_HHMMSS.sql.gz
```

### Recovery

```bash
# Restore from backup
./scripts/db_manager.sh restore backups/wolf_prowler_backup_20241220_120000.sql.gz

# Or manually
gunzip -c backup.sql.gz | docker-compose exec -T postgres psql -U wolf_admin -d wolf_prowler
```

## Troubleshooting

### Database Connection Issues

```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# View logs
docker-compose logs postgres

# Restart database
docker-compose restart postgres
```

### Network Issues

```bash
# Check network exists
docker network ls | grep wolf_prowler

# Inspect network
docker network inspect wolf_prowler_network

# Test connectivity
docker-compose exec cap ping postgres
docker-compose exec cap nc -zv postgres 5432
```

### Migration Issues

```bash
# Check migration status
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler -c "\dt"

# Re-run migrations
./scripts/db_manager.sh migrate
```

## Production Considerations

### Security

1. **Change Default Passwords**: Update `POSTGRES_PASSWORD` in production
2. **Use Secrets**: Store credentials in Docker secrets or vault
3. **Enable SSL**: Configure PostgreSQL SSL for encrypted connections
4. **Restrict Access**: Use firewall rules to limit database access

### Performance

1. **Connection Pooling**: Configured for 20 max connections per node
2. **Indexes**: All critical queries have indexes
3. **Partitioning**: Consider partitioning large tables (system_logs, peer_metrics)
4. **Vacuum**: Automatic vacuum configured

### High Availability

1. **Replication**: Set up PostgreSQL streaming replication
2. **Backup Strategy**: Automated daily backups with retention policy
3. **Monitoring**: Use Prometheus + Grafana for metrics
4. **Alerting**: Configure alerts for database issues

## References

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Docker Networking](https://docs.docker.com/network/)
- [SQLx Documentation](https://github.com/launchbadge/sqlx)
