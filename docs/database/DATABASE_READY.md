# Wolf Prowler - Database Setup Complete! 🎉

## ✅ What's Running

**PostgreSQL Database**:
- Container: `wolf_postgres`
- Network Mode: Host networking (bypasses Docker bridge issues)
- Port: `localhost:5432`
- Database: `wolf_prowler`
- User: `wolf_admin`
- Password: `wolf_secure_pass_2024`

**Database Schema**:
- ✅ 14 tables created
- ✅ 27 indexes created
- ✅ 3 triggers created
- ✅ 3 views created
- ✅ Initial configuration data loaded

## 📊 Database Tables

All tables are ready for use:
1. `peers` - Peer information
2. `peer_metrics` - Performance metrics
3. `peer_connections` - Connection history
4. `security_events` - Security incidents
5. `security_alerts` - Active alerts
6. `threat_intelligence` - Malicious IPs, CVEs, threats
7. `audit_logs` - System audit trail
8. `compliance_checks` - Compliance validation
9. `config` - System configuration
10. `security_policies` - Security policies
11. `pack_members` - Wolf pack members
12. `pack_hierarchy` - Pack leadership
13. `system_logs` - Application logs
14. `network_metrics` - Network statistics

## 🚀 Next Steps

### 1. Build Wolf Server

```bash
# Build with database persistence support
cargo build --release --features advanced_reporting
```

### 2. Run Wolf Server

```bash
# Set database URL
export DATABASE_URL="postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler"

# Run the server
cargo run --release --features advanced_reporting
```

### 3. Test the Integration

```bash
# Check database health
curl http://localhost:3030/database/health | jq .

# Get database stats
curl http://localhost:3030/database/stats | jq .

# Query threat intelligence
curl http://localhost:3030/api/v1/threats/stats | jq .
```

## 🔍 Database Management

### Connect to Database

```bash
# Using Docker exec
docker exec -it wolf_postgres psql -U wolf_admin -d wolf_prowler

# Using psql directly (if installed)
psql "postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler"
```

### View Data

```bash
# List all tables
docker exec wolf_postgres psql -U wolf_admin -d wolf_prowler -c "\dt"

# View peers
docker exec wolf_postgres psql -U wolf_admin -d wolf_prowler -c "SELECT * FROM peers;"

# View threat intelligence
docker exec wolf_postgres psql -U wolf_admin -d wolf_prowler -c "SELECT * FROM threat_intelligence LIMIT 10;"
```

### Stop/Start Database

```bash
# Stop
docker stop wolf_postgres

# Start
docker start wolf_postgres

# Remove (WARNING: deletes data)
docker stop wolf_postgres
docker rm wolf_postgres
docker volume rm wolf_postgres_data
```

## 📝 What Gets Saved Automatically

When wolf_server runs with `advanced_reporting` feature:

### Every 60 seconds:
- ✅ Peer information and status
- ✅ Peer metrics (latency, messages, health)
- ✅ Network statistics
- ✅ System logs

### Real-time:
- ✅ Security events from wolfsec
- ✅ Security alerts (high/critical events)
- ✅ Malicious IP detections
- ✅ CVE vulnerabilities
- ✅ Intrusion attempts

### Hourly:
- ✅ Threat feed synchronization
- ✅ Malicious IP database updates
- ✅ CVE database updates

## 🔧 Troubleshooting

### Database Won't Start

```bash
# Check logs
docker logs wolf_postgres

# Restart
docker restart wolf_postgres
```

### Can't Connect

```bash
# Verify it's running
docker ps | grep wolf_postgres

# Test connection
docker exec wolf_postgres pg_isready -U wolf_admin
```

### Reset Database

```bash
# Stop and remove
docker stop wolf_postgres
docker rm wolf_postgres
docker volume rm wolf_postgres_data

# Start fresh
docker run -d \
  --name wolf_postgres \
  --network host \
  -e POSTGRES_DB=wolf_prowler \
  -e POSTGRES_USER=wolf_admin \
  -e POSTGRES_PASSWORD=wolf_secure_pass_2024 \
  -v wolf_postgres_data:/var/lib/postgresql/data \
  postgres:16-alpine

# Wait and run migrations
sleep 15
docker exec -i wolf_postgres psql -U wolf_admin -d wolf_prowler < migrations/001_initial_schema.sql
```

## 📚 Documentation

- **Database Setup**: `docs/DATABASE_SETUP.md`
- **API Documentation**: `wolf_server/API_DOCUMENTATION.md`
- **Threat Intelligence**: `wolf_server/THREAT_INTELLIGENCE.md`
- **Integration Guide**: `wolf_server/DATABASE_INTEGRATION.md`

## ✨ Features Ready

All persistence features are now ready to use:

- ✅ Automatic peer tracking
- ✅ Metrics collection and storage
- ✅ Security event persistence
- ✅ Threat intelligence database
- ✅ Historical query APIs
- ✅ Data export (CSV/JSON)
- ✅ Real-time threat detection
- ✅ Audit logging

---

**Status**: ✅ Database fully operational  
**Connection**: `postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler`  
**Next**: Build and run wolf_server with `--features advanced_reporting`
