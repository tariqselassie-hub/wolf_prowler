# Wolf Prowler Database - Quick Reference

## 🚀 Quick Start

```bash
# Start everything
docker-compose up -d

# Initialize database
./scripts/db_manager.sh setup

# Verify
./scripts/db_manager.sh stats
```

## 🔗 Connection String

```bash
DATABASE_URL=postgresql://wolf_admin:wolf_secure_pass_2024@postgres:5432/wolf_prowler
```

## 🌐 Network

- **Name**: `wolf_prowler_network`
- **Subnet**: `172.20.0.0/16`
- **Gateway**: `172.20.0.1`

## 📊 Services

| Service | Internal Port | External Port | Purpose |
|---------|---------------|---------------|---------|
| postgres | 5432 | 5432 | Database |
| cap | 3031/3030 | 3031/3030 | Alpha Node |
| omega | 3031/3030 | 3033/3034 | Beta Node |
| ccj | 3031/3030 | 3035/3036 | Delta Node |
| pgadmin | 80 | 5050 | DB Admin (optional) |
| grafana | 3000 | 3000 | Monitoring (optional) |

## 💾 Database Tables

### Core
- `peers` - Peer information
- `peer_metrics` - Time-series metrics
- `peer_connections` - Connection history

### Security
- `security_events` - Security incidents
- `security_alerts` - Active alerts
- `threat_intelligence` - Threat data

### Audit
- `audit_logs` - System audit trail
- `compliance_checks` - Compliance status

### Configuration
- `config` - System configuration
- `security_policies` - Security policies

### Wolf Pack
- `pack_members` - Pack hierarchy
- `pack_hierarchy` - Leadership structure

### Logs
- `system_logs` - Application logs
- `network_metrics` - Network statistics

## 🛠️ Management Commands

```bash
./scripts/db_manager.sh check      # Check connection
./scripts/db_manager.sh migrate    # Run migrations
./scripts/db_manager.sh backup     # Backup database
./scripts/db_manager.sh restore    # Restore database
./scripts/db_manager.sh stats      # Show statistics
./scripts/db_manager.sh clean      # Clean old data
./scripts/db_manager.sh            # Interactive menu
```

## 🔍 Docker Commands

```bash
# Start services
docker-compose up -d

# With admin UI
docker-compose --profile admin up -d

# With monitoring
docker-compose --profile monitoring up -d

# View logs
docker-compose logs -f postgres
docker-compose logs -f cap

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Restart service
docker-compose restart postgres
```

## 🔌 Database Access

```bash
# Connect via psql
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler

# Run SQL file
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler -f /path/to/file.sql

# Backup
docker-compose exec postgres pg_dump -U wolf_admin wolf_prowler > backup.sql

# Restore
cat backup.sql | docker-compose exec -T postgres psql -U wolf_admin -d wolf_prowler
```

## 📈 Common Queries

```sql
-- Active peers
SELECT * FROM active_peers_with_metrics;

-- Recent alerts
SELECT * FROM recent_security_alerts;

-- Pack overview
SELECT * FROM pack_overview;

-- Table sizes
SELECT tablename, pg_size_pretty(pg_total_relation_size('public.'||tablename))
FROM pg_tables WHERE schemaname = 'public';

-- Row counts
SELECT 'peers' as table, COUNT(*) FROM peers
UNION ALL SELECT 'security_alerts', COUNT(*) FROM security_alerts;
```

## 🔒 Security

### Production Checklist
- [ ] Change PostgreSQL password
- [ ] Use Docker secrets
- [ ] Enable SSL
- [ ] Configure firewall
- [ ] Set up automated backups

### Default Credentials
- **PostgreSQL**: `wolf_admin` / `wolf_secure_pass_2024`
- **PgAdmin**: `admin@wolfprowler.local` / `admin123`
- **Grafana**: `admin` / `wolfprowler123`

⚠️ **Change these in production!**

## 🧪 Testing

```bash
# Test connectivity
docker-compose exec cap ping postgres
docker-compose exec cap nc -zv postgres 5432

# Test database
docker-compose exec postgres pg_isready -U wolf_admin

# Test API
curl http://localhost:3030/api/v1/status
```

## 📝 Data Retention

- **Peer metrics**: 30 days
- **Resolved security events**: 90 days
- **System logs**: 7 days
- **Audit logs**: Indefinite

## 🔧 Troubleshooting

### Database won't start
```bash
docker-compose logs postgres
docker-compose restart postgres
```

### Can't connect
```bash
docker network inspect wolf_prowler_network
docker-compose exec cap ping postgres
```

### Migration failed
```bash
./scripts/db_manager.sh migrate
docker-compose exec postgres psql -U wolf_admin -d wolf_prowler -c "\dt"
```

## 📚 Documentation

- **Setup Guide**: `docs/DATABASE_SETUP.md`
- **Implementation Plan**: See artifacts
- **Schema**: `migrations/001_initial_schema.sql`
- **README**: `DATABASE_README.md`

## 🎯 Next Steps

1. Update `wolf_server` to use persistence
2. Integrate with `wolfsec` for alerts
3. Add periodic metrics collection
4. Implement API endpoints for queries
5. Set up automated backups
6. Configure monitoring dashboards

---

**Status**: ✅ Ready to use  
**Version**: 1.0.0  
**Database**: PostgreSQL 16  
**Network**: wolf_prowler_network
