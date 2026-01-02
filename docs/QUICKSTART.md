# Wolf Prowler - Quick Start Guide

## Database Setup (One-Time)

PostgreSQL is already running with host networking:

```bash
# Verify it's running
docker ps | grep wolf_postgres

# If not running, start it
docker run -d \
  --name wolf_postgres \
  --network host \
  -e POSTGRES_DB=wolf_prowler \
  -e POSTGRES_USER=wolf_admin \
  -e POSTGRES_PASSWORD=wolf_secure_pass_2024 \
  -v wolf_postgres_data:/var/lib/postgresql/data \
  postgres:16-alpine
```

Database is already set up with all tables!

## Running Wolf Prowler

### Set Environment Variable

```bash
export DATABASE_URL="postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler"
```

### Build and Run

```bash
# Build (database persistence enabled by default!)
cargo build --release

# Run
cargo run --release
```

That's it! No feature flags needed.

## What Happens Automatically

✅ **Connects to database** on startup  
✅ **Saves all peer data** every 60 seconds  
✅ **Saves all security events** in real-time  
✅ **Saves all malicious IPs** when detected  
✅ **Saves all CVEs** when detected  
✅ **Saves all intrusion attempts** when detected  
✅ **Syncs threat feeds** every hour  

## API Endpoints

Once running, you can access:

### Basic
- `http://localhost:3030/status` - Server status
- `http://localhost:3030/peers` - Connected peers
- `http://localhost:3030/metrics` - Network metrics

### Database
- `http://localhost:3030/database/health` - Database health
- `http://localhost:3030/database/stats` - Database statistics

### Threat Intelligence
- `http://localhost:3030/api/v1/threats/ips` - Malicious IPs
- `http://localhost:3030/api/v1/threats/cves` - Vulnerabilities
- `http://localhost:3030/api/v1/threats/stats` - Threat statistics
- `http://localhost:3030/api/v1/threats/active` - Active threats

### Historical Data
- `http://localhost:3030/api/v1/peers/history` - Peer history
- `http://localhost:3030/api/v1/alerts/history` - Alert history
- `http://localhost:3030/api/v1/metrics/timeline` - Metrics timeline

### Data Export
- `http://localhost:3030/api/v1/export/peers/csv` - Export peers as CSV
- `http://localhost:3030/api/v1/export/alerts/csv` - Export alerts as CSV
- `http://localhost:3030/api/v1/export/metrics/csv` - Export metrics as CSV

## Verify Everything Works

```bash
# 1. Check database health
curl http://localhost:3030/database/health | jq .

# 2. Get threat statistics
curl http://localhost:3030/api/v1/threats/stats | jq .

# 3. View database tables
docker exec wolf_postgres psql -U wolf_admin -d wolf_prowler -c "\dt"
```

## Troubleshooting

### Build Errors

If you see `sqlx` errors, make sure you're building from the project root:

```bash
cd /home/t4riq/Desktop/Rust/wolf_prowler
cargo build --release
```

### Database Connection Failed

```bash
# Check if PostgreSQL is running
docker ps | grep wolf_postgres

# Check logs
docker logs wolf_postgres

# Restart if needed
docker restart wolf_postgres
```

### Server Won't Start

```bash
# Make sure DATABASE_URL is set
echo $DATABASE_URL

# Should output:
# postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler
```

## Stop Services

```bash
# Stop wolf_server (Ctrl+C)

# Stop database
docker stop wolf_postgres

# Remove database (WARNING: deletes all data)
docker stop wolf_postgres
docker rm wolf_postgres
docker volume rm wolf_postgres_data
```

---

**Ready to go!** Just `cargo run --release` and everything works automatically.
