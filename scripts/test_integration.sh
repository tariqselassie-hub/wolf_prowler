#!/bin/bash
# Test wolf_server database integration

set -e

echo "🐺 Wolf Server - Database Integration Test"
echo "=========================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "✓ Docker is running"
echo ""

# Start PostgreSQL
echo "📦 Starting PostgreSQL..."
docker-compose up -d postgres

# Wait for PostgreSQL
echo "⏳ Waiting for PostgreSQL..."
timeout 30 bash -c 'until docker-compose exec -T postgres pg_isready -U wolf_admin > /dev/null 2>&1; do sleep 1; done'

if [ $? -eq 0 ]; then
    echo "✓ PostgreSQL is ready"
else
    echo "❌ PostgreSQL failed to start"
    exit 1
fi

echo ""

# Run migrations
echo "🔄 Running migrations..."
./scripts/db_manager.sh migrate > /dev/null 2>&1
echo "✓ Migrations complete"
echo ""

# Build wolf_server with persistence
echo "🔨 Building wolf_server with persistence..."
docker-compose build cap > /dev/null 2>&1
echo "✓ Build complete"
echo ""

# Start CAP node
echo "🚀 Starting CAP node..."
docker-compose up -d cap

# Wait for startup
echo "⏳ Waiting for wolf_server to start..."
sleep 5

# Check if it's running
if docker-compose ps cap | grep -q "Up"; then
    echo "✓ CAP node is running"
else
    echo "❌ CAP node failed to start"
    docker-compose logs cap
    exit 1
fi

echo ""

# Test API endpoints
echo "🧪 Testing API endpoints..."
echo ""

# Test status endpoint
echo "1. Testing /status endpoint..."
STATUS=$(curl -s http://localhost:3030/status)
if echo "$STATUS" | grep -q "peer_id"; then
    echo "   ✓ Status endpoint working"
else
    echo "   ❌ Status endpoint failed"
fi

# Test database health endpoint
echo "2. Testing /database/health endpoint..."
HEALTH=$(curl -s http://localhost:3030/database/health)
if echo "$HEALTH" | grep -q "status"; then
    echo "   ✓ Database health endpoint working"
    echo "   Response: $HEALTH"
else
    echo "   ❌ Database health endpoint failed"
fi

# Test database stats endpoint
echo "3. Testing /database/stats endpoint..."
STATS=$(curl -s http://localhost:3030/database/stats)
if echo "$STATS" | grep -q "active_peers"; then
    echo "   ✓ Database stats endpoint working"
    echo "   Response: $STATS"
else
    echo "   ❌ Database stats endpoint failed"
fi

echo ""

# Check logs for metrics collection
echo "📊 Checking for metrics collection..."
sleep 65  # Wait for first metrics collection

if docker-compose logs cap | grep -q "Starting periodic metrics collection"; then
    echo "✓ Metrics collection started"
else
    echo "⚠ Metrics collection not detected in logs"
fi

echo ""

# Verify data in database
echo "🔍 Verifying data in database..."
PEER_COUNT=$(docker-compose exec -T postgres psql -U wolf_admin -d wolf_prowler -t -c "SELECT COUNT(*) FROM peers;" | tr -d ' ')
LOG_COUNT=$(docker-compose exec -T postgres psql -U wolf_admin -d wolf_prowler -t -c "SELECT COUNT(*) FROM system_logs;" | tr -d ' ')

echo "   Peers in database: $PEER_COUNT"
echo "   System logs in database: $LOG_COUNT"

if [ "$LOG_COUNT" -gt 0 ]; then
    echo "✓ Data is being persisted"
else
    echo "⚠ No data found in database yet"
fi

echo ""
echo "✅ Integration test complete!"
echo ""
echo "📝 View logs:"
echo "   docker-compose logs -f cap"
echo ""
echo "🔍 Query database:"
echo "   docker-compose exec postgres psql -U wolf_admin -d wolf_prowler"
echo ""
echo "🛑 Stop services:"
echo "   docker-compose down"
