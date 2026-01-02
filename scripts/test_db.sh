#!/bin/bash
# Quick test script for database persistence layer

set -e

echo "🐺 Wolf Prowler - Database Persistence Test"
echo "==========================================="
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

# Wait for PostgreSQL to be healthy
echo "⏳ Waiting for PostgreSQL to be ready..."
timeout 30 bash -c 'until docker-compose exec -T postgres pg_isready -U wolf_admin > /dev/null 2>&1; do sleep 1; done'

if [ $? -eq 0 ]; then
    echo "✓ PostgreSQL is ready"
else
    echo "❌ PostgreSQL failed to start"
    exit 1
fi

echo ""

# Run migrations
echo "🔄 Running database migrations..."
./scripts/db_manager.sh migrate

echo ""

# Show database stats
echo "📊 Database Statistics:"
./scripts/db_manager.sh stats

echo ""
echo "✅ Database persistence layer is ready!"
echo ""
echo "Next steps:"
echo "  1. Start wolf_server nodes: docker-compose up -d"
echo "  2. View logs: docker-compose logs -f cap"
echo "  3. Access PgAdmin: docker-compose --profile admin up -d"
echo "  4. Monitor: docker-compose --profile monitoring up -d"
