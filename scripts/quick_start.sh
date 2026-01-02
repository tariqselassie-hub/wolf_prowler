#!/bin/bash
# Quick start script with default Docker networking

set -e

echo "🐺 Wolf Prowler - Quick Start"
echo "=============================="
echo ""

# Clean up any existing containers
echo "🧹 Cleaning up..."
docker-compose down -v 2>/dev/null || true
docker network prune -f >/dev/null 2>&1 || true

echo ""

# Start PostgreSQL
echo "📦 Starting PostgreSQL..."
docker-compose up -d postgres

# Wait for PostgreSQL
echo "⏳ Waiting for PostgreSQL to be ready..."
timeout 30 bash -c 'until docker-compose exec -T postgres pg_isready -U wolf_admin > /dev/null 2>&1; do sleep 1; done'

if [ $? -eq 0 ]; then
    echo "✓ PostgreSQL is ready"
else
    echo "❌ PostgreSQL failed to start"
    docker-compose logs postgres
    exit 1
fi

echo ""

# Run database setup
echo "🔄 Setting up database..."
./scripts/db_manager.sh setup

echo ""

# Start wolf_server nodes
echo "🚀 Starting wolf_server nodes..."
docker-compose up -d cap omega ccj

echo ""

# Wait a moment for startup
sleep 5

# Check status
echo "📊 Service Status:"
docker-compose ps

echo ""
echo "✅ Wolf Prowler is running!"
echo ""
echo "📡 API Endpoints:"
echo "  CAP:   http://localhost:3030"
echo "  OMEGA: http://localhost:3033"
echo "  CCJ:   http://localhost:3035"
echo ""
echo "🔍 Database:"
echo "  PostgreSQL: localhost:5432"
echo "  Database:   wolf_prowler"
echo "  User:       wolf_admin"
echo ""
echo "📝 View logs:"
echo "  docker-compose logs -f cap"
echo ""
echo "🛑 Stop services:"
echo "  docker-compose down"
