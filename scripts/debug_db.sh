#!/bin/bash
# scripts/debug_db.sh

echo "🔍 Debugging Database Connection..."

# 1. Check if .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found in $(pwd)"
    exit 1
fi

# 2. Load .env
export $(grep -v '^#' .env | xargs)
echo "📋 Loaded DATABASE_URL from .env"

# 3. Parse Host and Port from DATABASE_URL
# Assuming format postgres://user:pass@host:port/db
HOST_PORT=$(echo $DATABASE_URL | sed -e 's/.*@//' -e 's/\/.*//')
DB_HOST=$(echo $HOST_PORT | cut -d: -f1)
DB_PORT=$(echo $HOST_PORT | cut -d: -f2)

# Default port if not specified
if [ "$DB_HOST" == "$HOST_PORT" ]; then
    DB_PORT="5432"
fi

echo "🎯 Target: $DB_HOST:$DB_PORT"

# 4. Check Docker Container
echo "🐳 Checking Docker container..."
# Find container mapping to this port
CONTAINER_ID=$(docker ps -q | xargs docker inspect --format '{{.Id}} {{.NetworkSettings.Ports}}' | grep "$DB_PORT" | awk '{print $1}')

if [ -z "$CONTAINER_ID" ]; then
    echo "❌ No Docker container found listening on port $DB_PORT"
    echo "   Running containers:"
    docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"
else
    NAME=$(docker ps -f id=$CONTAINER_ID --format "{{.Names}}")
    echo "✅ Found container: $NAME ($CONTAINER_ID)"
    
    # 5. Check Container Logs
    echo "📜 Recent logs for $NAME:"
    docker logs --tail 10 $CONTAINER_ID
fi

# 6. Test TCP Connection
echo "🔌 Testing TCP connection..."
if command -v nc >/dev/null; then
    if nc -z -v -w 2 $DB_HOST $DB_PORT 2>/dev/null; then
        echo "✅ TCP Connection successful to $DB_HOST:$DB_PORT"
    else
        echo "❌ TCP Connection FAILED to $DB_HOST:$DB_PORT"
        echo "   - Check if the container is running"
        echo "   - Check if ports are mapped correctly (e.g., -p 5432:5432)"
        echo "   - Try using 127.0.0.1 instead of localhost"
    fi
else
    echo "⚠️ 'nc' (netcat) not installed, skipping TCP check."
fi

# 7. Test SQLx Connection
echo "🛠 Testing sqlx connection..."
if command -v sqlx >/dev/null; then
    # Try to create the database (idempotent) to test auth
    if sqlx database create; then
        echo "✅ SQLx connection successful"
    else
        echo "❌ SQLx connection failed"
    fi
else
    echo "⚠️ sqlx-cli not installed."
fi