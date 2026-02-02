#!/bin/bash

# Lock Prowler Dashboard Startup Script
# This script helps start the Lock Prowler system with proper configuration

set -e

echo "🚀 Lock Prowler V4.0 Startup Script"
echo "=================================="

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Please run this script from the Lock Prowler project root directory"
    exit 1
fi

# Set environment variables
export WOLF_DB_PATH="./wolf_data"
export RUST_LOG="info"

# Create database directory if it doesn't exist
if [ ! -d "$WOLF_DB_PATH" ]; then
    echo "📁 Creating database directory: $WOLF_DB_PATH"
    mkdir -p "$WOLF_DB_PATH"
fi

# Function to check if a port is available
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 1
    else
        return 0
    fi
}

# Check if dashboard port is available
DASHBOARD_PORT=7620
if ! check_port $DASHBOARD_PORT; then
    echo "⚠️  Warning: Port $DASHBOARD_PORT is already in use"
    echo "   You may need to stop another instance of the dashboard"
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Startup cancelled"
        exit 1
    fi
fi

# Build the project
echo "🔨 Building Lock Prowler Dashboard..."
cargo build --release --bin lock_prowler_dashboard 2>&1 | tee build.log

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Check build.log for details."
    exit 1
fi

echo "✅ Build successful"

# Start the dashboard
echo "🌐 Starting Lock Prowler Dashboard..."
echo "   Dashboard will be available at: http://127.0.0.1:$DASHBOARD_PORT"
echo "   Database path: $WOLF_DB_PATH"
echo ""
echo "📋 Dashboard Features:"
echo "   • Database initialization/unlocking"
echo "   • Secret vault management"
echo "   • Threat detection and scanning"
echo "   • Shard management and recovery"
echo "   • WolfPack network integration"
echo "   • Headless mode control"
echo ""
echo "💡 Tips:"
echo "   • Use Ctrl+C to stop the dashboard"
echo "   • Database will be initialized on first use"
echo "   • Check the Activity Log for system events"
echo ""

# Start the dashboard
cd lock_prowler_dashboard
cargo run --release

echo "✅ Dashboard stopped"