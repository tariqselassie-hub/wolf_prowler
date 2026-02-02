#!/bin/bash
# scripts/run_migrations.sh

# Ensure we are in the project root (one level up from scripts/)
cd "$(dirname "$0")/.."

# Check if .env exists
if [ ! -f .env ]; then
    echo "Error: .env file not found in project root."
    echo "Please create one. Example:"
    echo "DATABASE_URL=postgres://postgres:password@localhost:5432/wolf_prowler"
    exit 1
else
    # Export variables from .env
    export $(grep -v '^#' .env | xargs)
fi

# Install sqlx-cli if missing
if ! command -v sqlx &> /dev/null; then
    echo "Installing sqlx-cli..."
    cargo install sqlx-cli --no-default-features --features postgres,rustls
fi

echo "Creating database..."
sqlx database create

echo "Running migrations..."
sqlx migrate run

echo "Database setup complete."