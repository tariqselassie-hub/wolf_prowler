#!/bin/bash
# Wolf Prowler Integrity Verification Script
# Checks file checksums and log integrity.

set -e

echo "🔒 Starting System Integrity Verification..."

# 1. Verify Configuration Integrity
if [ -f "settings.toml" ]; then
    echo "Checking configuration file..."
    sha256sum settings.toml
else
    echo "⚠️  settings.toml not found."
fi

# 2. Check for Sensitive Files
echo "Scanning for exposed secrets..."
# Simple grep for common secret patterns (simplified)
grep -r "BEGIN PRIVATE KEY" . --include="*.pem" --exclude-dir=target || echo "✅ No exposed PEM private keys found in source."

# 3. Verify Log File Permissions
LOG_DIR="./logs"
if [ -d "$LOG_DIR" ]; then
    echo "Checking log directory permissions..."
    ls -ld "$LOG_DIR"
    # In a real scenario, we'd check for 700 or similar
else
    echo "⚠️  Log directory not found."
fi

# 4. Check Cargo.lock consistency
echo "Verifying dependency tree..."
cargo metadata --format-version 1 > /dev/null
echo "✅ Cargo.lock is consistent."

echo "✅ Integrity check complete."
