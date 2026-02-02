#!/bin/bash
# install.sh - Setup permissions and SUID removal

set -e

echo "Setting up TercesPot environment..."

# Create directory for postbox if it doesn't exist
mkdir -p /tmp/postbox
chmod 777 /tmp/postbox # World writable for submission, but be careful in production

echo "Environment setup complete."
