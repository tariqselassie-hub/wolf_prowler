#!/bin/bash
# Create complete backup before history rewrite

set -e

BACKUP_DIR="/home/t4riq/Desktop/wolf_prowler_backup_$(date +%Y%m%d_%H%M%S)"

echo "Creating backup at: $BACKUP_DIR"
cp -r /home/t4riq/Desktop/Rust/wolf_prowler "$BACKUP_DIR"

echo ""
echo "✅ Backup complete!"
echo "Location: $BACKUP_DIR"
echo ""
echo "If anything goes wrong, restore with:"
echo "  rm -rf /home/t4riq/Desktop/Rust/wolf_prowler"
echo "  cp -r $BACKUP_DIR /home/t4riq/Desktop/Rust/wolf_prowler"
