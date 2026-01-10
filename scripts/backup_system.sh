#!/bin/bash
# Wolf Prowler System Backup Script
# Archives critical data directories and configuration files.

set -e

BACKUP_ROOT="./backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="$BACKUP_ROOT/backup_$TIMESTAMP"
DATA_DIR="./wolf_data"
CONFIG_FILE="./settings.toml"
POSTBOX_DIR="./postbox"

echo "Starting system backup to $BACKUP_DIR..."

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup Database & Data
if [ -d "$DATA_DIR" ]; then
    echo "Backing up wolf_data..."
    cp -r "$DATA_DIR" "$BACKUP_DIR/"
else
    echo "Warning: $DATA_DIR not found, skipping."
fi

# Backup Configuration
if [ -f "$CONFIG_FILE" ]; then
    echo "Backing up settings.toml..."
    cp "$CONFIG_FILE" "$BACKUP_DIR/"
else
    echo "Warning: $CONFIG_FILE not found, skipping."
fi

# Backup TersecPot Postbox (if exists)
if [ -d "$POSTBOX_DIR" ]; then
    echo "Backing up postbox..."
    cp -r "$POSTBOX_DIR" "$BACKUP_DIR/"
else
    echo "Warning: $POSTBOX_DIR not found, skipping."
fi

# Create archive
TAR_FILE="$BACKUP_ROOT/wolf_prowler_backup_$TIMESTAMP.tar.gz"
echo "Creating archive $TAR_FILE..."
tar -czf "$TAR_FILE" -C "$BACKUP_ROOT" "backup_$TIMESTAMP"

# Cleanup temporary dir
rm -rf "$BACKUP_DIR"

echo "✅ Backup completed successfully: $TAR_FILE"
