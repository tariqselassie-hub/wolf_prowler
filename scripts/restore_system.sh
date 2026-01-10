#!/bin/bash
# Wolf Prowler System Restore Script
# Restores system from a specified backup archive.

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_backup_tar_gz>"
    exit 1
fi

BACKUP_FILE="$1"
RESTORE_TEMP="./restore_temp"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file $BACKUP_FILE not found."
    exit 1
fi

echo "Starting system restore from $BACKUP_FILE..."

# Create temp dir
mkdir -p "$RESTORE_TEMP"

# Extract archive
echo "Extracting archive..."
tar -xzf "$BACKUP_FILE" -C "$RESTORE_TEMP"

# Find the backup directory name (it varies by timestamp)
BACKUP_DIR=$(find "$RESTORE_TEMP" -maxdepth 1 -type d -name "backup_*" | head -n 1)

if [ -z "$BACKUP_DIR" ]; then
    echo "Error: Invalid backup structure."
    rm -rf "$RESTORE_TEMP"
    exit 1
fi

echo "Restoring from $BACKUP_DIR..."

# Restore Data
if [ -d "$BACKUP_DIR/wolf_data" ]; then
    echo "Restoring wolf_data..."
    rm -rf ./wolf_data
    cp -r "$BACKUP_DIR/wolf_data" ./
fi

# Restore Config
if [ -f "$BACKUP_DIR/settings.toml" ]; then
    echo "Restoring settings.toml..."
    cp "$BACKUP_DIR/settings.toml" ./
fi

# Restore Postbox
if [ -d "$BACKUP_DIR/postbox" ]; then
    echo "Restoring postbox..."
    rm -rf ./postbox
    cp -r "$BACKUP_DIR/postbox" ./
fi

# Cleanup
rm -rf "$RESTORE_TEMP"

echo "✅ System restored successfully."
