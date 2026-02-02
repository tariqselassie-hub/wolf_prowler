#!/bin/bash
set -e

# Cleanup Phase 1 Script
# usage: ./scripts/cleanup_phase1.sh

echo "🐺 Starting Wolf Prowler Phase 1 Cleanup..."

# 1. Fix the Critical Nesting Error (wolf_web/src/static -> wolf_web/static)
if [ -d "wolf_web/src/static" ]; then
    echo " -> Detect 'wolf_web/src/static'. Moving to 'wolf_web/static'..."
    mkdir -p wolf_web/static
    # Copy contents, overwriting destination if exists
    cp -r wolf_web/src/static/* wolf_web/static/
    # Remove the incorrect folder
    rm -rf wolf_web/src/static
    echo " ✅ Fixed: static assets moved out of src/."
else
    echo " -> 'wolf_web/src/static' not found. Skipping fix."
fi

# 2. Archive 'legacy_static'
if [ -d "legacy_static" ]; then
    echo " -> Moving 'legacy_static' to backup..."
    mkdir -p legacy/static_backup
    mv legacy_static legacy/static_backup/
    echo " ✅ Moved legacy_static."
fi

# 3. Archive 'static2'
if [ -d "static2" ]; then
    echo " -> Moving 'static2' to backup..."
    mkdir -p legacy/static_backup
    mv static2 legacy/static_backup/
    echo " ✅ Moved static2."
fi

# 4. Archive 'logs' folder
if [ -d "logs" ]; then
    echo " -> Moving 'logs' folder to archive..."
    mkdir -p legacy/archive_2025
    mv logs legacy/archive_2025/
    echo " ✅ Moved logs."
fi

# 5. Move root scripts
if [ -f "docker-manager.sh" ]; then
    echo " -> Moving 'docker-manager.sh' to scripts/..."
    mv docker-manager.sh scripts/
    echo " ✅ Moved docker-manager.sh."
fi

if [ -f "consolidate_dashboard.sh" ]; then
     echo " -> Moving 'consolidate_dashboard.sh' to scripts/..."
     mv consolidate_dashboard.sh scripts/
     echo " ✅ Moved consolidate_dashboard.sh."
fi

# 6. Cleanup root log files
echo " -> Cleaning up root log files..."
mkdir -p legacy/archive_2025
mv *.log legacy/archive_2025/ 2>/dev/null || true
mv *.txt legacy/archive_2025/ 2>/dev/null || true
# Move back module-level TODOs if they were caught by *.txt (usually they are .md so safe)

echo "🐺 Cleanup Complete! Directory structure should now be correct."
ls -F
