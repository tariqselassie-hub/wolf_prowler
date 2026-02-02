#!/bin/bash
set -e

echo "🐺 Starting Phase 2 Cleanup (Final Polish)..."

# 1. Consolidate CSS
echo " -> Processing CSS..."
mkdir -p wolf_web/static/css
if [ -d "css" ]; then
    # Copy root css files to wolf_web/static/css
    cp -r css/* wolf_web/static/css/ 2>/dev/null || true
    # Remove root css folder
    rm -rf css
    echo " ✅ Moved root 'css/' to 'wolf_web/static/css/'"
fi

# 2. Fix Recursive Static Folder (wolf_web/static/static)
if [ -d "wolf_web/static/static" ]; then
    echo " -> Detect recursive 'wolf_web/static/static'..."
    # Move its contents up to wolf_web/static/
    cp -r wolf_web/static/static/* wolf_web/static/ 2>/dev/null || true
    rm -rf wolf_web/static/static
    echo " ✅ Un-nested 'wolf_web/static/static'"
fi

# 3. Handle 'assets' (Move to wolf_web/static/img if appropriate, or archive)
# User has 'assets' in root.
if [ -d "assets" ]; then
     echo " -> Checking 'assets'..."
     # If wolf_web/static/img doesn't exist, make it
     mkdir -p wolf_web/static/img
     # Move assets content
     cp -r assets/* wolf_web/static/img/ 2>/dev/null || true
     rm -rf assets
     echo " ✅ Merged 'assets/' into 'wolf_web/static/img/'"
fi

# 4. Remove empty directories if any
rmdir wolf_web/src/static 2>/dev/null || true

echo "🐺 Phase 2 Complete. Directory Structure polished."
ls -F wolf_web/static/
