#!/bin/bash
# check_dashboard_config.sh

echo "=== Wolf Prowler Static Asset Diagnostic ==="

# 1. Check Rust Configuration
echo -e "\n1. Checking Axum Router Configuration (src/):"
GREP_RESULT=$(grep -r "ServeDir::new" src/)
if [ -n "$GREP_RESULT" ]; then
    echo "Found ServeDir configuration:"
    echo "$GREP_RESULT" | sed 's/^/   /'
    
    # Extract the path
    DETECTED_PATH=$(echo "$GREP_RESULT" | grep -o 'ServeDir::new("[^"]*")' | cut -d'"' -f2 | head -n 1)
    echo -e "\n-> SYSTEM IS CURRENTLY SERVING FROM: '$DETECTED_PATH'"
else
    echo "❌ No ServeDir configuration found in src/. Static serving might not be configured."
fi

# 2. Check Folder Contents
echo -e "\n2. Checking Asset Folders:"

check_folder() {
    if [ -d "$1" ]; then
        COUNT=$(find "$1" -maxdepth 1 -type f | wc -l)
        echo "   📂 $1: Found $COUNT files"
        # Show a few examples
        ls "$1" | head -n 3 | sed 's/^/      - /'
        if [ $(ls "$1" | wc -l) -gt 3 ]; then echo "      ... and more"; fi
    else
        echo "   ❌ $1: Does not exist"
    fi
}

check_folder "static"
check_folder "src/dashboard"
check_folder "wolf_web/static"
check_folder "public"

echo -e "\n=== End Diagnostic ==="