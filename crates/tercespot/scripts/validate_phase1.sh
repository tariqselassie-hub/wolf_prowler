#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== Validating Phase 1: Key Ceremony Tool ===${NC}"

# Setup temp environment
WORK_DIR=$(mktemp -d)
USB1="${WORK_DIR}/usb1"
USB2="${WORK_DIR}/usb2"
mkdir -p "$USB1"
mkdir -p "$USB2"

CONFIG_FILE="${WORK_DIR}/test_ceremony.json"

# Create test config
cat > "$CONFIG_FILE" <<EOF
{
    "n": 2,
    "roles": ["DevOps", "ComplianceManager"],
    "usb_paths": ["$USB1", "$USB2"]
}
EOF

echo "Created test config at $CONFIG_FILE"

# Build the ceremony tool
echo "Building ceremony tool..."
cargo build -p ceremony --quiet

# Run the ceremony tool in test mode
echo "Running ceremony tool..."
# We assume the binary is in target/debug/ceremony
# Adjust path if needed or use cargo run
cargo run -p ceremony --quiet -- --test-config "$CONFIG_FILE"

# Verify Results

# 1. Check authorized_keys.json
if [ -f "authorized_keys.json" ]; then
    echo -e "${GREEN}✓ authorized_keys.json created${NC}"
    # Basic content check
    if grep -q "ceremony_" "authorized_keys.json" && grep -q "DevOps" "authorized_keys.json"; then
         echo -e "${GREEN}✓ authorized_keys.json content looks valid${NC}"
    else
         echo -e "${RED}✗ authorized_keys.json content invalid${NC}"
         exit 1
    fi
else
    echo -e "${RED}✗ authorized_keys.json NOT found${NC}"
    exit 1
fi

# 2. Check Private Keys
if [ -f "${USB1}/officer_key" ]; then
    echo -e "${GREEN}✓ Officer 1 key found at ${USB1}/officer_key${NC}"
else
    echo -e "${RED}✗ Officer 1 key missing${NC}"
    exit 1
fi

if [ -f "${USB2}/officer_key" ]; then
    echo -e "${GREEN}✓ Officer 2 key found at ${USB2}/officer_key${NC}"
else
    echo -e "${RED}✗ Officer 2 key missing${NC}"
    exit 1
fi

# Cleanup
rm -rf "$WORK_DIR"
rm "authorized_keys.json"

echo -e "${GREEN}=== Phase 1 Validation Successful ===${NC}"
