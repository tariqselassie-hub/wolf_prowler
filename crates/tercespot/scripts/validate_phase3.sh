#!/bin/bash
set -e

# ==============================================================================
# validate_phase3.sh
# ------------------------------------------------------------------------------
# Verifies Phase 3: Policy Enforcement (Time-Bound & Geo-Fenced).
# ==============================================================================

# 1. Setup Environment
export TERSEC_POSTBOX="/tmp/tersec_phase3_test"
export TERSEC_LOG="${TERSEC_POSTBOX}/access.log"
export TERSEC_PULSE_MODE="WEB"
export TERSEC_PULSE_ARG="${TERSEC_LOG}"
export RUST_BACKTRACE=1

# Clean previous run
rm -rf "${TERSEC_POSTBOX}"
mkdir -p "${TERSEC_POSTBOX}"
touch "${TERSEC_LOG}"

# 2. Build Binaries
echo "[1] Building binaries..."
cargo build -p submitter -p sentinel -q

SUBMITTER=./target/debug/submitter
SENTINEL=./target/debug/sentinel

# 3. Generate Keys (Simulate Key Ceremony)
echo "[2] Generating Keys..."
# We will use the submitter to auto-generate keys for a "DevOps" role
# In a real scenario, we'd use 'ceremony', but for this logic test, we just need valid keys.
# We need to manually craft authorized_keys.json to map the generated key to a Role.

# Run submitter to generate keys
$SUBMITTER keygen

# Extract Public Key from the generated file
PK_PATH="${TERSEC_POSTBOX}/authorized_keys/client_key"
if [ ! -f "$PK_PATH" ]; then
    echo "Error: Public key not found at $PK_PATH"
    exit 1
fi
PK_HEX=$(od -An -t x1 "${PK_PATH}" | tr -d ' \n')
echo "Public Key: ${PK_HEX:0:16}..."

# Create authorized_keys.json mapping this key to "DevOps"
cat <<EOF > "${TERSEC_POSTBOX}/authorized_keys.json"
{
  "ceremony_id": "phase3_test",
  "timestamp": 1234567890,
  "officers": [
    {
      "role": "DevOps",
      "public_key_hex": "${PK_HEX}"
    }
  ]
}
EOF

# 4. Create Policies
echo "[3] Defining Policies..."
# We define 4 policies based on "operation" metadata:
# 1. time_pass: Valid time window
# 2. time_fail: Invalid time window
# 3. geo_pass:  Valid region (US-East for Web Pulse)
# 4. geo_fail:  Invalid region (Local for Web Pulse)

cat <<EOF > "${TERSEC_POSTBOX}/policies.toml"
[[policies]]
name = "Time Pass"
roles = ["DevOps"]
operations = ["time_pass"]
resources = ["*"]
threshold = 1
conditions = [
    { TimeBound = { start_time = "00:00", end_time = "23:59", days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"] } }
]

[[policies]]
name = "Time Fail"
roles = ["DevOps"]
operations = ["time_fail"]
resources = ["*"]
threshold = 1
conditions = [
    { TimeBound = { start_time = "00:00", end_time = "00:01", days = [] } }
]

[[policies]]
name = "Geo Pass"
roles = ["DevOps"]
operations = ["geo_pass"]
resources = ["*"]
threshold = 1
conditions = [
    { GeoBound = { allowed_regions = ["US-East"] } }
]

[[policies]]
name = "Geo Fail"
roles = ["DevOps"]
operations = ["geo_fail"]
resources = ["*"]
threshold = 1
conditions = [
    { GeoBound = { allowed_regions = ["Local"] } }
]

[role_mappings]
EOF

# 5. Start Sentinel
echo "[4] Starting Sentinel..."
$SENTINEL > "${TERSEC_POSTBOX}/sentinel.log" 2>&1 &
SENTINEL_PID=$!

cleanup() {
    echo "Stopping Sentinel..."
    kill $SENTINEL_PID || true
    cat "${TERSEC_POSTBOX}/sentinel.log"
}
trap cleanup EXIT

# Wait for startup
sleep 2

# Helper function for submission
submit_cmd() {
    local cmd="$1"
    local name="$2"
    echo "Submitting $name..."
    $SUBMITTER submit --partial "$cmd" --signers 1 --output "${name}.partial"
    $SUBMITTER submit --append "${name}.partial" --role DevOps
    $SUBMITTER submit --submit "${name}.partial"
}

# 6. Execute Tests

# Test A: Time Pass
echo "[TEST A] Time Pass..."
CMD_A='#TERSEC_META:{"role":"DevOps","operation":"time_pass","resource":"system","parameters":{}}
echo "TIME_PASS_OK"'
submit_cmd "$CMD_A" "test_a"
sleep 1
# Trigger Pulse
echo "UNLOCK_COMMAND_B7A2" >> "${TERSEC_LOG}"
sleep 2
if grep -q "TIME_PASS_OK" "/tmp/sentinel_history.log"; then
    echo "✅ Success: Time Pass command executed."
else
    echo "❌ Fail: Time Pass command NOT executed."
    exit 1
fi
rm -f /tmp/sentinel_history.log

# Test B: Time Fail
echo "[TEST B] Time Fail..."
CMD_B='#TERSEC_META:{"role":"DevOps","operation":"time_fail","resource":"system","parameters":{}}
echo "TIME_FAIL_BAD"'
submit_cmd "$CMD_B" "test_b"
sleep 1
echo "UNLOCK_COMMAND_B7A2" >> "${TERSEC_LOG}"
sleep 2
if grep -q "TIME_FAIL_BAD" "/tmp/sentinel_history.log" 2>/dev/null; then
    echo "❌ Fail: Time Fail command WAS executed (should be blocked)."
    exit 1
else
    echo "✅ Success: Time Fail command blocked."
fi

# Test C: Geo Pass
echo "[TEST C] Geo Pass (Web Pulse -> US-East)..."
CMD_C='#TERSEC_META:{"role":"DevOps","operation":"geo_pass","resource":"system","parameters":{}}
echo "GEO_PASS_OK"'
submit_cmd "$CMD_C" "test_c"
sleep 1
echo "UNLOCK_COMMAND_B7A2" >> "${TERSEC_LOG}"
sleep 2
if grep -q "GEO_PASS_OK" "/tmp/sentinel_history.log"; then
    echo "✅ Success: Geo Pass command executed."
else
    echo "❌ Fail: Geo Pass command NOT executed."
    exit 1
fi
rm -f /tmp/sentinel_history.log

# Test D: Geo Fail
echo "[TEST D] Geo Fail (Web Pulse -> US-East, Policy requires Local)..."
CMD_D='#TERSEC_META:{"role":"DevOps","operation":"geo_fail","resource":"system","parameters":{}}
echo "GEO_FAIL_BAD"'
submit_cmd "$CMD_D" "test_d"
sleep 1
echo "UNLOCK_COMMAND_B7A2" >> "${TERSEC_LOG}"
sleep 2
if grep -q "GEO_FAIL_BAD" "/tmp/sentinel_history.log" 2>/dev/null; then
    echo "❌ Fail: Geo Fail command WAS executed (should be blocked)."
    exit 1
else
    echo "✅ Success: Geo Fail command blocked."
fi

echo "=== ALL POLICY TESTS PASSED ==="
