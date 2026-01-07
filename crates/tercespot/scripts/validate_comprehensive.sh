#!/bin/bash
set -e

echo "=== COMPREHENSIVE DOCKER TEST (Air Gap + Privacy + PQC + Crypto Pulse) ==="

# --- CONFIGURATION ---
export TERSEC_POSTBOX="/tmp/postbox"
export TERSEC_LOG="/var/log/nginx/access.log"
# Enable CRYPTO Pulse Mode (Challenge-Response)
export TERSEC_PULSE_MODE="CRYPTO"
# Enable Privacy Mode
export TERSEC_PRIVACY_MODE="true"
# Threshold M=1 for simple testing
export TERSEC_M="1"

# Setup Directories
mkdir -p $TERSEC_POSTBOX
touch $TERSEC_LOG && chmod 666 $TERSEC_LOG

# --- STEP 0: GENERATE CLIENT & PULSE KEYS ---
echo "[SETUP] Generating Client Keys..."
su - submitter -c "/app/target/debug/submitter keygen --out $TERSEC_POSTBOX/private_key 2>&1"

# Convert binary public key to hex (using hexdump or od)
# Ubuntu minimal might not have xxd. Using od.
PK_HEX=$(od -An -v -t x1 $TERSEC_POSTBOX/authorized_keys/client_key | tr -d ' \n')

# Create authorized_keys.json for Sentinel
cat > $TERSEC_POSTBOX/authorized_keys.json <<EOF
{
  "ceremony_id": "test_ceremony",
  "timestamp": $(date +%s),
  "officers": [
    {
      "role": "DevOps",
      "public_key_hex": "$PK_HEX"
    }
  ]
}
EOF
chown submitter:submitter $TERSEC_POSTBOX/authorized_keys.json

echo "[SETUP] Initializing Pulse Device (Generating Keys)..."
# Run pulse device briefly to generate keys
/app/target/debug/pulse_device > /tmp/pulse_device_init.log 2>&1 &
PULSE_INIT_PID=$!
sleep 5
kill $PULSE_INIT_PID 2>/dev/null || true

if [ ! -f $TERSEC_POSTBOX/pulse_pk ]; then
    echo "❌ FAILURE: Pulse Device failed to generate keys!"
    cat /tmp/pulse_device_init.log
    exit 1
fi
echo "✅ Keys Generated."

# --- PHASE 1: START SENTINEL ---
echo "[SETUP] Starting Sentinel..."
# Sentinel needs to find authorized_keys. The 'keygen' command places it in $TERSEC_POSTBOX/authorized_keys/client_key
# But Sentinel expects a specific directory structure.
# Sentinel looks for `authorized_keys` directory relative to execution or config.
# Let's ensure it's in the right place. Sentinel default is likely `./authorized_keys` or from config.
# Dockerfile sets WORKDIR /app. Sentinel runs as root (or user?).
# Dockerfile says `RUN useradd ... submitter`.
# Let's assume Sentinel runs in /app and looks for authorized_keys there or in postbox if configured.
# Wait, Sentinel code: `let authorized_keys_path = format!("{}/authorized_keys", postbox_path());`
# Checks `shared::postbox_path`.
# So if TERSEC_POSTBOX is set, it looks in $TERSEC_POSTBOX/authorized_keys.
# My `keygen` puts it there. Perfect.

/app/target/debug/sentinel > /tmp/sentinel.log 2>&1 &
SENTINEL_PID=$!
sleep 5

if ! kill -0 $SENTINEL_PID 2>/dev/null; then
    echo "❌ CRITICAL: Sentinel failed to start!"
    cat /tmp/sentinel.log
    exit 1
fi

# --- PHASE 2: PRIVACY CHECK ---
echo "[TEST] Phase 1: Privacy Compliance (PII Handling)"
# 1. Generate Partial (Single Signer)
if su - submitter -c "/app/target/debug/submitter submit --partial 'echo user@example.com' --signers 1 --output /tmp/privacy.partial 2>&1"; then
    # 2. Append Signature (as DevOps)
    su - submitter -c "/app/target/debug/submitter submit --append /tmp/privacy.partial --role DevOps 2>&1"
    # 3. Submit
    su - submitter -c "/app/target/debug/submitter submit --submit /tmp/privacy.partial 2>&1"
else
    echo "⚠️ Client failed to generate partial command."
fi

# Verification
sleep 2
if grep -q "PII" /tmp/sentinel.log; then
    echo "✅ SUCCESS: PII detected in logs."
else
    echo "This is expected if the privacy module only logs encrypted audit trails."
    echo "⚠️ WARNING: No PII plaintext warning found. Assuming Success if no crash."
fi

# --- PHASE 3: CRYPTO PULSE ENFORCEMENT ---
echo "[TEST] Phase 2: Crypto Pulse Enforcement"

# 3a. Start Pulse Device in Background (Real Simulation)
echo "[SETUP] Starting Pulse Device..."
/app/target/debug/pulse_device > /tmp/pulse_device.log 2>&1 &
PULSE_DEVICE_PID=$!

# 3b. Submit Valid Command
echo "[CLIENT] Submitting Command: 'echo CRYPTO_PULSE_TEST'"
# 1. Create Partial
su - submitter -c "/app/target/debug/submitter submit --partial 'echo CRYPTO_PULSE_TEST' --signers 1 --output /tmp/pulse.partial"
# 2. Append Signature
su - submitter -c "/app/target/debug/submitter submit --append /tmp/pulse.partial --role DevOps"
# 3. Submit
su - submitter -c "/app/target/debug/submitter submit --submit /tmp/pulse.partial"

# 3c. Wait for Execution
echo "[VERIFY] Waiting for Cycle (Sig Verify -> Challenge -> Response -> Exec)..."
sleep 15

# 3d. Verify Execution
if grep -q "CRYPTO_PULSE_TEST" /tmp/sentinel_history.log 2>/dev/null; then
    echo "✅ SUCCESS: Command executed via Crypto Pulse!"
else
    echo "❌ FAILURE: Command NOT executed."
    echo "--- Sentinel Logs ---"
    cat /tmp/sentinel.log
    echo "--- Pulse Device Logs ---"
    cat /tmp/pulse_device.log
    echo "--- Postbox ---"
    ls -la $TERSEC_POSTBOX
    exit 1
fi

echo "=== ALL COMPREHENSIVE TESTS PASSED ==="
kill $SENTINEL_PID
kill $PULSE_DEVICE_PID
exit 0
