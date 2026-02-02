#!/bin/bash
set -e

# --- Configuration ---
POSTBOX_DIR="/tmp/tersec_postbox_p4"
DAEMON_BIN="./target/debug/sentinel"
CLIENT_BIN="./target/debug/submitter"
DAEMON_LOG="sentinel_p4.log"

# Clean previous run
rm -rf "$POSTBOX_DIR"
mkdir -p "$POSTBOX_DIR"
mkdir -p "$POSTBOX_DIR/local_audit"
mkdir -p "$POSTBOX_DIR/authorized_keys"

export TERSEC_POSTBOX="$POSTBOX_DIR"

# --- 1. Setup Environment (Keys & Config) ---
echo "[SETUP] Generating Daemon keys... (Daemon does this on start)"

echo "[SETUP] Generating Client keys..."
$CLIENT_BIN keygen --out "$POSTBOX_DIR/client.key"
# Client output public key to $POSTBOX_DIR/authorized_keys/client_key
CLIENT_PUB_KEY_PATH="$POSTBOX_DIR/authorized_keys/client_key"

# Convert binary pubkey to hex for authorized_keys.json using python3
CLIENT_PUB_HEX=$(python3 -c "import sys; print(open('$CLIENT_PUB_KEY_PATH', 'rb').read().hex())")

echo "[SETUP] Creating authorized_keys.json..."
cat <<EOF > "$POSTBOX_DIR/authorized_keys.json"
{
  "ceremony_id": "test_ceremony",
  "timestamp": 1234567890,
  "keys": [
    {
      "key": "$CLIENT_PUB_HEX",
      "args": [], 
      "role": "DevOps",
      "roles": ["DevOps"]
    }
  ],
  "officers": [
      {
          "role": "DevOps",
          "public_key_hex": "$CLIENT_PUB_HEX"
      }
  ]
}
EOF

# --- 2. Start Request Daemon ---
echo "[DAEMON] Starting Sentinel Daemon..."
# Set TERSEC_M=1 for simple test
export TERSEC_POSTBOX="$POSTBOX_DIR"
export TERSEC_M=1
export TERSEC_PULSE_MODE="file" 
export TERSEC_PULSE_ARG="$POSTBOX_DIR/pulse.signal"

$DAEMON_BIN > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
echo "Daemon PID: $DAEMON_PID"
sleep 2

# --- Helper Function: Submit Command ---
submit_command() {
    CMD_STR="$1"
    OUT_PREFIX="$2"
    
    # 1. Partial
    $CLIENT_BIN submit --partial "$CMD_STR" --signers 1 --output "${OUT_PREFIX}.partial"
    
    # 2. Append Signature
    $CLIENT_BIN submit --append "${OUT_PREFIX}.partial" \
        --role "DevOps" \
        --key "$POSTBOX_DIR/client.key" \
        --pubkey "$CLIENT_PUB_KEY_PATH"
        
    # 3. Submit
    $CLIENT_BIN submit --submit "${OUT_PREFIX}.partial"
}

# --- 3. Test Cases ---

echo "--- Test 1: PII Rejection (Email) ---"
rm -f "$POSTBOX_DIR/pulse.signal"
submit_command "echo 'Sending data to bad_actor@example.com'" "$POSTBOX_DIR/test_pii"

# Send Pulse to allow execution (PII check is after pulse)
sleep 1
echo "UNLOCK_COMMAND_B7A2" >> "$POSTBOX_DIR/pulse.signal"

sleep 2

if grep -q "Command blocked by PII check" "$DAEMON_LOG"; then
    echo "[PASS] Daemon rejected PII command."
else
    echo "[FAIL] Daemon did NOT reject PII command or log it correctly."
    grep "PRIVACY" "$DAEMON_LOG" || true
    kill $DAEMON_PID
    exit 1
fi

echo "--- Test 2: Emergency Alerting ---"
submit_command "echo 'emergency break-glass protocol initiated'" "$POSTBOX_DIR/test_emerg"

# Send Pulse to allow execution
sleep 1
echo "UNLOCK_COMMAND_B7A2" >> "$POSTBOX_DIR/pulse.signal"

sleep 2

if grep -q "break-glass" "$DAEMON_LOG" && grep -q "EXEC" "$DAEMON_LOG"; then
     echo "[PASS] Emergency command executed."
else
     echo "[FAIL] Emergency command did not execute or log."
     kill $DAEMON_PID
     exit 1
fi

# Determine if alerts were sent (mocked stdout)
if grep -q "Alert sent via SMS" "$DAEMON_LOG"; then
    echo "[PASS] Emergency Alerts triggered."
else
    echo "[FAIL] Emergency Alerts NOT triggered."
fi


echo "--- Test 3: Encrypted Audit Log ---"
AUDIT_DIR="$POSTBOX_DIR/audit_logs/local_audit"
COUNT=$(ls "$AUDIT_DIR" | wc -l)
if [ "$COUNT" -ge 1 ]; then
    echo "[PASS] Audit logs created ($COUNT files)."
    
    # Check content for "encrypted_command"
    LATEST_LOG=$(ls -t "$AUDIT_DIR" | head -n 1)
    if grep -q "encrypted_command" "$AUDIT_DIR/$LATEST_LOG"; then
         echo "[PASS] Audit log contains 'encrypted_command'."
    else
         echo "[FAIL] Audit log missing encrypted content."
         cat "$AUDIT_DIR/$LATEST_LOG"
         exit 1
    fi
else
    echo "[FAIL] No audit logs found in $AUDIT_DIR"
    exit 1
fi

# --- Cleanup ---
kill $DAEMON_PID
echo "[SUCCESS] Phase 4 Verification Complete!"
