#!/bin/bash
set -e

# Setup Workspace
WORK_DIR="$(pwd)/test_env_phase2"
POSTBOX="$WORK_DIR/postbox"
USB_DIR="$WORK_DIR/usb"
SCRIPTS_DIR="$(dirname "$0")"
ROOT_DIR="$(dirname "$SCRIPTS_DIR")"

echo "=== Setting up validation environment in $WORK_DIR ==="

rm -rf "$WORK_DIR"
mkdir -p "$POSTBOX/authorized_keys"
mkdir -p "$USB_DIR"

# Build binaries
echo "=== Building TersecPot binaries ==="
cd "$ROOT_DIR"
cargo build --bins

# 1. Run Ceremony to generate keys (Reusing Phase 1)
echo "=== Running Key Ceremony (Phase 1) ==="
mkdir -p "$USB_DIR/officer_1"
mkdir -p "$USB_DIR/officer_2"

# Note: authorized_keys.json is output to CWD by ceremony tool
cat > "$WORK_DIR/ceremony_config.json" <<EOF
{
  "n": 2,
  "roles": ["DevOps", "ComplianceManager"],
  "usb_paths": ["$USB_DIR/officer_1", "$USB_DIR/officer_2"]
}
EOF

# Run Ceremony
"$ROOT_DIR/target/debug/ceremony" --test-config "$WORK_DIR/ceremony_config.json"

# Move authorized_keys from CWD to POSTBOX
if [ -f "authorized_keys.json" ]; then
    mv "authorized_keys.json" "$POSTBOX/authorized_keys.json"
else
    echo "Error: authorized_keys.json not found in CWD"
    exit 1
fi

echo "Ceremony Complete. Keys generated."

# 2. Extract Public Keys for Client Verification (Workaround)
# The client 'append' command needs a public key file to verify the signature it creates.
# The `ceremony` tool puts public keys in authorized_keys.json but doesn't output individual .pub files.
# We need to extract them.
# We can use jq if available, or python.
echo "=== Extracting Public Keys ==="
if command -v jq >/dev/null 2>&1; then
    HEX1=$(jq -r '.officers[0].public_key_hex' "$POSTBOX/authorized_keys.json")
    HEX2=$(jq -r '.officers[1].public_key_hex' "$POSTBOX/authorized_keys.json")
else
    HEX1=$(python3 -c "import json, sys; data=json.load(open('$POSTBOX/authorized_keys.json')); print(data['officers'][0]['public_key_hex'])")
    HEX2=$(python3 -c "import json, sys; data=json.load(open('$POSTBOX/authorized_keys.json')); print(data['officers'][1]['public_key_hex'])")
fi

python3 -c "import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify('$HEX1'))" > "$USB_DIR/officer_1/key.pub"
python3 -c "import sys, binascii; sys.stdout.buffer.write(binascii.unhexlify('$HEX2'))" > "$USB_DIR/officer_2/key.pub"

# 3. Start Sentinel Daemon
echo "=== Starting Sentinel Daemon ==="
touch "$WORK_DIR/pulse.log"

export TERSEC_POSTBOX="$POSTBOX"
export TERSEC_M=2
export TERSEC_PULSE_MODE="WEB"
export TERSEC_PULSE_ARG="$WORK_DIR/pulse.log"
export RUST_BACKTRACE=1

"$ROOT_DIR/target/debug/sentinel" > "$WORK_DIR/daemon.log" 2>&1 &
DAEMON_PID=$!
echo "Daemon started with PID $DAEMON_PID"

cleanup() {
    echo "Stopping Daemon..."
    kill $DAEMON_PID || true
}
trap cleanup EXIT

# Wait for daemon startup (KEM key generation)
sleep 2
if [ ! -f "$POSTBOX/kem_public_key" ]; then
    echo "Error: Daemon failed to generate KEM keys"
    cat "$WORK_DIR/daemon.log"
    exit 1
fi

# 4. Create Partial Command (Client)
echo "=== Creating Partial Command ==="
# Command must be simple. Note: daemon executes with `sh -c`.
CMD="echo 'Phase 2 Validation Success' > $WORK_DIR/success.txt"
PARTIAL_FILE="$WORK_DIR/test_cmd.partial"

"$ROOT_DIR/target/debug/submitter" submit --partial "$CMD" --signers 2 --output "$PARTIAL_FILE"

if [ ! -f "$PARTIAL_FILE" ]; then
    echo "Error: Partial file not created"
    exit 1
fi

# 5. Sign by Officer 1 (DevOps)
echo "=== Officer 1 Signing ==="
"$ROOT_DIR/target/debug/submitter" submit --append "$PARTIAL_FILE" \
    --role "DevOps" \
    --key "$USB_DIR/officer_1/officer_key" \
    --pubkey "$USB_DIR/officer_1/key.pub"

# 6. Sign by Officer 2 (ComplianceManager)
echo "=== Officer 2 Signing ==="
"$ROOT_DIR/target/debug/submitter" submit --append "$PARTIAL_FILE" \
    --role "ComplianceManager" \
    --key "$USB_DIR/officer_2/officer_key" \
    --pubkey "$USB_DIR/officer_2/key.pub"

# 7. Submit
echo "=== Submitting Command ==="
"$ROOT_DIR/target/debug/submitter" submit --submit "$PARTIAL_FILE"

# 8. Trigger Pulse
echo "=== Triggering Pulse ==="
echo "UNLOCK_COMMAND_B7A2" >> "$WORK_DIR/pulse.log"

# 9. Verify Execution
echo "=== Verifying Execution ==="
for i in {1..10}; do
    if [ -f "$WORK_DIR/success.txt" ]; then
        echo "SUCCESS: Command executed!"
        grep "Phase 2 Validation Success" "$WORK_DIR/success.txt"
        exit 0
    fi
    sleep 0.5
    echo "UNLOCK_COMMAND_B7A2" >> "$WORK_DIR/pulse.log"
done

echo "FAILURE: Command did not execute."
cat "$WORK_DIR/daemon.log"
exit 1
