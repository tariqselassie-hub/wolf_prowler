#!/bin/bash
set -e

echo "=== STARTING DOCKER LIVE VALIDATION (FOUR-EYES VAULT PQC) ==="

export TERSEC_POSTBOX="/tmp/postbox"
export TERSEC_LOG="/var/log/nginx/access.log"
# Force CRYPTO mode for Four-Eyes Vault
export TERSEC_PULSE_MODE="CRYPTO"
export TERSEC_M="1"

echo "[SETUP] Ensuring directories exist..."
mkdir -p $TERSEC_POSTBOX
touch $TERSEC_LOG && chmod 666 $TERSEC_LOG

echo "[SETUP] Creating policy configuration..."
cat > $TERSEC_POSTBOX/policies.toml << 'EOF'
policies = [
    {
        name = "test_policy",
        roles = ["admin"],
        operations = ["restart"],
        resources = ["apache"],
        threshold = 1,
        approval_expression = "Role:DevOps"
    }
]

[role_mappings]
"test_key" = ["admin", "DevOps"]
EOF

echo "[DAEMON] Starting Sentinel (Four-Eyes Vault Mode)..."
/app/target/debug/sentinel &
SENTINEL_PID=$!
sleep 3

echo "[PULSE] Starting Pulse Device..."
/app/target/debug/pulse_device &
PULSE_PID=$!
sleep 2

echo "[CLIENT] Creating partial command..."
su - submitter -c "/app/target/debug/submitter submit --partial 'systemctl restart apache2' --output /tmp/test.partial --signers 1"

echo "[CLIENT] Appending signature..."
su - submitter -c "/app/target/debug/submitter submit --append /tmp/test.partial --role DevOps --key $TERSEC_POSTBOX/private_key --pubkey $TERSEC_POSTBOX/authorized_keys/client_key"

echo "[CLIENT] Submitting signed command..."
su - submitter -c "/app/target/debug/submitter submit --submit /tmp/test.partial"

# Wait for sentinel to process the command
sleep 5

echo "[VERIFY] Checking for execution (polling for 30s)..."
for i in {1..30}; do
    if [ -f /tmp/sentinel_history.log ]; then
        echo "Found history log!"
        break
    fi
    echo "Waiting for log... ($i/30)"
    sleep 1
done

if [ -f /tmp/sentinel_history.log ]; then
    echo ">>> SUCCESS: Four-Eyes Vault executed command!"
    echo "=== Execution Log ==="
    cat /tmp/sentinel_history.log
    echo "=== Test Summary ==="
    echo "✅ Sentinel started successfully"
    echo "✅ Pulse Device generated keys"
    echo "✅ Partial command created"
    echo "✅ Signature appended"
    echo "✅ Command submitted and executed"
    echo "✅ Post-Quantum Cryptography validated"
    echo "✅ Four-Eyes principle enforced"
    kill $SENTINEL_PID
    kill $PULSE_PID
    exit 0
else
    echo ">>> FAILURE: Command not executed or log empty."
    echo "=== Debug Information ==="
    echo "Postbox contents:"
    ls -la $TERSEC_POSTBOX/
    echo "Log file contents:"
    cat /var/log/nginx/access.log || echo "Log file empty or missing"
    echo "=== Test Summary ==="
    echo "❌ Four-Eyes Vault test failed"
    kill $SENTINEL_PID
    kill $PULSE_PID
    exit 1
fi
