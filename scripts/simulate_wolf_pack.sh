#!/bin/bash
set -e

# Cleanup previous runs
pkill -f "wolf_prowler" || true
rm -f logs/node_*.log

# Create logs directory
mkdir -p logs

echo "🔨 Building Wolf Prowler..."
cargo build --bin wolf_prowler

echo "🐺 Launching Alpha Node (Leader)..."
WOLF_ROLE="Alpha" WOLF_PORT=3030 WOLF_P2P_PORT=3031 RUST_LOG=info ./target/debug/wolf_prowler > logs/node_alpha.log 2>&1 &
ALPHA_PID=$!
echo "   PID: $ALPHA_PID"

sleep 5

echo "🐺 Launching Beta Node..."
WOLF_ROLE="Beta" WOLF_PORT=3040 WOLF_P2P_PORT=3041 WOLF_BOOTSTRAP="/ip4/127.0.0.1/tcp/3031" RUST_LOG=info ./target/debug/wolf_prowler > logs/node_beta.log 2>&1 &
BETA_PID=$!
echo "   PID: $BETA_PID"

sleep 5

echo "🐺 Launching Gamma Node..."
WOLF_ROLE="Gamma" WOLF_PORT=3050 WOLF_P2P_PORT=3051 WOLF_BOOTSTRAP="/ip4/127.0.0.1/tcp/3031" RUST_LOG=info ./target/debug/wolf_prowler > logs/node_gamma.log 2>&1 &
GAMMA_PID=$!
echo "   PID: $GAMMA_PID"

echo "✅ Simulation running. Logs are in logs/"
echo "   tail -f logs/node_alpha.log"
echo "   tail -f logs/node_beta.log"
echo "   tail -f logs/node_gamma.log"
echo ""
echo "Press Ctrl+C to stop simulation."

trap "kill $ALPHA_PID $BETA_PID $GAMMA_PID; exit" INT TERM

wait
