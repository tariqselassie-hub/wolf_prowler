#!/bin/bash
set -e

# Cleanup previous runs
pkill -f "headless" || true
rm -f runtime_data/logs/node_*.log
rm -rf runtime_data/wolf_data_node_*

# Create logs directory
mkdir -p runtime_data/logs

echo "🔨 Building Lock Prowler (Headless)..."
cargo build -p lock_prowler --bin headless

BINARY="./target/debug/headless"

echo "🐺 Launching Alpha Node (Leader)..."
WOLF_DB_PATH="./runtime_data/wolf_data_node_alpha" WOLF_P2P_PORT=3031 WOLF_IDENTITY_SEED="alpha_node_seed_value" RUST_LOG=info $BINARY --path ~ --no-auto-import > runtime_data/logs/node_alpha.log 2>&1 &
ALPHA_PID=$!
echo "   PID: $ALPHA_PID"

sleep 5

echo "🐺 Launching Beta Node..."
WOLF_DB_PATH="./runtime_data/wolf_data_node_beta" WOLF_P2P_PORT=3041 WOLF_IDENTITY_SEED="beta_node_seed_value" WOLF_BOOTSTRAP="/ip4/127.0.0.1/tcp/3031" RUST_LOG=info $BINARY --path ~ --no-auto-import > runtime_data/logs/node_beta.log 2>&1 &
BETA_PID=$!
echo "   PID: $BETA_PID"

sleep 5

echo "🐺 Launching Gamma Node..."
WOLF_DB_PATH="./runtime_data/wolf_data_node_gamma" WOLF_P2P_PORT=3051 WOLF_IDENTITY_SEED="gamma_node_seed_value" WOLF_BOOTSTRAP="/ip4/127.0.0.1/tcp/3031" RUST_LOG=info $BINARY --path ~ --no-auto-import > runtime_data/logs/node_gamma.log 2>&1 &
GAMMA_PID=$!
echo "   PID: $GAMMA_PID"

echo "✅ Simulation running. Logs are in runtime_data/logs/"
echo "   tail -f runtime_data/logs/node_alpha.log"
echo "   tail -f runtime_data/logs/node_beta.log"
echo "   tail -f runtime_data/logs/node_gamma.log"
echo ""
echo "Press Ctrl+C to stop simulation."

trap "kill $ALPHA_PID $BETA_PID $GAMMA_PID; exit" INT TERM

wait
