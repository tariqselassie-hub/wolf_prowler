#!/bin/bash
set -e

echo "🐺 Building Fuzzers..."
cargo build -p wolf_fuzz

echo "🚀 Running Crypto Fuzzer (1000 iterations)..."
cargo run -p wolf_fuzz --bin fuzz_crypto

echo "🚀 Running Network Fuzzer (1000 iterations)..."
cargo run -p wolf_fuzz --bin fuzz_net

echo "🚀 Running Security Fuzzer (1000 iterations)..."
cargo run -p wolf_fuzz --bin fuzz_security

echo "✅ All Fuzzers completed successfully."
