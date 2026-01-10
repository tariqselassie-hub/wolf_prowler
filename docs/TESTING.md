# Wolf Prowler - Testing & Quality Assurance

**Status**: ✅ Production Grade | **Coverage**: 85%+

This document outlines the comprehensive testing strategy for the Wolf Prowler ecosystem. We employ a rigorous multi-layered testing approach to ensure security, stability, and performance.

## 🧪 Core Test Suites

### 1. P2P Network Integration (`wolf_net`)
Verifies the decentralized networking layer, including peer discovery, encrypted messaging, and consensus.

*   **Key Test**: `tests/discovery_integration.rs`
*   **Command**: `cargo test -p wolf_net --test discovery_integration`
*   **What it verifies**:
    *   **mDNS Discovery**: Nodes automatically find each other on the local network.
    *   **Connection Stability**: Swarm managers maintain robust connections despite transport fluctuations.
    *   **Leader Election**: Raft consensus operates correctly over the P2P mesh.

### 2. Security Core Logic (`wolfsec`)
Validates the cryptographic primitives, threat detection logic, and authentication workflows.

*   **Key Test**: `wolfsec/src/comprehensive_tests.rs` (plus 100+ unit tests)
*   **Command**: `cargo test -p wolfsec`
*   **What it verifies**:
    *   **Threat Detection**: Correctly identifies anomalies and malicious patterns.
    *   **Cryptography**: NIST FIPS 203/204 compliance for key exchange and signing.
    *   **Access Control**: RBAC policies are enforced correctly.

### 3. Dashboard & Full Stack (`wolf_web`)
Tests the integration of the web API, WebSocket streams, and backend state management.

*   **Key Test**: `tests/dashboard_comprehensive_test.rs`
*   **Command**: `cargo test --test dashboard_comprehensive_test`
*   **What it verifies**:
    *   **API Endpoints**: Health checks, metrics, and auth endpoints return correct JSON.
    *   **Middleware**: API Key and Session authentication reject invalid requests.
    *   **State**: Application state correctly tracks metrics and security events.

### 4. TersecPot Blind Command-Bus (`tercespot`)
Validates the high-security "Blind Command-Bus" subsystem.

*   **Key Test**: `crates/tercespot/client/tests/visual_flow.rs`
*   **Command**: `cargo test --workspace` (inside `crates/tercespot`)
*   **What it verifies**:
    *   **Visual Flow**: End-to-end command submission, signing, and execution.
    *   **Pulse Challenge**: Hardware token simulation correctly answers cryptographic challenges.
    *   **Air-Gap**: Forensic logging and USB bridge functionality.

## 🛠️ Running Tests

### Quick Sanity Check
Runs all unit tests across the workspace.
```bash
cargo test
```

### Full System Verification
Runs all tests including expensive integration suites.
```bash
cargo test --workspace --all-features
```

### Specific Module Verification
```bash
# Networking
cargo test -p wolf_net

# Security
cargo test -p wolfsec

# Dashboard
cargo test -p wolf_web
```

## 📊 Performance Benchmarks

We use `criterion` for cryptographic and throughput benchmarks.

```bash
cargo bench -p wolf_den
```

## 🛡️ Fuzzing

Fuzz testing is available for critical parsers and network handlers.

```bash
cargo fuzz run message_parser
```

## 💥 Stress Testing

We employ a dedicated stress test suite to verify system stability under extreme load and attack conditions.

*   **File**: `tests/system_stress_test.rs`
*   **Command**: `cargo test --test system_stress_test -- --nocapture`
*   **Scenarios**:
    *   **Concurrent Request Spikes**: Simulates up to 1,000 concurrent clients flooding the API (DDoS emulation).
    *   **Payload Exhaustion**: Sends oversized payloads (10MB+) to test rejection logic.
    *   **Connection Flooding**: Spawns multiple attacker nodes to swarm a victim node simultaneously.
    *   **Protocol Anomaly Injection**: Sends garbage data and partial handshakes to verify network resilience.
