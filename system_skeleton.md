# Wolf Prowler - System Architecture Skeleton

This document provides a comprehensive structural overview of the Wolf Prowler system to aid in implementation and research. It maps out the relationships between the core crates (`wolf_net`, `wolfsec`, `wolf_den`) and the orchestration layer.

## 📂 Workspace Structure

```text
wolf_prowler/
├── Cargo.toml                # Workspace definition
├── src/                      # Main entry point (wolf_prowler binary)
│   ├── main.rs               # Bootstraps WolfNode
│   └── config.rs             # Global configuration loading
├── wolf_net/                 # P2P Networking & SaaS Integration
│   ├── src/
│   │   ├── lib.rs
│   │   ├── wolf_node.rs      # System Facade (Orchestrator)
│   │   ├── swarm_manager.rs  # Libp2p logic & Peer Management
│   │   ├── firewall.rs       # Internal Firewall (Rule Engine)
│   │   ├── hub_orchestration.rs # SaaS Auth & Token Management
│   │   └── reporting_service.rs # Telemetry Batching & Transmission
├── wolfsec/                  # Security Engine (ML/SIEM/SOAR)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── engine.rs         # MLSecurityEngine (Inference)
│   │   ├── features.rs       # Feature Extraction (Event -> Tensor)
│   │   ├── siem.rs           # Correlation Engine (Attack Chains)
│   │   └── soar.rs           # Automated Response (Playbooks)
├── wolf_den/                 # Cryptography
│   ├── src/
│   │   ├── lib.rs
│   │   └── crypto.rs         # AES/ChaCha20 wrappers & Key Rotation
├── wolf_server/              # Dashboard API (Axum)
└── wolf_control/             # TUI (Ratatui)
```

## 🧩 Core Component Skeletons

### 1. Networking (`wolf_net`)

**WolfNode (Facade)**
*   **Responsibility**: Orchestrates the startup and lifecycle of network components.
*   **State**: Holds `SwarmManager`, `InternalFirewall`, `HubOrchestration`, `ReportingService`, and the `reporting_tx` channel.
*   **Lifecycle**: `new()` -> `run()` (concurrent select loop for Swarm, Reporting, and Hub Auth).

**SwarmManager**
*   **Responsibility**: Manages libp2p swarm, peer discovery (Kademlia/mDNS), and transport (QUIC/TCP).
*   **Key Methods**: `start()`, `broadcast()`, `send_direct()`.

**InternalFirewall**
*   **Responsibility**: Filters traffic based on rules.
*   **Struct**: `InternalFirewall { rules: Vec<FirewallRule>, policy: FirewallPolicy }`.
*   **Logic**: Checks `(Target, Protocol, Direction)` against rules list.

**HubOrchestration**
*   **Responsibility**: Authenticates with SaaS Hub via JWT.
*   **Loop**: Authenticate -> Sleep(expires_in - 60s) -> Re-authenticate.
*   **State**: Shares `Arc<RwLock<Option<String>>>` (Token) with ReportingService.

**ReportingService**
*   **Responsibility**: Batches and sends telemetry to the SaaS Hub.
*   **Input**: `mpsc::Receiver<TelemetryEvent>`.
*   **Logic**: Buffers events -> Flushes on `batch_size` or `flush_interval`.

### 2. Security Engine (`wolfsec`)

**MLSecurityEngine**
```rust
pub struct MLSecurityEngine {
    models: HashMap<String, Model>, // ONNX sessions or Linfa models
    feature_extractor: FeatureExtractor,
    config: MLConfig,
}
```

**SiemEngine**
```rust
pub struct SiemEngine {
    event_buffer: VecDeque<SecurityEvent>,
    correlation_rules: Vec<CorrelationRule>,
    alerts: Vec<Alert>,
}
```

### 3. Cryptography (`wolf_den`)

**WolfDen**
```rust
pub struct WolfDen {
    level: SecurityLevel,
    key_store: KeyStore,
}

pub enum SecurityLevel {
    Low,    // AES-128
    Medium, // AES-192
    High,   // AES-256 / ChaCha20
}
```

## 🔄 Data Flow Architecture

### Inbound Traffic Flow
1.  **Transport**: Bytes arrive via QUIC/TCP (`wolf_net`).
2.  **Decryption**: `wolf_den` decrypts payload.
3.  **Firewall**: `InternalFirewall` checks PeerID/IP against Deny rules.
4.  **Protocol**: `SwarmManager` routes message to specific handler.
5.  **Analysis**: Payload sent to `wolfsec` for anomaly detection.

### Security Event Pipeline
1.  **Event Generation**: System component (e.g., Login, NetRequest) emits `SecurityEvent`.
2.  **Feature Extraction**: `wolfsec` converts event to tensor.
3.  **Inference**: ML Model predicts Risk Score (0.0 - 1.0).
4.  **Correlation**: `SiemEngine` checks if event is part of a chain (e.g., Brute Force).
5.  **Response**: If Severity > Threshold, `SoarOrchestrator` executes Playbook (e.g., Ban Peer).
6.  **Reporting**: `WolfNode::send_telemetry` -> `ReportingService` Queue -> Batch -> SaaS Hub.

## 📝 Implementation Checklist

- [x] **WolfNode**: Basic orchestration loop with graceful shutdown.
- [x] **Firewall**: Rule engine, policy logic, and thread-safe access (`Arc<RwLock>`).
- [x] **SaaS Auth**: HubOrchestration with automatic JWT refresh loop.
- [x] **Reporting**: Telemetry queue, background task, and shared auth token.
- [ ] **SwarmManager**: Full libp2p integration (currently implied/mocked in context).
- [ ] **ML Integration**: Connect `wolfsec` inference to `wolf_net` traffic.
- [ ] **Persistence**: Database integration for rules/logs (PostgreSQL).