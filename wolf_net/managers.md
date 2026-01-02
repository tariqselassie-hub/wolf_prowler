# Wolf Net - System Managers & Engines

This document outlines the core managers, engines, and services identified within the Wolf Net architecture.

## 🕸️ Core Networking

- **SwarmManager**
  - **Type**: Core Manager
  - **Function**: Orchestrates the P2P swarm, handling automated peer discovery, health monitoring, routing, and connection limits. It is the primary interface for initializing the network.

- **HyperPulse**
  - **Type**: Transport Engine
  - **Function**: A QUIC-based transport engine designed for low-latency, high-performance communication.

## 🛡️ Security & Control

- **Internal Firewall**
  - **Type**: Security Manager
  - **Function**: Controls inbound/outbound traffic via configurable Allow/Deny rules (IP, Port, Peer ID, Protocol) and supports dynamic rule management.

- **Alert Management**
  - **Type**: Event Engine
  - **Function**: Handles alert lifecycle including smart deduplication (30-min window), dynamic severity calculation, and automatic response generation. Scoped by `org_id` for multi-tenancy.

## ☁️ SaaS & Integration

- **ReportingService**
  - **Type**: Telemetry Service
  - **Function**: Manages the batching and transmission of telemetry and alerts to the Central Hub.

- **Hub Orchestration**
  - **Type**: Orchestration Manager
  - **Function**: Manages `headless-agent` mode and handles secure JWT authentication handshakes with the Central Hub.

## 🧠 System Orchestration

- **WolfNode**
  - **Type**: System Facade
  - **Function**: Encapsulates system initialization, wiring together the Swarm, Firewall, and Reporting services to keep `main` clean.

## 🏗️ Implementation Skeletons

### ReportingService

```rust
use tokio::sync::mpsc;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Manages the batching and transmission of telemetry and alerts to the Central Hub.
pub struct ReportingService {
    /// HTTP client for external communication with the Hub
    client: reqwest::Client,
    /// Base URL for the Central Hub API
    hub_url: String,
    /// Organization ID for multi-tenant scoping
    org_id: String,
    /// Secure storage for the JWT authentication token
    auth_token: Arc<RwLock<Option<String>>>,
    /// Channel for buffering telemetry events before batching
    event_queue: mpsc::Sender<TelemetryEvent>,
    /// Maximum number of events to batch before transmission
    batch_size: usize,
    /// Time interval for periodic flushing of the queue
    flush_interval_ms: u64,
}
```

### WolfNode (System Facade)

```rust
/// Top-level manager to clean up main.rs initialization
pub struct WolfNode {
    swarm: SwarmManager,
    reporting: Option<ReportingService>,
    // Centralized access to the firewall
    firewall: Arc<RwLock<InternalFirewall>>,
}

impl WolfNode {
    /// Initializes all subsystems based on config
    pub async fn new(config: NetworkConfig) -> Result<Self> { todo!() }

    /// Starts the main event loop
    pub async fn run(&mut self) -> Result<()> { todo!() }
}
```
```