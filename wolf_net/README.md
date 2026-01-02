# Wolf Net - P2P Networking Layer

**Status**: ✅ Production Ready | **Version**: 1.0

Wolf Net provides secure, encrypted peer-to-peer networking built on libp2p for the Wolf Prowler platform.

## 🌐 Features

- **Secure P2P Communication**
  - X25519 ECDH key exchange
  - ChaCha20-Poly1305 encryption for all peer connections
  - End-to-end encrypted messaging

- **Internal Firewall**
  - Configurable Allow/Deny rules
  - Filtering by IP, Port, Peer ID, or Protocol
  - Inbound and Outbound traffic control
  - Dynamic rule management via API

- **Network Protocols**
  - Kademlia DHT for peer discovery
  - mDNS for local network discovery
  - Gossipsub for pub/sub messaging
  - **HyperPulse**: QUIC transport for low-latency, high-performance communication
  - Automatic NAT traversal and relay support

- **Wolf Pack Hierarchy**
  - Role-based access control (Stray → Scout → Hunter → Beta → Alpha → Omega)
  - Prestige system with automatic rank evolution
  - **Prestige Decay**: Periodic reduction- **P2P Messaging**: Decentralized communication using `libp2p`.
- **Wolf Pack Protocol**: Custom protocol for pack coordination, status sharing, and hunting.
- **Alpha Election**: Prestige-weighted consensus mechanism for decentralized leader selection.
- **🔔 Alert Management**
  - Smart deduplication (30-minute window)
  - Dynamic severity calculation (event + correlation + attack chain)
  - Alert lifecycle tracking
  - Automatic response generation
  - **Multi-Tenant Isolation** 🆕: Alerts are strictly scoped by `org_id`
- **Swarm Management**: Automated peer discovery, health monitoring, and routing.
  - Health monitoring and liveness checks
  - Configurable connection limits

- **Performance**
  - Efficient message routing
  - Low-latency communication via QUIC (HyperPulse)
  - Scalable to 1000+ peers

- **Active Defense Integration**
  - **SOAR Execution**: Accepts direct kill orders (Ban, Disconnect) from WolfSec engine
  - **Threat Blocking**: Dynamic firewall updates based on SIEM alerts
  - **Real-time Isolation**: Immediate quarantine of compromised peers

- **SaaS Agent Reporting** 🆕
  - **ReportingService**: Batched telemetry and alert transmission
  - **Hub Orchestration**: Support for `headless-agent` mode
  - **JWT Authentication**: Secure handshake with the Central Hub

## 🖥️ Dashboard Integration

Wolf Net is fully integrated with the Wolf Prowler dashboard:

- **Global Map** (`/static/network.html`): Real-time geospatial visualization of peer nodes.
- **P2P Mesh** (`/static/p2p.html`): Force-directed graph of swarm connectivity and routing.
- **Firewall Control** (`/static/firewall.html`): Visual rule management and traffic monitoring.


## 🚀 Quick Start

```rust
use wolf_net::{SwarmManager, NetworkConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize network
    let config = NetworkConfig::default();
    let mut swarm = SwarmManager::new(config).await?;
    
    // Start networking
    swarm.start().await?;
    
    // Send encrypted message
    swarm.send_message(peer_id, b"Hello, secure world!").await?;
    
    Ok(())
}
```

## 📦 Installation

```toml
[dependencies]
wolf_net = { path = "../wolf_net" }
```

## 🔧 Configuration

```rust
let config = NetworkConfig {
    listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".parse()?],
    bootstrap_peers: vec![],
    max_connections: 100,
    ..Default::default()
};
```

## 🛡️ Security

- All peer-to-peer communication is encrypted with ChaCha20-Poly1305
- X25519 Elliptic Curve Diffie-Hellman for key exchange
- Perfect forward secrecy for all sessions
- Automatic peer authentication

## 📄 License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
See [LICENSE-APACHE](../LICENSE-APACHE) and [LICENSE-MIT](../LICENSE-MIT) for details.

### Third-Party Licenses
This crate includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit.
See [THIRD-PARTY-NOTICE.txt](../THIRD-PARTY-NOTICE.txt) in the project root for full details.