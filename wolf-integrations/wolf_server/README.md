# Wolf Server: Security Intelligence API

> **Status**: Production Ready (Version 2.0)
> **Role**: API Gateway & Threat Intelligence Hub
> **Stack**: Axum, PostgreSQL, Prometheus

Wolf Server is the backend reporting engine and API gateway / WebSocket server. Unlike the Dashboard (`wolf_web`), this server focuses on high-throughput event ingestion, persistence, and external API access.

## 🏗️ Architecture

Wolf Server acts as the "Memory" of the ecosystem, persisting ephemeral findings from `wolfsec` and `wolf_net` into long-term PostgreSQL storage.

### Core Modules

1.  **Metric Ingestion**:
    *   Exposes Prometheus-compatible endpoints (`/api/prometheus`).
    *   Collects peer metrics (latency, health score) every 60 seconds.
2.  **Threat Intelligence Loop**:
    *   Ingests events from `wolfsec`.
    *   Correlates IPs against known threat feeds (Hourly Sync).
    *   Stores CVE data and Intrusion Attempts.
3.  **Persistence Layer**:
    *   **PostgreSQL 16**: Primary storage for historical data.
    *   **Feature Flag**: `advanced_reporting` triggers DB initialization.

## 🔌 API Reference

### Health & Metrics
*   `GET /api/health` - Database & System status.
*   `GET /api/prometheus` - Scrape target for monitoring stacks.
*   `GET /database/stats` - Row counts (Peers, Alerts, Logs).

### Historical Data (Pagination Supported)
*   `GET /api/v1/peers/history` - Tracked peer behavior over time.
*   `GET /api/v1/alerts/history` - Security incident log.
*   `GET /api/v1/audit/logs` - Immutable audit trail.

### Threat Intelligence
*   `GET /api/v1/threats/ips` - List active malicious IPs.
*   `GET /api/v1/threats/cves` - Known vulnerability database.
*   `POST /api/v1/threats/block` - Manual IP blocklist injection.

### Data Export
*   `GET /api/v1/export/{peers|alerts|metrics}/csv` - Bulk export.
*   `GET /api/v1/export/peers/json` - JSON dump.

## 💾 Database Integration

To enable persistence, set `DATABASE_URL` and enable the `advanced_reporting` feature.

```bash
# Environment
export DATABASE_URL="postgresql://wolf_admin:pass@postgres:5432/wolf_prowler"

# Run with persistence
cargo run --release --features advanced_reporting
```

**Schema Overview**:
*   `peers`: Identity, Trust Score, Last Seen.
*   `peer_metrics`: Time-series data (Latency, Bytes).
*   `threat_intelligence`: Malicious IPs, CVEs, Confidence Scores.
*   `security_alerts`: Alert state (Active/Resolved), Severity.

## 🔒 Security

*   **Transport**: TLS 1.3 (Self-signed or Custom Certs).
*   **Auth**: JWT Middleware (Configurable).
*   **Performance**: Async connection pooling (max 1000 conns).

## 🚀 Quick Start

```rust
use wolf_server::{ServerConfig, start_server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ServerConfig {
        port: 3031,
        enable_tls: true,
        // PostgreSQL connection string
        database_url: Some(std::env::var("DATABASE_URL")?), 
        ..Default::default()
    };
    
    start_server(config).await?;
    Ok(())
}
```
