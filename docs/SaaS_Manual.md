# Wolf Prowler SaaS Manual - Hub & Agent Orchestration

## 🐺 Overview

Wolf Prowler has evolved from a standalone security tool into a **Multi-Tenant SaaS Platform**. The system now supports a **Central Hub** architecture where decentralized **Headless Agents** can securely register, receive security policies, and report telemetry—all isolated by organizational context.

---

## 🏗️ Architecture: Hub & Spoke

The platform now operates in two primary modes:

1. **Hub Mode** (Full Node): The central command center that manages multiple organizations, handles agent registrations, and provides a multi-tenant administrative dashboard.
2. **Agent Mode** (Headless): A lightweight security probe that runs on remote assets. It "phones home" to the Hub, periodically reporting metrics and critical security events.

### Security Layers

- **Organizational Isolation**: Every data point (peer, alert, metric) is strictly bound to a `org_id`.
- **Bootstrap Key (`X-Org-Key`)**: Used for the initial "handshake" between an agent and the Hub.
- **JWT Authentication**: Agents exchange their org key for a temporary JSON Web Token (JWT) for all subsequent telemetry reporting.

---

## 🚀 Setting Up an Organization

### 1. Create Organization (Hub Dashboard)

Log in to the **Omega Dashboard** as a super-admin and navigate to **Hub Management**.

- Click **New Organization**.
- Provide a name (e.g., "Acme Global") and an optional admin email.
- **Save the Bootstrap API Key** (e.g., `WOLF-ABCD-1234-XYZ`). This is required to onboard agents.

### 2. View Organization Stats

The Hub tracks live metrics for each organization:

- **Agent Count**: Number of active headless probes.
- **Critical Alerts**: Aggregated high-severity events across the entire organization.
- **Key Rotation**: Capability to rotate or revoke organizational access.

---

## 🧥 Headless Agent Deployment

Headless agents are designed to run in environments where a full UI is not required (e.g., servers, containers, IoT devices).

### Compilation

Build the binary with the `headless-agent` feature to strip the internal web server and GUI:

```bash
cargo build --release --features headless-agent,advanced_reporting
```

### Configuration (`settings.toml` or `.env`)

An agent requires the Hub's URL and its assigned Organization Key:

```toml
[dashboard]
hub_url = "https://central-hub.wolfprowler.com:3031"
org_key = "WOLF-ABCD-1234-XYZ"
```

### Lifecycle

1. **Registration**: On startup, the agent registers itself with the Hub. It receives a persistent `peer_id` and unique identity.
2. **Login**: The agent authenticates using the `org_key` to receive a JWT.
3. **Policy Fetch**: The agent downloads its organization-specific Security Policy (e.g., which ML models to use, what to block).
4. **Reporting**: Every 10 seconds, telemetry is batched and sent via the secure `ReportingService`.

---

## 🛡️ Security Policies

Hub administrators can define policies that apply to all agents within an organization:

- **Reputation Thresholds**: Minimum prestige required for peers to interact.
- **Firewall Rules**: Organization-wide blocklists.
- **Alerting Sensitivity**: Tuning the ML risk-scoring thresholds.

---

## 📊 Multi-Tenant Monitoring

The Hub's **Omega User** can switch between organizational contexts to view:

- **Scoped Alerts**: See only the threats affecting a specific tenant.
- **Peer Topology**: Visualize the specific network mesh of an organization.
- **Resource Usage**: Track the telemetry volume and resource footprint per org.

---

## 🛠️ Troubleshooting

### Agent "Failed to Authenticate"

- Verify that the `org_key` matches the one generated on the Hub.
- Check that the Hub's `DASHBOARD_SECRET_KEY` is consistent across restarts (required for JWT validation).

### Missing Telemetry

- Ensure the agent has network visibility to the `hub_url`.
- Check agent logs for "JWT Expired" errors; the `ReportingService` should automatically re-authenticate.

---

> [!IMPORTANT]
> The `X-Org-Key` should be treated like a root password. If compromised, rotate the key immediately in the Hub Management UI and update all agent configurations.
