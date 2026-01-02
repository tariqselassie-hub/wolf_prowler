# Wolf Prowler SaaS Migration Strategy

This document outlines the transition of the Wolf Prowler security suite into a **Security-as-a-Service (SaaS)** model. We are moving from a standalone "fat node" architecture to a **Hub-and-Spoke** model.

## 🐺 The Architecture Split

The system will be split into two distinct components:

### 1. The Central SaaS Hub (The "Control Plane")
The Hub is the multi-tenant brain of the operation, hosted by the provider.

*   **Responsibilities:**
    *   **Unified Dashboard**: A single glass pane for users to view all their agents.
    *   **Multi-tenant CRM/Auth**: Managing user registrations, organization IDs, and permissions.
    *   **SIEM Aggregator**: Receives security events from all distributed agents for correlation.
    *   **Managed Wolf Brain (AI)**: Centralized high-performance LLM inference to reduce agent compute requirements.
    *   **License/Usage Management**: Tracking agent counts and data throughput.
*   **Infrastructure:** Distributed PostgreSQL, Redis for caching, and high-availability API gateway.

### 2. The Headless Agent (The "Data Plane")
The Agent is what the user downloads and runs on their local servers or cloud clusters.

*   **Responsibilities:**
    *   **Network Introspection**: High-speed packet analysis and territory scanning.
    *   **P2P Swarm Formation**: Peer discovery and local pack coordination.
    *   **Local Mitigation**: Executing firewall rules and dropping malicious connections locally.
    *   **Hub Reporting**: Periodically pushing health, metrics, and alerts to the Central Hub via a Secure mTLS tunnel.
*   **Attributes:** Lightweight, headless, low-dependency, and containerized.

---

## 🛠️ Implementation Phases

### Phase 1: Agent Decoupling (Current Focus)
*   **[ ] API Key Provisioning**: Agents must be authenticated via a unique `ORG_KEY` to talk to the Hub.
*   **[ ] Headless Build Profile**: Create a Cargo feature flag `headless-agent` that excludes the embedded dashboard files and local API handlers from the binary.
*   **[ ] Reporting Client**: Implement a background service in the agent that "phones home" to the Hub URL.

### Phase 2: Central Hub Infrastructure
*   **[ ] Multi-tenancy Support**: Update the DB schema to include `org_id` on every table (Peers, Alerts, Events).
*   **[ ] External Dashboard Hosting**: Decouple the `wolf_web` static files to run as a standalone React/Next.js frontend.
*   **[ ] Agent Orchestration API**: Create endpoints for agents to register and fetch security updates.

### Phase 3: SaaS Features
*   **[ ] Global Threat Intelligence**: Aggregated threat feeds shared across all organization nodes.
*   **[ ] AI-as-a-Service**: Offloading `LlamaClient` calls from the agent to the Hub.

---

## 🚀 Efficient Deployment (Docker)

### Updated Agent Docker Configuration
The **Agent** will be deployed using a streamlined `docker-compose.yml`:

```yaml
version: '3.8'
services:
  wolf_agent:
    image: wolfprowler/agent:latest
    environment:
      - WOLF_HUB_URL=https://hub.wolfprowler.com
      - WOLF_ORG_KEY=${WOLF_ORG_KEY}
      - P2P_PORT=3030
    ports:
      - "3030:3030"
    volumes:
      - ./keys:/app/keys
    restart: always
```

---

## 📅 Roadmap to SaaS Launch
1.  **Beta 1**: Headless Agent connecting to a hardcoded Hub endpoint.
2.  **Beta 2**: Multi-tenant UI for the Hub.
3.  **Production**: Dynamic Agent provisioning and billing integration.
