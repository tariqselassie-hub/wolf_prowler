# Container & Cloud Security

Wolf Prowler provides sophisticated runtime protection for containerized environments and cloud infrastructure.

## 🐳 Docker Container Orchestration

**Status**: ✅ Enabled by Default  
**Feature Flag**: `container_security`

Wolf Prowler natively integrates with the Docker daemon to secure container workloads in real-time. It acts as an active "guardian" den, patrolling the runtime environment for threats.

### Key Capabilities

#### 1. Real-Time Scanning
The system connects to the local Docker socket (`/var/run/docker.sock`) to continuously inspect running containers.

*   **Privileged Mode Detection**: Flags containers running with `--privileged` (Risk Score +50).
*   **Host Networking**: Detects containers bypassing network isolation (Risk Score +30).
*   **Sensitive Mounts**: Identifies dangerous volume mounts like `/proc`, `/sys`, or the Docker socket itself (Risk Score +40).
*   **Resource State**: Monitors for OOM (Out of Memory) kills and instability.

#### 2. Risk Assessment (Wolf Den Logic)
Containers are assigned a **Pack Rank** based on their risk score:
*   **Score < 50**: `PackRank::Hunter` (Standard Operation)
*   **Score > 70**: `PackRank::Omega` (High Danger / Investigation Required)

#### 3. Active Response (Isolation)
The `WolfSecurity` engine can issue `isolate_container` commands to:
*   **Stop**: Gracefully terminate a compromised container.
*   **Kill**: Immediately halt a dangerous process.

### Configuration & Micropackaging

This feature is designed for flexibility. It is **enabled by default** for enterprise builds but can be disabled for lightweight IoT deployments.

#### Default Build (With Docker Support)
```bash
cargo build --release
```
*Requires functional Docker environment on the host.*

#### Lightweight Build (No Docker)
To reduce binary size and remove the `bollard` dependency:
```bash
cargo build --no-default-features --features "advanced_reporting,threat_intelligence,ai_capabilities"
```
*Useful for embedded devices where no container runtime exists.*

---

## ☁️ Cloud Integrations (Enterprise)

**Status**: 🚧 Feature Flagged (`cloud_security`)

For cloud-native deployments, Wolf Prowler supports:

*   **AWS**: Security monitoring for EC2 metadata and S3 buckets.
*   **Azure**: Integration with Azure Compute management.
*   **GCP**: Native Google Cloud Platform authentication and resource tracking.

## ☸️ Kubernetes (Enterprise)

**Status**: 🚧 Staged (`container_security` + Config)

Future roadmap includes full K8s API integration for pod-level security context constraints (SCC) and RBAC auditing.
