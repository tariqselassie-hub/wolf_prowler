# Wolf Pack Architecture: The Hunter-Killer Grid
**Document:** Technical Architecture & Design Specification
**Date:** December 28, 2025
**Role:** Senior Project Developer & Senior Full Stack Developer

---

## 1. Executive Overview

The **Wolf Pack Hunter-Killer Grid** is an autonomous, decentralized threat response system. Unlike traditional "passive" security (block & log), this architecture enables the network to "hunt" adversarial entities. It leverages a biological autoimmune model where nodes (Wolves) autonomously Detect (Scout), Verify (Hunt), and Neutralize (Kill) threats, evolving their status (Prestige) based on performance.

This design prioritizes **Robustness** (Fail-Safe Execution) and **Memory Safety** (Rust Ownership Model) to ensure the system is unkillable and crash-resistant.

---

## 2. Core Architecture

### 2.1 The "Wolf" Entity (Node State)
Each node maintains a local state machine representing its role in the grid. This state is thread-safe and protected via `Arc<RwLock<WolfState>>`.

```rust
pub enum WolfRole {
    Stray,   // Untrusted / New (Can only listen)
    Scout,   // Detector (Can initiate warnings)
    Hunter,  // Verifier (Can participate in active hunts)
    Beta,    // Coordinator (Can authorize local hunts)
    Alpha,   // Leader (Pack strategy & global bans)
    Omega,   // Dev God Mode (Absolute authority, invisible to automated bans)
}

pub struct WolfState {
    pub role: WolfRole,
    pub prestige: u32,               // Evolving metric of trust
    pub active_hunts: Vec<HuntId>,   // Concurrent safe tracking
    pub territory: Vec<IpNetwork>,   // Assigned patrol subnets
}
```

### 2.2 The "Hunt" Lifecycle (State Machine)
A "Hunt" is a transactional operation with strict states. It must be atomic and reversible (roll-back on error).

1.  **Scent (Detection)**:
    *   Scout detects traffic anomaly (e.g., port scan).
    *   Action: Emits signed `WarningHowl(target_ip, evidence)`.
2.  **Stalk (Verification)**:
    *   Hunters subscribed to the territory receive the Howl.
    *   Action: 3+ Hunters probe the target from different IPs (avoiding false positives from single-view).
3.  **Strike (Execution)**:
    *   If Consensus > Threshold (e.g., 66% Hunters confirm):
    *   Action: Global `KillOrder(target_ip)` broadcast.
    *   Result: All nodes update Firewall rules instantly.
4.  **Feast (Evolution)**:
    *   Participating Hunters gain `+Prestige`.
    *   False Reporter (if Hunt fails verification) loses `-Prestige`.

---

## 3. Robust Error System ("The Immortal Pack")

We will implement a custom `WolfPackError` system rooted in `thiserror` but extended for distributed state recovery.

### 3.1 Error Taxonomy
```rust
#[derive(Debug, Error)]
pub enum WolfPackError {
    #[error("Pack Partition: Quorum lost for Hunt {0}")]
    PartitionLost(HuntId),

    #[error("Hunt Timeout: Target {0} evaded verification")]
    HuntTimeout(String),

    #[error("Prestige Insufficient: Node {0} attempted unauthorized howl")]
    UnauthorizedHowl(PeerId),

    #[error("Territory Conflict: {0}")]
    TerritoryOverlap(String),

    #[error("Critical Memory Logic: {0}")]
    MemorySafetyViolation(String), // Should never happen with Safe Rust, but tracked for panic recovery
}
```

### 3.2 "Fail-Safe Hunting" Protocol
*   **Problem**: A Hunter crashes or disconnects mid-hunt.
*   **Solution**:
    *   **Leased Tasks**: Hunts have a TTL (Time-To-Live). If a Hunter doesn't report back in `T` seconds, the task returns to the "Pool" for another node.
    *   **Orphan Cleanup**: A background `GarbageCollector` task scans for stuck Hunt states and rolls them back, ensuring no "zombie hunts" leak memory or lock resources.

---

## 4. Memory Safety Strategy

Rust guarantees memory safety, but we must design for *logical* safety in a highly concurrent async environment.

### 4.1 Concurrency Model (`Actor-Like`)
To avoid deadlocks (the enemy of robustness), we will **NOT** use complex mutex chains.
*   **Design**: `HuntCoordinator` is an independent Actor (Task) communicating via `tokio::mpsc::channels`.
*   **Rule**: State is *owned* by the Coordinator. Other components request mutations via messages (`Msg::StartHunt`, `Msg::ReportResult`).
*   **Benefit**: This eliminates `Data Race` possibilities entirely at the architectural level.

### 4.2 Resource Bounding
*   **Problem**: An attacker floods with fake "scents" to OOM (Out Of Memory) the Wolf nodes.
*   **Defense**:
    *   `Bounded Channels`: All message queues have fixed capacity.
    *   `Hunt Cap`: Max `N` active hunts per node based on available RAM/CPU.
    *   `Prestige Filter`: Low-prestige nodes have strict rate limits on Howls.

---

## 5. Implementation Roadmap (Duo Approach)

**Phase 1: Foundation (Project Dev Focus)**
*   Define `WolfPackError` and `HuntResult` types in `src/core/error.rs`.
*   Implement `WolfState` and Prestige logic in `wolf_net`.

**Phase 2: The Grid (Full Stack Focus)**
*   Implement the P2P `Howl` protocol (encrypted gossipsub).
*   Create the `HuntCoordinator` actor loop.

**Phase 3: Visualization (Full Stack Focus)**
*   Connect Backend `Prestige` updates to `packs.html` via WebSocket.
*   Visualize "Active Hunts" as live operations on the map.

---

This architecture ensures that Wolf Prowler is not just a tool, but a **resilient, self-healing, and evolving security organism**.
