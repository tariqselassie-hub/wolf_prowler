# Wolf Prowler – Project Roadmap

_Last updated: 2025-12-10_

---

## 1  Current Feature Matrix

| Area | Crate / Folder | Status | Notes |
|------|----------------|--------|-------|
| **Core IDs** | `wolf_net::peer` | ✅ stable | PeerId, DeviceId, ServiceId, SystemId, EntityId/Info |
| **Networking** | `wolf_net::swarm` + `behavior` | ✅ compiling | Ping, Identify, Gossipsub, TCP/Noise/Yamux |
| **Discovery** | `wolf_net::discovery` | ✅ basic | MDNS + DHT scaffolding |
| **Security** | `wolf_net::security` | ✅ helper structs | EncryptionType, SecurityLevel, KeyExchange enum |
| **CLI Demo** | `wolf_net::main` | ⚠️ builds, demo stubs | Entity demo, TODO: NAT / ping demo functions |
| **Crypto Engine** | `wolf_den` | ✅ compiles (warnings) | Signing / MAC / KDF helpers |
| **Dashboard (Web)** | `wolf_dashboard` (to locate) | ⚠️ scaffold | Needs real-time data wiring |

---

## 2  Quick-Win Improvements (≤ 2 days)

* Expose a **local HTTP/WS API** from `wolf_net` for metrics & peer list.
* Wire dashboard components to the API (React/Tauri or Yew).
* Display:
  * Local Peer-ID & version.
  * Connected peers table with RTT, trust.
  * Traffic counters (bytes, msgs).
* Add **unit tests** for `peer` helper methods.
* Silence easy compiler warnings (unused imports, recursion getters).

---

## 3  Medium Items (≤ 2 weeks)

* **NAT detection & AutoNAT** protocol integration.
* File-transfer protocol over Gossipsub / bitswap.
* **Reputation engine** fed by EntityInfo trust_score.
* Persist peer database to disk (sled / sqlite).
* Docker compose for multi-node local network demo.

---

## 4  Larger Roadmap (2026-Q1)

* **WebRTC / QUIC** transport option (mobile + browser peers).
* Cross-platform mobile SDK (Swift/Kotlin wrappers around wolf_net via FFI).
* Distributed **service registry** & discovery UI.
* End-to-end **encrypted inbox** with forward-secure ratcheting.
* Performance / load testing harness.

---

## 5  Open Design Questions

1. **API Layer** – gRPC vs REST vs GraphQL?  
2. **Persistent storage** – sled vs sqlite vs postgres.
3. **Auth model** – JWT vs macaroons vs custom token.

Feedback welcome!
