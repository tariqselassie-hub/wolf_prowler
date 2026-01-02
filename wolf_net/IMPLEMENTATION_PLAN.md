# Wolf Net Implementation Plan

This document outlines the phased plan to complete the P2P network protocol implementations for the `wolf_net` crate, moving from placeholder TODOs to a fully functional and integrated networking layer.

## Phase 1: The Foundational Approach (Core `libp2p` Integration)

**Goal:** Establish a baseline of a functional, secure P2P network capable of peer discovery and basic pub/sub messaging.

**Steps:**
1.  **Fix Compilation Errors:** Resolve compilation issues by updating the `NetworkBehaviour` struct in `behavior.rs` to conform to the `libp2p v0.53` API.
2.  **Implement `PeerInfo` Status:** Address the `todo!()` in `peer.rs` by defining an initial peer status (e.g., `Discovered`, `Connecting`).
3.  **Activate Core `libp2p` Behaviours:**
    -   **Kademlia (Kad):** Implement logic to join the Kademlia DHT for peer discovery.
    -   **Gossipsub:** Define a primary topic (e.g., `wolf-prowler-global`) for general announcements.
    -   **mDNS:** Enable for local network discovery.
4.  **Integrate `NetworkSecurity`:** Utilize `wolf_net/src/security.rs`. All outgoing `gossipsub` messages must be wrapped in a `SignedEnvelope`, and all incoming messages must be verified.
5.  **Build the `NetworkManager` Event Loop:** Create the main loop to poll the `libp2p` Swarm for events and log them to prove functionality.

---

## Phase 2: The Enhanced Reliability Approach (Adding Request-Response)

**Goal:** Implement a reliable, two-way communication channel for specific commands between individual peers.

**Steps:**
1.  **Complete all steps from Phase 1.**
2.  **Implement the `Request-Response` Protocol:**
    -   Define the specific `Request` and `Response` message structs (e.g., `enum NetworkRequest { GetPeerStatus }`).
    -   Create a `RequestResponseCodec` to handle serialization.
3.  **Integrate into `NetworkBehaviour`:** Add the `libp2p::request_response::Behaviour` to the custom `NetworkBehaviour` struct.
4.  **Expose `NetworkManager` API:** Add functions to `NetworkManager` like `send_request(&self, peer_id: PeerId, request: NetworkRequest)` and handle events in the main loop.

---

## Phase 3: The Advanced Integration Approach (Connecting to `wolfsec`)

**Goal:** Create a seamless, two-way communication bridge between the `wolf_net` and `wolfsec` modules.

**Steps:**
1.  **Complete all steps from Phase 2.**
2.  **Establish Inter-Crate Communication:** Use `tokio::sync::mpsc` channels to link `NetworkManager` (`wolf_net`) and `WolfSecurity` (`wolfsec`).
3.  **Forward Network Events to `wolfsec`:** The `NetworkManager` will listen for relevant network events (e.g., a `SecurityAlert` message) and forward them to `wolfsec` for analysis.
4.  **Execute Commands from `wolfsec`:** The `NetworkManager` will listen for commands sent by `wolfsec` and use the network to execute them.
    -   **Example Command:** `BanPeer(PeerId)` -> `NetworkManager` calls `swarm.ban_peer_id(peer_id)`.
    -   **Example Command:** `QueryPeer(PeerId, Query)` -> `NetworkManager` uses the `request-response` protocol.