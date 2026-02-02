# Wolf Net - Implementation Gaps

## High Priority
- [ ] **Application Layer Encryption**: Integrate `wolf_den` to encrypt message payloads before transmission.
- [ ] **Peer Status Management**: Implement state machine for `PeerInfo` (Connecting -> Online -> Offline).
- [ ] **Metrics Calculation**: Implement real logic for latency and connection duration in `metrics_simple.rs`.

## Medium Priority
- [ ] **Message Routing**: Optimize gossipsub topics and routing logic.
- [ ] **Connection Health**: Improve heartbeat and idle connection pruning.
- [ ] **API Integration**: Ensure all `SwarmCommand`s are accessible via the Dashboard API.