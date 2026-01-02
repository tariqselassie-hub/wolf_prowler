# Networking Features

Wolf Prowler's networking layer is built for resilience, speed, and decentralization.

## Protocols & Transport

- **P2P Core**: Built on `libp2p` with Gossipsub, Kademlia DHT, and mDNS discovery.
- **HyperPulse (QUIC)**: High-throughput, low-latency transport for large data transfers.
- **Noise Protocol**: End-to-end encrypted tunnels for all inter-node communication.
- **Yamux Multiplexing**: Efficient stream management over single connections.

## Distributed Systems

- **Raft Consensus**: Distributed state machine for cluster-wide configuration and consistency.
- **Persistent Storage**: `sled` embedded database for node state and consensus logs.
- **GeoIP Integration**: Real-time geolocation of peer nodes via external telemetry.
