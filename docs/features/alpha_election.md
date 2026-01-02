# Alpha Election System

## Overview
The Alpha Election system in Wolf Prowler is a decentralized consensus mechanism designed to select a leader (Alpha) for the Wolf Pack. It uses a modified Raft algorithm that incorporates "Prestige" as a weighting factor, ensuring that the most reputable and capable nodes assume leadership roles.

## Core Concepts

### 1. Election States
Nodes in the Wolf Pack can be in one of three states relative to the election:
- **Follower**: Passive state. Listens for heartbeats from the Alpha.
- **Candidate**: Active state. Solicits votes from peers to become the Alpha.
- **Leader (Alpha)**: Authorities state. Manages the pack and sends periodic heartbeats.

### 2. Prestige Weighting
Unlike standard Raft where all votes are equal, Wolf Prowler favors high-prestige nodes.
- When a node receives an `ElectionRequest`, it compares the candidate's prestige against its own and the current leader's.
- This bias effectively "stacks the deck" in favor of more experienced nodes, providing stability and meritocratic leadership.

### 3. Protocol Messages
Three key message types facilitate the election (defined in `wolf_net/src/wolf_pack/howl.rs`):
- `ElectionRequest`: Sent by a Candidate to request votes. Includes `term`, `candidate_id`, and `prestige`.
- `ElectionVote`: Sent by a peer in response to a request, granting or denying the vote.
- `AlphaHeartbeat`: Broadcast by the Leader to assert authority and prevent new elections.

## Configuration
The election behavior is controlled by several parameters in `ElectionManager` (`wolf_net/src/wolf_pack/election.rs`):
- **Election Timeout**: Randomized (e.g., 150-300ms) to reduce split vote collisions.
- **Heartbeat Interval**: Fixed interval (e.g., 50ms) to maintain authority.
- **Quorum**: Currently requires a simple majority (or self-vote in small clusters).

## Architecture
The `ElectionManager` is the core state machine, but it is integrated into the `HuntCoordinator` actor.
1. `HuntCoordinator` receives P2P messages via `SwarmManager`.
2. It delegates election-specific messages to `ElectionManager::handle_howl`.
3. It calls `ElectionManager::tick()` periodically to drive timeouts and state transitions.
4. Outgoing messages (votes, requests, heartbeats) are routed back through `SwarmManager` for broadcast.

## Future Improvements
- **Dynamic Quorum**: Adjust quorum size based on active peer count.
- **Prestige Decay details**: Tying election weight to the specific decay mechanics of the Prestige System.
- **Term Persistence**: Storing `current_term` and `voted_for` to disk to survive restarts.
