# Wolf Prowler Refactoring Plan

This document outlines the roadmap for completing the refactoring of the Wolf Prowler system, specifically focusing on the `wolf_net` crate and the integration of the new `wolf_pack` logic.

## 🎯 Objective

To transition the Wolf Prowler networking layer from a monolithic structure to a modular, actor-based architecture that separates concerns between low-level networking (Swarm), high-level business logic (Wolf Pack), and state management.

## 🗺️ Roadmap

### Phase 1: Core Logic & State Separation (Current Status: In Progress)

- [x] **Define State Models**: Create `wolf_pack/state.rs` for `WolfRole`, `WolfState`, and `ActiveHunt`.
- [x] **Define Messaging**: Create `wolf_pack/messaging.rs` and `wolf_pack/howl.rs` for protocol definitions.
- [x] **Implement Election Logic**: Create `wolf_pack/election.rs` with Raft-like consensus.
- [x] **Implement Coordinator Actor**: Create `wolf_pack/coordinator.rs` to manage the actor loop and message handling.
- [x] **Error Handling**: Create `wolf_pack/error.rs` for domain-specific errors.
- [ ] **State Machine Isolation**: Create `wolf_pack/state_machine.rs` to decouple pure state transitions from the actor.

### Phase 2: Integration & Wiring

- [ ] **Refactor Coordinator**: Update `HuntCoordinator` to use `WolfStateMachine` for logic execution.
- [ ] **Swarm Integration**: Ensure `SwarmManager` correctly routes `Gossipsub` messages to the `WolfNode` -> `HuntCoordinator` pipeline.
- [ ] **WolfNode Wiring**: Verify `WolfNode` initializes the coordinator and handles the bidirectional channel communication correctly.
- [ ] **API Integration**: Connect the `wolf_server` API endpoints to the `HuntCoordinator` via `NodeCommand`s (e.g., triggering a manual hunt or election).

### Phase 3: Testing & Validation

- [ ] **Unit Tests**: Add comprehensive unit tests for `WolfStateMachine` covering all transition edge cases.
- [ ] **Integration Tests**: Create a test simulating a small cluster (3 nodes) to verify election leader selection and failover.
- [ ] **Hunt Simulation**: Verify the full "Scent -> Stalk -> Strike" lifecycle with mocked peers.

### Phase 4: Cleanup & Optimization

- [ ] **Remove Legacy Code**: Deprecate and remove `wolf_net/src/logic.rs` once `wolf_pack` is fully integrated.
- [ ] **Optimize Locking**: Review `Arc<RwLock<WolfState>>` usage to minimize contention.
- [ ] **Documentation**: Update crate-level documentation in `wolf_net/src/lib.rs` to reflect the new architecture.

## 🛠️ Implementation Details

### 1. State Machine Refactor

The `HuntCoordinator` currently contains mixed concerns (actor messaging + business logic). We will move the logic into `WolfStateMachine`:

```rust
// wolf_net/src/wolf_pack/state_machine.rs
pub struct WolfStateMachine;

impl WolfStateMachine {
    pub fn on_warning_howl(state: &mut WolfState, ...) -> Result<...> { ... }
    pub fn on_hunt_report(state: &mut WolfState, ...) -> Result<...> { ... }
}
```

### 2. Coordinator Simplification

The `HuntCoordinator` will become a thin shell:

```rust
// wolf_net/src/wolf_pack/coordinator.rs
async fn handle_warning_howl(&mut self, ...) -> Result<()> {
    let mut state = self.state.write().await;
    WolfStateMachine::on_warning_howl(&mut state, ...)?;
    Ok(())
}
```