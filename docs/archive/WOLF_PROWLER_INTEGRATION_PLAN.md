# Wolf Prowler Integration & Build Fix Plan

**Objective:** Integrate `wolf_net`, `wolfsec`, and `wolf_den` modules into the main `wolf_prowler` application, ensuring all features are enabled and compilation issues are resolved.

## 1. Workspace & Dependency Management
- [x] **Workspace Setup**: Verify root `Cargo.toml` includes `wolf_prowler`, `wolfsec`, `wolf_net`, and `wolf_den` as members.
- [x] **Crate Dependencies**:
    - Ensure `wolf_prowler` depends on `wolfsec`, `wolf_net`, `wolf_den`.
    - Ensure `wolfsec` has necessary dependencies (e.g., `uuid`, `chrono`, `anyhow`, `tokio`, `serde`, `libp2p`).
- [x] **Version Alignment**: Synchronize versions of common dependencies (especially `tokio`, `uuid`, `serde`, `chrono`, `libp2p`) across all crates to avoid type mismatch errors.

## 2. Module Resolution (Fixing `crate::wolf_pack` errors)
- [x] **Locate `wolf_pack`**: The `wolfsec` code currently references `crate::wolf_pack` (e.g., in `container_security/mod.rs`).
    - *Diagnosis*: `wolfsec` expects `wolf_pack` to be a module within itself.
    - *Action*: If `wolf_pack` logic resides in `wolf_den` or a separate crate, update `wolfsec` imports to use the external crate (e.g., `use wolf_den::hierarchy::...`) and add it to `wolfsec/Cargo.toml`.
    - *Action*: If `wolf_pack` is missing, restore the module structure in `wolfsec/src/wolf_pack/`.

## 3. WolfSec Integration
- [x] **Public API Exposure**: Ensure `ContainerSecurityManager` and its config structs in `wolfsec` are `pub` and accessible to `wolf_prowler`.
- [x] **Configuration Mapping**: Create a mapping from `wolf_prowler`'s configuration (TOML/Env) to `ContainerSecurityConfig`.
- [x] **Initialization**:
    - In `wolf_prowler/src/main.rs`, initialize `ContainerSecurityManager::new(config)`.

## 4. WolfNet & WolfDen Integration
- [x] **WolfDen Wiring**:
    - Ensure `WolfDenContainerManager` in `wolfsec` is correctly using types from the `wolf_den` crate.
    - Verify `WolfDenConfig` availability and instantiation.
- [x] **WolfNet Wiring**:
    - Initialize `wolf_net` P2P stack.
    - Connect network events to `ContainerNetworkPolicyManager` in `wolfsec`.
    - Ensure `PeerId` types match between `wolf_net` and `wolfsec`.

## 5. Feature Restoration & Compilation Fixes
- [ ] **Restore Missing Modules**: If any files were moved to `backup/` during cleanup, restore essential logic for `wolf_pack` hierarchy if it is not present in `wolf_den`.
- [x] **Fix Imports**: Run `cargo check` and systematically fix `use` statements, particularly those referencing `crate::wolf_pack` inside `wolfsec`.
- [x] **Async Runtime**: Ensure `wolf_prowler` sets up the `tokio` runtime correctly to support the async methods in `ContainerSecurityManager`.

## 6. Verification Steps
- [ ] Run `cargo check --workspace` to verify type checking across all modules.
- [ ] Run `cargo build --bin wolf_prowler` to verify binary compilation.
- [ ] Run `cargo test --all` to ensure logic integrity.

## 7. Immediate Action Items (Code Level)
1.  **Fix `wolfsec` Imports**:
    - Open `wolfsec/src/security/advanced/container_security/mod.rs`.
    - Change `use crate::wolf_pack::hierarchy::{PackRank, WolfDenConfig};` to point to the correct crate (likely `wolf_den` or `wolf_pack` if it exists as a dependency).
2.  **Fix `wolfsec` Cargo.toml**:
    - Add `wolf_den` (or `wolf_pack`) as a dependency.
3.  **Main Entry Point**:
    - Update `wolf_prowler/src/main.rs` to instantiate the security manager.

## 8. Critical Fix: Cyclic Dependency Resolution
- [ ] **Identify Cycle**: `wolf_net` depends on `wolfsec` (likely for security types), and `wolfsec` depends on `wolf_net` (for P2P types).
- [ ] **Move Logic**: Move `wolf_pack` (hierarchy/roles) from `wolfsec` to `wolf_net` as requested.
- [ ] **Break Dependency**: Remove `wolfsec` from `wolf_net`'s dependencies. `wolf_net` should be lower-level than `wolfsec`.
- [ ] **Refactor**: Update `wolfsec` to import `wolf_pack` from `wolf_net`.