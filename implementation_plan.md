# implementation_plan.md - Consolidated TODO Resolution

## Goal
Systematically resolve all outstanding `TODO` and `FixMe` items identified in the codebase to achieve true "Production Readiness". We prioritize stability (fixing broken tests/bugs) over new feature implementation.

## User Review Required
None at this stage, proceeding with standard cleanup protocols.

## Proposed Changes

### Phase 1: Critical Identity & PKI Fixes (WolfSec)
**Goal**: Resolve known bugs in the Identity module that cause test failures or functional errors.
- [ ] **Fix Chain Validation**: `wolfsec/src/identity/key_management.rs`
    - The test fails because test certificates are self-signed and not properly anchored to a trusted root for the test context.
- [ ] **Fix PKCS12 Export**: `wolfsec/src/identity/key_management.rs`
    - Fix the key mismatch error during export.
- [ ] **X.509 Parsing Integration**: `wolfsec/src/identity/iam/identity_providers.rs`
    - Replace stub with `wolf_den::certs` integration.

### Phase 2: Infrastructure Cleanup
**Goal**: Remove legacy dependencies and hardcoded values.
- [ ] **Remove PostgreSQL**: `wolfsec/Cargo.toml` & `wolf_server/Cargo.toml`
    - Remove `sqlx` and related dependencies now that `WolfDb` is the standard.
- [ ] **Dynamic Versioning**: `src/startup_validation.rs`
    - Replace hardcoded "0.1.0" strings with `env!("CARGO_PKG_VERSION")`.

### Phase 3: Core Security Logic
**Goal**: functionality to empty stubs in the critical path.
- [ ] **Blocking Logic**: `wolfsec/src/application/advanced_manager.rs`
    - Implement `block_peer` using `wolf_net` firewall integration.
- [ ] **ML Inference**: `wolfsec/src/protection/ml_security/`
    - Connect `isolation_forest.rs` and `threat_classifier.rs` to `linfa` or `ort` runtime.
    - Implement SHAP value calculation stub.

### Phase 4: Advanced Features (Nice to Have)
**Goal**: Complete "Enterprise" feature set.
- [ ] **PDF Reports**: `wolfsec/src/observability/adv_reporting.rs`
- [ ] **Container Scanning**: `wolfsec/src/protection/devsecops/container_security.rs`
- [ ] **SBOM Validation**: `wolfsec/src/protection/sbom_validation.rs`

## Verification Plan

### Automated Tests
- Run `cargo test -p wolfsec --lib identity` to verify PKI fixes.
- Run `cargo build` to ensure no dependency breakages after removing Postgres.
