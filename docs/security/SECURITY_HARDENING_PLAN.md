# Security Hardening Plan: TLS & Event Validation

**Date:** 2026-01-08
**Status:** Complete
**Reference:** GemAnal.md (Section 3)

## 1. Executive Summary
This document outlines the engineering roadmap to remediate the vulnerabilities identified in the recent Security Scan. The primary objectives are to implement support for CA-signed certificates (removing the reliance on self-signed generation in production) and to harden the internal event bus against injection attacks.

## 2. Remediation Tasks

### 2.1. Task A: Production TLS Implementation
**Severity:** High (MITM Risk)
**Owner:** Infrastructure / Core Team

#### Objective
Modify `wolf_server` to accept external TLS certificate paths via configuration, disabling self-signed generation in production environments.

#### Implementation Plan
1.  **Configuration Update (`SecureAppSettings`)**:
    *   Add optional fields: `tls_cert_path` (PathBuf) and `tls_key_path` (PathBuf).
    *   Map these fields to environment variables: `WOLF_TLS_CERT` and `WOLF_TLS_KEY`.
    *   **Status:** Implemented in `crates/wolf_server/src/tls.rs`.

2.  **Startup Logic Refactor (`main.rs`)**:
    *   **Priority Check**: On startup, check if `tls_cert_path` and `tls_key_path` are provided.
    *   **Production Mode**:
        *   If paths are provided: Load certificates. If loading fails, **panic/abort** immediately.
        *   If paths are missing: **Abort startup**. Do not fallback to self-signed certs in production.
    *   **Development Mode**:
        *   If paths are missing: Log a warning and proceed with the existing self-signed certificate generation logic.
    *   **Status:** Implemented in `crates/wolf_server/src/main.rs`.

3.  **Certificate Hot-Reloading (Optional)**:
    *   Implement a `SIGHUP` signal handler or a file watcher to reload certificates without restarting the server process.
    *   **Status:** Implemented in `crates/wolf_server/src/main.rs`.

### 2.2. Task B: Network Event Validation (Input Sanitization)
**Severity:** Medium (Spoofing/Injection Risk)
**Owner:** Security Team (`wolfsec`)

#### Objective
Ensure that data entering the `wolfsec` engine from the `wolf_net` layer is strictly validated to prevent internal spoofing or malformed data processing.

#### Implementation Plan
1.  **Validation Middleware**:
    *   Create a new trait or service `EventValidator` within `wolfsec`.
    *   Implement `validate_ingress(event: &NetworkEvent) -> Result<(), SecurityError>`.
    *   **Status:** Implemented in `crates/wolfsec/src/validation.rs`.

2.  **Validation Logic**:
    *   **Source Authenticity**: Ensure the `PeerId` attached to the event matches the cryptographic identity of the sender (leveraging `libp2p` noise handshake results).
    *   **Payload Sanitization**: Scan string fields (e.g., user agents, custom protocol messages) for control characters or excessive length to prevent log injection or buffer issues.
    *   **Schema Enforcement**: Reject events that do not strictly conform to the expected `bincode` or JSON schema.
    *   **Status:** Logic & Tests Implemented.

3.  **Integration**:
    *   Inject the `EventValidator` into the main event loop in `main.rs` before the event is passed to `WolfSecurity::process_event`.
    *   Log any validation failures to the audit trail with a specific threat tag (e.g., `INTERNAL_SPOOF_ATTEMPT`).
    *   **Status:** Implemented in `crates/wolf_server/src/main.rs`.

### 2.3. Task C: Security Event Persistence
**Severity:** Medium (Audit/Compliance)
**Owner:** Backend Team

#### Objective
Ensure all security events and alerts are persisted to `WolfDb` for audit trails and historical analysis.

#### Implementation Plan
1.  **Repository & Integration**:
    *   Implement `WolfDbThreatRepository` in `wolfsec` and connect it via `wolf_server`.
    *   **Status:** Implemented in `wolf_server/src/wolfsec_integration.rs` and `wolfsec/src/store.rs`.
    *   **Verification:** Unit test `test_security_event_persistence` passed.

2.  **API Access**:
    *   Implement endpoint to retrieve historical alerts.
    *   **Status:** Implemented `get_alerts_history` in `wolf_server/src/api.rs`.

## 3. Verification & Testing Strategy

### 3.1. TLS Verification
| Test Case | Environment | Expected Outcome |
| :--- | :--- | :--- |
| Start with valid CA certs | Prod | Server starts, browser trusts connection |
| Start with invalid paths | Prod | Server crashes (Exit Code 1) |
| Start with no certs | Prod | Server crashes (Exit Code 1) |
| Start with no certs | Dev | Server starts, generates self-signed cert |
| SIGHUP Signal | Docker | Logs confirm "Reloading TLS certificates" |

### 3.2. Event Validation Verification
*   **Fuzz Testing**: Use `cargo-fuzz` to send malformed byte sequences to the network event handler.
*   **Spoof Simulation**: Create a unit test where a mock peer attempts to send an event attributed to `PeerId::Admin` without a valid signature. Assert that `validate_ingress` returns `Err`.

## 4. Timeline

*   **Sprint 1 (Days 1-2)**:
    *   Update `SecureAppSettings` and `main.rs` TLS logic.
    *   Draft `EventValidator` trait.
*   **Sprint 1 (Days 3-5)**:
    *   Implement validation logic and unit tests.
    *   Integration testing with `wolf_net` mock swarm.
*   **Review**: Code audit by Security Architect before merge.