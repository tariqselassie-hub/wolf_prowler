# Wolf Prowler Consolidation Plan

This plan outlines the steps to realign the `wolfsec`, `lock_prowler`, and `tercespot` codebases to eliminate duplication and create a single, unified "Super Dashboard".

## Goal Description
The goal is to simplify the architecture by:
1.  **One Dashboard**: Merging all UI logic into `wolf_web`.
2.  **One Crypto Core**: centralization of cryptographic primitives in `wolf_den`.
3.  **Clear Responsibilities**: Defining strict roles for `wolfsec` (Brain), `tercespot` (Agent), and `lock_prowler` (Tool).

## User Review Required
> [!IMPORTANT]
> **Dashboard Consolidation**: We will retire `lock_prowler_dashboard` as a standalone binary and move its Dioxus components into `wolf_web`. `wolf_web` will be upgraded to Dioxus 0.6 to match.

## Proposed Changes

### 1. Dashboard Unification (`wolf_web`)
The `wolf_web` crate will become the central UI hub.
-   **Upgrade**: Update `wolf_web` to Dioxus 0.6 (Fullstack/LiveView).
-   **Merge**: Import components from `crates/lock_prowler/lock_prowler_dashboard/src` into `wolf_web/src/components/vault/`.
-   **Integrate**: content from `crates/WolfDb/dashboard.html` will be recreated as a Dioxus component `wolf_web/src/components/db/`.
-   **Serve**: `wolf_web` will serve the UI for the entire platform.

### 2. Security Logic Realignment
eliminate duplicate implementations of core logic.

#### `wolf_den` (The Crypto Core)
-   **Action**: Move `lock_prowler/src/crypto.rs` and `wolfsec/src/crypto.rs` logic into `wolf_den`.
-   **Result**: All crates depend on `wolf_den` for signing, hashing, and encryption.

#### `wolfsec` (The Brain)
-   **Responsibility**: IAM, Authentication, Compliance, ML Analysis, SIEM.
-   **Action**: Remove any "file watching" or "daemon" code that overlaps with `tercespot`. Focus on *processing* data, not collecting it.

#### `tercespot` (The Nervous System)
-   **Responsibility**: Distributed Agents, File Watching (`file_watcher.rs`), Pulse Checks (`pulse.rs`).
-   **Action**: Ensure it sends data to `wolfsec` (or WolfDb) for processing, rather than doing heavy analysis locally.

#### `lock_prowler` (The Vault Tool)
-   **Responsibility**: Local Forensics, Vault Management (`vault.rs`), Sharding (`sharding.rs`).
-   **Action**: Refactor to use `wolf_den` for crypto and `WolfDb` for storage.

### 3. Unified Storage (`WolfDb`)
-   **Action**: Replace any remaining CSV/SQLite/Postgres code in `wolfsec` and `lock_prowler` with `WolfDb` client calls.

## Execution Order
1.  **Refactor Crypto**: Move common crypto to `wolf_den`.
2.  **Refactor Storage**: standardization on `WolfDb`.
3.  **Merge Dashboards**: Migrate `lock_prowler` UI to `wolf_web`.
4.  **Cleanup**: Delete consolidated code.
