// /home/t4riq/Desktop/Rust/wolf_prowler/docs/ERROR_HANDLING_STRATEGY.md
# Error Handling Standardization Strategy

**Date:** December 23, 2025
**Auditor:** Gemini Code Assist

## 1. Goal

To standardize error handling across the Wolf Prowler workspace, improving ergonomics, maintainability, and observability. This follows the recommendation in `BACKEND_OPTIMIZATION.md`.

## 2. Core Principles

- **Libraries (`wolf_den`, `wolf_net`, `wolfsec` domain/infra):** Use `thiserror` to create specific, structured error enums. This allows callers to match on specific error types.
- **Applications (`wolf_server`, `wolf_control`, `wolfsec` application layer):** Use `anyhow` for easy error propagation and adding contextual information.

## 3. Implementation Plan

### Step 1: Library Error Refactoring (`thiserror`)

- **Target:** `wolfsec/src/lib.rs` -> `WolfSecError`
    - **Action:** Replace the manual `impl Display` and `impl Error` with `#[derive(Error)]` from `thiserror`. Use `#[error("...")]` attributes on each variant.
    - **Status:** **DONE**

- **Target:** `wolf_den/src/error.rs` -> `Error`
    - **Action:** Refactor the complex, manual `Error` enum to use `thiserror`. This will significantly reduce boilerplate code.
    - **Status:** **DONE**

### Step 2: Application Error Propagation (`anyhow`)

- **Audit Target:** All `async fn` handlers in `wolf_server` and `wolfsec/src/application`.
- **Action:** Ensure that any fallible operation (that returns a `Result`) is followed by `.context("Descriptive message")` from the `anyhow::Context` trait. This provides a clear stack trace of *what* was being attempted when an error occurred.
- **Status:** **Mostly complete.** The new application layer handlers in `wolfsec` already follow this pattern. A full audit of legacy code is pending.

### Step 3: Consistent Error Responses in APIs

- **Target:** `wolf_server/src/main.rs` API handlers.
- **Action:** Standardize all error responses to return a consistent JSON object, e.g., `{ "error": "message" }`. The current implementation is already good, but this should be formalized as a best practice.
- **Status:** **Good.** The current implementation converts errors to JSON responses with appropriate status codes.

## 4. Example: `WolfSecError` Refactoring

**Before:**
```rust
#[derive(Debug)]
pub enum WolfSecError {
    InitializationError(String),
    // ...
}
impl std::fmt::Display for WolfSecError { /* ... */ }
impl std::error::Error for WolfSecError {}
```

**After:**
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WolfSecError {
    #[error("Initialization Error: {0}")]
    InitializationError(String),
    // ...
}
```