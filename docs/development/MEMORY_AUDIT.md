# Memory & Performance Audit: "Clone Wars"

**Date:** December 23, 2025
**Auditor:** Gemini Code Assist

## 1. Audit Goal

Identify and reduce expensive cloning operations (`.clone()` on heap-allocated types like `String` and `Vec<T>`) to improve performance and reduce memory pressure, as outlined in `BACKEND_OPTIMIZATION.md`.

## 2. Key Findings & Optimizations

### High-Impact Finding: Entity Constructors

- **Observation**: The `Alert::new` constructor required owned `String` types for its arguments (`title`, `description`, `source`). This forced calling code, such as the `ThreatAnalyzer` service, to perform a `.clone()` on its data just to create a new `Alert`.
- **Optimization**: The `Alert::new` function signature was modified to use generics with an `impl Into<String>` trait bound.
    - **Before**: `fn new(title: String, ...)`
    - **After**: `fn new(title: impl Into<String>, ...)`
- **Benefit**: This change allows the function to accept `&str`, `String`, or any other type that can be converted into a `String`. The caller no longer needs to clone. In the case of `ThreatAnalyzer`, we can now pass a reference `&threat.description` directly, eliminating a heap allocation and memory copy.

### Application Layer Commands/DTOs

- **Observation**: Command structs like `CreateAlertCommand` and `RegisterUserCommand` were defined with owned `String` fields. This is inefficient when the data already exists and is owned by another struct (like an Axum JSON payload).
- **Optimization**: The string fields in these command structs were changed from `String` to `Cow<'a, str>`. This allows the command to be constructed with borrowed string slices (`&str`) when the data is available, avoiding a clone. When owned data is necessary (e.g., for sending to another thread), it can be constructed with `Cow::Owned(String)`.
- **Benefit**: In API handlers, we can now construct commands using `Cow::Borrowed(&payload.field)`, which is a zero-copy operation for the string data, improving request handling performance.

### Vector Allocations

- **Location**: `wolfsec/src/infrastructure/services/wolf_den_cryptography_provider.rs`
- **Observation**: The `decrypt` method was cloning the ciphertext vector and then extending it with the tag. This caused a potential double allocation (one for clone, one for extension if capacity was exceeded).
- **Optimization**: Replaced with `Vec::with_capacity` followed by two `extend_from_slice` calls. This ensures exactly one allocation of the correct size.

- **Location**: `wolf_server/src/main.rs` (`get_peers` handler)
- **Observation**: The handler was creating an intermediate `Vec<PeerId>` by cloning IDs from the swarm list, iterating over it to update the pack, and then mapping it again to `Vec<String>`.
- **Optimization**: Refactored to iterate over the source list once, updating the pack and collecting strings into a pre-allocated vector in a single pass. Removed the intermediate vector and cloning.

- **Location**: `wolfsec/src/infrastructure/services/wolf_den_cryptography_provider.rs` (`encrypt` method)
- **Observation**: The `encrypt` method was splitting the ciphertext (which includes the tag) using `split_at`, then calling `to_vec()` on both parts. This caused a deep copy of the entire ciphertext body.
- **Optimization**: Changed to use `Vec::split_off`. This keeps the ciphertext body in the original vector (truncating it) and only allocates a new vector for the small 16-byte tag.

### Acceptable Clones (For Now)

#### Anti-Corruption Layers
- **Location**: `wolfsec/src/infrastructure/services/legacy_threat_detector.rs`
- **Observation**: Multiple `.clone()` calls exist when converting from the new `domain::entities::SecurityEvent` to the old `crate::SecurityEvent`.
- **Rationale**: This is an **Adapter** or **Anti-Corruption Layer**. Its purpose is to translate between the new, clean architecture and the legacy implementation. The cost of cloning here is an explicit trade-off we make to keep the two systems decoupled. As we migrate away from the legacy code, these clones will naturally be eliminated. **No action is required here.**

#### Releasing Locks Quickly
- **Location**: `wolf_server/src/main.rs` (e.g., `get_logs`, `get_config` handlers)
- **Observation**: Handlers lock a `Mutex`, clone the data inside, and immediately drop the lock (e.g., `state.logs.lock().await.clone()`).
- **Rationale**: This is a correct and important concurrency pattern. It prevents holding a lock for a long time (e.g., during JSON serialization), which would block other tasks. While the `.clone()` has a cost, it is often less than the cost of blocking the entire system. The log buffer is capped at 200 entries, making this clone acceptable for now. **No action is required here.**

## 3. Next Steps

- [x] Apply the `impl Into<String>` or `Cow<'a, str>` pattern to other entity constructors and DTOs.
- [x] Audit `Vec<T>` cloning, especially in loops, and replace with iterators or references where possible.
- [ ] For data that is read far more often than it is written, consider using `Arc<T>` or `Cow<'a, T>` to avoid clones on read paths.