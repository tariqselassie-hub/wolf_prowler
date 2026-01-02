# Implementation Plan - Replace XOR with AES-GCM-SIV

## Goal
Replace the insecure XOR encryption placeholders in `wolf-prowler/src/wolf_prowler_prototype/crypto.rs` with robust AES-256-GCM-SIV encryption, properly managing key material.

## User Review Required
> [!IMPORTANT]
> This change modifies the `CryptoKey` struct to include a `secret` field containing raw key bytes.
> Use `#[serde(skip)]` to prevent accidental serialization of secrets in logs or API responses.
> This implies keys are currently **in-memory only** and will be lost on restart (which matches current behavior).

## Proposed Changes

### `wolf-prowler/src/wolf_prowler_prototype/crypto.rs`

#### [MODIFY] `CryptoKey` struct
- Add `#[serde(skip)] pub secret: Vec<u8>` field.
- Update `new()` constructor to accept `secret`.
- derive `Zeroize` for manual memory clearing if possible (requires adding `zeroize` to imports).

#### [MODIFY] `CryptoEngine::generate_key`
- Generate actual random bytes using `rand::rngs::OsRng` (secure random).
- Size depends on algorithm (32 bytes for AES-256 / ChaCha20).
- Pass these bytes to `CryptoKey::new`.

#### [MODIFY] `CryptoEngine::encrypt` and `CryptoEngine::decrypt`
- Retrieve `secret` from the key.
- Pass `secret` to the internal encryption/decryption methods.

#### [MODIFY] `simulate_encrypt` -> `perform_encrypt`
- Rename method.
- Accept `key: &[u8]` argument.
- Use `aes_gcm_siv` crate for AES-GCM.
- Use `chacha20poly1305` if requested (or fallback/error if crate not available, but `wolf_net` used `ring` for this? `wolf-prowler` has `aes-gcm-siv`).
- **Correction**: `wolf-prowler` Cargo.toml lists `aes-gcm-siv`. It does NOT list `chacha20poly1305`.
- **Decision**: Implement `AES256GCM` using `aes-gcm-siv`. For `ChaCha20Poly1305`, I should either add the dependency or temporarily map it to AES (bad) or error.
- Checking `wolf-prowler` Cargo.toml again... `aes-gcm-siv` is there.
- I'll add `chacha20poly1305` dependency if needed, or stick to implementing AES-GCM as the primary fix requested ("Replace XOR ... with AES-GCM").

#### [MODIFY] `simulate_hash` -> `perform_hash`
- Rename method.
- Use `sha2` crate (present in Cargo.toml) for hashing.

## Verification Plan

### Automated Tests
- Create a new test case in `crypto.rs` (or `test_client.rs`) that:
    1. Generates an AES256GCM key.
    2. Encrypts a sample "Hello World".
    3. Decrypts it back.
    4. Asserts plaintext matches.
    5. Asserts ciphertext is NOT same as plaintext (and looks random).

### Manual Verification
- Run `cargo test -p wolf-prowler` to ensure all crypto tests pass.
