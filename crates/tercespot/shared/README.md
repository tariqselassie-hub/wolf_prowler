# Shared Crate

Common types, constants, and cryptographic utilities for the TersecPot ecosystem.

## Contents
*   **Constants**: Key sizes (`SIG_SIZE`, `PK_SIZE`) for ML-DSA-44 and ML-KEM-1024.
*   **Crypto Helpers**: Wrappers for `fips204` (Sign/Verify) and `fips203` (Encap/Decap).
*   **Policy Types**: Structs for RBAC policy definitions (`Policy`, `Role`).

## Standards
*   **Signing**: NIST FIPS 204 (ML-DSA-44).
*   **Encryption**: NIST FIPS 203 (ML-KEM-1024) + AES-256-GCM.
