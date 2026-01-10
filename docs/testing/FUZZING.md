# Fuzzing Wolf Prowler

Wolf Prowler employs automated fuzz testing to ensure robustness and security against malformed inputs. We leverage `libafl` components to generate test cases for critical system boundaries.

## Fuzzing Architecture

The fuzzing infrastructure is located in the `wolf_fuzz` crate and targets three key areas:

1.  **Cryptography (`fuzz_crypto`)**: Targets `wolf_den` primitives (Hashing, MAC, Key Derivation).
2.  **Networking (`fuzz_net`)**: Targets `wolf_net` message deserialization and protocol parsing.
3.  **Security (`fuzz_security`)**: Targets `wolfsec` event ingestion and validation logic.

## Running Fuzzers

A convenience script is provided to build and run all fuzzers in a "smoke test" mode (finite iterations):

```bash
./scripts/run_fuzzers.sh
```

### Continuous Fuzzing

To run a specific fuzzer continuously (e.g., for finding deep bugs), run the binary directly:

```bash
# Run Crypto Fuzzer
cargo run -p wolf_fuzz --bin fuzz_crypto

# Run Network Fuzzer
cargo run -p wolf_fuzz --bin fuzz_net

# Run Security Fuzzer
cargo run -p wolf_fuzz --bin fuzz_security
```

*Note: The current configuration runs for a fixed number of iterations (1000) for CI compatibility. To enable infinite fuzzing, modify the loop condition in the respective source files in `wolf_fuzz/src/`.*

## CI Integration

The `run_fuzzers.sh` script is designed to be integrated into the CI pipeline. It returns exit code 0 if all fuzzers run without panicking, ensuring that basic stability is maintained.

## Coverage

Fuzzing targets the following high-risk interfaces:
- `wolf_den::CryptoEngine` public API.
- `wolf_net::Message` JSON deserialization.
- `wolfsec::SecurityEvent` construction and validation.
