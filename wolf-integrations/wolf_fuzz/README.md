# Wolf Fuzz: Advanced Fuzzing Suite

> **Status**: Experimental / Internal
> **Engine**: LibAFL (Library for Automated Fuzzing)
> **Targets**: Crypto, Network, Security Logic

Wolf Fuzz is a specialized crate for stress-testing the Wolf Prowler ecosystem. It utilizes `LibAFL` to create coverage-guided fuzzers that explore edge cases in critical components.

## 🎯 Fuzzing Targets

### 1. `fuzz_crypto`
Stress tests the `wolf_den` cryptographic primitives.
- **Focus**: `CryptoEngine` builder, Symmetric encryption (AES/ChaCha), and KEM encapsulation.
- **Goal**: Detect panic-inducing inputs or nonce reuse vulnerabilities.

### 2. `fuzz_net`
Targets the `wolf_net` packet parsing and serialization logic.
- **Focus**: `WolfPacket` deserialization, Handshake protocol parsing.
- **Goal**: Ensure the network layer is robust against malformed packets.

### 3. `fuzz_security`
Tests the `wolfsec` Threat Detection Engine.
- **Focus**: `BehavioralAnalyzer` and Rule Engine evaluation.
- **Goal**: Verify that extreme event patterns do not cause memory exhaustion or logic errors.

## 💻 Usage

To start a fuzzing session, run the corresponding binary. Note that fuzzers run indefinitely until stopped (`Ctrl+C`).

```bash
# Run the Crypto Fuzzer
cargo run --bin fuzz_crypto

# Run the Network Fuzzer
cargo run --bin fuzz_net
```

## 📦 Dependencies

- `libafl`: Modern, modular fuzzing framework.
- `libafl_bolts`: Core components for LibAFL.
- `wolf_den`, `wolf_net`, `wolfsec`: Crates under test.
