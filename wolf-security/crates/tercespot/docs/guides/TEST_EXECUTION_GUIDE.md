# TersecPot Four-Eyes Testing Execution Guide

## Overview

This guide provides comprehensive instructions for executing and validating the Four-Eyes Vault testing suite for TersecPot. The testing covers all components of the multi-party signing system including ceremony, shared libraries, submitter, and sentinel modules.

## Prerequisites

### System Requirements
- **Rust Toolchain**: Rust 1.70+ with cargo
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 4GB RAM recommended
- **Storage**: 1GB free disk space

### Dependencies
```bash
# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

## Quick Start

### 1. Clone and Setup
```bash
git clone <repository-url>
cd TersecPot/tercespot
```

### 2. Run All Tests
```bash
cargo test --all
```

### 3. View Results
- **Expected**: 41/41 core tests passing
- **Visual Flow**: Manual test (expected to fail in automated runs)

## Detailed Test Execution

### Component-Specific Testing

#### Ceremony Module
```bash
# Run ceremony tests only
cargo test -p ceremony

# Run specific ceremony test
cargo test -p ceremony test_ceremony_id_uniqueness
```

**Tests Covered**:
- Key generation and storage security
- Memory wiping validation
- USB device path handling
- Ceremony ID uniqueness

#### Shared Library Module
```bash
# Run all shared library tests
cargo test -p shared

# Run Four-Eyes specific tests
cargo test -p shared four_eyes_vault_spec

# Run specific shared tests
cargo test -p shared test_parse_and_evaluate_complex_expressions
```

**Tests Covered**:
- Role enum serialization
- Policy parsing and validation
- Cryptographic operations (ML-KEM-1024, ML-DSA-44)
- Expression parsing and evaluation
- Command metadata processing

#### Submitter Module
```bash
# Run submitter tests
cargo test -p submitter

# Run PQC signature tests
cargo test -p submitter pqc_sign_spec

# Run specific submitter test
cargo test -p submitter test_partial_command_creation
```

**Tests Covered**:
- Partial command creation and management
- Signature appending and validation
- PQC signature correctness
- Binary package format validation
- Multi-party signing workflow

#### Sentinel Module
```bash
# Run sentinel tests
cargo test -p sentinel

# Run PQC verification tests
cargo test -p sentinel pqc_verify_spec

# Run specific sentinel test
cargo test -p sentinel test_evaluate_policies
```

**Tests Covered**:
- Policy evaluation and enforcement
- Signature verification
- Wire format parsing
- Authorized key management
- Command execution validation

### Four-Eyes Integration Testing

#### Automated Tests
```bash
# Run all Four-Eyes related tests (excluding manual)
cargo test --all --exclude-test visual_flow
```

#### Manual Integration Test
```bash
# Run visual flow test (requires manual interaction)
cargo test -p submitter visual_flow
```

**Note**: The visual flow test requires manual setup and interaction. It's designed to test the complete end-to-end workflow but is not suitable for automated CI/CD pipelines.

## Test Configuration

### Environment Variables
```bash
# Set custom postbox location
export TERSEC_POSTBOX="/custom/path/postbox"

# Set custom log location
export TERSEC_LOG="/custom/path/access.log"

# Set pulse mode for testing
export TERSEC_PULSE_MODE="CRYPTO"

# Set signature threshold
export TERSEC_M="2"
```

### Test Data
Test files are automatically generated in temporary directories during test execution. No manual setup is required for unit tests.

## Expected Test Results

### Success Criteria
- **Core Tests**: 41/41 passing (100%)
- **Visual Flow**: Manual test (may fail in automated runs)
- **Execution Time**: ~18 seconds total
- **Memory Usage**: Standard Rust test footprint

### Sample Output
```
running 41 tests
test test_ceremony_id_uniqueness ... ok
test test_memory_wiping ... ok
test test_usb_path_validation ... ok
test test_key_generation_and_storage ... ok
test test_role_enum_serialization ... ok
test test_partial_signature_creation ... ok
test test_policy_parsing_edge_cases ... ok
test test_parse_command_metadata_edge_cases ... ok
test test_load_policy_config_from_file ... ok
test test_encrypt_decrypt_for_sentinel ... ok
test test_encrypt_decrypt_invalid_data ... ok
test test_load_kem_public_key ... ok
test test_load_kem_public_key_invalid ... ok
test test_parse_and_evaluate_complex_expressions ... ok
test test_parse_expr_invalid_input ... ok
test test_partial_command_creation ... ok
test test_append_signature ... ok
test test_partial_save_load ... ok
test test_package_structure ... ok
test test_duplicate_role_rejection ... ok
test test_sign_and_verify ... ok
test test_partial_to_signed ... ok
test test_partial_completion ... ok
test test_package_format ... ok
test test_pqc_signature_correctness ... ok
test test_check_pulse_found ... ok
test test_check_policy_threshold ... ok
test test_evaluate_policies ... ok
test test_evaluate_policies_no_match ... ok
test test_parse_plaintext ... ok
test test_parse_plaintext_invalid ... ok
test test_parse_wire_format_invalid ... ok
test test_load_authorized_keys ... ok
test test_parse_and_verify ... ok
test test_verify_signature_invalid ... ok
test test_valid_signature_verification ... ok
test test_invalid_signature_verification ... ok

test result: ok. 41 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 18.10s
```

## Troubleshooting

### Common Issues

#### 1. Test Failures
```bash
# Check for compilation errors
cargo check --all

# Run tests with verbose output
cargo test --all -- --nocapture

# Run specific failing test
cargo test -p <package> <test_name> -- --nocapture
```

#### 2. Memory Issues
```bash
# Run tests with reduced parallelism
cargo test --all -- --test-threads=1

# Check memory usage
cargo test --all -- --nocapture --show-output
```

#### 3. Permission Issues
```bash
# Ensure write permissions in test directory
chmod -R 755 /tmp/tersec_visual_test_*

# Clean up previous test runs
rm -rf /tmp/tersec_visual_test_*
```

#### 4. Network/Time Dependencies
Some tests may fail due to timing issues. Retry failed tests:
```bash
cargo test --all
```

### Debug Information

#### Enable Debug Logging
```bash
# Run with debug output
RUST_LOG=debug cargo test --all
```

#### Check Test Environment
```bash
# Verify Rust version
rustc --version

# Check available targets
rustup target list --installed

# Verify cargo configuration
cargo --version
```

## Continuous Integration

### GitHub Actions Example
```yaml
name: Test Four-Eyes Vault

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        profile: minimal
        
    - name: Run Tests
      run: |
        cd tercespot
        cargo test --all --exclude-test visual_flow
        
    - name: Check Test Results
      run: |
        if [ $? -eq 0 ]; then
          echo "✅ All tests passed"
        else
          echo "❌ Tests failed"
          exit 1
        fi
```

### Local CI Simulation
```bash
# Simulate CI environment
cargo clean
cargo test --all --exclude-test visual_flow
```

## Performance Monitoring

### Test Execution Metrics
```bash
# Measure test execution time
time cargo test --all --exclude-test visual_flow

# Check memory usage during tests
cargo test --all -- --test-threads=1
```

### Benchmarking
```bash
# Run with benchmarking (if available)
cargo bench --all
```

## Security Validation

### Cryptographic Verification
All tests validate:
- ML-DSA-44 signature correctness
- ML-KEM-1024 encryption/decryption
- AES-256-GCM secure encryption
- Secure key generation and storage

### Policy Enforcement Validation
Tests confirm:
- Role-based access control
- Multi-party signing requirements
- Complex approval expressions
- Threshold enforcement

## Maintenance

### Regular Testing Schedule
- **Daily**: Automated test runs
- **Weekly**: Full integration testing
- **Monthly**: Security review and updates
- **Quarterly**: Performance benchmarking

### Test Updates
When modifying Four-Eyes functionality:
1. Update relevant unit tests
2. Add integration tests for new features
3. Update this guide if procedures change
4. Verify all 41 core tests still pass

## Support

### Getting Help
- **Documentation**: See [`FOUR_EYES_TESTING_REPORT.md`](FOUR_EYES_TESTING_REPORT.md)
- **Issues**: Report test failures or documentation issues
- **Questions**: Contact the TersecPot development team

### Contributing
To contribute test improvements:
1. Fork the repository
2. Create a feature branch
3. Add or improve tests
4. Ensure all existing tests pass
5. Submit a pull request

---

**Last Updated**: January 3, 2026  
**Version**: 1.0  
**Maintainer**: TersecPot Development Team