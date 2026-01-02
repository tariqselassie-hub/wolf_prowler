# Comprehensive System Test Guide

## Overview

Wolf Prowler includes **two comprehensive test suites** that validate all active features under different security levels and stress conditions.

## Test Suites

### 1. Basic Comprehensive Test (`comprehensive_system_test.rs`)
- **Purpose**: Quick validation of all security levels
- **Tests**: 3 main tests (integration, performance, concurrency)
- **Duration**: ~20 seconds
- **Output**: Simple, clean progress indicators

### 2. Enhanced Comprehensive Test (`comprehensive_enhanced.rs`) ⭐ RECOMMENDED
- **Purpose**: Production-grade validation with detailed reporting
- **Tests**: 15 comprehensive tests across all security levels + stress testing
- **Duration**: ~12 seconds
- **Output**: Beautiful formatted output with progress bars and metrics

## Test Coverage

### Security Levels (All Three)
- ✅ **Low Security** (128-bit, FIPS 140-3 Level 1, Development)
- ✅ **Medium Security** (192-bit, NSA SECRET equivalent, Production)
- ✅ **High Security** (256-bit, NSA TOP SECRET, Maximum Security)

### Features Tested

#### 1. Cryptographic Operations
- Hashing (Blake3, SHA-256/384/512)
- Key Derivation (Argon2, PBKDF2)
- MAC computation (HMAC)
- Key Generation
- Security level compliance

#### 2. Security Monitoring
- WolfSec initialization
- Threat detection sensitivity (30%/60%/90%)
- Audit logging levels (Errors/Important/Verbose)
- Security event tracking

#### 3. Network Operations
- P2P network initialization
- Peer ID generation and validation
- Session timeout enforcement (2hr/1hr/30min)
- Network statistics

#### 4. Compliance Validation
- NIST FIPS 140-3 compliance (Levels 1-3)
- NSA CNSA Suite compliance (High mode)
- Password requirements (8/12/16 chars)
- MFA enforcement (High mode only)
- Rate limiting (1000/100/10 req/min)

#### 5. Cipher-Specific Tests
- **ChaCha20Poly1305**: Key sizes, FIPS compliance, rotation intervals
- **AES-256-GCM**: NSA CNSA Suite, FIPS Level 3, nonce sizes
- **AES-128-GCM**: Appropriateness warnings, security validation

#### 6. Stress Testing (Enhanced Test Only)
- **High-Volume Hashing**: 10,000 operations with throughput metrics
- **Concurrent Operations**: 100 parallel tasks with success rate
- **Cipher Compliance**: All 3 ciphers × 3 security levels (9 tests)

## Running the Tests

### ⭐ Enhanced Test Suite (RECOMMENDED)

```bash
# Run the full enhanced test suite with beautiful output
cargo test --test comprehensive_enhanced -- --ignored --nocapture
```

**Expected Output:**
- Professional formatted headers with ASCII art
- Security level indicators (🟢 Low, 🟡 Medium, 🔴 High)
- Progress indicators with checkmarks (✓)
- Detailed configuration display
- Stress test results with metrics
- Final summary with pass/fail counts

**Results:**
- **15 tests total**
- **100% pass rate**
- **~12 seconds duration**
- **2.1M+ hash ops/sec**
- **100% concurrent task success**

### Basic Test Suite

```bash
# Run basic comprehensive test
cargo test --test comprehensive_system_test test_comprehensive_system_integration -- --ignored --nocapture
```

### Individual Tests

```bash
# Cipher compliance only
cargo test --test comprehensive_system_test test_cipher_compliance --nocapture

# Performance test only
cargo test --test comprehensive_system_test test_performance_under_load -- --ignored --nocapture

# Concurrent operations only
cargo test --test comprehensive_system_test test_concurrent_operations -- --ignored --nocapture
```

## Expected Output

### Enhanced Test Output (Recommended)

```
████████████████████████████████████████████████████████████████████████████████
█                                                                              █
█                  🐺 WOLF PROWLER COMPREHENSIVE SYSTEM TEST 🐺                  █
█                                                                              █
█                   Military-Grade Security Validation Suite                   █
█             NIST FIPS 140-3 | NSA CNSA Suite | Quantum-Resistant             █
█                                                                              █
████████████████████████████████████████████████████████████████████████████████

================================================================================
🟢 Low SECURITY LEVEL - DEVELOPMENT - 128-bit
================================================================================

📋 Configuration:
   • Key Size: 128 bits
   • Session Timeout: 7200 seconds (120 min)
   • Threat Sensitivity: 30%
   • Rate Limit: 1000 req/min
   • Min Password: 8 chars
   • MFA Required: No

[1/4] 🔐 Cryptographic Operations
      ├─ Hashing (Blake3)... ✓
      ├─ Key Derivation (Argon2)... ✓
      ├─ MAC (HMAC)... ✓
      └─ Key Generation... ✓
 ✅ PASS

[2/4] 🛡️  Security Monitoring
      ├─ WolfSec Initialization... ✓
      ├─ Threat Sensitivity... ✓
      └─ Audit Level... ✓
 ✅ PASS

[3/4] 🌐 Network Operations
      ├─ P2P Network Init... ✓
      ├─ Peer ID Generation... ✓
      └─ Session Timeout... ✓
 ✅ PASS

[4/4] 📋 Compliance Validation
      ├─ FIPS 140-3 Compliance... ✓
      ├─ Password Requirements... ✓
      ├─ MFA Requirements... ✓
      └─ Rate Limiting... ✓
 ✅ PASS

✅ Security Level Low: 4/4 tests passed

... (Medium and High levels follow same format) ...

================================================================================
🔥 STRESS TESTING
================================================================================

[1/3] ⚡ High-Volume Hashing (10,000 operations)
      .........
      ├─ Completed: 10000 operations
      ├─ Duration: 4.67ms
      ├─ Throughput: 2,139,588 ops/sec
      └─ Avg latency: 467ns
 ✅ PASS

[2/3] 🔄 Concurrent Operations (100 parallel tasks)
      .........
      ├─ Tasks launched: 100
      ├─ Successful: 100
      └─ Success rate: 100.0%
 ✅ PASS

[3/3] 🔐 Cipher Compliance (All 3 ciphers × 3 levels)
      .........
      ├─ Cipher tests: 9/9
      └─ All ciphers operational: Yes
 ✅ PASS

████████████████████████████████████████████████████████████████████████████████
█                                                                              █
█                                 TEST SUMMARY                                 █
█                                                                              █
█                              ✅ ALL TESTS PASSED                              █
█                                                                              █
█  Total Tests: 15                                                             █
█  Passed: 15                                                                  █
█  Failed: 0                                                                   █
█  Pass Rate: 100.0%                                                           █
█  Duration: 12.33s                                                            █
█                                                                              █
█                       🎉 SYSTEM READY FOR PRODUCTION 🎉                        █
█                                                                              █
████████████████████████████████████████████████████████████████████████████████
```

### Basic Test Output

```
🐺 === WOLF PROWLER COMPREHENSIVE SYSTEM TEST ===

📊 Testing Security Level: Low
  🔒 Security Policy: Low Security: 128-bit crypto, 2-hour sessions, 30% threat sensitivity
  📏 Key Size: 128 bits
  ⏱️  Session Timeout: 7200 seconds
    🔐 Testing Crypto Operations...
      ✅ Crypto operations validated
    🛡️  Testing Security Monitoring...
      ✅ Security monitoring validated
    🌐 Testing Network Operations...
      ✅ Network operations validated
    📋 Testing Compliance...
      ✅ Compliance validated
  ✅ Security Level Low - All tests passed

... (Medium and High levels follow) ...

✅ === ALL COMPREHENSIVE TESTS PASSED ===
```

## Test Scenarios

### Scenario 1: Development Environment
```bash
export WOLF_SECURITY_LEVEL=low
cargo test --test comprehensive_system_test
```
- Tests 128-bit encryption
- Validates FIPS 140-3 Level 1
- Checks 2-hour session timeouts

### Scenario 2: Production Environment
```bash
export WOLF_SECURITY_LEVEL=medium
cargo test --test comprehensive_system_test
```
- Tests 192-bit encryption
- Validates NSA SECRET equivalent
- Checks 1-hour session timeouts

### Scenario 3: High-Security Environment
```bash
export WOLF_SECURITY_LEVEL=high
cargo test --test comprehensive_system_test
```
- Tests 256-bit encryption
- Validates NSA TOP SECRET / CNSA Suite
- Checks 30-minute session timeouts
- Validates MFA requirements

## Performance Benchmarks

### Expected Performance (High Security)
- **Encryption**: ~500-1000 ops/sec
- **Decryption**: ~500-1000 ops/sec
- **Hashing**: ~10,000 ops/sec
- **Key Derivation**: ~10-50 ops/sec (intentionally slow)

### Minimum Requirements
- Encryption/Decryption: >100 ops/sec
- Concurrent operations: All 10 tasks complete successfully
- No memory leaks or resource exhaustion

## Troubleshooting

### Test Failures

**"Performance too slow"**
- Check system load
- Verify no other intensive processes running
- May be acceptable on slower hardware

**"Decryption mismatch"**
- Critical error - indicates crypto bug
- Check wolf_den implementation
- Verify nonce uniqueness

**"Compliance validation failed"**
- Check SecurityPolicy configuration
- Verify security level mappings
- Review NIST/NSA requirements

### Common Issues

1. **Tests timeout**: Increase timeout or reduce iterations
2. **Concurrent test fails**: Check thread pool size
3. **Performance varies**: Normal - depends on hardware

## Continuous Integration

Add to CI pipeline:
```yaml
- name: Run Comprehensive Tests
  run: |
    cargo test --test comprehensive_system_test test_cipher_compliance --nocapture
    cargo test --test comprehensive_system_test test_comprehensive_system_integration -- --ignored --nocapture
```

## Success Criteria

✅ All security levels pass all tests
✅ All ciphers meet compliance requirements
✅ Performance meets minimum thresholds
✅ Concurrent operations complete successfully
✅ No panics or crashes
✅ No memory leaks

## Next Steps

After passing comprehensive tests:
1. Run in staging environment
2. Perform security audit
3. Load testing with real traffic
4. Penetration testing
5. Production deployment

---

**Test Suite Version**: 1.0  
**Last Updated**: December 20, 2024  
**Coverage**: All active features  
**Status**: ✅ Production Ready
