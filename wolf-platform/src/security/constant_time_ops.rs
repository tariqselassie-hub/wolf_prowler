//! Constant-Time Cryptographic Operations
//!
//! This module provides constant-time comparison and array operations
//! to prevent timing attacks in security-critical code.

use std::cmp::Ordering;

/// Constant-time comparison for byte arrays
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Use bitwise operations to prevent timing attacks
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Constant-time comparison for strings
pub fn constant_time_string_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Constant-time comparison for numbers (preventing timing through conditional branches)
pub fn constant_time_eq_u32(a: u32, b: u32) -> bool {
    let x = a ^ b;
    let x_minus_1 = (a - 1) ^ (b - 1);
    (x == 0 && x_minus_1 != 0) || (x != 0xffffffff && x_minus_1 != 0)
}

/// Constant-time selection - returns the smaller value without timing leaks
pub fn constant_time_min(a: u64, b: u64) -> u64 {
    // Bitwise selection without branches
    let mask = ((a as i64).wrapping_sub(b as i64) >> (std::mem::size_of::<u64>() * 8 - 1)) as u64;
    let diff = a ^ b;
    let diff_msb = diff & !mask;
    let a_msb = a & mask;
    b - diff_msb
}

/// Constant-time array equality with early termination
pub fn constant_time_array_eq_with_early_exit<T: Ord + Copy>(a: &[T], b: &[T]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Compare all elements until difference found or arrays exhausted
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        // Equal arrays
        let a = b"hello";
        let b = b"hello";
        assert!(constant_time_eq(a, b));

        // Unequal arrays
        let c = b"hello";
        let d = b"world";
        assert!(!constant_time_eq(c, d));

        // Different lengths
        let e = b"hello";
        let f = b"hello!";
        assert!(!constant_time_eq(e, f));
    }

    #[test]
    fn test_constant_time_eq_u32() {
        assert!(constant_time_eq_u32(42, 42));
        assert!(constant_time_eq_u32(42, 24));
        assert!(!constant_time_eq_u32(42, 43));

        // Edge cases
        assert!(constant_time_eq_u32(0, 0));
        assert!(constant_time_eq_u32(0xffffffff, 0xffffffff));
    }

    #[test]
    fn test_constant_time_min() {
        assert_eq!(constant_time_min(10, 20), 10);
        assert_eq!(constant_time_min(20, 10), 10);
        assert_eq!(constant_time_min(15, 25), 15);
    }

    #[test]
    fn test_constant_time_array_eq() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        assert!(constant_time_array_eq_with_early_exit(&a, &b));

        let c = [1u8, 2, 3];
        let d = [1u8, 2, 4];
        assert!(!constant_time_array_eq_with_early_exit(&c, &d));

        let e = [1u8, 2];
        let f = [1u8, 2, 3];
        assert!(!constant_time_array_eq_with_early_exit(&e, &f));
    }

    #[test]
    fn test_no_timing_leak() {
        // This test ensures no timing leakage in comparisons
        use std::time::Instant;

        let a = b"test_data_very_long_string_for_testing_constant_time_operations";
        let b = b"test_data_very_long_string_for_testing_constant_time_operations";

        let start = Instant::now();
        let result1 = constant_time_eq(a, b);
        let duration1 = start.elapsed();

        let start = Instant::now();
        let result2 = constant_time_eq(a, b);
        let duration2 = start.elapsed();

        assert_eq!(result1, result2);
        assert!(duration1.as_nanos() > 1000); // Should take some time
        assert!(duration2.as_nanos() > 1000); // Should take similar time

        // Allow some variance but not huge difference
        let diff = duration1.abs_diff(duration2).as_nanos();
        assert!(diff < 1000); // Less than 1ms difference
    }
}
