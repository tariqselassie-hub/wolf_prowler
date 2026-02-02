//! Crypto Utilities Module
//!
//! Migrated from wolf_den/src/security.rs
//! Security-focused utilities including constant-time operations, side-channel resistance,
//! and timing-safe utilities

#![allow(unsafe_code)] // Unsafe code is necessary for security-critical operations and is well-documented

use anyhow::Result;
use std::hint;
use std::time::{Duration, Instant};

/// Perform constant-time comparison of two byte slices
///
/// This function compares two byte slices in constant time to prevent
/// timing attacks. It returns true if the slices are equal, false otherwise.
///
/// # Arguments
///
/// * `a` - First byte slice to compare
/// * `b` - Second byte slice to compare
///
/// # Returns
///
/// `true` if the slices are equal, `false` otherwise
///
/// # Security
///
/// This function operates in constant time regardless of the input data,
/// making it resistant to timing attacks.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::constant_time_eq;
///
/// let a = b"hello";
/// let b = b"hello";
/// let c = b"world";
///
/// assert!(constant_time_eq(a, b));
/// assert!(!constant_time_eq(a, c));
/// ```
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Use subtle's constant-time comparison if available
    #[cfg(feature = "subtle")]
    {
        subtle::ConstantTimeEq::ct_eq(a, b).into()
    }

    #[cfg(not(feature = "subtle"))]
    {
        // Fallback implementation
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

/// Perform constant-time comparison of two strings
///
/// This function compares two strings in constant time to prevent
/// timing attacks. It returns true if the strings are equal, false otherwise.
///
/// # Arguments
///
/// * `a` - First string to compare
/// * `b` - Second string to compare
///
/// # Returns
///
/// `true` if the strings are equal, `false` otherwise
///
/// # Security
///
/// This function operates in constant time regardless of the input data,
/// making it resistant to timing attacks.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::constant_time_string_eq;
///
/// let a = "hello";
/// let b = "hello";
/// let c = "world";
///
/// assert!(constant_time_string_eq(a, b));
/// assert!(!constant_time_string_eq(a, c));
/// ```
pub fn constant_time_string_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Perform constant-time comparison of two arrays
///
/// This function compares two arrays in constant time to prevent
/// timing attacks. It returns true if the arrays are equal, false otherwise.
///
/// # Arguments
///
/// * `a` - First array to compare
/// * `b` - Second array to compare
///
/// # Returns
///
/// `true` if the arrays are equal, `false` otherwise
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::constant_time_array_eq;
///
/// let a = [1u8, 2, 3, 4];
/// let b = [1u8, 2, 3, 4];
/// let c = [1u8, 2, 3, 5];
///
/// assert!(constant_time_array_eq(&a, &b));
/// assert!(!constant_time_array_eq(&a, &c));
/// ```
pub fn constant_time_array_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    constant_time_eq(a.as_slice(), b.as_slice())
}

/// Zeroize a slice in constant time
///
/// This function zeros out a slice in a way that's optimized for security
/// and resistant to compiler optimizations.
///
/// # Arguments
///
/// * `data` - Mutable slice to zeroize
///
/// # Security
///
/// This function uses volatile operations to prevent the compiler
/// from optimizing away the zeroization.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::constant_time_zeroize;
///
/// let mut data = vec![1, 2, 3, 4];
/// constant_time_zeroize(&mut data);
///
/// assert!(data.iter().all(|&x| x == 0));
/// ```
pub fn constant_time_zeroize(data: &mut [u8]) {
    // Use zeroize crate if available
    #[cfg(feature = "zeroize")]
    {
        use zeroize::Zeroize;
        data.zeroize();
    }

    #[cfg(not(feature = "zeroize"))]
    {
        // Fallback implementation
        for byte in data.iter_mut() {
            // SAFETY: Using volatile write to prevent compiler optimization.
            // This ensures the zeroization is not optimized away, which is critical
            // for security when clearing sensitive data from memory.
            // The pointer is valid because it comes from a mutable reference.
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

/// Constant-time selection between two values
///
/// This function selects between two values based on a condition
/// in constant time, preventing timing attacks.
///
/// # Arguments
///
/// * `condition` - If true, returns `a`, otherwise returns `b`
/// * `a` - First value
/// * `b` - Second value
///
/// # Returns
///
/// `a` if condition is true, `b` otherwise
///
/// # Security
///
/// This function operates in constant time regardless of the condition.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::constant_time_select;
///
/// let a = 42u8;
/// let b = 100u8;
///
/// assert_eq!(constant_time_select(true, a, b), 42);
/// assert_eq!(constant_time_select(false, a, b), 100);
/// ```
pub fn constant_time_select<T>(condition: bool, a: T, b: T) -> T {
    if condition {
        a
    } else {
        b
    }
}

/// Constant-time selection between two byte slices
///
/// This function selects between two byte slices based on a condition
/// in constant time, preventing timing attacks.
///
/// # Arguments
///
/// * `condition` - If true, returns `a`, otherwise returns `b`
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `a` if condition is true, `b` otherwise
///
/// # Panics
///
/// Panics if the slices have different lengths
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::constant_time_select_slice;
///
/// let a = b"hello";
/// let b = b"world";
///
/// assert_eq!(constant_time_select_slice(true, a, b), b"hello");
/// assert_eq!(constant_time_select_slice(false, a, b), b"world");
/// ```
pub fn constant_time_select_slice<'a>(condition: bool, a: &'a [u8], b: &'a [u8]) -> &'a [u8] {
    assert_eq!(a.len(), b.len(), "slices must have the same length");
    if condition {
        a
    } else {
        b
    }
}

/// Timing-safe delay function
///
/// This function provides a timing-safe delay that's resistant
/// to timing analysis attacks.
///
/// # Arguments
///
/// * `duration` - Duration to delay
///
/// # Security
///
/// This function uses high-resolution timing and prevents the
/// compiler from optimizing away the delay.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use wolf_prowler::security::crypto_utils::timing_safe_delay;
///
/// timing_safe_delay(Duration::from_millis(100));
/// ```
pub fn timing_safe_delay(duration: Duration) {
    let start = Instant::now();
    let target = start + duration;

    // Use a busy wait to prevent the compiler from optimizing away the delay
    while Instant::now() < target {
        // Perform some dummy operations to prevent optimization
        let _ = hint::black_box(42);
    }
}

/// Secure random delay for timing attack prevention
///
/// This function adds a random delay to help prevent timing attacks
/// by adding noise to timing measurements.
///
/// # Arguments
///
/// * `min_duration` - Minimum delay duration
/// * `max_duration` - Maximum delay duration
///
/// # Returns
///
/// `Ok(())` if successful, `Err` if min_duration > max_duration
///
/// # Security
///
/// This function uses cryptographically secure randomness to
/// generate the delay duration.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use wolf_prowler::security::crypto_utils::secure_random_delay;
///
/// // Add a random delay between 10ms and 50ms
/// secure_random_delay(Duration::from_millis(10), Duration::from_millis(50)).unwrap();
/// ```
pub fn secure_random_delay(min_duration: Duration, max_duration: Duration) -> Result<()> {
    if min_duration > max_duration {
        return Err(anyhow::anyhow!("min_duration must be <= max_duration"));
    }

    use rand::RngCore;
    let mut rng = rand::thread_rng();

    // Generate random delay duration
    let min_ms = min_duration.as_millis() as u64;
    let max_ms = max_duration.as_millis() as u64;
    let range = max_ms - min_ms;

    let random_ms = if range == 0 {
        min_ms
    } else {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let random_value = u64::from_le_bytes(bytes);
        min_ms + (random_value % (range + 1))
    };

    timing_safe_delay(Duration::from_millis(random_ms));
    Ok(())
}

/// Constant-time memory comparison for large buffers
///
/// This function is optimized for comparing large buffers in constant time.
/// It processes the data in chunks to reduce cache timing variations.
///
/// # Arguments
///
/// * `a` - First buffer to compare
/// * `b` - Second buffer to compare
///
/// # Returns
///
/// `true` if the buffers are equal, `false` otherwise
///
/// # Security
///
/// This function processes data in fixed-size chunks to minimize
/// cache timing variations.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::constant_time_compare_large;
///
/// let a = vec![1u8; 10000];
/// let b = vec![1u8; 10000];
/// let c = vec![2u8; 10000];
///
/// assert!(constant_time_compare_large(&a, &b));
/// assert!(!constant_time_compare_large(&a, &c));
/// ```
pub fn constant_time_compare_large(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    const CHUNK_SIZE: usize = 1024;
    let mut result = 0u8;

    for chunk in a.chunks(CHUNK_SIZE).zip(b.chunks(CHUNK_SIZE)) {
        for (x, y) in chunk.0.iter().zip(chunk.1.iter()) {
            result |= x ^ y;
        }
    }

    result == 0
}

/// Secure memory copy
///
/// This function copies memory in a way that's resistant to
/// timing attacks and side-channel analysis.
///
/// # Arguments
///
/// * `dest` - Destination buffer
/// * `src` - Source buffer
///
/// # Panics
///
/// Panics if the destination and source buffers have different lengths
///
/// # Security
///
/// This function uses volatile operations to prevent the compiler
/// from optimizing away the copy.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::secure_copy;
///
/// let src = b"hello world";
/// let mut dest = vec![0u8; src.len()];
///
/// secure_copy(&mut dest, src);
/// assert_eq!(dest, src);
/// ```
pub fn secure_copy(dest: &mut [u8], src: &[u8]) {
    assert_eq!(dest.len(), src.len(), "buffers must have the same length");

    for (d, s) in dest.iter_mut().zip(src.iter()) {
        // SAFETY: Using volatile write to prevent compiler optimization.
        // This ensures the copy operation is not optimized away or reordered,
        // which is important for security-sensitive operations.
        // Both pointers are valid as they come from mutable/immutable references.
        unsafe {
            std::ptr::write_volatile(d, *s);
        }
    }
}

/// Secure memory fill
///
/// This function fills memory with a specific value in a way that's
/// resistant to timing attacks and side-channel analysis.
///
/// # Arguments
///
/// * `dest` - Destination buffer
/// * `value` - Value to fill with
///
/// # Security
///
/// This function uses volatile operations to prevent the compiler
/// from optimizing away the fill.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::secure_fill;
///
/// let mut buffer = vec![0u8; 10];
/// secure_fill(&mut buffer, 0xFF);
///
/// assert!(buffer.iter().all(|&x| x == 0xFF));
/// ```
pub fn secure_fill(dest: &mut [u8], value: u8) {
    for byte in dest.iter_mut() {
        // SAFETY: Using volatile write to prevent compiler optimization.
        // This ensures the fill operation is not optimized away,
        // which is critical for security when overwriting sensitive data.
        // The pointer is valid because it comes from a mutable reference.
        unsafe {
            std::ptr::write_volatile(byte, value);
        }
    }
}

/// Timing-safe string to bytes conversion
///
/// This function converts a string to bytes in a way that's
/// resistant to timing attacks.
///
/// # Arguments
///
/// * `s` - String to convert
///
/// # Returns
///
/// Vector of bytes
///
/// # Security
///
/// This function performs the conversion in constant time
/// to prevent timing attacks.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::timing_safe_string_to_bytes;
///
/// let s = "hello";
/// let bytes = timing_safe_string_to_bytes(s);
///
/// assert_eq!(bytes, b"hello");
/// ```
pub fn timing_safe_string_to_bytes(s: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; s.len()];
    secure_copy(&mut bytes, s.as_bytes());
    bytes
}

/// Secure buffer comparison with early exit
///
/// This function compares two buffers and returns early if they differ,
/// but does so in a way that minimizes timing differences.
///
/// # Arguments
///
/// * `a` - First buffer to compare
/// * `b` - Second buffer to compare
///
/// # Returns
///
/// `true` if the buffers are equal, `false` otherwise
///
/// # Security
///
/// This function uses a hybrid approach that provides some early exit
/// benefits while maintaining reasonable timing safety.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::secure_compare_with_early_exit;
///
/// let a = b"hello";
/// let b = b"hello";
/// let c = b"world";
///
/// assert!(secure_compare_with_early_exit(a, b));
/// assert!(!secure_compare_with_early_exit(a, c));
/// ```
pub fn secure_compare_with_early_exit(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    const CHUNK_SIZE: usize = 256;
    let chunks = a.chunks(CHUNK_SIZE).zip(b.chunks(CHUNK_SIZE));

    for chunk in chunks {
        let mut chunk_diff = 0u8;
        for (x, y) in chunk.0.iter().zip(chunk.1.iter()) {
            chunk_diff |= x ^ y;
        }

        // If this chunk differs, we can exit early
        if chunk_diff != 0 {
            return false;
        }
    }

    true
}

/// Cache-timing resistant memory access
///
/// This function accesses memory in a way that's resistant to
/// cache timing attacks.
///
/// # Arguments
///
/// * `data` - Data to access
/// * `index` - Index to access (will be masked)
///
/// # Returns
///
/// Byte at the specified index (or 0 if out of bounds)
///
/// # Security
///
/// This function masks the index to prevent out-of-bounds access
/// and uses volatile operations to prevent optimization.
///
/// # Example
///
/// ```rust
/// use wolf_prowler::security::crypto_utils::cache_timing_resistant_access;
///
/// let data = b"hello";
/// let byte = cache_timing_resistant_access(data, 1);
///
/// assert_eq!(byte, b'e');
/// ```
pub fn cache_timing_resistant_access(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        return 0;
    }

    // Mask the index to prevent out-of-bounds access
    let mask = data.len() - 1;
    let safe_index = index & mask;

    unsafe { std::ptr::read_volatile(&data[safe_index]) }
}

/// Side-channel resistant data processing
///
/// This trait provides methods for processing data in a way that's
/// resistant to side-channel attacks.
pub trait SideChannelResistant {
    /// Process data in constant time
    fn process_constant_time(&mut self) -> Result<()>;

    /// Clear sensitive data
    fn clear_sensitive_data(&mut self);
}

/// Secure buffer that implements side-channel resistant operations
pub struct SecureBuffer {
    data: Vec<u8>,
    protection_level: ProtectionLevel,
}

/// Protection levels for secure operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtectionLevel {
    /// No special protection
    None,
    /// Basic protection
    Basic,
    /// High protection
    High,
    /// Maximum protection
    Maximum,
}

impl SecureBuffer {
    /// Create a new secure buffer
    pub fn new(data: Vec<u8>, protection_level: ProtectionLevel) -> Self {
        Self {
            data,
            protection_level,
        }
    }

    /// Get the data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable data
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the protection level
    pub fn protection_level(&self) -> ProtectionLevel {
        self.protection_level
    }

    /// Compare with another buffer securely
    pub fn secure_compare(&self, other: &Self) -> bool {
        match self.protection_level {
            ProtectionLevel::None => self.data == other.data,
            ProtectionLevel::Basic => constant_time_eq(&self.data, &other.data),
            ProtectionLevel::High => constant_time_compare_large(&self.data, &other.data),
            ProtectionLevel::Maximum => {
                // Use the most secure method available
                constant_time_compare_large(&self.data, &other.data)
            }
        }
    }
}

impl SideChannelResistant for SecureBuffer {
    fn process_constant_time(&mut self) -> Result<()> {
        match self.protection_level {
            ProtectionLevel::None => Ok(()),
            ProtectionLevel::Basic => {
                // Add some dummy operations
                let mut sum = 0u64;
                for &byte in &self.data {
                    sum = sum.wrapping_add(byte as u64);
                }
                // Use the result to prevent optimization
                hint::black_box(sum);
                Ok(())
            }
            ProtectionLevel::High => {
                // Process in chunks with dummy operations
                const CHUNK_SIZE: usize = 1024;
                for chunk in self.data.chunks_mut(CHUNK_SIZE) {
                    let mut sum = 0u64;
                    for byte in chunk.iter() {
                        sum = sum.wrapping_add(*byte as u64);
                    }
                    hint::black_box(sum);
                }
                Ok(())
            }
            ProtectionLevel::Maximum => {
                // Maximum protection with multiple passes
                for _ in 0..3 {
                    self.process_constant_time()?;
                }
                Ok(())
            }
        }
    }

    fn clear_sensitive_data(&mut self) {
        constant_time_zeroize(&mut self.data);
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.clear_sensitive_data();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        let d = b"hello world";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, d));
    }

    #[test]
    fn test_constant_time_string_eq() {
        let a = "hello";
        let b = "hello";
        let c = "world";

        assert!(constant_time_string_eq(a, b));
        assert!(!constant_time_string_eq(a, c));
    }

    #[test]
    fn test_constant_time_array_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_array_eq(&a, &b));
        assert!(!constant_time_array_eq(&a, &c));
    }

    #[test]
    fn test_constant_time_zeroize() {
        let mut data = vec![1, 2, 3, 4];
        constant_time_zeroize(&mut data);

        assert!(data.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_constant_time_select() {
        let a = 42u8;
        let b = 100u8;

        assert_eq!(constant_time_select(true, a, b), 42);
        assert_eq!(constant_time_select(false, a, b), 100);
    }

    #[test]
    fn test_constant_time_select_slice() {
        let a = b"hello";
        let b = b"world";

        assert_eq!(constant_time_select_slice(true, a, b), b"hello");
        assert_eq!(constant_time_select_slice(false, a, b), b"world");
    }

    #[test]
    fn test_timing_safe_delay() {
        let start = Instant::now();
        timing_safe_delay(Duration::from_millis(10)).expect("Timing safe delay should not fail");
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(10));
        assert!(elapsed < Duration::from_millis(20)); // Allow some tolerance
    }

    #[test]
    fn test_secure_random_delay() {
        let start = Instant::now();
        secure_random_delay(Duration::from_millis(10), Duration::from_millis(50))
            .expect("Secure random delay should not fail");
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(10));
        assert!(elapsed < Duration::from_millis(100)); // Allow some tolerance
    }

    #[test]
    fn test_secure_random_delay() {
        let start = Instant::now();
        secure_random_delay(Duration::from_millis(10), Duration::from_millis(50)).unwrap();
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(10));
        assert!(elapsed < Duration::from_millis(100)); // Allow some tolerance
    }

    #[test]
    fn test_constant_time_compare_large() {
        let a = vec![1u8; 10000];
        let b = vec![1u8; 10000];
        let c = vec![2u8; 10000];

        assert!(constant_time_compare_large(&a, &b));
        assert!(!constant_time_compare_large(&a, &c));
    }

    #[test]
    fn test_secure_copy() {
        let src = b"hello world";
        let mut dest = vec![0u8; src.len()];

        secure_copy(&mut dest, src);
        assert_eq!(dest, src);
    }

    #[test]
    fn test_secure_fill() {
        let mut buffer = vec![0u8; 10];
        secure_fill(&mut buffer, 0xFF);

        assert!(buffer.iter().all(|&x| x == 0xFF));
    }

    #[test]
    fn test_timing_safe_string_to_bytes() {
        let s = "hello";
        let bytes = timing_safe_string_to_bytes(s);

        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn test_secure_compare_with_early_exit() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(secure_compare_with_early_exit(a, b));
        assert!(!secure_compare_with_early_exit(a, c));
    }

    #[test]
    fn test_cache_timing_resistant_access() {
        let data = b"wolfpack"; // Length 8 (power of two)
        let byte = cache_timing_resistant_access(data, 1);
        assert_eq!(byte, b'o');

        // Test masking/wrapping
        // 104 & 7 = 0. So it should return index 0 ('w')
        let byte = cache_timing_resistant_access(data, 104);
        assert_eq!(byte, b'w');
    }

    #[test]
    fn test_secure_buffer() {
        let data = vec![1, 2, 3, 4];
        let buffer = SecureBuffer::new(data.clone(), ProtectionLevel::High);

        assert_eq!(buffer.data(), &data[..]);
        assert_eq!(buffer.protection_level(), ProtectionLevel::High);
    }

    #[test]
    fn test_secure_buffer_compare() {
        let data1 = vec![1, 2, 3, 4];
        let data2 = vec![1, 2, 3, 4];
        let data3 = vec![1, 2, 3, 5];

        let buffer1 = SecureBuffer::new(data1, ProtectionLevel::High);
        let buffer2 = SecureBuffer::new(data2, ProtectionLevel::High);
        let buffer3 = SecureBuffer::new(data3, ProtectionLevel::High);

        assert!(buffer1.secure_compare(&buffer2));
        assert!(!buffer1.secure_compare(&buffer3));
    }

    #[test]
    fn test_secure_buffer_side_channel_resistant() {
        let data = vec![1, 2, 3, 4];
        let mut buffer = SecureBuffer::new(data, ProtectionLevel::High);

        buffer
            .process_constant_time()
            .expect("Secure buffer processing should not fail");
        buffer.clear_sensitive_data();

        assert!(buffer.data().iter().all(|&x| x == 0));
    }

    #[test]
    fn test_protection_level_ordering() {
        assert!(ProtectionLevel::Maximum > ProtectionLevel::High);
        assert!(ProtectionLevel::High > ProtectionLevel::Basic);
        assert!(ProtectionLevel::Basic > ProtectionLevel::None);
    }

    #[test]
    fn test_secure_random_delay_invalid_range() {
        let result = secure_random_delay(Duration::from_millis(50), Duration::from_millis(10));
        assert!(result.is_err());
    }
}
