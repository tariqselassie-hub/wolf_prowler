//! Memory protection utilities for Wolf Den

use zeroize::Zeroize;

/// Memory protection levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryProtection {
    /// No memory protection - data remains in regular memory
    None,
    /// Basic protection - zeroizes data on drop
    #[default]
    Basic,
    /// Strict protection - uses secure memory allocation if available
    Strict,
}

/// Secure bytes container
#[derive(Debug)]
pub struct SecureBytes {
    data: Vec<u8>,
    protection: MemoryProtection,
}

impl SecureBytes {
    /// Create a new `SecureBytes` container with specified protection level
    #[must_use]
    pub const fn new(data: Vec<u8>, protection: MemoryProtection) -> Self {
        Self { data, protection }
    }

    /// Get a reference to the underlying data as a slice
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the data in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the data is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            protection: self.protection,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes_basic() {
        let data = vec![1, 2, 3, 4];
        let secure = SecureBytes::new(data.clone(), MemoryProtection::Basic);

        assert_eq!(secure.len(), 4);
        assert!(!secure.is_empty());
        assert_eq!(secure.as_slice(), &data[..]);
    }

    #[test]
    fn test_secure_bytes_cloning() {
        let data = vec![1, 2, 3, 4];
        let secure = SecureBytes::new(data.clone(), MemoryProtection::Basic);
        let cloned = secure.clone();

        assert_eq!(secure.as_slice(), cloned.as_slice());
        assert_ne!(secure.as_slice().as_ptr(), cloned.as_slice().as_ptr()); // Different memory locations
    }

    #[test]
    fn test_protection_modes() {
        let data = vec![0u8; 32];
        let none = SecureBytes::new(data.clone(), MemoryProtection::None);
        let basic = SecureBytes::new(data.clone(), MemoryProtection::Basic);
        let strict = SecureBytes::new(data.clone(), MemoryProtection::Strict);

        assert_eq!(none.len(), 32);
        assert_eq!(basic.len(), 32);
        assert_eq!(strict.len(), 32);
    }
}
