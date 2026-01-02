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
    /// Create a new SecureBytes container with specified protection level
    pub fn new(data: Vec<u8>, protection: MemoryProtection) -> Self {
        Self { data, protection }
    }

    /// Get a reference to the underlying data as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the data in bytes
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the data is empty
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
