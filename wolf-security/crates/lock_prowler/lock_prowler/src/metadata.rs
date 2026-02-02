use anyhow::{bail, Result};

pub const FVE_SIGNATURE: &[u8; 8] = b"-FVE-FS-";

/// Header information for FVE (Full Volume Encryption) metadata.
#[derive(Debug)]
pub struct FveHeader {
    /// FVE signature string.
    pub signature: [u8; 8],
    /// Metadata version number.
    pub version: u16,
    /// Total size of the metadata in bytes.
    pub metadata_size: u32,
    /// Offset to the last entry in the metadata block.
    pub last_entry_offset: u32,
}

/// Types of entries found in FVE metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FveEntryType {
    /// Protects the volume encryption key.
    KeyProtector,
    /// Full Volume Encryption Key (FVEK).
    Fvek,
    /// Validation information.
    Validation,
    /// Volume description.
    Description,
    /// Auto-unlock configuration.
    AutoUnlock,
    /// Drive label information.
    DriveLabel,
    /// Encryption method details.
    EncryptionMethod,
    /// Unknown entry type.
    Unknown(u16),
}

impl From<u16> for FveEntryType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => FveEntryType::KeyProtector,
            0x0002 => FveEntryType::Fvek,
            0x0003 => FveEntryType::Validation,
            0x0004 => FveEntryType::Description,
            0x0005 => FveEntryType::AutoUnlock,
            0x0006 => FveEntryType::DriveLabel,
            0x0007 => FveEntryType::EncryptionMethod,
            _ => FveEntryType::Unknown(v),
        }
    }
}

/// A generic entry within the FVE metadata.
pub struct FveEntry {
    /// Size of the entry in bytes.
    pub size: u16,
    /// Type of the entry.
    pub entry_type: FveEntryType,
    /// Raw data content of the entry.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Types of key protectors used to secure the volume.
pub enum KeyProtectorType {
    /// Trusted Platform Module.
    Tpm,
    /// External key file (e.g., USB key).
    ExternalKey,
    /// Numerical recovery password.
    RecoveryPassword,
    /// User password.
    Password,
    /// Data Recovery Agent.
    Dra,
    /// Unknown protector type.
    Unknown(u16),
}

impl From<u16> for KeyProtectorType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => KeyProtectorType::Tpm,
            0x0002 => KeyProtectorType::ExternalKey,
            0x0003 => KeyProtectorType::RecoveryPassword,
            0x0004 => KeyProtectorType::Password,
            0x0005 => KeyProtectorType::Dra,
            _ => KeyProtectorType::Unknown(v),
        }
    }
}

/// A specific key protector instance.
pub struct KeyProtector {
    /// Type of the protector.
    pub p_type: KeyProtectorType,
    /// Unique identifier for the protector.
    pub id: [u8; 16],
    /// Specific data associated with the protector (e.g., key material).
    pub data: Vec<u8>,
}

/// Parsed BitLocker metadata structure.
pub struct BitLockerMetadata {
    /// Metadata header.
    pub header: FveHeader,
    /// List of all parsed entries.
    pub entries: Vec<FveEntry>,
    /// List of identified key protectors.
    pub protectors: Vec<KeyProtector>,
}

impl BitLockerMetadata {
    /// Parses raw bytes into a `BitLockerMetadata` structure.
    ///
    /// # Errors
    /// Returns an error if the data is too short or if the signature is invalid.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 48 {
            bail!("Metadata too short");
        }

        if &data[0..8] != FVE_SIGNATURE {
            bail!("Invalid FVE signature");
        }

        let signature = [
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ];

        let version = u16::from_le_bytes([data[8], data[9]]);
        let metadata_size = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        let last_entry_offset = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);

        let mut entries = Vec::new();
        let mut protectors = Vec::new();
        let mut offset = 48; // Common start offset for entries

        while offset + 4 <= metadata_size as usize && offset + 4 <= data.len() {
            let entry_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            if entry_size < 4 || offset + entry_size > data.len() {
                break;
            }

            let entry_type_raw = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
            let entry_type = FveEntryType::from(entry_type_raw);
            let entry_data = data[offset + 4..offset + entry_size].to_vec();

            if entry_type == FveEntryType::KeyProtector && entry_data.len() >= 20 {
                let p_type_raw = u16::from_le_bytes([entry_data[0], entry_data[1]]);
                let mut id = [0u8; 16];
                id.copy_from_slice(&entry_data[4..20]);

                protectors.push(KeyProtector {
                    p_type: KeyProtectorType::from(p_type_raw),
                    id,
                    data: entry_data[20..].to_vec(),
                });
            }

            entries.push(FveEntry {
                size: entry_size as u16,
                entry_type,
                data: entry_data,
            });

            offset += entry_size;
            if entry_size == 0 {
                break;
            }
        }

        Ok(BitLockerMetadata {
            header: FveHeader {
                signature,
                version,
                metadata_size,
                last_entry_offset,
            },
            entries,
            protectors,
        })
    }
}

/// A sampler that provides data blocks for entropy analysis.
/// Can be used to sample real disk data or simulate entropy patterns.
pub struct EntropySampler {
    simulation_state: f32,
}

impl EntropySampler {
    /// Creates a new `EntropySampler`.
    pub fn new() -> Self {
        Self {
            simulation_state: 0.0,
        }
    }

    /// Generates a realistic simulated entropy value.
    /// Simulates small fluctuations around a base "healthy" level.
    pub fn sample_simulated_entropy(&mut self) -> f32 {
        use std::f32::consts::PI;

        self.simulation_state += 0.1;
        let base = 7.98;
        let variance =
            (self.simulation_state.sin() * 0.02) + (self.simulation_state * 2.0 * PI).cos() * 0.005;

        (base + variance).min(8.0).max(0.0)
    }

    /// Samples a block of data (Mock).
    pub fn sample_block(&self, _offset: u64, size: usize) -> Vec<u8> {
        // In a real implementation, this would use pread or similar to read from a block device.
        let mut data = vec![0u8; size];
        // Use a pseudo-random seed to make it look like "data"
        for i in 0..size {
            data[i] = ((i * 31) % 256) as u8;
        }
        data
    }
}

impl Default for EntropySampler {
    fn default() -> Self {
        Self::new()
    }
}
