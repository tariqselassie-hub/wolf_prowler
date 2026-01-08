use anyhow::{bail, Result};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = data.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_string = String::deserialize(deserializer)?;
        let data: Result<Vec<u8>, _> = (0..hex_string.len())
            .step_by(2)
            .map(|i| {
                let byte_str = &hex_string[i..i + 2];
                u8::from_str_radix(byte_str, 16).map_err(serde::de::Error::custom)
            })
            .collect();
        data
    }

}

/// A shard of a recovery key.
/// A shard of a recovery key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShard {
    /// Unique identifier for this shard.
    pub shard_id: String,
    /// Identifier of the secret this shard belongs to.
    pub secret_id: String,
    /// Index of this shard (x-coordinate).
    pub index: u8,
    /// Shard data (y-coordinate/value).
    #[serde(with = "hex_serde")]
    pub data: Vec<u8>,
}

/// Metadata for shard storage
/// Metadata for shard storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMetadata {
    /// Unique identifier for this shard.
    pub shard_id: String,
    /// Identifier of the secret this shard belongs to.
    pub secret_id: String,
    /// Index of this shard.
    pub index: u8,
    /// Total number of shards created for this secret.
    pub total_shards: u8,
    /// Threshold number of shards required for reconstruction.
    pub threshold: u8,
}

/// Implements Shamir's Secret Sharing over GF(256).
pub struct Sharder;

impl Sharder {
    /// Splits a 32-byte secret into 3 shards with a threshold of 2.
    /// Uses a random polynomial f(x) = secret + a1*x over GF(256).
    pub fn split(secret: &[u8; 32]) -> Vec<KeyShard> {
        let mut rng = rand::thread_rng();

        // Generate a secret ID for this key
        let mut secret_id_bytes = [0u8; 16];
        rng.fill_bytes(&mut secret_id_bytes);
        let secret_id = hex::encode(secret_id_bytes);

        // We'll have 3 shards.
        let mut shard1_data = Vec::with_capacity(32);
        let mut shard2_data = Vec::with_capacity(32);
        let mut shard3_data = Vec::with_capacity(32);

        for i in 0..32 {
            let s = secret[i];
            // Generate a random coefficient a1 for the linear term.
            // Degree = threshold - 1 = 2 - 1 = 1.
            let a1: u8 = rng.r#gen();

            // Evaluate polynomial at x=1, x=2, x=3
            // f(x) = s + a1 * x
            let y1 = gf256_add(s, gf256_mul(a1, 1));
            let y2 = gf256_add(s, gf256_mul(a1, 2));
            let y3 = gf256_add(s, gf256_mul(a1, 3));

            shard1_data.push(y1);
            shard2_data.push(y2);
            shard3_data.push(y3);
        }

        vec![
            KeyShard {
                shard_id: format!("{}_1", secret_id),
                secret_id: secret_id.clone(),
                index: 1,
                data: shard1_data,
            },
            KeyShard {
                shard_id: format!("{}_2", secret_id),
                secret_id: secret_id.clone(),
                index: 2,
                data: shard2_data,
            },
            KeyShard {
                shard_id: format!("{}_3", secret_id),
                secret_id,
                index: 3,
                data: shard3_data,
            },
        ]
    }

    /// Reconstructs the secret from ANY 2 shards using Lagrange Interpolation.
    pub fn reconstruct(shards: &[KeyShard]) -> Result<[u8; 32]> {
        if shards.len() < 2 {
            bail!(
                "Insufficient shards for reconstruction (need 2, have {})",
                shards.len()
            );
        }

        let s1 = &shards[0];
        let s2 = &shards[1];

        if s1.index == s2.index {
            bail!("Shards must have unique indices");
        }

        let x0 = s1.index;
        let x1 = s2.index;

        let mut secret = [0u8; 32];

        // Lagrange Interpolation for x=0 (the secret implementation).
        // Since we only need 2 points (linear), the formula matches the generic Lagrange form.
        // L0(0) = (0 - x1) / (x0 - x1) = x1 / (x1 - x0)  -- careful with subtraction/division
        // L1(0) = (0 - x0) / (x1 - x0) = x0 / (x0 - x1)

        // Precompute Lagrange basis polynomials at 0 for the two x coordinates.
        let l0 = gf256_div(x1, gf256_sub(x0, x1));
        let l1 = gf256_div(x0, gf256_sub(x1, x0));

        for i in 0..32 {
            let y0 = s1.data[i];
            let y1 = s2.data[i];

            // S = y0 * L0 + y1 * L1
            let term0 = gf256_mul(y0, l0);
            let term1 = gf256_mul(y1, l1);

            secret[i] = gf256_add(term0, term1);
        }

        Ok(secret)
    }
}

// --- GF(256) Arithmetic Implementation ---
// Field generator polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B) (Rijndael/AES standard)

fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b // In GF(2^n), addition = subtraction
}

fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;

    // Peasant's algorithm for GF(2^8) multiplication
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }

        let carry = (a & 0x80) != 0;
        a <<= 1;
        if carry {
            a ^= 0x1B; // 0x11B polynomial, but we only XOR the lower 8 bits (0x1B)
        }
        b >>= 1;
    }
    p
}

fn gf256_div(a: u8, b: u8) -> u8 {
    if b == 0 {
        panic!("Division by zero in GF(256)");
    }
    // a / b = a * inv(b)
    gf256_mul(a, gf256_inv(b))
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("Inversion of zero in GF(256)");
    }
    // In GF(2^8), a^254 is the multiplicative inverse of a
    // Since a^255 = 1 for a != 0
    let mut res = 1;
    let mut base = a;
    let mut exp = 254;

    // Modular exponentiation
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf256_mul(res, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_ops() {
        assert_eq!(gf256_add(10, 20), 10 ^ 20);
        // 3 * 3 in normal math is 9. In GF(256): 0x03 * 0x03 = (x+1)(x+1) = x^2 + 1 + 1 + 1(gone) = x^2 + 0x1 = x^2+1 = 5? No.
        // (x+1)(x+1) = x^2 + x + x + 1 = x^2 + 1 (since 2x = 0).
        // 0x03 is 11 binary.
        // Peasant check:
        // a=3 (11), b=3 (11).
        // b&1=1 -> p^=3 (p=3). a<<1=6 (110). b>>1=1.
        // b&1=1 -> p^=6 (3^6 = 011^110 = 101 = 5). Correct.
        assert_eq!(gf256_mul(3, 3), 5);

        // Inverse check: 5 * inv(5) should be 1.
        let inv5 = gf256_inv(5);
        assert_eq!(gf256_mul(5, inv5), 1);
    }

    #[test]
    fn test_shamir_reconstruction_any_subset() {
        let secret = [0x42; 32]; // Fixed secret
        let shards = Sharder::split(&secret);

        assert_eq!(shards.len(), 3);

        // Test 1 & 2
        let rec12 =
            Sharder::reconstruct(&[shards[0].clone(), shards[1].clone()]).expect("1&2 failed");
        assert_eq!(rec12, secret, "Failed to reconstruct with shards 1 and 2");

        // Test 2 & 3
        let rec23 =
            Sharder::reconstruct(&[shards[1].clone(), shards[2].clone()]).expect("2&3 failed");
        assert_eq!(rec23, secret, "Failed to reconstruct with shards 2 and 3");

        // Test 1 & 3
        let rec13 =
            Sharder::reconstruct(&[shards[0].clone(), shards[2].clone()]).expect("1&3 failed");
        assert_eq!(rec13, secret, "Failed to reconstruct with shards 1 and 3");
    }

    #[test]
    fn test_shamir_random_secret() {
        let mut rng = rand::thread_rng();
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);

        let shards = Sharder::split(&secret);

        // Pick random 2
        let rec = Sharder::reconstruct(&[shards[0].clone(), shards[2].clone()]).unwrap();
        assert_eq!(rec, secret);
    }
}

/// Manages key shards and their storage/retrieval from database
pub struct ShardManager;

impl ShardManager {
    /// Saves shards to the database
    pub async fn save_shards_to_db(
        store: &mut crate::storage::WolfStore,
        secret_id: &str,
        shards: &[KeyShard],
        _threshold: u8,
    ) -> Result<()> {
        for shard in shards {
            let data_hex: String = shard.data.iter().map(|b| format!("{:02x}", b)).collect();
            store.save_key_shard(
                &shard.shard_id,
                secret_id,
                shard.index,
                &data_hex,
            ).await?;
        }
        Ok(())
    }

    /// Loads shards for a secret from the database
    pub async fn load_shards_from_db(
        store: &crate::storage::WolfStore,
        secret_id: &str,
    ) -> Result<Vec<KeyShard>> {
        let records = store.find_shards_for_secret(secret_id).await?;
        
        let mut shards: Vec<KeyShard> = records
            .into_iter()
            .map(|record| {
                let data_hex = record.get("data_hex")
                    .ok_or_else(|| anyhow::anyhow!("Missing data_hex in shard record"))?;
                let data: Vec<u8> = (0..data_hex.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&data_hex[i..i+2], 16)
                            .map_err(|_| anyhow::anyhow!("Invalid hex in shard data"))
                    })
                    .collect::<Result<Vec<u8>, _>>()?;
                
                Ok(KeyShard {
                    shard_id: record.get("shard_id")
                        .ok_or_else(|| anyhow::anyhow!("Missing shard_id"))?
                        .clone(),
                    secret_id: secret_id.to_string(),
                    index: record.get("index")
                        .ok_or_else(|| anyhow::anyhow!("Missing index"))?
                        .parse()
                        .map_err(|_| anyhow::anyhow!("Invalid index format"))?,
                    data,
                })
            })
            .collect::<Result<Vec<KeyShard>, anyhow::Error>>()?;
        
        // Sort by index
        shards.sort_by(|a, b| a.index.cmp(&b.index));
        
        Ok(shards)
    }

    /// Checks if we have enough shards for reconstruction
    pub fn check_reconstruction_status(shards: &[KeyShard], threshold: u8) -> ShardStatus {
        let total = shards.len() as u8;
        let needed = threshold.saturating_sub(total);
        
        ShardStatus {
            total_shards: total,
            threshold,
            needed_for_recovery: needed,
            can_reconstruct: total >= threshold,
        }
    }
}

/// Status of shard collection for a specific secret.
#[derive(Debug, Clone, PartialEq)]
pub struct ShardStatus {
    /// Total number of shards found.
    pub total_shards: u8,
    /// Threshold required for reconstruction.
    pub threshold: u8,
    /// Number of additional shards needed for recovery.
    pub needed_for_recovery: u8,
    /// Whether enough shards are available to reconstruct the secret.
    pub can_reconstruct: bool,
}
