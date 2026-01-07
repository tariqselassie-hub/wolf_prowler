use fips204::ml_dsa_44; // ML-DSA-44 is the chosen parameter set via fips204
use fips204::traits::SerDes;
use std::env;
use std::fs;
use std::path::Path;

// ML-DSA-44 Constants
pub const SIG_SIZE: usize = 2420;
pub const SEQ_SIZE: usize = 8;
pub const TS_SIZE: usize = 8;
pub const PK_SIZE: usize = 1312;
pub const SK_SIZE: usize = 2560;
pub const HEADER_SIZE: usize = SIG_SIZE + SEQ_SIZE + TS_SIZE;

// ML-KEM-1024 Constants
pub const KEM_PK_SIZE: usize = 1568;
pub const KEM_SK_SIZE: usize = 3168;
pub const KEM_CT_SIZE: usize = 1568;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const CRYPTO_OVERHEAD: usize = KEM_CT_SIZE + NONCE_SIZE + TAG_SIZE;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, SerDes as KemSerDes};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum Role {
    DevOps,
    ComplianceManager,
    SecurityOfficer,
    // Add more roles as needed
}

pub fn postbox_path() -> String {
    env::var("TERSEC_POSTBOX").unwrap_or_else(|_| "/tmp/postbox".to_string())
}

pub fn log_path() -> String {
    env::var("TERSEC_LOG").unwrap_or_else(|_| "/var/log/nginx/access.log".to_string())
}

/// Loads the public key from the standard location
pub fn load_public_key<P: AsRef<Path>>(path: P) -> std::io::Result<ml_dsa_44::PublicKey> {
    let bytes = fs::read(path)?;
    // Ensure sufficient bytes
    if bytes.len() < PK_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Key file too short",
        ));
    }

    // Try to deserialize
    let array: [u8; PK_SIZE] = bytes[..PK_SIZE].try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid public key content",
        )
    })?;
    ml_dsa_44::PublicKey::try_from_bytes(array).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid public key content struct",
        )
    })
}

pub fn load_kem_public_key(path: &str) -> std::io::Result<ml_kem_1024::EncapsKey> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)?;
    let mut bytes = [0u8; KEM_PK_SIZE];
    file.read_exact(&mut bytes)?;

    // Use SerDes trait method
    ml_kem_1024::EncapsKey::try_from_bytes(bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid KEM public key"))
}

/// Encrypts data for the Sentinel.
/// Returns: KEM_CT || Nonce || AES_CT
pub fn encrypt_for_sentinel(data: &[u8], sentinel_pk: &ml_kem_1024::EncapsKey) -> Vec<u8> {
    // 1. Encapsulate -> Shared Secret
    let (ss, ct) = sentinel_pk.try_encaps().expect("Encapsulation failed");

    // 2. Derive AES Key (Use valid SS bytes directly)
    // ss is SharedSecretKey. Convert to bytes.
    // Try into_bytes() if SerDes derived, or as_ref().
    // SS size is 32 bytes.
    // Assuming into_bytes works (standard trait).
    let ss_bytes = ss.into_bytes();
    let key = Key::<Aes256Gcm>::from_slice(&ss_bytes);
    let cipher = Aes256Gcm::new(key);

    // 3. Generate Nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits

    // 4. Encrypt
    let aes_ct = cipher.encrypt(&nonce, data).expect("Encryption failed");

    // 5. Pack: CT (1568) || Nonce (12) || AES_CT (N+16)
    let ct_bytes = ct.into_bytes();
    let mut output = Vec::with_capacity(ct_bytes.len() + NONCE_SIZE + aes_ct.len());
    output.extend_from_slice(&ct_bytes);
    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&aes_ct);

    output
}

/// Decrypts data from Client
/// Input: KEM_CT || Nonce || AES_CT
pub fn decrypt_from_client(blob: &[u8], sentinel_sk: &ml_kem_1024::DecapsKey) -> Option<Vec<u8>> {
    if blob.len() < KEM_CT_SIZE + NONCE_SIZE + TAG_SIZE {
        return None;
    }

    let (kem_ct_bytes, rest) = blob.split_at(KEM_CT_SIZE);
    let (nonce_bytes, aes_ct) = rest.split_at(NONCE_SIZE);

    // 1. Decapsulate
    // Construct CipherText from bytes
    let kem_ct_array: [u8; KEM_CT_SIZE] = kem_ct_bytes.try_into().ok()?;
    let kem_ct = ml_kem_1024::CipherText::try_from_bytes(kem_ct_array).ok()?;

    let ss = sentinel_sk.try_decaps(&kem_ct).ok()?;

    // 2. Setup AES
    let ss_bytes = ss.into_bytes();
    let key = Key::<Aes256Gcm>::from_slice(&ss_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    // 3. Decrypt
    cipher.decrypt(nonce, aes_ct).ok()
}

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alphanumeric1, space0},
    sequence::tuple,
    IResult,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandMetadata {
    pub role: String,
    pub operation: String,
    pub resource: String,
    pub parameters: std::collections::HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TimeWindow {
    pub start_time: String, // HH:MM (24-hour format)
    pub end_time: String,   // HH:MM
    pub days: Vec<String>,  // Monday, Tuesday, etc.
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub roles: Vec<String>,
    pub operations: Vec<String>,
    pub resources: Vec<String>,
    pub threshold: usize,
    pub conditions: Vec<PolicyCondition>,
    pub time_windows: Option<Vec<TimeWindow>>, // Added field for time windows
    pub approval_expression: Option<String>,   // e.g., "Role:DevOps AND Role:ComplianceManager"
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GeoFence {
    pub allowed_regions: Vec<String>, // e.g., ["US-East", "EU-West"]
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PulseMetadata {
    pub timestamp: u64,
    pub location: String, // "US-East", "Local", "WebLog"
    pub method: String,   // "USB", "WEB", "TCP"
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PolicyCondition {
    RequireApproval(String), // Role name
    MaxFrequency(u32),       // Max operations per hour
    IpWhitelist(Vec<String>),
    TimeBound(TimeWindow),
    GeoBound(GeoFence),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyConfig {
    pub policies: Vec<Policy>,
    pub role_mappings: std::collections::HashMap<String, Vec<String>>, // Public key hex -> roles
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartialSignature {
    pub signer_role: Role,
    pub signature: Vec<u8>, // ML-DSA-44 signature bytes
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartialCommand {
    pub command: String,
    pub seq: u64,
    pub ts: u64,
    pub encrypted_payload: Vec<u8>,
    pub signatures: Vec<Option<PartialSignature>>,
    pub required_signers: usize,
}

pub fn create_partial_command(
    command: String,
    encrypted_payload: Vec<u8>,
    required_signers: usize,
) -> Result<PartialCommand, String> {
    let seq = 0; // Will be set when submitting
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    Ok(PartialCommand {
        command,
        seq,
        ts,
        encrypted_payload,
        signatures: vec![None; required_signers],
        required_signers,
    })
}

pub fn is_partial_complete(partial: &PartialCommand) -> bool {
    partial.signatures.iter().all(|s| s.is_some())
}

/// Packages signatures and payload into the wire format
/// Format: Count(u8) || Sig1 (2420) || Sig2 (2420) ... || Body
pub fn package_payload(signatures: &[[u8; 2420]], body: &[u8]) -> Vec<u8> {
    let count = signatures.len() as u8;
    let sig_size = 2420;
    let mut data = Vec::with_capacity(1 + (count as usize * sig_size) + body.len());

    data.push(count);
    for sig in signatures {
        data.extend_from_slice(sig);
    }
    data.extend_from_slice(body);
    data
}

pub fn parse_command_metadata(cmd: &str) -> Option<CommandMetadata> {
    // Parse JSON metadata from command (e.g., embedded as comment or prefix)
    // Format: #TERSEC_META:{"role":"admin","operation":"restart","resource":"service"}
    if let Some(start) = cmd.find("#TERSEC_META:") {
        let json_start = start + "#TERSEC_META:".len();

        // Find the end of the JSON object by looking for the closing brace
        let mut brace_count = 0;
        let mut json_end = json_start;
        let mut found_json = false;

        for (i, ch) in cmd[json_start..].chars().enumerate() {
            if ch == '{' {
                brace_count += 1;
            } else if ch == '}' {
                brace_count -= 1;
                if brace_count == 0 {
                    json_end = json_start + i + 1;
                    found_json = true;
                    break;
                }
            }
        }

        if found_json {
            let json_str = &cmd[json_start..json_end];
            // Try to parse the JSON, but handle errors gracefully
            match serde_json::from_str::<CommandMetadata>(json_str) {
                Ok(metadata) => Some(metadata),
                Err(_) => None, // Return None for malformed JSON
            }
        } else {
            None
        }
    } else {
        None
    }
}

pub fn load_policy_config<P: AsRef<Path>>(path: P) -> std::io::Result<PolicyConfig> {
    let content = fs::read_to_string(path)?;
    toml::from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[derive(Debug, Clone)]
pub enum Expr {
    Role(Role),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

fn parse_role(input: &str) -> IResult<&str, Role> {
    let (input, _) = tag("Role:")(input)?;
    let (input, role_str) = alphanumeric1(input)?;
    let role = match role_str {
        "DevOps" => Role::DevOps,
        "ComplianceManager" => Role::ComplianceManager,
        "SecurityOfficer" => Role::SecurityOfficer,
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )))
        }
    };
    Ok((input, role))
}

fn parse_expr(input: &str) -> IResult<&str, Expr> {
    // Handle parentheses first
    let parenthesized = nom::sequence::delimited(
        nom::character::complete::char('('),
        nom::combinator::complete(parse_expr),
        nom::character::complete::char(')'),
    );

    let (input, left) = nom::branch::alt((
        parenthesized,
        nom::combinator::map(parse_role, |role| Expr::Role(role)),
    ))(input)?;

    let (input, rest) = nom::combinator::opt(tuple((
        space0,
        alt((tag("AND"), tag("OR"))),
        space0,
        parse_expr,
    )))(input)?;

    match rest {
        Some((_, op, _, right)) => {
            let expr = match op {
                "AND" => Expr::And(Box::new(left), Box::new(right)),
                "OR" => Expr::Or(Box::new(left), Box::new(right)),
                _ => unreachable!(),
            };
            Ok((input, expr))
        }
        None => Ok((input, left)),
    }
}

pub fn evaluate_expression(expr: &Expr, roles: &std::collections::HashSet<Role>) -> bool {
    match expr {
        Expr::Role(r) => roles.contains(r),
        Expr::And(left, right) => {
            evaluate_expression(left, roles) && evaluate_expression(right, roles)
        }
        Expr::Or(left, right) => {
            evaluate_expression(left, roles) || evaluate_expression(right, roles)
        }
    }
}

pub fn parse_and_evaluate(
    expression: &str,
    roles: &std::collections::HashSet<Role>,
) -> Result<bool, String> {
    match parse_expr(expression) {
        Ok((remaining, expr)) => {
            // Check if there's any unparsed content remaining
            if remaining.trim().is_empty() {
                Ok(evaluate_expression(&expr, roles))
            } else {
                Err("Failed to parse expression".to_string())
            }
        }
        Err(_) => Err("Failed to parse expression".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::{KeyGen, SerDes};
    use std::io::Write;

    #[test]
    fn test_load_public_key() {
        // Generate a random PQC key
        let (pk, _sk) = ml_dsa_44::KG::try_keygen().unwrap();

        // Write to temp file
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let pk_bytes = pk.into_bytes();
        temp_file.write_all(&pk_bytes).unwrap();

        // Load and verify
        let loaded_key = load_public_key(temp_file.path()).unwrap();
        assert_eq!(loaded_key.into_bytes(), pk_bytes);
    }

    #[test]
    fn test_parse_command_metadata() {
        let cmd = "#TERSEC_META:{\"role\":\"admin\",\"operation\":\"restart\",\"resource\":\"apache\",\"parameters\":{}}\nsystemctl restart apache2";
        let meta = parse_command_metadata(cmd).unwrap();
        assert_eq!(meta.role, "admin");
        assert_eq!(meta.operation, "restart");
        assert_eq!(meta.resource, "apache");
    }

    #[test]
    fn test_policy_config() {
        let config = PolicyConfig {
            policies: vec![Policy {
                name: "admin_restart".to_string(),
                roles: vec!["admin".to_string()],
                operations: vec!["restart".to_string()],
                resources: vec!["apache".to_string(), "nginx".to_string()],
                threshold: 2,
                conditions: vec![],
                time_windows: None,
                approval_expression: None,
            }],
            role_mappings: std::collections::HashMap::new(),
        };

        let toml = toml::to_string(&config).unwrap();
        let parsed: PolicyConfig = toml::from_str(&toml).unwrap();
        assert_eq!(parsed.policies[0].name, "admin_restart");
    }

    #[test]
    fn test_parse_and_evaluate_expression() {
        use std::collections::HashSet;
        let mut roles = HashSet::new();
        roles.insert(Role::DevOps);
        roles.insert(Role::ComplianceManager);

        // Test single role
        assert!(parse_and_evaluate("Role:DevOps", &roles).unwrap());

        // Test AND
        assert!(parse_and_evaluate("Role:DevOps AND Role:ComplianceManager", &roles).unwrap());

        // Test OR
        assert!(parse_and_evaluate("Role:DevOps OR Role:SecurityOfficer", &roles).unwrap());

        // Test false
        let mut roles2 = HashSet::new();
        roles2.insert(Role::DevOps);
        assert!(!parse_and_evaluate("Role:DevOps AND Role:ComplianceManager", &roles2).unwrap());
    }
}
