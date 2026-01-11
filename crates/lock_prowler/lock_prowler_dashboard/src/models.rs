use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemStats {
    pub volume_size: String,
    pub encrypted_sectors: f32,
    pub entropy: f32,
    pub db_status: String,
}
