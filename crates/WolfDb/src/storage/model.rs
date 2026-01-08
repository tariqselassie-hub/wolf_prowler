use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Core data unit in `WolfDb`, containing relational data and optional vector embeddings
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    /// Unique identifier for the record
    pub id: String,
    /// Metadata/relational fields stored as key-value pairs
    pub data: HashMap<String, String>, // Simple relational data
    /// Optional high-dimensional vector for similarity search
    pub vector: Option<Vec<f32>>,      // Optional vector for similarity search
}
