use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    pub id: String,
    pub data: HashMap<String, String>, // Simple relational data
    pub vector: Option<Vec<f32>>,      // Optional vector for similarity search
}
