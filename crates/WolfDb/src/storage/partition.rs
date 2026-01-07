

/// Partition types for separating vector and relational data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Partition {
    /// Pure relational data, no vectors
    Relational,
    /// Vector data with HNSW indexing
    Vector,
    /// Hybrid partition supporting both (default)
    Hybrid,
}

impl Partition {
    /// Determine partition from table name
    /// Format: "partition:table_name" or just "table_name" (defaults to Hybrid)
    pub fn from_table(table: &str) -> (Self, String) {
        if let Some((prefix, table_name)) = table.split_once(':') {
            let partition = match prefix {
                "relational" => Partition::Relational,
                "vector" => Partition::Vector,
                "hybrid" => Partition::Hybrid,
                _ => Partition::Hybrid, // Unknown prefix defaults to hybrid
            };
            (partition, table_name.to_string())
        } else {
            // No prefix, default to hybrid for backward compatibility
            (Partition::Hybrid, table.to_string())
        }
    }
    
    /// Get the database path for this partition
    pub fn get_db_path(&self, base_path: &str) -> String {
        match self {
            Partition::Relational => format!("{}/relational", base_path),
            Partition::Vector => format!("{}/vector", base_path),
            Partition::Hybrid => base_path.to_string(),
        }
    }
    
    /// Get the vector index path for this partition
    pub fn get_index_path(&self, base_path: &str, table: &str) -> String {
        match self {
            Partition::Relational => {
                // Relational partitions don't have vector indices
                format!("{}/indices/relational_{}", base_path, table)
            }
            Partition::Vector => {
                format!("{}/indices/vector_{}", base_path, table)
            }
            Partition::Hybrid => {
                format!("{}/vectors/{}", base_path, table)
            }
        }
    }
    
    /// Check if this partition supports vectors
    pub fn supports_vectors(&self) -> bool {
        matches!(self, Partition::Vector | Partition::Hybrid)
    }
    
    /// Get a human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Partition::Relational => "relational",
            Partition::Vector => "vector",
            Partition::Hybrid => "hybrid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_from_table() {
        assert_eq!(
            Partition::from_table("relational:users"),
            (Partition::Relational, "users".to_string())
        );
        assert_eq!(
            Partition::from_table("vector:embeddings"),
            (Partition::Vector, "embeddings".to_string())
        );
        assert_eq!(
            Partition::from_table("hybrid:products"),
            (Partition::Hybrid, "products".to_string())
        );
        assert_eq!(
            Partition::from_table("products"),
            (Partition::Hybrid, "products".to_string())
        );
    }

    #[test]
    fn test_partition_paths() {
        let base = "wolf.db";
        
        assert_eq!(
            Partition::Relational.get_db_path(base),
            "wolf.db/relational"
        );
        assert_eq!(
            Partition::Vector.get_db_path(base),
            "wolf.db/vector"
        );
        assert_eq!(
            Partition::Hybrid.get_db_path(base),
            "wolf.db"
        );
    }

    #[test]
    fn test_supports_vectors() {
        assert!(!Partition::Relational.supports_vectors());
        assert!(Partition::Vector.supports_vectors());
        assert!(Partition::Hybrid.supports_vectors());
    }
}
