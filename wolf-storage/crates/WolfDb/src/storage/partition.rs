/// Partition types for separating vector and relational data
/// Storage partition types for separating different data workloads
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
    /// Determines the partition type and base table name from a formatted table string.
    /// Format: "`partition:table_name`" (e.g., "relational:users") or just "`table_name`" (defaults to Hybrid).
    #[must_use]
    pub fn from_table(table: &str) -> (Self, String) {
        if let Some((prefix, table_name)) = table.split_once(':') {
            let partition = match prefix {
                "relational" => Self::Relational,
                "vector" => Self::Vector,
                _ => Self::Hybrid, // Unknown prefix or "hybrid" defaults to hybrid
            };
            (partition, table_name.to_string())
        } else {
            // No prefix, default to hybrid for backward compatibility
            (Self::Hybrid, table.to_string())
        }
    }

    /// Returns the database path for this partition
    #[must_use]
    pub fn get_db_path(&self, base_path: &str) -> String {
        match self {
            Self::Relational => format!("{base_path}/relational"),
            Self::Vector => format!("{base_path}/vector"),
            Self::Hybrid => base_path.to_string(),
        }
    }

    /// Get the vector index path for this partition
    #[must_use]
    pub fn get_index_path(&self, base_path: &str, table: &str) -> String {
        match self {
            Self::Relational => {
                // Relational partitions don't have vector indices
                format!("{base_path}/indices/relational_{table}")
            }
            Self::Vector => {
                format!("{base_path}/indices/vector_{table}")
            }
            Self::Hybrid => {
                format!("{base_path}/vectors/{table}")
            }
        }
    }

    /// Returns true if this partition supports vector storage and indexing
    #[must_use]
    pub const fn supports_vectors(&self) -> bool {
        matches!(self, Self::Vector | Self::Hybrid)
    }

    /// Returns the human-readable prefix name for this partition
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Relational => "relational",
            Self::Vector => "vector",
            Self::Hybrid => "hybrid",
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
        assert_eq!(Partition::Vector.get_db_path(base), "wolf.db/vector");
        assert_eq!(Partition::Hybrid.get_db_path(base), "wolf.db");
    }

    #[test]
    fn test_supports_vectors() {
        assert!(!Partition::Relational.supports_vectors());
        assert!(Partition::Vector.supports_vectors());
        assert!(Partition::Hybrid.supports_vectors());
    }
}
