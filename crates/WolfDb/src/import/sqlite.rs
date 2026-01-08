use crate::storage::model::Record;
use anyhow::Result;
use std::collections::HashMap;
use base64::Engine;

/// Utility for importing data from `SQLite` databases
pub struct SqliteImporter;

impl SqliteImporter {
    /// Reads all user tables from a `SQLite` file and converts them to `WolfDb` Records
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` file cannot be opened or if data retrieval fails.
    pub fn import_from_path(path: &str) -> Result<HashMap<String, Vec<Record>>> {
        let conn = rusqlite::Connection::open(path)?;

        let mut stmt = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")?;
        let tables: Vec<String> = stmt.query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;

        let mut result = HashMap::new();

        for table_name in tables {
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table_name}\""))?;
            let column_names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
            let column_count = column_names.len();

            let rows = stmt.query_map([], |row| {
                let mut data_map = HashMap::new();
                let mut id = None;

                for (i, col_name) in column_names.iter().enumerate().take(column_count) {
                    let val_ref = row.get_ref(i)?;

                    let val_str = match val_ref {
                        rusqlite::types::ValueRef::Null => "null".to_string(),
                        rusqlite::types::ValueRef::Integer(i) => i.to_string(),
                        rusqlite::types::ValueRef::Real(r) => r.to_string(),
                        rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).to_string(),
                        rusqlite::types::ValueRef::Blob(b) => base64::engine::general_purpose::STANDARD.encode(b),
                    };

                    if (col_name == "id" || col_name == "uuid") && id.is_none() {
                        id = Some(val_str.clone());
                    }

                    data_map.insert(col_name.clone(), val_str);
                }

                Ok((id, data_map))
            })?;

            let mut batch = Vec::new();
            for row_res in rows {
                let (id_opt, data): (Option<String>, HashMap<String, String>) = row_res?;
                let id = id_opt.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

                batch.push(Record {
                    id,
                    data,
                    vector: None,
                });
            }
            
            result.insert(table_name, batch);
        }

        Ok(result)
    }
}
