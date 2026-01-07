use crate::vault::SecretType;
use crate::storage::WolfStore;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Represents a scan result that can be stored in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub path: String,
    pub secret_type: String,
    pub confidence: f32,
    pub suggestion: String,
    pub scanned_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Represents a scan session with multiple results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hunter {
    pub scan_history: Vec<ScanResult>,
}

impl Hunter {
    pub fn new() -> Self {
        Self {
            scan_history: Vec::new(),
        }
    }

    /// Saves a scan result to the database
    pub fn save_scan_result(&mut self, store: &mut WolfStore, result: &DiscoveredSecret) -> Result<()> {
        let scan_result = ScanResult {
            id: format!("scan_{}", chrono::Utc::now().timestamp_millis()),
            path: result.path.to_string_lossy().to_string(),
            secret_type: format!("{:?}", result.distinct_type),
            confidence: result.confidence,
            suggestion: result.suggestion.clone(),
            scanned_at: Utc::now(),
            metadata: HashMap::new(),
        };
        
        // Save to database
        store.save_session(&scan_result.id, scan_result.metadata.clone())
            .context("Failed to save scan result")?;
        
        // Add to local history
        self.scan_history.push(scan_result);
        
        println!("[Hunter] Saved scan result: {}", result.path.to_string_lossy());
        Ok(())
    }

    /// Saves multiple scan results to the database
    pub fn save_scan_results(&mut self, store: &mut WolfStore, results: &[DiscoveredSecret]) -> Result<usize> {
        let mut saved_count = 0;
        
        for result in results {
            if self.save_scan_result(store, result).is_ok() {
                saved_count += 1;
            }
        }
        
        println!("[Hunter] Saved {}/{} scan results to database", saved_count, results.len());
        Ok(saved_count)
    }

    /// Loads scan history from the database
    pub fn load_scan_history(&mut self, _store: &mut WolfStore) -> Result<()> {
        println!("[Hunter] Loading scan history from database");
        
        // This would load all session records from the forensics table
        // For now, we keep the scan_history in memory
        
        Ok(())
    }

    /// Returns scan results filtered by secret type
    pub fn get_results_by_type(&self, secret_type: &SecretType) -> Vec<&ScanResult> {
        let type_str = format!("{:?}", secret_type);
        self.scan_history
            .iter()
            .filter(|r| r.secret_type == type_str)
            .collect()
    }

    /// Returns all scan results
    pub fn get_all_results(&self) -> &[ScanResult] {
        &self.scan_history
    }

    /// Clears the scan history
    pub fn clear_history(&mut self) {
        self.scan_history.clear();
    }
}

impl Default for Hunter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredSecret {
    pub path: PathBuf,
    pub distinct_type: SecretType,
    pub confidence: f32,
    pub suggestion: String,
}

pub struct SecretScanner {
    rules: Vec<ScanRule>,
}

struct ScanRule {
    secret_type: SecretType,
    filename_regex: Option<Regex>,
    #[allow(dead_code)]
    content_regex: Option<Regex>,
}

impl SecretScanner {
    pub fn new() -> Self {
        // Initialize with robust default rules for the "Hunter" ranges
        let rules = vec![
            // Identity Range
            ScanRule {
                secret_type: SecretType::SSH,
                filename_regex: Some(Regex::new(r"^id_rsa$|^id_ed25519$").unwrap()),
                content_regex: Some(Regex::new(r"BEGIN OPENSSH PRIVATE KEY").unwrap()),
            },
            ScanRule {
                secret_type: SecretType::PGP,
                filename_regex: Some(Regex::new(r"^secring\.gpg$").unwrap()),
                content_regex: None,
            },
            // Cloud Range
            ScanRule {
                secret_type: SecretType::APIKey,
                filename_regex: Some(Regex::new(r"^credentials$").unwrap()), // .aws/credentials
                content_regex: Some(Regex::new(r"aws_access_key_id").unwrap()),
            },
            ScanRule {
                secret_type: SecretType::APIKey,
                filename_regex: Some(Regex::new(r"^kubeconfig$|^config$").unwrap()),
                content_regex: Some(Regex::new(r"apiVersion: v1").unwrap()),
            },
            // Dev Range
            ScanRule {
                secret_type: SecretType::Generic,
                filename_regex: Some(Regex::new(r"^\.env$").unwrap()),
                content_regex: Some(Regex::new(r"API_KEY|SECRET|PASSWORD").unwrap()),
            },
        ];

        Self { rules }
    }

    /// Scans a directory structure for potential secrets.
    pub fn scan(&self, root: &Path) -> Vec<DiscoveredSecret> {
        let mut results = Vec::new();

        // Safety limit: Don't cross file systems or go too deep in this version
        for entry in WalkDir::new(root)
            .max_depth(5)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(secret) = self.inspect_file(entry.path()) {
                    results.push(secret);
                }
            }
        }

        results
    }

    fn inspect_file(&self, path: &Path) -> Option<DiscoveredSecret> {
        let filename = path.file_name()?.to_string_lossy();

        for rule in &self.rules {
            // Check filename first (fast)
            if let Some(re) = &rule.filename_regex {
                if re.is_match(&filename) {
                    // Start with high confidence if filename matches
                    let confidence = 0.8;

                    // Simple logic: if filename matched, it's a good candidate.
                    // Reading content would verify it (increase to 0.99),
                    // but we might skip that for performance/permissions in this initial version.

                    return Some(DiscoveredSecret {
                        path: path.to_path_buf(),
                        distinct_type: rule.secret_type.clone(),
                        confidence,
                        suggestion: format!("Import detected {:?} credential", rule.secret_type),
                    });
                }
            }
        }
        None
    }
}

// Default constructor
impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}
