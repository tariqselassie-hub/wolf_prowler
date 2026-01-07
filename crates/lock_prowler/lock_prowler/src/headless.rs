use crate::hunter::{DiscoveredSecret, Hunter, SecretScanner};
use crate::storage::WolfStore;
use crate::vault::Vault;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Duration};
use wolf_net::libp2p;
use wolf_net::wolf_node::WolfNode;
use wolf_net::WolfConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessConfig {
    pub scan_paths: Vec<String>,
    pub scan_interval: u64, // seconds
    pub auto_import: bool,
    pub shard_threshold: u8,
    pub enable_wolfpack: bool,
}

impl Default for HeadlessConfig {
    fn default() -> Self {
        Self {
            scan_paths: vec!["~".to_string()],
            scan_interval: 300, // 5 minutes
            auto_import: true,
            shard_threshold: 2,
            enable_wolfpack: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadlessStatus {
    pub is_running: bool,
    pub current_target: Option<String>,
    pub progress: f32,
    pub discovered_secrets: usize,
    pub imported_secrets: usize,
    pub last_scan_time: Option<DateTime<Utc>>,
    pub next_scan_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub peer_count: usize,
    pub node_id: Option<String>,
    pub is_connected: bool,
    pub active_wolfpack_nodes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullSystemStats {
    pub headless: HeadlessStatus,
    pub database: crate::storage::DatabaseStats,
    pub network: NetworkStats,
}

pub struct HeadlessWolfProwler {
    config: HeadlessConfig,
    status: Arc<Mutex<HeadlessStatus>>,
    store: Arc<Mutex<WolfStore>>,
    scanner: SecretScanner,
    hunter: Hunter,
    log_tx: broadcast::Sender<String>,
    wolf_node: Arc<RwLock<Option<WolfNode>>>,
}

impl HeadlessWolfProwler {
    pub fn new(config: HeadlessConfig, store: WolfStore) -> Self {
        let (log_tx, _) = broadcast::channel(100);
        let wolf_node = Arc::new(RwLock::new(None));

        if config.enable_wolfpack {
            let node_clone = wolf_node.clone();
            let _config_clone = config.clone();
            tokio::spawn(async move {
                // Initialize defaults for now, in prod this comes from config file
                let mut wolf_config = WolfConfig::default();

                // Override with environment variables for simulation/staging
                if let Ok(port_str) = std::env::var("WOLF_P2P_PORT") {
                    if let Ok(port) = port_str.parse::<u16>() {
                        wolf_config.network.listen_port = port;
                        println!("[Headless] Configured P2P port via env: {}", port);
                    }
                }

                if let Ok(seed) = std::env::var("WOLF_IDENTITY_SEED") {
                    println!("[Headless] WOLF_IDENTITY_SEED env var found");
                    wolf_config.network.identity_seed = Some(seed);
                }

                if let Ok(bootstrap_str) = std::env::var("WOLF_BOOTSTRAP") {
                    println!("[Headless] WOLF_BOOTSTRAP env var found: {}", bootstrap_str);
                    if let Ok(addr) = bootstrap_str.parse::<libp2p::Multiaddr>() {
                        // For simulation, we assume specific peer IDs derived from known seeds
                        // Alpha: seed=alpha -> PeerID ...
                        // This is a simplification; in production we'd pass full Multiaddr including PeerID

                        // We need the bootstrap peer ID to be correct for libp2p noise handshake
                        // For now we just add the address, SwarmManager logic handles discovery
                        wolf_config
                            .network
                            .bootstrap_peers
                            .push((libp2p::PeerId::random(), addr));
                    }
                }

                match WolfNode::new(wolf_config).await {
                    Ok(node) => {
                        let mut guard: tokio::sync::RwLockWriteGuard<Option<WolfNode>> =
                            node_clone.write().await;
                        *guard = Some(node);
                        println!("[Headless] WolfNode initialized successfully");
                    }
                    Err(e) => {
                        println!("[Headless] Failed to initialize WolfNode: {}", e);
                    }
                }
            });
        }

        Self {
            config,
            status: Arc::new(Mutex::new(HeadlessStatus {
                is_running: false,
                current_target: None,
                progress: 0.0,
                discovered_secrets: 0,
                imported_secrets: 0,
                last_scan_time: None,
                next_scan_time: None,
            })),
            store: Arc::new(Mutex::new(store)),
            scanner: SecretScanner::new(),
            hunter: Hunter::new(),
            log_tx,
            wolf_node,
        }
    }

    pub fn subscribe_logs(&self) -> broadcast::Receiver<String> {
        self.log_tx.subscribe()
    }

    fn log(&self, msg: String) {
        let timestamp = Utc::now().format("%H:%M:%S");
        let formatted = format!("[{}] {}", timestamp, msg);
        println!("{}", formatted);
        let _ = self.log_tx.send(formatted);
    }

    pub async fn start(&self) -> Result<()> {
        let mut status = self.status.lock().await;
        status.is_running = true;
        status.progress = 0.0;
        drop(status);

        self.log("Starting automated scan service...".to_string());

        // Start the main scanning loop
        let status_clone = self.status.clone();
        let store_clone = self.store.clone();
        let scanner_clone = SecretScanner::new();
        let hunter_clone = Hunter::new();
        let config_clone = self.config.clone();
        let log_tx_clone = self.log_tx.clone();

        tokio::spawn(async move {
            Self::scan_loop(
                status_clone,
                store_clone,
                scanner_clone,
                hunter_clone,
                config_clone,
                log_tx_clone,
            )
            .await;
        });

        // Start WolfNode if present
        let wolf_node_clone = self.wolf_node.clone();
        tokio::spawn(async move {
            let mut guard: tokio::sync::RwLockWriteGuard<Option<WolfNode>> =
                wolf_node_clone.write().await;
            if let Some(node) = guard.as_mut() {
                println!("[Headless] Starting WolfNode event loop...");
                if let Err(e) = node.run().await {
                    println!("[Headless] WolfNode run error: {}", e);
                }
            }
        });

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut status = self.status.lock().await;
        status.is_running = false;
        status.progress = 0.0;
        println!("[Headless] Stopping automated scan service...");
        Ok(())
    }

    pub async fn get_status(&self) -> HeadlessStatus {
        let status = self.status.lock().await;
        status.clone()
    }

    pub async fn get_store_stats(&self) -> crate::storage::DatabaseStats {
        let store = self.store.lock().await;
        store.get_stats().clone()
    }

    pub async fn list_database_records(
        &self,
        table: &str,
    ) -> Result<Vec<wolf_db::storage::model::Record>> {
        let store = self.store.lock().await;
        store.list_table_records(table)
    }

    pub async fn add_database_record(
        &self,
        table: &str,
        id: &str,
        data: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let mut store = self.store.lock().await;
        store.generic_insert(table, id, data)
    }

    pub async fn delete_database_record(&self, table: &str, id: &str) -> Result<()> {
        let mut store = self.store.lock().await;
        store.delete_record(table, id)
    }

    pub async fn get_network_stats(&self) -> NetworkStats {
        let guard: tokio::sync::RwLockReadGuard<Option<WolfNode>> = self.wolf_node.read().await;
        if let Some(node) = guard.as_ref() {
            let metrics: tokio::sync::RwLockReadGuard<
                std::collections::HashMap<wolf_net::PeerId, wolf_net::peer::EntityInfo>,
            > = node.metrics.read().await;
            let peer_count = metrics.len();

            // Extract some "active" node IDs for display
            // p type is infered as &wolf_net::PeerId due to map key type
            let active_wolfpack_nodes = metrics.keys().take(5).map(|p| p.to_string()).collect();

            NetworkStats {
                peer_count,
                node_id: Some("local-node".to_string()), // TODO: access actual ID
                is_connected: true,
                active_wolfpack_nodes,
            }
        } else {
            NetworkStats {
                peer_count: 0,
                node_id: None,
                is_connected: false,
                active_wolfpack_nodes: vec![],
            }
        }
    }

    pub async fn scan_target(&mut self, target_path: &str) -> Result<Vec<DiscoveredSecret>> {
        self.log(format!("Starting manual scan of: {}", target_path));

        let path = PathBuf::from(target_path);
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "Target path does not exist: {}",
                target_path
            ));
        }

        // Update status
        {
            let mut status = self.status.lock().await;
            status.current_target = Some(target_path.to_string());
            status.progress = 0.0;
        }

        // Perform scan
        let results = self.scanner.scan(&path);

        // Update progress
        {
            let mut status = self.status.lock().await;
            status.discovered_secrets = results.len();
            status.progress = 100.0;
            status.last_scan_time = Some(Utc::now());
        }

        // Auto-import if enabled
        if self.config.auto_import {
            self.import_discovered_secrets(&results).await?;
        }

        // Save results to database
        {
            let mut store = self.store.lock().await;
            self.hunter
                .save_scan_results(&mut store, &results)
                .context("Failed to save scan results to database")?;
        }

        self.log(format!("Scan completed. Found {} secrets", results.len()));
        Ok(results)
    }

    async fn scan_loop(
        status: Arc<Mutex<HeadlessStatus>>,
        store: Arc<Mutex<WolfStore>>,
        scanner: SecretScanner,
        mut hunter: Hunter,
        config: HeadlessConfig,
        log_tx: broadcast::Sender<String>,
    ) {
        loop {
            let mut status_guard = status.lock().await;
            if !status_guard.is_running {
                drop(status_guard);
                sleep(Duration::from_millis(1000)).await;
                continue;
            }

            // Calculate next scan time
            let next_scan = Utc::now() + chrono::Duration::seconds(config.scan_interval as i64);
            status_guard.next_scan_time = Some(next_scan);
            drop(status_guard);

            // Scan each configured path
            for path_str in &config.scan_paths {
                let path = PathBuf::from(shellexpand::tilde(path_str).to_string());
                if !path.exists() {
                    println!("[Headless] Skipping non-existent path: {}", path_str);
                    continue;
                }

                let _ = log_tx.send(format!("[Headless] Scanning: {}", path.display()));

                // Update progress
                {
                    let mut status_guard = status.lock().await;
                    status_guard.current_target = Some(path.display().to_string());
                    status_guard.progress = 0.0;
                }

                // Perform scan
                let results = scanner.scan(&path);

                // Update discovered count
                {
                    let mut status_guard = status.lock().await;
                    status_guard.discovered_secrets += results.len();
                    status_guard.progress = 50.0;
                }

                // Auto-import if enabled
                if config.auto_import {
                    if let Err(e) = Self::import_secrets_to_vault(&store, &results).await {
                        let _ = log_tx.send(format!("[Headless] Failed to import secrets: {}", e));
                    }
                }

                // Save results to database
                {
                    let mut store_guard = store.lock().await;
                    if let Err(e) = hunter.save_scan_results(&mut store_guard, &results) {
                        let _ =
                            log_tx.send(format!("[Headless] Failed to save scan results: {}", e));
                    }
                }

                // Update progress
                {
                    let mut status_guard = status.lock().await;
                    status_guard.progress = 100.0;
                    status_guard.last_scan_time = Some(Utc::now());
                }

                // Small delay between paths
                sleep(Duration::from_millis(1000)).await;
            }

            // Wait for next scan interval
            sleep(Duration::from_secs(config.scan_interval)).await;
        }
    }

    async fn import_secrets_to_vault(
        store: &Arc<Mutex<WolfStore>>,
        secrets: &[DiscoveredSecret],
    ) -> Result<()> {
        let mut store_guard = store.lock().await;
        let mut vault =
            Vault::load_from_db(&mut store_guard).context("Failed to load vault for import")?;

        let mut imported_count = 0;
        let master_key = generate_master_key();

        for secret in secrets {
            let entry_id = format!(
                "auto_{:?}_{}",
                secret.distinct_type,
                Utc::now().timestamp_millis()
            );

            // For auto-import, we'll use a placeholder for the actual secret data
            // In a real implementation, you'd extract the actual secret content
            let placeholder_data = format!(
                "Auto-imported {:?} from {}",
                secret.distinct_type,
                secret.path.display()
            );

            if let Err(e) = vault.add_secret(
                &master_key,
                &entry_id,
                secret.distinct_type.clone(),
                placeholder_data.as_bytes(),
            ) {
                println!("[Headless] Failed to add secret to vault: {}", e);
                continue;
            }

            imported_count += 1;
        }

        if imported_count > 0 {
            vault
                .save_to_db(&mut store_guard)
                .context("Failed to save vault after import")?;
            println!("[Headless] Imported {} secrets to vault", imported_count);
        }

        Ok(())
    }

    async fn import_discovered_secrets(&self, secrets: &[DiscoveredSecret]) -> Result<()> {
        Self::import_secrets_to_vault(&self.store, secrets).await
    }
}

fn generate_master_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_headless_prowler() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_db");

        let store = WolfStore::new(db_path.to_str().unwrap()).unwrap();
        let config = HeadlessConfig::default();
        let prowler = HeadlessWolfProwler::new(config, store);

        // Test status
        let status = prowler.get_status().await;
        assert!(!status.is_running);
        assert_eq!(status.discovered_secrets, 0);

        // Test starting
        prowler.start().await.unwrap();
        let status = prowler.get_status().await;
        assert!(status.is_running);

        // Test stopping
        prowler.stop().await.unwrap();
        let status = prowler.get_status().await;
        assert!(!status.is_running);
    }
}
