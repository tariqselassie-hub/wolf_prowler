use crate::core::security_policy::SecurityPolicy;
use crate::core::{AppSettings, P2PNetwork, WolfRole};
use crate::persistence::PersistenceManager;
use crate::network_extensions::NetworkSecurityManagerExt;
use crate::threat_feeds::ThreatDatabase;
use crate::utils::metrics_simple::{MetricsCollector, SystemEvent};
use anyhow::Result;
use axum::extract::FromRef;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;
use wolf_den::CryptoEngine;
use wolf_net::{firewall::FirewallRule, Message, MessageType, SwarmCommand, SwarmManager};
use wolfsec::network_security::{
    SecurityLevel, SecurityManager as NetworkSecurityManager, SecuritySession,
};
use wolfsec::security::advanced::compliance::ComplianceFrameworkManager;
use wolfsec::security::advanced::container_security::ContainerSecurityManager;
use wolfsec::security::advanced::risk_assessment::RiskAssessmentManager;
use wolfsec::security::advanced::SecurityManager;
use wolfsec::WolfSecurity;
use wolf_den::{
    symmetric::create_cipher,
    Cipher, CipherSuite, SecurityLevel as WolfDenSecurityLevel,
};

/// Consolidated application state for the entire dashboard.
/// Optimized to reduce cloning overhead by using an internal Arc.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

impl Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct AppStateInner {
    pub config: Arc<RwLock<AppSettings>>,
    pub network: Arc<RwLock<P2PNetwork>>,
    pub security_events: Arc<RwLock<Vec<SystemEvent>>>,
    pub crypto: Arc<CryptoEngine>,
    pub wolf_security: Arc<RwLock<WolfSecurity>>,
    pub security_manager: Arc<SecurityManager>,
    pub broadcast_tx: broadcast::Sender<String>,
    pub peers: Arc<RwLock<HashMap<String, ApiPeerInfo>>>,
    pub sessions: Arc<RwLock<HashMap<String, UserSession>>>,
    pub metrics: Arc<MetricsCollector>,
    pub security_level: Arc<SecurityLevel>,
    pub swarm_manager: Arc<SwarmManager>,
    pub container_security: Arc<RwLock<ContainerSecurityManager>>,
    pub system_metrics: Arc<RwLock<SystemMetricsData>>, // This is fine, it's for live metrics
    pub risk_manager: Arc<RwLock<RiskAssessmentManager>>,
    pub compliance_manager: Arc<RwLock<ComplianceFrameworkManager>>,
    /// Messaging service
    pub howl_service: Arc<HowlService>,
    /// Vault service
    pub vault_service: Arc<VaultService>,
    /// Threat service
    pub threat_service: Arc<ThreatService>,
    /// Rate limiting for login attempts
    pub login_attempts: Arc<RwLock<HashMap<IpAddr, (u32, Instant)>>>,
    /// Unified security policy
    pub security_policy: Arc<RwLock<SecurityPolicy>>,
    /// Llama 3 Client ("Black")
    pub wolf_brain: Arc<crate::wolf_brain::LlamaClient>,
    #[cfg(feature = "advanced_reporting")]
    pub db_pool: Option<sqlx::PgPool>,
    pub persistence: Option<Arc<PersistenceManager>>,
}

pub struct HowlService {
    pub howl_messages: Arc<RwLock<Vec<HowlMessage>>>,
    pub howl_channels: Arc<RwLock<HashMap<String, HowlChannel>>>,
    pub message_routes: Arc<RwLock<HashMap<String, Vec<String>>>>,
    pub active_sessions: Arc<RwLock<HashMap<String, SecuritySession>>>,
    pub network_security: Arc<NetworkSecurityManager>,
    pub security_events: Arc<RwLock<Vec<SystemEvent>>>,
    pub message_store: Arc<RwLock<Vec<StoredHowlMessage>>>,
    pub message_metadata: Arc<RwLock<HashMap<String, MessageMetadata>>>,
    pub swarm_manager: Arc<SwarmManager>,
}

impl HowlService {
    const XOR_KEY: &'static [u8] = b"wolf_prowler_encryption_key_12345";

    pub async fn send_howl(
        &self,
        channel: String,
        recipient: Option<String>,
        message: String,
        priority: String,
    ) -> Result<serde_json::Value> {
        let message_id = Uuid::new_v4().to_string();

        // Log security event
        let event = SystemEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: "howl_sent".to_string(),
            message: format!("Howl message sent to channel: {}", channel),
            severity: "info".to_string(),
            source: "howl_service".to_string(),
            user_id: None,
            ip_address: None,
            metadata: HashMap::new(),
            correlation_id: None,
        };
        self.security_events.write().await.push(event);

        let howl_message = HowlMessage {
            id: message_id.clone(),
            channel: channel.clone(),
            recipient: recipient.clone(),
            message: message.clone(),
            priority: priority.clone(),
            sender: "Omega".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            encrypted: true,
        };

        let message_data = serde_json::to_vec(&howl_message)?;
        let mut successful_deliveries = Vec::new();
        let mut failed_deliveries = Vec::new();

        if let Some(target) = recipient {
            match self.send_to_pack_member(&target, &message_data).await {
                Ok(_) => successful_deliveries.push(target),
                Err(e) => failed_deliveries.push((target, e.to_string())),
            }
        } else {
            let target_peers = {
                let routes = self.message_routes.read().await;
                routes.get(&channel).cloned().unwrap_or_default()
            };

            for peer_id in target_peers {
                match self.send_to_pack_member(&peer_id, &message_data).await {
                    Ok(_) => successful_deliveries.push(peer_id),
                    Err(e) => failed_deliveries.push((peer_id, e.to_string())),
                }
            }
        }

        self.howl_messages.write().await.push(howl_message);

        Ok(serde_json::json!({
            "success": true,
            "message": "Howl sent successfully",
            "delivered_to": successful_deliveries,
            "failed_deliveries": failed_deliveries
        }))
    }

    pub async fn get_messages(&self) -> Vec<HowlMessage> {
        let messages = self.howl_messages.read().await;
        messages
            .iter()
            .map(|msg| {
                let decrypted_content = if let Ok(ciphertext) = hex::decode(&msg.message) {
                    let mut decrypted = Vec::with_capacity(ciphertext.len());
                    for (i, &byte) in ciphertext.iter().enumerate() {
                        decrypted.push(byte ^ Self::XOR_KEY[i % Self::XOR_KEY.len()]);
                    }
                    String::from_utf8(decrypted).unwrap_or_else(|_| "Decryption failed".to_string())
                } else {
                    msg.message.clone()
                };

                HowlMessage {
                    message: decrypted_content,
                    ..msg.clone()
                }
            })
            .collect()
    }

    /// Returns all available howl channels, initializing defaults if none exist.
    pub async fn get_channels(&self) -> Vec<HowlChannel> {
        {
            let channels = self.howl_channels.read().await;
            if !channels.is_empty() {
                return channels.values().cloned().collect();
            }
        }

        let mut channels_mut = self.howl_channels.write().await;
        if channels_mut.is_empty() {
            channels_mut.insert(
                "alpha".to_string(),
                HowlChannel {
                    id: "alpha".to_string(),
                    name: "Alpha Channel".to_string(),
                    description: "Admin-only channel for critical communications".to_string(),
                    members: vec!["omega".to_string(), "alpha_tech".to_string()],
                    created: Utc::now().to_rfc3339(),
                    encrypted: true,
                },
            );
            channels_mut.insert(
                "pack".to_string(),
                HowlChannel {
                    id: "pack".to_string(),
                    name: "Pack Channel".to_string(),
                    description: "General channel for all pack members".to_string(),
                    members: vec![
                        "omega".to_string(),
                        "alpha_tech".to_string(),
                        "beta_1".to_string(),
                    ],
                    created: Utc::now().to_rfc3339(),
                    encrypted: true,
                },
            );
        }
        channels_mut.values().cloned().collect()
    }

    pub async fn send_to_pack_member(&self, peer_id: &str, message: &[u8]) -> Result<()> {
        let session_id = format!("session_{}", peer_id);
        let session_exists = self.active_sessions.read().await.contains_key(&session_id);

        if !session_exists {
            // Note: create_session is currently a simulation helper in extensions
            let new_session = self.network_security.create_session(peer_id).await?;
            self.active_sessions
                .write()
                .await
                .insert(session_id.clone(), new_session);
        }

        // 1. Encrypt payload using NetworkSecurityManagerExt
        let encrypted_payload = self
            .network_security
            .encrypt_message(&session_id, message)
            .await?;

        // 2. Parse PeerId
        let target_peer_id = wolf_net::PeerId::from_string(peer_id.to_string());

        // 3. Construct Message
        let msg = Message {
            id: Uuid::new_v4().to_string(),
            from: wolf_net::PeerId::from_string(self.swarm_manager.local_peer_id.to_string()),
            to: Some(target_peer_id.clone()),
            message_type: MessageType::Data {
                data: encrypted_payload,
                format: "howl".to_string(),
                checksum: None,
                encrypted: true,
            },
            timestamp: Utc::now(),
            signature: None,
            encryption_key_id: None,
            version: "1.0".to_string(),
            ttl: Some(chrono::Duration::minutes(5)),
            priority: wolf_net::message::MessagePriority::High,
            metadata: HashMap::new(),
            routing_path: Vec::new(),
        };

        // 4. Send via SwarmManager
        let sender = self.swarm_manager.command_sender();
        sender
            .send(SwarmCommand::SendMessage {
                target: target_peer_id,
                message: msg,
            })
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send swarm command: {}", e))?;

        Ok(())
    }

    pub async fn store_message(&self, message: StoredHowlMessage) -> Result<()> {
        let mut store = self.message_store.write().await;
        store.push(message);
        Ok(())
    }

    pub async fn update_message_metadata(&self, message_id: &str, metadata: MessageMetadata) {
        let mut metadata_store = self.message_metadata.write().await;
        metadata_store.insert(message_id.to_string(), metadata);
    }
}

pub struct ThreatService {
    pub threat_db: Arc<RwLock<ThreatDatabase>>,
    pub wolf_security: Arc<RwLock<WolfSecurity>>,
    pub security_events: Arc<RwLock<Vec<SystemEvent>>>,
}

impl ThreatService {
    pub async fn get_intelligence(&self) -> serde_json::Value {
        let db = self.threat_db.read().await;
        let wolf_status = self
            .wolf_security
            .read()
            .await
            .threat_detector
            .get_status()
            .await;
        let active_threats = self
            .wolf_security
            .read()
            .await
            .threat_detector
            .get_active_threats()
            .await;

        let threat_types: Vec<String> = active_threats
            .iter()
            .map(|t| format!("{:?}", t.severity))
            .collect();

        serde_json::json!({
            "internal_status": wolf_status,
            "feed_stats": {
                "known_bad_ips": db.malicious_ips.len(),
                "known_cves": db.known_cves.len(),
                "last_updated": db.last_updated,
                "total_threats": active_threats.len(),
                "threat_types": threat_types
            }
        })
    }

    pub async fn get_cve_feed(&self) -> serde_json::Value {
        let internal_vulns = self
            .wolf_security
            .read()
            .await
            .vulnerability_scanner
            .get_vulnerabilities()
            .await;
        let db = self.threat_db.read().await;

        let feed_cves: Vec<serde_json::Value> = db.known_cves.values().map(|v| {
            serde_json::json!({"id": v.id, "cvss": v.severity, "summary": v.description, "status": v.status, "source": "External Feed"})
        }).collect();

        let internal_cves: Vec<serde_json::Value> = internal_vulns.iter().map(|v| {
            serde_json::json!({"id": v.cve_id, "cvss": v.cvss_score, "summary": v.description, "status": v.status, "source": "Internal Scanner"})
        }).collect();

        let all_cves = [feed_cves, internal_cves].concat();
        let total_critical = all_cves
            .iter()
            .filter(|v| v["cvss"].as_f64().unwrap_or(0.0) >= 9.0)
            .count();
        let total_high = all_cves
            .iter()
            .filter(|v| {
                let score = v["cvss"].as_f64().unwrap_or(0.0);
                score >= 7.0 && score < 9.0
            })
            .count();

        serde_json::json!({
            "total_critical": total_critical,
            "total_high": total_high,
            "cves": all_cves,
            "last_updated": db.last_updated
        })
    }

    pub async fn perform_scan(&self, scan_type: &str, target: &str) -> Result<serde_json::Value> {
        match self
            .wolf_security
            .read()
            .await
            .vulnerability_scanner
            .perform_scan()
            .await
        {
            Ok(results) => Ok(serde_json::json!({
                "success": true,
                "message": format!("Vulnerability scan ({}) completed successfully on {}", scan_type, target),
                "issues_found": results.len(),
                "scan_params": {"type": scan_type, "target": target},
                "timestamp": Utc::now().to_rfc3339()
            })),
            Err(e) => Err(anyhow::anyhow!("Failed to perform scan: {}", e)),
        }
    }

    pub async fn manual_scan(&self, target_type: &str, target_value: &str) -> serde_json::Value {
        let db = self.threat_db.read().await;
        let mut found = false;
        let mut details = "No threats detected in local database".to_string();
        let target_value = target_value.trim();

        match target_type.to_lowercase().as_str() {
            "ip" => {
                if db.malicious_ips.contains(target_value) {
                    found = true;
                    details = "IP found in malicious blocklist".to_string();
                }
            }
            "cve" => {
                if let Some(cve) = db.known_cves.get(target_value) {
                    found = true;
                    details = format!("CVE found: {}", cve.description);
                }
            }
            _ => {
                if db.malicious_ips.contains(target_value) {
                    found = true;
                    details = "Found in IP blocklist".to_string();
                } else if let Some(cve) = db.known_cves.get(target_value) {
                    found = true;
                    details = format!("Found in CVE database: {}", cve.description);
                }
            }
        }

        let event = SystemEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: "manual_threat_scan".to_string(),
            message: format!(
                "Manual scan for {} ({}): {}",
                target_value,
                target_type,
                if found { "THREAT" } else { "CLEAN" }
            ),
            severity: if found {
                "high".to_string()
            } else {
                "info".to_string()
            },
            source: "threat_service".to_string(),
            user_id: None,
            ip_address: if target_type == "ip" {
                Some(target_value.to_string())
            } else {
                None
            },
            metadata: HashMap::from([
                ("target".to_string(), target_value.to_string()),
                ("found".to_string(), found.to_string()),
            ]),
            correlation_id: None,
        };
        self.security_events.write().await.push(event);

        serde_json::json!({
            "success": true,
            "found": found,
            "details": details,
            "target": target_value,
            "timestamp": Utc::now().to_rfc3339()
        })
    }

    pub async fn resolve_threat(
        &self,
        id: String,
        resolution: Option<String>,
    ) -> serde_json::Value {
        let resolution = resolution.unwrap_or_else(|| "Manual resolution".to_string());
        let event = SystemEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: "threat_resolved".to_string(),
            message: format!("Threat {} resolved: {}", id, resolution),
            severity: "info".to_string(),
            source: "threat_service".to_string(),
            user_id: None,
            ip_address: None,
            metadata: HashMap::from([
                ("threat_id".to_string(), id.clone()),
                ("resolution".to_string(), resolution.clone()),
            ]),
            correlation_id: None,
        };
        self.security_events.write().await.push(event);
        serde_json::json!({
            "success": true,
            "message": format!("Threat {} marked as resolved", id),
            "resolution": resolution,
            "timestamp": Utc::now().to_rfc3339()
        })
    }

    pub async fn block_ip(&self, ip: String, reason: Option<String>) -> serde_json::Value {
        let reason = reason.unwrap_or_else(|| "Manual block".to_string());
        {
            let mut db = self.threat_db.write().await;
            db.malicious_ips.insert(ip.clone());
        }
        let event = SystemEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: "ip_blocked_manual".to_string(),
            message: format!("IP {} manually blocked: {}", ip, reason),
            severity: "warning".to_string(),
            source: "threat_service".to_string(),
            user_id: None,
            ip_address: Some(ip.clone()),
            metadata: HashMap::from([("reason".to_string(), reason.clone())]),
            correlation_id: None,
        };
        self.security_events.write().await.push(event);

        serde_json::json!({
            "success": true,
            "message": format!("IP {} manually blocked: {}", ip, reason),
            "ip": ip,
            "reason": reason,
            "timestamp": Utc::now().to_rfc3339()
        })
    }
}

pub struct VaultService {
    pub vault: Arc<RwLock<Vec<VaultItem>>>,
    pub unlocked_key: Arc<RwLock<Option<Vec<u8>>>>,
    pub crypto: Arc<CryptoEngine>,
    pub config: Arc<RwLock<AppSettings>>,
}

impl VaultService {
    pub async fn unlock(&self, password: &str) -> bool {
        let config = self.config.read().await;
        let admin_password = config.dashboard.admin_password.as_bytes();
        let user_password = password.as_bytes();
        let success = self.crypto.secure_compare(user_password, admin_password);
        
        if success {
            // Derive a session key from the password for vault encryption
            // In a real scenario, we might use a master key, but here we derive from admin pass
            let salt = b"wolf_prowler_vault_salt_static"; // Fixed salt for reproducibility in this context
            if let Ok(key) = self.crypto.derive_key(user_password, salt, 32).await {
                *self.unlocked_key.write().await = Some(key);
                return true;
            }
        }
        false
    }

    pub async fn is_unlocked(&self) -> bool {
        self.unlocked_key.read().await.is_some()
    }

    pub async fn get_items(&self) -> Result<Vec<VaultItem>, String> {
        let key_guard = self.unlocked_key.read().await;
        let key = key_guard.as_ref().ok_or("Vault is locked")?;
        
        let cipher = create_cipher(CipherSuite::ChaCha20Poly1305, WolfDenSecurityLevel::Maximum)
            .map_err(|e| e.to_string())?;

        let raw_items = self.vault.read().await;
        let mut decrypted_items = Vec::new();

        for item in raw_items.iter() {
            let parts: Vec<&str> = item.content.split(':').collect();
            if parts.len() != 2 {
                // Skip invalid items or return error? Skipping for now to avoid crash
                continue;
            }
            
            let nonce = hex::decode(parts[0]).map_err(|_| "Invalid nonce hex")?;
            let ciphertext = hex::decode(parts[1]).map_err(|_| "Invalid ciphertext hex")?;

            match cipher.decrypt(&ciphertext, key, &nonce).await {
                Ok(plaintext) => {
                     let mut new_item = item.clone();
                     new_item.content = String::from_utf8(plaintext).unwrap_or_else(|_| "Invalid UTF-8".to_string());
                     decrypted_items.push(new_item);
                },
                Err(_) => {
                    // Decryption failed (wrong key?), skip or show error placeholder
                    let mut err_item = item.clone();
                    err_item.content = "[Decryption Failed]".to_string();
                    decrypted_items.push(err_item);
                }
            }
        }

        Ok(decrypted_items)
    }

    pub async fn add_item(
        &self,
        name: String,
        content: String,
        category: String,
    ) -> Result<(), String> {
        let key_guard = self.unlocked_key.read().await;
        let key = key_guard.as_ref().ok_or("Vault is locked")?;

        let cipher = create_cipher(CipherSuite::ChaCha20Poly1305, WolfDenSecurityLevel::Maximum)
            .map_err(|e| e.to_string())?;
            
        let nonce = cipher.generate_key().await.map_err(|e| e.to_string())?; // Reusing generate_key for random bytes
        // Adjust nonce length for ChaCha20Poly1305 (24 bytes)
        let nonce = nonce[0..24].to_vec();

        let ciphertext = cipher.encrypt(content.as_bytes(), key, &nonce)
            .await.map_err(|e| e.to_string())?;

        // Format: hex(nonce):hex(ciphertext)
        let encrypted_content = format!("{}:{}", hex::encode(nonce), hex::encode(ciphertext));

        let vault_item = VaultItem {
            id: Uuid::new_v4().to_string(),
            name,
            content: encrypted_content,
            category,
            created: Utc::now().to_rfc3339(),
        };

        self.vault.write().await.push(vault_item);
        Ok(())
    }

    pub async fn delete_item(&self, id: &str) -> Result<(), String> {
        if !self.is_unlocked().await {
            return Err("Vault is locked".to_string());
        }
        let mut vault = self.vault.write().await;
        if let Some(pos) = vault.iter().position(|item| item.id == id) {
            vault.remove(pos);
            Ok(())
        } else {
            Err("Item not found".to_string())
        }
    }

    pub async fn clear(&self) -> Result<(), String> {
        if !self.is_unlocked().await {
            return Err("Vault is locked".to_string());
        }
        self.vault.write().await.clear();
        Ok(())
    }

    pub async fn export(&self) -> Result<String, String> {
        let key_guard = self.unlocked_key.read().await;
        let key = key_guard.as_ref().ok_or("Vault is locked")?;
        
        let cipher = create_cipher(CipherSuite::ChaCha20Poly1305, WolfDenSecurityLevel::Maximum)
            .map_err(|e| e.to_string())?;

        let vault_items = self.vault.read().await;
        let mut export_data = Vec::new();
        for item in vault_items.iter() {
            let parts: Vec<&str> = item.content.split(':').collect();
            let decrypted_content = if parts.len() == 2 {
                let nonce = hex::decode(parts[0]).unwrap_or_default();
                let ciphertext = hex::decode(parts[1]).unwrap_or_default();
                
                if let Ok(plaintext) = cipher.decrypt(&ciphertext, key, &nonce).await {
                     String::from_utf8(plaintext).unwrap_or_else(|_| "Invalid UTF-8".to_string())
                } else {
                    "[Decryption Failed]".to_string()
                }
            } else {
                "Invalid content format".to_string()
            };

            export_data.push(serde_json::json!({
                "id": item.id,
                "name": item.name,
                "content": decrypted_content,
                "category": item.category,
                "created": item.created
            }));
        }
        serde_json::to_string(&export_data).map_err(|e| e.to_string())
    }
}

impl FromRef<AppState> for Arc<HowlService> {
    fn from_ref(state: &AppState) -> Self {
        state.howl_service.clone()
    }
}

impl FromRef<AppState> for Arc<VaultService> {
    fn from_ref(state: &AppState) -> Self {
        state.vault_service.clone()
    }
}

impl FromRef<AppState> for Arc<NetworkSecurityManager> {
    fn from_ref(state: &AppState) -> Self {
        state.howl_service.network_security.clone()
    }
}

impl FromRef<AppState> for Arc<CryptoEngine> {
    fn from_ref(state: &AppState) -> Self {
        state.crypto.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<ComplianceFrameworkManager>> {
    fn from_ref(state: &AppState) -> Self {
        state.compliance_manager.clone()
    }
}

impl FromRef<AppState> for Arc<SecurityManager> {
    fn from_ref(state: &AppState) -> Self {
        state.security_manager.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<RiskAssessmentManager>> {
    fn from_ref(state: &AppState) -> Self {
        state.risk_manager.clone()
    }
}

impl FromRef<AppState> for Arc<SwarmManager> {
    fn from_ref(state: &AppState) -> Self {
        state.swarm_manager.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<AppSettings>> {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<HashMap<String, ApiPeerInfo>>> {
    fn from_ref(state: &AppState) -> Self {
        state.peers.clone()
    }
}

impl FromRef<AppState> for Arc<MetricsCollector> {
    fn from_ref(state: &AppState) -> Self {
        state.metrics.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<SystemMetricsData>> {
    fn from_ref(state: &AppState) -> Self {
        state.system_metrics.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<SecurityPolicy>> {
    fn from_ref(state: &AppState) -> Self {
        state.security_policy.clone()
    }
}



impl FromRef<AppState> for Arc<RwLock<Vec<VaultItem>>> {
    fn from_ref(state: &AppState) -> Self {
        state.vault_service.vault.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<Vec<SystemEvent>>> {
    fn from_ref(state: &AppState) -> Self {
        state.security_events.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<ThreatDatabase>> {
    fn from_ref(state: &AppState) -> Self {
        state.threat_service.threat_db.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<HashMap<String, SecuritySession>>> {
    fn from_ref(state: &AppState) -> Self {
        state.howl_service.active_sessions.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<HashMap<String, Vec<String>>>> {
    fn from_ref(state: &AppState) -> Self {
        state.howl_service.message_routes.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<WolfSecurity>> {
    fn from_ref(state: &AppState) -> Self {
        state.wolf_security.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<HashMap<IpAddr, (u32, Instant)>>> {
    fn from_ref(state: &AppState) -> Self {
        state.login_attempts.clone()
    }
}

impl FromRef<AppState> for Arc<crate::wolf_brain::LlamaClient> {
    fn from_ref(state: &AppState) -> Self {
        state.wolf_brain.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<Vec<HowlMessage>>> {
    fn from_ref(state: &AppState) -> Self {
        state.howl_service.howl_messages.clone()
    }
}

impl FromRef<AppState> for Arc<RwLock<HashMap<String, HowlChannel>>> {
    fn from_ref(state: &AppState) -> Self {
        state.howl_service.howl_channels.clone()
    }
}

#[cfg(feature = "advanced_reporting")]
impl FromRef<AppState> for Option<sqlx::PgPool> {
    fn from_ref(state: &AppState) -> Self {
        state.db_pool.clone()
    }
}

impl FromRef<AppState> for Option<Arc<PersistenceManager>> {
    fn from_ref(state: &AppState) -> Self {
        state.persistence.clone()
    }
}

impl AppState {
    pub fn new(inner: AppStateInner) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl AppStateInner {
    pub async fn add_peer(&self, peer: ApiPeerInfo) {
        let peer_id = peer.id.clone();
        self.peers.write().await.insert(peer_id, peer);
    }
}

// =========================================================================================
// TEST HELPERS
// =========================================================================================

/// Helper to create a minimal AppState for testing using Builder pattern
pub struct ApiTestStateBuilder {
    config: AppSettings,
}

impl ApiTestStateBuilder {
    pub fn new() -> Self {
        Self {
            config: AppSettings::default(),
        }
    }

    pub fn with_config(mut self, config: AppSettings) -> Self {
        self.config = config;
        self
    }

    pub async fn build(self) -> AppState {
        let config = self.config;
        let crypto = Arc::new(CryptoEngine::new(wolf_den::SecurityLevel::Standard).unwrap());
        let settings_arc = Arc::new(RwLock::new(config.clone()));
        let (broadcast_tx, _) = broadcast::channel(10);

        // Mock/Default other components
        let network = Arc::new(RwLock::new(
            crate::core::P2PNetwork::new(&config.network).unwrap(),
        ));
        let security_events = Arc::new(RwLock::new(Vec::new()));
        let wolf_security = Arc::new(RwLock::new(WolfSecurity::new(Default::default()).unwrap()));
        let security_manager = Arc::new(
            wolfsec::security::advanced::SecurityManager::new(Default::default())
                .await
                .unwrap(),
        );
        let swarm_manager = Arc::new(SwarmManager::new(Default::default()).unwrap());

        // Initialize services with minimal dependencies
        let howl_service = Arc::new(HowlService {
            howl_messages: Arc::new(RwLock::new(Vec::new())),
            howl_channels: Arc::new(RwLock::new(HashMap::new())),
            message_routes: Arc::new(RwLock::new(HashMap::new())),
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            network_security: Arc::new(wolfsec::network_security::SecurityManager::new(
                "test".to_string(),
                Default::default(),
            )),
            security_events: security_events.clone(),
            message_store: Arc::new(RwLock::new(Vec::new())),
            message_metadata: Arc::new(RwLock::new(HashMap::new())),
            swarm_manager: swarm_manager.clone(), // Fix missing field
        });

        let vault_service = Arc::new(VaultService {
            vault: Arc::new(RwLock::new(Vec::new())),
            unlocked_key: Arc::new(RwLock::new(None)),
            crypto: crypto.clone(),
            config: settings_arc.clone(),
        });

        let threat_service = Arc::new(ThreatService {
            threat_db: Arc::new(RwLock::new(crate::threat_feeds::ThreatDatabase::default())),
            wolf_security: wolf_security.clone(),
            security_events: security_events.clone(),
        });

        let inner = AppStateInner {
            config: settings_arc.clone(),
            network,
            security_events,
            crypto,
            wolf_security,
            security_manager,
            broadcast_tx,
            peers: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(MetricsCollector::new()),
            security_level: Arc::new(wolfsec::network_security::SecurityLevel::default()),
            swarm_manager,
            container_security: Arc::new(RwLock::new(
                wolfsec::security::advanced::container_security::ContainerSecurityManager::new(
                    Default::default(),
                )
                .unwrap(),
            )),
            system_metrics: Arc::new(RwLock::new(SystemMetricsData::default())),
            risk_manager: Arc::new(RwLock::new(
                wolfsec::security::advanced::risk_assessment::RiskAssessmentManager::new(
                    Default::default(),
                )
                .unwrap(),
            )),
            compliance_manager: Arc::new(RwLock::new(
                wolfsec::security::advanced::compliance::ComplianceFrameworkManager::new(
                    Default::default(),
                )
                .unwrap(),
            )),
            howl_service,
            vault_service,
            threat_service,
            login_attempts: Arc::new(RwLock::new(HashMap::new())),
            security_policy: Arc::new(RwLock::new(
                crate::core::security_policy::SecurityPolicy::default(),
            )),
            wolf_brain: Arc::new(crate::wolf_brain::LlamaClient::new(
                settings_arc,
                Some(config.ai.model_name.clone()),
            )),
            #[cfg(feature = "advanced_reporting")]
            db_pool: None,
            persistence: None,
        };

        AppState::new(inner)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ApiPeerInfo {
    pub id: String,
    pub address: String,
    pub connected_since: String,
    pub trust_level: f64,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSession {
    pub id: Uuid,
    pub user_id: String,
    pub role: WolfRole,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl UserSession {
    pub fn new(
        user_id: impl Into<String>,
        role: WolfRole,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id: user_id.into(),
            role,
            created_at: now,
            expires_at: now + chrono::Duration::hours(24),
            last_active: now,
            ip_address,
            user_agent,
        }
    }
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
    pub fn has_role(&self, required_role: &WolfRole) -> bool {
        &self.role == required_role || self.role == WolfRole::Alpha
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemMetricsData {
    pub cpu_usage_history: VecDeque<MetricPoint>,
    pub memory_usage_history: VecDeque<MetricPoint>,
    pub current_cpu_usage: f64,
    pub current_memory_usage: f64,
    pub process_count: usize,
    pub current_network_rx_kbps: f64,
    pub current_network_tx_kbps: f64,
    pub current_disk_usage_percent: f64,
}

impl Default for SystemMetricsData {
    fn default() -> Self {
        Self {
            cpu_usage_history: VecDeque::with_capacity(100),
            memory_usage_history: VecDeque::with_capacity(100),
            current_cpu_usage: 0.0,
            current_memory_usage: 0.0,
            process_count: 0,
            current_network_rx_kbps: 0.0,
            current_network_tx_kbps: 0.0,
            current_disk_usage_percent: 0.0,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeSettings {
    pub encryption_algorithm: String,
    pub security_level: String,
    pub theme: String,
    pub notifications: bool,
    pub auto_refresh: bool,
    pub llm_api_url: Option<String>,
    pub firewall_rules: Vec<FirewallRule>,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            encryption_algorithm: "AES-256-GCM".to_string(),
            security_level: "Standard".to_string(),
            theme: "Wolf Red".to_string(),
            notifications: true,
            auto_refresh: true,
            llm_api_url: Some("http://localhost:11434/api/generate".to_string()),
            firewall_rules: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub content: String,
    pub category: String,
    pub created: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HowlMessage {
    pub id: String,
    pub channel: String,
    pub recipient: Option<String>,
    pub message: String,
    pub priority: String,
    pub sender: String,
    pub timestamp: String,
    pub encrypted: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HowlChannel {
    pub id: String,
    pub name: String,
    pub description: String,
    pub members: Vec<String>,
    pub created: String,
    pub encrypted: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StoredHowlMessage {
    pub id: String,
    pub encrypted_content: String,
    pub channel: String,
    pub recipient: Option<String>,
    pub sender: String,
    pub priority: String,
    pub timestamp: String,
    pub message_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MessageMetadata {
    pub delivery_status: String,
    pub delivery_attempts: u32,
    pub last_attempt: String,
    pub target_peers: Vec<String>,
}
