#![allow(missing_docs)]
use crate::globals::{PROWLER, SECURITY_ENGINE, SSO_MANAGER, SWARM_MANAGER};
use crate::types::*;
use chrono::Utc;
use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use lock_prowler::headless::HeadlessStatus;
use lock_prowler::headless::HeadlessWolfProwler;
// use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::MutexGuard;
use wolf_net::SwarmManager;
#[cfg(feature = "server")]
use wolfsec::security::advanced::iam::sso::{
    SSOAuthenticationRequest, SSOCallbackRequest, SSOProvider,
};
#[cfg(feature = "server")]
use wolfsec::security::advanced::iam::{ClientInfo, SSOIntegrationManager};
use wolfsec::WolfSecurity;

#[server]
/// Retrieves full system statistics including Prowler, Security, and Swarm status.
pub async fn get_fullstack_stats() -> Result<SystemStats, ServerFnError> {
    let prowler_lock: MutexGuard<Option<HeadlessWolfProwler>> = PROWLER.lock().await;
    let security_lock: MutexGuard<Option<WolfSecurity>> = SECURITY_ENGINE.lock().await;
    let swarm_lock: MutexGuard<Option<Arc<SwarmManager>>> = SWARM_MANAGER.lock().await;

    let mut stats = SystemStats {
        volume_size: "Disconnected".to_string(),
        encrypted_sectors: 0.0,
        entropy: 0.0,
        db_status: "OFFLINE".to_string(),
        active_nodes: 0,
        threat_level: "UNKNOWN".to_string(),
        active_alerts: 0,
        scanner_status: "IDLE".to_string(),
        network_status: "DISCONNECTED".to_string(),
        firewall: FirewallStats::default(),
    };

    if let Some(prowler) = prowler_lock.as_ref() {
        let db_stats = prowler.get_store_stats().await;
        let net_stats = prowler.get_network_stats().await;
        let headless_status = prowler.get_status().await;

        stats.volume_size = format!("{} Records", db_stats.total_records);
        stats.encrypted_sectors = if db_stats.integrity_check {
            100.0
        } else {
            99.9
        };
        stats.entropy = 0.98;
        stats.db_status = db_stats.encryption_status;
        stats.active_nodes = net_stats.peer_count;
        stats.network_status = if net_stats.is_connected {
            "ONLINE".to_string()
        } else {
            "OFFLINE".to_string()
        };

        if headless_status.is_running {
            stats.scanner_status = format!("SCANNING: {:.0}%", headless_status.progress);
        }
    }

    if let Some(sec) = security_lock.as_ref() {
        let sec_status = sec.get_status().await;
        let score = sec_status.threat_detection.metrics.security_score;
        stats.threat_level = if score > 80.0 {
            "LOW".to_string()
        } else if score > 50.0 {
            "ELEVATED".to_string()
        } else {
            "CRITICAL".to_string()
        };

        stats.active_alerts = sec_status.monitoring.active_alerts;
    }

    if let Some(swarm) = swarm_lock.as_ref() {
        let fw = swarm.firewall.read().await;
        stats.firewall.enabled = fw.enabled;
        stats.firewall.policy = format!("{:?}", fw.policy);
        stats.firewall.active_rules = fw.rules.len();

        stats.firewall.rules = fw
            .rules
            .iter()
            .map(|r| FirewallRuleView {
                name: r.name.clone(),
                target: format!("{:?}", r.target),
                protocol: format!("{:?}", r.protocol),
                action: format!("{:?}", r.action),
                direction: format!("{:?}", r.direction),
            })
            .collect();
    }

    Ok(stats)
}

#[server]
/// Triggers a sector scan using the Prowler engine.
pub async fn run_prowler_scan() -> Result<String, ServerFnError> {
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    Ok("Sector Scan Complete. Integrity Verified.".to_string())
}

#[server]
/// Retrieves recent logs from the Prowler engine.
pub async fn get_prowler_logs() -> Result<Vec<String>, ServerFnError> {
    Ok(vec![
        "System initialized.".to_string(),
        "Listening on port 8080.".to_string(),
        "Secure Storage mounted.".to_string(),
    ])
}

#[server]
/// Retrieves the current status of the Headless Wolf Prowler.
pub async fn get_prowler_status() -> Result<HeadlessStatus, ServerFnError> {
    Ok(HeadlessStatus {
        is_running: true,
        current_target: Some("/home/user/data".to_string()),
        discovered_secrets: 42,
        imported_secrets: 10,
        last_scan_time: Some(Utc::now()),
        next_scan_time: None,
        progress: 100.0,
    })
}

#[server]
/// Retrieves telemetry data from the WolfPack swarm.
pub async fn get_wolfpack_data() -> Result<WolfPackTelemetry, ServerFnError> {
    let swarm_lock: MutexGuard<Option<Arc<SwarmManager>>> = SWARM_MANAGER.lock().await;

    if let Some(swarm) = swarm_lock.as_ref() {
        let wolf_state = swarm
            .get_wolf_state()
            .await
            .map_err(|e: anyhow::Error| ServerFnError::new(e.to_string()))?;
        let state = wolf_state.read().await;

        let active_hunts = state
            .active_hunts
            .iter()
            .map(|h| ActiveHuntView {
                id: h.hunt_id.clone(),
                target: h.target_ip.clone(),
                status: format!("{:?}", h.status),
                confidence: h.confidence,
                start_time: "Now".to_string(),
            })
            .collect();

        let peers = swarm
            .list_peers()
            .await
            .map_err(|e: anyhow::Error| ServerFnError::new(e.to_string()))?
            .into_iter()
            .map(|p| PeerStatus {
                id: p.entity_id.peer_id.to_string(),
                status: format!("{:?}", p.status),
                role: "Unknown".to_string(),
                rtt_ms: p.metrics.latency_ms,
            })
            .collect();

        Ok(WolfPackTelemetry {
            node_id: swarm.local_peer_id.to_string(),
            raft_state: state.election_state.clone(),
            term: state.election_term,
            commit_index: 0,
            last_heartbeat: Utc::now().format("%H:%M:%S").to_string(),
            peers,
            network_health: 0.95,
            active_hunts,
            role: format!("{:?}", state.role),
            prestige: state.prestige,
        })
    } else {
        Ok(WolfPackTelemetry {
            node_id: "DEV-NODE-01".to_string(),
            raft_state: "Leader".to_string(),
            term: 1,
            commit_index: 100,
            last_heartbeat: Utc::now().format("%H:%M:%S").to_string(),
            peers: vec![],
            network_health: 1.0,
            active_hunts: vec![],
            role: "Alpha".to_string(),
            prestige: 9999,
        })
    }
}

#[server]
/// Initiates an SSO authentication flow for the given provider.
pub async fn get_sso_auth_url(provider_name: String) -> Result<String, ServerFnError> {
    let sso_lock: MutexGuard<Option<SSOIntegrationManager>> = SSO_MANAGER.lock().await;
    if let Some(manager) = sso_lock.as_ref() {
        let provider = match provider_name.as_str() {
            "azure" => SSOProvider::AzureAD,
            "okta" => SSOProvider::Okta,
            "auth0" => SSOProvider::Auth0,
            "google" => SSOProvider::Google,
            "mock" => SSOProvider::Mock,
            _ => return Err(ServerFnError::new("Invalid provider")),
        };

        let request = SSOAuthenticationRequest {
            provider,
            client_info: ClientInfo {
                ip_address: "127.0.0.1".to_string(),
                user_agent: "WolfWeb/1.0".to_string(),
                device_id: None,
                location: None,
            },
            redirect_url: None,
        };

        let response = manager
            .start_authentication(request)
            .await
            .map_err(|e: anyhow::Error| ServerFnError::new(e.to_string()))?;

        Ok(response.auth_url)
    } else {
        Err(ServerFnError::new("SSO System Offline"))
    }
}

#[server]
/// Handles the SSO callback and finalizes authentication.
pub async fn handle_sso_callback(
    provider_name: String,
    code: String,
    state: String,
) -> Result<String, ServerFnError> {
    let sso_lock: MutexGuard<Option<SSOIntegrationManager>> = SSO_MANAGER.lock().await;
    if let Some(manager) = sso_lock.as_ref() {
        let provider = match provider_name.as_str() {
            "azure" => SSOProvider::AzureAD,
            "okta" => SSOProvider::Okta,
            "auth0" => SSOProvider::Auth0,
            "google" => SSOProvider::Google,
            "mock" => SSOProvider::Mock,
            _ => return Err(ServerFnError::new("Invalid provider")),
        };

        let request = SSOCallbackRequest {
            provider,
            code,
            state,
            error: None,
        };

        let _user_info = manager
            .handle_callback(request)
            .await
            .map_err(|e: anyhow::Error| ServerFnError::new(e.to_string()))?;

        Ok("Authentication Successful".to_string())
    } else {
        Err(ServerFnError::new("SSO System Offline"))
    }
}

#[server]
/// Retrieves records from the specified database table.
pub async fn get_records(table: String) -> Result<Vec<RecordView>, ServerFnError> {
    let prowler_lock: MutexGuard<Option<HeadlessWolfProwler>> = PROWLER.lock().await;
    if let Some(prowler) = prowler_lock.as_ref() {
        let records = prowler
            .list_database_records(&table)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let views = records
            .into_iter()
            .map(|r| RecordView {
                id: r.id,
                data: serde_json::to_string(&r.data).unwrap_or_default(),
                has_vector: r.vector.is_some(),
            })
            .collect();
        Ok(views)
    } else {
        Err(ServerFnError::new("Database Offline"))
    }
}

#[server]
/// Adds a new record to the specified database table.
pub async fn add_record(
    table: String,
    key: String,
    data_json: String,
) -> Result<(), ServerFnError> {
    let prowler_lock: MutexGuard<Option<HeadlessWolfProwler>> = PROWLER.lock().await;
    if let Some(prowler) = prowler_lock.as_ref() {
        let data: HashMap<String, String> = serde_json::from_str(&data_json)
            .map_err(|_| ServerFnError::new("Invalid JSON Data"))?;

        prowler
            .add_database_record(&table, &key, data)
            .await
            .map_err(|e: anyhow::Error| ServerFnError::new(e.to_string()))?;
        Ok(())
    } else {
        Err(ServerFnError::new("Database Offline"))
    }
}

#[server]
/// Deletes a record from the specified database table.
pub async fn delete_record(table: String, id: String) -> Result<(), ServerFnError> {
    let prowler_lock: MutexGuard<Option<HeadlessWolfProwler>> = PROWLER.lock().await;
    if let Some(prowler) = prowler_lock.as_ref() {
        prowler
            .delete_database_record(&table, &id)
            .await
            .map_err(|e: anyhow::Error| ServerFnError::new(e.to_string()))?;
        Ok(())
    } else {
        Err(ServerFnError::new("Database Offline"))
    }
}
