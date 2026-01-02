use crate::compliance_service::ComplianceService;
use crate::core::security_policy::{SecurityPolicy, SecurityStance};
use crate::core::{AppSettings, WolfRole};
use crate::dashboard::network::{
    DetailedTopology, DialRequest, NetworkLink, NetworkMetricsResponse, NetworkNode,
    NetworkOverview, NetworkTopologyResponse, NodeLink, NodeTopology, PeerStatus,
};
use crate::dashboard::state::{
    ApiPeerInfo, AppState, HowlChannel, HowlMessage, SystemMetricsData, VaultItem, VaultService,
};
use crate::utils::metrics_simple::SystemEvent;

use wolf_net::consensus::proposals::Proposal;
use wolf_net::wolf_pack::state::{HuntStatus, WolfRole as NetWolfRole};
use wolf_net::{EntityInfo, PeerId, SwarmCommand, SwarmManager, SwarmStats};

use axum::http::{header, request::Parts, HeaderMap, StatusCode};
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Path, Query, State},
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
// use hyper::StatusCode; // Removed conflicting import
use crate::threat_feeds::{ThreatDatabase, ThreatFeedManager};
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
// use sqlx::PgPool;
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};
use tokio::sync::RwLock; // Fix: Import RwLock (for explicit usage if any, though AppState uses it from imports)
use uuid::Uuid;
// use wolf_net::event::SecurityEvent as NetworkSecurityEvent;
// use wolf_net::peer::EntityStatus;
use wolf_net::wolf_pack::WolfRank;
// SystemEvent removed
#[cfg(feature = "cloud_security")]
use crate::core::cloud::{aws::AwsScanner, CloudProvider, CloudScanResult};
use tracing::{info, instrument, warn};
use wolfsec::monitoring;
// use wolfsec::network_security::SecuritySession;
// use wolfsec::security::advanced::compliance::ComplianceFrameworkManager;
use wolfsec::security::advanced::risk_assessment::{AssessmentScope, AssessmentType};
use wolfsec::threat_detection::Threat;

const AUTH_COOKIE_NAME: &str = "wolf_prowler_auth";

/// Extractor for an authenticated user session.
pub struct AuthenticatedUser {
    pub role: WolfRole,
    pub session_token: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);

        // Check for X-API-Key (Development/Direct Access)
        if let Some(api_key) = parts.headers.get("X-API-Key") {
            if let Ok(key_str) = api_key.to_str() {
                // For now, accept the dev key used in api.js
                // In production, this should check against a hashed value in Config or DB
                if key_str == "dev-key-12345" {
                    return Ok(AuthenticatedUser {
                        role: WolfRole::Alpha,
                        session_token: "dev-session".to_string(),
                    });
                }
            }
        }

        // Try to extract the token from the Authorization header first, then fall back to cookies
        let raw_token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string())
            .or_else(|| {
                CookieJar::from_headers(&parts.headers)
                    .get(AUTH_COOKIE_NAME)
                    .map(|c| c.value().to_string())
            })
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let (value, mac_hex) = raw_token.split_once('.').ok_or(StatusCode::UNAUTHORIZED)?;
        let mac_bytes = hex::decode(mac_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;

        // Cryptographically verify the session integrity
        if !state
            .crypto
            .verify_mac(value.as_bytes(), &mac_bytes)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let (token, role_str) = value.split_once(':').ok_or(StatusCode::UNAUTHORIZED)?;
        let role = match role_str {
            "omega" => WolfRole::Omega,
            "alpha" => WolfRole::Alpha,
            "gamma" => WolfRole::Gamma,
            "beta" => WolfRole::Beta,
            _ => return Err(StatusCode::UNAUTHORIZED),
        };

        Ok(Self {
            role,
            session_token: token.to_string(),
        })
    }
}

/// Extractor that requires the user to have administrative privileges (Alpha or Omega).
pub struct AdminUser(pub AuthenticatedUser);

#[async_trait]
impl<S> FromRequestParts<S> for AdminUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;
        if user.role == WolfRole::Alpha || user.role == WolfRole::Omega {
            Ok(AdminUser(user))
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// Extractor that requires the user to have Omega privileges.
pub struct OmegaUser(pub AuthenticatedUser);

#[async_trait]
impl<S> FromRequestParts<S> for OmegaUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;
        if user.role == WolfRole::Omega {
            Ok(OmegaUser(user))
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// A standardized API error type that can be converted into an Axum response.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Authentication failed")]
    Unauthorized,
    #[error("Permission denied: {0}")]
    Forbidden(String),
    #[error("Resource not found: {0}")]
    NotFound(String),
    #[error("Invalid request: {0}")]
    BadRequest(String),
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({
            "success": false,
            "error": self.to_string(),
        }));

        (status, body).into_response()
    }
}

/// A helper type for API results.
pub type ApiResult<T> = Result<Json<T>, ApiError>;

/// A standardized response structure for simple success/failure.
#[derive(Serialize)]
pub struct StatusResponse {
    pub success: bool,
    pub message: String,
}

impl StatusResponse {
    pub fn ok(message: impl Into<String>) -> Json<Self> {
        Json(Self {
            success: true,
            message: message.into(),
        })
    }
}

/// API request and response structures
#[derive(Deserialize)]
pub struct HashRequest {
    pub data: String,
    pub algorithm: String,
}

#[derive(Serialize)]
pub struct HashResponse {
    pub hash: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct VaultUnlockRequest {
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct VaultResponse {
    pub success: bool,
    pub items: Option<Vec<VaultItem>>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct VaultAddRequest {
    pub name: String,
    pub content: String,
    pub category: String,
}

#[derive(Deserialize)]
pub struct VaultDeleteRequest {
    pub id: String,
}

#[derive(Deserialize)]
pub struct HowlSendRequest {
    pub channel: String,
    pub recipient: Option<String>,
    pub message: String,
    pub priority: String,
}

#[derive(Serialize, Deserialize)]
pub struct HowlResponse {
    pub success: bool,
    pub messages: Option<Vec<HowlMessage>>,
    pub channels: Option<Vec<HowlChannel>>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct KdfRequest {
    pub password: String,
    pub salt: String,
}

#[derive(Serialize)]
pub struct KdfResponse {
    pub key: String,
    pub length: usize,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct MacRequest {
    pub data: String,
    pub key: String,
}

#[derive(Deserialize)]
pub struct UnblockRequest {
    pub ip: String,
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    pub address: String,
}

use wolf_net::firewall::{Action, FirewallRule, Protocol, RuleTarget, TrafficDirection};

#[derive(Deserialize)]
pub struct AddFirewallRuleRequest {
    pub name: String,
    pub target_type: String, // "ip", "port", "peer", "any"
    pub target_value: String,
    pub protocol: String,  // "tcp", "udp", "icmp", "wolf", "any"
    pub action: String,    // "allow", "deny"
    pub direction: String, // "inbound", "outbound", "both"
}

#[derive(Deserialize)]
pub struct DeleteFirewallRuleRequest {
    pub rule_name: String,
}

pub async fn api_firewall_get_rules(State(state): State<AppState>) -> Json<Vec<FirewallRule>> {
    let config = state.config.read().await;
    Json(config.firewall_rules.clone())
}

#[derive(Deserialize)]
pub struct FirewallToggleRequest {
    pub enabled: bool,
}

/// API: Toggle firewall on/off
pub async fn api_firewall_toggle(
    State(state): State<AppState>,
    Json(payload): Json<FirewallToggleRequest>,
) -> ApiResult<serde_json::Value> {
    let mut firewall = state.swarm_manager.firewall.write().await;
    firewall.enabled = payload.enabled;

    info!("🔥 Firewall status set to: {}", firewall.enabled);

    Ok(Json(serde_json::json!({
        "success": true,
        "enabled": firewall.enabled,
        "message": format!("Firewall {}", if firewall.enabled { "enabled" } else { "disabled" })
    })))
}

pub async fn api_firewall_add_rule(
    State(state): State<AppState>,
    Json(req): Json<AddFirewallRuleRequest>,
) -> ApiResult<serde_json::Value> {
    let target = match req.target_type.to_lowercase().as_str() {
        "ip" => {
            let ip = req
                .target_value
                .parse::<IpAddr>()
                .map_err(|_| ApiError::BadRequest("Invalid IP".into()))?;
            RuleTarget::Ip(ip)
        }
        "port" => {
            let port = req
                .target_value
                .parse::<u16>()
                .map_err(|_| ApiError::BadRequest("Invalid Port".into()))?;
            RuleTarget::Port(port)
        }
        "peer" => RuleTarget::PeerId(req.target_value),
        "any" => RuleTarget::Any,
        _ => return Err(ApiError::BadRequest("Invalid target type".into())),
    };

    let protocol = match req.protocol.to_lowercase().as_str() {
        "tcp" => Protocol::TCP,
        "udp" => Protocol::UDP,
        "icmp" => Protocol::ICMP,
        "wolf" => Protocol::WolfProto,
        "any" => Protocol::Any,
        _ => return Err(ApiError::BadRequest("Invalid protocol".into())),
    };

    let action = match req.action.to_lowercase().as_str() {
        "allow" => Action::Allow,
        "deny" => Action::Deny,
        _ => return Err(ApiError::BadRequest("Invalid action".into())),
    };

    let direction = match req.direction.to_lowercase().as_str() {
        "inbound" => TrafficDirection::Inbound,
        "outbound" => TrafficDirection::Outbound,
        "both" => TrafficDirection::Both,
        _ => return Err(ApiError::BadRequest("Invalid direction".into())),
    };

    let rule = FirewallRule::new(req.name.clone(), target, protocol, action, direction);

    {
        let mut config = state.config.write().await;
        config.firewall_rules.push(rule.clone());
        config
            .save()
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    }

    info!("🛡️ Firewall rule added and persisted: {}", rule.name);
    Ok(Json(
        json!({"success": true, "message": format!("Rule '{}' added", rule.name)}),
    ))
}

pub async fn api_firewall_delete_rule(
    State(state): State<AppState>,
    Json(req): Json<DeleteFirewallRuleRequest>,
) -> ApiResult<serde_json::Value> {
    {
        let mut config = state.config.write().await;
        let initial_len = config.firewall_rules.len();
        config.firewall_rules.retain(|r| r.name != req.rule_name);
        if config.firewall_rules.len() == initial_len {
            return Err(ApiError::NotFound(format!(
                "Rule '{}' not found",
                req.rule_name
            )));
        }
        config
            .save()
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    }
    info!("🗑️ Firewall rule deleted and persisted: {}", req.rule_name);
    Ok(Json(json!({"success": true, "message": "Rule deleted"})))
}

pub async fn api_swarm_connect(
    State(state): State<AppState>,
    Json(payload): Json<ConnectRequest>,
) -> Json<serde_json::Value> {
    let swarm_manager = &state.swarm_manager;
    match swarm_manager
        .dial_addr(
            payload
                .address
                .parse()
                .unwrap_or_else(|_| "/ip4/127.0.0.1/tcp/0".parse().unwrap()),
        )
        .await
    {
        Ok(_) => Json(
            json!({"success": true, "message": format!("Attempting to connect to {}", payload.address)}),
        ),
        Err(e) => Json(
            json!({"success": false, "message": format!("Failed to initiate connection: {}", e)}),
        ),
    }
}

pub async fn api_v1_auth_unblock(
    State(state): State<AppState>,
    Json(payload): Json<UnblockRequest>,
) -> ApiResult<serde_json::Value> {
    let login_attempts = &state.login_attempts;
    if let Ok(ip_addr) = payload.ip.parse::<IpAddr>() {
        let mut attempts = login_attempts.write().await;
        if attempts.remove(&ip_addr).is_some() {
            Ok(Json(json!({
                "success": true,
                "message": format!("IP {} unblocked", payload.ip)
            })))
        } else {
            Ok(Json(json!({
                "success": false,
                "message": format!("IP {} was not blocked", payload.ip)
            })))
        }
    } else {
        Err(ApiError::BadRequest("Invalid IP address".to_string()))
    }
}

#[derive(Serialize)]
pub struct MacResponse {
    pub mac: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct SecurityEventsResponse {
    pub events: Vec<monitoring::SecurityEvent>,
}

#[derive(Deserialize)]
pub struct ThreatFilter {
    pub severity: Option<String>,
}

pub async fn api_risk_assessment(State(state): State<AppState>) -> Json<serde_json::Value> {
    let risk_manager = &state.risk_manager;
    let mut risk_manager = risk_manager.write().await;
    let result = match risk_manager
        .run_assessment(AssessmentType::Periodic, AssessmentScope::default())
        .await
    {
        Ok(res) => res,
        Err(e) => return Json(json!({"error": format!("Failed to run risk assessment: {}", e)})),
    };
    Json(serde_json::to_value(result).unwrap_or(json!({"error": "Serialization failed"})))
}

#[derive(Deserialize)]
pub struct VerifySignatureRequest {
    pub timestamp: String,
    pub score: f64,
    pub critical: u32,
    pub total: u32,
    pub signature: String,
}

pub async fn api_compliance_verify(
    State(state): State<AppState>,
    Json(req): Json<VerifySignatureRequest>,
) -> Json<serde_json::Value> {
    let crypto = &state.crypto;
    let integrity_data = format!(
        "{}|{:.1}|{}|{}",
        req.timestamp, req.score, req.critical, req.total
    );
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) => b,
        Err(_) => return Json(json!({"valid": false, "error": "Invalid hex signature"})),
    };

    match crypto
        .verify_mac(integrity_data.as_bytes(), &sig_bytes)
        .await
    {
        Ok(valid) => Json(json!({"valid": valid})),
        Err(e) => Json(json!({"valid": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct CliLoginRequest {
    pub password: String,
}

#[derive(Serialize)]
pub struct CliLoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub role: Option<String>,
    pub error: Option<String>,
}

/// API: JSON login for CLI users. Returns a signed token.
pub async fn api_login_json(
    State(state): State<AppState>,
    Json(payload): Json<CliLoginRequest>,
) -> impl IntoResponse {
    let config = state.config.read().await;
    let password_bytes = payload.password.as_bytes();
    let admin_password_bytes = config.dashboard.admin_password.as_bytes();

    // Constant-time comparison to prevent timing attacks
    if !state
        .crypto
        .secure_compare(password_bytes, admin_password_bytes)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(CliLoginResponse {
                success: false,
                token: None,
                role: None,
                error: Some("Invalid password".to_string()),
            }),
        )
            .into_response();
    }

    // Generate a random session token (32 bytes)
    let session_token = Uuid::new_v4().to_string().replace("-", "");
    let user_role = config.dashboard.admin_role.clone();
    let role_str = user_role.to_string();

    // Format: token:role
    let session_data = format!("{}:{}", session_token, role_str);

    // Sign the session data
    match state.crypto.compute_mac(session_data.as_bytes()).await {
        Ok(mac) => {
            let full_token = format!("{}.{}", session_data, hex::encode(mac));
            Json(CliLoginResponse {
                success: true,
                token: Some(full_token),
                role: Some(role_str),
                error: None,
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(CliLoginResponse {
                success: false,
                token: None,
                role: None,
                error: Some(format!("Token generation failed: {}", e)),
            }),
        )
            .into_response(),
    }
}

pub async fn api_compliance_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let compliance_manager = &state.compliance_manager;
    let mut compliance_manager = compliance_manager.write().await;
    let status = match compliance_manager.get_compliance_status().await {
        Ok(s) => s,
        Err(e) => return Json(json!({"error": format!("Failed to get compliance status: {}", e)})),
    };
    Json(serde_json::to_value(status).unwrap_or(json!({"error": "Serialization failed"})))
}

pub async fn api_compliance_export_pdf(State(state): State<AppState>) -> axum::response::Response {
    use genpdf::elements::{Break, TableLayout, Text};
    use genpdf::style::Style;
    use genpdf::Element;

    let status = ComplianceService::get_status().await;

    // Create a unique string to sign representing the report's integrity
    let integrity_data = format!(
        "{}|{:.1}|{}|{}",
        status.timestamp.to_rfc3339(),
        status.overall_score,
        status.critical_findings,
        status.total_findings
    );

    // Use the CryptoEngine to sign the integrity data
    let signature = state
        .crypto
        .compute_mac(integrity_data.as_bytes())
        .await
        .ok();

    // 1. Load Font (Adjust path as needed for your system)
    let font_dir = "/usr/share/fonts/truetype/liberation";
    let font_family = genpdf::fonts::from_files(font_dir, "LiberationSans", None)
        .unwrap_or_else(|_| genpdf::fonts::from_files(font_dir, "DejaVuSans", None).unwrap());

    // 2. Initialize Document
    let mut doc = genpdf::Document::new(font_family);
    doc.set_title("Wolf Prowler Compliance Report");
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins(15);
    doc.set_page_decorator(decorator);

    // 3. Header Section
    doc.push(Text::new("WOLF PROWLER").styled(Style::new().bold().with_font_size(20)));
    doc.push(Text::new("Compliance Audit Report").styled(Style::new().with_font_size(14)));
    doc.push(Break::new(1.5));

    // 4. Executive Summary Table
    doc.push(Text::new("Executive Summary").styled(Style::new().bold()));
    let mut summary_table = TableLayout::new(vec![1, 2]);
    summary_table.set_cell_decorator(genpdf::elements::FrameCellDecorator::new(true, true, true));

    summary_table
        .row()
        .element(Text::new("Overall Compliance Score"))
        .element(Text::new(format!("{:.1}%", status.overall_score)))
        .push()
        .expect("Failed to push row");

    summary_table
        .row()
        .element(Text::new("Critical Findings"))
        .element(Text::new(status.critical_findings.to_string()))
        .push()
        .expect("Failed to push row");

    summary_table
        .row()
        .element(Text::new("Total Issues"))
        .element(Text::new(status.total_findings.to_string()))
        .push()
        .expect("Failed to push row");

    summary_table
        .row()
        .element(Text::new("Assessment Date"))
        .element(Text::new(status.last_assessment.to_rfc3339()))
        .push()
        .expect("Failed to push row");

    doc.push(summary_table);
    doc.push(Break::new(2.0));

    // 4.5 Trend Chart (Commented out until Image support is confirmed)
    /*
    if !status.history.is_empty() {
        if let Ok(png_data) = generate_trend_chart_png(&status.history) {
            doc.push(Text::new("Compliance Trend Over Time"));
            doc.push(
                Image::from_reader(std::io::Cursor::new(png_data))
                    .expect("Failed to load chart image into PDF"),
            );
            doc.push(Break::new(2.0));
        }
    }
    */

    // 5. Framework Breakdown Table
    doc.push(Text::new("Framework Performance"));
    let mut fw_table = TableLayout::new(vec![3, 1]);
    fw_table
        .row()
        .element(Text::new("Framework"))
        .element(Text::new("Score"))
        .push()
        .expect("Failed to push row");
    for (fw, score) in &status.framework_scores {
        fw_table
            .row()
            .element(Text::new(fw))
            .element(Text::new(format!("{:.1}%", score)))
            .push()
            .expect("Failed to push row");
    }
    doc.push(fw_table);
    doc.push(Break::new(2.0));

    // 6. Detailed Findings Table
    doc.push(Text::new("Detailed Findings"));
    let mut findings_table = TableLayout::new(vec![1, 1, 3, 1]);
    findings_table
        .row()
        .element(Text::new("Severity"))
        .element(Text::new("Framework"))
        .element(Text::new("Control"))
        .element(Text::new("Status"))
        .push()
        .expect("Failed to push row");

    for f in &status.recent_findings {
        findings_table
            .row()
            .element(Text::new(&f.severity))
            .element(Text::new(&f.framework))
            .element(Text::new(&f.control))
            .element(Text::new(&f.status))
            .push()
            .expect("Failed to push row");
    }
    doc.push(findings_table);
    doc.push(Break::new(2.0));
    // Digital Signature (Wolf Den Integration)
    if let Some(sig) = signature {
        let sig_hex = hex::encode(sig);
        doc.push(Break::new(2.0));
        doc.push(Text::new("Security Verification").styled(Style::new().bold()));
        doc.push(
            Text::new(format!("Digital Signature (HMAC-SHA256): {}", sig_hex))
                .styled(Style::new().with_font_size(8)),
        );
        doc.push(
            Text::new("Verified by Wolf Prowler CryptoEngine")
                .styled(Style::new().with_font_size(8)),
        );
    }

    // 8. Render to Buffer
    let mut buffer = Vec::new();
    match doc.render(&mut buffer) {
        Ok(_) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/pdf"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"wolf_compliance_report.pdf\"",
                ),
            ],
            buffer,
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate PDF").into_response(),
    }
}

pub async fn api_compliance_run_assessment(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let compliance_manager = &state.compliance_manager;
    #[cfg(feature = "advanced_reporting")]
    let pool = &state.db_pool;
    let mut compliance_manager = compliance_manager.write().await;
    let frameworks = [
        wolfsec::security::advanced::compliance::ComplianceFramework::SOC2,
        wolfsec::security::advanced::compliance::ComplianceFramework::ISO27001,
        // wolfsec::security::advanced::compliance::ComplianceFramework::GDPR, // Add if needed
    ];

    let mut results = Vec::new();
    let mut errors = Vec::new();

    for framework in frameworks {
        match compliance_manager
            .run_assessment(
                framework.clone(),
                wolfsec::security::advanced::compliance::AssessmentType::Periodic,
            )
            .await
        {
            Ok(result) => results.push(result),
            Err(e) => errors.push(format!("Failed to assess {:?}: {}", framework, e)),
        }
    }

    let compliance_status = ComplianceService::get_status().await;

    #[cfg(feature = "advanced_reporting")]
    {
        if let Some(pool) = pool {
            if let Err(e) = ComplianceService::save_status(&pool, &compliance_status).await {
                errors.push(format!("Failed to save compliance status: {}", e));
            }
        }
    }

    if errors.is_empty() {
        Json(json!({
            "success": true,
            "message": "Compliance assessment completed successfully",
            "results_count": results.len()
        }))
    } else {
        Json(json!({
            "success": false,
            "error": format!("Assessment completed with errors: {:?}", errors),
            "results_count": results.len()
        }))
    }
}

pub async fn api_neural_network_state(State(state): State<AppState>) -> Json<serde_json::Value> {
    let security_manager = &state.security_manager;
    // Get real data from ML Engine
    let ml_engine = security_manager.get_ml_engine();
    let stats = ml_engine.get_statistics();
    let predictions = ml_engine.get_recent_predictions();

    // Map recent predictions to JSON
    let recent_activity: Vec<serde_json::Value> = predictions
        .iter()
        .map(|p| {
            json!({
                "timestamp": p.timestamp,
                "predicted_class": p.predicted_class,
                "risk_score": p.risk_score,
                "explanation": p.explanation,
                "confidence": p.confidence,
                "ai_enhanced": p.explanation.contains("AI Analysis")
            })
        })
        .collect();

    // Determine activity level based on recent predictions count or risk
    let recent_high_risk = predictions.iter().filter(|p| p.risk_score > 0.7).count();
    let activity_level = if recent_high_risk > 0 { 0.9 } else { 0.3 };

    Json(json!({
        "layers": [8, 12, 12, 8, 4], // Visualization structure
        "total_neurons": 44,
        "input_features": [
            "Network Traffic", "Login Frequency", "Failed Attempts",
            "Resource Usage", "API Calls", "Peer Trust", "Time of Day", "Geolocation"
        ],
        "confidence": if !predictions.is_empty() { predictions.last().unwrap().confidence } else { 0.85 },
        "activity_metrics": {
            "forward_pass_time_ms": 12, // Placeholder
            "active_neurons": (44.0 * activity_level) as u32,
            "total_predictions": stats.total_predictions,
            "accuracy": if stats.total_predictions > 0 {
                1.0 - ((stats.false_positives + stats.false_negatives) as f64 / stats.total_predictions as f64)
            } else {
                0.95 // Default high accuracy when no data
            }
        },
        "recent_activity": recent_activity,
        "status": "online"
    }))
}

pub async fn api_threat_intelligence(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db = state.threat_service.threat_db.read().await;
    let wolf_status = state
        .wolf_security
        .read()
        .await
        .threat_detector
        .get_status()
        .await;
    let active_threats = state
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

    Json(json!({
        "internal_status": wolf_status,
        "feed_stats": {
            "known_bad_ips": db.malicious_ips.len(),
            "known_cves": db.known_cves.len(),
            "last_updated": db.last_updated,
            "total_threats": active_threats.len(),
            "threat_types": threat_types
        }
    }))
}

pub async fn api_cve_feed(State(state): State<AppState>) -> Json<serde_json::Value> {
    let internal_vulns = state
        .wolf_security
        .read()
        .await
        .vulnerability_scanner
        .get_vulnerabilities()
        .await;
    let db = state.threat_service.threat_db.read().await;
    let feed_cves: Vec<serde_json::Value> = db.known_cves.values().map(|v| {
        json!({"id": v.id, "cvss": v.severity, "summary": v.description, "status": v.status, "source": "External Feed"})
    }).collect();
    let internal_cves: Vec<serde_json::Value> = internal_vulns.iter().map(|v| {
        json!({"id": v.cve_id, "cvss": v.cvss_score, "summary": v.description, "status": v.status, "source": "Internal Scanner"})
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
    Json(
        json!({"total_critical": total_critical, "total_high": total_high, "cves": all_cves, "last_updated": db.last_updated}),
    )
}

pub async fn api_dashboard_data(State(state): State<AppState>) -> Json<serde_json::Value> {
    let microseg = state.security_manager.get_microsegmentation();
    let zero_trust_stats = microseg.get_statistics();
    let peers_count = state.peers.read().await.len();

    // Simulate some continuous auth data if not available in security manager yet
    let biometric_confidence = 98.5;

    Json(json!({
        "microsegmentation": {
            "segment_count": zero_trust_stats.total_segments
        },
        "device_trust": {
            "trusted_devices": peers_count // simplified mapping
        },
        "continuous_auth": {
            "biometric_confidence": biometric_confidence
        },
        "policy_engine": {
            "items_enforced": "Active"
        }
    }))
}

pub async fn api_zero_trust(State(state): State<AppState>) -> Json<serde_json::Value> {
    let policy_engine = state.security_manager.get_policy_engine();
    let microseg = state.security_manager.get_microsegmentation();
    let policy_stats = policy_engine.get_statistics();
    let microseg_stats = microseg.get_statistics();
    let active_policies = policy_engine.get_policies();
    let segments = microseg.get_segments();
    let peers = state.peers.read().await;
    let total_devices = peers.len();
    let trusted_devices = peers.values().filter(|p| p.trust_level >= 0.8).count();
    Json(json!({
        "policy_engine": {"active_policy_count": active_policies.len(), "stats": policy_stats, "policies": active_policies.values().map(|p| &p.name).collect::<Vec<_>>()},
        "microsegmentation": {"segment_count": segments.len(), "stats": microseg_stats, "segments": segments.values().map(|s| json!({"name": s.segment_name, "security_level": s.security_level})).collect::<Vec<_>>()},
        "network_segments": {"active": segments.len(), "total": segments.len()},
        "device_trust": {"trusted_devices": trusted_devices, "total_devices": total_devices},
        "continuous_auth": {"biometric_confidence": 98.5},
        "policy_enforcement": {"enforced_policies": policy_stats.policies_enforced, "total_evaluations": policy_stats.total_evaluations}
    }))
}

pub async fn api_siem_analytics(State(state): State<AppState>) -> Json<serde_json::Value> {
    let wolf_security = state.wolf_security.read().await;
    let login_attempts = &state.login_attempts;
    let status = wolf_security.monitor.get_status().await;
    let mut response = serde_json::to_value(status).unwrap_or(json!({}));

    // Integrate rate-limiting threat data from login attempts
    let attempts = login_attempts.read().await;
    let now = Instant::now();
    let brute_force_stats = attempts
        .iter()
        .map(|(ip, (count, last_attempt))| {
            json!({
                "ip": ip.to_string(),
                "attempt_count": count,
                "is_blocked": *count >= 5,
                "last_seen_secs_ago": now.duration_since(*last_attempt).as_secs()
            })
        })
        .collect::<Vec<_>>();

    if let Some(obj) = response.as_object_mut() {
        obj.insert("auth_threat_intel".to_string(), json!({
            "monitored_ips": brute_force_stats.len(),
            "blocked_ips_count": brute_force_stats.iter().filter(|v| v["is_blocked"].as_bool().unwrap_or(false)).count(),
            "active_threats": brute_force_stats
        }));
    }

    Json(response)
}

pub async fn api_system_metrics(State(state): State<AppState>) -> Json<SystemMetricsData> {
    let system_metrics = &state.system_metrics;
    let metrics = system_metrics.read().await;
    Json(metrics.clone())
}

pub async fn api_v1_network_status(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let swarm_manager = &state.swarm_manager;
    let peers = &state.peers;
    let metrics = &state.metrics;
    let swarm_metrics = swarm_manager.get_metrics().await;
    let peer_count = peers.read().await.len();
    let net_snapshot = metrics.get_network_snapshot();
    Ok(Json(json!({
        "status": "online",
        "active_nodes": peer_count,
        "connected_peers": swarm_metrics.active_connections,
        "network_health": 95.0 + (net_snapshot.avg_message_latency / 100.0).min(5.0),
        "avg_latency": net_snapshot.avg_message_latency,
        "avg_duration": net_snapshot.avg_connection_duration,
        "total_messages": net_snapshot.messages_sent_total + net_snapshot.messages_received_total,
        "total_peers": peer_count,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

// --- Utility Functions ---

/// API Key Authentication Function
pub async fn validate_api_key(headers: &HeaderMap) -> Result<(), StatusCode> {
    if let Some(api_key) = headers.get("X-API-Key") {
        if api_key.to_str().unwrap_or("")
            == std::env::var("WOLF_PROWLER_API_KEY").unwrap_or_default()
        {
            return Ok(());
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// Security Event Logger Function
pub async fn log_security_event(
    events: &Arc<RwLock<Vec<SystemEvent>>>,
    event_type: &str,
    message: &str,
) {
    let event = SystemEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: event_type.to_string(),
        message: message.to_string(),
        severity: "info".to_string(),
        source: "system".to_string(),
        user_id: None,
        ip_address: None,
        metadata: HashMap::<String, String>::new(),
        correlation_id: None,
    };
    let mut events_guard: tokio::sync::RwLockWriteGuard<Vec<SystemEvent>> = events.write().await;
    events_guard.push(event);
}

/// Peer Discovery Status Function
pub async fn get_peer_status(peers: &Arc<RwLock<HashMap<String, ApiPeerInfo>>>) -> Vec<PeerStatus> {
    let peers_map: tokio::sync::RwLockReadGuard<std::collections::HashMap<String, ApiPeerInfo>> =
        peers.read().await;
    peers_map
        .iter()
        .map(|(id, info): (&String, &ApiPeerInfo)| PeerStatus {
            id: id.clone(),
            address: vec![info.address.clone()],
            status: "active".to_string(),
            last_seen: Utc::now().to_rfc3339(),
        })
        .collect()
}

/// API: Triggers a system reboot (simulated)
pub async fn api_v1_system_reboot(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    tracing::warn!("API request received to reboot the system.");

    // Log this as a high-severity security event
    log_security_event(
        &state.security_events,
        "system_reboot_request",
        "System reboot initiated via API endpoint",
    )
    .await;

    // In a real application, you would trigger the reboot here.
    Ok(Json(json!({
        "success": true,
        "message": "System reboot command received and logged."
    })))
}

/// API: Test connection to AI backend
pub async fn api_v1_test_ai_connection(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let ml_engine = state.security_manager.get_ml_engine();
    // Access config with read lock
    let url = state.config.read().await.ai.llm_api_url.clone();

    match ml_engine.test_ai_connection(url).await {
        Ok(success) => Ok(Json(json!({
            "success": success,
            "message": if success { "Successfully connected to AI backend" } else { "Failed to connect to AI backend" }
        }))),
        Err(e) => Err(ApiError::Internal(format!(
            "Error testing connection: {}",
            e
        ))),
    }
}

/// API: Summarize recent security events using AI
pub async fn api_v1_neural_summarize(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let events = state.security_events.read().await;
    // Get the 20 most recent events
    let recent_events: Vec<SystemEvent> = events.iter().rev().take(20).cloned().collect();

    match state.wolf_brain.summarize_events(&recent_events).await {
        Ok(summary) => Ok(Json(json!({
            "success": true,
            "summary": summary
        }))),
        Err(e) => Err(ApiError::Internal(format!(
            "AI Summarization failed: {}",
            e
        ))),
    }
}

/// API: Suggest firewall rules using AI based on recent events
pub async fn api_v1_neural_suggest_rules(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let events = state.security_events.read().await;
    // Get the 20 most recent events
    let recent_events: Vec<SystemEvent> = events.iter().rev().take(20).cloned().collect();
    let config = state.config.read().await;
    let current_rules = &config.firewall_rules;

    match state
        .wolf_brain
        .suggest_firewall_rules(&recent_events, current_rules)
        .await
    {
        Ok(suggestions) => Ok(Json(json!({
            "success": true,
            "suggestions": suggestions
        }))),
        Err(e) => Err(ApiError::Internal(format!(
            "AI Rule Suggestion failed: {}",
            e
        ))),
    }
}

#[derive(Deserialize)]
pub struct NeuralCommand {
    pub command: String,
}

pub async fn api_v1_neural_command(
    State(state): State<AppState>,
    Json(payload): Json<NeuralCommand>,
) -> ApiResult<serde_json::Value> {
    match state.wolf_brain.ask_black(&payload.command).await {
        Ok(response) => Ok(Json(json!({
            "success": true,
            "response": response
        }))),
        Err(e) => Err(ApiError::Internal(format!(
            "Error processing command: {}",
            e
        ))),
    }
}

/// API: Returns identified security threats.
pub async fn api_security_threats(State(state): State<AppState>) -> ApiResult<Vec<Threat>> {
    Ok(Json(
        state
            .wolf_security
            .read()
            .await
            .threat_detector
            .get_active_threats()
            .await,
    ))
}

/// API: Unlock vault with password
pub async fn api_vault_unlock(
    State(vault_service): State<Arc<VaultService>>,
    Json(request): Json<VaultUnlockRequest>,
) -> impl IntoResponse {
    if vault_service.unlock(&request.password).await {
        Json(json!({"success": true, "message": "Vault unlocked successfully"}))
    } else {
        Json(json!({"success": false, "message": "Invalid password"}))
    }
}

/// API: Get vault contents
pub async fn api_vault_contents(State(state): State<AppState>) -> Json<serde_json::Value> {
    let vault_service = &state.vault_service;
    let unlocked = vault_service.is_unlocked().await;
    Json(json!({
        "success": true,
        "status": if unlocked { "unlocked" } else { "locked" },
        "error": None::<String>,
    }))
}

/// API: Add item to vault
pub async fn api_vault_add(
    State(state): State<AppState>,
    Json(request): Json<VaultAddRequest>,
) -> Json<serde_json::Value> {
    let vault_service = &state.vault_service;
    match vault_service
        .add_item(request.name, request.content, request.category)
        .await
    {
        Ok(_) => Json(json!({"success": true, "message": "Item added to vault"})),
        Err(e) => Json(json!({"success": false, "message": e})),
    }
}

/// API: Delete item from vault
pub async fn api_vault_delete(
    State(state): State<AppState>,
    Json(request): Json<VaultDeleteRequest>,
) -> Json<serde_json::Value> {
    let vault_service = &state.vault_service;
    match vault_service.delete_item(&request.id).await {
        Ok(_) => Json(json!({"success": true, "message": "Item deleted from vault"})),
        Err(e) => Json(json!({"success": false, "message": e})),
    }
}

/// API: Retrieve item from vault (internal helper or extra endpoint)
pub async fn api_vault_retrieve(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let vault_service = &state.vault_service;
    match vault_service.get_items().await {
        Ok(items) => {
            if let Some(item) = items.iter().find(|i| i.id == id) {
                Json(json!({"success": true, "item": item}))
            } else {
                Json(json!({"success": false, "message": "Item not found"}))
            }
        }
        Err(e) => Json(json!({"success": false, "message": e})),
    }
}

/// API: Export vault contents
pub async fn api_vault_export(State(state): State<AppState>) -> impl IntoResponse {
    let vault_service = &state.vault_service;
    match vault_service.export().await {
        Ok(json_data) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .header(
                "Content-Disposition",
                "attachment; filename=\"wolf_den_vault.json\"",
            )
            .body(axum::body::Body::from(json_data))
            .expect("Failed to build response"),
        Err(e) => Json(json!({"success": false, "message": e})).into_response(),
    }
}

/// API: Clear vault contents
pub async fn api_vault_clear(State(state): State<AppState>) -> impl IntoResponse {
    let vault_service = &state.vault_service;
    match vault_service.clear().await {
        Ok(_) => Json(json!({"success": true, "message": "Vault cleared successfully"})),
        Err(e) => Json(json!({"success": false, "message": e})),
    }
}

/// API: Send howl message
pub async fn api_howl_send(
    State(state): State<AppState>,
    Json(request): Json<HowlSendRequest>,
) -> Json<serde_json::Value> {
    let howl_service = &state.howl_service;
    match howl_service
        .send_howl(
            request.channel,
            request.recipient,
            request.message,
            request.priority,
        )
        .await
    {
        Ok(val) => Json(val),
        Err(e) => Json(json!({"success": false, "message": format!("Failed to send howl: {}", e)})),
    }
}

/// API: Get howl messages
pub async fn api_howl_messages(State(state): State<AppState>) -> Json<HowlResponse> {
    let howl_service = &state.howl_service;
    let messages = howl_service.get_messages().await;
    Json(HowlResponse {
        success: true,
        messages: Some(messages),
        channels: None,
        error: None,
    })
}

/// API: Get howl channels
pub async fn api_howl_channels(State(state): State<AppState>) -> Json<HowlResponse> {
    let howl_service = &state.howl_service;
    let channels_list = howl_service.get_channels().await;
    Json(HowlResponse {
        success: true,
        messages: None,
        channels: Some(channels_list),
        error: None,
    })
}

/// API: Hashes data using Blake3.
pub async fn api_hash(
    State(state): State<AppState>,
    Json(request): Json<HashRequest>,
) -> ApiResult<HashResponse> {
    if request.algorithm != "blake3" {
        return Err(ApiError::BadRequest(
            "Unsupported algorithm. Only 'blake3' is available.".to_string(),
        ));
    }

    let hash = state
        .crypto
        .hash(request.data.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(HashResponse {
        hash: hex::encode(hash),
        success: true,
        error: None,
    }))
}

/// API: Derives a key using the configured KDF.
pub async fn api_kdf(
    State(state): State<AppState>,
    Json(request): Json<KdfRequest>,
) -> ApiResult<KdfResponse> {
    let key_length = 32; // Default to 32 bytes
    let key = state
        .crypto
        .derive_key(
            request.password.as_bytes(),
            request.salt.as_bytes(),
            key_length,
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(KdfResponse {
        key: hex::encode(key),
        length: key_length,
        success: true,
        error: None,
    }))
}

/// API: Generates a Message Authentication Code.
pub async fn api_mac(
    State(state): State<AppState>,
    Json(request): Json<MacRequest>,
) -> Json<MacResponse> {
    let key_bytes = match hex::decode(&request.key) {
        Ok(kb) => kb,
        Err(_) => {
            return Json(MacResponse {
                mac: String::new(),
                success: false,
                error: Some("Invalid hex for key".to_string()),
            })
        }
    };
    match state.crypto.mac(request.data.as_bytes(), &key_bytes).await {
        Ok(mac) => Json(MacResponse {
            mac: hex::encode(mac),
            success: true,
            error: None,
        }),
        Err(e) => Json(MacResponse {
            mac: String::new(),
            success: false,
            error: Some(e.to_string()),
        }),
    }
}

/// API: Returns the status of the security module.
pub async fn api_security_status(
    State(state): State<AppState>,
    _headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Validate API key
    // validate_api_key(&headers).await?;

    // Original implementation
    let status = state.wolf_security.read().await.get_status().await;

    let threat_level = if status.threat_detection.active_threats > 0 {
        "elevated"
    } else {
        "low"
    };

    let firewall_enabled = state.swarm_manager.firewall.read().await.enabled;

    Ok(Json(serde_json::json!({
        "status": "active",
        "threat_level": threat_level,
        "active_threats": status.threat_detection.active_threats,
        "total_events_processed": status.monitoring.events_processed,
        "firewall_enabled": firewall_enabled,
    })))
}

/// API: Returns recorded security events.
pub async fn api_security_events(State(state): State<AppState>) -> Json<SecurityEventsResponse> {
    Json(SecurityEventsResponse {
        events: state.wolf_security.read().await.monitor.get_events().await,
    })
}

/// API: Returns detailed peer status information
pub async fn api_peer_status(State(state): State<AppState>) -> Json<Vec<PeerStatus>> {
    Json(get_peer_status(&state.peers).await)
}

/// API: Returns the list of system events.
pub async fn api_events(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let events: tokio::sync::RwLockReadGuard<Vec<SystemEvent>> = state.security_events.read().await;
    Ok(Json(serde_json::json!({
        "events": *events,
        "count": events.len(),
        "timestamp": Utc::now().to_rfc3339()
    })))
}

/// API: Returns the current user's wolf role
pub async fn api_user_role(
    State(state): State<AppState>,
    jar: axum_extra::extract::CookieJar,
) -> impl IntoResponse {
    if let Some(cookie) = jar.get(AUTH_COOKIE_NAME) {
        if let Some((value, mac)) = cookie.value().split_once('.') {
            if let Ok(mac_bytes) = hex::decode(mac) {
                if let Ok(valid) = state.crypto.verify_mac(value.as_bytes(), &mac_bytes).await {
                    if valid {
                        // Parse session data to extract role
                        let parts: Vec<&str> = value.split(':').collect();
                        if parts.len() >= 2 {
                            let role_str = parts[1];
                            let role_display = match role_str {
                                "omega" => "Omega (Pack Leader)",
                                "alpha" => "Alpha (Administrator)",
                                "gamma" => "Gamma (Specialist)",
                                "beta" => "Beta (Pack Member)",
                                _ => "Unknown",
                            };
                            return Json(json!({
                                "role": role_str,
                                "display": role_display,
                                "success": true
                            }));
                        }
                    }
                }
            }
        }
    }

    Json(json!({"role": "none", "display": "Not Authenticated", "success": false}))
}

/// API: Returns overall network status from wolf_net
pub async fn api_network_status(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let swarm_manager = &state.swarm_manager;
    let stats: SwarmStats = swarm_manager
        .get_stats()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to get network stats: {}", e)))?;

    Ok(Json(json!({
        "peer_id": swarm_manager.local_peer_id.as_str(),
        "connected_peers": stats.connected_peers,
        "metrics": stats.metrics,
        "listen_addresses": swarm_manager.get_listeners().await.unwrap_or_default(),
        "swarm_status": if !swarm_manager.get_listeners().await.unwrap_or_default().is_empty() { "Connected" } else { "Disconnected" }
    })))
}

/// API: Lists all peers known by the network swarm
pub async fn api_network_peers(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let swarm_manager = &state.swarm_manager;
    let peers: Vec<EntityInfo> = swarm_manager
        .list_peers()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to list network peers: {}", e)))?;

    Ok(Json(json!({
        "count": peers.len(),
        "peers": peers
    })))
}

/// API: Get details for a specific peer
pub async fn api_network_peer_details(
    State(swarm_manager): State<Arc<SwarmManager>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult<serde_json::Value> {
    let peer_id = PeerId::from_string(id);

    let info: Option<EntityInfo> = swarm_manager
        .get_peer_info(peer_id)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to get peer info from swarm: {}", e)))?;

    Ok(Json(json!(info)))
}

/// API: Returns detailed network health metrics
pub async fn api_network_metrics(
    State(swarm_manager): State<Arc<SwarmManager>>,
) -> ApiResult<NetworkMetricsResponse> {
    let metrics = swarm_manager.get_metrics().await;
    let peers: Vec<EntityInfo> = swarm_manager.list_peers().await.unwrap_or_default();

    let avg_health = if peers.is_empty() {
        1.0
    } else {
        peers.iter().map(|p| p.metrics.health_score).sum::<f64>() / peers.len() as f64
    };

    Ok(Json(NetworkMetricsResponse {
        overall_health_score: avg_health,
        node_metrics: serde_json::to_value(metrics).unwrap_or_default(),
    }))
}

/// API: Dial a new peer
pub async fn api_network_dial(
    State(state): State<AppState>,
    Json(payload): Json<DialRequest>,
) -> ApiResult<serde_json::Value> {
    info!("🔗 API Dial request for address: {}", payload.address);

    // Parse the address to Multiaddr
    let multiaddr = payload
        .address
        .parse()
        .map_err(|e| ApiError::BadRequest(format!("Invalid multiaddress: {}", e)))?;

    // Dial the address via SwarmManager
    state
        .swarm_manager
        .dial_addr(multiaddr)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to dial: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "message": format!("Dialing address: {}", payload.address)
    })))
}

/// API: Block a peer (disconnect and blacklist)
pub async fn api_network_block(
    State(swarm_manager): State<Arc<SwarmManager>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<axum::http::StatusCode, axum::http::StatusCode> {
    let peer_id = PeerId::from_string(id);

    swarm_manager
        .command_sender()
        .send(SwarmCommand::BlockPeer { peer_id })
        .await
        .map_err(|e| {
            tracing::error!("Failed to block peer: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(axum::http::StatusCode::OK)
}

#[derive(Deserialize)]
pub struct ScanTriggerRequest {
    pub scan_type: Option<String>,
    pub target: Option<String>,
}

pub async fn api_v1_scan_trigger(
    State(state): State<AppState>,
    Json(payload): Json<ScanTriggerRequest>,
) -> ApiResult<serde_json::Value> {
    let scan_type = payload.scan_type.unwrap_or_else(|| "full".to_string());
    let target = payload.target.unwrap_or_else(|| "system".to_string());
    match state
        .wolf_security
        .read()
        .await
        .vulnerability_scanner
        .perform_scan()
        .await
    {
        Ok(results) => Ok(Json(json!({
            "success": true,
            "message": format!("Vulnerability scan ({}) completed successfully on {}", scan_type, target),
            "issues_found": results.len(),
            "scan_params": {"type": scan_type, "target": target},
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))),
        Err(e) => Err(ApiError::Internal(format!("Failed to perform scan: {}", e))),
    }
}

#[derive(Deserialize)]
pub struct ThreatScanRequest {
    pub target_type: String,
    pub target_value: String,
}

pub async fn api_v1_threat_scan_trigger(
    State(state): State<AppState>,
    Json(payload): Json<ThreatScanRequest>,
) -> ApiResult<serde_json::Value> {
    let db = state.threat_service.threat_db.read().await;
    let mut found = false;
    let mut details = "No threats detected in local database".to_string();
    let target_value = payload.target_value.trim();

    match payload.target_type.to_lowercase().as_str() {
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
            payload.target_type,
            if found { "THREAT" } else { "CLEAN" }
        ),
        severity: if found {
            "high".to_string()
        } else {
            "info".to_string()
        },
        source: "api".to_string(),
        user_id: None,
        ip_address: if payload.target_type == "ip" {
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
    state.security_events.write().await.push(event);

    Ok(Json(json!({
        "success": true,
        "found": found,
        "details": details,
        "target": target_value,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

pub async fn api_v1_threat_details(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let threats = state
        .wolf_security
        .read()
        .await
        .threat_detector
        .get_active_threats()
        .await;
    match threats.into_iter().find(|t| t.id == id) {
        Some(threat) => Ok(Json(serde_json::json!(threat))),
        None => Err(ApiError::NotFound(format!("Threat not found: {}", id))),
    }
}

#[derive(Deserialize)]
pub struct ThreatResolveRequest {
    pub id: String,
    pub resolution: Option<String>,
}

pub async fn api_v1_threat_resolve(
    State(state): State<AppState>,
    Json(payload): Json<ThreatResolveRequest>,
) -> ApiResult<serde_json::Value> {
    let resolution = payload
        .resolution
        .clone()
        .unwrap_or_else(|| "Manual resolution".to_string());
    let event = SystemEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: "threat_resolved".to_string(),
        message: format!("Threat {} resolved: {}", payload.id, resolution),
        severity: "info".to_string(),
        source: "api".to_string(),
        user_id: None,
        ip_address: None,
        metadata: HashMap::from([
            ("threat_id".to_string(), payload.id.clone()),
            ("resolution".to_string(), resolution.clone()),
        ]),
        correlation_id: None,
    };
    state.security_events.write().await.push(event);
    Ok(Json(json!({
        "success": true,
        "message": format!("Threat {} marked as resolved", payload.id),
        "resolution": resolution,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

#[derive(Deserialize)]
pub struct ThreatIgnoreRequest {
    pub id: String,
    pub reason: Option<String>,
}

pub async fn api_v1_threat_ignore(
    State(state): State<AppState>,
    Json(payload): Json<ThreatIgnoreRequest>,
) -> ApiResult<serde_json::Value> {
    let reason = payload
        .reason
        .clone()
        .unwrap_or_else(|| "Manual ignore".to_string());
    let event = SystemEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: "threat_ignored".to_string(),
        message: format!("Threat {} ignored: {}", payload.id, reason),
        severity: "warning".to_string(),
        source: "api".to_string(),
        user_id: None,
        ip_address: None,
        metadata: HashMap::from([
            ("threat_id".to_string(), payload.id.clone()),
            ("reason".to_string(), reason.clone()),
        ]),
        correlation_id: None,
    };
    state.security_events.write().await.push(event);
    Ok(Json(json!({
        "success": true,
        "message": format!("Threat {} marked as ignored", payload.id),
        "reason": reason,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// API v1 security metrics endpoint
pub async fn api_v1_security_metrics(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let stats = state.security_manager.get_security_stats();
    Ok(Json(serde_json::json!({ "metrics": stats })))
}

/// API v1 behavioral metrics endpoint
pub async fn api_v1_behavioral_metrics(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let swarm_metrics = state.swarm_manager.get_metrics().await;
    let security_stats = state.wolf_security.read().await.get_status().await;

    Ok(Json(serde_json::json!({
        "metrics": {
            "anomalies_detected": security_stats.threat_detection.metrics.threats_detected,
            "behavioral_patterns_analyzed": security_stats.threat_detection.metrics.total_events,
            "risk_score_avg": security_stats.threat_detection.metrics.risk_score,
            "connection_attempts": swarm_metrics.connection_attempts,
            "active_connections": swarm_metrics.active_connections,
            "suspicious_connections": security_stats.threat_detection.suspicious_peers,
            "failed_handshakes": 0,
            "policy_violations": security_stats.threat_detection.metrics.compliance_violations,
        }
    })))
}

/// API v1 peer behavior endpoint
pub async fn api_v1_peer_behavior(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let peer_id = id.clone();
    let info = state
        .swarm_manager
        .get_peer_info(PeerId::from_string(peer_id))
        .await;

    let (risk_score, anomalies): (f64, Vec<String>) = if let Ok(Some(info)) = info {
        (1.0 - info.trust_score, vec![])
    } else {
        (0.0, vec![])
    };

    Ok(Json(serde_json::json!({
        "peer_id": id,
        "behavior": {
            "risk_score": risk_score,
            "anomalies": anomalies,
            "patterns": []
        }
    })))
}

/// API v1 crypto metrics endpoint
pub async fn api_v1_crypto_metrics(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let active_sessions = state.howl_service.active_sessions.read().await.len();

    Ok(Json(serde_json::json!({
        "metrics": {
            "algorithm": "AES-256-GCM", // Derived from security stance
            "key_size": 256,
            "active_sessions": active_sessions,
            "operations_count": 0
        }
    })))
}

/// API v1 crypto status endpoint
pub async fn api_v1_crypto_status(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let config = state.config.read().await;
    Ok(Json(serde_json::json!({
        "status": "active",
        "algorithm": "AES-256-GCM",
        "security_level": config.security.stance,
        "public_key": state.swarm_manager.local_peer_id.to_string()
    })))
}

/// API v1 threat intelligence endpoint
pub async fn api_v1_threat_intelligence(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let active_threats = state
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

    let mut severity_distribution = HashMap::new();
    let mut type_distribution = HashMap::new();
    for threat in &active_threats {
        let severity = format!("{:?}", threat.severity);
        *severity_distribution.entry(severity).or_insert(0) += 1;
        let t_type = format!("{:?}", threat.threat_type);
        *type_distribution.entry(t_type).or_insert(0) += 1;
    }

    Ok(Json(serde_json::json!({
        "intelligence": {
            "total_threats": active_threats.len(),
            "threat_types": threat_types,
            "severity_distribution": severity_distribution,
            "type_distribution": type_distribution
        }
    })))
}

/// API v1 active threats endpoint
pub async fn api_v1_active_threats(
    State(state): State<AppState>,
    Query(filter): Query<ThreatFilter>,
) -> ApiResult<serde_json::Value> {
    let active_threats = state
        .wolf_security
        .read()
        .await
        .threat_detector
        .get_active_threats()
        .await;

    let active_threats: Vec<_> = if let Some(severity) = filter.severity {
        active_threats
            .into_iter()
            .filter(|t| format!("{:?}", t.severity).to_lowercase() == severity.to_lowercase())
            .collect()
    } else {
        active_threats
    };
    let count = active_threats.len();

    Ok(Json(serde_json::json!({
        "active_threats": active_threats,
        "count": count
    })))
}

/// API: Returns the overall system status with enhanced metrics and security context
#[instrument(skip(state))]
pub async fn api_status(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    // Get read locks for all required state
    let (uptime_secs, peer_count, peer_details, events_count_last_hour) = {
        let peers: tokio::sync::RwLockReadGuard<HashMap<String, ApiPeerInfo>> =
            state.peers.read().await;
        let security_events: tokio::sync::RwLockReadGuard<Vec<SystemEvent>> =
            state.security_events.read().await;

        // Calculate system uptime
        let uptime = Utc::now()
            .signed_duration_since(state.metrics.start_time)
            .to_std()
            .unwrap_or_default();

        // Compile peer statistics
        let peer_stats = peers
            .values()
            .fold(HashMap::<String, usize>::new(), |mut acc, peer| {
                *acc.entry(peer.status.clone()).or_default() += 1;
                acc
            });

        let events_last_hour = security_events
            .iter()
            .filter(|e| e.timestamp > Utc::now() - chrono::Duration::hours(1))
            .count();

        (uptime.as_secs(), peers.len(), peer_stats, events_last_hour)
    }; // Locks are dropped here

    let security_stats = state.security_manager.get_security_stats();
    let active_threats = state.security_manager.get_active_threats();

    // Prepare response
    let response = json!({
        "status": "operational",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime_secs,
        "peers": {
            "total": peer_count,
            "by_status": peer_details,
        },
        "security": {
            "trusted_peers": security_stats.trusted_peers,
            "suspicious_peers": security_stats.suspicious_peers,
            "active_threats": active_threats,
            "events_last_hour": events_count_last_hour,
        },
        "last_updated": Utc::now().to_rfc3339(),
        "network_status": "connected",
    });

    // Log the status check
    {
        let mut events: tokio::sync::RwLockWriteGuard<Vec<SystemEvent>> =
            state.security_events.write().await;
        events.push(SystemEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: "status_check".to_string(),
            message: "System status retrieved".to_string(),
            severity: "info".to_string(),
            source: "api".to_string(),
            user_id: None,
            ip_address: None,
            metadata: {
                let mut m = HashMap::<String, String>::new();
                m.insert("peer_count".to_string(), peer_count.to_string());
                m
            },
            correlation_id: None,
        });
    }

    Ok(Json(response))
}

/// API: Returns the list of connected peers.
pub async fn api_peers(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let peers = state.peers.read().await;
    let peer_list: Vec<&ApiPeerInfo> = peers.values().collect();
    Ok(Json(serde_json::json!({
        "count": peer_list.len(),
        "peers": peer_list,
    })))
}

pub async fn api_v1_threat_history(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let events: tokio::sync::RwLockReadGuard<Vec<SystemEvent>> = state.security_events.read().await;
    let history: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "threat_resolved" || e.event_type == "threat_ignored")
        .collect();
    Ok(Json(json!({"history": history, "count": history.len()})))
}

pub async fn api_v1_threat_export(State(state): State<AppState>) -> Result<Response, ApiError> {
    let events: tokio::sync::RwLockReadGuard<Vec<SystemEvent>> = state.security_events.read().await;
    let history: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "threat_resolved" || e.event_type == "threat_ignored")
        .collect();
    let mut csv = String::from("Timestamp,Event Type,Message,Severity,Threat ID,Details\n");
    for event in history {
        let threat_id = event
            .metadata
            .get("threat_id")
            .map(|s| s.as_str())
            .unwrap_or("");
        let details = if event.event_type == "threat_resolved" {
            event
                .metadata
                .get("resolution")
                .map(|s| s.as_str())
                .unwrap_or("")
        } else {
            event
                .metadata
                .get("reason")
                .map(|s| s.as_str())
                .unwrap_or("")
        };
        let escape = |s: &str| -> String {
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace("\"", "\"\""))
            } else {
                s.to_string()
            }
        };
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            event.timestamp.to_rfc3339(),
            escape(&event.event_type),
            escape(&event.message),
            escape(&event.severity),
            escape(threat_id),
            escape(details)
        ));
    }
    Ok(axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("Content-Type", "text/csv")
        .header(
            "Content-Disposition",
            "attachment; filename=\"threat_history.csv\"",
        )
        .body(axum::body::Body::from(csv))
        .unwrap())
}

pub async fn api_v1_threat_stats(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let active_threats = state
        .wolf_security
        .read()
        .await
        .threat_detector
        .get_active_threats()
        .await;
    let mut severity_counts = HashMap::new();
    let mut type_counts = HashMap::new();
    for threat in &active_threats {
        let severity = format!("{:?}", threat.severity);
        *severity_counts.entry(severity).or_insert(0) += 1;
        let t_type = format!("{:?}", threat.threat_type);
        *type_counts.entry(t_type).or_insert(0) += 1;
    }
    let events: tokio::sync::RwLockReadGuard<Vec<SystemEvent>> = state.security_events.read().await;
    let now = Utc::now();
    let one_day_ago = now - Duration::days(1);
    let mut resolved_count = 0;
    let mut ignored_count = 0;
    let mut activity_24h = HashMap::new();
    for event in events.iter() {
        if event.event_type == "threat_resolved" {
            resolved_count += 1;
        } else if event.event_type == "threat_ignored" {
            ignored_count += 1;
        }
        if event.timestamp > one_day_ago && (event.event_type.starts_with("threat")) {
            let hour_key = event.timestamp.format("%Y-%m-%dT%H:00:00Z").to_string();
            *activity_24h.entry(hour_key).or_insert(0) += 1;
        }
    }

    let mut activity_timeline: Vec<_> = activity_24h
        .into_iter()
        .map(|(time, count)| json!({"time": time, "count": count}))
        .collect();
    activity_timeline.sort_by(|a, b| a["time"].as_str().unwrap().cmp(b["time"].as_str().unwrap()));

    Ok(Json(json!({
        "active_summary": {
            "total": active_threats.len(),
            "by_severity": severity_counts,
            "by_type": type_counts
        },
        "historical_summary": {
            "total_resolved": resolved_count,
            "total_ignored": ignored_count
        },
        "activity_timeline_24h": activity_timeline.clone(),
        "activity_timeline": activity_timeline,
        "timestamp": now.to_rfc3339()
    })))
}

pub async fn api_v1_threat_timeline(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let events: tokio::sync::RwLockReadGuard<Vec<SystemEvent>> = state.security_events.read().await;
    let mut timeline: Vec<_> = events
        .iter()
        .filter(|e| e.event_type.contains("threat") || e.event_type.contains("security"))
        .collect();
    timeline.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(Json(json!({
        "timeline": timeline,
        "count": timeline.len(),
        "timestamp": Utc::now().to_rfc3339()
    })))
}

pub async fn api_v1_threat_feed_status(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let db = state.threat_service.threat_db.read().await;
    let status = if db.last_updated.is_some() {
        "active"
    } else {
        "initializing"
    };
    Ok(Json(json!({
        "status": status,
        "last_updated": db.last_updated,
        "stats": {
            "malicious_ips_count": db.malicious_ips.len(),
            "known_cves_count": db.known_cves.len()
        },
        "feeds": [
            {"name": "Emerging Threats (IPs)", "status": "active"},
            {"name": "CIRCL.lu (CVEs)", "status": "active"}
        ]
    })))
}

#[derive(Deserialize)]
pub struct BlockIpRequest {
    pub ip: String,
    pub reason: Option<String>,
}

pub async fn api_v1_threat_block_ip(
    State(state): State<AppState>,
    Json(payload): Json<BlockIpRequest>,
) -> ApiResult<serde_json::Value> {
    let ip = payload.ip.trim().to_string();
    let reason = payload.reason.unwrap_or_else(|| "Manual block".to_string());
    {
        let mut db = state.threat_service.threat_db.write().await;
        db.malicious_ips.insert(ip.clone());
    }
    let event = SystemEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: "ip_blocked_manual".to_string(),
        message: format!("IP {} manually blocked: {}", ip, reason),
        severity: "warning".to_string(),
        source: "api".to_string(),
        user_id: None,
        ip_address: Some(ip.clone()),
        metadata: HashMap::from([
            ("ip".to_string(), ip.clone()),
            ("reason".to_string(), reason.clone()),
        ]),
        correlation_id: None,
    };
    state.security_events.write().await.push(event);
    Ok(Json(json!({
        "success": true,
        "message": format!("IP {} added to blocklist", ip),
        "ip": ip,
        "reason": reason,
        "timestamp": Utc::now().to_rfc3339()
    })))
}

#[derive(Deserialize)]
pub struct UnblockIpRequest {
    pub ip: String,
    pub reason: Option<String>,
}

pub async fn api_v1_threat_unblock_ip(
    State(state): State<AppState>,
    Json(payload): Json<UnblockIpRequest>,
) -> ApiResult<serde_json::Value> {
    let ip = payload.ip.trim().to_string();
    let reason = payload
        .reason
        .unwrap_or_else(|| "Manual unblock".to_string());
    let removed = {
        let mut db = state.threat_service.threat_db.write().await;
        db.malicious_ips.remove(&ip)
    };
    if removed {
        let event = SystemEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: "ip_unblocked_manual".to_string(),
            message: format!("IP {} manually unblocked: {}", ip, reason),
            severity: "info".to_string(),
            source: "api".to_string(),
            user_id: None,
            ip_address: Some(ip.clone()),
            metadata: HashMap::<String, String>::from([
                ("ip".to_string(), ip.clone()),
                ("reason".to_string(), reason.clone()),
            ]),
            correlation_id: None,
        };
        state.security_events.write().await.push(event);
        Ok(Json(json!({
            "success": true,
            "message": format!("IP {} removed from blocklist", ip),
            "ip": ip,
            "reason": reason,
            "timestamp": Utc::now().to_rfc3339()
        })))
    } else {
        Ok(Json(json!({
            "success": false,
            "message": format!("IP {} was not in the blocklist", ip),
            "ip": ip,
            "timestamp": Utc::now().to_rfc3339()
        })))
    }
}

#[derive(Deserialize)]
pub struct ThreatSearchRequest {
    pub query: String,
}

pub async fn api_v1_threat_search(
    State(state): State<AppState>,
    Query(params): Query<ThreatSearchRequest>,
) -> ApiResult<serde_json::Value> {
    let db = state.threat_service.threat_db.read().await;
    let query = params.query.trim().to_lowercase();
    let matching_ips: Vec<&String> = db
        .malicious_ips
        .iter()
        .filter(|ip| ip.contains(&query))
        .collect();
    let matching_cves: Vec<&_> = db
        .known_cves
        .values()
        .filter(|cve| {
            cve.id.to_lowercase().contains(&query)
                || cve.description.to_lowercase().contains(&query)
        })
        .collect();
    Ok(Json(json!({
        "query": params.query,
        "results": {
            "ips": matching_ips,
            "cves": matching_cves
        },
        "count": matching_ips.len() + matching_cves.len(),
        "timestamp": Utc::now().to_rfc3339()
    })))
}

pub async fn api_v1_threat_report(State(state): State<AppState>) -> Result<Response, ApiError> {
    let now = Utc::now();
    let db = state.threat_service.threat_db.read().await;
    let feed_status = if db.last_updated.is_some() {
        "Active"
    } else {
        "Initializing"
    };
    let ip_count = db.malicious_ips.len();
    let cve_count = db.known_cves.len();
    let last_update = db
        .last_updated
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "Never".to_string());
    let active_threats = state
        .wolf_security
        .read()
        .await
        .threat_detector
        .get_active_threats()
        .await;
    let critical_count = active_threats
        .iter()
        .filter(|t| {
            format!("{:?}", t.severity)
                .to_lowercase()
                .contains("critical")
        })
        .count();
    let high_count = active_threats
        .iter()
        .filter(|t| format!("{:?}", t.severity).to_lowercase().contains("high"))
        .count();
    let events: tokio::sync::RwLockReadGuard<Vec<SystemEvent>> = state.security_events.read().await;
    let recent_events: Vec<_> = events.iter().rev().take(15).collect();
    let mut report = String::new();
    report.push_str(&format!("WOLF PROWLER THREAT LANDSCAPE REPORT\nGenerated: {}\n==================================================\n\n", now.to_rfc3339()));
    report.push_str(&format!("1. THREAT INTELLIGENCE STATUS\n-----------------------------\nFeed Status:   {}\nMalicious IPs: {}\nKnown CVEs:    {}\nLast Updated:  {}\n\n", feed_status, ip_count, cve_count, last_update));
    report.push_str(&format!("2. ACTIVE THREAT SUMMARY\n------------------------\nTotal Active:  {}\nCritical:      {}\nHigh Severity: {}\n\n", active_threats.len(), critical_count, high_count));
    report.push_str("3. RECENT SECURITY EVENTS\n-------------------------\n");
    for event in recent_events {
        report.push_str(&format!(
            "[{}] [{}] {}: {}\n",
            event.timestamp.format("%H:%M:%S"),
            event.severity.to_uppercase(),
            event.event_type,
            event.message
        ));
    }
    report.push_str("\n==================================================\n");
    Ok(axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("Content-Type", "text/markdown")
        .header(
            "Content-Disposition",
            "attachment; filename=\"threat_report.md\"",
        )
        .body(axum::body::Body::from(report))
        .unwrap())
}

pub async fn api_v1_threat_feed_refresh(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    match ThreatFeedManager::update_feeds(state.threat_service.threat_db.clone()).await {
        Ok(_) => Ok(Json(json!({
            "success": true,
            "message": "Threat feeds updated successfully",
            "timestamp": Utc::now().to_rfc3339()
        }))),
        Err(e) => Err(ApiError::Internal(format!(
            "Failed to update threat feeds: {}",
            e
        ))),
    }
}

#[derive(Deserialize)]
pub struct ThreatFeedConfigRequest {
    pub ip_feed_url: Option<String>,
    pub cve_feed_url: Option<String>,
}

pub async fn api_v1_threat_feed_config(
    State(state): State<AppState>,
    Json(payload): Json<ThreatFeedConfigRequest>,
) -> ApiResult<serde_json::Value> {
    let mut db = state.threat_service.threat_db.write().await;
    if let Some(url) = payload.ip_feed_url {
        db.config.ip_feed_url = url;
    }
    if let Some(url) = payload.cve_feed_url {
        db.config.cve_feed_url = url;
    }
    Ok(Json(json!({
        "success": true,
        "message": "Threat feed configuration updated",
        "config": db.config,
        "timestamp": Utc::now().to_rfc3339()
    })))
}

pub async fn api_v1_threat_feed_reset(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let mut db = state.threat_service.threat_db.write().await;
    db.config = crate::threat_feeds::ThreatFeedConfig::default();
    Ok(Json(json!({
        "success": true,
        "message": "Threat feed configuration reset to defaults",
        "config": db.config,
        "timestamp": Utc::now().to_rfc3339()
    })))
}

pub async fn api_v1_threat_feed_validate(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let validation_results =
        ThreatFeedManager::validate_feeds(state.threat_service.threat_db.clone()).await;
    let all_reachable = validation_results.values().all(|s| s == "reachable");
    Ok(Json(json!({
        "success": true,
        "valid": all_reachable,
        "results": validation_results,
        "timestamp": Utc::now().to_rfc3339()
    })))
}

/// API: Returns the network topology for visualization
pub async fn api_network_topology(
    State(state): State<AppState>,
) -> ApiResult<NetworkTopologyResponse> {
    let swarm_manager = &state.swarm_manager;
    let config = state.config.read().await;
    let local_peer_id = swarm_manager.local_peer_id.as_str().to_string();

    let peers: Vec<EntityInfo> = match swarm_manager.list_peers().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to list peers from swarm: {}", e);
            return Err(ApiError::Internal(format!("Failed to list peers: {}", e)));
        }
    };

    let stats: SwarmStats = match swarm_manager.get_stats().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to get stats from swarm: {}", e);
            return Err(ApiError::Internal(format!("Failed to get stats: {}", e)));
        }
    };

    // Create nodes from peer list
    let mut nodes: Vec<NetworkNode> = peers
        .into_iter()
        .map(|peer_info| {
            let peer_id_str = peer_info.entity_id.peer_id.as_str().to_string();
            NetworkNode {
                id: peer_id_str.clone(),
                label: peer_id_str.chars().take(8).collect(),
                role: if peer_info.metrics.health_score > 90.0 {
                    format!("{:?}", WolfRank::Beta)
                } else if peer_info.metrics.health_score > 70.0 {
                    format!("{:?}", WolfRank::Hunter)
                } else {
                    format!("{:?}", WolfRank::Omega)
                },
                status: format!("{:?}", peer_info.status),
                last_seen: Some(peer_info.last_seen.to_rfc3339()),
                version: peer_info.agent_version,
                addresses: Some(peer_info.addresses.iter().map(|a| a.to_string()).collect()),
            }
        })
        .collect();

    // Ensure local node is in the list
    if !nodes.iter().any(|n| n.id == local_peer_id) {
        let local_role = config.dashboard.admin_role.clone();
        nodes.push(NetworkNode {
            id: local_peer_id.clone(),
            label: "Local".to_string(),
            role: format!("{:?}", local_role),
            status: "Online".to_string(),
            last_seen: Some(Utc::now().to_rfc3339()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            addresses: None,
        });
    }

    // Create links for connected peers
    let links: Vec<NetworkLink> = stats
        .connected_peers_list
        .iter()
        .map(|peer_id: &PeerId| NetworkLink {
            source: local_peer_id.clone(),
            target: peer_id.as_str().to_string(),
            latency: None, // TODO: Get latency from peer metrics
            protocol: Some("tcp".to_string()),
        })
        .collect();

    // Create overview metrics
    let metrics = NetworkOverview {
        total_peers: stats.metrics.unique_peers_seen,
        active_connections: stats.metrics.active_connections,
        total_messages_sent: stats.metrics.total_messages_sent,
        total_messages_received: stats.metrics.total_messages_received,
    };

    // Create detailed topology using extended structures
    let detailed_topology = Some(DetailedTopology {
        nodes: nodes
            .iter()
            .map(|n| NodeTopology { id: n.id.clone() })
            .collect(),
        links: links
            .iter()
            .map(|l| NodeLink {
                from: l.source.clone(),
                to: l.target.clone(),
            })
            .collect(),
    });

    Ok(Json(NetworkTopologyResponse {
        local_node_id: local_peer_id,
        nodes,
        links,
        metrics,
        detailed_topology,
    }))
}
pub async fn api_v1_threat_feed_backup(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let db = state.threat_service.threat_db.read().await;
    let json_data = serde_json::to_string_pretty(&*db).unwrap_or_default();
    let filename = format!(
        "threat_db_backup_{}.json",
        Utc::now().format("%Y%m%d_%H%M%S")
    );
    Ok(axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header("Content-Type", "application/json")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(axum::body::Body::from(json_data))
        .unwrap())
}

pub async fn api_v1_threat_feed_restore(
    State(state): State<AppState>,
    Json(backup): Json<ThreatDatabase>,
) -> ApiResult<serde_json::Value> {
    let mut db = state.threat_service.threat_db.write().await;
    *db = backup;
    Ok(Json(json!({
        "success": true,
        "message": "Threat database restored successfully",
        "stats": {
            "malicious_ips_count": db.malicious_ips.len(),
            "known_cves_count": db.known_cves.len()
        },
        "timestamp": Utc::now().to_rfc3339()
    })))
}

#[cfg(feature = "cloud_security")]
pub async fn api_cloud_scan_aws() -> ApiResult<serde_json::Value> {
    let mut scanner = match AwsScanner::new().await {
        Ok(s) => s,
        Err(e) => return Err(ApiError::Internal(e.to_string())),
    };

    match scanner.scan().await {
        Ok(result) => {
            let res: CloudScanResult = result;
            Ok(Json(json!({"status": "success", "results": res})))
        }
        Err(e) => Err(ApiError::Internal(e.to_string())),
    }
}

#[cfg(not(feature = "cloud_security"))]
pub async fn api_cloud_scan_aws() -> ApiResult<serde_json::Value> {
    Err(ApiError::BadRequest(
        "Cloud security feature not enabled".to_string(),
    ))
}

#[cfg(feature = "cloud_security")]
pub async fn api_cloud_status() -> ApiResult<serde_json::Value> {
    match AwsScanner::new().await {
        Ok(scanner) => match scanner.status().await {
            Ok(status) => Ok(Json(
                json!({"status": "ok", "aws": true, "details": status}),
            )),
            Err(e) => Err(ApiError::Internal(e.to_string())),
        },
        Err(e) => Ok(Json(
            json!({"status": "ok", "aws": false, "error": e.to_string()}),
        )),
    }
}

#[cfg(not(feature = "cloud_security"))]
pub async fn api_cloud_status() -> ApiResult<serde_json::Value> {
    Ok(Json(
        json!({"status": "ok", "aws": false, "cloud_scanning": "disabled"}),
    ))
}

pub async fn api_v1_system_metrics_history(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let metrics = state.system_metrics.read().await;
    Ok(Json(json!({
        "cpu_usage_history": metrics.cpu_usage_history,
        "memory_usage_history": metrics.memory_usage_history,
        "current_cpu": metrics.current_cpu_usage,
        "current_memory": metrics.current_memory_usage,
        "timestamp": Utc::now().to_rfc3339()
    })))
}
/// Request to change security level
#[derive(Deserialize)]
pub struct SecurityLevelRequest {
    pub stance: SecurityStance,
    pub threat_sensitivity: Option<f64>,
    pub rate_limit_strictness: Option<u32>,
    pub min_password_length: Option<usize>,
    pub require_mfa: Option<bool>,
}

/// Response with security policy information
#[derive(Serialize)]
pub struct SecurityPolicyResponse {
    pub stance: String,
    pub description: String,
    pub key_size_bits: u16,
    pub session_timeout_secs: u64,
    pub threat_sensitivity: f64,
    pub rate_limit_strictness: u32,
    pub min_password_length: usize,
    pub require_mfa: bool,
    pub audit_level: String,
    pub peer_trust_mode: String,
}

impl From<&SecurityPolicy> for SecurityPolicyResponse {
    fn from(policy: &SecurityPolicy) -> Self {
        Self {
            stance: policy.stance.to_string(),
            description: policy.description(),
            key_size_bits: policy.key_size_bits(),
            session_timeout_secs: policy.session_timeout_secs(),
            threat_sensitivity: policy.threat_sensitivity,
            rate_limit_strictness: policy.rate_limit_strictness,
            min_password_length: policy.min_password_length,
            require_mfa: policy.require_mfa,
            audit_level: format!("{:?}", policy.audit_level),
            peer_trust_mode: format!("{:?}", policy.peer_trust_mode),
        }
    }
}

/// API: Get current security policy
pub async fn api_security_policy_get(
    State(state): State<AppState>,
) -> ApiResult<SecurityPolicyResponse> {
    let policy = state.security_policy.read().await;
    Ok(Json(SecurityPolicyResponse::from(&*policy)))
}

/// API: Change security policy
pub async fn api_security_policy_set(
    State(state): State<AppState>,
    Json(req): Json<SecurityLevelRequest>,
) -> ApiResult<serde_json::Value> {
    // Create base policy from requested stance
    let mut new_policy = SecurityPolicy::from_stance(req.stance);

    // If Custom, apply provided overrides
    if req.stance == SecurityStance::Custom {
        if let Some(ts) = req.threat_sensitivity {
            new_policy.threat_sensitivity = ts.clamp(0.0, 1.0);
        }
        if let Some(rl) = req.rate_limit_strictness {
            new_policy.rate_limit_strictness = rl;
        }
        if let Some(mpl) = req.min_password_length {
            new_policy.min_password_length = mpl;
        }
        if let Some(mfa) = req.require_mfa {
            new_policy.require_mfa = mfa;
        }
    }

    // Update the policy
    {
        let mut policy = state.security_policy.write().await;
        *policy = new_policy.clone();
    }

    // Note: In a full implementation, we would:
    // 1. Reinitialize CryptoEngine with new level (requires restart)
    // 2. Update NetworkSecurityManager sessions
    // 3. Adjust threat detection sensitivity
    // 4. Update rate limiting

    info!(
        "🔒 Security policy changed to: {}",
        new_policy.description()
    );

    Ok(Json(json!({
        "success": true,
        "message": format!("Security policy changed to {}", new_policy.stance),
        "policy": SecurityPolicyResponse::from(&new_policy),
        "note": "Some changes require server restart to take full effect"
    })))
}

/// API: Get available security stances
pub async fn api_security_stances() -> ApiResult<serde_json::Value> {
    let stances = SecurityStance::all_stances()
        .iter()
        .map(|stance| {
            let policy = SecurityPolicy::from_stance(stance.clone());
            json!({
                "value": stance.to_string().to_lowercase(),
                "name": format!("{} Security", stance),
                "description": policy.description(),
                "key_size": policy.key_size_bits(),
                "session_timeout": policy.session_timeout_secs(),
                "require_mfa": policy.require_mfa,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({ "stances": stances })))
}

/// API: Update runtime settings
pub async fn api_settings_update(
    State(state): State<AppState>,
    Json(settings): Json<crate::dashboard::state::RuntimeSettings>,
) -> ApiResult<serde_json::Value> {
    {
        let mut config = state.config.write().await;
        config.ai.llm_api_url = settings.llm_api_url;
        config.firewall_rules = settings.firewall_rules;
        config
            .save()
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    }

    info!("⚙️ System settings updated and persisted.");
    Ok(Json(
        json!({"success": true, "message": "Settings updated successfully"}),
    ))
}

/// API: Get runtime settings
pub async fn api_settings_get(
    State(state): State<AppState>,
) -> ApiResult<crate::dashboard::state::RuntimeSettings> {
    // Map AppSettings back to the legacy RuntimeSettings structure for the UI
    let config = state.config.read().await;
    Ok(Json(crate::dashboard::state::RuntimeSettings {
        encryption_algorithm: "AES-256-GCM".to_string(),
        security_level: config.security.stance.clone(),
        theme: "Wolf Red".to_string(),
        notifications: config.logging.level != "off",
        auto_refresh: true,
        llm_api_url: config.ai.llm_api_url.clone(),
        firewall_rules: config.firewall_rules.clone(),
    }))
}

// --- Consensus APIs ---

pub async fn api_consensus_status(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let swarm = &state.swarm_manager;
    let consensus_lock = swarm.consensus.read().await;

    if let Some(consensus) = consensus_lock.as_ref() {
        match consensus.get_status().await {
            Ok(status) => Ok(Json(
                serde_json::to_value(status).unwrap_or(json!({"error": "Serialization failed"})),
            )),
            Err(e) => Err(ApiError::Internal(format!(
                "Failed to get consensus status: {}",
                e
            ))),
        }
    } else {
        Err(ApiError::NotFound("Consensus not initialized".into()))
    }
}

pub async fn api_consensus_state(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let swarm = &state.swarm_manager;
    let consensus_lock = swarm.consensus.read().await;

    if let Some(consensus) = consensus_lock.as_ref() {
        match consensus.get_state().await {
            Ok(shared_state) => Ok(Json(
                serde_json::to_value(shared_state)
                    .unwrap_or(json!({"error": "Serialization failed"})),
            )),
            Err(e) => Err(ApiError::Internal(format!(
                "Failed to get shared state: {}",
                e
            ))),
        }
    } else {
        Err(ApiError::NotFound("Consensus not initialized".into()))
    }
}

pub async fn api_consensus_propose(
    State(state): State<AppState>,
    Json(proposal): Json<Proposal>,
) -> ApiResult<serde_json::Value> {
    let swarm = &state.swarm_manager;
    let consensus_lock = swarm.consensus.read().await;

    if let Some(consensus) = consensus_lock.as_ref() {
        match consensus.propose(proposal).await {
            Ok(_) => Ok(Json(
                json!({"success": true, "message": "Proposal submitted"}),
            )),
            Err(e) => Err(ApiError::Internal(format!("Proposal failed: {}", e))),
        }
    } else {
        Err(ApiError::NotFound("Consensus not initialized".into()))
    }
}

pub async fn api_wolf_pack_state(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let swarm_manager = &state.swarm_manager;
    let wolf_state = swarm_manager
        .get_wolf_state()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let state_read = wolf_state.read().await;

    // Get active hunts
    let active_hunts = swarm_manager.get_active_hunts().await.unwrap_or_default();

    // Get peer list
    let peers = swarm_manager.list_peers().await.unwrap_or_default();

    // Build comprehensive response
    let leader_id = state_read.leader_id.clone();

    let response = serde_json::json!({
        "role": state_read.role,
        "prestige": state_read.prestige,
        "peer_id": swarm_manager.local_peer_id.to_string(),
        "election_term": state_read.election_term,
        "election_state": state_read.election_state,
        "leader_id": leader_id,
        "active_hunts": active_hunts.iter().map(|hunt| {
            serde_json::json!({
                "hunt_id": hunt.hunt_id,
                "target_ip": hunt.target_ip,
                "status": format!("{:?}", hunt.status),
                "phase": match hunt.status {
                    HuntStatus::Scent => "Warning",
                    HuntStatus::Stalk => "Verified",
                    HuntStatus::Strike => "Hunt",
                    HuntStatus::Feast => "Complete",
                    HuntStatus::Failed => "Failed",
                },
                "participants": hunt.participants.len(),
                "evidence_count": hunt.evidence.len(),
                "start_time": hunt.start_time.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs(),
            })
        }).collect::<Vec<_>>(),
        "peers": peers.iter().map(|peer| {
            let pid = peer.entity_id.peer_id.to_string();
            let role = if let Some(lid) = &leader_id {
                if lid == &pid { "Alpha" } else { "Scout" }
            } else {
                "Scout"
            };

            serde_json::json!({
                "id": pid,
                "role": role,
                "trust_score": peer.trust_score,
                "status": format!("{:?}", peer.status),
            })
        }).collect::<Vec<_>>(),
        "total_hunts_neutralized": 0, // TODO: Track this in state
        "territories": state_read.territories,
    });

    Ok(Json(response))
}

// =========================================================================================
// OMEGA CONTROL DOMINANCE API
// =========================================================================================

#[derive(Serialize)]
pub struct UserRoleResponse {
    pub role: WolfRole,
}

pub async fn api_omega_user_role(user: AuthenticatedUser) -> Json<UserRoleResponse> {
    Json(UserRoleResponse { role: user.role })
}

#[derive(Deserialize)]
pub struct ForceRankRequest {
    pub target: String,
    pub role: String, // Parse manually to convert between WolfRole types
}

pub async fn api_omega_force_rank(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(payload): Json<ForceRankRequest>,
) -> impl IntoResponse {
    if user.role != WolfRole::Omega {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "ACCESS DENIED: Omega Clearance Required"})),
        )
            .into_response();
    }

    let target_peer = wolf_net::PeerId::from_string(payload.target);

    // Parse WolfRole from string to convert between types
    let role = match payload.role.as_str() {
        "Stray" => wolf_net::wolf_pack::WolfRole::Stray,
        "Scout" => wolf_net::wolf_pack::WolfRole::Scout,
        "Hunter" => wolf_net::wolf_pack::WolfRole::Hunter,
        "Beta" => wolf_net::wolf_pack::WolfRole::Beta,
        "Alpha" => wolf_net::wolf_pack::WolfRole::Alpha,
        "Omega" => wolf_net::wolf_pack::WolfRole::Omega,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid role"})),
            )
                .into_response()
        }
    };

    let cmd = SwarmCommand::OmegaForceRank {
        target: target_peer,
        role,
    };

    if let Err(e) = state.swarm_manager.command_sender().send(cmd).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Swarm Command Failed: {}", e)})),
        )
            .into_response();
    }

    (StatusCode::OK, Json(json!({"success": true}))).into_response()
}

#[derive(Deserialize)]
pub struct ForcePrestigeRequest {
    pub target: String,
    pub change: i32,
}

pub async fn api_omega_force_prestige(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(payload): Json<ForcePrestigeRequest>,
) -> impl IntoResponse {
    if user.role != WolfRole::Omega {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "ACCESS DENIED: Omega Clearance Required"})),
        )
            .into_response();
    }

    let target_peer = wolf_net::PeerId::from_string(payload.target);

    let cmd = SwarmCommand::OmegaForcePrestige {
        target: target_peer,
        change: payload.change,
    };

    if let Err(e) = state.swarm_manager.command_sender().send(cmd).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("Swarm Command Failed: {}", e)})),
        )
            .into_response();
    }

    (StatusCode::OK, Json(json!({"success": true}))).into_response()
}
// Query parameters for hunts
#[derive(Deserialize)]
pub struct HuntQuery {
    pub id: Option<String>,
}

pub async fn api_wolf_pack_hunts(
    State(state): State<AppState>,
    Query(params): Query<HuntQuery>,
) -> ApiResult<serde_json::Value> {
    let swarm_manager = &state.swarm_manager;
    let active_hunts = swarm_manager
        .get_active_hunts()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Filter by ID if provided
    let filtered_hunts: Vec<_> = if let Some(id) = params.id {
        active_hunts
            .into_iter()
            .filter(|h| h.hunt_id == id)
            .collect()
    } else {
        active_hunts
    };

    let hunts_json = filtered_hunts
        .iter()
        .map(|hunt| {
            serde_json::json!({
                "hunt_id": hunt.hunt_id,
                "target_ip": hunt.target_ip,
                "status": format!("{:?}", hunt.status),
                "phase": match hunt.status {
                    HuntStatus::Scent => "Scent",
                    HuntStatus::Stalk => "Stalk",
                    HuntStatus::Strike => "Strike",
                    HuntStatus::Feast => "Feast",
                    HuntStatus::Failed => "Failed",
                },
                "participants": hunt.participants.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                "evidence": hunt.evidence,
                "start_time": hunt.start_time.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs(),
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(serde_json::json!({
        "hunts": hunts_json,
        "count": filtered_hunts.len(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })))
}

/// API: Initiate a new hunt
#[derive(Deserialize)]
pub struct InitiateHuntRequest {
    pub target_ip: String,
    pub evidence: String,
}

pub async fn api_wolf_pack_initiate_hunt(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(payload): Json<InitiateHuntRequest>,
) -> ApiResult<serde_json::Value> {
    // Authorization Check
    if user.role != WolfRole::Omega && user.role != WolfRole::Alpha && user.role != WolfRole::Gamma
    {
        return Err(ApiError::Forbidden(
            "Insufficient rank to initiate hunts".into(),
        ));
    }

    let swarm_manager = &state.swarm_manager;

    // Initiate the hunt
    let sender = state.swarm_manager.hunt_coordinator_sender();
    let hunt_id = format!("hunt-{}-{}", payload.target_ip, Uuid::new_v4());

    // Send HuntRequest directly to coordinator
    sender
        .send(
            wolf_net::wolf_pack::coordinator::CoordinatorMsg::HuntRequest {
                hunt_id: hunt_id.clone(),
                source: state.swarm_manager.local_peer_id.clone(),
                target_ip: payload.target_ip.clone(),
                min_role: NetWolfRole::Hunter,
            },
        )
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to send hunt request: {}", e)))?;

    info!(
        "🎯 Hunt initiated via API: {} for target {}",
        hunt_id, payload.target_ip
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "hunt_id": hunt_id,
        "target_ip": payload.target_ip,
        "message": "Hunt initiated successfully",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })))
}

// Query parameters for peers
#[derive(Deserialize)]
pub struct PeerQuery {
    pub id: Option<String>,
}

/// API: Get pack members/peers
pub async fn api_wolf_pack_peers(
    State(state): State<AppState>,
    Query(params): Query<PeerQuery>,
) -> ApiResult<serde_json::Value> {
    let swarm_manager = &state.swarm_manager;
    let peers = swarm_manager
        .list_peers()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Filter by ID
    let filtered_peers: Vec<_> = if let Some(id) = params.id {
        peers
            .clone()
            .into_iter()
            .filter(|p| p.entity_id.peer_id.to_string() == id)
            .collect()
    } else {
        peers.clone()
    };

    let peers_json = filtered_peers
        .iter()
        .map(|peer| {
            serde_json::json!({
                "id": peer.entity_id.peer_id.to_string(),
                "role": "scout", // TODO: Get actual role from WolfPack member data
                "trust_score": peer.trust_score,
                "status": format!("{:?}", peer.status),
                "last_seen": peer.last_seen.to_rfc3339(),
                "latency_ms": peer.metrics.latency_ms,
                "health_score": peer.metrics.health_score,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(serde_json::json!({
        "peers": peers_json,
        "count": peers.len(),
        "local_peer_id": swarm_manager.local_peer_id.to_string(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })))
}

// =========================================================================================
// HOWL COMMUNICATION API
// =========================================================================================

#[derive(Deserialize)]
pub struct SendHowlRequest {
    pub priority: String,     // "Info", "Warning", "Alert"
    pub payload_type: String, // "WarningHowl", "KillOrder", "TerritoryUpdate"

    // Payload Fields (Optional depending on type)
    pub target_ip: Option<String>,
    pub evidence: Option<String>,
    pub reason: Option<String>,
    pub region: Option<String>,
    pub status: Option<String>,
    pub hunt_id: Option<String>,
}

pub async fn api_howl_broadcast(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<SendHowlRequest>,
) -> ApiResult<serde_json::Value> {
    let priority = match req.priority.as_str() {
        "Alert" => wolf_net::wolf_pack::howl::HowlPriority::Alert,
        "Warning" => wolf_net::wolf_pack::howl::HowlPriority::Warning,
        _ => wolf_net::wolf_pack::howl::HowlPriority::Info,
    };

    // Role Validation for High Priority
    // Role Validation for High Priority
    if priority == wolf_net::wolf_pack::howl::HowlPriority::Alert && user.role > WolfRole::Alpha {
        return Err(ApiError::Forbidden(
            "Only Alpha can send Alert priority Howls".into(),
        ));
    }

    // Construct Payload
    let payload = match req.payload_type.as_str() {
        "WarningHowl" => wolf_net::wolf_pack::howl::HowlPayload::WarningHowl {
            target_ip: req
                .target_ip
                .ok_or(ApiError::BadRequest("Missing target_ip".into()))?,
            evidence: req.evidence.unwrap_or_default(),
        },
        "KillOrder" => {
            if user.role > WolfRole::Alpha {
                return Err(ApiError::Forbidden(
                    "Only Alpha can issue Kill Orders".into(),
                ));
            }
            wolf_net::wolf_pack::howl::HowlPayload::KillOrder {
                target_ip: req
                    .target_ip
                    .ok_or(ApiError::BadRequest("Missing target_ip".into()))?,
                reason: req.reason.unwrap_or_default(),
                hunt_id: req.hunt_id.unwrap_or_else(|| "manual".into()),
            }
        }
        "TerritoryUpdate" => wolf_net::wolf_pack::howl::HowlPayload::TerritoryUpdate {
            region_cidr: req
                .region
                .ok_or(ApiError::BadRequest("Missing region".into()))?,
            owner: state.swarm_manager.local_peer_id.clone(), // Fix 1: Clone
            status: req.status.unwrap_or("Patrolling".into()),
        },
        _ => {
            return Err(ApiError::BadRequest(
                "Unknown or unsupported payload type".into(),
            ))
        }
    };

    // Create Message
    let msg = wolf_net::wolf_pack::howl::HowlMessage::new(
        state.swarm_manager.local_peer_id.clone(), // Fix 2: Clone
        priority,
        payload,
    );

    // Send to Swarm
    let cmd = SwarmCommand::BroadcastHowl { message: msg };
    if let Err(e) = state.swarm_manager.command_sender().send(cmd).await {
        return Err(ApiError::Internal(format!(
            "Failed to broadcast Howl: {}",
            e
        )));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Howl broadcasted successfully"
    })))
}
