use crate::core::security_policy::{SecurityPolicy, SecurityStance};
use crate::core::settings::WolfRole;
use crate::dashboard::api::OmegaUser;
use crate::dashboard::state::AppState;
use crate::utils::metrics_simple::SystemEvent;
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use chrono::Utc;
use hex;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use tower_cookies::cookie::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;

const AUTH_COOKIE_NAME: &str = "wolf_prowler_auth";

pub async fn root_handler(jar: CookieJar) -> Html<&'static str> {
    if jar.get(AUTH_COOKIE_NAME).is_some() {
        Html(include_str!("../../wolf_web/static/navigation_hub.html"))
    } else {
        Html(include_str!("../../wolf_web/static/auth_enhanced.html"))
    }
}

pub async fn security_dashboard_handler() -> Html<&'static str> {
    Html(include_str!(
        "../../wolf_web/static/security_dashboard.html"
    ))
}

pub async fn dashboard_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/dashboard_modern.html"))
}

pub async fn cloud_security_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/cloud_security.html"))
}

pub async fn nav_hub_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/navigation_hub.html"))
}

pub async fn timezone_settings_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/timezone_settings.html"))
}

pub async fn scent_trails_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/scent_trails.html"))
}

pub async fn lunar_calendar_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/lunar_calendar.html"))
}

pub async fn territory_marking_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/territory_marking.html"))
}

pub async fn network_map_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/network_map.html"))
}

pub async fn threat_detection_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/threat_detection.html"))
}

pub async fn crypto_handler() -> Html<&'static str> {
    Html(include_str!(
        "../../wolf_web/static/crypto_advanced_v2.html"
    ))
}

pub async fn settings_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/settings.html"))
}

pub async fn logs_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/logs.html"))
}

pub async fn monitoring_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/monitoring.html"))
}

pub async fn p2p_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/p2p.html"))
}

pub async fn packs_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/packs.html"))
}

pub async fn howl_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/howl.html"))
}

pub async fn network_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/network.html"))
}

pub async fn security_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/security.html"))
}

pub async fn compliance_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/compliance.html"))
}

pub async fn neural_center_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/neural_center.html"))
}

pub async fn consensus_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/consensus.html"))
}

pub async fn security_policy_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/security_policy.html"))
}

pub async fn hub_organizations_handler() -> Html<&'static str> {
    Html(include_str!("../../wolf_web/static/hub_organizations.html"))
}

/// Handles user logout by clearing the session cookie.
pub async fn logout_handler(jar: CookieJar, headers: HeaderMap) -> (CookieJar, Response) {
    let mut cookie = Cookie::new(AUTH_COOKIE_NAME, "");
    cookie.set_path("/");
    let jar = jar.remove(cookie);
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if accept.contains("application/json") {
        (
            jar,
            axum::Json(json!({"status": "success", "message": "Logged out"})).into_response(),
        )
    } else {
        (jar, Redirect::to("/").into_response())
    }
}

#[derive(Deserialize)]
pub struct LoginPayload {
    pub password: String,
    #[serde(default)]
    pub remember_me: bool,
}

/// Handles login form submission.
pub async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(payload): Form<LoginPayload>,
) -> (CookieJar, Response) {
    let config = state.config.read().await;
    let password_bytes = payload.password.as_bytes();
    let admin_password_bytes = config.dashboard.admin_password.as_bytes();

    // Use constant-time comparison to prevent timing attacks.
    let passwords_match = state
        .crypto
        .secure_compare(password_bytes, admin_password_bytes);

    if passwords_match {
        info!("Successful login");

        // Generate a secure session token
        let session_token = match state.crypto.generate_key(32) {
            Ok(token) => hex::encode(token),
            Err(_) => {
                error!("Failed to generate session token");
                return (jar, StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };

        // Generate a secure session token with role information
        let user_role = config.dashboard.admin_role.clone();
        let session_data = format!("{}:{}", session_token, user_role);

        // Create a secure cookie with role data
        let mut cookie = Cookie::new(AUTH_COOKIE_NAME, session_data);
        cookie.set_http_only(true);
        cookie.set_secure(true); // Only send over HTTPS
        cookie.set_path("/");

        // Sign the cookie value using the crypto engine
        if let Ok(mac) = state.crypto.compute_mac(cookie.value().as_bytes()).await {
            let signed_value = format!("{}.{}", cookie.value(), hex::encode(mac));
            let mut secure_cookie = Cookie::new(AUTH_COOKIE_NAME, signed_value);
            secure_cookie.set_http_only(true);
            secure_cookie.set_secure(true);
            secure_cookie.set_path("/");
            if payload.remember_me {
                secure_cookie.set_max_age(Some(Duration::days(30)));
            }

            // Check for JSON preference (e.g. from TUI/API clients)
            let accept = headers
                .get("accept")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if accept.contains("application/json") {
                let body = json!({
                    "status": "success",
                    "message": "Login successful",
                    "role": user_role.to_string(),
                });
                (jar.add(secure_cookie), axum::Json(body).into_response())
            } else {
                (jar.add(secure_cookie), Redirect::to("/nav").into_response())
            }
        } else {
            error!("Failed to sign session cookie");
            (jar, StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    } else {
        warn!("Failed login attempt");
        let accept = headers
            .get("accept")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if accept.contains("application/json") {
            (
                jar,
                (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(json!({"status": "error", "message": "Invalid credentials"})),
                )
                    .into_response(),
            )
        } else {
            (jar, StatusCode::UNAUTHORIZED.into_response())
        }
    }
}

/// Triggers a network-wide lockdown. A high-privilege Omega-only action.
#[axum::debug_handler]
pub async fn api_system_panic(
    State(state): State<AppState>,
    _user: OmegaUser,
) -> impl IntoResponse {
    info!("🚨 OMEGA ACTION: System-wide panic initiated.");

    // 2. Set security policy to most restrictive
    {
        let mut policy = state.security_policy.write().await;
        *policy = SecurityPolicy::from_stance(SecurityStance::Paranoid);
        info!("🔒 Security policy set to PARANOID.");
    }

    // 3. Broadcast lockdown event via WebSocket
    let broadcast_payload = json!({
        "type": "lockdown_activated",
        "data": {
            "message": "SYSTEM-WIDE LOCKDOWN INITIATED. ALL NON-ESSENTIAL CONNECTIONS TERMINATED.",
            "activated_at": Utc::now().to_rfc3339(),
        }
    });
    if state
        .broadcast_tx
        .send(broadcast_payload.to_string())
        .is_err()
    {
        warn!("Failed to broadcast lockdown event to WebSocket clients.");
    }

    // 4. Log a critical security event
    let event = SystemEvent {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type: "system_lockdown".to_string(),
        message: "Omega user triggered a system-wide panic lockdown.".to_string(),
        severity: "critical".to_string(),
        source: "omega_control".to_string(),
        user_id: None,
        ip_address: None,
        metadata: HashMap::new(),
        correlation_id: None,
    };
    state.security_events.write().await.push(event);

    (
        StatusCode::OK,
        Json(json!({"success": true, "message": "System lockdown initiated."})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::settings::AppSettings;
    use crate::dashboard::state::SystemMetricsData;
    use crate::dashboard::state::{AppStateInner, HowlService, ThreatService, VaultService};
    use crate::utils::metrics_simple::MetricsCollector;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{broadcast, RwLock};
    use wolf_den::CryptoEngine;
    use wolf_net::SwarmManager;
    use wolfsec::WolfSecurity;

    // Helper to create a minimal AppState for testing using Builder pattern
    struct TestStateBuilder {
        config: AppSettings,
    }

    impl TestStateBuilder {
        fn new() -> Self {
            Self {
                config: AppSettings::default(),
            }
        }

        #[allow(dead_code)]
        fn with_config(mut self, config: AppSettings) -> Self {
            self.config = config;
            self
        }

        async fn build(self) -> AppState {
            let config = self.config;
            let crypto = Arc::new(CryptoEngine::new(wolf_den::SecurityLevel::Standard).unwrap());
            let (broadcast_tx, _) = broadcast::channel(10);
            let settings_arc = Arc::new(RwLock::new(config.clone()));

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
                swarm_manager: swarm_manager.clone(),
            });

            let vault_service = Arc::new(VaultService {
                vault: Arc::new(RwLock::new(Vec::new())),
                unlocked_key: Arc::new(RwLock::new(None)),
                crypto: crypto.clone(),
                config: Arc::new(RwLock::new(config.clone())),
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
                    settings_arc.clone(),
                    Some(config.ai.model_name.clone()),
                )),
                #[cfg(feature = "advanced_reporting")]
                db_pool: None,
                persistence: None,
            };

            AppState::new(inner)
        }
    }

    #[tokio::test]
    async fn test_root_handler_serves_login_without_cookie() {
        let jar = CookieJar::new();
        let response = root_handler(jar).await;
        assert_eq!(
            response.0,
            include_str!("../../wolf_web/static/auth_enhanced.html")
        );
    }

    #[tokio::test]
    async fn test_root_handler_serves_dashboard_with_cookie() {
        let jar = CookieJar::new().add(Cookie::new(AUTH_COOKIE_NAME, "valid_session"));
        let response = root_handler(jar).await;
        assert_eq!(
            response.0,
            include_str!("../../wolf_web/static/navigation_hub.html")
        );
    }

    #[tokio::test]
    async fn test_login_handler_success() {
        let state = TestStateBuilder::new().build().await;
        let jar = CookieJar::new();

        // Use the default admin password from Config::default()
        // Assuming default config has a known password, or we can check what it is.
        // Usually Config::default() sets admin_password to "admin" or similar for dev.
        // Let's check the config in state.
        let admin_password = state.config.read().await.dashboard.admin_password.clone();

        let payload = LoginPayload {
            password: admin_password,
            remember_me: false,
        };
        let headers = axum::http::HeaderMap::new();

        let (updated_jar, response) =
            login_handler(State(state), jar, headers, Form(payload)).await;

        // Verify cookie was set
        let cookie = updated_jar.get(AUTH_COOKIE_NAME);
        assert!(
            cookie.is_some(),
            "Auth cookie should be set on successful login"
        );

        // Verify response is a redirect
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get("location").unwrap(), "/nav");
    }

    #[tokio::test]
    async fn test_login_handler_failure() {
        let state = TestStateBuilder::new().build().await;
        let jar = CookieJar::new();

        let payload = LoginPayload {
            password: "wrong_password".to_string(),
            remember_me: false,
        };
        let headers = axum::http::HeaderMap::new();

        let (updated_jar, response) =
            login_handler(State(state), jar, headers, Form(payload)).await;

        // Verify cookie was NOT set
        let cookie = updated_jar.get(AUTH_COOKIE_NAME);
        assert!(
            cookie.is_none(),
            "Auth cookie should not be set on failed login"
        );

        // Verify response is Unauthorized
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_security_dashboard_handler_serves_correct_file() {
        let response = security_dashboard_handler().await;
        assert_eq!(
            response.0,
            include_str!("../../wolf_web/static/security_dashboard.html")
        );
    }

    #[tokio::test]
    async fn test_network_map_handler_serves_correct_file() {
        let response = network_map_handler().await;
        assert_eq!(
            response.0,
            include_str!("../../wolf_web/static/network_map.html")
        );
    }

    #[tokio::test]
    async fn test_threat_detection_handler_serves_correct_file() {
        let response = threat_detection_handler().await;
        assert_eq!(
            response.0,
            include_str!("../../wolf_web/static/threat_detection.html")
        );
    }

    #[tokio::test]
    async fn test_logout_handler() {
        let jar = CookieJar::new().add(Cookie::new(AUTH_COOKIE_NAME, "valid_session"));
        let headers = axum::http::HeaderMap::new();

        let (updated_jar, response) = logout_handler(jar, headers).await;

        // Verify cookie was removed (value should be empty or None)
        let cookie_value = updated_jar.get(AUTH_COOKIE_NAME).map(|c| c.value()).unwrap_or("");
        assert_eq!(cookie_value, "");

        // Verify redirect (default behavior without JSON header)
        let response = response.into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
}
