// Append to src/dashboard/api.rs

use crate::core::security_policy::{SecurityPolicy, SecurityStance};

/// Request to change security level
#[derive(Deserialize)]
pub struct SecurityLevelRequest {
    pub stance: SecurityStance,
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
) -> Json<SecurityPolicyResponse> {
    let policy = state.security_policy.read().await;
    Json(SecurityPolicyResponse::from(&*policy))
}

/// API: Change security policy
pub async fn api_security_policy_set(
    State(state): State<AppState>,
    Json(req): Json<SecurityLevelRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Create new policy from requested stance
    let new_policy = SecurityPolicy::from_stance(req.stance);

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
pub async fn api_security_stances() -> Json<serde_json::Value> {
    Json(json!({
        "stances": [
            {
                "value": "low",
                "name": "Low Security",
                "description": "For testing and development. 128-bit keys, 2-hour sessions, lenient threat detection.",
                "key_size": 128,
                "session_timeout": 7200,
                "recommended_for": "Development environments"
            },
            {
                "value": "medium",
                "name": "Medium Security",
                "description": "Recommended for production. 192-bit keys, 1-hour sessions, balanced threat detection.",
                "key_size": 192,
                "session_timeout": 3600,
                "recommended_for": "Production environments"
            },
            {
                "value": "high",
                "name": "High Security",
                "description": "Maximum protection. 256-bit keys, 30-minute sessions, aggressive threat detection.",
                "key_size": 256,
                "session_timeout": 1800,
                "recommended_for": "High-security environments"
            }
        ]
    }))
}
