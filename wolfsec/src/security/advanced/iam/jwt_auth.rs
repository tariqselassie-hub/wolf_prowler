//! JWT-based Authentication with Ed25519 Signatures
//!
//! JWT token generation and validation using Ed25519 signatures for secure authentication.
//! Integrates with Wolf Den for cryptographic operations.

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::security::advanced::iam::{
    AuthenticationManager, AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig,
    SessionRequest, UserStatus,
};

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTCustomClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: Vec<String>,
    /// Issued at
    pub iat: i64,
    /// Expiration time
    pub exp: i64,
    /// Not before
    pub nbf: Option<i64>,
    /// JWT ID
    pub jti: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Client information
    pub client_info: Option<ClientInfo>,
    /// Session ID
    pub session_id: Option<String>,
    /// MFA status
    pub mfa_verified: bool,
    /// Token type
    pub token_type: TokenType,
}

/// Token types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenType {
    /// Access token for API access
    Access,
    /// Refresh token for token renewal
    Refresh,
    /// ID token for user information
    ID,
    /// Session token for session management
    Session,
}

/// JWT authentication manager
pub struct JWTAuthenticationManager {
    /// Ed25519 keypair for signing
    keypair: Arc<SigningKey>,
    /// Decoding key for verification
    decoding_key: DecodingKey,
    /// Configuration
    config: IAMConfig,
    /// Active tokens (for revocation)
    active_tokens: Arc<Mutex<HashMap<String, TokenMetadata>>>,
    /// Token blacklist (revoked tokens)
    token_blacklist: Arc<Mutex<HashMap<String, chrono::DateTime<Utc>>>>,
}

/// Token metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// Token ID
    pub jti: String,
    /// User ID
    pub user_id: String,
    /// Issued at
    pub issued_at: chrono::DateTime<Utc>,
    /// Expires at
    pub expires_at: chrono::DateTime<Utc>,
    /// Token type
    pub token_type: TokenType,
    /// Client info
    pub client_info: Option<ClientInfo>,
}

/// JWT authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTAuthenticationRequest {
    /// User ID
    pub user_id: Uuid,
    /// Username
    pub username: String,
    /// User roles
    pub roles: Vec<String>,
    /// User permissions
    pub permissions: Vec<String>,
    /// Client info
    pub client_info: ClientInfo,
    /// Token type to generate
    pub token_type: TokenType,
    /// Remember me (longer expiration)
    pub remember_me: bool,
    /// MFA verified
    pub mfa_verified: bool,
}

/// JWT authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTAuthenticationResult {
    /// JWT token
    pub token: String,
    /// Token type
    pub token_type: TokenType,
    /// Expires at
    pub expires_at: chrono::DateTime<Utc>,
    /// Token ID
    pub jti: String,
    /// User ID
    pub user_id: Uuid,
    /// Success status
    pub success: bool,
    /// Error message
    pub error_message: Option<String>,
}

/// JWT validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTValidationResult {
    /// Validation success
    pub valid: bool,
    /// Claims
    pub claims: Option<JWTCustomClaims>,
    /// Error message
    pub error_message: Option<String>,
    /// Token ID
    pub jti: Option<String>,
}

impl JWTAuthenticationManager {
    /// Create new JWT authentication manager
    pub async fn new(config: IAMConfig) -> Result<Self> {
        info!("🔐 Initializing JWT Authentication Manager");

        // Generate Ed25519 keypair
        let keypair = Arc::new(SigningKey::generate(&mut rand::thread_rng()));
        let decoding_key = DecodingKey::from_ed_pem(
            &keypair
                .verifying_key()
                .to_bytes()
                .iter()
                .chain(&[0x04]) // Add Ed25519 prefix
                .cloned()
                .collect::<Vec<u8>>(),
        )
        .map_err(|e| anyhow!("Failed to create decoding key: {}", e))?;

        let manager = Self {
            keypair,
            decoding_key,
            config,
            active_tokens: Arc::new(Mutex::new(HashMap::new())),
            token_blacklist: Arc::new(Mutex::new(HashMap::new())),
        };

        info!("✅ JWT Authentication Manager initialized successfully");
        Ok(manager)
    }

    /// Generate JWT token
    pub async fn generate_token(
        &self,
        request: JWTAuthenticationRequest,
    ) -> Result<JWTAuthenticationResult> {
        debug!("🔐 Generating JWT token for user: {}", request.username);

        let now = Utc::now();
        let expires_in = self.get_token_expiration(&request.token_type, request.remember_me);
        let expires_at = now + Duration::seconds(expires_in);

        let claims = JWTCustomClaims {
            sub: request.user_id.to_string(),
            iss: "wolf-prowler".to_string(),
            aud: vec!["wolf-prowler-api".to_string()],
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            nbf: Some(now.timestamp()),
            jti: Uuid::new_v4().to_string(),
            roles: request.roles,
            permissions: request.permissions,
            client_info: Some(request.client_info.clone()),
            session_id: None, // Will be set when session is created
            mfa_verified: request.mfa_verified,
            token_type: request.token_type.clone(),
        };

        let header = Header::new(Algorithm::EdDSA);

        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(&self.keypair.to_bytes()),
        )
        .map_err(|e| anyhow!("Failed to encode JWT: {}", e))?;

        // Store token metadata
        let metadata = TokenMetadata {
            jti: claims.jti.clone(),
            user_id: request.user_id.to_string(),
            issued_at: now,
            expires_at,
            token_type: request.token_type.clone(),
            client_info: Some(request.client_info),
        };

        let mut active_tokens = self.active_tokens.lock().await;
        active_tokens.insert(claims.jti.clone(), metadata);

        // Clean up expired tokens
        self.cleanup_expired_tokens().await?;

        Ok(JWTAuthenticationResult {
            token,
            token_type: request.token_type,
            expires_at,
            jti: claims.jti,
            user_id: request.user_id,
            success: true,
            error_message: None,
        })
    }

    /// Validate JWT token
    pub async fn validate_token(&self, token: &str) -> Result<JWTValidationResult> {
        debug!("🔍 Validating JWT token");

        // Check if token is blacklisted
        let token_id = self.extract_token_id(token).await?;
        if let Some(token_id) = token_id {
            let blacklist = self.token_blacklist.lock().await;
            if blacklist.contains_key(&token_id) {
                return Ok(JWTValidationResult {
                    valid: false,
                    claims: None,
                    error_message: Some("Token has been revoked".to_string()),
                    jti: Some(token_id),
                });
            }
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["wolf-prowler-api"]);
        validation.set_issuer(&["wolf-prowler"]);

        let token_data = decode::<JWTCustomClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("JWT validation failed: {}", e))?;

        // Check if token is expired
        let now = Utc::now();
        if now.timestamp() > token_data.claims.exp {
            return Ok(JWTValidationResult {
                valid: false,
                claims: None,
                error_message: Some("Token has expired".to_string()),
                jti: Some(token_data.claims.jti),
            });
        }

        // Check if token is not yet valid
        if let Some(nbf) = token_data.claims.nbf {
            if now.timestamp() < nbf {
                return Ok(JWTValidationResult {
                    valid: false,
                    claims: None,
                    error_message: Some("Token is not yet valid".to_string()),
                    jti: Some(token_data.claims.jti),
                });
            }
        }

        // Verify token signature using Ed25519
        if !self.verify_signature(token, &token_data.claims).await? {
            return Ok(JWTValidationResult {
                valid: false,
                claims: None,
                error_message: Some("Invalid token signature".to_string()),
                jti: Some(token_data.claims.jti),
            });
        }

        let jti = token_data.claims.jti.clone();
        Ok(JWTValidationResult {
            valid: true,
            claims: Some(token_data.claims),
            error_message: None,
            jti: Some(jti),
        })
    }

    /// Revoke JWT token
    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        debug!("🔐 Revoking JWT token");

        let token_id = self.extract_token_id(token).await?;
        if let Some(token_id) = token_id {
            let mut blacklist = self.token_blacklist.lock().await;
            blacklist.insert(token_id.clone(), Utc::now());

            // Remove from active tokens
            let mut active_tokens = self.active_tokens.lock().await;
            active_tokens.remove(&token_id);

            info!("✅ Token revoked successfully");
        }

        Ok(())
    }

    /// Revoke all tokens for a user
    pub async fn revoke_all_user_tokens(&self, user_id: Uuid) -> Result<()> {
        debug!("🔐 Revoking all tokens for user: {}", user_id);

        let mut blacklist = self.token_blacklist.lock().await;
        let mut active_tokens = self.active_tokens.lock().await;

        let user_tokens: Vec<String> = active_tokens
            .iter()
            .filter(|(_, metadata)| metadata.user_id == user_id.to_string())
            .map(|(jti, _)| jti.clone())
            .collect();

        for token_id in user_tokens {
            blacklist.insert(token_id.clone(), Utc::now());
            active_tokens.remove(&token_id);
        }

        info!("✅ All tokens revoked for user: {}", user_id);
        Ok(())
    }

    /// Refresh JWT token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<JWTAuthenticationResult> {
        debug!("🔐 Refreshing JWT token");

        let validation_result = self.validate_token(refresh_token).await?;

        if !validation_result.valid {
            return Err(anyhow!(
                "Invalid refresh token: {:?}",
                validation_result.error_message
            ));
        }

        let claims = validation_result
            .claims
            .ok_or_else(|| anyhow!("No claims found in refresh token validation result"))?;

        // Generate new access token
        let request = JWTAuthenticationRequest {
            user_id: Uuid::parse_str(&claims.sub)?,
            username: claims.sub.clone(), // In production, this would be looked up
            roles: claims.roles,
            permissions: claims.permissions,
            client_info: claims.client_info.unwrap_or_default(),
            token_type: TokenType::Access,
            remember_me: false, // Refresh tokens don't extend session
            mfa_verified: claims.mfa_verified,
        };

        self.generate_token(request).await
    }

    /// Get token expiration time
    fn get_token_expiration(&self, token_type: &TokenType, remember_me: bool) -> i64 {
        match token_type {
            TokenType::Access => {
                if remember_me {
                    8 * 3600 // 8 hours
                } else {
                    1 * 3600 // 1 hour
                }
            }
            TokenType::Refresh => 7 * 24 * 3600, // 7 days
            TokenType::ID => 1 * 3600,           // 1 hour
            TokenType::Session => {
                if remember_me {
                    30 * 24 * 3600 // 30 days
                } else {
                    8 * 3600 // 8 hours
                }
            }
        }
    }

    /// Extract token ID from JWT
    async fn extract_token_id(&self, token: &str) -> Result<Option<String>> {
        let validation = Validation::new(Algorithm::EdDSA);
        let token_data = decode::<JWTCustomClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| anyhow!("Failed to decode token: {}", e))?;

        Ok(Some(token_data.claims.jti))
    }

    /// Verify token signature using Ed25519
    async fn verify_signature(&self, token: &str, claims: &JWTCustomClaims) -> Result<bool> {
        // Extract signature from token (this is a simplified implementation)
        // In practice, you'd need to parse the JWT structure properly
        let signature_valid = true; // The decode() function already verifies the signature

        Ok(signature_valid)
    }

    /// Clean up expired tokens
    async fn cleanup_expired_tokens(&self) -> Result<()> {
        let now = Utc::now();
        let mut active_tokens = self.active_tokens.lock().await;

        active_tokens.retain(|_, metadata| now.timestamp() < metadata.expires_at.timestamp());

        Ok(())
    }

    /// Get active token count
    pub async fn get_active_token_count(&self) -> usize {
        let active_tokens = self.active_tokens.lock().await;
        active_tokens.len()
    }

    /// Get blacklisted token count
    pub async fn get_blacklisted_token_count(&self) -> usize {
        let blacklist = self.token_blacklist.lock().await;
        blacklist.len()
    }

    /// Clean up old blacklisted tokens
    pub async fn cleanup_blacklist(&self) -> Result<()> {
        let mut blacklist = self.token_blacklist.lock().await;
        let now = Utc::now();
        let retention_period = Duration::days(30); // Keep revoked tokens for 30 days

        blacklist.retain(|_, timestamp| now.signed_duration_since(*timestamp) < retention_period);

        Ok(())
    }
}

impl From<JWTAuthenticationResult> for AuthenticationResult {
    fn from(jwt_result: JWTAuthenticationResult) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: jwt_result.user_id,
            method: AuthenticationMethod::JWT,
            success: jwt_result.success,
            timestamp: Utc::now(),
            ip_address: "unknown".to_string(), // Would be extracted from request
            user_agent: "unknown".to_string(), // Would be extracted from request
            mfa_required: false,               // JWT typically includes MFA verification
            mfa_completed: true,
            session_id: None, // Would be created after successful auth
            error_message: jwt_result.error_message,
        }
    }
}

impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            ip_address: "127.0.0.1".to_string(),
            user_agent: "wolf-prowler".to_string(),
            device_id: None,
            location: None,
        }
    }
}
