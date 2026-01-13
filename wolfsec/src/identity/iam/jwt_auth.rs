//! JWT-based Authentication with Ed25519 Signatures
//!
//! JWT token generation and validation using Ed25519 signatures for secure authentication.
//! Integrates with Wolf Den for cryptographic operations.

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;

use crate::identity::iam::{
    AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig,
};

/// Standardized JWT claims specifically tailored for the Wolf Prowler ecosystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTCustomClaims {
    /// Subject (Principal identifier, usually a serialized [Uuid])
    pub sub: String,
    /// Issuer (The authority that generated the token)
    pub iss: String,
    /// Audience (Service identifiers expected to consume this token)
    pub aud: Vec<String>,
    /// Issued at (Seconds since Unix epoch)
    pub iat: i64,
    /// Expiration time (Seconds since Unix epoch)
    pub exp: i64,
    /// Not valid before (Optional seconds since Unix epoch)
    pub nbf: Option<i64>,
    /// Unique identifier for this specific token instance
    pub jti: String,
    /// High-level roles assigned to the subject
    pub roles: Vec<String>,
    /// Detailed fine-grained permissions for the subject
    pub permissions: Vec<String>,
    /// Environmental and device information of the requester at issuance
    pub client_info: Option<ClientInfo>,
    /// Associated session identifier, if applicable
    pub session_id: Option<String>,
    /// True if identity was confirmed with a secondary factor
    pub mfa_verified: bool,
    /// Classification of the token according to [TokenType]
    pub token_type: TokenType,
}

/// Categorization of tokens based on their intended use case
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenType {
    /// Proof of identity for calling protected APIs
    Access,
    /// Long-lived token used to obtain a new Access token
    Refresh,
    /// OpenID Connect compliant identity information container
    ID,
    /// Proof of an active, server-side tracked session
    Session,
}

/// Specialized manager for handling the signing, verification, and revocation of JSON Web Tokens
pub struct JWTAuthenticationManager {
    /// Ed25519 signing key used to cryptographically prove token authenticity
    keypair: Arc<SigningKey>,
    /// Compiled public key and validation logic for incoming tokens
    decoding_key: DecodingKey,
    /// Shared global IAM configuration
    config: IAMConfig,
    /// Internal registry of unexpired tokens for revocation purposes
    active_tokens: Arc<Mutex<HashMap<String, TokenMetadata>>>,
    /// Persistent list of token IDs that have been explicitly invalidated
    token_blacklist: Arc<Mutex<HashMap<String, chrono::DateTime<Utc>>>>,
}

/// Non-cryptographic record for tracking issued tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// The unique JWT ID (jti)
    pub jti: String,
    /// Internal identifier for the owner
    pub user_id: String,
    /// Time when the token was successfully signed
    pub issued_at: chrono::DateTime<Utc>,
    /// Time when the token will become naturally invalid
    pub expires_at: chrono::DateTime<Utc>,
    /// Intended usage of the token
    pub token_type: TokenType,
    /// Contextual information captured at issuance
    pub client_info: Option<ClientInfo>,
}

/// Input parameters required to mint a new JWT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTAuthenticationRequest {
    /// Unique internal identifier for the subject
    pub user_id: Uuid,
    /// Human-readable identity for the subject
    pub username: String,
    /// Active roles to be embedded in the token claims
    pub roles: Vec<String>,
    /// Explicit permissions to be embedded in the token claims
    pub permissions: Vec<String>,
    /// Information about the client application requesting issuance
    pub client_info: ClientInfo,
    /// The specific tier or usage of token to generate
    pub token_type: TokenType,
    /// If true, applies extended expiration policies
    pub remember_me: bool,
    /// Indicates if identity was proven via primary and secondary factor
    pub mfa_verified: bool,
}

/// Output returned after a successful JWT generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTAuthenticationResult {
    /// The signed, Base64Url-encoded JWT string
    pub token: String,
    /// The classification of the issued token
    pub token_type: TokenType,
    /// The absolute expiration time calculated for this token
    pub expires_at: chrono::DateTime<Utc>,
    /// The unique JWT ID for auditing and revocation
    pub jti: String,
    /// The internal identifier of the authenticated owner
    pub user_id: Uuid,
    /// Status indicating if issuance completed without error
    pub success: bool,
    /// Descriptive text if generation or signing failed
    pub error_message: Option<String>,
}

/// Detailed feedback from the token parsing and signature verification engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JWTValidationResult {
    /// Status indicating if the token is authenticated and not expired or blacklisted
    pub valid: bool,
    /// Fully parsed claims from a cryptographically verified token
    pub claims: Option<JWTCustomClaims>,
    /// Explanation if the token fails validity or trust checks
    pub error_message: Option<String>,
    /// The unique identifier of the token, even if partially invalid
    pub jti: Option<String>,
}

impl JWTAuthenticationManager {
    /// Initializes the manager, generating a new ephemeral Ed25519 keypair for token signing.
    ///
    /// # Errors
    /// Returns an error if keypair generation or decoding key creation fails.
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

    /// Mints a new JWT with encapsulated identity and permission claims.
    ///
    /// # Errors
    /// Returns an error if encoding fails or internal cleanup fails.
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

    /// Parses a token string, verifies its cryptographic signature, and checks its validity status.
    ///
    /// # Errors
    /// Returns an error if the token is malformed or decoding fails.
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

    /// Explicitly invalidates a token by adding its ID to the blacklist.
    ///
    /// # Errors
    /// Returns an error if token extraction fails.
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

    /// Mass revokes all outstanding tokens associated with a specific user identity.
    ///
    /// # Errors
    /// Returns an error if the mass revocation fails.
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

    /// Consumes a valid Refresh token to issue a new, short-lived Access token.
    ///
    /// # Errors
    /// Returns an error if the refresh token is invalid or issuance fails.
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
    async fn verify_signature(&self, _token: &str, _claims: &JWTCustomClaims) -> Result<bool> {
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

    /// Returns the current count of issued tokens that have not yet expired naturally.
    pub async fn get_active_token_count(&self) -> usize {
        let active_tokens = self.active_tokens.lock().await;
        active_tokens.len()
    }

    /// Returns the current count of token IDs present in the revocation blacklist.
    pub async fn get_blacklisted_token_count(&self) -> usize {
        let blacklist = self.token_blacklist.lock().await;
        blacklist.len()
    }

    /// Cleans up historical entries from the blacklist that are past the defined retention period.
    ///
    /// # Errors
    /// Returns an error if cleanup fails.
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
