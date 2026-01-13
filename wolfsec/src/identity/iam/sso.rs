//! OAuth2/OIDC Integration for Enterprise SSO
//!
//! Enterprise Single Sign-On integration with Azure AD, Okta, Auth0, and other providers.
//! Uses wolf pack principles for secure authentication and authorization.

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use openidconnect::{HttpRequest, HttpResponse};

/// Error type for HTTP client operations
#[derive(Debug)]
pub struct HttpClientError(String);

impl std::fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HttpClientError: {}", self.0)
    }
}

impl std::error::Error for HttpClientError {}

/// Standardized asynchronous HTTP client for OIDC protocol communication
pub async fn async_http_client(request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| HttpClientError(e.to_string()))?;

    let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
        .map_err(|e| HttpClientError(e.to_string()))?;
    let mut builder = client.request(method, request.uri().to_string());

    for (name, value) in request.headers() {
        if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(n, v);
            }
        }
    }

    let body = request.body();
    if !body.is_empty() {
        builder = builder.body(body.clone());
    }

    let response = builder
        .send()
        .await
        .map_err(|e| HttpClientError(e.to_string()))?;

    let mut response_builder = http::Response::builder().status(
        http::StatusCode::from_u16(response.status().as_u16())
            .map_err(|e| HttpClientError(e.to_string()))?,
    );

    for (name, value) in response.headers() {
        if let Ok(n) = http::header::HeaderName::from_bytes(name.as_str().as_bytes())
        {
            if let Ok(v) = http::header::HeaderValue::from_bytes(value.as_bytes()) {
                response_builder = response_builder.header(n, v);
            }
        }
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| HttpClientError(e.to_string()))?
        .to_vec();
    Ok(response_builder
        .body(body)
        .map_err(|e| HttpClientError(e.to_string()))?)
}
use openidconnect::{
    core::{CoreClient, CoreResponseType, CoreTokenResponse},
    AuthUrl, AuthenticationFlow, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    IssuerUrl, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken,
    Scope, TokenResponse, UserInfoUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::identity::iam::{
    AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig,
};

/// Externally supported Single Sign-On identity providers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SSOProvider {
    /// Microsoft Azure Active Directory / Entra ID
    AzureAD,
    /// Okta Identity Cloud
    Okta,
    /// Auth0 by Okta
    Auth0,
    /// Google Identity Platform
    Google,
    /// Simulated provider for local development and testing
    Mock,
    /// User-defined OIDC compliant provider
    Custom(String),
}

/// Global configuration and secrets for a specific SSO provider integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOProviderConfig {
    /// The target identity provider
    pub provider: SSOProvider,
    /// The unique client identifier for the Wolf Prowler application
    pub client_id: String,
    /// The secure client secret for token exchange
    pub client_secret: String,
    /// The base OIDC discovery URL for the provider
    pub issuer_url: String,
    /// The authorized callback landing page for the provider
    pub redirect_url: String,
    /// List of OIDC/OAuth2 scopes requested during authentication
    pub scopes: Vec<String>,
    /// Additional provider-specific metadata or flags
    pub provider_config: HashMap<String, String>,
}

/// Temporary in-memory state tracking for an active OIDC authentication challenge
#[derive(Debug)]
pub struct SSOAuthState {
    /// Random token for cross-site request forgery protection
    pub csrf_token: CsrfToken,
    /// Verification secret for Proof Key for Code Exchange (PKCE)
    pub pkce_verifier: PkceCodeVerifier,
    /// The provider associated with this authentication attempt
    pub provider: SSOProvider,
    /// Point in time when the state was generated
    pub created_at: chrono::DateTime<Utc>,
}

/// Normalized user identity data extracted from an external identity provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOUserInfo {
    /// Universal unique identifier for the user within the provider
    pub sub: String,
    /// User's verified email address
    pub email: Option<String>,
    /// True if the provider has confirmed the user's email ownership
    pub email_verified: Option<bool>,
    /// User's complete display name
    pub name: Option<String>,
    /// User's first or given name
    pub given_name: Option<String>,
    /// User's surname or family name
    pub family_name: Option<String>,
    /// URL to the user's avatar image
    pub picture: Option<String>,
    /// The provider that asserted this identity
    pub provider: SSOProvider,
    /// The internal username or link for the provider
    pub provider_user_id: String,
}

/// Central authority for managing federated Single Sign-On integrations and lifecycle
pub struct SSOIntegrationManager {
    /// Active registry of configured identity providers
    providers: Arc<Mutex<HashMap<SSOProvider, SSOProviderConfig>>>,
    /// Outstanding authentication states awaiting provider callbacks
    auth_states: Arc<Mutex<HashMap<String, SSOAuthState>>>,
    /// Global IAM system configuration
    config: IAMConfig,
}

// Type alias for fully configured client
// Type alias for fully configured client using CoreClient defaults
type FullyConfiguredClient = CoreClient<
    EndpointSet,    // AuthUrl (Forced Set)
    EndpointNotSet, // DeviceAuthUrl
    EndpointNotSet, // IntrospectionUrl
    EndpointSet,    // RevocationUrl
    EndpointSet,    // TokenUrl (Forced Set)
    EndpointSet,    // UserInfoUrl
>;

/// Parameters for initiating a new Single Sign-On authentication flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOAuthenticationRequest {
    /// Target identity provider (Google, Okta, etc.)
    pub provider: SSOProvider,
    /// Requester's environment and browser context
    pub client_info: ClientInfo,
    /// Optional override for the post-authentication redirect location
    pub redirect_url: Option<String>,
}

/// Parameters received from the identity provider after a successful user authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOCallbackRequest {
    /// The identity provider that issued the callback
    pub provider: SSOProvider,
    /// Random state token returned by the provider to mitigate CSRF attacks
    pub state: String,
    /// Authorization code generated by the provider for token exchange
    pub code: String,
    /// Detailed error message if the provider encountered an issue
    pub error: Option<String>,
}

impl SSOIntegrationManager {
    /// Initializes a new `SSOIntegrationManager` and registers default providers.
    ///
    /// # Errors
    /// Returns an error if initialization or default provider registration fails.
    pub async fn new(config: IAMConfig) -> Result<Self> {
        info!("🔐 Initializing SSO Integration Manager");

        let manager = Self {
            providers: Arc::new(Mutex::new(HashMap::new())),
            auth_states: Arc::new(Mutex::new(HashMap::new())),
            config,
        };
        manager.initialize_default_providers().await?;

        info!("✅ SSO Integration Manager initialized successfully");
        Ok(manager)
    }

    /// Initialize default SSO providers with environment-based configuration
    ///
    /// # Errors
    /// Returns an error if provider registration fails.
    async fn initialize_default_providers(&self) -> Result<()> {
        // Azure AD configuration
        let azure_config = SSOProviderConfig {
            provider: SSOProvider::AzureAD,
            client_id: std::env::var("AZURE_AD_CLIENT_ID")
                .unwrap_or_else(|_| "azure-client-id".to_string()),
            client_secret: std::env::var("AZURE_AD_CLIENT_SECRET")
                .unwrap_or_else(|_| "azure-client-secret".to_string()),
            issuer_url: std::env::var("AZURE_AD_ISSUER_URL")
                .unwrap_or_else(|_| "https://login.microsoftonline.com/common/v2.0".to_string()),
            redirect_url: std::env::var("AZURE_AD_REDIRECT_URL")
                .unwrap_or_else(|_| "http://localhost:3000/auth/azure/callback".to_string()),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
            provider_config: HashMap::new(),
        };

        // Okta configuration
        let okta_config = SSOProviderConfig {
            provider: SSOProvider::Okta,
            client_id: std::env::var("OKTA_CLIENT_ID")
                .unwrap_or_else(|_| "okta-client-id".to_string()),
            client_secret: std::env::var("OKTA_CLIENT_SECRET")
                .unwrap_or_else(|_| "okta-client-secret".to_string()),
            issuer_url: std::env::var("OKTA_ISSUER_URL")
                .unwrap_or_else(|_| "https://dev-123456.okta.com/oauth2/default".to_string()),
            redirect_url: std::env::var("OKTA_REDIRECT_URL")
                .unwrap_or_else(|_| "http://localhost:3000/auth/okta/callback".to_string()),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
            provider_config: HashMap::new(),
        };

        // Auth0 configuration
        let auth0_config = SSOProviderConfig {
            provider: SSOProvider::Auth0,
            client_id: std::env::var("AUTH0_CLIENT_ID")
                .unwrap_or_else(|_| "auth0-client-id".to_string()),
            client_secret: std::env::var("AUTH0_CLIENT_SECRET")
                .unwrap_or_else(|_| "auth0-client-secret".to_string()),
            issuer_url: std::env::var("AUTH0_ISSUER_URL")
                .unwrap_or_else(|_| "https://your-domain.auth0.com/".to_string()),
            redirect_url: std::env::var("AUTH0_REDIRECT_URL")
                .unwrap_or_else(|_| "http://localhost:3000/auth/auth0/callback".to_string()),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
            provider_config: HashMap::new(),
        };

        let mut providers = self.providers.lock().await;
        providers.insert(SSOProvider::AzureAD, azure_config);
        providers.insert(SSOProvider::Okta, okta_config);
        providers.insert(SSOProvider::Auth0, auth0_config);

        Ok(())
    }

    /// Constructs a fully configured OIDC client for a specific provider
    ///
    /// # Errors
    /// Returns an error if the provider is not configured or URL mapping fails.
    async fn create_client(&self, provider: &SSOProvider) -> Result<FullyConfiguredClient> {
        let providers = self.providers.lock().await;
        let config = providers
            .get(provider)
            .ok_or_else(|| anyhow!("Provider not configured: {:?}", provider))?;

        let issuer_url = IssuerUrl::new(config.issuer_url.clone())
            .map_err(|e| anyhow!("Invalid issuer URL: {}", e))?;

        let client = CoreClient::new(
            ClientId::new(config.client_id.clone()),
            issuer_url,
            openidconnect::JsonWebKeySet::new(vec![]),
        )
        .set_client_secret(ClientSecret::new(config.client_secret.clone()))
        .set_user_info_url(
            UserInfoUrl::new(config.issuer_url.clone() + "/oauth2/v2.0/userinfo")
                .map_err(|e| anyhow!("Invalid user info URL: {}", e))?,
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_url.clone())
                .map_err(|e| anyhow!("Invalid redirect URL: {}", e))?,
        )
        .set_auth_uri(
            AuthUrl::new(config.issuer_url.clone() + "/oauth2/v2.0/authorize")
                .map_err(|e| anyhow!("Invalid auth URL: {}", e))?,
        )
        .set_token_uri(
            openidconnect::TokenUrl::new(config.issuer_url.clone() + "/oauth2/v2.0/token")
                .map_err(|e| anyhow!("Invalid token URL: {}", e))?,
        )
        .set_revocation_url(
            openidconnect::RevocationUrl::new(config.issuer_url.clone() + "/oauth2/v2.0/revoke")
                .map_err(|e| anyhow!("Invalid revocation URL: {}", e))?,
        );

        Ok(client)
    }

    /// Generates the initial authorization URL and CSRF state for an identity provider challenge.
    ///
    /// # Errors
    /// Returns an error if the provider is not found or URL generation fails.
    pub async fn start_authentication(
        &self,
        request: SSOAuthenticationRequest,
    ) -> Result<SSOAuthResponse> {
        debug!(
            "🔐 Starting SSO authentication for provider: {:?}",
            request.provider
        );

        if let SSOProvider::Mock = request.provider {
            // Generate mock auth state
            let csrf_token = CsrfToken::new_random();
            let (_pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

            let auth_state = SSOAuthState {
                csrf_token: csrf_token.clone(),
                pkce_verifier,
                provider: request.provider.clone(),
                created_at: Utc::now(),
            };

            let state_key = format!("{}-{}", request.provider.to_string(), csrf_token.secret());
            let mut auth_states = self.auth_states.lock().await;
            auth_states.insert(state_key, auth_state);

            // Return callback URL directly
            // Assuming wolf_web running on localhost:8080
            return Ok(SSOAuthResponse {
                auth_url: format!(
                    "http://localhost:8080/callback/Mock?code=mock_code&state={}",
                    csrf_token.secret()
                ),
                state: csrf_token.secret().clone(),
                provider: request.provider,
            });
        }

        let client = self.create_client(&request.provider).await?;

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate state token
        // Build authorization URL
        let (auth_url, csrf_state, _nonce) = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                openidconnect::Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        // Store authentication state
        let auth_state = SSOAuthState {
            csrf_token: csrf_state.clone(),
            pkce_verifier,
            provider: request.provider.clone(),
            created_at: Utc::now(),
        };

        let state_key = format!("{}-{}", request.provider.to_string(), csrf_state.secret());
        let mut auth_states = self.auth_states.lock().await;
        auth_states.insert(state_key.clone(), auth_state);

        // Clean up old states
        self.cleanup_expired_states().await?;

        Ok(SSOAuthResponse {
            auth_url: auth_url.to_string(),
            state: csrf_state.secret().clone(),
            provider: request.provider,
        })
    }

    /// Processes the provider's callback, verifies the CSRF state, and retrieves the final user identity.
    ///
    /// # Errors
    /// Returns an error if the callback state is invalid, expired, or token exchange fails.
    pub async fn handle_callback(
        &self,
        request: SSOCallbackRequest,
    ) -> Result<SSOAuthenticationResult> {
        debug!(
            "🔐 Handling SSO callback for provider: {:?}",
            request.provider
        );

        if let Some(error) = request.error {
            return Err(anyhow!("SSO authentication failed: {}", error));
        }

        let state_key = format!("{}-{}", request.provider.to_string(), request.state);
        let mut auth_states = self.auth_states.lock().await;

        let auth_state = auth_states
            .remove(&state_key)
            .ok_or_else(|| anyhow!("Invalid or expired state token"))?;

        // Verify state token
        if auth_state.csrf_token.secret() != &request.state {
            return Err(anyhow!("State token mismatch"));
        }

        // Verify provider
        if auth_state.provider != request.provider {
            return Err(anyhow!("Provider mismatch"));
        }

        if let SSOProvider::Mock = request.provider {
            // Return mock result
            let user_info = SSOUserInfo {
                sub: "mock-user-123".to_string(),
                email: Some("mock@wolf.corp".to_string()),
                email_verified: Some(true),
                name: Some("Mock Wolf".to_string()),
                given_name: Some("Mock".to_string()),
                family_name: Some("Wolf".to_string()),
                picture: None,
                provider: SSOProvider::Mock,
                provider_user_id: "mock-user-123".to_string(),
            };

            return Ok(SSOAuthenticationResult {
                success: true,
                user_info,
                access_token: "mock_access_token".to_string(),
                refresh_token: Some("mock_refresh_token".to_string()),
                expires_in: Some(3600),
                id_token: Some("mock_id_token".to_string()),
                provider: SSOProvider::Mock,
            });
        }

        let client = self.create_client(&request.provider).await?;

        // Exchange code for tokens
        let token_response: CoreTokenResponse = client
            .exchange_code(openidconnect::AuthorizationCode::new(request.code))
            .set_pkce_verifier(PkceCodeVerifier::new(
                auth_state.pkce_verifier.secret().clone(),
            ))
            .request_async(&async_http_client)
            .await
            .map_err(|e| anyhow!("Token exchange failed: {}", e))?;

        // Get user info
        let user_info = self
            .get_user_info(&request.provider, &token_response)
            .await?;

        // Create authentication result
        let auth_result = SSOAuthenticationResult {
            success: true,
            user_info,
            access_token: token_response.access_token().secret().clone(),
            refresh_token: token_response
                .refresh_token()
                .map(|rt: &RefreshToken| rt.secret().clone()),
            expires_in: token_response.expires_in().map(|d| d.as_secs()),
            id_token: token_response
                .id_token()
                .map(|it: &openidconnect::core::CoreIdToken| it.to_string()),
            provider: request.provider,
        };

        debug!("✅ SSO authentication completed successfully");
        Ok(auth_result)
    }

    /// Get user information from provider
    async fn get_user_info(
        &self,
        provider: &SSOProvider,
        token_response: &CoreTokenResponse,
    ) -> Result<SSOUserInfo> {
        let client = self.create_client(provider).await?;

        let user_info: openidconnect::UserInfoClaims<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::core::CoreGenderClaim,
        > = client
            .user_info(token_response.access_token().clone(), None)
            .request_async(&async_http_client)
            .await
            .map_err(|e| anyhow!("User info request failed: {}", e))?;

        Ok(SSOUserInfo {
            sub: user_info.subject().to_string(),
            email: user_info.email().map(|e| e.to_string()),
            email_verified: user_info.email_verified(),
            name: user_info
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string()),
            given_name: user_info
                .given_name()
                .and_then(|gn| gn.get(None))
                .map(|gn| gn.to_string()),
            family_name: user_info
                .family_name()
                .and_then(|fn_| fn_.get(None))
                .map(|fn_| fn_.to_string()),
            picture: user_info
                .picture()
                .and_then(|p| p.get(None))
                .map(|p| p.to_string()),
            provider: provider.clone(),
            provider_user_id: user_info.subject().to_string(),
        })
    }

    /// Uses a refresh token to obtain a new set of access and ID tokens from the provider.
    ///
    /// # Errors
    /// Returns an error if the refresh token is invalid or the provider rejects the request.
    pub async fn refresh_token(
        &self,
        provider: SSOProvider,
        refresh_token: String,
    ) -> Result<SSORefreshResult> {
        debug!("🔐 Refreshing token for provider: {:?}", provider);

        let client: FullyConfiguredClient = self.create_client(&provider).await?;

        let token_response: CoreTokenResponse = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token))
            .request_async(&async_http_client)
            .await
            .map_err(|e| anyhow!("Token refresh failed: {}", e))?;

        Ok(SSORefreshResult {
            access_token: token_response.access_token().secret().clone(),
            refresh_token: token_response
                .refresh_token()
                .map(|rt: &RefreshToken| rt.secret().clone()),
            expires_in: token_response.expires_in().map(|d| d.as_secs()),
            id_token: token_response
                .id_token()
                .map(|it: &openidconnect::core::CoreIdToken| it.to_string()),
        })
    }

    /// Requests that the identity provider invalidate an active access token.
    ///
    /// # Errors
    /// Returns an error if the provider cannot be configured for revocation.
    pub async fn revoke_token(
        &self,
        provider: SSOProvider,
        token: String,
    ) -> Result<SSORevokeResult> {
        debug!("🔐 Revoking token for provider: {:?}", provider);

        let client: FullyConfiguredClient = self.create_client(&provider).await?;

        let result = client
            .revoke_token(openidconnect::core::CoreRevocableToken::AccessToken(
                openidconnect::AccessToken::new(token),
            ))?
            .request_async(&async_http_client)
            .await;

        match result {
            Ok(_) => Ok(SSORevokeResult {
                success: true,
                message: "Token revoked successfully".to_string(),
            }),
            Err(e) => {
                warn!("Token revocation failed: {}", e);
                Ok(SSORevokeResult {
                    success: false,
                    message: format!("Token revocation failed: {}", e),
                })
            }
        }
    }

    /// Dynamically registers a new identity provider configuration in the manager.
    ///
    /// # Errors
    /// Returns an error if registration fails.
    pub async fn add_provider(&self, config: SSOProviderConfig) -> Result<()> {
        info!("🔐 Adding SSO provider: {:?}", config.provider);

        let mut providers = self.providers.lock().await;
        providers.insert(config.provider.clone(), config.clone());

        info!("✅ SSO provider added successfully: {:?}", config.provider);
        Ok(())
    }

    /// Removes an existing identity provider configuration from the manager.
    ///
    /// # Errors
    /// Returns an error if removal fails.
    pub async fn remove_provider(&self, provider: SSOProvider) -> Result<()> {
        info!("🗑️ Removing SSO provider: {:?}", provider);

        let mut providers = self.providers.lock().await;
        providers.remove(&provider);

        info!("✅ SSO provider removed successfully: {:?}", provider);
        Ok(())
    }

    /// Clean up expired authentication states
    async fn cleanup_expired_states(&self) -> Result<()> {
        let mut auth_states = self.auth_states.lock().await;
        let now = Utc::now();
        let expiry_duration = Duration::minutes(15); // 15 minute expiry

        auth_states
            .retain(|_, state| now.signed_duration_since(state.created_at) < expiry_duration);

        Ok(())
    }

    /// Retrieves the low-level OIDC configuration for a specific provider.
    pub async fn get_provider_config(&self, provider: SSOProvider) -> Option<SSOProviderConfig> {
        let providers = self.providers.lock().await;
        providers.get(&provider).cloned()
    }

    /// Returns a list of all currently configured identity providers.
    pub async fn list_providers(&self) -> Vec<SSOProvider> {
        let providers = self.providers.lock().await;
        providers.keys().cloned().collect()
    }
}

/// Response containing the interactive authorization URL for the user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOAuthResponse {
    /// Fully qualified provider authorization URL
    pub auth_url: String,
    /// The random state token used for CSRF verification
    pub state: String,
    /// The identity provider targeted by the request
    pub provider: SSOProvider,
}

/// Comprehensive outcome of a successful SSO identity federation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOAuthenticationResult {
    /// True if the identity was successfully asserted and verified
    pub success: bool,
    /// Normalized user metadata from the provider
    pub user_info: SSOUserInfo,
    /// Bearer token for accessing provider resources or Wolf Prowler services
    pub access_token: String,
    /// Token used for acquiring new access tokens without user interaction
    pub refresh_token: Option<String>,
    /// Token validity duration in seconds
    pub expires_in: Option<u64>,
    /// OIDC Identity Token containing claims about the authenticated user
    pub id_token: Option<String>,
    /// The provider that issued these credentials
    pub provider: SSOProvider,
}

/// Outcome of a token refresh operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSORefreshResult {
    /// Newly issued access token
    pub access_token: String,
    /// Updated refresh token if rotated by the provider
    pub refresh_token: Option<String>,
    /// Validity of the new access token in seconds
    pub expires_in: Option<u64>,
    /// Newly issued ID token
    pub id_token: Option<String>,
}

/// Outcome of an explicit token revocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSORevokeResult {
    /// True if the provider successfully invalidated the token
    pub success: bool,
    /// Narrative detailing the result or error
    pub message: String,
}

impl From<SSOAuthenticationResult> for AuthenticationResult {
    fn from(sso_result: SSOAuthenticationResult) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(), // This would be mapped to internal user ID
            method: AuthenticationMethod::SSO,
            success: sso_result.success,
            timestamp: Utc::now(),
            ip_address: "unknown".to_string(), // Would be extracted from request
            user_agent: "unknown".to_string(), // Would be extracted from request
            mfa_required: false,               // Would be determined by provider
            mfa_completed: true,               // SSO typically includes MFA
            session_id: None,                  // Would be created after successful auth
            error_message: None,
        }
    }
}

impl SSOProvider {
    pub fn to_string(&self) -> String {
        match self {
            SSOProvider::AzureAD => "azure_ad".to_string(),
            SSOProvider::Okta => "okta".to_string(),
            SSOProvider::Auth0 => "auth0".to_string(),
            SSOProvider::Google => "google".to_string(),
            SSOProvider::Mock => "mock".to_string(),
            SSOProvider::Custom(name) => name.clone(),
        }
    }
}
