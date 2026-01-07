//! Session Management System
//!
//! Advanced session management with security features, timeout handling, and revocation.
//! Uses wolf pack principles for secure session handling.

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
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

/// Session entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub id: Uuid,
    /// User ID
    pub user_id: Uuid,
    /// Created timestamp
    pub created_at: chrono::DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: chrono::DateTime<Utc>,
    /// Expires at timestamp
    pub expires_at: chrono::DateTime<Utc>,
    /// Client information
    pub client_info: ClientInfo,
    /// Session status
    pub status: SessionStatus,
    /// Session type
    pub session_type: SessionType,
    /// Security context
    pub security_context: SecurityContext,
    /// JWT token (if applicable)
    pub jwt_token: Option<String>,
    /// Refresh token (if applicable)
    pub refresh_token: Option<String>,
}

/// Session status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    /// Active session
    Active,
    /// Expired session
    Expired,
    /// Terminated session
    Terminated,
    /// Suspended session
    Suspended,
    /// Locked session (security violation)
    Locked,
}

/// Session type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionType {
    /// Regular user session
    Regular,
    /// Admin session
    Admin,
    /// API session
    API,
    /// SSO session
    SSO,
    /// MFA session
    MFA,
}

/// Security context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// IP address changes detected
    pub ip_changes: Vec<String>,
    /// User agent changes detected
    pub user_agent_changes: Vec<String>,
    /// Location changes detected
    pub location_changes: Vec<String>,
    /// Security violations
    pub security_violations: Vec<SecurityViolation>,
    /// Risk score (0-100)
    pub risk_score: u8,
    /// MFA verified
    pub mfa_verified: bool,
    /// Session locked
    pub locked: bool,
    /// Last security check
    pub last_security_check: chrono::DateTime<Utc>,
}

/// Security violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityViolation {
    /// Violation type
    pub violation_type: SecurityViolationType,
    /// Violation description
    pub description: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<Utc>,
    /// Severity
    pub severity: SecuritySeverity,
}

/// Security violation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityViolationType {
    /// IP address change
    IPAddressChange,
    /// User agent change
    UserAgentChange,
    /// Location change
    LocationChange,
    /// Suspicious activity
    SuspiciousActivity,
    /// Multiple failed attempts
    MultipleFailedAttempts,
    /// Session hijacking attempt
    SessionHijackingAttempt,
    /// Privilege escalation attempt
    PrivilegeEscalationAttempt,
}

/// Security severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecuritySeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Session manager
pub struct SessionManager {
    /// Active sessions
    sessions: Arc<Mutex<HashMap<Uuid, Session>>>,
    /// User session mapping
    user_sessions: Arc<Mutex<HashMap<Uuid, Vec<Uuid>>>>,
    /// Configuration
    config: IAMConfig,
    /// Session cleanup interval
    cleanup_interval: Duration,
}

impl Clone for SessionManager {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
            user_sessions: self.user_sessions.clone(),
            config: self.config.clone(),
            cleanup_interval: self.cleanup_interval,
        }
    }
}

/// Session validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionValidationResult {
    /// Validation success
    pub valid: bool,
    /// Session ID
    pub session_id: Option<Uuid>,
    /// User ID
    pub user_id: Option<Uuid>,
    /// Expires at
    pub expires_at: Option<chrono::DateTime<Utc>>,
    /// Security context
    pub security_context: Option<SecurityContext>,
    /// Error message
    pub error_message: Option<String>,
    /// Risk score
    pub risk_score: Option<u8>,
}

/// Session update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUpdateRequest {
    /// Session ID
    pub session_id: Uuid,
    /// New client info
    pub client_info: Option<ClientInfo>,
    /// Activity type
    pub activity_type: SessionActivityType,
    /// Additional context
    pub context: Option<HashMap<String, String>>,
}

/// Session activity types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionActivityType {
    /// API request
    APIRequest,
    /// Dashboard access
    DashboardAccess,
    /// Authentication
    Authentication,
    /// Authorization
    Authorization,
    /// Logout
    Logout,
    /// Security check
    SecurityCheck,
}

impl SessionManager {
    /// Create new session manager
    pub async fn new(config: IAMConfig) -> Result<Self> {
        info!("🔐 Initializing Session Manager");

        let manager = Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            user_sessions: Arc::new(Mutex::new(HashMap::new())),
            config,
            cleanup_interval: Duration::minutes(5), // Cleanup every 5 minutes
        };

        // Start background cleanup task
        tokio::spawn(manager.clone().session_cleanup_task());

        info!("✅ Session Manager initialized successfully");
        Ok(manager)
    }

    /// Create new session
    pub async fn create_session(&self, user_id: Uuid, request: SessionRequest) -> Result<Session> {
        debug!("🔐 Creating session for user: {}", user_id);

        let now = Utc::now();
        let expires_at = now + Duration::minutes(self.config.session_timeout_minutes as i64);

        let session = Session {
            id: Uuid::new_v4(),
            user_id,
            created_at: now,
            last_activity: now,
            expires_at,
            client_info: ClientInfo {
                ip_address: request.ip_address,
                user_agent: request.user_agent,
                device_id: None,
                location: None,
            },
            status: SessionStatus::Active,
            session_type: SessionType::Regular,
            security_context: SecurityContext {
                ip_changes: Vec::new(),
                user_agent_changes: Vec::new(),
                location_changes: Vec::new(),
                security_violations: Vec::new(),
                risk_score: 0,
                mfa_verified: false,
                locked: false,
                last_security_check: now,
            },
            jwt_token: None,
            refresh_token: None,
        };

        // Store session
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session.id, session.clone());

        // Update user session mapping
        let mut user_sessions = self.user_sessions.lock().await;
        let user_session_list = user_sessions.entry(user_id).or_insert_with(Vec::new);
        user_session_list.push(session.id);

        // Limit concurrent sessions per user
        self.limit_user_sessions(user_id).await?;

        info!("✅ Session created: {} for user {}", session.id, user_id);
        Ok(session)
    }

    /// Validate session
    pub async fn validate_session(&self, session_id: Uuid) -> Result<SessionValidationResult> {
        debug!("🔍 Validating session: {}", session_id);

        let sessions = self.sessions.lock().await;
        let session = sessions.get(&session_id).cloned();

        if let Some(session) = session {
            let now = Utc::now();

            // Check if session is expired
            if now > session.expires_at {
                return Ok(SessionValidationResult {
                    valid: false,
                    session_id: Some(session_id),
                    user_id: Some(session.user_id),
                    expires_at: Some(session.expires_at),
                    security_context: Some(session.security_context.clone()),
                    error_message: Some("Session expired".to_string()),
                    risk_score: Some(session.security_context.risk_score),
                });
            }

            // Check if session is terminated or locked
            match session.status {
                SessionStatus::Active => {
                    // Perform security checks
                    let security_result = self.perform_security_checks(&session).await?;

                    if security_result.locked {
                        // Lock the session
                        let mut sessions_mut = self.sessions.lock().await;
                        if let Some(sess) = sessions_mut.get_mut(&session_id) {
                            sess.status = SessionStatus::Locked;
                            sess.security_context.locked = true;
                        }

                        return Ok(SessionValidationResult {
                            valid: false,
                            session_id: Some(session_id),
                            user_id: Some(session.user_id),
                            expires_at: Some(session.expires_at),
                            security_context: Some(session.security_context.clone()),
                            error_message: Some(
                                "Session locked due to security violation".to_string(),
                            ),
                            risk_score: Some(session.security_context.risk_score),
                        });
                    }

                    Ok(SessionValidationResult {
                        valid: true,
                        session_id: Some(session_id),
                        user_id: Some(session.user_id),
                        expires_at: Some(session.expires_at),
                        security_context: Some(session.security_context.clone()),
                        error_message: None,
                        risk_score: Some(session.security_context.risk_score),
                    })
                }
                SessionStatus::Expired => Ok(SessionValidationResult {
                    valid: false,
                    session_id: Some(session_id),
                    user_id: Some(session.user_id),
                    expires_at: Some(session.expires_at),
                    security_context: Some(session.security_context.clone()),
                    error_message: Some("Session expired".to_string()),
                    risk_score: Some(session.security_context.risk_score),
                }),
                SessionStatus::Terminated | SessionStatus::Suspended | SessionStatus::Locked => {
                    Ok(SessionValidationResult {
                        valid: false,
                        session_id: Some(session_id),
                        user_id: Some(session.user_id),
                        expires_at: Some(session.expires_at),
                        security_context: Some(session.security_context.clone()),
                        error_message: Some(format!("Session status: {:?}", session.status)),
                        risk_score: Some(session.security_context.risk_score),
                    })
                }
            }
        } else {
            Ok(SessionValidationResult {
                valid: false,
                session_id: None,
                user_id: None,
                expires_at: None,
                security_context: None,
                error_message: Some("Session not found".to_string()),
                risk_score: None,
            })
        }
    }

    /// Update session activity
    pub async fn update_session_activity(
        &self,
        session_id: Uuid,
        request: SessionUpdateRequest,
    ) -> Result<Session> {
        debug!("🔐 Updating session activity: {}", session_id);

        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        // Update last activity
        session.last_activity = Utc::now();

        // Update client info if provided
        if let Some(client_info) = request.client_info {
            self.check_session_security(session, &client_info).await?;
            session.client_info = client_info;
        }

        // Update security context based on activity
        self.update_security_context(session, &request.activity_type)
            .await?;

        info!("✅ Session activity updated: {}", session_id);
        Ok(session.clone())
    }

    /// Terminate session
    pub async fn terminate_session(&self, session_id: Uuid) -> Result<()> {
        debug!("🔐 Terminating session: {}", session_id);

        let mut sessions = self.sessions.lock().await;
        let session = sessions.get_mut(&session_id);

        if let Some(session) = session {
            session.status = SessionStatus::Terminated;

            // Remove from user sessions
            let mut user_sessions = self.user_sessions.lock().await;
            if let Some(user_session_list) = user_sessions.get_mut(&session.user_id) {
                user_session_list.retain(|id| *id != session_id);
            }

            info!("✅ Session terminated: {}", session_id);
        } else {
            warn!("Session not found for termination: {}", session_id);
        }

        Ok(())
    }

    /// Terminate all sessions for user
    pub async fn terminate_user_sessions(&self, user_id: Uuid) -> Result<()> {
        debug!("🔐 Terminating all sessions for user: {}", user_id);

        let mut sessions = self.sessions.lock().await;
        let mut user_sessions = self.user_sessions.lock().await;

        if let Some(session_ids) = user_sessions.get(&user_id).cloned() {
            for session_id in session_ids {
                if let Some(session) = sessions.get_mut(&session_id) {
                    session.status = SessionStatus::Terminated;
                }
            }
        }

        user_sessions.remove(&user_id);

        info!("✅ All sessions terminated for user: {}", user_id);
        Ok(())
    }

    /// Get user sessions
    pub async fn get_user_sessions(&self, user_id: Uuid) -> Vec<Session> {
        let user_sessions = self.user_sessions.lock().await;
        let session_ids = user_sessions.get(&user_id).cloned().unwrap_or_default();

        let sessions = self.sessions.lock().await;
        session_ids
            .iter()
            .filter_map(|id| sessions.get(id).cloned())
            .collect()
    }

    /// Check session security
    async fn check_session_security(
        &self,
        session: &mut Session,
        new_client_info: &ClientInfo,
    ) -> Result<()> {
        let mut security_violations = Vec::new();

        // Check IP address changes
        if session.client_info.ip_address != new_client_info.ip_address {
            session
                .security_context
                .ip_changes
                .push(new_client_info.ip_address.clone());

            security_violations.push(SecurityViolation {
                violation_type: SecurityViolationType::IPAddressChange,
                description: format!(
                    "IP address changed from {} to {}",
                    session.client_info.ip_address, new_client_info.ip_address
                ),
                timestamp: Utc::now(),
                severity: SecuritySeverity::Medium,
            });

            session.security_context.risk_score += 20;
        }

        // Check user agent changes
        if session.client_info.user_agent != new_client_info.user_agent {
            session
                .security_context
                .user_agent_changes
                .push(new_client_info.user_agent.clone());

            security_violations.push(SecurityViolation {
                violation_type: SecurityViolationType::UserAgentChange,
                description: format!(
                    "User agent changed from {} to {}",
                    session.client_info.user_agent, new_client_info.user_agent
                ),
                timestamp: Utc::now(),
                severity: SecuritySeverity::Low,
            });

            session.security_context.risk_score += 10;
        }

        // Check location changes (if available)
        if let (Some(old_location), Some(new_location)) =
            (&session.client_info.location, &new_client_info.location)
        {
            if old_location != new_location {
                session
                    .security_context
                    .location_changes
                    .push(new_location.clone());

                security_violations.push(SecurityViolation {
                    violation_type: SecurityViolationType::LocationChange,
                    description: format!(
                        "Location changed from {} to {}",
                        old_location, new_location
                    ),
                    timestamp: Utc::now(),
                    severity: SecuritySeverity::High,
                });

                session.security_context.risk_score += 30;
            }
        }

        // Add security violations
        session
            .security_context
            .security_violations
            .extend(security_violations);

        // Update last security check
        session.security_context.last_security_check = Utc::now();

        // Lock session if risk score is too high
        if session.security_context.risk_score > 75 {
            session.security_context.locked = true;
            session.status = SessionStatus::Locked;
        }

        Ok(())
    }

    /// Update security context based on activity
    async fn update_security_context(
        &self,
        session: &mut Session,
        activity_type: &SessionActivityType,
    ) -> Result<()> {
        match activity_type {
            SessionActivityType::APIRequest => {
                // API requests are normal, no additional risk
            }
            SessionActivityType::DashboardAccess => {
                // Dashboard access is normal, no additional risk
            }
            SessionActivityType::Authentication => {
                // Authentication events are good, reduce risk slightly
                if session.security_context.risk_score > 0 {
                    session.security_context.risk_score -= 1;
                }
            }
            SessionActivityType::Authorization => {
                // Authorization checks are normal
            }
            SessionActivityType::Logout => {
                // Logout is good, reduce risk
                if session.security_context.risk_score > 5 {
                    session.security_context.risk_score -= 5;
                }
            }
            SessionActivityType::SecurityCheck => {
                // Security checks are good, reduce risk
                if session.security_context.risk_score > 2 {
                    session.security_context.risk_score -= 2;
                }
            }
        }

        session.security_context.last_security_check = Utc::now();
        Ok(())
    }

    /// Perform security checks on session
    async fn perform_security_checks(&self, session: &Session) -> Result<SecurityContext> {
        let mut security_context = session.security_context.clone();
        let now = Utc::now();

        // Check for expired security violations
        security_context.security_violations.retain(|violation| {
            now.signed_duration_since(violation.timestamp) < Duration::hours(24)
        });

        // Recalculate risk score based on recent violations
        let mut risk_score = 0;
        for violation in &security_context.security_violations {
            match violation.severity {
                SecuritySeverity::Low => risk_score += 5,
                SecuritySeverity::Medium => risk_score += 15,
                SecuritySeverity::High => risk_score += 30,
                SecuritySeverity::Critical => risk_score += 50,
            }
        }

        security_context.risk_score = risk_score.min(100);
        security_context.last_security_check = now;

        Ok(security_context)
    }

    /// Limit concurrent sessions per user
    async fn limit_user_sessions(&self, user_id: Uuid) -> Result<()> {
        let max_sessions = 5; // Maximum concurrent sessions per user

        let mut user_sessions = self.user_sessions.lock().await;
        let session_ids = user_sessions.get_mut(&user_id).unwrap();

        if session_ids.len() > max_sessions {
            // Remove oldest sessions
            session_ids.sort_by_key(|id| {
                let sessions = self.sessions.blocking_lock();
                sessions.get(id).map(|s| s.created_at)
            });

            let sessions_to_remove = session_ids.split_off(max_sessions);
            let mut sessions = self.sessions.lock().await;

            for session_id in sessions_to_remove {
                if let Some(session) = sessions.get_mut(&session_id) {
                    session.status = SessionStatus::Terminated;
                }
            }
        }

        Ok(())
    }

    /// Session cleanup task
    async fn session_cleanup_task(self) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.cleanup_interval.num_seconds() as u64,
            ))
            .await;

            if let Err(e) = self.cleanup_expired_sessions().await {
                error!("Session cleanup failed: {}", e);
            }
        }
    }

    /// Clean up expired sessions
    async fn cleanup_expired_sessions(&self) -> Result<()> {
        let now = Utc::now();
        let mut sessions = self.sessions.lock().await;
        let mut user_sessions = self.user_sessions.lock().await;

        let expired_sessions: Vec<Uuid> = sessions
            .iter()
            .filter(|(_, session)| {
                now > session.expires_at || session.status == SessionStatus::Expired
            })
            .map(|(id, _)| *id)
            .collect();

        for session_id in &expired_sessions {
            if let Some(session) = sessions.remove(&session_id) {
                // Remove from user sessions
                if let Some(user_session_list) = user_sessions.get_mut(&session.user_id) {
                    user_session_list.retain(|id| *id != *session_id);
                }
            }
        }

        // Clean up empty user session lists
        user_sessions.retain(|_, session_ids| !session_ids.is_empty());

        info!("✅ Cleaned up {} expired sessions", expired_sessions.len());
        Ok(())
    }

    /// Get session statistics
    pub async fn get_stats(&self) -> SessionStats {
        let sessions = self.sessions.lock().await;
        let user_sessions = self.user_sessions.lock().await;

        let active_sessions = sessions
            .values()
            .filter(|s| s.status == SessionStatus::Active)
            .count();
        let expired_sessions = sessions
            .values()
            .filter(|s| s.status == SessionStatus::Expired)
            .count();
        let terminated_sessions = sessions
            .values()
            .filter(|s| s.status == SessionStatus::Terminated)
            .count();

        SessionStats {
            total_sessions: sessions.len(),
            active_sessions,
            expired_sessions,
            terminated_sessions,
            total_users: user_sessions.len(),
            last_update: Utc::now(),
        }
    }

    /// Extend session timeout
    pub async fn extend_session(&self, session_id: Uuid, minutes: i64) -> Result<()> {
        debug!(
            "🔐 Extending session: {} by {} minutes",
            session_id, minutes
        );

        let mut sessions = self.sessions.lock().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?;

        session.expires_at = session.expires_at + Duration::minutes(minutes);
        session.last_activity = Utc::now();

        info!("✅ Session extended: {}", session_id);
        Ok(())
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: Uuid) -> Option<Session> {
        let sessions = self.sessions.lock().await;
        sessions.get(&session_id).cloned()
    }
}

/// Session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    /// Total sessions
    pub total_sessions: usize,
    /// Active sessions
    pub active_sessions: usize,
    /// Expired sessions
    pub expired_sessions: usize,
    /// Terminated sessions
    pub terminated_sessions: usize,
    /// Total users with sessions
    pub total_users: usize,
    /// Last update timestamp
    pub last_update: chrono::DateTime<Utc>,
}

impl From<SessionValidationResult> for AuthenticationResult {
    fn from(session_result: SessionValidationResult) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: session_result.user_id.unwrap_or_default(),
            method: AuthenticationMethod::Session,
            success: session_result.valid,
            timestamp: Utc::now(),
            ip_address: "unknown".to_string(), // Would be extracted from request
            user_agent: "unknown".to_string(), // Would be extracted from request
            mfa_required: false,
            mfa_completed: true,
            session_id: session_result.session_id,
            error_message: session_result.error_message,
        }
    }
}
