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
    AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig, SessionRequest,
};

/// Represents an active, authenticated logical connection between a user identity and the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique internal identifier for the session instance.
    pub id: Uuid,
    /// The user identity associated with this session.
    pub user_id: Uuid,
    /// Point in time when the session was initially established.
    pub created_at: chrono::DateTime<Utc>,
    /// Point in time of the most recent user activity or validation.
    pub last_activity: chrono::DateTime<Utc>,
    /// Deadline after which the session automatically becomes invalid.
    pub expires_at: chrono::DateTime<Utc>,
    /// Environment and device context of the requester.
    pub client_info: ClientInfo,
    /// Current lifecycle state of the session.
    pub status: SessionStatus,
    /// Classification of the session purpose.
    pub session_type: SessionType,
    /// Metadata tracking security-relevant events and risk during the session.
    pub security_context: SecurityContext,
    /// Optional JWT token string if the session is backed by a bearer token.
    pub jwt_token: Option<String>,
    /// Optional refresh token for extending the session lifecycle.
    pub refresh_token: Option<String>,
}

/// Possible lifecycle states for a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    /// Session is valid and accepting requests.
    Active,
    /// Session has naturally reached its expiration deadline.
    Expired,
    /// Session was explicitly closed by the user or an administrator.
    Terminated,
    /// Session is temporarily inactive but not yet destroyed.
    Suspended,
    /// Session is restricted due to a detected security anomaly or violation.
    Locked,
}

/// Categorization of sessions based on their authentication origin and scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionType {
    /// Standard interactive user session via primary credentials.
    Regular,
    /// High-privileged administrative session for system management.
    Admin,
    /// Non-interactive session for programmatic service-to-service calls.
    API,
    /// Session established via an external Single Sign-On provider.
    SSO,
    /// Stepped-up session requiring active multi-factor verification.
    MFA,
}

/// Contextual security metadata maintained throughout the session lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// History of IP address changes observed during the session.
    pub ip_changes: Vec<String>,
    /// History of browser or client metadata changes observed.
    pub user_agent_changes: Vec<String>,
    /// Significant geographic or network location transitions.
    pub location_changes: Vec<String>,
    /// Log of specific policy violations or anomalies detected.
    pub security_violations: Vec<SecurityViolation>,
    /// Dynamically calculated risk level (0-100).
    pub risk_score: u8,
    /// True if the session has successfully fulfilled an MFA challenge.
    pub mfa_verified: bool,
    /// Administrative lock flag based on accumulated risk or violations.
    pub locked: bool,
    /// Point in time of the most recent automated security posture evaluation.
    pub last_security_check: chrono::DateTime<Utc>,
}

/// Detailed record of a detected security-relevant anomaly or policy breach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityViolation {
    /// Categorization of the event (e.g., SessionHijacking).
    pub violation_type: SecurityViolationType,
    /// Narrative detailing the specific trigger or observation.
    pub description: String,
    /// Point in time when the violation was recorded.
    pub timestamp: chrono::DateTime<Utc>,
    /// Severity classification for risk calculation.
    pub severity: SecuritySeverity,
}

/// Security violation types categorized by nature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityViolationType {
    /// IP address has changed significantly.
    IPAddressChange,
    /// User agent header has changed mid-session.
    UserAgentChange,
    /// Geographic location has changed unexpectedly.
    LocationChange,
    /// Activity patterns suggesting non-human or malicious use.
    SuspiciousActivity,
    /// Threshold of failed actions exceeded.
    MultipleFailedAttempts,
    /// Indicators that the session has been taken over.
    SessionHijackingAttempt,
    /// Attempts to access unauthorized resources.
    PrivilegeEscalationAttempt,
}

/// Severity tiers for prioritizing response to security violations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecuritySeverity {
    /// Informational or low-impact anomalies.
    Low,
    /// Notable changes in behavior requiring monitoring.
    Medium,
    /// Indicators of potential unauthorized access.
    High,
    /// Immediate threats requiring session termination.
    Critical,
}

/// Central authority for creating, tracking, and securing authenticated user sessions
pub struct SessionManager {
    /// Thread-safe localized registry of all active sessions
    sessions: Arc<Mutex<HashMap<Uuid, Session>>>,
    /// Map of user IDs to their associated active session identifiers
    user_sessions: Arc<Mutex<HashMap<Uuid, Vec<Uuid>>>>,
    /// Global IAM system configuration
    config: IAMConfig,
    /// Frequency at which expired or anomalous sessions are pruned
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

/// Comprehensive outcome of a session integrity and validity evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionValidationResult {
    /// True if the session exists, is active, and conforms to security policies.
    pub valid: bool,
    /// The unique identifier of the validated session.
    pub session_id: Option<Uuid>,
    /// The identity associated with the session.
    pub user_id: Option<Uuid>,
    /// The current calculated expiration deadline.
    pub expires_at: Option<chrono::DateTime<Utc>>,
    /// Current snapshot of risk and violation metadata.
    pub security_context: Option<SecurityContext>,
    /// Descriptive error if the session failed validation.
    pub error_message: Option<String>,
    /// Current session risk score (0-100).
    pub risk_score: Option<u8>,
}

/// Parameters for modifying and verifying the state of an active session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUpdateRequest {
    /// Identifier of the session to transition.
    pub session_id: Uuid,
    /// Updated environment and browser context.
    pub client_info: Option<ClientInfo>,
    /// The specific nature of the interaction.
     pub activity_type: SessionActivityType,
    /// Optional payload of domain-specific session metadata.
    pub context: Option<HashMap<String, String>>,
}

/// Categorization of user-initiated or system-driven interactions for security auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionActivityType {
    /// Interaction via the programmatic API layer.
    APIRequest,
    /// Interaction with the visual management interface.
    DashboardAccess,
    /// Explicit credential verification or identity assertion.
    Authentication,
    /// Policy evaluation for specific resource access.
    Authorization,
    /// Explicit session termination request.
    Logout,
    /// Internal automated verification of session integrity.
    SecurityCheck,
}

impl SessionManager {
    /// Initializes a new `SessionManager` and launches the background cleanup task.
    ///
    /// # Errors
    /// Returns an error if initialization fails.
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

    /// Establishes a new authenticated session for a user and enforces concurrency limits.
    ///
    /// # Errors
    /// Returns an error if session creation or limit enforcement fails.
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

    /// Performs a comprehensive evaluation of session state, including expiration and risk assessment.
    ///
    /// # Errors
    /// Returns an error if validation logic fails.
    pub async fn validate_session(&self, session_id: Uuid) -> Result<SessionValidationResult> {
        debug!("🔍 Validating session: {}", session_id);

        let sessions = self.sessions.lock().await;
        let session = sessions.get(&session_id).cloned();

        if let Some(session) = session {
            let now = Utc::now();

            // Check if session is expired (Absolute Timeout)
            if now > session.expires_at {
                return Ok(SessionValidationResult {
                    valid: false,
                    session_id: Some(session_id),
                    user_id: Some(session.user_id),
                    expires_at: Some(session.expires_at),
                    security_context: Some(session.security_context.clone()),
                    error_message: Some("Session expired (Absolute)".to_string()),
                    risk_score: Some(session.security_context.risk_score),
                });
            }

            // Check for Idle Timeout
            let idle_duration = now - session.last_activity;
            if idle_duration > Duration::minutes(self.config.idle_timeout_minutes as i64) {
                return Ok(SessionValidationResult {
                    valid: false,
                    session_id: Some(session_id),
                    user_id: Some(session.user_id),
                    expires_at: Some(session.expires_at),
                    security_context: Some(session.security_context.clone()),
                    error_message: Some("Session expired (Inactivity)".to_string()),
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

    /// Updates session metadata and assesses risk based on the provided activity details.
    ///
    /// # Errors
    /// Returns an error if the session is not found or security checks fail.
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

    /// Formally marks a session as inactive and prunes it from the active registry.
    ///
    /// # Errors
    /// Returns an error if termination fails.
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

    /// Explicitly terminates a session with a recorded reason, enforcing immediate revocation.
    ///
    /// # Errors
    /// Returns an error if the session cannot be found.
    pub async fn force_terminate_session(&self, session_id: Uuid, reason: &str) -> Result<()> {
        info!("🔐 Force terminating session: {} (Reason: {})", session_id, reason);

        let mut sessions = self.sessions.lock().await;
        
        if let Some(session) = sessions.get_mut(&session_id) {
            session.status = SessionStatus::Terminated;
            session.security_context.locked = true;
            
            // Log the violation/reason
            session.security_context.security_violations.push(SecurityViolation {
                violation_type: SecurityViolationType::SuspiciousActivity, // Or generic admin action
                description: format!("Administrative Termination: {}", reason),
                timestamp: Utc::now(),
                severity: SecuritySeverity::High,
            });

            // Remove from user sessions immediately to prevent race conditions during cleanup?
            // Actually, keeping it as Terminated ensures audit trail persists until cleanup.
            // But we should remove it from the user's active list.
            let mut user_sessions = self.user_sessions.lock().await;
            if let Some(user_session_list) = user_sessions.get_mut(&session.user_id) {
                user_session_list.retain(|id| *id != session_id);
            }

            info!("✅ Session force terminated: {}", session_id);
            Ok(())
        } else {
            Err(anyhow!("Session not found for force termination: {}", session_id))
        }
    }

    /// Revokes every active session associated with a specific user identity.
    ///
    /// # Errors
    /// Returns an error if termination fails.
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

    /// Retrieves all active and inactive sessions associated with a specific user identity.
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

    /// Scans the session registry and removes expired or terminated entries.
    ///
    /// # Errors
    /// Returns an error if cleanup fails.
    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        let now = Utc::now();
        let idle_timeout = Duration::minutes(self.config.idle_timeout_minutes as i64);
        let mut sessions = self.sessions.lock().await;
        let mut user_sessions = self.user_sessions.lock().await;

        let expired_sessions: Vec<Uuid> = sessions
            .iter()
            .filter(|(_, session)| {
                let is_expired = now > session.expires_at;
                let is_idle = (now - session.last_activity) > idle_timeout;
                let is_invalid_status = session.status == SessionStatus::Expired;
                
                is_expired || is_idle || is_invalid_status
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

    /// Aggregates current session telemetry for system health and load monitoring.
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

    /// Adjusts the expiration timestamp for an active session.
    ///
    /// # Errors
    /// Returns an error if the session is not found.
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

    /// Retrieves a complete session snapshot from the active registry.
    pub async fn get_session(&self, session_id: Uuid) -> Option<Session> {
        let sessions = self.sessions.lock().await;
        sessions.get(&session_id).cloned()
    }
}

/// Summary metrics for the global state of user sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    /// Aggregate count of all tracked sessions.
    pub total_sessions: usize,
    /// Number of sessions currently in the Active state.
    pub active_sessions: usize,
    /// Number of sessions that have reached their expiration deadline.
    pub expired_sessions: usize,
    /// Number of sessions that were explicitly closed.
    pub terminated_sessions: usize,
    /// Aggregate count of distinct user identities.
    pub total_users: usize,
    /// Point in time when this summary was generated.
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
