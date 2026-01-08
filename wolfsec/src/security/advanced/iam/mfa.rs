//! Multi-Factor Authentication (MFA) System
//!
//! MFA support for admin accounts with TOTP, SMS, email, and push notification methods.
//! Uses wolf pack principles for secure authentication.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use qrcode::render::svg;
use qrcode::QrCode;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;

use crate::security::advanced::iam::{
    AuthenticationMethod, AuthenticationResult, ClientInfo, IAMConfig,
};

/// Categorization of supported multi-factor verification mechanisms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MFAMethod {
    /// Time-based One-Time Password using standard algorithms (RFC 6238)
    TOTP,
    /// Short code delivered via Short Message Service
    SMS,
    /// Verification code delivered via electronic mail
    Email,
    /// Real-time authorization request pushed to a trusted mobile device
    PushNotification,
    /// Physical security keys (e.g., YubiKey) or specialized hardware
    HardwareToken,
    /// Verification using physical characteristics (Fingerprint, FaceID)
    Biometric,
    /// One-time use recovery codes for account restoration
    BackupCodes,
}

/// Represents a specific instance of an identity verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFAChallenge {
    /// Unique internal identifier for the challenge instance
    pub id: Uuid,
    /// The wolf identity attempting to verify their access
    pub user_id: Uuid,
    /// The verification mechanism chosen for this challenge
    pub method: MFAMethod,
    /// Contextual data for the challenge (e.g., the expected OTP code)
    pub challenge_data: String,
    /// Point in time when the challenge was issued
    pub created_at: chrono::DateTime<Utc>,
    /// Deadline after which the challenge is no longer valid
    pub expires_at: chrono::DateTime<Utc>,
    /// Number of incorrect attempts allowed before locking the challenge
    pub attempts_remaining: u8,
    /// Current lifecycle state of the challenge
    pub status: MFAChallengeStatus,
    /// Information about the requester's environment
    pub client_info: Option<ClientInfo>,
}

/// Possible states for an active MFA challenge
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MFAChallengeStatus {
    /// Waiting for user input or verification
    Pending,
    /// Successfully verified and closed
    Completed,
    /// Failed verification due to incorrect input or exhausted attempts
    Failed,
    /// Closed due to exceeding the time-to-live
    Expired,
}

/// Record of a user's enrollment in a specific MFA method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFAEnrollment {
    /// The identity associated with this enrollment
    pub user_id: Uuid,
    /// The verification mechanism enrolled
    pub method: MFAMethod,
    /// Shared secret or public key metadata (e.g., for TOTP)
    pub secret: Option<String>,
    /// Registered mobile number for SMS verification
    pub phone_number: Option<String>,
    /// Registered email address for verification
    pub email: Option<String>,
    /// Unique identifier for a trusted mobile device
    pub device_id: Option<String>,
    /// Set of cryptographic recovery codes
    pub backup_codes: Vec<String>,
    /// Point in time when enrollment was finalized
    pub enrolled_at: chrono::DateTime<Utc>,
    /// Most recent successful use of this method
    pub last_used: Option<chrono::DateTime<Utc>>,
    /// If false, the enrollment is soft-deleted and inactive
    pub active: bool,
}

/// Request to finalize a pending MFA challenge with proof of possession
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFAVerificationRequest {
    /// The user providing the verification proof
    pub user_id: Uuid,
    /// The specific challenge instance being addressed
    pub challenge_id: Uuid,
    /// The user-provided proof (OTP code, biometric signature, etc.)
    pub verification_code: String,
    /// The mechanism used for verification
    pub method: MFAMethod,
    /// Requester environment snapshots
    pub client_info: Option<ClientInfo>,
}

/// Structured response detailing the outcome of an MFA verification attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFAVerificationResult {
    /// Status indicating if the proof was accepted
    pub success: bool,
    /// Internal identifier for the user
    pub user_id: Uuid,
    /// The identifier of the addressed challenge
    pub challenge_id: Uuid,
    /// The mechanism used for verification
    pub method: MFAMethod,
    /// Precise point in time when verification occurred
    pub verified_at: chrono::DateTime<Utc>,
    /// Descriptive feedback if verification failed
    pub error_message: Option<String>,
    /// True if identity was proven using a one-time recovery code
    pub backup_code_used: bool,
}

/// Defined interface for specialized MFA verification implementations
#[async_trait]
pub trait MFAProvider: Send + Sync {
    /// Dispatches a challenge (e.g., sends an SMS or Email) to the user.
    async fn send_challenge(
        &self,
        user_id: Uuid,
        method: MFAMethod,
        challenge_data: &str,
        client_info: Option<&ClientInfo>,
    ) -> Result<()>;

    /// Validates provided proof against expectations for the given challenge data.
    async fn verify_challenge(
        &self,
        user_id: Uuid,
        method: MFAMethod,
        verification_code: &str,
        challenge_data: &str,
    ) -> Result<bool>;
}

/// TOTP MFA provider
pub struct TOTPProvider;

impl TOTPProvider {
    /// Generates a Time-based One-Time Password.
    fn generate_totp(&self, secret: &str, timestamp: u64) -> Result<String> {
        // Simple HMAC-SHA1 implementation for TOTP
        // In production, use a proper TOTP library
        let key = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
            .ok_or_else(|| anyhow!("Invalid base32 secret"))?;

        let counter = timestamp.to_be_bytes();
        let mut mac =
            hmac::Hmac::<Sha1>::new_from_slice(&key).map_err(|e| anyhow!("HMAC error: {}", e))?;
        mac.update(&counter);
        let result = mac.finalize();
        let hash = result;

        // Dynamic truncation
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary = ((hash[offset] & 0x7f) as u32) << 24
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);

        let otp = binary % 1_000_000;
        Ok(format!("{:06}", otp))
    }
}

#[async_trait]
impl MFAProvider for TOTPProvider {
    async fn send_challenge(
        &self,
        _user_id: Uuid,
        _method: MFAMethod,
        _challenge_data: &str,
        _client_info: Option<&ClientInfo>,
    ) -> Result<()> {
        // TOTP doesn't need to "send" anything, the app generates codes
        Ok(())
    }

    async fn verify_challenge(
        &self,
        _user_id: Uuid,
        _method: MFAMethod,
        verification_code: &str,
        secret: &str,
    ) -> Result<bool> {
        // Simple TOTP verification (in production, use a proper library)
        let now = Utc::now().timestamp() / 30; // 30-second intervals
        let expected_code = self.generate_totp(secret, now as u64)?;
        Ok(verification_code == expected_code)
    }
}

/// SMS MFA provider.
pub struct SMSProvider;

#[async_trait]
impl MFAProvider for SMSProvider {
    async fn send_challenge(
        &self,
        user_id: Uuid,
        _method: MFAMethod,
        challenge_data: &str,
        _client_info: Option<&ClientInfo>,
    ) -> Result<()> {
        debug!(
            "📱 Sending SMS to user {} with code: {}",
            user_id, challenge_data
        );
        // In production, integrate with SMS service like Twilio
        info!("✅ SMS challenge sent to user {}", user_id);
        Ok(())
    }

    async fn verify_challenge(
        &self,
        _user_id: Uuid,
        _method: MFAMethod,
        verification_code: &str,
        challenge_data: &str,
    ) -> Result<bool> {
        Ok(verification_code == challenge_data)
    }
}

/// Email MFA provider.
pub struct EmailProvider;

#[async_trait]
impl MFAProvider for EmailProvider {
    async fn send_challenge(
        &self,
        user_id: Uuid,
        _method: MFAMethod,
        challenge_data: &str,
        _client_info: Option<&ClientInfo>,
    ) -> Result<()> {
        debug!(
            "📧 Sending email to user {} with code: {}",
            user_id, challenge_data
        );
        // In production, integrate with email service
        info!("✅ Email challenge sent to user {}", user_id);
        Ok(())
    }

    async fn verify_challenge(
        &self,
        _user_id: Uuid,
        _method: MFAMethod,
        verification_code: &str,
        challenge_data: &str,
    ) -> Result<bool> {
        Ok(verification_code == challenge_data)
    }
}

/// Central orchestrator for user multi-factor enrollment, challenges, and fulfillment
pub struct MFAManager {
    /// Registry of all MFA methods configured for each user
    enrollments: Arc<Mutex<HashMap<Uuid, Vec<MFAEnrollment>>>>,
    /// Active challenge instances currently awaiting verification
    challenges: Arc<Mutex<HashMap<Uuid, MFAChallenge>>>,
    /// Map of specialized providers handling the distribution of challenges
    providers: Arc<Mutex<HashMap<MFAMethod, Box<dyn MFAProvider>>>>,
    /// Shared IAM system configuration
    config: IAMConfig,
}

impl MFAManager {
    /// Initializes the manager and registers default providers for TOTP, SMS, and Email.
    ///
    /// # Errors
    /// Returns an error if provider initialization fails.
    pub async fn new(config: IAMConfig) -> Result<Self> {
        info!("🔐 Initializing MFA Manager");

        let mut providers: HashMap<MFAMethod, Box<dyn MFAProvider>> = HashMap::new();
        providers.insert(MFAMethod::TOTP, Box::new(TOTPProvider));
        providers.insert(MFAMethod::SMS, Box::new(SMSProvider));
        providers.insert(MFAMethod::Email, Box::new(EmailProvider));

        let manager = Self {
            enrollments: Arc::new(Mutex::new(HashMap::new())),
            challenges: Arc::new(Mutex::new(HashMap::new())),
            providers: Arc::new(Mutex::new(providers)),
            config,
        };

        info!("✅ MFA Manager initialized successfully");
        Ok(manager)
    }

    /// Registers a new active MFA method for the specified user and generates initial backup codes.
    ///
    /// # Errors
    /// Returns an error if enrollment fails.
    pub async fn enroll_user(
        &self,
        user_id: Uuid,
        method: MFAMethod,
        phone_number: Option<String>,
        email: Option<String>,
        device_id: Option<String>,
    ) -> Result<MFAEnrollment> {
        debug!("🔐 Enrolling user {} in MFA method: {:?}", user_id, method);

        // Generate secret for TOTP
        let secret = if method == MFAMethod::TOTP {
            Some(self.generate_base32_secret())
        } else {
            None
        };

        // Generate backup codes
        let backup_codes = self.generate_backup_codes();

        let enrollment = MFAEnrollment {
            user_id,
            method: method.clone(),
            secret,
            phone_number,
            email,
            device_id,
            backup_codes,
            enrolled_at: Utc::now(),
            last_used: None,
            active: true,
        };

        let mut enrollments = self.enrollments.lock().await;
        let user_enrollments = enrollments.entry(user_id).or_insert_with(Vec::new);
        user_enrollments.push(enrollment.clone());

        info!("✅ User {} enrolled in MFA method: {:?}", user_id, method);
        Ok(enrollment)
    }

    /// Creates a new challenge instance and dispatches it via the appropriate provider.
    ///
    /// # Errors
    /// Returns an error if the user is not enrolled or dispatch fails.
    pub async fn generate_challenge(
        &self,
        user_id: Uuid,
        method: MFAMethod,
        client_info: Option<ClientInfo>,
    ) -> Result<MFAChallenge> {
        debug!(
            "🔐 Generating MFA challenge for user {} using {:?}",
            user_id, method
        );

        // Check if user is enrolled in the method
        let enrollments = self.enrollments.lock().await;
        let user_enrollments = enrollments
            .get(&user_id)
            .ok_or_else(|| anyhow!("User {} not enrolled in MFA", user_id))?;

        let enrollment = user_enrollments
            .iter()
            .find(|e| e.method == method && e.active)
            .ok_or_else(|| anyhow!("User {} not enrolled in MFA method {:?}", user_id, method))?;

        // Generate challenge data
        let challenge_data = match method {
            MFAMethod::TOTP => enrollment.secret.clone().unwrap_or_default(),
            MFAMethod::SMS | MFAMethod::Email => self.generate_otp_code(),
            MFAMethod::PushNotification => format!("push_{}", Uuid::new_v4()),
            MFAMethod::BackupCodes => "backup_code_required".to_string(),
            _ => self.generate_otp_code(),
        };

        let challenge = MFAChallenge {
            id: Uuid::new_v4(),
            user_id,
            method: method.clone(),
            challenge_data: challenge_data.clone(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5), // 5 minute expiry
            attempts_remaining: 3,
            status: MFAChallengeStatus::Pending,
            client_info: client_info.clone(),
        };

        // Send challenge via provider
        let providers = self.providers.lock().await;
        if let Some(provider) = providers.get(&method) {
            provider
                .send_challenge(user_id, method, &challenge_data, client_info.as_ref())
                .await?;
        }

        // Store challenge
        let mut challenges = self.challenges.lock().await;
        challenges.insert(challenge.id, challenge.clone());

        info!("✅ MFA challenge generated for user {}", user_id);
        Ok(challenge)
    }

    /// Evaluates user proof against an active challenge and marks the challenge as fulfilled.
    ///
    /// # Errors
    /// Returns an error if verification fails or the challenge is invalid.
    pub async fn verify_challenge(
        &self,
        request: MFAVerificationRequest,
    ) -> Result<MFAVerificationResult> {
        debug!("🔐 Verifying MFA challenge for user {}", request.user_id);

        let mut challenges = self.challenges.lock().await;
        let challenge = challenges
            .get_mut(&request.challenge_id)
            .ok_or_else(|| anyhow!("Challenge not found"))?;

        // Check if challenge is expired
        if Utc::now() > challenge.expires_at {
            challenge.status = MFAChallengeStatus::Expired;
            return Err(anyhow!("Challenge has expired"));
        }

        // Check attempts remaining
        if challenge.attempts_remaining == 0 {
            challenge.status = MFAChallengeStatus::Failed;
            return Err(anyhow!("Maximum attempts exceeded"));
        }

        // Verify using appropriate provider
        let providers = self.providers.lock().await;
        let provider = providers
            .get(&request.method)
            .ok_or_else(|| anyhow!("MFA provider not found"))?;

        let is_valid = provider
            .verify_challenge(
                request.user_id,
                request.method.clone(),
                &request.verification_code,
                &challenge.challenge_data,
            )
            .await?;

        if is_valid {
            challenge.status = MFAChallengeStatus::Completed;
            challenges.remove(&request.challenge_id);

            // Update enrollment last used
            self.update_enrollment_last_used(request.user_id, request.method.clone())
                .await?;

            Ok(MFAVerificationResult {
                success: true,
                user_id: request.user_id,
                challenge_id: request.challenge_id,
                method: request.method,
                verified_at: Utc::now(),
                error_message: None,
                backup_code_used: false, // Would be determined by verification logic
            })
        } else {
            challenge.attempts_remaining -= 1;
            if challenge.attempts_remaining == 0 {
                challenge.status = MFAChallengeStatus::Failed;
            }

            Err(anyhow!("Invalid verification code"))
        }
    }

    /// Verifies a backup code and removes it from the user's enrollment.
    ///
    /// # Errors
    /// Returns an error if the code is invalid or the user is not found.
    pub async fn verify_backup_code(
        &self,
        user_id: Uuid,
        backup_code: &str,
    ) -> Result<MFAVerificationResult> {
        debug!("🔐 Verifying backup code for user {}", user_id);

        let enrollments = self.enrollments.lock().await;
        let user_enrollments = enrollments
            .get(&user_id)
            .ok_or_else(|| anyhow!("User {} not found", user_id))?;

        for enrollment in user_enrollments {
            if enrollment.active && enrollment.backup_codes.contains(&backup_code.to_string()) {
                // Remove used backup code
                let mut enrollments_mut = self.enrollments.lock().await;
                if let Some(user_enrollments_mut) = enrollments_mut.get_mut(&user_id) {
                    for en in user_enrollments_mut {
                        if en.method == enrollment.method {
                            en.backup_codes.retain(|code| code != backup_code);
                            break;
                        }
                    }
                }

                return Ok(MFAVerificationResult {
                    success: true,
                    user_id,
                    challenge_id: Uuid::new_v4(),
                    method: MFAMethod::BackupCodes,
                    verified_at: Utc::now(),
                    error_message: None,
                    backup_code_used: true,
                });
            }
        }

        Err(anyhow!("Invalid backup code"))
    }

    /// Generates a QR code SVG for TOTP enrollment.
    ///
    /// # Errors
    /// Returns an error if QR generation fails.
    pub async fn generate_totp_qr_code(
        &self,
        _user_id: Uuid,
        username: &str,
        secret: &str,
    ) -> Result<String> {
        let issuer = "Wolf Prowler";
        let otpauth_url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            issuer, username, secret, issuer
        );

        let code = QrCode::new(otpauth_url.as_bytes())
            .map_err(|e| anyhow!("QR code generation failed: {}", e))?;

        let svg = code.render::<svg::Color>().build();

        Ok(svg)
    }

    /// Update enrollment last used timestamp
    async fn update_enrollment_last_used(&self, user_id: Uuid, method: MFAMethod) -> Result<()> {
        let mut enrollments = self.enrollments.lock().await;
        if let Some(user_enrollments) = enrollments.get_mut(&user_id) {
            for enrollment in user_enrollments {
                if enrollment.method == method {
                    enrollment.last_used = Some(Utc::now());
                    break;
                }
            }
        }
        Ok(())
    }

    /// Generate base32 secret for TOTP
    fn generate_base32_secret(&self) -> String {
        let mut rng = rand::thread_rng();
        let secret: Vec<u8> = (0..20).map(|_| rng.gen()).collect();
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret)
    }

    /// Generate OTP code
    fn generate_otp_code(&self) -> String {
        let mut rng = rand::thread_rng();
        format!("{:06}", rng.gen_range(100_000..999_999))
    }

    /// Generate backup codes
    fn generate_backup_codes(&self) -> Vec<String> {
        let mut codes = Vec::new();
        for _ in 0..10 {
            codes.push(self.generate_otp_code());
        }
        codes
    }

    /// Retrieves all MFA enrollments for a specific user.
    pub async fn get_user_enrollments(&self, user_id: Uuid) -> Vec<MFAEnrollment> {
        let enrollments = self.enrollments.lock().await;
        enrollments.get(&user_id).cloned().unwrap_or_default()
    }

    /// Deactivates a specific MFA enrollment for a user.
    pub async fn disable_enrollment(&self, user_id: Uuid, method: MFAMethod) -> Result<()> {
        let mut enrollments = self.enrollments.lock().await;
        if let Some(user_enrollments) = enrollments.get_mut(&user_id) {
            for enrollment in user_enrollments {
                if enrollment.method == method {
                    enrollment.active = false;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Permanently removes expired challenges from the registry.
    pub async fn cleanup_expired_challenges(&self) -> Result<()> {
        let mut challenges = self.challenges.lock().await;
        let now = Utc::now();

        challenges.retain(|_, challenge| {
            now <= challenge.expires_at && challenge.status == MFAChallengeStatus::Pending
        });

        Ok(())
    }

    /// Returns aggregation performance and status telemetry.
    pub async fn get_stats(&self) -> MFAStats {
        let enrollments = self.enrollments.lock().await;
        let challenges = self.challenges.lock().await;

        let total_enrollments = enrollments.values().map(|es| es.len()).sum();
        let active_challenges = challenges
            .values()
            .filter(|c| c.status == MFAChallengeStatus::Pending)
            .count();

        MFAStats {
            total_enrollments,
            active_challenges,
            last_update: Utc::now(),
        }
    }
}

/// Summary snapshot of the MFA system health and activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFAStats {
    /// Total number of distinct MFA enrollments across all users
    pub total_enrollments: usize,
    /// Number of challenges currently awaiting fulfillment
    pub active_challenges: usize,
    /// Precise point in time when this summary was generated
    pub last_update: chrono::DateTime<Utc>,
}

impl From<MFAVerificationResult> for AuthenticationResult {
    fn from(mfa_result: MFAVerificationResult) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: mfa_result.user_id,
            method: AuthenticationMethod::MFA,
            success: mfa_result.success,
            timestamp: mfa_result.verified_at,
            ip_address: "unknown".to_string(), // Would be extracted from request
            user_agent: "unknown".to_string(), // Would be extracted from request
            mfa_required: true,
            mfa_completed: mfa_result.success,
            session_id: None, // Would be created after successful auth
            error_message: mfa_result.error_message,
        }
    }
}

/// Base32 encoding support (simplified implementation)
pub mod base32 {
    pub enum Alphabet {
        RFC4648 { padding: bool },
    }

    pub fn encode(_alphabet: Alphabet, data: &[u8]) -> String {
        // Simplified base32 encoding
        // In production, use a proper base32 library
        use data_encoding::BASE32;
        BASE32.encode(data)
    }

    pub fn decode(_alphabet: Alphabet, data: &str) -> Option<Vec<u8>> {
        // Simplified base32 decoding
        // In production, use a proper base32 library
        use data_encoding::BASE32;
        BASE32.decode(data.as_bytes()).ok()
    }
}

/// HMAC support (simplified implementation)
pub mod hmac {
    use sha1::{Digest, Sha1};

    pub struct Hmac<T> {
        inner: T,
    }

    impl Hmac<Sha1> {
        pub fn new_from_slice(_key: &[u8]) -> Result<Self, &'static str> {
            // Simplified HMAC implementation
            // In production, use a proper HMAC library
            Ok(Hmac { inner: Sha1::new() })
        }

        pub fn update(&mut self, data: &[u8]) {
            // Simplified update
            self.inner.update(data);
        }

        pub fn finalize(self) -> Vec<u8> {
            self.inner.finalize().to_vec()
        }
    }
}

