use anyhow::Result;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// Service for sending recovery keys via email
pub struct EmailBackup;

impl EmailBackup {
    /// Sends a recovery key blob to the specified email address
    ///
    /// # Errors
    ///
    /// Returns an error if the email message cannot be built, if SMTP transport fails, or if address parsing fails.
    #[allow(clippy::cognitive_complexity)]
    pub async fn send_recovery_key(
        email: &str,
        encrypted_blob_b64: &str,
        smtp_config: Option<(String, String, String)>, // (server, user, pass)
    ) -> Result<()> {
        let body = format!(
            "Welcome to WolfDb.\n\n\
            Your PQC Recovery Key (Encrypted) is attached below.\n\n\
            --- RECOVERY BLOB START ---\n\
            {encrypted_blob_b64}\n\
            --- RECOVERY BLOB END ---\n\n\
            Keep this safe. It is required to recover your database if you lose your master password.\n\
            The blob itself is encrypted with your Recovery Password."
        );

        let email_msg = Message::builder()
            .from("WolfDb Backup <backup@wolfdb.local>".parse()?)
            .to(email.parse()?)
            .subject("WolfDb PQC Recovery Key")
            .body(body.clone())?;

        if let Some((server, user, pass)) = smtp_config {
            let creds = Credentials::new(user, pass);
            let transport: AsyncSmtpTransport<Tokio1Executor> =
                AsyncSmtpTransport::<Tokio1Executor>::relay(&server)?
                    .credentials(creds)
                    .build();
            transport.send(email_msg).await?;
            tracing::info!("{}", "✔ Recovery email sent via SMTP.".bright_green());
        } else {
            // Simulation Mode
            tracing::info!(
                "\n{}",
                "--- EMAIL SIMULATION MODE ---".bright_yellow().bold()
            );
            tracing::info!("To: {}", email.bright_white());
            tracing::info!("Subject: WolfDb PQC Recovery Key");
            tracing::info!("Body: \n{body}");
            tracing::info!("{}", "--- END OF SIMULATION ---".bright_yellow().bold());
            tracing::info!(
                "{}",
                "✔ Recovery email generated (Simulation Mode).".bright_green()
            );
        }

        Ok(())
    }
}
