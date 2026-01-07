use anyhow::Result;
use colored::*;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub struct EmailBackup;

impl EmailBackup {
    pub async fn send_recovery_key(
        email: &str,
        encrypted_blob_b64: &str,
        smtp_config: Option<(String, String, String)>, // (server, user, pass)
    ) -> Result<()> {
        let body = format!(
            "Welcome to WolfDb.\n\n\
            Your PQC Recovery Key (Encrypted) is attached below.\n\n\
            --- RECOVERY BLOB START ---\n\
            {}\n\
            --- RECOVERY BLOB END ---\n\n\
            Keep this safe. It is required to recover your database if you lose your master password.\n\
            The blob itself is encrypted with your Recovery Password.",
            encrypted_blob_b64
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
            println!("{}", "✔ Recovery email sent via SMTP.".bright_green());
        } else {
            // Simulation Mode
            println!(
                "\n{}",
                "--- EMAIL SIMULATION MODE ---".bright_yellow().bold()
            );
            println!("To: {}", email.bright_white());
            println!("Subject: WolfDb PQC Recovery Key");
            println!("Body: \n{}", body);
            println!("{}\n", "--- END OF SIMULATION ---".bright_yellow().bold());
            println!(
                "{}",
                "✔ Recovery email generated (Simulation Mode).".bright_green()
            );
        }

        Ok(())
    }
}
