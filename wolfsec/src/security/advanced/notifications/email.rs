use super::*;
use lettre::{Message, AsyncSmtpTransport, Tokio1Executor, AsyncTransport};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;

pub struct EmailSender {
    config: EmailConfig,
}

impl EmailSender {
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NotificationSender for EmailSender {
    async fn send(&self, title: &str, message: &str, metadata: &NotificationMetadata) -> Result<()> {
        if self.config.to_addresses.is_empty() {
            return Ok(());
        }

        let mut email_builder = Message::builder()
            .from(self.config.from_address.parse::<Mailbox>()?)
            .subject(format!("Security Alert: {}", title));

        for to in &self.config.to_addresses {
            email_builder = email_builder.to(to.parse::<Mailbox>()?);
        }

        let mut body = format!(
            "Security Alert\n\nTitle: {}\n\n{}\n\nTime: {}\n\nMetadata:\n",
            title,
            message,
            chrono::Utc::now().to_rfc3339()
        );

        for (key, value) in metadata {
            body.push_str(&format!("{}: {}\n", key, value));
        }

        let email = email_builder.body(body)?;

        // Configure transport
        let mut mailer_builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.smtp_server)?
            .port(self.config.smtp_port);

        if !self.config.username.is_empty() && !self.config.password.is_empty() {
            let creds = Credentials::new(self.config.username.clone(), self.config.password.clone());
            mailer_builder = mailer_builder.credentials(creds);
        }

        let mailer = mailer_builder.build();

        mailer.send(email).await?;
        Ok(())
    }

    fn name(&self) -> &str {
        "Email"
    }
}
