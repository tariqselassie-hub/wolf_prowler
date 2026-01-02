use std::collections::HashMap;

pub enum NotificationType {
    SecurityAlert,
    SystemHealth,
    ComplianceViolation,
    ThreatDetection,
}

pub struct NotificationTemplate {
    pub subject_template: String,
    pub body_template: String,
}

impl NotificationTemplate {
    pub fn render(&self, data: &HashMap<String, String>) -> (String, String) {
        let mut subject = self.subject_template.clone();
        let mut body = self.body_template.clone();

        for (key, value) in data {
            let placeholder = format!("{{{{{}}}}}", key);
            subject = subject.replace(&placeholder, value);
            body = body.replace(&placeholder, value);
        }

        (subject, body)
    }

    pub fn default_alert() -> Self {
        Self {
            subject_template: "🚨 Wolf Prowler Security Alert: {{{title}}}".to_string(),
            body_template: r#"
Wolf Prowler Security Notification
==================================

Severity: {{{severity}}}
Category: {{{category}}}
Source:   {{{source}}}

Description:
{{{message}}}

Time: {{{timestamp}}}
Alert ID: {{{alert_id}}}

Metadata:
{{{details}}}

--
Wolf Prowler Pack Sentinel
"#.to_string(),
        }
    }
}
