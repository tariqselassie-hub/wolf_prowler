use super::{IncidentContext, ResponseAction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Playbook step definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub name: String,
    pub description: String,
    pub action: ResponseAction,
    pub timeout_seconds: u32,
    pub retry_count: u32,
    pub continue_on_failure: bool,
}

/// Playbook definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trigger_conditions: Vec<String>,
    pub steps: Vec<PlaybookStep>,
    pub severity_threshold: f64,
}

/// Playbook library containing standard response playbooks
pub struct PlaybookLibrary {
    playbooks: HashMap<String, Playbook>,
}

impl PlaybookLibrary {
    pub fn new() -> Self {
        let mut library = Self {
            playbooks: HashMap::new(),
        };

        // Register standard playbooks
        library.register_brute_force_playbook();
        library.register_malware_playbook();
        library.register_data_exfiltration_playbook();
        library.register_insider_threat_playbook();

        library
    }

    /// Register brute force attack response playbook
    fn register_brute_force_playbook(&mut self) {
        let playbook = Playbook {
            id: "brute_force_response".to_string(),
            name: "Brute Force Attack Response".to_string(),
            description: "Automated response to brute force authentication attempts".to_string(),
            trigger_conditions: vec![
                "Multiple failed login attempts".to_string(),
                "Account lockout triggered".to_string(),
            ],
            steps: vec![
                PlaybookStep {
                    name: "Block Source IP".to_string(),
                    description: "Block the attacking IP address".to_string(),
                    action: ResponseAction::BlockNetwork,
                    timeout_seconds: 30,
                    retry_count: 3,
                    continue_on_failure: false,
                },
                PlaybookStep {
                    name: "Increase Monitoring".to_string(),
                    description: "Increase monitoring on affected accounts".to_string(),
                    action: ResponseAction::IncreaseMonitoring,
                    timeout_seconds: 10,
                    retry_count: 1,
                    continue_on_failure: true,
                },
                PlaybookStep {
                    name: "Notify Admin".to_string(),
                    description: "Send notification to security team".to_string(),
                    action: ResponseAction::SendNotification,
                    timeout_seconds: 5,
                    retry_count: 2,
                    continue_on_failure: true,
                },
                PlaybookStep {
                    name: "Log Incident".to_string(),
                    description: "Log for forensic investigation".to_string(),
                    action: ResponseAction::LogForInvestigation,
                    timeout_seconds: 5,
                    retry_count: 1,
                    continue_on_failure: false,
                },
            ],
            severity_threshold: 0.7,
        };

        self.playbooks.insert(playbook.id.clone(), playbook);
    }

    /// Register malware detection response playbook
    fn register_malware_playbook(&mut self) {
        let playbook = Playbook {
            id: "malware_response".to_string(),
            name: "Malware Detection Response".to_string(),
            description: "Automated response to malware detection".to_string(),
            trigger_conditions: vec![
                "Malware signature detected".to_string(),
                "Suspicious process behavior".to_string(),
            ],
            steps: vec![
                PlaybookStep {
                    name: "Isolate System".to_string(),
                    description: "Isolate infected system from network".to_string(),
                    action: ResponseAction::IsolateSystem,
                    timeout_seconds: 60,
                    retry_count: 3,
                    continue_on_failure: false,
                },
                PlaybookStep {
                    name: "Quarantine System".to_string(),
                    description: "Move system to quarantine zone".to_string(),
                    action: ResponseAction::QuarantineSystem,
                    timeout_seconds: 30,
                    retry_count: 2,
                    continue_on_failure: false,
                },
                PlaybookStep {
                    name: "Notify Security Team".to_string(),
                    description: "Alert security operations center".to_string(),
                    action: ResponseAction::SendNotification,
                    timeout_seconds: 5,
                    retry_count: 2,
                    continue_on_failure: true,
                },
                PlaybookStep {
                    name: "Log for Forensics".to_string(),
                    description: "Capture system state for analysis".to_string(),
                    action: ResponseAction::LogForInvestigation,
                    timeout_seconds: 10,
                    retry_count: 1,
                    continue_on_failure: false,
                },
            ],
            severity_threshold: 0.9,
        };

        self.playbooks.insert(playbook.id.clone(), playbook);
    }

    /// Register data exfiltration response playbook
    fn register_data_exfiltration_playbook(&mut self) {
        let playbook = Playbook {
            id: "data_exfiltration_response".to_string(),
            name: "Data Exfiltration Response".to_string(),
            description: "Automated response to data exfiltration attempts".to_string(),
            trigger_conditions: vec![
                "Unusual outbound data transfer".to_string(),
                "Sensitive data access anomaly".to_string(),
            ],
            steps: vec![
                PlaybookStep {
                    name: "Block Network".to_string(),
                    description: "Block outbound network connections".to_string(),
                    action: ResponseAction::BlockNetwork,
                    timeout_seconds: 30,
                    retry_count: 3,
                    continue_on_failure: false,
                },
                PlaybookStep {
                    name: "Revoke Access".to_string(),
                    description: "Revoke user access credentials".to_string(),
                    action: ResponseAction::RevokeAccess,
                    timeout_seconds: 20,
                    retry_count: 2,
                    continue_on_failure: false,
                },
                PlaybookStep {
                    name: "Increase Monitoring".to_string(),
                    description: "Enable enhanced monitoring".to_string(),
                    action: ResponseAction::IncreaseMonitoring,
                    timeout_seconds: 10,
                    retry_count: 1,
                    continue_on_failure: true,
                },
                PlaybookStep {
                    name: "Notify Incident Response".to_string(),
                    description: "Alert incident response team".to_string(),
                    action: ResponseAction::SendNotification,
                    timeout_seconds: 5,
                    retry_count: 2,
                    continue_on_failure: true,
                },
            ],
            severity_threshold: 0.95,
        };

        self.playbooks.insert(playbook.id.clone(), playbook);
    }

    /// Register insider threat response playbook
    fn register_insider_threat_playbook(&mut self) {
        let playbook = Playbook {
            id: "insider_threat_response".to_string(),
            name: "Insider Threat Response".to_string(),
            description: "Automated response to insider threat indicators".to_string(),
            trigger_conditions: vec![
                "Privilege escalation attempt".to_string(),
                "Unusual access patterns".to_string(),
            ],
            steps: vec![
                PlaybookStep {
                    name: "Require MFA".to_string(),
                    description: "Require multi-factor authentication".to_string(),
                    action: ResponseAction::RequireMFA,
                    timeout_seconds: 10,
                    retry_count: 1,
                    continue_on_failure: false,
                },
                PlaybookStep {
                    name: "Increase Monitoring".to_string(),
                    description: "Enable enhanced user monitoring".to_string(),
                    action: ResponseAction::IncreaseMonitoring,
                    timeout_seconds: 10,
                    retry_count: 1,
                    continue_on_failure: true,
                },
                PlaybookStep {
                    name: "Notify Security".to_string(),
                    description: "Alert security team for investigation".to_string(),
                    action: ResponseAction::SendNotification,
                    timeout_seconds: 5,
                    retry_count: 2,
                    continue_on_failure: true,
                },
                PlaybookStep {
                    name: "Log Activity".to_string(),
                    description: "Log all user activity for review".to_string(),
                    action: ResponseAction::LogForInvestigation,
                    timeout_seconds: 5,
                    retry_count: 1,
                    continue_on_failure: false,
                },
            ],
            severity_threshold: 0.8,
        };

        self.playbooks.insert(playbook.id.clone(), playbook);
    }

    /// Get a playbook by ID
    pub fn get_playbook(&self, id: &str) -> Option<&Playbook> {
        self.playbooks.get(id)
    }

    /// List all available playbooks
    pub fn list_playbooks(&self) -> Vec<String> {
        self.playbooks.keys().cloned().collect()
    }

    /// Select appropriate playbook based on incident context
    pub fn select_playbook(&self, context: &IncidentContext) -> Option<&Playbook> {
        // Simple selection logic based on event type and severity
        // In a real implementation, this would use more sophisticated matching

        if context.severity_score >= 0.95 {
            self.get_playbook("data_exfiltration_response")
        } else if context.severity_score >= 0.9 {
            self.get_playbook("malware_response")
        } else if context.severity_score >= 0.8 {
            self.get_playbook("insider_threat_response")
        } else if context.severity_score >= 0.7 {
            self.get_playbook("brute_force_response")
        } else {
            None
        }
    }
}
