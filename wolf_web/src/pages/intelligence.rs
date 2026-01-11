use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::MutexGuard;
#[cfg(feature = "server")]
use wolfsec::WolfSecurity;

#[cfg(feature = "server")]
use crate::SECURITY_ENGINE;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatItem {
    pub id: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub timestamp: String,
}

#[server]
async fn get_intelligence_data() -> Result<Vec<ThreatItem>, ServerFnError> {
    let mut threats = Vec::new();

    // Simulate some threats or fetch from WolfSec
    let sec_lock: MutexGuard<Option<WolfSecurity>> = SECURITY_ENGINE.lock().await;
    if let Some(sec) = sec_lock.as_ref() {
        let _status = sec.get_status().await;
        // In a real impl, we would iterate status.threat_detection.active_threats
        // For now, simulating based on security score
    }

    threats.push(ThreatItem {
        id: "THR-2026-001".to_string(),
        severity: "LOW".to_string(),
        source: "192.168.1.105".to_string(),
        description: "Port scan detected".to_string(),
        timestamp: chrono::Local::now().to_string(),
    });

    Ok(threats)
}

#[component]
pub fn IntelligencePage() -> Element {
    let threats = use_resource(get_intelligence_data);

    rsx! {
        div { class: "p-8 space-y-8",
            h1 { class: "text-3xl font-bold uppercase tracking-widest text-red-500", "Global Threat Intelligence" }

            div { class: "grid grid-cols-1 lg:grid-cols-2 gap-8",
                 // Active Threats List
                 div { class: "bg-gray-900/50 border border-red-900/30 p-6 rounded",
                    h3 { class: "text-lg font-bold text-gray-400 mb-4 flex items-center gap-2",
                        i { class: "lucide-skull" } "DETECTED HOSTILES"
                    }
                    div { class: "space-y-4",
                        match &*threats.read_unchecked() {
                            Some(Ok(items)) => rsx! {
                                for item in items.iter() {
                                    div { key: "{item.id}", class: "flex items-center justify-between p-4 bg-black/40 rounded border border-red-900/20",
                                        div {
                                            div { class: "font-bold text-red-400", "{item.description}" }
                                            div { class: "text-xs text-gray-500", "{item.source} • {item.timestamp}" }
                                        }
                                        span { class: "px-2 py-1 text-xs font-bold bg-red-900/50 text-red-200 rounded", "{item.severity}" }
                                    }
                                }
                            },
                             _ => rsx! { div { class: "text-gray-500", "Scanning..." } }
                        }
                    }
                 }

                 // Reputation Network Visualization (Placeholder)
                 div { class: "bg-gray-900/50 border border-blue-900/30 p-6 rounded flex flex-col items-center justify-center min-h-[300px]",
                    i { class: "lucide-globe w-24 h-24 text-blue-900/50 mb-4" }
                    div { class: "text-gray-500 font-mono", "NEURAL MAP OFFLINE" }
                    div { class: "text-xs text-gray-600 mt-2", "Connect more peers to visualize swarm topology" }
                 }
            }
        }
    }
}
