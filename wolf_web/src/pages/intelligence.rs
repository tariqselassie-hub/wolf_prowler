use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::MutexGuard;
#[cfg(feature = "server")]
use wolfsec::WolfSecurity;

use crate::dashboard::api::server_fns::get_wolfpack_data;
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
    let sec_lock = SECURITY_ENGINE.lock().await;
    if let Some(sec_arc) = sec_lock.as_ref() {
        let sec = sec_arc.read().await;
        if let Ok(_status) = sec.get_status().await {
            // In a real impl, we would iterate status.threat_detection.active_threats
            // For now, simulating based on security score
        }
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
    let pack_data = use_resource(get_wolfpack_data);

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
                 div { class: "bg-gray-900/50 border border-blue-900/30 p-6 rounded flex flex-col min-h-[400px]",
                    h3 { class: "text-lg font-bold text-gray-400 mb-6 flex items-center gap-2",
                        i { class: "lucide-users" } "PEER REPUTATION REGISTRY"
                    }



                    div { class: "space-y-4 overflow-y-auto max-h-[500px] pr-2 custom-scrollbar",
                        match &*pack_data.read_unchecked() {
                            Some(Ok(telemetry)) => rsx! {
                                for peer in telemetry.peers.iter() {
                                    div { key: "{peer.id}", class: "p-4 bg-black/40 rounded border border-blue-900/20 hover:border-blue-500/50 transition-colors",
                                        div { class: "flex justify-between items-start mb-2",
                                            div {
                                                div { class: "font-mono text-xs text-blue-400 mb-1", "{peer.id}" }
                                                div { class: "flex items-center gap-2",
                                                    span { class: "px-2 py-0.5 text-[10px] bg-blue-900/30 text-blue-300 rounded uppercase font-bold", "{peer.reputation_tier}" }
                                                    span { class: "text-xs text-gray-500", "RTT: {peer.rtt_ms}ms" }
                                                }
                                            }
                                            div { class: "text-right",
                                                div {
                                                    class: if peer.reputation >= 0.7 { "text-green-500" } else if peer.reputation >= 0.4 { "text-yellow-500" } else { "text-red-500" },
                                                    class: "text-xl font-bold font-mono",
                                                    "{peer.reputation:.2}"
                                                }
                                                div { class: "text-[10px] text-gray-600 uppercase", "Reputation Score" }
                                            }
                                        }
                                        // Visual Score Bar
                                        div { class: "w-full h-1 bg-gray-800 rounded-full overflow-hidden",
                                            div {
                                                class: if peer.reputation >= 0.7 { "bg-green-500" } else if peer.reputation >= 0.4 { "bg-yellow-500" } else { "bg-red-500" },
                                                style: "width: {peer.reputation * 100.0}%",
                                                class: "h-full transition-all duration-500"
                                            }
                                        }
                                    }
                                }
                                if telemetry.peers.is_empty() {
                                    div { class: "flex flex-col items-center justify-center h-full text-gray-600 space-y-4 py-12",
                                        i { class: "lucide-globe w-12 h-12 opacity-20" }
                                        div { class: "font-mono text-sm", "NO EXTERNAL PERSPECTIVES DETECTED" }
                                    }
                                }
                            },
                             _ => rsx! {
                                div { class: "flex items-center justify-center h-full",
                                    div { class: "animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" }
                                }
                             }
                        }
                    }
                 }
            }
        }
    }
}
