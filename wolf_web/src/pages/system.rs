use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::MutexGuard;
#[cfg(feature = "server")]
use wolfsec::WolfSecurity;

#[cfg(feature = "server")]
use crate::SECURITY_ENGINE;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub source: String,
    pub message: String,
}

#[server]
async fn get_system_logs() -> Result<Vec<LogEntry>, ServerFnError> {
    // In a real scenario, we'd fetch from a log file or ring buffer
    // For now, we simulate recent logs based on system state
    let mut logs = Vec::new();
    let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();

    logs.push(LogEntry {
        timestamp: timestamp.clone(),
        level: "INFO".to_string(),
        source: "WolfNet".to_string(),
        message: "Peer discovery active. Swarm telemetry stable.".to_string(),
    });

    let sec_lock: MutexGuard<Option<WolfSecurity>> = SECURITY_ENGINE.lock().await;
    if let Some(sec) = sec_lock.as_ref() {
        let status = sec.get_status().await;
        logs.push(LogEntry {
            timestamp: timestamp.clone(),
            level: "INFO".to_string(),
            source: "WolfSec".to_string(),
            message: format!(
                "Threat detection running. Score: {:.1}",
                status.threat_detection.metrics.security_score
            ),
        });
    }

    Ok(logs)
}

#[component]
pub fn SystemPage() -> Element {
    let logs = use_resource(get_system_logs);

    rsx! {
        div { class: "p-8 space-y-8",
            // Header
            div { class: "flex justify-between items-center",
                h1 { class: "text-3xl font-bold uppercase tracking-widest text-blue-500", "System Telemetry" }
                div { class: "flex gap-2",
                    button { class: "px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded",
                        "EXPORT LOGS"
                    }
                    button { class: "px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-white font-bold",
                        "RUN DIAGNOSTICS"
                    }
                }
            }

            // Metrics Grid
            div { class: "grid grid-cols-1 lg:grid-cols-3 gap-6",
                // CPU / Memory (Simulated)
                div { class: "bg-gray-900/50 border border-blue-900/30 p-6 rounded",
                    h3 { class: "text-lg font-bold text-gray-400 mb-4", "COMPUTE RESOURCES" }
                    div { class: "space-y-4",
                        div {
                            div { class: "flex justify-between mb-1 text-sm", span { "CPU CORE 0" } span { "12%" } }
                            div { class: "h-2 bg-gray-800 rounded overflow-hidden",
                                div { class: "h-full bg-blue-500 w-[12%]" }
                            }
                        }
                        div {
                            div { class: "flex justify-between mb-1 text-sm", span { "MEMORY ALLOCATION" } span { "4.2GB / 16GB" } }
                            div { class: "h-2 bg-gray-800 rounded overflow-hidden",
                                div { class: "h-full bg-purple-500 w-[26%]" }
                            }
                        }
                    }
                }

                // Disk I/O
                div { class: "bg-gray-900/50 border border-blue-900/30 p-6 rounded",
                    h3 { class: "text-lg font-bold text-gray-400 mb-4", "STORAGE I/O" }
                    div { class: "flex items-center justify-center h-full pb-6 text-4xl font-mono text-blue-400",
                        "458 MB/s"
                    }
                }

                // Network Throughput
                 div { class: "bg-gray-900/50 border border-blue-900/30 p-6 rounded",
                    h3 { class: "text-lg font-bold text-gray-400 mb-4", "NETWORK FLUX" }
                     div { class: "flex items-center justify-center h-full pb-6 text-4xl font-mono text-green-400",
                        "1.2 GB/s"
                    }
                }
            }

            // Console / Logs
            div { class: "border border-gray-700 bg-black rounded-lg overflow-hidden",
                div { class: "bg-gray-800 px-4 py-2 text-xs font-mono text-gray-400 flex justify-between",
                    span { "root@wolf-prowler:~# tail -f /var/log/syslog" }
                    span { "LIVE" }
                }
                div { class: "p-4 font-mono text-sm h-96 overflow-y-auto space-y-1",
                    match &*logs.read_unchecked() {
                        Some(Ok(entries)) => rsx! {
                            for log in entries.iter() {
                                div { key: "{log.timestamp}{log.message}", class: "text-gray-300",
                                    span { class: "text-gray-500 mr-2", "[{log.timestamp}]" }
                                    span { class: match log.level.as_str() {
                                        "WARN" => "text-yellow-500 font-bold mr-2",
                                        "ERROR" => "text-red-500 font-bold mr-2",
                                        _ => "text-blue-400 font-bold mr-2"
                                    }, "{log.level}" }
                                    span { class: "text-purple-400 mr-2", "{log.source}:" }
                                    "{log.message}"
                                }
                            }
                        },
                        Some(Err(e)) => rsx! { div { class: "text-red-500", "Failed to load logs: {e}" } },
                        None => rsx! { div { class: "text-gray-500 animate-pulse", "Initializing log stream..." } }
                    }
                }
            }
        }
    }
}
