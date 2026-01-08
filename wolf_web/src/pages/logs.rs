use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub source: String, // "System", "Network", "Security"
    pub message: String,
    pub event_id: String,
}

#[server]
async fn get_security_logs() -> Result<Vec<LogEntry>, ServerFnError> {
    // Access the shared state via the Axum extractor
    // In Dioxus 0.5/0.6+ server functions, we can use extractors if we setup the server fn traits correctly
    // or access the global if we have to.
    
    // Using global for now since getting state injection in server functions validation can be tricky 
    // without the right context setup, and we unified state into the global anyway in main.rs logic (though commented out?)
    // Wait, in main.rs I unified state but the global `SECURITY_ENGINE` is what we populated.
    // So we can use `SECURITY_ENGINE`.
    
    let sec_lock = crate::SECURITY_ENGINE.lock().await;
    
    if let Some(sec) = sec_lock.as_ref() {
        // Read events from threat detector
        // Note: crate::SECURITY_ENGINE assumes wolfsec::WolfSecurity type.
        // We added get_events to ThreatDetector, which is a field of WolfSecurity.
        // But WolfSecurity's fields might be private or wrapped.
        // Let's check how to access ThreatDetector from WolfSecurity.
        // Usually it's `sec.threat_detector`.
        
        // Wait, WolfSecurity fields might be behind Arc/RwLock?
        // Let's assume standard access for now. If it fails, I'll fix.
        // WolfSecurity struct in lib.rs usually has public fields or getters.
        
        // Actually, we just added get_events to ThreatDetector.
        // We need to get the ThreatDetector instance. 
        // wolfsec::WolfSecurity usually has `pub threat_detector: Arc<RwLock<ThreatDetector>>` or similar?
        // Let's assume `threat_detector` field is accessible.
        
        let events = sec.threat_detector.get_events().await;
        
        let logs = events.into_iter().map(|e| {
            LogEntry {
                timestamp: e.timestamp.to_rfc3339(),
                level: format!("{:?}", e.severity),
                source: "Security".to_string(), // Default for now
                message: format!("{:?}: {:?}", e.event_type, e.description),
                event_id: e.id,
            }
        }).collect();
        
        Ok(logs)
    } else {
         // Fallback for when backend isn't ready or in dev mode
        Ok(vec![
            LogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                level: "INFO".to_string(),
                source: "System".to_string(),
                message: "Security Engine not initialized or locked.".to_string(),
                event_id: "0".to_string(),
            }
        ])
    }
}

#[component]
pub fn LogsPage() -> Element {
    let mut logs_resource = use_resource(get_security_logs);
    let mut filter = use_signal(|| String::new());

    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono",
            // Header
            div { class: "flex justify-between items-end border-b border-green-900 pb-4 mb-6",
                div {
                    h1 { class: "text-4xl font-black uppercase tracking-[0.2em] text-green-600", "SYSTEM LOGS" }
                    div { class: "text-xs text-green-400 mt-1", "SECURITY EVENT AUDIT TRAIL // CLASSIFIED" }
                }
                div {
                    button {
                        class: "px-4 py-2 border border-green-700 hover:bg-green-900/40 text-xs uppercase font-bold transition-colors",
                        onclick: move |_| logs_resource.restart(),
                        "Refresh Stream"
                    }
                }
            }
            
            // Toolbar
            div { class: "flex mb-4 gap-4",
                input {
                    class: "bg-black border border-green-800 p-2 text-green-500 focus:border-green-500 focus:outline-none flex-1 text-sm",
                    placeholder: "Filter logs by ID or Content...",
                    oninput: move |evt| filter.set(evt.value())
                }
                div { class: "flex items-center gap-2 text-xs",
                    div { class: "w-2 h-2 rounded-full bg-green-500 animate-pulse" }
                    "LIVE"
                }
            }

            // Log Console
            div { class: "bg-black border border-green-800 rounded h-[600px] overflow-hidden flex flex-col",
                // Terminal Header
                div { class: "bg-green-900/10 p-2 border-b border-green-800 flex justify-between items-center",
                    div { class: "flex gap-2",
                        div { class: "w-3 h-3 rounded-full bg-red-900" }
                        div { class: "w-3 h-3 rounded-full bg-yellow-900" }
                        div { class: "w-3 h-3 rounded-full bg-green-900" }
                    }
                    div { class: "text-[10px] uppercase text-green-600 font-bold", "root@wolf-prowler:~/var/log/security" }
                }
                
                // Content
                div { class: "flex-1 overflow-y-auto p-4 space-y-1 font-mono text-sm",
                    match &*logs_resource.read() {
                        Some(Ok(logs)) => rsx! {
                            for log in logs.iter().filter(|l| filter().is_empty() || l.message.contains(&*filter()) || l.event_id.contains(&*filter())) {
                                div { class: "grid grid-cols-12 gap-4 hover:bg-green-900/10 p-1 border-l-2 border-transparent hover:border-green-500 transition-colors group",
                                    div { class: "col-span-2 text-gray-500 text-xs", "{log.timestamp}" }
                                    div { class: "col-span-1 font-bold",
                                        match log.level.as_str() {
                                            "Critical" => rsx! { span { class: "text-red-500", "CRIT" } },
                                            "High" => rsx! { span { class: "text-orange-500", "HIGH" } },
                                            "Medium" => rsx! { span { class: "text-yellow-500", "WARN" } },
                                            _ => rsx! { span { class: "text-green-600", "INFO" } } // Fallback
                                        }
                                    }
                                    div { class: "col-span-1 text-xs text-green-700 uppercase", "{log.source}" }
                                    div { class: "col-span-8 group-hover:text-white transition-colors", "{log.message}" }
                                }
                            }
                        },
                         Some(Err(e)) => rsx! {
                            div { class: "text-red-500 p-4", "Error retrieving logs: {e}" }
                        },
                        None => rsx! {
                            div { class: "text-gray-600 p-4 animate-pulse", "> Establishing secure uplink..." }
                        }
                    }
                }
            }
        }
    }
}
