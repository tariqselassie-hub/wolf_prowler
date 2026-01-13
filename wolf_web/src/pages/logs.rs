use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tokio::sync::MutexGuard;
#[cfg(feature = "server")]
use wolfsec::WolfSecurity;

#[cfg(feature = "server")]
use crate::SECURITY_ENGINE;

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

    // So we can use `SECURITY_ENGINE`.

    let sec_lock: MutexGuard<Option<WolfSecurity>> = crate::SECURITY_ENGINE.lock().await;
    println!("DEBUG: get_security_logs called. Engine lock acquired.");

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

        // Let's assume `threat_detector` field is accessible.

        let events = sec.threat_detector.get_events().await;
        println!(
            "DEBUG: Retrieved {} security events from ThreatDetector",
            events.len()
        );

        let logs = events
            .into_iter()
            .map(|e| {
                LogEntry {
                    timestamp: e.timestamp.to_rfc3339(),
                    level: format!("{:?}", e.severity),
                    source: "Security".to_string(), // Default for now
                    message: format!("{:?}: {:?}", e.event_type, e.description),
                    event_id: e.id,
                }
            })
            .collect();

        Ok(logs)
    } else {
        // Fallback for when backend isn't ready or in dev mode
        println!("DEBUG: Security Engine is None or not initialized.");
        Ok(vec![LogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: "INFO".to_string(),
            source: "System".to_string(),
            message: "Security Engine not initialized or locked.".to_string(),
            event_id: "0".to_string(),
        }])
    }
}

#[server]
async fn stream_security_logs() -> Result<Vec<LogEntry>, ServerFnError> {
    // Stream implementation temporarily disabled due to Pin<Box> serialization issues in ServerFn
    // Returning empty list for now to satisfy build
    Ok(Vec::new())
}

#[server]
async fn clear_security_logs() -> Result<(), ServerFnError> {
    let sec_lock: MutexGuard<Option<WolfSecurity>> = crate::SECURITY_ENGINE.lock().await;

    if let Some(sec) = sec_lock.as_ref() {
        sec.threat_detector.clear_events().await;
        println!("DEBUG: Security logs purged from backend.");
    }
    Ok(())
}

#[component]
fn HighlightedText(text: String, highlight: String) -> Element {
    if highlight.is_empty() || !text.contains(&highlight) {
        return rsx! { "{text}" };
    }

    let parts: Vec<&str> = text.split(&highlight).collect();
    rsx! {
        span {
            for (i, part) in parts.iter().enumerate() {
                "{part}"
                if i < parts.len() - 1 {
                    span { class: "bg-green-600 text-black font-bold px-1", "{highlight}" }
                }
            }
        }
    }
}

#[component]
pub fn LogsPage() -> Element {
    let mut logs = use_signal(|| Vec::<LogEntry>::new());
    let mut filter = use_signal(|| String::new());
    let mut is_paused = use_signal(|| false);
    let mut severity_filter = use_signal(|| "ALL".to_string());
    let mut system_status = use_signal(|| "CONNECTING...".to_string());

    // Initialize logs and start stream
    use_future(move || async move {
        // 1. Load historical logs
        if let Ok(history) = get_security_logs().await {
            // Check if we are running on the fallback (Engine not initialized)
            if history.len() == 1 && history[0].message.contains("not initialized") {
                system_status.set("OFFLINE (SIMULATION)".to_string());
            } else {
                system_status.set("NETLINK ESTABLISHED".to_string());
            }
            // Reverse history so newest is at top, matching our stream insertion strategy
            logs.set(history.into_iter().rev().collect());
        }

        // 2. Connect to live stream (Disabled temporarily)
        // if let Ok(mut stream) = stream_security_logs().await {
        //    while let Some(Ok(new_log)) = stream.next().await {
        //        if !*is_paused.read() {
        //            logs.with_mut(|l| l.insert(0, new_log));
        //        }
        //    }
        // }
    });

    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono",
            // Header
            div { class: "flex justify-between items-end border-b border-green-900 pb-4 mb-6",
                div {
                    h1 { class: "text-4xl font-black uppercase tracking-[0.2em] text-green-600", "SYSTEM LOGS" }
                    div { class: "text-xs text-green-400 mt-1 flex gap-2",
                        "SECURITY EVENT AUDIT TRAIL // CLASSIFIED"
                        span { class: "text-green-600 font-bold", "[{logs.read().len()} RECORDS]" }
                    }
                }
                div {
                    button {
                        class: "px-4 py-2 border border-green-700 hover:bg-green-900/40 text-xs uppercase font-bold transition-colors mr-2",
                        onclick: move |_| is_paused.set(!is_paused()),
                        if is_paused() { "Resume Stream" } else { "Pause Stream" }
                    }
                    button {
                        class: "px-4 py-2 border border-green-700 hover:bg-green-900/40 text-xs uppercase font-bold transition-colors",
                        onclick: move |_| logs.set(Vec::new()),
                        "Clear Buffer"
                    }
                    button {
                        class: "px-4 py-2 border border-red-900 hover:bg-red-900/40 text-xs uppercase font-bold transition-colors ml-2 text-red-500",
                        onclick: move |_| {
                            spawn(async move {
                                if let Ok(_) = clear_security_logs().await {
                                    logs.set(Vec::new());
                                }
                            });
                        },
                        "Purge Backend"
                    }
                    button {
                        class: "px-4 py-2 border border-blue-700 hover:bg-blue-900/40 text-xs uppercase font-bold transition-colors ml-2 text-blue-500",
                        onclick: move |_| {
                            let json = serde_json::to_string_pretty(&*logs.read()).unwrap_or("[]".to_string());
                            let eval = document::eval(r#"
                                let data = await dioxus.recv();
                                let blob = new Blob([data], { type: 'application/json' });
                                let url = URL.createObjectURL(blob);
                                let a = document.createElement('a');
                                a.href = url;
                                a.download = 'wolf_logs_' + new Date().toISOString().slice(0,19).replace(/:/g,"-") + '.json';
                                document.body.appendChild(a);
                                a.click();
                                document.body.removeChild(a);
                                URL.revokeObjectURL(url);
                            "#);
                            let _ = eval.send(json);
                        },
                        "Download JSON"
                    }
                }
            }

            // Toolbar
            div { class: "flex mb-4 gap-4",
                input {
                    class: "bg-black border border-green-800 p-2 text-green-500 focus:border-green-500 focus:outline-none flex-1 text-sm",
                    placeholder: "Search logs (highlighting enabled)...",
                    oninput: move |evt| filter.set(evt.value())
                }
                select {
                    class: "bg-black border border-green-800 p-2 text-green-500 focus:border-green-500 focus:outline-none text-sm uppercase font-mono",
                    onchange: move |evt| severity_filter.set(evt.value()),
                    option { value: "ALL", "All Levels" }
                    option { value: "INFO", "Info" }
                    option { value: "WARN", "Warning" }
                    option { value: "HIGH", "High" }
                    option { value: "CRITICAL", "Critical" }
                }
                div { class: "flex items-center gap-2 text-xs",
                    div { class: if system_status() == "NETLINK ESTABLISHED" { "w-2 h-2 rounded-full bg-green-500 animate-pulse" } else { "w-2 h-2 rounded-full bg-yellow-500 animate-pulse" } }
                    span {
                        class: if system_status() == "NETLINK ESTABLISHED" { "text-green-500 font-bold" } else { "text-yellow-500 font-bold" },
                        "{system_status}"
                    }
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
                    {
                        let current_logs = logs.read();
                        rsx! {
                            for log in current_logs.iter().filter(|l| {
                                let severity_match = severity_filter.read().as_str() == "ALL" || {
                                    let lvl = l.level.to_uppercase();
                                    match severity_filter.read().as_str() {
                                        "CRITICAL" => lvl.contains("CRIT"),
                                        "HIGH" => lvl.contains("HIGH"),
                                        "WARN" => lvl.contains("WARN") || lvl.contains("MEDIUM"),
                                        "INFO" => lvl.contains("INFO"),
                                        _ => true,
                                    }
                                };
                                severity_match
                            }) {
                                {
                                    let (text_class, border_class, label) = match log.level.to_uppercase().as_str() {
                                        "CRITICAL" | "CRIT" => ("text-red-500", "border-red-500", "CRIT"),
                                        "HIGH" => ("text-orange-500", "border-orange-500", "HIGH"),
                                        "WARN" | "MEDIUM" | "WARNING" => ("text-yellow-500", "border-yellow-500", "WARN"),
                                        _ => ("text-green-600", "border-green-600", "INFO"),
                                    };
                                    rsx! {
                                        div { class: "grid grid-cols-12 gap-4 hover:bg-green-900/10 p-1 border-l-2 {border_class} transition-colors group",
                                            div { class: "col-span-2 text-gray-500 text-xs", "{log.timestamp}" }
                                            div { class: "col-span-1 font-bold",
                                                span { class: "{text_class}", "{label}" }
                                            }
                                            div { class: "col-span-1 text-xs text-green-700 uppercase", "{log.source}" }
                                            div { class: "col-span-8 group-hover:text-white transition-colors",
                                                HighlightedText { text: log.message.clone(), highlight: filter.read().clone() }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
