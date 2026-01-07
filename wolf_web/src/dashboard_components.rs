use crate::SystemStats;
use dioxus::prelude::*;

#[component]
pub fn NetworkBanner(stats: SystemStats) -> Element {
    let status_color = if stats.network_status == "ONLINE" {
        "text-green-400"
    } else {
        "text-red-500"
    };
    let nodes_color = if stats.active_nodes > 0 {
        "text-green-400"
    } else {
        "text-gray-500"
    };

    rsx! {
        div { class: "border border-green-800 bg-gray-900/50 p-6 rounded relative overflow-hidden",
            h3 { class: "text-lg font-bold mb-4 uppercase flex items-center gap-2 border-b border-green-800 pb-2",
                 i { class: "lucide-network" } "WolfNet Status"
            }
            div { class: "space-y-4",
                div { class: "flex justify-between",
                    span { class: "text-gray-400 uppercase text-xs", "Connectivity" }
                    span { class: "font-mono font-bold {status_color}", "{stats.network_status}" }
                }
                div { class: "flex justify-between",
                    span { class: "text-gray-400 uppercase text-xs", "Active Peers" }
                    span { class: "font-mono font-bold {nodes_color} text-xl", "{stats.active_nodes}" }
                }
            }
            if stats.active_nodes > 0 {
                div { class: "absolute bottom-0 right-0 p-4 opacity-10",
                    i { class: "lucide-globe w-24 h-24" }
                }
            }
        }
    }
}

#[component]
pub fn SecurityBanner(stats: SystemStats) -> Element {
    let (color, icon) = match stats.threat_level.as_str() {
        "LOW" => ("text-green-400", "lucide-shield-check"),
        "ELEVATED" => ("text-yellow-400", "lucide-shield-alert"),
        "CRITICAL" => ("text-red-500", "lucide-siren"),
        _ => ("text-gray-400", "lucide-shield"),
    };

    rsx! {
        div { class: "border border-green-800 bg-gray-900/50 p-6 rounded relative overflow-hidden",
            h3 { class: "text-lg font-bold mb-4 uppercase flex items-center gap-2 border-b border-green-800 pb-2",
                 i { class: "{icon}" } "Security Level"
            }
            div { class: "flex items-center justify-between",
                 div { class: "text-4xl font-bold {color} tracking-wider", "{stats.threat_level}" }
                 div { class: "text-center",
                    div { class: "text-2xl font-bold {color}", "{stats.active_alerts}" }
                    div { class: "text-xs text-gray-500 uppercase", "Active Alerts" }
                 }
            }
             div { class: "mt-4 text-xs text-gray-400 flex items-center gap-1",
                 i { class: "lucide-activity w-3 h-3" }
                 "Real-time heuristic analysis active"
             }
        }
    }
}

#[component]
pub fn ScannerBanner(stats: SystemStats) -> Element {
    rsx! {
        div { class: "border border-green-800 bg-gray-900/50 p-6 rounded",
            h3 { class: "text-lg font-bold mb-4 uppercase flex items-center gap-2 border-b border-green-800 pb-2",
                 i { class: "lucide-scan-eye" } "Scanner Status"
            }
            div { class: "space-y-4",
                 div { class: "flex justify-between",
                    span { class: "text-gray-400 uppercase text-xs", "Current Task" }
                    span { class: "font-mono text-green-300", "{stats.scanner_status}" }
                }
                 div { class: "flex justify-between",
                    span { class: "text-gray-400 uppercase text-xs", "Volume Size" }
                    span { class: "font-mono text-gray-300", "{stats.volume_size}" }
                }
                 div { class: "flex justify-between",
                    span { class: "text-gray-400 uppercase text-xs", "Integrity" }
                    span { class: "font-mono text-green-400", "{stats.encrypted_sectors}%" }
                }
            }
        }
    }
}
