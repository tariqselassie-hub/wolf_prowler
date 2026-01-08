use wolf_web::types::SystemStats;
use crate::ui_kit::Card;
use dioxus::prelude::*;

#[component]
pub fn NetworkBanner(stats: SystemStats) -> Element {
    let status_color = if stats.network_status == "ONLINE" {
        "text-green-400 drop-shadow-[0_0_5px_rgba(74,222,128,0.8)]"
    } else {
        "text-red-500 drop-shadow-[0_0_5px_rgba(239,68,68,0.8)]"
    };
    let nodes_color = if stats.active_nodes > 0 {
        "text-green-400"
    } else {
        "text-gray-500"
    };

    rsx! {
        Card {
            // Dynamic Background Grid
            div { class: "absolute inset-0 bg-[linear-gradient(rgba(0,255,0,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,0,0.03)_1px,transparent_1px)] bg-[size:20px_20px] opacity-20" }
            
            h3 { class: "text-lg font-bold mb-4 uppercase flex items-center gap-2 border-b border-green-800/50 pb-2 relative z-10",
                 i { class: "lucide-network text-green-400 animate-pulse" } 
                 span { class: "tracking-widest", "WolfNet Status" }
            }
            div { class: "space-y-4 relative z-10",
                div { class: "flex justify-between items-end",
                    span { class: "text-gray-400 uppercase text-xs tracking-wider", "Connectivity" }
                    span { class: "font-mono font-bold {status_color} text-lg", "{stats.network_status}" }
                }
                div { class: "flex justify-between items-end",
                    span { class: "text-gray-400 uppercase text-xs tracking-wider", "Active Peers" }
                    span { class: "font-mono font-bold {nodes_color} text-2xl drop-shadow-[0_0_8px_rgba(74,222,128,0.3)]", "{stats.active_nodes}" }
                }
            }
            
            // Decorative Data Stream
            if stats.active_nodes > 0 {
                div { class: "absolute bottom-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity",
                    i { class: "lucide-globe w-32 h-32 animate-[spin_10s_linear_infinite]" }
                }
            }
        }
    }
}

#[component]
pub fn SecurityBanner(stats: SystemStats) -> Element {
    let (color, icon, glow_class) = match stats.threat_level.as_str() {
        "LOW" => ("text-green-400", "lucide-shield-check", "shadow-[0_0_15px_rgba(74,222,128,0.2)]"),
        "ELEVATED" => ("text-yellow-400", "lucide-shield-alert", "shadow-[0_0_15px_rgba(250,204,21,0.2)]"),
        "CRITICAL" => ("text-red-500", "lucide-siren", "shadow-[0_0_20px_rgba(239,68,68,0.4)]"),
        _ => ("text-gray-400", "lucide-shield", ""),
    };

    rsx! {
        Card { class: "{glow_class}",
             // Scanline overlay
            div { class: "absolute inset-0 bg-repeat-y opacity-5 pointer-events-none bg-[url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAADCAYAAABS3WWCAAAAE0lEQVQIW2NkQAKrVq36zwjjAwAltoH/h0OBxQAAAABJRU5ErkJggg==')]" }

            h3 { class: "text-lg font-bold mb-4 uppercase flex items-center gap-2 border-b border-green-800/50 pb-2 relative z-10",
                 i { class: "{icon} {color}" } 
                 span { class: "tracking-widest", "Security Level" }
            }
            div { class: "flex items-center justify-between relative z-10",
                 div { class: "text-4xl font-bold {color} tracking-widest drop-shadow-[0_0_10px_currentColor]", "{stats.threat_level}" }
                 div { class: "text-center p-2 bg-gray-900/50 rounded border border-gray-700/50",
                    div { class: "text-2xl font-bold {color} drop-shadow-[0_0_5px_currentColor]", "{stats.active_alerts}" }
                    div { class: "text-[10px] text-gray-500 uppercase tracking-tight", "Active Alerts" }
                 }
            }
             div { class: "mt-4 text-xs text-green-500/70 flex items-center gap-2 font-mono relative z-10",
                 span { class: "relative flex h-2 w-2",
                    span { class: "animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" }
                    span { class: "relative inline-flex rounded-full h-2 w-2 bg-green-500" }
                 }
                 "Heuristics Active"
             }
        }
    }
}

#[component]
pub fn ScannerBanner(stats: SystemStats) -> Element {
    rsx! {
        Card {
             div { class: "absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-green-500/50 to-transparent opacity-50" }

            h3 { class: "text-lg font-bold mb-4 uppercase flex items-center gap-2 border-b border-green-800/50 pb-2",
                 i { class: "lucide-scan-eye text-green-400" } 
                 span { class: "tracking-widest", "Scanner Status" }
            }
            div { class: "space-y-4 font-mono text-sm",
                 div { class: "flex justify-between items-center group/item",
                    span { class: "text-gray-500 uppercase text-xs tracking-wider group-hover/item:text-green-400 transition-colors", "Current Task" }
                    span { class: "text-green-300 drop-shadow-[0_0_2px_rgba(134,239,172,0.5)]", "{stats.scanner_status}" }
                }
                 div { class: "flex justify-between items-center group/item",
                    span { class: "text-gray-500 uppercase text-xs tracking-wider group-hover/item:text-green-400 transition-colors", "Volume Size" }
                    span { class: "text-gray-300", "{stats.volume_size}" }
                }
                 div { class: "flex justify-between items-center group/item",
                    span { class: "text-gray-500 uppercase text-xs tracking-wider group-hover/item:text-green-400 transition-colors", "Integrity" }
                    div { class: "flex items-center gap-2",
                        div { class: "w-16 h-1 bg-gray-800 rounded-full overflow-hidden",
                            div { class: "h-full bg-green-500 shadow-[0_0_5px_#22c55e]", style: "width: {stats.encrypted_sectors}%" }
                        }
                        span { class: "text-green-400 font-bold", "{stats.encrypted_sectors}%" }
                    }
                }
            }
        }
    }
}
