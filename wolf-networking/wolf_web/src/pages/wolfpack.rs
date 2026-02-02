#![allow(non_snake_case)]
use crate::ui_kit::{Badge, Card};
use crate::Route;
use dioxus::prelude::*;
use wolf_web::dashboard::api::server_fns::get_wolfpack_data;

#[component]
pub fn WolfPackPage() -> Element {
    let mut telemetry_resource = use_resource(get_wolfpack_data);

    // Auto-refresh
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            telemetry_resource.restart();
        }
    });

    rsx! {
        div { class: "min-h-screen bg-black text-blue-500 p-8 font-mono",
            Link { to: Route::Dashboard {}, class: "mb-8 inline-block hover:underline", "< RETURN TO HUD" }

            div { class: "flex justify-between items-center mb-8",
                div {
                    h1 { class: "text-4xl font-black uppercase tracking-widest text-blue-500", "WolfPack" }
                    div { class: "text-xs text-blue-400/60 mt-1 uppercase tracking-widest", "Distributed Consensus & Hunting Grid" }
                }
                div { class: "flex gap-4 items-center",
                    match &*telemetry_resource.read_unchecked() {
                        Some(Ok(data)) => rsx! {
                            div { class: "text-right",
                                div { class: "text-xs text-gray-500 uppercase", "Your Rank" }
                                div { class: "text-xl font-bold text-white", "{data.role}" }
                            }
                            div { class: "text-right",
                                div { class: "text-xs text-gray-500 uppercase", "Prestige" }
                                div { class: "text-xl font-bold text-yellow-500", "{data.prestige}" }
                            }
                        },
                        _ => rsx! { div { class: "animate-pulse", "Syncing..." } }
                    }
                }
            }

            match &*telemetry_resource.read_unchecked() {
                Some(Ok(data)) => rsx! {
                    div { class: "grid grid-cols-1 lg:grid-cols-3 gap-8",
                        // 1. Consensus State
                        Card { class: "lg:col-span-1",
                            h3 { class: "text-lg font-bold mb-4 uppercase border-b border-blue-900/50 pb-2 flex items-center gap-2",
                                i { class: "lucide-vote text-blue-400" } "Raft Consensus"
                            }
                            div { class: "space-y-4",
                                div { class: "flex justify-between items-center",
                                    span { class: "text-sm text-gray-400", "Node ID" }
                                    span { class: "text-xs font-mono bg-gray-900 px-2 py-1 rounded text-gray-300", "{data.node_id}" }
                                }
                                div { class: "flex justify-between items-center",
                                    span { class: "text-sm text-gray-400", "State" }
                                    Badge { label: data.raft_state.clone(), color: if data.raft_state == "Leader" { "blue".to_string() } else { "green".to_string() } }
                                }
                                div { class: "flex justify-between items-center",
                                    span { class: "text-sm text-gray-400", "Term" }
                                    span { class: "font-bold text-white", "{data.term}" }
                                }
                                div { class: "flex justify-between items-center",
                                    span { class: "text-sm text-gray-400", "Commit Index" }
                                    span { class: "font-bold text-green-400", "#{data.commit_index}" }
                                }
                                div { class: "flex justify-between items-center",
                                    span { class: "text-sm text-gray-400", "Last Heartbeat" }
                                    span { class: "text-xs text-blue-300", "{data.last_heartbeat}" }
                                }
                            }
                        }

                        // 2. Active Hunts (Center Stage)
                        Card { class: "lg:col-span-2 relative overflow-hidden",
                            // Background effect
                            div { class: "absolute top-0 right-0 p-8 opacity-10 pointer-events-none",
                                i { class: "lucide-crosshair w-64 h-64 text-red-500" }
                            }

                            div { class: "flex justify-between items-center border-b border-red-900/30 pb-2 mb-4 relative z-10",
                                h3 { class: "text-lg font-bold uppercase flex items-center gap-2 text-red-400",
                                    i { class: "lucide-sword" } "Active Hunts"
                                }
                                Badge { label: format!("{} ACTIVE", data.active_hunts.len()), color: "red".to_string() }
                            }

                            if data.active_hunts.is_empty() {
                                div { class: "flex flex-col items-center justify-center h-48 text-gray-600 relative z-10",
                                    i { class: "lucide-shield-check w-12 h-12 mb-2 opacity-50" }
                                    "No active threats detected. Territory secure."
                                }
                            } else {
                                div { class: "space-y-4 relative z-10",
                                    for hunt in &data.active_hunts {
                                        div { class: "bg-red-950/20 border border-red-900/50 p-4 rounded hover:bg-red-900/20 transition-colors",
                                            div { class: "flex justify-between items-start mb-2",
                                                div {
                                                    div { class: "font-bold text-white text-lg", "{hunt.target}" }
                                                    div { class: "text-xs text-red-400 uppercase", "ID: {hunt.id}" }
                                                }
                                                Badge { label: hunt.status.clone(), color: "red".to_string() }
                                            }
                                            div { class: "flex justify-between items-end",
                                                div { class: "text-xs text-gray-400", "Confidence: {hunt.confidence * 100.0:.1}%" }
                                                div { class: "w-32 bg-gray-900 h-1 rounded-full overflow-hidden",
                                                    div { class: "h-full bg-red-500", style: "width: {hunt.confidence * 100.0}%" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // 3. Peer Grid
                        Card { class: "lg:col-span-3",
                            h3 { class: "text-lg font-bold mb-4 uppercase border-b border-blue-900/50 pb-2", "Pack Membership" }
                            div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4",
                                for peer in &data.peers {
                                    div { class: "bg-gray-900/50 border border-gray-800 p-3 rounded hover:border-blue-500/50 transition-colors group",
                                        div { class: "flex justify-between items-start mb-2",
                                            div {
                                                div { class: "font-bold text-sm text-gray-300 group-hover:text-white truncate", "{peer.id}" }
                                                div { class: "text-[10px] text-gray-500 uppercase", "{peer.role}" }
                                            }
                                            div { class: if peer.status == "Active" { "w-2 h-2 rounded-full bg-green-500 shadow-[0_0_5px_#22c55e]" } else { "w-2 h-2 rounded-full bg-gray-500" } }
                                        }
                                        div { class: "flex justify-between items-center text-xs mt-2",
                                            span { class: "text-gray-600", "Latency" }
                                            span { class: if peer.rtt_ms < 50 { "text-green-400" } else { "text-yellow-400" }, "{peer.rtt_ms}ms" }
                                        }
                                    }
                                }
                                if data.peers.is_empty() {
                                    div { class: "col-span-4 text-center py-8 text-gray-600", "No peers connected. Operating in localized mode." }
                                }
                            }
                        }
                    }
                },
                _ => rsx! {
                    div { class: "flex items-center justify-center h-64",
                        div { class: "animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" }
                    }
                }
            }
        }
    }
}
