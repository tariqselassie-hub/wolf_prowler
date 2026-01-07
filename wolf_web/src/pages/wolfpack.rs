use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WolfPackTelemetry {
    pub node_id: String,
    pub raft_state: String, // "Leader", "Follower", "Candidate"
    pub term: u64,
    pub commit_index: u64,
    pub last_heartbeat: String,
    pub peers: Vec<PeerStatus>,
    pub network_health: f64, // 0.0 - 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerStatus {
    pub id: String,
    pub status: String, // "Active", "Unknown"
    pub role: String,   // "Voter", "Learner"
    pub rtt_ms: u64,
}

#[server]
async fn get_wolfpack_telemetry() -> Result<WolfPackTelemetry, ServerFnError> {
    // In a real implementation, we would lock PROWLER and read the RaftNode state
    // For now, we simulate a convincing live state

    let state = "Leader"; // Can alternate based on randomness or time
    let term = 6;
    let commit_index = 1042;

    Ok(WolfPackTelemetry {
        node_id: "1976481702526407581".to_string(),
        raft_state: state.to_string(),
        term,
        commit_index,
        last_heartbeat: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
        peers: vec![
            PeerStatus {
                id: "192.168.1.50".to_string(),
                status: "Active".to_string(),
                role: "Voter".to_string(),
                rtt_ms: 12,
            },
            PeerStatus {
                id: "10.0.0.4".to_string(),
                status: "Active".to_string(),
                role: "Voter".to_string(),
                rtt_ms: 45,
            },
            PeerStatus {
                id: "10.0.0.9".to_string(),
                status: "Unknown".to_string(),
                role: "Learner".to_string(),
                rtt_ms: 0,
            },
        ],
        network_health: 0.92,
    })
}

#[component]
pub fn WolfPackPage() -> Element {
    let mut telemetry = use_resource(get_wolfpack_telemetry);

    // Auto-refresh every 2 seconds to simulate "Live" view
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            telemetry.restart();
        }
    });

    rsx! {
        div { class: "p-8 space-y-8 min-h-screen bg-black text-gray-300 font-mono",
            // HUD Header
            div { class: "flex justify-between items-end border-b border-blue-900/50 pb-4",
                div {
                    h1 { class: "text-4xl font-black uppercase tracking-[0.2em] text-blue-500", "WolfPack" }
                    div { class: "text-xs text-blue-400 mt-1", "P2P SWARM TOPOLOGY // ACTIVE" }
                }
                div { class: "flex gap-8 text-right",
                   match &*telemetry.read_unchecked() {
                        Some(Ok(data)) => rsx! {
                             div {
                                div { class: "text-xs text-gray-500 uppercase", "Consensus Term" }
                                div { class: "text-2xl font-bold text-white", "{data.term}" }
                             }
                             div {
                                div { class: "text-xs text-gray-500 uppercase", "Commit Index" }
                                div { class: "text-2xl font-bold text-green-400", "#{data.commit_index}" }
                             }
                             div {
                                div { class: "text-xs text-gray-500 uppercase", "Node State" }
                                div { class: "text-2xl font-bold text-blue-400 animate-pulse", "{data.raft_state}" }
                             }
                        },
                        _ => rsx! { div { "Syncing..." } }
                   }
                }
            }

            // Main Visualization Area
            div { class: "grid grid-cols-1 lg:grid-cols-3 gap-6 h-[500px]",

                // Topology Map (Center)
                div { class: "lg:col-span-2 bg-gray-900/30 border border-blue-900/30 rounded-lg p-6 relative overflow-hidden flex items-center justify-center",
                    // Decorative Grid
                    div { class: "absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-blue-900/10 to-transparent pointer-events-none" }

                    // Central Node (Self)
                    div { class: "relative z-10 flex flex-col items-center",
                        div { class: "w-24 h-24 rounded-full border-4 border-blue-500 bg-black flex items-center justify-center shadow-[0_0_30px_rgba(59,130,246,0.5)] z-20",
                            i { class: "lucide-server w-10 h-10 text-white" }
                        }
                        div { class: "mt-4 font-bold text-blue-300 tracking-wider bg-black/50 px-3 py-1 rounded border border-blue-900", "ALPHA_NODE" }
                    }

                    // Satellites (Simulated CSS positioning)
                    div { class: "absolute top-1/4 left-1/4 animate-bounce duration-[3000ms]",
                        div { class: "w-16 h-16 rounded-full border-2 border-green-500/50 bg-black/80 flex items-center justify-center",
                             i { class: "lucide-check text-green-500" }
                        }
                    }
                    div { class: "absolute bottom-1/3 right-1/4 animate-bounce duration-[4500ms]",
                         div { class: "w-16 h-16 rounded-full border-2 border-green-500/50 bg-black/80 flex items-center justify-center",
                             i { class: "lucide-check text-green-500" }
                        }
                    }
                     div { class: "absolute top-1/2 right-10 animate-pulse",
                         div { class: "w-12 h-12 rounded-full border-2 border-gray-700 bg-black/80 flex items-center justify-center grayscale opacity-50",
                             i { class: "lucide-help-circle text-gray-500" }
                        }
                    }
                }

                // Peer List / Sidebar
                div { class: "bg-gray-900/30 border border-blue-900/30 rounded-lg p-0 overflow-hidden flex flex-col",
                    div { class: "p-4 bg-blue-900/20 border-b border-blue-900/30 font-bold text-sm tracking-wider flex justify-between",
                        span { "CONNECTED PEERS" }
                        span { class: "text-blue-400", "03 ACTIVE" }
                    }
                    div { class: "flex-1 overflow-y-auto p-4 space-y-2",
                         match &*telemetry.read_unchecked() {
                            Some(Ok(data)) => rsx! {
                                for peer in data.peers.iter() {
                                    div { key: "{peer.id}", class: "p-3 bg-black/40 border border-gray-800 rounded flex items-center justify-between group hover:border-blue-700 transition",
                                        div {
                                            div { class: "text-sm font-bold text-gray-300 group-hover:text-white", "{peer.id}" }
                                            div { class: "text-[10px] text-gray-600 uppercase tracking-wider", "{peer.role}" }
                                        }
                                        div { class: "text-right",
                                            div { class: match peer.status.as_str() {
                                                "Active" => "text-green-500 text-xs font-bold",
                                                _ => "text-gray-500 text-xs font-bold"
                                            }, "{peer.status}" }
                                             div { class: "text-[10px] text-gray-600", "{peer.rtt_ms}ms" }
                                        }
                                    }
                                }
                            },
                             _ => rsx! { div { class: "p-4 text-center text-gray-600 text-xs", "Scanning Network..." } }
                        }
                    }
                }
            }

            // Bottom Diagnostics Strip
            div { class: "grid grid-cols-4 gap-4",
                 div { class: "bg-gray-900/20 p-4 rounded border border-gray-800",
                    div { class: "text-[10px] text-gray-500 uppercase", "Throughput" }
                    div { class: "text-xl font-mono text-gray-300", "24.5 MB/s" }
                    div { class: "h-1 w-full bg-gray-800 mt-2", div { class: "h-full bg-blue-600 w-3/4" } }
                 }
                 div { class: "bg-gray-900/20 p-4 rounded border border-gray-800",
                    div { class: "text-[10px] text-gray-500 uppercase", "Latency (Avg)" }
                    div { class: "text-xl font-mono text-green-400", "18ms" }
                     div { class: "h-1 w-full bg-gray-800 mt-2", div { class: "h-full bg-green-600 w-1/4" } }
                 }
                 div { class: "bg-gray-900/20 p-4 rounded border border-gray-800",
                    div { class: "text-[10px] text-gray-500 uppercase", "Packet Loss" }
                    div { class: "text-xl font-mono text-gray-300", "0.01%" }
                     div { class: "h-1 w-full bg-gray-800 mt-2", div { class: "h-full bg-gray-600 w-[1px]" } }
                 }
                 div { class: "bg-gray-900/20 p-4 rounded border border-gray-800",
                    div { class: "text-[10px] text-gray-500 uppercase", "Uptime" }
                    div { class: "text-xl font-mono text-gray-300", "04:22:19" }
                 }
            }
        }
    }
}
