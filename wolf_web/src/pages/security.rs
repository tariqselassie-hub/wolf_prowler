#![allow(non_snake_case)]
use crate::ui_kit::{Card, Badge, Button};
use crate::get_fullstack_stats;
use crate::Route;
use dioxus::prelude::*;

#[component]
pub fn SecurityPage() -> Element {
    let stats_resource = use_resource(get_fullstack_stats);

    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono",
            Link { to: Route::Dashboard {}, class: "mb-8 inline-block hover:underline", "< RETURN TO HUD" }

            div { class: "flex justify-between items-center mb-8",
                h1 { class: "text-4xl font-bold uppercase tracking-widest", "Security Operations" }
                div { class: "flex gap-2",
                    Button { class: "border-red-900/50 text-red-500 hover:bg-red-900/20", "Panic: Lockdown" }
                }
            }

            match &*stats_resource.read_unchecked() {
                Some(Ok(stats)) => rsx! {
                    div { class: "grid grid-cols-1 lg:grid-cols-3 gap-8",
                        // Threat Overview
                        Card { class: "lg:col-span-1",
                            h3 { class: "text-lg font-bold mb-4 uppercase border-b border-green-800/50 pb-2", "Threat Intelligence" }
                            div { class: "space-y-4",
                                div { class: "flex justify-between",
                                    span { "Threat Level" }
                                    Badge { label: stats.threat_level.clone(), color: if stats.threat_level == "CRITICAL" { "red".to_string() } else { "green".to_string() } }
                                }
                                div { class: "flex justify-between",
                                    span { "Active Alerts" }
                                    span { class: "font-bold text-yellow-500", "{stats.active_alerts}" }
                                }
                            }
                        }

                        // Firewall Status
                        Card { class: "lg:col-span-2",
                            div { class: "flex justify-between items-center border-b border-green-800/50 pb-2 mb-4",
                                h3 { class: "text-lg font-bold uppercase", "Internal Firewall" }
                                Badge { 
                                    label: if stats.firewall.enabled { "ACTIVE".to_string() } else { "DISABLED".to_string() }, 
                                    color: if stats.firewall.enabled { "green".to_string() } else { "red".to_string() } 
                                }
                            }
                            
                            div { class: "grid grid-cols-3 gap-4 mb-6",
                                div { class: "text-center p-2 bg-gray-900/50 rounded",
                                    div { class: "text-xs uppercase text-gray-500", "Default Policy" }
                                    div { class: "font-bold text-green-400", "{stats.firewall.policy}" }
                                }
                                div { class: "text-center p-2 bg-gray-900/50 rounded",
                                    div { class: "text-xs uppercase text-gray-500", "Active Rules" }
                                    div { class: "font-bold text-blue-400", "{stats.firewall.active_rules}" }
                                }
                                div { class: "text-center p-2 bg-gray-900/50 rounded",
                                    div { class: "text-xs uppercase text-gray-500", "Blocked Events" }
                                    div { class: "font-bold text-red-400", "{stats.firewall.blocked_count}" }
                                }
                            }

                            // Rules Table
                            h4 { class: "text-xs font-bold uppercase mb-2 text-gray-500", "Active Ruleset" }
                            div { class: "overflow-x-auto max-h-48 overflow-y-auto mb-6 border border-green-900/30",
                                table { class: "w-full text-left text-sm",
                                    thead { class: "bg-green-900/20 text-green-300",
                                        tr {
                                            th { class: "p-2", "Name" }
                                            th { class: "p-2", "Target" }
                                            th { class: "p-2", "Proto" }
                                            th { class: "p-2", "Dir" }
                                            th { class: "p-2", "Action" }
                                        }
                                    }
                                    tbody {
                                        for rule in &stats.firewall.rules {
                                            tr { class: "border-b border-green-900/10 hover:bg-green-900/5",
                                                td { class: "p-2", "{rule.name}" }
                                                td { class: "p-2 font-mono text-xs", "{rule.target}" }
                                                td { class: "p-2", "{rule.protocol}" }
                                                td { class: "p-2", "{rule.direction}" }
                                                td { class: "p-2", 
                                                    span { class: if rule.action == "Deny" { "text-red-500" } else { "text-green-500" }, "{rule.action}" }
                                                }
                                            }
                                        }
                                        if stats.firewall.rules.is_empty() {
                                            tr { td { colspan: "5", class: "p-4 text-center text-gray-500", "No active rules." } }
                                        }
                                    }
                                }
                            }

                            // Event Log
                            h4 { class: "text-xs font-bold uppercase mb-2 text-gray-500", "Firewall Events" }
                            div { class: "bg-black p-2 border border-green-900 font-mono text-xs max-h-32 overflow-y-auto space-y-1",
                                for event in &stats.firewall.recent_events {
                                    div {
                                        span { class: "text-gray-500", "[{event.timestamp}]" }
                                        span { class: "ml-2 text-yellow-500", "{event.source}" }
                                        span { class: "ml-2 text-red-400", "{event.action}" }
                                        span { class: "ml-2 text-gray-400", "({event.reason})" }
                                    }
                                }
                                if stats.firewall.recent_events.is_empty() {
                                    div { class: "text-gray-600 italic", "No recent firewall events." }
                                }
                            }
                        }
                    }
                },
                _ => rsx! { div { class: "animate-pulse", "Loading Security Data..." } }
            }
        }
    }
}
