use crate::ui_kit::{Button, Card};
use crate::Route;
use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;

#[server]
async fn save_node_config(node_name: String, debug_mode: bool) -> Result<(), ServerFnError> {
    println!("Saving config: Name={}, Debug={}", node_name, debug_mode);
    Ok(())
}

#[component]
pub fn SettingsPage() -> Element {
    let mut node_name = use_signal(|| "WolfNode-Alpha".to_string());
    let mut debug_mode = use_signal(|| false);

    let save_action = move |_| {
        spawn(async move {
            let _ = save_node_config(node_name(), debug_mode()).await;
        });
    };

    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono",
            Link { to: Route::Dashboard {}, class: "mb-8 inline-block hover:underline", "< RETURN TO HUD" }

            h1 { class: "text-4xl font-bold mb-8 uppercase tracking-widest text-green-500", "System Configuration" }

            div { class: "max-w-2xl",
                Card {
                    div { class: "space-y-6",
                        // Node Identity
                        div {
                            label { class: "block text-xs font-bold text-gray-500 mb-2 uppercase", "Node Identity" }
                            input {
                                class: "w-full bg-black/50 border border-green-800 p-3 text-green-300 focus:border-green-500 focus:outline-none font-mono text-sm",
                                value: "{node_name}",
                                oninput: move |e| node_name.set(e.value())
                            }
                        }

                        // Toggles
                        div { class: "flex items-center justify-between border-b border-green-900/30 pb-4",
                            div {
                                div { class: "font-bold text-green-400 text-sm uppercase", "Debug & Tracing" }
                                div { class: "text-xs text-gray-600", "Enable verbose logging for diagnostics" }
                            }
                            button {
                                class: if debug_mode() { "bg-green-600 w-12 h-6 rounded-full relative transition-colors shadow-[0_0_10px_rgba(22,163,74,0.5)]" } else { "bg-gray-800 w-12 h-6 rounded-full relative transition-colors border border-gray-700" },
                                onclick: move |_| debug_mode.set(!debug_mode()),
                                div { class: if debug_mode() { "absolute right-1 top-1 w-4 h-4 bg-white rounded-full transition-all" } else { "absolute left-1 top-1 w-4 h-4 bg-gray-500 rounded-full transition-all" } }
                            }
                        }

                         div { class: "flex items-center justify-between border-b border-green-900/30 pb-4",
                             div {
                                div { class: "font-bold text-green-400 text-sm uppercase", "Silent Mode" }
                                div { class: "text-xs text-gray-600", "Suppress standard alerts and notifications" }
                            }
                            div { class: "w-12 h-6 bg-gray-900 rounded-full relative opacity-50 cursor-not-allowed border border-gray-800",
                                 div { class: "absolute left-1 top-1 w-4 h-4 bg-gray-600 rounded-full" }
                            }
                        }

                        // Save Button
                        div { class: "pt-6",
                            Button {
                                onclick: save_action,
                                class: "w-full py-3",
                                "Commit Configuration"
                            }
                        }
                    }
                }
            }
        }
    }
}
