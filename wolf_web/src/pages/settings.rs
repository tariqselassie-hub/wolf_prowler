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
        div { class: "p-8 space-y-8",
            h1 { class: "text-3xl font-bold uppercase tracking-widest text-gray-400", "Node Configuration" }

            div { class: "max-w-2xl bg-gray-900/50 border border-gray-800 p-8 rounded",
                div { class: "space-y-6",
                    // Node Identity
                    div {
                        label { class: "block text-sm font-bold text-gray-500 mb-2 uppercase", "Node Identity" }
                        input {
                            class: "w-full bg-black/50 border border-gray-700 rounded px-4 py-3 text-gray-200 focus:border-blue-500 focus:outline-none",
                            value: "{node_name}",
                            oninput: move |e| node_name.set(e.value())
                        }
                    }

                    // Toggles
                    div { class: "flex items-center justify-between",
                        div {
                            div { class: "font-bold text-gray-300", "Debug & Tracing" }
                            div { class: "text-xs text-gray-500", "Enable verbose logging for diagnostics" }
                        }
                        button {
                            class: if debug_mode() { "bg-blue-600 w-12 h-6 rounded-full relative transition-colors" } else { "bg-gray-700 w-12 h-6 rounded-full relative transition-colors" },
                            onclick: move |_| debug_mode.set(!debug_mode()),
                            div { class: if debug_mode() { "absolute right-1 top-1 w-4 h-4 bg-white rounded-full transition-all" } else { "absolute left-1 top-1 w-4 h-4 bg-gray-400 rounded-full transition-all" } }
                        }
                    }

                     div { class: "flex items-center justify-between",
                         div {
                            div { class: "font-bold text-gray-300", "Silent Mode" }
                            div { class: "text-xs text-gray-500", "Suppress standard alerts and notifications" }
                        }
                        div { class: "w-12 h-6 bg-gray-700 rounded-full relative opacity-50 cursor-not-allowed",
                             div { class: "absolute left-1 top-1 w-4 h-4 bg-gray-400 rounded-full" }
                        }
                    }

                    // Save Button
                    div { class: "pt-6 border-t border-gray-800",
                        button {
                            onclick: save_action,
                            class: "w-full py-3 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded uppercase tracking-wider transition-colors",
                            "Save Configuration"
                        }
                    }
                }
            }
        }
    }
}
