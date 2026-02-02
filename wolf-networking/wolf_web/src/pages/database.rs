use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
// use serde::{Deserialize, Serialize}; // Unused

#[server]
async fn save_file_to_db(name: String, data: Vec<u8>) -> Result<String, ServerFnError> {
    // In a real implementation, we would write to WolfDb
    use std::io::Write;
    let path = std::path::Path::new("uploads").join(&name);
    // Ensure uploads dir exists
    if let Err(_) = std::fs::create_dir_all("uploads") {
        return Err(ServerFnError::new("Failed to create upload dir"));
    }

    let mut file = std::fs::File::create(&path).map_err(|e| ServerFnError::new(e.to_string()))?;
    file.write_all(&data)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    Ok(format!(
        "File {} saved successfully ({} bytes)",
        name,
        data.len()
    ))
}

#[server]
async fn list_db_files() -> Result<Vec<String>, ServerFnError> {
    // List files in local uploads dir or WolfDb
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir("uploads") {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Ok(name) = entry.file_name().into_string() {
                    files.push(name);
                }
            }
        }
    } else {
        // Return dummy data if dir doesn't exist yet
        files.push("config.json".to_string());
        files.push("sector_map.dat".to_string());
    }
    Ok(files)
}

#[component]
pub fn DatabasePage() -> Element {
    let mut files_list = use_resource(list_db_files);
    let mut active_file_name = use_signal(|| Option::<String>::None);
    let mut active_file_content = use_signal(|| Option::<String>::None); // For text view
    let _active_view_mode = use_signal(|| "text".to_string()); // text, hex

    let on_drop = move |event: DragEvent| {
        event.stop_propagation();
        event.prevent_default();

        if let Some(file_engine) = event.files() {
            let files = file_engine.files();
            if let Some(file_name) = files.into_iter().next() {
                let file_name_clone = file_name.clone();
                spawn(async move {
                    if let Some(bytes) = file_engine.read_file(&file_name_clone).await {
                        let bytes_vec = bytes; // Dioxus read_file usually returns Vec<u8>

                        // Converting buffer to string for preview
                        let text = String::from_utf8_lossy(&bytes_vec).to_string();
                        active_file_content.set(Some(text));
                        active_file_name.set(Some(file_name_clone.clone()));

                        // Upload
                        match save_file_to_db(file_name_clone, bytes_vec).await {
                            Ok(msg) => println!("Upload: {}", msg),
                            Err(e) => println!("Upload failed: {}", e),
                        }
                        files_list.restart();
                    }
                });
            }
        }
    };

    let on_drag_over = move |event: DragEvent| {
        event.stop_propagation();
        event.prevent_default();
    };

    rsx! {
        div { class: "p-8 space-y-8 min-h-screen bg-black text-gray-300 font-mono flex flex-col",
            // Header
             div { class: "flex justify-between items-end border-b border-green-900/50 pb-4",
                div {
                    h1 { class: "text-4xl font-black uppercase tracking-[0.2em] text-green-500", "WolfDb Interface" }
                    div { class: "text-xs text-green-400 mt-1", "STORAGE PERSISTENCE LAYER // V1.0" }
                }
            }

            div { class: "flex-1 grid grid-cols-1 lg:grid-cols-4 gap-6",

                // File List Sidebar
                div { class: "col-span-1 bg-gray-900/30 border border-green-900/30 rounded-lg p-0 flex flex-col",
                    div { class: "p-4 bg-green-900/20 border-b border-green-900/30 font-bold text-sm tracking-wider", "STORED ARTIFACTS" }
                    div { class: "flex-1 overflow-y-auto p-2 space-y-1",
                         match &*files_list.read_unchecked() {
                            Some(Ok(files)) => rsx! {
                                {files.iter().map(|f| {
                                    let f_cloned = f.clone();
                                    rsx! {
                                        div { key: "{f}",
                                              class: "p-2 hover:bg-green-900/20 cursor-pointer rounded text-sm truncate flex items-center gap-2",
                                              onclick: move |_| { active_file_name.set(Some(f_cloned.clone())); active_file_content.set(Some(format!("Loading content for {}...", f_cloned))); },
                                              i { class: "lucide-file w-4 h-4 text-gray-500" }
                                              "{f}"
                                        }
                                    }
                                })}
                            },
                            _ => rsx! { div { class: "p-4 text-xs text-gray-500", "Loading index..." } }
                        }
                    }
                }

                // Main Viewport & Drop Zone
                div { class: "col-span-3 flex flex-col gap-4",

                    // Drop Zone / File Input
                    div {
                        class: "border-2 border-dashed border-gray-700 rounded-lg p-8 flex flex-col items-center justify-center bg-gray-900/20 hover:bg-gray-900/40 hover:border-green-500 transition-colors cursor-pointer active:scale-[0.99]",
                        ondragover: on_drag_over,
                        ondrop: on_drop,

                        i { class: "lucide-upload-cloud w-12 h-12 text-gray-500 mb-4" }
                        div { class: "text-lg font-bold text-gray-300", "Drag & Drop Files Here" }
                        div { class: "text-sm text-gray-500", "or click to browse local system" }
                        input { type: "file", class: "hidden" } // Hidden input for click fallback (not fully wired in this snippet)
                    }

                    // Viewport
                    div { class: "flex-1 bg-black border border-gray-800 rounded-lg overflow-hidden flex flex-col",
                        // Toolbar
                        div { class: "h-10 border-b border-gray-800 bg-gray-900/50 flex items-center px-4 justify-between",
                             div { class: "text-xs font-bold text-gray-400 uppercase",
                                if let Some(name) = active_file_name() { "{name}" } else { "NO FILE SELECTED" }
                             }
                             div { class: "flex gap-2",
                                 button { class: "px-2 py-1 text-xs bg-gray-800 hover:bg-gray-700 rounded border border-gray-700", "TEXT" }
                                 button { class: "px-2 py-1 text-xs bg-gray-800 hover:bg-gray-700 rounded border border-gray-700", "HEX" }
                                 button { class: "px-2 py-1 text-xs bg-gray-800 hover:bg-gray-700 rounded border border-gray-700", "IMG" }
                             }
                        }

                        // Content
                        div { class: "flex-1 p-4 overflow-auto font-mono text-sm text-green-300/80 whitespace-pre scrollbar-thin scrollbar-thumb-gray-800",
                             if let Some(content) = active_file_content() {
                                 "{content}"
                             } else {
                                 div { class: "h-full flex items-center justify-center text-gray-600",
                                     i { class: "lucide-eye-off w-8 h-8 mr-2" }
                                     "Viewport Empty"
                                 }
                             }
                        }
                    }
                }
            }
        }
    }
}
