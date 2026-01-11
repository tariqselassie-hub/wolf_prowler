#![cfg_attr(feature = "bundle", allow(missing_docs))]

//! Lock Prowler Dashboard
//!
//! A Dioxus-based web dashboard for monitoring and controlling the Wolf Prowler system.

#[cfg(feature = "server")]
use axum::Router;
use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
use lock_prowler::headless::HeadlessWolfProwler;
#[cfg(feature = "server")]
use tower_http::cors::CorsLayer;

mod models;
mod services;

// --- Routing ---

/// Application Routes
#[derive(Clone, Routable, Debug, PartialEq, Serialize, Deserialize)]
pub enum Route {
    /// Main Dashboard View
    #[route("/")]
    Dashboard {},
    /// Application Settings
    #[route("/settings")]
    Settings {},
}
#[cfg(feature = "server")]
use services::PROWLER;
use services::{get_fullstack_stats, run_prowler_scan};

// --- Components ---

#[component]
fn Dashboard() -> Element {
    let stats = use_resource(get_fullstack_stats);
    let mut scan_status = use_signal(|| String::new());
    let mut is_loading = use_signal(|| false);
    let logs = use_signal(|| Vec::<String>::new());
    let mut progress = use_signal(|| 0.0f32);

    // Note: Log streaming temporarily disabled logic is removed for brevity as it's commented out anyway
    // If needed, re-add use_resource calls for stream_prowler_logs/status

    rsx! {
        div { class: "p-8",
            h1 { "System Overview" }
            match &*stats.read_unchecked() {
                Some(Ok(s)) => rsx! {
                    div { "Status: {s.db_status}" }
                    div { "Entropy: {s.entropy}" }
                },
                _ => rsx! { "Loading stats..." }
            }

            div { class: "mt-6 p-4 border rounded bg-gray-50",
                h2 { class: "text-lg font-semibold mb-2", "Actions" }
                button {
                    class: "px-4 py-2 bg-orange-600 text-white rounded hover:bg-orange-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center",
                    disabled: is_loading(),
                    onclick: move |_| async move {
                        is_loading.set(true);
                        progress.set(0.0);
                        scan_status.set("Initializing Headless Prowler...".to_string());
                        match run_prowler_scan().await {
                            Ok(msg) => scan_status.set(msg),
                            Err(e) => scan_status.set(format!("Scan Error: {e}")),
                        }
                        is_loading.set(false);
                    },
                    {
                        if is_loading() {
                            rsx! {
                                svg { class: "animate-spin -ml-1 mr-3 h-5 w-5 text-white", xmlns: "http://www.w3.org/2000/svg", fill: "none", view_box: "0 0 24 24",
                                    circle { class: "opacity-25", cx: "12", cy: "12", r: "10", stroke: "currentColor", stroke_width: "4" }
                                    path { class: "opacity-75", fill: "currentColor", d: "M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" }
                                }
                                "Scanning..."
                            }
                        } else {
                            rsx! { "Trigger Manual Scan" }
                        }
                    }
                }

                // Progress Bar
                if is_loading() || progress() > 0.0 {
                    div { class: "mt-4",
                        div { class: "flex justify-between mb-1",
                            span { class: "text-sm font-medium text-orange-700", "Scan Progress" }
                            span { class: "text-sm font-medium text-orange-700", "{progress().round()}%" }
                        }
                        div { class: "w-full bg-gray-200 rounded-full h-2.5",
                            div {
                                class: "bg-orange-600 h-2.5 rounded-full transition-all duration-500",
                                style: "width: {progress()}%"
                            }
                        }
                    }
                }

                if !scan_status.read().is_empty() {
                    p { class: "mt-3 text-sm font-mono text-gray-700", "{scan_status}" }
                }

                div { class: "mt-4 p-2 bg-black text-green-400 font-mono text-xs rounded h-40 overflow-y-auto",
                    h3 { class: "text-gray-400 mb-1 border-b border-gray-800", "Live Logs" }
                    // Re-enable if logs streaming is fixed
                    for log in logs.read().iter() {
                        div { "{log}" }
                    }
                    if logs.read().is_empty() {
                        div { class: "text-gray-600", "Waiting for scan activity..." }
                    }
                }
            }

            div { class: "mt-8", Link { to: Route::Settings {}, "Go to Settings" } }
        }
    }
}

#[component]
fn Settings() -> Element {
    rsx! {
        div { class: "p-8",
            h1 { "Settings" }
            Link { to: Route::Dashboard {}, "Back to Dashboard" }
        }
    }
}

#[component]
fn App() -> Element {
    rsx! {
        Router::<Route> {}
    }
}

// --- Main / Server Entry ---

#[cfg(feature = "server")]
#[tokio::main]
async fn main() {
    // Initialize Prowler on the server
    let db_path = std::env::var("WOLF_DB_PATH").unwrap_or_else(|_| "./wolf_data".to_string());
    let store = lock_prowler::storage::WolfStore::new(&db_path)
        .await
        .unwrap();
    let config = lock_prowler::headless::HeadlessConfig::default();
    let prowler = HeadlessWolfProwler::new(config, store);

    // Initialize the global state in services module
    *services::PROWLER.lock().await = Some(prowler);

    // Initialize Axum Router
    let app = Router::new()
        // Dioxus 0.7 integration with Axum
        .serve_dioxus_application(ServeConfig::new(), App)
        .layer(CorsLayer::permissive());

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    println!("Server running on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

#[cfg(not(feature = "server"))]
fn main() {
    // Launch client-side (WASM/Desktop)
    dioxus::launch(App);
}
