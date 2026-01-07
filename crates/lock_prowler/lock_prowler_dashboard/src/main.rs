#[cfg(feature = "server")]
use axum::Router;
use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Serialize, Deserialize};
#[cfg(feature = "server")]
use tower_http::cors::CorsLayer;
use tokio::sync::Mutex as AsyncMutex;
use futures_util::StreamExt;
use std::pin::Pin;
use lock_prowler::headless::HeadlessStatus;
#[cfg(feature = "server")]
use lock_prowler::headless::HeadlessWolfProwler;
use once_cell::sync::Lazy;

// --- Types & State ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemStats {
    pub volume_size: String,
    pub encrypted_sectors: f32,
    pub entropy: f32,
    pub db_status: String,
}

// Global state simulation
#[cfg(feature = "server")]
static PROWLER: Lazy<AsyncMutex<Option<HeadlessWolfProwler>>> = Lazy::new(|| AsyncMutex::new(None));

// --- Server Functions (Dioxus 0.7 RPC) ---

#[server]
async fn get_fullstack_stats() -> Result<SystemStats, ServerFnError> {
    Ok(SystemStats {
        volume_size: "512_GB_BitLocker".to_string(),
        encrypted_sectors: 98.2,
        entropy: 0.88,
        db_status: "CONNECTED".to_string(),
    })
}

#[server]
async fn run_prowler_scan() -> Result<String, ServerFnError> {
    // Integration point for HeadlessWolfProwler
    // Example: lock_prowler::engine::HeadlessWolfProwler::run().await?;
    
    // Simulating backend processing time
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    
    Ok("Scan completed: 1,024 sectors verified. No unauthorized modifications detected.".to_string())
}

#[server]
async fn stream_prowler_logs() -> Result<Pin<Box<dyn Stream<Item = Result<String, ServerFnError>> + Send>>, ServerFnError> {
    let prowler_lock = PROWLER.lock().await;
    let prowler = prowler_lock.as_ref().ok_or_else(|| ServerFnError::new("Prowler not initialized"))?;
    let rx = prowler.subscribe_logs();
    
    // Convert broadcast receiver to a stream
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
        .map(|res| match res {
            Ok(msg) => Ok(msg),
            Err(e) => Err(ServerFnError::new(e.to_string())),
        });

    Ok(Box::pin(stream))
}

#[server]
async fn stream_prowler_status() -> Result<Pin<Box<dyn Stream<Item = Result<HeadlessStatus, ServerFnError>> + Send>>, ServerFnError> {
    let prowler_lock = PROWLER.lock().await;
    let prowler = prowler_lock.as_ref().ok_or_else(|| ServerFnError::new("Prowler not initialized"))?;
    let rx = prowler.subscribe_status();
    
    // Convert broadcast receiver to a stream
    let stream = tokio_stream::wrappers::BroadcastStream::new(rx)
        .map(|res| match res {
            Ok(s) => Ok(s),
            Err(e) => Err(ServerFnError::new(e.to_string())),
        });

    Ok(Box::pin(stream))
}

// --- Routing (Dioxus 0.7 Routable) ---

#[derive(Clone, Routable, Debug, PartialEq, Serialize, Deserialize)]
pub enum Route {
    #[route("/")]
    Dashboard {},
    #[route("/settings")]
    Settings {},
}

// --- Components ---

#[component]
fn Dashboard() -> Element {
    let stats = use_resource(get_fullstack_stats);
    let mut scan_status = use_signal(|| String::new());
    let mut is_loading = use_signal(|| false);
    let mut logs = use_signal(|| Vec::new());
    let mut progress = use_signal(|| 0.0f32);

    // Consume the log stream
    let _ = use_resource(move || async move {
        if let Ok(mut stream) = stream_prowler_logs().await {
            while let Some(Ok(log)) = stream.next().await {
                logs.with_mut(|l| {
                    l.push(log);
                    // Keep only the last 10 logs for display
                    if l.len() > 10 { l.remove(0); }
                });
            }
        }
    });

    // Consume the status stream
    let _ = use_resource(move || async move {
        if let Ok(mut stream) = stream_prowler_status().await {
            while let Some(Ok(status)) = stream.next().await {
                progress.set(status.progress);
            }
        }
    });

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
                    if is_loading() {
                        rsx! {
                            svg { class: "animate-spin -ml-1 mr-3 h-5 w-5 text-white", xmlns: "http://www.w3.org/2000/svg", fill: "none", viewBox: "0 0 24 24",
                                circle { class: "opacity-25", cx: "12", cy: "12", r: "10", stroke: "currentColor", stroke_width: "4" }
                                path { class: "opacity-75", fill: "currentColor", d: "M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" }
                            }
                            "Scanning..."
                        }
                    } else {
                        rsx! { "Trigger Manual Scan" }
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
    let store = lock_prowler::storage::WolfStore::new(&db_path).unwrap();
    let config = lock_prowler::headless::HeadlessConfig::default();
    let prowler = HeadlessWolfProwler::new(config, store);
    *PROWLER.lock().await = Some(prowler);

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