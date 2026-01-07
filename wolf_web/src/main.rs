#![allow(non_snake_case)]

use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
#[cfg(feature = "server")]
use tower_http::cors::CorsLayer;
// use futures_util::{Stream, StreamExt}; // Streaming disabled for now
// use std::pin::Pin;
// Use imports from lock_prowler crate (now in crates/lock_prowler)
#[cfg(feature = "server")]
use axum::Router;
use chrono::Utc; // Import Utc explicitly
use lock_prowler::headless::HeadlessConfig;
use lock_prowler::headless::HeadlessStatus;
#[cfg(feature = "server")]
use lock_prowler::headless::HeadlessWolfProwler;
use once_cell::sync::Lazy; // Import Router explicitly
use std::collections::HashMap;

use wolfsec::security::advanced::iam::sso::{SSOAuthenticationRequest, SSOCallbackRequest};
use wolfsec::security::advanced::iam::ClientInfo;
use wolfsec::security::advanced::iam::{IAMConfig, SSOIntegrationManager, SSOProvider};
#[cfg(feature = "server")]
use wolf_web::dashboard;
#[cfg(feature = "server")]
use wolf_web::dashboard::state::AppState;

// --- Types & State ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemStats {
    pub volume_size: String,
    pub encrypted_sectors: f32,
    pub entropy: f32,
    pub db_status: String,
    pub active_nodes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecordView {
    pub id: String,
    pub data: String, // Scrubbed or raw JSON
    pub has_vector: bool,
}

// Global state simulation
#[cfg(feature = "server")]
static PROWLER: Lazy<AsyncMutex<Option<HeadlessWolfProwler>>> = Lazy::new(|| AsyncMutex::new(None));
#[cfg(feature = "server")]
static SSO_MANAGER: Lazy<AsyncMutex<Option<SSOIntegrationManager>>> =
    Lazy::new(|| AsyncMutex::new(None));
#[cfg(feature = "server")]
static APP_STATE: Lazy<AsyncMutex<Option<AppState>>> = Lazy::new(|| AsyncMutex::new(None));

// --- Server Functions (Dioxus 0.6 RPC) ---

#[server]
async fn get_fullstack_stats() -> Result<SystemStats, ServerFnError> {
    let prowler_lock = PROWLER.lock().await;

    if let Some(prowler) = prowler_lock.as_ref() {
        let db_stats = prowler.get_store_stats().await;

        Ok(SystemStats {
            volume_size: format!("{} Records", db_stats.total_records),
            encrypted_sectors: if db_stats.integrity_check {
                100.0
            } else {
                99.9
            },
            entropy: 0.95,
            db_status: db_stats.encryption_status,
            active_nodes: prowler.get_network_stats().await.peer_count,
        })
    } else {
        Ok(SystemStats {
            volume_size: "Disconnected".to_string(),
            encrypted_sectors: 0.0,
            entropy: 0.0,
            db_status: "OFFLINE".to_string(),
            active_nodes: 0,
        })
    }
}

#[server]
async fn run_prowler_scan() -> Result<String, ServerFnError> {
    // Simulating backend processing
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    Ok("Sector Scan Complete. Integrity Verified.".to_string())
}

#[server]
async fn get_prowler_logs() -> Result<Vec<String>, ServerFnError> {
    // Simplified to non-streaming for initial build
    Ok(vec![
        "System initialized.".to_string(),
        "Listening on port 8080.".to_string(),
        "Secure Storage mounted.".to_string(),
    ])
}

#[server]
async fn get_prowler_status() -> Result<HeadlessStatus, ServerFnError> {
    // Simplified status return matching actual struct
    Ok(HeadlessStatus {
        is_running: true,
        current_target: Some("/home/user/data".to_string()),
        discovered_secrets: 42,
        imported_secrets: 10,
        last_scan_time: Some(Utc::now()),
        next_scan_time: None,
        progress: 100.0,
    })
}

// --- SSO Server Functions ---

#[server]
async fn get_sso_auth_url(provider_name: String) -> Result<String, ServerFnError> {
    let sso_lock = SSO_MANAGER.lock().await;
    if let Some(manager) = sso_lock.as_ref() {
        let provider = match provider_name.as_str() {
            "azure" => SSOProvider::AzureAD,
            "okta" => SSOProvider::Okta,
            "auth0" => SSOProvider::Auth0,
            "google" => SSOProvider::Google,
            "mock" => SSOProvider::Mock,
            _ => return Err(ServerFnError::new("Invalid provider")),
        };

        let request = SSOAuthenticationRequest {
            provider,
            client_info: ClientInfo {
                ip_address: "127.0.0.1".to_string(), // In real app, extract from headers
                user_agent: "WolfWeb/1.0".to_string(),
                device_id: None,
                location: None,
            },
            redirect_url: None, // Use default
        };

        let response = manager
            .start_authentication(request)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        Ok(response.auth_url)
    } else {
        Err(ServerFnError::new("SSO System Offline"))
    }
}

#[server]
async fn handle_sso_callback(
    provider_name: String,
    code: String,
    state: String,
) -> Result<String, ServerFnError> {
    let sso_lock = SSO_MANAGER.lock().await;
    if let Some(manager) = sso_lock.as_ref() {
        let provider = match provider_name.as_str() {
            "azure" => SSOProvider::AzureAD,
            "okta" => SSOProvider::Okta,
            "auth0" => SSOProvider::Auth0,
            "google" => SSOProvider::Google,
            "mock" => SSOProvider::Mock,
            _ => return Err(ServerFnError::new("Invalid provider")),
        };

        let request = SSOCallbackRequest {
            provider,
            code,
            state,
            error: None,
        };

        // In a real app, this would return a session token/cookie.
        // For now, we just verify the handshake succeeds.
        let _user_info = manager
            .handle_callback(request)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;

        Ok("Authentication Successful".to_string())
    } else {
        Err(ServerFnError::new("SSO System Offline"))
    }
}

// --- Database Server Functions ---

#[server]
async fn get_records(table: String) -> Result<Vec<RecordView>, ServerFnError> {
    let prowler_lock = PROWLER.lock().await;
    if let Some(prowler) = prowler_lock.as_ref() {
        let records = prowler
            .list_database_records(&table)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        let views = records
            .into_iter()
            .map(|r| RecordView {
                id: r.id,
                data: serde_json::to_string(&r.data).unwrap_or_default(),
                has_vector: r.vector.is_some(),
            })
            .collect();
        Ok(views)
    } else {
        Err(ServerFnError::new("Database Offline"))
    }
}

#[server]
async fn add_record(table: String, key: String, data_json: String) -> Result<(), ServerFnError> {
    let prowler_lock = PROWLER.lock().await;
    if let Some(prowler) = prowler_lock.as_ref() {
        // Parse data_json to HashMap
        let data: HashMap<String, String> = serde_json::from_str(&data_json)
            .map_err(|_| ServerFnError::new("Invalid JSON Data"))?;

        prowler
            .add_database_record(&table, &key, data)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(())
    } else {
        Err(ServerFnError::new("Database Offline"))
    }
}

#[server]
async fn delete_record(table: String, id: String) -> Result<(), ServerFnError> {
    let prowler_lock = PROWLER.lock().await;
    if let Some(prowler) = prowler_lock.as_ref() {
        prowler
            .delete_database_record(&table, &id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        Ok(())
    } else {
        Err(ServerFnError::new("Database Offline"))
    }
}

// --- Routing ---

#[derive(Clone, Routable, Debug, PartialEq, Serialize, Deserialize)]
pub enum Route {
    #[layout(DashboardLayout)]
    #[route("/")]
    Dashboard {},
    #[route("/security")]
    SecurityPage {},
    #[route("/network")]
    Network {}, // Renamed Network to NetworkPage logic if needed, but existing Network component is fine for now
    #[route("/system")]
    SystemPage {},
    #[route("/intelligence")]
    IntelligencePage {},
    #[route("/compliance")]
    CompliancePage {},
    #[route("/admin")]
    AdministrationPage {},
    #[route("/settings")]
    SettingsPage {},
    #[route("/database")]
    Database {},
    #[route("/vault")] // Vault was specific, keeping it here
    Vault {},
    #[end_layout]
    #[route("/login")]
    Login {},
}

// --- Components ---

#[component]
fn DashboardLayout() -> Element {
    // Initialize Lucide icons
    use_effect(|| {
        use js_sys::wasm_bindgen::JsCast;
        let window = web_sys::window();
        if let Some(win) = window {
            if let Some(lucide) = js_sys::Reflect::get(&win, &"lucide".into())
                .ok()
                .and_then(|v| v.dyn_into::<js_sys::Object>().ok())
            {
                if let Some(create_icons) = js_sys::Reflect::get(&lucide, &"createIcons".into())
                    .ok()
                    .and_then(|v| -> Option<js_sys::Function> { v.dyn_into::<js_sys::Function>().ok() })
                {
                    let _ = create_icons.call0(&lucide);
                }
            }
        }
    });

    rsx! {
        div { class: "flex min-h-screen bg-black text-green-500 font-mono",
            Sidebar {}
            main { class: "flex-1 p-8 overflow-auto",
                Outlet::<Route> {}
            }
        }
    }
}

#[component]
fn Sidebar() -> Element {
    rsx! {
        div { class: "w-64 bg-gray-900/80 backdrop-blur-sm border-r border-gray-700 flex flex-col hidden md:flex sticky top-0 h-screen",
            // Logo
            div { class: "p-4 border-b border-gray-700",
                h1 { class: "text-xl font-bold flex items-center space-x-2 text-green-500",
                    i { class: "lucide-shield w-6 h-6" } // Using standard classes referencing loaded Lucide script
                    span { "Wolf Prowler" }
                }
            }

            // Nav
            nav { class: "flex-1 p-4 space-y-2 overflow-y-auto",
                SidebarLink { to: Route::Dashboard {}, icon: "home", label: "Overview" }
                SidebarLink { to: Route::SecurityPage {}, icon: "shield-alert", label: "Security" }
                SidebarLink { to: Route::Network {}, icon: "network", label: "Network" }
                SidebarLink { to: Route::SystemPage {}, icon: "cpu", label: "System" }
                SidebarLink { to: Route::IntelligencePage {}, icon: "brain", label: "Intelligence" }
                SidebarLink { to: Route::CompliancePage {}, icon: "file-check", label: "Compliance" }
                SidebarLink { to: Route::AdministrationPage {}, icon: "users", label: "Administration" }
                SidebarLink { to: Route::SettingsPage {}, icon: "settings", label: "Settings" }
                SidebarLink { to: Route::Database {}, icon: "database", label: "Database" }
                SidebarLink { to: Route::Vault {}, icon: "lock", label: "Vault" }
            }

            // User Info
             div { class: "p-4 border-t border-gray-700",
                div { class: "flex items-center space-x-3",
                    div { class: "w-8 h-8 bg-purple-500 rounded-full flex items-center justify-center",
                        i { class: "lucide-user w-4 h-4 text-white" }
                    }
                    div {
                        p { class: "text-sm font-medium text-gray-200", "Admin" }
                        p { class: "text-xs text-green-400", "Online" }
                    }
                }
            }
        }
    }
}

#[component]
fn SidebarLink(to: Route, icon: &'static str, label: &'static str) -> Element {
    rsx! {
        Link {
            to: to,
            class: "flex items-center space-x-3 p-2 rounded-lg text-gray-400 hover:bg-gray-700/50 hover:text-white transition-colors",
            active_class: "bg-purple-600/20 text-purple-300",
            i { class: "lucide-{icon} w-5 h-5" }
            span { "{label}" }
        }
    }
}

#[component]
fn Dashboard() -> Element {
    let stats = use_resource(get_fullstack_stats);
    let mut scan_status = use_signal(|| String::new());
    let mut is_loading = use_signal(|| false);
    let logs_resource = use_resource(get_prowler_logs);
    let mut progress = use_signal(|| 0.0f32);

    rsx! {
        div { class: "min-h-screen bg-black text-green-500 font-mono p-6",
            // HUD Header (Moved inside Dashboard content or kept as TopBar specific to Dashboard)
            div { class: "flex justify-between items-center mb-8",
                div {
                    h2 { class: "text-xl font-semibold text-white", "Dashboard Overview" }
                     div { class: "flex items-center space-x-2 mt-1",
                        div { class: "w-3 h-3 bg-green-500 rounded-full animate-pulse" }
                        span { class: "text-sm text-gray-400", "Real-time System Status" }
                    }
                }
                div { class: "flex space-x-3",
                     Link { to: Route::Login {}, class: "p-2 hover:bg-gray-800 rounded text-red-400", "[LOGOUT]" }
                }
            }



            // Main Grid
            div { class: "p-8 grid grid-cols-1 lg:grid-cols-3 gap-8",

                // Column 1: System Status
                div { class: "lg:col-span-1 space-y-8",
                    // Stats Module
                    div { class: "border border-green-800 bg-gray-900/50 p-6 rounded relative overflow-hidden group hover:border-green-500 transition-colors",
                         div { class: "absolute top-0 right-0 p-2 opacity-20 group-hover:opacity-40",
                             svg { class: "w-16 h-16", fill: "currentColor", view_box: "0 0 24 24", path { d: "M12 2L2 7l10 5 10-5-10-5zm0 9l2.5-1.25L12 8.5l-2.5 1.25L12 11zm0 2.5l-5-2.5-5 2.5L12 22l10-8.5-5-2.5-5 2.5z" } }
                         }
                        h2 { class: "text-xl font-bold mb-4 uppercase border-b border-green-800 pb-2", "System Integrity" }

                        match &*stats.read_unchecked() {
                            Some(Ok(s)) => rsx! {
                                div { class: "space-y-4",
                                    StatRow { label: "Database", value: &s.db_status, active: true }
                                    StatRow { label: "Entropy", value: &format!("{:.2}", s.entropy), active: true }
                                    StatRow { label: "Encryption", value: &format!("{}%", s.encrypted_sectors), active: true }
                                    StatRow { label: "Active Nodes", value: &s.active_nodes.to_string(), active: true }
                                }
                            },
                            _ => rsx! { div { class: "animate-pulse", "Calibrating Sensors..." } }
                        }
                    }

                    // Actions Module
                    div { class: "border border-green-800 bg-gray-900/50 p-6 rounded",
                        h2 { class: "text-xl font-bold mb-4 uppercase border-b border-green-800 pb-2", "Operations" }

                        button {
                            class: "w-full py-4 bg-green-900/20 border border-green-600 hover:bg-green-600 hover:text-black transition-all duration-300 uppercase font-bold tracking-wider relative overflow-hidden group",
                            disabled: is_loading(),
                            onclick: move |_| async move {
                                is_loading.set(true);
                                progress.set(0.0);
                                scan_status.set("INITIATING SCAN SEQUENCE...".to_string());
                                match run_prowler_scan().await {
                                    Ok(msg) => scan_status.set(msg),
                                    Err(e) => scan_status.set(format!("ERROR: {e}")),
                                }
                                is_loading.set(false);
                            },
                            if is_loading() {
                                span { class: "animate-pulse", "SCANNING..." }
                            } else {
                                "Initialize Sector Scan"
                            }
                        }

                         if is_loading() || progress() > 0.0 {
                            div { class: "mt-4",
                                div { class: "w-full bg-green-900/30 h-1",
                                    div {
                                        class: "bg-green-500 h-1 shadow-[0_0_10px_#22c55e] transition-all duration-200",
                                        style: "width: {progress()}%"
                                    }
                                }
                                div { class: "flex justify-between text-xs mt-1 text-green-400",
                                    span { "PROGRESS" }
                                    span { "{progress().round()}%" }
                                }
                            }
                        }

                        if !scan_status.read().is_empty() {
                            div { class: "mt-4 p-2 border border-green-500/30 bg-black text-xs font-mono",
                                "> {scan_status}"
                            }
                        }
                    }
                }

                // Column 2 & 3: Console / Logs
                div { class: "lg:col-span-2",
                    div { class: "border border-green-800 bg-black h-full rounded flex flex-col relative",
                        div { class: "p-3 border-b border-green-800 bg-green-900/10 flex justify-between",
                            span { class: "uppercase text-sm font-bold", "Terminal Output" }
                            div { class: "flex space-x-2",
                                div { class: "w-3 h-3 rounded-full bg-red-900" }
                                div { class: "w-3 h-3 rounded-full bg-yellow-900" }
                                div { class: "w-3 h-3 rounded-full bg-green-900" }
                            }
                        }
                        div { class: "flex-1 p-4 font-mono text-sm overflow-y-auto space-y-1 scrollbar-thin scrollbar-thumb-green-900 scrollbar-track-black",
                            match &*logs_resource.read_unchecked() {
                                Some(Ok(logs)) => rsx! {
                                    for log in logs {
                                        div { class: "hover:bg-green-900/20 px-1 border-l-2 border-transparent hover:border-green-500",
                                            span { class: "opacity-50 mr-2", "[LOG]" }
                                            "{log}"
                                        }
                                    }
                                },
                                _ => rsx! {
                                    div { class: "opacity-50",
                                        p { "> System Ready." }
                                        p { "> Awaiting Command input..." }
                                    }
                                }
                            }
                        }
                         // Blinking cursor footer
                        div { class: "p-2 border-t border-green-800 bg-black text-xs",
                            span { class: "animate-pulse", "█" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn StatRow(label: String, value: String, active: bool) -> Element {
    rsx! {
        div { class: "flex justify-between items-center group",
            span { class: "text-green-700 uppercase text-sm group-hover:text-green-400 transition-colors", "{label}" }
            div { class: "flex items-center",
                span { class: "font-bold text-green-400 group-hover:text-white group-hover:shadow-[0_0_8px_#22c55e] transition-all", "{value}" }
                if active {
                    div { class: "w-1.5 h-1.5 ml-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_5px_#22c55e]" }
                }
            }
        }
    }
}

#[component]
fn Vault() -> Element {
    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono",
            h1 { class: "text-4xl mb-4 font-bold uppercase", "Secure Vault" }
            div { class: "p-12 border border-green-800 border-dashed flex items-center justify-center opacity-50",
                "ACCESS RESTRICTED // BIOMETRIC SCAN REQUIRED"
            }
        }
    }
}

#[component]
fn Network() -> Element {
    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono",
            h1 { class: "text-4xl mb-4 font-bold uppercase", "Network Grid" }
             div { class: "grid grid-cols-4 gap-4",
                for i in 0..4 {
                    div { class: "border border-green-800 p-4 aspect-square flex items-center justify-center hover:bg-green-900/20 transition-all",
                        "NODE_0{i}"
                    }
                }
             }
        }
    }
}

#[component]
fn Login() -> Element {
    let mut auth_url = use_signal(|| String::new());
    let mut error = use_signal(|| String::new());

    let handle_login = move |provider: String| async move {
        match get_sso_auth_url(provider).await {
            Ok(url) => {
                let nav = use_navigator();
                // Dioxus web doesn't have direct window access in server fun calls easily without eval
                // usage of eval:
                let mut eval = document::eval(&format!("window.location.href = '{}'", url));
                let _ = eval.recv::<serde_json::Value>().await;
            }
            Err(e) => error.set(e.to_string()),
        }
    };

    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono flex flex-col items-center justify-center",
            h1 { class: "text-4xl mb-8 font-bold uppercase tracking-widest", "Identity Verification" }

            if !error.read().is_empty() {
                div { class: "mb-4 p-4 border border-red-500 text-red-500", "{error}" }
            }

            div { class: "space-y-4 w-full max-w-md",
                button {
                    class: "w-full py-3 border border-green-800 hover:bg-green-900/20 transition-all uppercase tracking-wider",
                    onclick: move |_| handle_login("azure".to_string()),
                    "Authenticate via Azure AD"
                }
                button {
                    class: "w-full py-3 border border-green-800 hover:bg-green-900/20 transition-all uppercase tracking-wider",
                    onclick: move |_| handle_login("okta".to_string()),
                    "Authenticate via Okta"
                }
                button {
                    class: "w-full py-3 border border-yellow-800 text-yellow-500 hover:bg-yellow-900/20 transition-all uppercase tracking-wider",
                    onclick: move |_| handle_login("mock".to_string()),
                    "Test Mock Login (Dev)"
                }
                 Link { to: Route::Dashboard {}, class: "block text-center mt-8 opacity-50 hover:opacity-100", "Bypass (Dev Mode)" }
            }
        }
    }
}

#[component]
fn Callback(provider: String, code: String, state: String) -> Element {
    let navigator = use_navigator();
    let mut status_msg = use_signal(|| "Verifying Token...".to_string());
    let mut error_msg = use_signal(|| Option::<String>::None);

    let _verification = use_resource(move || {
        let provider = provider.clone();
        let code = code.clone();
        let state = state.clone();
        async move {
            match handle_sso_callback(provider, code, state).await {
                Ok(_) => {
                    status_msg.set("Access Granted. Redirecting...".to_string());
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    navigator.push(Route::Dashboard {});
                }
                Err(e) => {
                    error_msg.set(Some(e.to_string()));
                    status_msg.set("Authentication Failed".to_string());
                }
            }
        }
    });

    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono flex items-center justify-center flex-col space-y-4",
            div { class: "text-center animate-pulse",
                h2 { class: "text-xl font-bold uppercase", "{status_msg}" }
                if let Some(error) = error_msg() {
                    p { class: "text-red-500 mt-2", "{error}" }
                    Link { to: Route::Login {}, class: "mt-4 inline-block border border-green-800 px-4 py-2 hover:bg-green-900/20", "Return to Login" }
                } else {
                    p { class: "text-sm opacity-50", "Processing handshake with provider" }
                }
            }
        }
    }
}

#[component]
fn Database() -> Element {
    let mut selected_table = use_signal(|| "vault".to_string());
    let mut search_query = use_signal(|| String::new());
    let mut is_add_modal_open = use_signal(|| false);

    // Add Modals states
    let mut new_key = use_signal(|| String::new());
    let mut new_value = use_signal(|| "{}".to_string());
    let mut error_msg = use_signal(|| String::new());

    let mut records_resource = use_resource(move || {
        let table = selected_table.read().clone();
        async move { get_records(table).await }
    });

    let delete_handler = move |id: String| async move {
        let table = selected_table.read().clone();
        if let Ok(_) = delete_record(table, id).await {
            records_resource.restart();
        }
    };

    let add_handler = move |_| async move {
        let table = selected_table.read().clone();
        let key = new_key.read().clone();
        let data = new_value.read().clone();

        match add_record(table, key, data).await {
            Ok(_) => {
                is_add_modal_open.set(false);
                new_key.set(String::new());
                new_value.set("{}".to_string());
                records_resource.restart();
            }
            Err(e) => error_msg.set(e.to_string()),
        }
    };

    rsx! {
        div { class: "min-h-screen bg-black text-green-500 p-8 font-mono",
            Link { to: Route::Dashboard {}, class: "mb-8 inline-block hover:underline", "< RETURN TO HUD" }

            div { class: "flex justify-between items-center mb-8",
                h1 { class: "text-4xl font-bold uppercase", "Database Manager" }
                button {
                    class: "px-4 py-2 border border-green-500 hover:bg-green-900/40 uppercase font-bold",
                    onclick: move |_| is_add_modal_open.set(true),
                    "Add Record [+]"
                }
            }

            // Tab Bar
            div { class: "flex space-x-1 mb-6 border-b border-green-800",
                for tab in vec!["vault", "shards", "forensics"] {
                    button {
                        class: if selected_table() == tab { "px-4 py-2 bg-green-900/40 border-t border-l border-r border-green-500 text-white font-bold uppercase" } else { "px-4 py-2 text-green-700 hover:text-green-500 uppercase" },
                        onclick: move |_| selected_table.set(tab.to_string()),
                        "{tab}"
                    }
                }
            }

            // Search Filter
            div { class: "mb-6",
                input {
                    class: "w-full bg-black border border-green-800 p-2 text-green-500 focus:border-green-500 focus:outline-none",
                    placeholder: "Filter by ID...",
                    oninput: move |evt| search_query.set(evt.value())
                }
            }

            // Data Grid
            div { class: "border border-green-800",
                div { class: "grid grid-cols-12 bg-green-900/20 p-2 font-bold uppercase text-xs border-b border-green-800",
                    div { class: "col-span-3", "Record ID" }
                    div { class: "col-span-1", "Vector" }
                    div { class: "col-span-7", "Data Payload" }
                    div { class: "col-span-1 text-right", "Actions" }
                }

                match &*records_resource.read() {
                    Some(Ok(records)) => {
                        let filtered_records = records.iter().filter(|r| search_query.read().is_empty() || r.id.contains(&*search_query.read()));
                        rsx! {
                            for record in filtered_records {
                                {
                                    let id = record.id.clone();
                                    rsx! {
                                        div { class: "grid grid-cols-12 p-2 border-b border-green-900/30 hover:bg-green-900/10 text-sm font-mono items-center",
                                            div { class: "col-span-3 truncate font-bold", "{record.id}" }
                                            div { class: "col-span-1 text-xs opacity-70", "{record.has_vector}" }
                                            div { class: "col-span-7 font-mono text-xs opacity-80 truncate", "{record.data}" }
                                            div { class: "col-span-1 text-right",
                                                button {
                                                    class: "text-red-500 hover:text-red-300 hover:underline text-xs uppercase",
                                                    onclick: move |_| delete_handler(id.clone()),
                                                    "[DEL]"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Some(Err(e)) => rsx! { div { class: "p-4 text-red-500", "Error loading data: {e}" } },
                    None => rsx! { div { class: "p-4 animate-pulse", "Accessing Secure Storage..." } }
                }
            }

            // Add Modal
            if is_add_modal_open() {
                div { class: "fixed inset-0 bg-black/90 flex items-center justify-center z-50",
                    div { class: "bg-gray-900 border border-green-500 p-8 w-full max-w-lg shadow-[0_0_20px_rgba(34,197,94,0.2)]",
                        h2 { class: "text-xl font-bold uppercase mb-6 border-b border-green-800 pb-2", "Inject New Record" }

                        if !error_msg().is_empty() {
                            div { class: "text-red-500 mb-4 text-sm border border-red-900 p-2 bg-red-900/10", "{error_msg}" }
                        }

                        div { class: "space-y-4",
                            div {
                                label { class: "block text-xs uppercase mb-1", "Partition (Table)" }
                                div { class: "p-2 bg-black border border-green-800 text-gray-500", "{selected_table}" }
                            }
                            div {
                                label { class: "block text-xs uppercase mb-1", "Record ID (Unique Key)" }
                                input {
                                    class: "w-full bg-black border border-green-800 p-2 text-white focus:border-green-500 focus:outline-none",
                                    value: "{new_key}",
                                    oninput: move |evt| new_key.set(evt.value())
                                }
                            }
                            div {
                                label { class: "block text-xs uppercase mb-1", "JSON Data Payload" }
                                textarea {
                                    class: "w-full h-32 bg-black border border-green-800 p-2 text-white font-mono text-xs focus:border-green-500 focus:outline-none",
                                    value: "{new_value}",
                                    oninput: move |evt| new_value.set(evt.value())
                                }
                            }
                        }

                        div { class: "flex justify-end space-x-4 mt-8",
                            button {
                                class: "px-4 py-2 text-green-700 hover:text-white uppercase text-sm",
                                onclick: move |_| is_add_modal_open.set(false),
                                "Cancel"
                            }
                            button {
                                class: "px-6 py-2 bg-green-900/50 border border-green-500 hover:bg-green-600 hover:text-black uppercase font-bold transition-all",
                                onclick: add_handler,
                                "Commit Write"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn App() -> Element {
    rsx! {
        // Tailwind CDN and Lucide Icons
         script { src: "https://cdn.tailwindcss.com" }
         script { src: "https://unpkg.com/lucide@latest" }
         Router::<Route> {}
    }
}

// --- Placeholder Pages ---

#[component]
fn SecurityPage() -> Element {
    rsx! {
        div { class: "p-8",
            h1 { class: "text-3xl font-bold mb-4", "Security Operations Center" }
            p { class: "text-gray-400", "Threat detection and response modules." }
            div { class: "grid grid-cols-3 gap-6 mt-8",
                div { class: "p-6 bg-gray-800 rounded border border-red-900/30",
                    h3 { class: "text-lg font-bold text-red-500", "Active Threats" }
                    p { class: "text-4xl font-mono mt-2", "0" }
                }
                div { class: "p-6 bg-gray-800 rounded border border-blue-900/30",
                    h3 { class: "text-lg font-bold text-blue-500", "Behavioral Score" }
                    p { class: "text-4xl font-mono mt-2", "98/100" }
                }
            }
        }
    }
}

#[component]
fn SystemPage() -> Element {
    rsx! { div { class: "p-8", h1 { class: "text-2xl font-bold", "System Administration" } } }
}

#[component]
fn IntelligencePage() -> Element {
    rsx! { div { class: "p-8", h1 { class: "text-2xl font-bold", "Threat Intelligence" } } }
}

#[component]
fn CompliancePage() -> Element {
    rsx! { div { class: "p-8", h1 { class: "text-2xl font-bold", "Compliance & Reporting" } } }
}

#[component]
fn AdministrationPage() -> Element {
    rsx! { div { class: "p-8", h1 { class: "text-2xl font-bold", "User Administration" } } }
}

#[component]
fn SettingsPage() -> Element {
    rsx! { div { class: "p-8", h1 { class: "text-2xl font-bold", "Settings" } } }
}

// --- Main / Server Entry ---

#[cfg(feature = "server")]
#[tokio::main]
async fn main() {
    // Initialize Prowler
    let db_path = std::env::var("WOLF_DB_PATH").unwrap_or_else(|_| "./wolf_data".to_string());

    // We try to init the store, might fail if db is locked, handle gracefully or panic for now
    if let Ok(store) = lock_prowler::storage::WolfStore::new(&db_path) {
        let config = HeadlessConfig::default();
        let prowler = HeadlessWolfProwler::new(config, store);
        *PROWLER.lock().await = Some(prowler);
    } else {
        eprintln!("Failed to initialize WolfStore (DB might be locked). Running in limited mode.");
    }

    // Initialize SSO
    let sso_config = IAMConfig::default();
    match SSOIntegrationManager::new(sso_config).await {
        Ok(sso) => {
            *SSO_MANAGER.lock().await = Some(sso);
            println!("SSO Manager Initialized");
        }
        Err(e) => eprintln!("Failed to initialize SSO: {}", e),
    }

    // Initialize Dashboard
    let dashboard_state = dashboard::init().await;
    let dashboard_router = dashboard::create_router(dashboard_state).await;

    // Initialize Axum Router
    let app = Router::new()
        .merge(dashboard_router)
        .serve_dioxus_application(
            ServeConfig::builder()
                .index_path("wolf_web/assets/index.html".into())
                .build()
                .unwrap(),
            App,
        )
        .layer(CorsLayer::permissive());

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    println!("Wolf Prowler Dashboard Online: http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

#[cfg(not(feature = "server"))]
fn main() {
    dioxus::launch(App);
}
