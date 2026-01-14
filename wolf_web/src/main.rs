#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(unused_qualifications)]

use anyhow::{Context, Result};
use axum::Router;
use chrono::Utc;
use dioxus::prelude::*;
use dioxus_fullstack::prelude::*;
use lock_prowler::headless::HeadlessConfig;
use lock_prowler::headless::HeadlessWolfProwler;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
#[cfg(feature = "server")]
use wolf_web::dashboard;
#[cfg(feature = "server")]
use wolf_web::dashboard::state::AppState;
use wolfsec::identity::iam::{AuthenticationManager, IAMConfig, SSOIntegrationManager};
use wolfsec::threat_detection::BehavioralAnalyzer;

mod vault_components;
use crate::vault_components::*;

mod ui_kit;
use crate::ui_kit::*;

mod dashboard_components;
use crate::dashboard_components::*;

mod pages;
use crate::pages::admin::AdministrationPage;
use crate::pages::compliance::CompliancePage;
use crate::pages::database::DatabasePage;
use crate::pages::intelligence::IntelligencePage;
use crate::pages::logs::LogsPage;
use crate::pages::security::SecurityPage;
use crate::pages::settings::SettingsPage;
use crate::pages::system::SystemPage;
use crate::pages::wolfpack::WolfPackPage;

// --- Types & State ---
use wolf_web::types::*;

// Global state simulation
// Global state is now in crate::globals
use wolf_web::dashboard::api::server_fns::{
    add_record, delete_record, get_fullstack_stats, get_prowler_logs, get_records,
    get_sso_auth_url, handle_sso_callback, run_prowler_scan,
};
use wolf_web::globals::{PROWLER, SECURITY_ENGINE, SSO_MANAGER, SWARM_MANAGER};

// --- Server Functions (Dioxus 0.6 RPC) ---

// Server functions moved to wolf_web::dashboard::api::server_fns

// --- Routing ---

#[derive(Clone, Routable, Debug, PartialEq, Serialize, Deserialize)]
pub enum Route {
    #[layout(DashboardLayout)]
    #[route("/")]
    Dashboard {},
    #[route("/security")]
    SecurityPage {},
    #[route("/system")]
    SystemPage {},
    #[route("/wolfpack")]
    WolfPackPage {},
    #[route("/logs")]
    LogsPage {},
    #[route("/intelligence")]
    IntelligencePage {},
    #[route("/compliance")]
    CompliancePage {},
    #[route("/admin")]
    AdministrationPage {},
    #[route("/settings")]
    SettingsPage {},
    #[route("/database")]
    DatabasePage {},
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
                    .and_then(|v| -> Option<js_sys::Function> {
                        v.dyn_into::<js_sys::Function>().ok()
                    })
                {
                    let _ = create_icons.call0(&lucide);
                }
            }
        }
    });

    rsx! {
        div { class: "flex min-h-screen bg-black text-green-500 font-mono bg-[url('https://www.transparenttextures.com/patterns/dark-matter.png')] text-shadow-[0_0_2px_rgba(74,222,128,0.5)]",
            Sidebar {}
            main { class: "flex-1 p-8 overflow-auto relative",
                // Vignette overlay
                div { class: "pointer-events-none fixed inset-0 z-50 bg-[radial-gradient(circle_at_center,transparent_0%,rgba(0,0,0,0.4)_100%)] inset-0 w-full h-full" }
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
                SidebarLink { to: Route::WolfPackPage {}, icon: "network", label: "WolfPack" }
                SidebarLink { to: Route::SystemPage {}, icon: "cpu", label: "System" }
                SidebarLink { to: Route::IntelligencePage {}, icon: "brain", label: "Intelligence" }
                SidebarLink { to: Route::CompliancePage {}, icon: "file-check", label: "Compliance" }
                SidebarLink { to: Route::AdministrationPage {}, icon: "users", label: "Administration" }
                SidebarLink { to: Route::SettingsPage {}, icon: "settings", label: "Settings" }
                SidebarLink { to: Route::DatabasePage {}, icon: "database", label: "Database" }
                SidebarLink { to: Route::Vault {}, icon: "lock", label: "Vault" }
                SidebarLink { to: Route::LogsPage {}, icon: "file-text", label: "Logs" }
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
    let mut stats_resource = use_resource(get_fullstack_stats);
    let mut scan_status = use_signal(|| String::new());
    let mut is_loading = use_signal(|| false);
    let mut logs_resource = use_resource(get_prowler_logs);
    let mut progress = use_signal(|| 0.0f32);

    let stats = stats_resource
        .read()
        .clone()
        .unwrap_or(Ok(SystemStats {
            volume_size: "---".to_string(),
            encrypted_sectors: 0.0,
            entropy: 0.0,
            db_status: "OFFLINE".to_string(),
            active_nodes: 0,
            threat_level: "UNKNOWN".to_string(),
            active_alerts: 0,
            scanner_status: "IDLE".to_string(),
            network_status: "DISCONNECTED".to_string(),
            firewall: FirewallStats::default(),
        }))
        .unwrap_or(SystemStats {
            volume_size: "Error".to_string(),
            encrypted_sectors: 0.0,
            entropy: 0.0,
            db_status: "ERROR".to_string(),
            active_nodes: 0,
            threat_level: "ERROR".to_string(),
            active_alerts: 0,
            scanner_status: "ERROR".to_string(),
            network_status: "ERROR".to_string(),
            firewall: FirewallStats::default(),
        });

    // Mock history data for sparklines (would be real in prod)
    let threat_history = vec![10.0, 20.0, 15.0, 40.0, 30.0, 60.0, 20.0, 10.0];
    let network_history = vec![50.0, 55.0, 60.0, 58.0, 65.0, 70.0, 75.0, 80.0];

    rsx! {
        div { class: "min-h-screen text-green-500 font-mono p-6 relative flex flex-col gap-6",
            // 1. Top Bar / HUD
            div { class: "flex justify-between items-end border-b border-green-900/50 pb-4",
                div {
                    h2 { class: "text-3xl font-bold text-white tracking-widest uppercase flex items-center gap-3",
                        i { class: "lucide-layout-dashboard" }
                        "Command Center"
                    }
                    div { class: "flex items-center gap-4 mt-2",
                        Badge { label: format!("NET: {}", stats.network_status), color: if stats.network_status == "ONLINE" { "green".to_string() } else { "red".to_string() } }
                        Badge { label: format!("DB: {}", stats.db_status), color: "blue".to_string() }
                        span { class: "text-xs text-green-500/60 uppercase tracking-wider", "System Uptime: 42h 12m" }
                    }
                }
                div { class: "flex gap-2",
                     Button { onclick: move |_| { stats_resource.restart(); logs_resource.restart(); },
                        i { class: "lucide-refresh-cw w-4 h-4 mr-2" } "Refresh"
                     }
                     Link { to: Route::Login {}, class: "px-4 py-2 border border-red-900/50 bg-red-950/20 text-red-500 hover:bg-red-900/40 rounded uppercase text-xs font-bold tracking-wider transition-all flex items-center",
                        i { class: "lucide-log-out w-4 h-4 mr-2" } "Logout"
                     }
                }
            }

            // 2. Metrics Grid (Sparklines & Key Data)
            div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6",
                Card {
                    h3 { class: "text-gray-400 text-xs uppercase tracking-widest mb-2", "Threat Level" }
                    div { class: "flex justify-between items-end",
                        span { class: "text-3xl font-bold text-white", "{stats.threat_level}" }
                        Sparkline { data: threat_history, width: 80.0, height: 25.0, color: if stats.threat_level == "CRITICAL" { "red".to_string() } else { "green".to_string() } }
                    }
                }
                Card {
                    h3 { class: "text-gray-400 text-xs uppercase tracking-widest mb-2", "Active Nodes" }
                    div { class: "flex justify-between items-end",
                        span { class: "text-3xl font-bold text-white", "{stats.active_nodes}" }
                        Sparkline { data: network_history, width: 80.0, height: 25.0, color: "blue".to_string() }
                    }
                }
                Card {
                    h3 { class: "text-gray-400 text-xs uppercase tracking-widest mb-2", "Volume Encrypted" }
                    div { class: "flex justify-between items-end",
                        span { class: "text-3xl font-bold text-white", "{stats.encrypted_sectors}%" }
                        i { class: "lucide-lock w-8 h-8 text-green-500 opacity-50" }
                    }
                }
                Card {
                    h3 { class: "text-gray-400 text-xs uppercase tracking-widest mb-2", "Active Alerts" }
                    div { class: "flex justify-between items-end",
                        span { class: "text-3xl font-bold text-yellow-500", "{stats.active_alerts}" }
                        i { class: "lucide-bell w-8 h-8 text-yellow-500 opacity-50" }
                    }
                }
            }

            // 3. Main Operations Area (Split View)
            div { class: "grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1",
                // Left: Scanner Control & Detailed Status
                div { class: "space-y-6",
                    Card {
                        h3 { class: "text-lg font-bold mb-4 uppercase border-b border-green-800/50 pb-2 flex items-center gap-2",
                             i { class: "lucide-scan-line" } "Deep Scan Control"
                        }
                        div { class: "space-y-4",
                            div { class: "flex justify-between text-sm",
                                span { "Scanner Status:" }
                                span { class: "font-bold", "{stats.scanner_status}" }
                            }
                            if is_loading() || progress() > 0.0 {
                                div { class: "w-full bg-black border border-green-900 h-2 relative overflow-hidden rounded",
                                    div {
                                        class: "bg-green-500 h-full transition-all duration-200",
                                        style: "width: {progress()}%"
                                    }
                                }
                            }
                            Button {
                                class: "w-full py-4 text-lg",
                                disabled: is_loading(),
                                onclick: move |_| async move {
                                    is_loading.set(true);
                                    progress.set(0.0);
                                    scan_status.set("INITIATING...".to_string());
                                    // Mock progress
                                    for i in 0..10 {
                                        progress.set(i as f32 * 10.0);
                                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                                    }
                                    match run_prowler_scan().await {
                                        Ok(msg) => scan_status.set(msg),
                                        Err(e) => scan_status.set(format!("ERROR: {e}")),
                                    }
                                    progress.set(100.0);
                                    is_loading.set(false);
                                },
                                if is_loading() { "SCANNING..." } else { "INITIALIZE SCAN" }
                            }
                            if !scan_status.read().is_empty() {
                                div { class: "p-2 bg-black/50 border-l-2 border-green-500 text-xs font-mono text-green-300",
                                    "> {scan_status}"
                                }
                            }
                        }
                    }

                    // Quick Actions
                    Card {
                        h3 { class: "text-lg font-bold mb-4 uppercase border-b border-green-800/50 pb-2", "Quick Actions" }
                        div { class: "grid grid-cols-2 gap-2",
                            Button { class: "text-xs", "Flush Cache" }
                            Button { class: "text-xs", "Rotate Keys" }
                            Button { class: "text-xs", "Export Logs" }
                            Button { class: "text-xs text-red-400 border-red-900/50 hover:bg-red-900/20", "Emergency Stop" }
                        }
                    }
                }

                // Right: Live Terminal / Map
                div { class: "lg:col-span-2 flex flex-col h-full",
                    div { class: "border border-green-800 bg-black/90 flex-1 rounded flex flex-col relative overflow-hidden shadow-[0_0_30px_rgba(0,0,0,0.8)] min-h-[400px]",
                        // Terminal Header
                        div { class: "p-2 border-b border-green-800 bg-green-900/20 flex justify-between items-center",
                            div { class: "flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-green-400/80",
                                i { class: "lucide-terminal-square w-4 h-4" }
                                "System Output Stream"
                            }
                            div { class: "flex space-x-1",
                                div { class: "w-2 h-2 rounded-full bg-red-900/50" }
                                div { class: "w-2 h-2 rounded-full bg-yellow-900/50" }
                                div { class: "w-2 h-2 rounded-full bg-green-900/50" }
                            }
                        }

                        // Terminal Body
                        div { class: "flex-1 p-4 font-mono text-sm overflow-y-auto space-y-1 font-medium relative",
                            // Scanline Overlay
                            div { class: "pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%] z-20 opacity-20" }

                            match &*logs_resource.read() {
                                Some(Ok(logs)) => rsx! {
                                    {logs.into_iter().map(|log| {
                                        let ts = Utc::now().format("%H:%M:%S").to_string();
                                        rsx! {
                                            div { class: "hover:bg-green-500/10 px-2 py-0.5 border-l-2 border-transparent hover:border-green-500 transition-colors text-green-100/90 text-shadow-sm",
                                                span { class: "opacity-50 mr-3 text-green-600 text-[10px]", "[{ts}]" }
                                                span { class: "text-green-400 mr-2", ">" }
                                                "{log}"
                                            }
                                        }
                                    })}
                                },
                                _ => rsx! {
                                    div { class: "opacity-50", "> System Ready. Waiting for data..." }
                                }
                            }
                             // Cursor
                            div { class: "p-2 mt-4 text-xs flex items-center gap-2",
                                span { class: "text-green-500 font-bold", "root@wolf_prowler:~#"}
                                span { class: "w-2 h-4 bg-green-500 animate-[pulse_1s_steps(2)_infinite]" }
                            }
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
            Link { to: Route::Dashboard {}, class: "mb-8 inline-block hover:underline", "< RETURN TO HUD" }

            div { class: "flex justify-between items-center mb-8",
                h1 { class: "text-4xl font-bold uppercase tracking-widest", "Crypto Vault" }
                 div { class: "flex items-center space-x-2 bg-green-900/20 px-4 py-2 rounded-full border border-green-500/30",
                    div { class: "w-2 h-2 bg-green-500 rounded-full animate-pulse" }
                    span { class: "text-xs font-bold uppercase", "Engine Active" }
                }
            }

            // Overview Section
            VaultOverview {}

            // Tools Section
            VaultTools {}

            // Key Management Section
            VaultKeys {}
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
    let _auth_url = use_signal(|| String::new());
    let mut error = use_signal(|| String::new());

    let handle_login = move |provider: String| async move {
        match get_sso_auth_url(provider).await {
            Ok(url) => {
                let _nav = use_navigator();
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

// Placeholders removed, imported from pages module

// --- Main / Server Entry ---

#[cfg(feature = "server")]
#[tokio::main]
async fn main() {
    // Initialize Prowler
    let db_path = std::env::var("WOLF_DB_PATH").unwrap_or_else(|_| "./wolf_data".to_string());

    // We try to init the store, might fail if db is locked, handle gracefully or panic for now
    if let Ok(store) = lock_prowler::storage::WolfStore::new(&db_path).await {
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

    // Initialize Security Engine
    let mut sec_config = wolfsec::WolfSecurityConfig::default();
    sec_config.db_path = std::path::PathBuf::from(&db_path).join("wolfsec.db");

    // Create shared components
    let wolf_security = match wolfsec::WolfSecurity::create(sec_config).await {
        Ok(mut sec) => {
            if let Err(e) = sec.initialize().await {
                eprintln!("Failed to initialize WolfSecurity components: {}", e);
            }
            println!("Wolf Security Engine Initialized");
            Some(Arc::new(RwLock::new(sec)))
        }
        Err(e) => {
            eprintln!("Failed to create WolfSecurity: {}", e);
            None
        }
    };

    // Update global reference
    if let Some(_sec) = &wolf_security {
        // ... (commented out code in original)
    }

    // Initialize SwarmManager (for Firewall stats)
    let swarm_config = wolf_net::SwarmConfig::default();
    match wolf_net::SwarmManager::new(swarm_config) {
        Ok(swarm) => {
            *SWARM_MANAGER.lock().await = Some(Arc::new(swarm));
            println!("Swarm Manager Initialized");
        }
        Err(e) => eprintln!("Failed to initialize Swarm Manager: {}", e),
    }

    // Initialize Authentication Manager (IAM)
    let _auth_manager: AuthenticationManager = AuthenticationManager::new(IAMConfig::default())
        .await
        .expect("Failed to initialize Authentication Manager");

    // Initialize Behavioral Analyzer (Default for now)
    let behavioral_engine = BehavioralAnalyzer {
        baseline_window: 100,
        deviation_threshold: 2.0,
        patterns_detected: 0,
    };

    // Prepare AppState components
    let threat_detector = if let Some(sec) = &wolf_security {
        sec.read().await.threat_detector.clone()
    } else {
        // Fallback or error
        wolfsec::ThreatDetector::new(
            wolfsec::threat_detection::ThreatDetectionConfig::default(),
            Arc::new(dashboard::MockThreatRepository),
        )
    };

    // Create AppState

    // Hack: We need SwarmManager for with_system_components.
    // Creating a placeholder SwarmManager might have side effects (binding ports).
    // Let's construct AppState manually if needed or update AppState.
    // AppState struct fields are public.

    let real_app_state = match wolf_security {
        Some(sec) => {
            AppState {
                threat_engine: Arc::new(Mutex::new(sec.read().await.threat_detector.clone())),
                behavioral_engine: Arc::new(Mutex::new(behavioral_engine)),
                request_count: Arc::new(Mutex::new(0)),
                websocket_state: Arc::new(wolf_web::dashboard::websocket::WebSocketState::new()),
                auth_manager: Arc::new(Mutex::new(
                    AuthenticationManager::new(IAMConfig::default())
                        .await
                        .expect("Failed to init auth manager"),
                )), // Re-init auth manager? No, use the one we made.
                wolf_security: Some(sec.clone()),
                swarm_manager: None, // Keep None for now
            }
        }
        None => AppState::new(
            threat_detector,
            behavioral_engine,
            AuthenticationManager::new(IAMConfig::default())
                .await
                .expect("Failed to init auth manager fallback"),
        ),
    };

    // Initialize Global for legacy access if possible, or just accept it's broken for now.
    // *APP_STATE.lock().await = Some(real_app_state.clone());

    // Initialize Dashboard Router with State
    let dashboard_router = dashboard::create_router_with_state(real_app_state.clone()).await;

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
    // .with_state(Arc::new(real_app_state)); // Inject state into Axum

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    println!("Wolf Prowler Dashboard Online: http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}

#[cfg(not(feature = "server"))]
fn main() {
    dioxus::launch(App);
}
