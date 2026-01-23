#![allow(missing_docs)]
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Sparkline, Tabs, Wrap},
    Frame, Terminal,
};
use serde::Deserialize;
use thiserror::Error;
use wolf_control::config::Config;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time;

// --- Data Structures (Mirroring Server API) ---

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThemeMode {
    Standard,
    Hacker,
    Predator,
    Cyberpunk,
}

impl ThemeMode {
    pub fn next(&self) -> Self {
        match self {
            ThemeMode::Standard => ThemeMode::Hacker,
            ThemeMode::Hacker => ThemeMode::Cyberpunk,
            ThemeMode::Cyberpunk => ThemeMode::Predator,
            ThemeMode::Predator => ThemeMode::Standard,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LogFilter {
    All,
    Info,
    Warn,
    Error,
    Debug,
}

impl LogFilter {
    pub fn next(&self) -> Self {
        match self {
            LogFilter::All => LogFilter::Info,
            LogFilter::Info => LogFilter::Warn,
            LogFilter::Warn => LogFilter::Error,
            LogFilter::Error => LogFilter::Debug,
            LogFilter::Debug => LogFilter::All,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            LogFilter::All => "ALL",
            LogFilter::Info => "INFO",
            LogFilter::Warn => "WARN",
            LogFilter::Error => "ERROR",
            LogFilter::Debug => "DEBUG",
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
struct NodeStatus {
    peer_id: String,
    version: String,
    uptime_seconds: u64,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct NetworkMetrics {
    total_bytes_sent: u64,
    total_bytes_received: u64,
    active_connections: usize,
    messages_sent: u64,
    messages_received: u64,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct Member {
    pub peer_id: String,
    pub rank: String,
    pub trust_score: f64,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct WolfPack {
    pub pack_name: String,
    pub alpha_id: Option<String>,
    pub members: HashMap<String, Member>,
}

/// Server configuration (fetched from wolf_server /config endpoint)
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct ServerConfig {
    pub p2p_port: u16,
    pub api_port: u16,
    pub max_connections: usize,
    pub admin_password: String,
    pub accept_invalid_certs: bool,
    pub pack_name: String,
    pub default_rank: String,
    pub encryption_enabled: bool,
    pub trust_threshold: f64,
    pub auto_alpha: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            p2p_port: 3030,
            api_port: 3031,
            max_connections: 50,
            pack_name: "Wolf Pack V2".to_string(),
            default_rank: "Omega".to_string(),
            admin_password: "selassie11".to_string(),
            accept_invalid_certs: false,
            encryption_enabled: true,
            trust_threshold: 0.5,
            auto_alpha: true,
        }
    }
}

/// Log entry from server
#[derive(Debug, Clone, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct ZeroTrustStats {
    active_policy_count: usize,
    enforced_policies: u64,
    policy_violations: u64,
    active_segments: usize,
    isolation_events: u64,
}

#[derive(Debug, Clone, Error)]
pub enum ClientError {
    #[error("Authentication Failed: {0}")]
    Auth(String),
    #[error("Connection Refused - Is the server running?")]
    ConnectionRefused,
    #[error("Request Timeout - Server is slow or unreachable")]
    Timeout,
    #[error("Server Error {0}: {1}")]
    Server(u16, String),
    #[error("Response Parse Error: {0}")]
    Parse(String),
    #[error("Configuration Error: {0}")]
    Config(String),
    #[error("I/O Error: {0}")]
    Io(String),
    #[error("Error: {0}")]
    Unknown(String),
}

#[derive(Clone)]
struct AppData {
    status: NodeStatus,
    peers: Vec<String>,
    metrics: NetworkMetrics,
    pack: Option<WolfPack>,
    config: Config,
    server_config: ServerConfig,
    logs: Vec<LogEntry>,
    last_update: String,
    connected: bool,
    // Activity tracking
    tick: u64,
    prev_bytes_sent: u64,
    prev_bytes_recv: u64,
    // New Security Stats
    zero_trust_stats: ZeroTrustStats,
    last_error: Option<ClientError>,
    is_fetching: bool,
}

impl Default for AppData {
    fn default() -> Self {
        Self {
            status: NodeStatus::default(),
            peers: Vec::new(),
            metrics: NetworkMetrics::default(),
            pack: None,
            config: Config::default(),
            server_config: ServerConfig::default(),
            logs: Vec::new(),
            last_update: "Never".to_string(),
            connected: false,
            tick: 0,
            prev_bytes_sent: 0,
            prev_bytes_recv: 0,
            zero_trust_stats: ZeroTrustStats::default(),
            last_error: None,
            is_fetching: false,
        }
    }
}

// --- Application State ---

#[derive(Debug, PartialEq, Eq)]
enum Tab {
    Overview,
    Peers,
    Pack,
    Security,
    Logs,
    Metrics,
    Config,
    Verify,
}

impl Tab {
    fn title(&self) -> &str {
        match self {
            Tab::Overview => "Overview",
            Tab::Peers => "Peers",
            Tab::Pack => "Pack",
            Tab::Security => "Security",
            Tab::Logs => "Logs",
            Tab::Metrics => "Metrics",
            Tab::Config => "Config",
            Tab::Verify => "Verify",
        }
    }

    fn next(&self) -> Self {
        match self {
            Tab::Overview => Tab::Peers,
            Tab::Peers => Tab::Pack,
            Tab::Pack => Tab::Security,
            Tab::Security => Tab::Logs,
            Tab::Logs => Tab::Metrics,
            Tab::Metrics => Tab::Config,
            Tab::Config => Tab::Verify,
            Tab::Verify => Tab::Overview,
        }
    }

    fn prev(&self) -> Self {
        match self {
            Tab::Overview => Tab::Config,
            Tab::Peers => Tab::Overview,
            Tab::Pack => Tab::Peers,
            Tab::Security => Tab::Pack,
            Tab::Logs => Tab::Security,
            Tab::Metrics => Tab::Logs,
            Tab::Config => Tab::Metrics,
            Tab::Verify => Tab::Config,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AppState {
    Login,
    Main,
}

// --- Application State ---

struct App {
    state: AppState,
    login_input: String,
    login_error: Option<String>,
    current_tab: Tab,
    data: Arc<Mutex<AppData>>,
    should_quit: bool,
    api_url: String,
    config_path: String,
    selected_peer_index: usize,
    show_help: bool,
    command_mode: bool,
    command_input: String,
    command_result: Option<String>,
    // New Features
    sparkline_data: Vec<u64>,
    theme_mode: ThemeMode,
    show_hex_inspector: bool,
    last_packet: Option<Vec<u8>>,
    log_filter: LogFilter,
    // Verification Tool State
    verify_inputs: [String; 5],
    active_verify_input: usize,
    verify_result: Option<String>,
    is_verifying: bool,
    refresh_notify: Arc<tokio::sync::Notify>,
}

impl App {
    fn new(api_url: String, config_path: String) -> Self {
        Self {
            state: AppState::Login,
            login_input: String::new(),
            login_error: None,
            current_tab: Tab::Overview,
            data: Arc::new(Mutex::new(AppData::default())),
            should_quit: false,
            api_url,
            config_path,
            selected_peer_index: 0,
            show_help: false,
            command_mode: false,
            command_input: String::new(),
            command_result: None,
            sparkline_data: vec![0; 100],
            theme_mode: ThemeMode::Standard,
            show_hex_inspector: false,
            last_packet: None,
            verify_inputs: [
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ],
            active_verify_input: 0,
            verify_result: None,
            is_verifying: false,
            log_filter: LogFilter::All,
            refresh_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn execute_command(&mut self) {
        let cmd = self.command_input.trim().to_lowercase();
        let parts: Vec<&str> = cmd.split_whitespace().collect();

        self.command_result = Some(match parts.first().copied() {
            Some("help") | Some("h") => {
                "Commands: help, quit, tab <name>, dial <addr>, status, clear".to_string()
            }
            Some("quit") | Some("q") => {
                self.should_quit = true;
                "Quitting...".to_string()
            }
            Some("tab") => {
                if let Some(tab_name) = parts.get(1) {
                    match *tab_name {
                        "overview" | "0" => {
                            self.current_tab = Tab::Overview;
                            "Switched to Overview".to_string()
                        }
                        "peers" | "1" => {
                            self.current_tab = Tab::Peers;
                            "Switched to Peers".to_string()
                        }
                        "pack" | "2" => {
                            self.current_tab = Tab::Pack;
                            "Switched to Pack".to_string()
                        }
                        "security" | "3" => {
                            self.current_tab = Tab::Security;
                            "Switched to Security".to_string()
                        }
                        "logs" | "4" => {
                            self.current_tab = Tab::Logs;
                            "Switched to Logs".to_string()
                        }
                        "metrics" | "5" => {
                            self.current_tab = Tab::Metrics;
                            "Switched to Metrics".to_string()
                        }
                        "config" | "6" => {
                            self.current_tab = Tab::Config;
                            "Switched to Config".to_string()
                        }
                        _ => format!("Unknown tab: {}", tab_name),
                    }
                } else {
                    "Usage: tab <overview|peers|pack|security|logs|metrics|config>".to_string()
                }
            }
            Some("status") => {
                let data = self.data.lock().unwrap();
                format!(
                    "Connected: {} | Peers: {} | Uptime: {}s",
                    data.connected,
                    data.peers.len(),
                    data.status.uptime_seconds
                )
            }
            Some("clear") => {
                self.command_result = None;
                "".to_string()
            }
            Some("dial") => {
                if let Some(_addr) = parts.get(1) {
                    "Dial functionality coming soon...".to_string()
                } else {
                    "Usage: dial <multiaddr>".to_string()
                }
            }
            Some("reconnect") | Some("refresh") => {
                self.refresh_notify.notify_one();
                "Triggering immediate refresh...".to_string()
            }
            Some(unknown) => format!(
                "Unknown command: {}. Type 'help' for available commands.",
                unknown
            ),
            None => "".to_string(),
        });

        self.command_input.clear();
        self.command_mode = false;
    }

    fn on_key(&mut self, c: char) {
        match c {
            'q' => self.should_quit = true,
            'n' | '\t' => self.current_tab = self.current_tab.next(),
            'p' => self.current_tab = self.current_tab.prev(),
            '?' => self.show_help = !self.show_help,
            ':' => {
                self.command_mode = true;
                self.command_input.clear();
            }

            // Peer/List navigation
            'j' => {
                let data = self.data.lock().unwrap();
                let max = data.peers.len().saturating_sub(1);
                drop(data);
                if self.selected_peer_index < max {
                    self.selected_peer_index += 1;
                }
            }
            'k' => {
                if self.selected_peer_index > 0 {
                    self.selected_peer_index -= 1;
                }
            }

            // TUI Config Controls
            'v' => {
                let mut data = self.data.lock().unwrap();
                data.config.verbose = !data.config.verbose;
            }
            '+' => {
                let mut data = self.data.lock().unwrap();
                data.config.poll_interval_secs += 1;
            }
            '-' => {
                let mut data = self.data.lock().unwrap();
                if data.config.poll_interval_secs > 1 {
                    data.config.poll_interval_secs -= 1;
                }
            }
            't' => {
                self.theme_mode = match self.theme_mode {
                    ThemeMode::Standard => ThemeMode::Hacker,
                    ThemeMode::Hacker => ThemeMode::Cyberpunk,
                    ThemeMode::Cyberpunk => ThemeMode::Predator,
                    ThemeMode::Predator => ThemeMode::Standard,
                };
            }
            'h' => {
                self.show_hex_inspector = !self.show_hex_inspector;
            }
            'l' => {
                self.log_filter = self.log_filter.next();
            }
            'c' => {
                let mut data = self.data.lock().unwrap();
                data.config = Config::load_from_path(&self.config_path);
            }
            's' => {
                let data = self.data.lock().unwrap();
                let _ = Config::save_to_path(&data.config, &self.config_path);
            }

            // Server Config Controls
            'e' => {
                let mut data = self.data.lock().unwrap();
                data.server_config.encryption_enabled = !data.server_config.encryption_enabled;
            }
            'a' => {
                let mut data = self.data.lock().unwrap();
                data.server_config.auto_alpha = !data.server_config.auto_alpha;
            }
            'm' => {
                let mut data = self.data.lock().unwrap();
                data.server_config.max_connections += 5;
            }
            'M' => {
                let mut data = self.data.lock().unwrap();
                if data.server_config.max_connections > 5 {
                    data.server_config.max_connections -= 5;
                }
            }
            'S' => {
                // Save server config to server via POST
            }
            _ => {}
        }
    }

    fn next_tab(&mut self) {
        self.current_tab = self.current_tab.next();
    }

    fn prev_tab(&mut self) {
        self.current_tab = self.current_tab.prev();
    }

    fn on_network_stats(&mut self, tx: u64, rx: u64) {
        // Calculate effective activity (simple sum for visualization)
        let activity = (tx + rx) / 1024; // KB
        let val = if activity > 50 { 50 } else { activity };
        if !self.sparkline_data.is_empty() {
            self.sparkline_data.remove(0);
        }
        self.sparkline_data.push(val);
    }

    fn get_theme_colors(&self) -> (Color, Color, Color) {
        match self.theme_mode {
            ThemeMode::Standard => (Color::Red, Color::DarkGray, Color::White),
            ThemeMode::Hacker => (Color::Green, Color::Black, Color::Green),
            ThemeMode::Cyberpunk => (Color::Magenta, Color::Cyan, Color::Yellow),
            ThemeMode::Predator => (Color::Red, Color::Black, Color::Red),
        }
    }
}

// --- Main Entry Point ---

// --- Terminal Handling & Graceful Shutdown ---

/// A wrapper around the terminal to ensure cleanup on drop.
pub struct Tui {
    pub terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl Tui {
    /// Initialize the terminal interface
    pub fn new() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    /// Restore terminal to original state
    pub fn exit(&mut self) -> Result<()> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        self.terminal.show_cursor()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tab_title() {
        assert_eq!(Tab::Overview.title(), "Overview");
        assert_eq!(Tab::Peers.title(), "Peers");
        assert_eq!(Tab::Pack.title(), "Pack");
        assert_eq!(Tab::Security.title(), "Security");
        assert_eq!(Tab::Logs.title(), "Logs");
        assert_eq!(Tab::Metrics.title(), "Metrics");
        assert_eq!(Tab::Config.title(), "Config");
        assert_eq!(Tab::Verify.title(), "Verify");
    }

    #[test]
    fn test_tab_next() {
        assert_eq!(Tab::Overview.next(), Tab::Peers);
        assert_eq!(Tab::Peers.next(), Tab::Pack);
        assert_eq!(Tab::Pack.next(), Tab::Security);
        assert_eq!(Tab::Security.next(), Tab::Logs);
        assert_eq!(Tab::Logs.next(), Tab::Metrics);
        assert_eq!(Tab::Metrics.next(), Tab::Config);
        assert_eq!(Tab::Config.next(), Tab::Verify);
        assert_eq!(Tab::Verify.next(), Tab::Overview);
    }

    #[test]
    fn test_tab_prev() {
        assert_eq!(Tab::Overview.prev(), Tab::Config);
        assert_eq!(Tab::Peers.prev(), Tab::Overview);
        assert_eq!(Tab::Pack.prev(), Tab::Peers);
        assert_eq!(Tab::Security.prev(), Tab::Pack);
        assert_eq!(Tab::Logs.prev(), Tab::Security);
        assert_eq!(Tab::Metrics.prev(), Tab::Logs);
        assert_eq!(Tab::Config.prev(), Tab::Metrics);
        assert_eq!(Tab::Verify.prev(), Tab::Config);
    }

    #[test]
    fn test_app_state_debug() {
        assert_eq!(format!("{:?}", AppState::Login), "Login");
        assert_eq!(format!("{:?}", AppState::Main), "Main");
    }

    #[test]
    fn test_node_status_default() {
        let status = NodeStatus::default();
        assert!(status.peer_id.is_empty());
        assert!(status.version.is_empty());
        assert_eq!(status.uptime_seconds, 0);
    }

    #[test]
    fn test_network_metrics_default() {
        let metrics = NetworkMetrics::default();
        assert_eq!(metrics.total_bytes_sent, 0);
        assert_eq!(metrics.total_bytes_received, 0);
        assert_eq!(metrics.active_connections, 0);
        assert_eq!(metrics.messages_sent, 0);
        assert_eq!(metrics.messages_received, 0);
    }

    #[test]
    fn test_zero_trust_stats_default() {
        let stats = ZeroTrustStats::default();
        assert_eq!(stats.active_policy_count, 0);
        assert_eq!(stats.enforced_policies, 0);
        assert_eq!(stats.policy_violations, 0);
        assert_eq!(stats.active_segments, 0);
        assert_eq!(stats.isolation_events, 0);
    }

    #[test]
    fn test_app_data_default() {
        let data = AppData::default();
        assert!(data.peers.is_empty());
        assert!(data.logs.is_empty());
        assert!(!data.connected);
        assert_eq!(data.tick, 0);
        assert_eq!(data.prev_bytes_sent, 0);
        assert_eq!(data.prev_bytes_recv, 0);
        assert_eq!(data.last_update, "Never");
        assert!(data.last_error.is_none());
        assert!(!data.is_fetching);
    }

    #[test]
    fn test_member_debug() {
        let member = Member {
            peer_id: "peer1".to_string(),
            rank: "Alpha".to_string(),
            trust_score: 0.95,
        };
        assert!(format!("{:?}", member).contains("peer1"));
        assert!(format!("{:?}", member).contains("Alpha"));
    }

    #[test]
    fn test_wolf_pack_debug() {
        let pack = WolfPack {
            pack_name: "Test Pack".to_string(),
            alpha_id: Some("alpha1".to_string()),
            members: HashMap::new(),
        };
        assert!(format!("{:?}", pack).contains("Test Pack"));
    }

    #[test]
    fn test_log_entry_debug() {
        let entry = LogEntry {
            timestamp: "2023-01-01T00:00:00Z".to_string(),
            level: "INFO".to_string(),
            message: "Test message".to_string(),
        };
        assert!(format!("{:?}", entry).contains("INFO"));
        assert!(format!("{:?}", entry).contains("Test message"));
    }
}
}

impl Drop for Tui {
    fn drop(&mut self) {
        // We use a simplified error handling here since we can't return Result from Drop
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
    }
}

/// Installs a panic hook that restores the terminal before printing the panic.
pub fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Attempt to restore terminal state
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);

        // Print the panic info
        original_hook(panic_info);
    }));
}

// --- Main Entry Point ---

#[tokio::main]
async fn main() -> Result<()> {
    // Install panic hook for graceful crash handling
    install_panic_hook();

    // Parse command line arguments first
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = "config.toml".to_string();
    for i in 1..args.len() {
        if (args[i] == "-c" || args[i] == "--config") && i + 1 < args.len() {
            config_path = args[i + 1].clone();
        }
    }

    // Initialize App Data & Config BEFORE starting TUI to validate first
    let mut app_data = AppData::default();
    app_data.config = Config::load_from_path(&config_path);

    if let Err(e) = app_data.config.validate() {
        eprintln!("Configuration error: {}", e);
        return Err(anyhow::anyhow!("Configuration error: {}", e));
    }

    let mut api_url = app_data.config.api_url.clone();
    if api_url.ends_with('/') {
        api_url.pop();
    }

    // Setup terminal (RAII pattern)
    let mut tui = Tui::new()?;

    // Run boot sequence
    run_boot_sequence(&mut tui.terminal).await?;

    // Create App instance
    let mut app_instance = App::new(api_url.clone(), config_path);
    app_instance.data = Arc::new(Mutex::new(app_data));
    let app = Arc::new(Mutex::new(app_instance));

    // Spawn Background Poller
    let app_clone = app.clone();
    tokio::spawn(async move {
        // Load certificates and config safely
        let (config, _accept_invalid_certs) = {
            let guard = app_clone.lock().unwrap();
            let data = guard.data.lock().unwrap();
            (data.config.clone(), data.config.accept_invalid_certs)
        };

        let wolf_identity = config.load_certs().await.unwrap_or_default();

        let client = config
            .create_http_client(&wolf_identity)
            .unwrap_or_else(|e| {
                // We're in a background thread and TUI is active, so standard print might break layout.
                // In a real app we'd send an error event to the TUI.
                // For now, we try to create a default client.
                eprintln!("Failed to create HTTP client: {}", e);
                reqwest::Client::new()
            });

        let refresh_notify = {
            let guard = app_clone.lock().unwrap();
            guard.refresh_notify.clone()
        };

        loop {
            // Get current app state before attempting to update data
            let current_state = {
                let guard = app_clone.lock().unwrap();
                guard.state
            };

            update_data(&client, &api_url, &app_clone, current_state).await;

            let poll = {
                let data = app_clone.lock().unwrap();
                let cfg = data.data.lock().unwrap().config.poll_interval_secs;
                cfg
            };
            tokio::select! {
                _ = time::sleep(Duration::from_secs(poll)) => {},
                _ = refresh_notify.notified() => {}
            }
        }
    });

    // Run UI Loop
    let res = run_app(&mut tui.terminal, app).await;

    // Explicit cleanup (optional due to Drop, but good for error checking)
    tui.exit()?;

    if let Err(err) = res {
        println!("Error: {:?}", err)
    }

    Ok(())
}

async fn update_data(
    client: &reqwest::Client,
    base_url: &str,
    app: &Arc<Mutex<App>>,
    current_state: AppState,
) {
    // Get the admin password from config
    let admin_password = {
        let app_guard = app.lock().unwrap();
        let data_guard = app_guard.data.lock().unwrap();
        data_guard.config.admin_password.clone()
    };

    // Skip data fetching when in Login state AND password is empty
    // This prevents auto-login attempts before user enters password
    // But allows authentication after user submits password
    if current_state == AppState::Login && admin_password.is_empty() {
        return;
    }

    // Prevent auto-login loop if password is not set (redundant check but kept for clarity)
    if admin_password.is_empty() {
        let mut data = {
            let app_guard = app.lock().unwrap();
            let data_guard = app_guard.data.lock().unwrap();
            data_guard.clone()
        };
        data.connected = false;
        // Don't show an error, just wait for input
        data.last_error = None;

        let app_guard = app.lock().unwrap();
        let mut data_guard = app_guard.data.lock().unwrap();
        *data_guard = data;
        return;
    }

    // Indicate fetching started and get max_retries from config
    let max_retries = {
        let app_guard = app.lock().unwrap();
        let mut data_guard = app_guard.data.lock().unwrap();
        data_guard.is_fetching = true;
        data_guard.config.max_retries
    };

    // Authenticate first
    let auth_url = format!("{}/login", base_url);
    let auth_result = client
        .post(&auth_url)
        .form(&[("password", &admin_password)])
        .send()
        .await;

    match auth_result {
        Ok(resp) => {
            if !resp.status().is_success() {
                let mut data = {
                    let app_guard = app.lock().unwrap();
                    let data_guard = app_guard.data.lock().unwrap();
                    data_guard.clone()
                };
                data.connected = false;
                data.last_error = Some(ClientError::Auth(format!(
                    "Authentication failed: {}",
                    resp.status()
                )));
                // Clear password to prevent retry loop
                data.config.admin_password.clear();

                let app_guard = app.lock().unwrap();
                let mut data_guard = app_guard.data.lock().unwrap();
                *data_guard = data;
                return;
            }
        }
        Err(e) => {
            let mut data = {
                let app_guard = app.lock().unwrap();
                let data_guard = app_guard.data.lock().unwrap();
                data_guard.clone()
            };
            data.connected = false;
            data.last_error = Some(ClientError::Auth(format!(
                "Authentication request failed: {}",
                e
            )));
            // Clear password to prevent retry loop
            data.config.admin_password.clear();

            let app_guard = app.lock().unwrap();
            let mut data_guard = app_guard.data.lock().unwrap();
            *data_guard = data;
            return;
        }
    }

    // Helper closure for retrying requests with exponential backoff
    let fetch_with_retry = |endpoint: &str| {
        let url = format!("{}{}", base_url, endpoint);
        let client = client.clone();
        async move {
            let mut retries = 0;
            loop {
                match client.get(&url).send().await {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        if retries >= max_retries {
                            return Err(e);
                        }
                        retries += 1;
                        // Exponential backoff: 50ms, 100ms
                        time::sleep(Duration::from_millis(50 * (1 << (retries - 1)))).await;
                    }
                }
            }
        }
    };

    // Run all requests concurrently with retry logic
    let (status_res, peers_res, pack_res, metrics_res, server_config_res, logs_res, zero_trust_res) = tokio::join!(
        fetch_with_retry("/api/status"),
        fetch_with_retry("/api/peers"),
        fetch_with_retry("/api/pack"),
        fetch_with_retry("/api/metrics"),
        fetch_with_retry("/api/config"),
        fetch_with_retry("/api/logs"),
        fetch_with_retry("/api/v1/zero/trust"),
    );

    let mut data = {
        let app_guard = app.lock().unwrap();
        let data_guard = app_guard.data.lock().unwrap();
        data_guard.clone()
    };

    data.last_update = chrono::Local::now().format("%H:%M:%S").to_string();

    match status_res {
        Ok(res) => {
            if let Ok(s) = res.json::<NodeStatus>().await {
                data.status = s;
                data.connected = true;
                data.last_error = None;
            } else {
                data.connected = false;
                data.last_error = Some(ClientError::Parse("Invalid status response".to_string()));
            }
        }
        Err(e) => {
            data.connected = false;
            data.last_error = Some(if e.is_timeout() {
                ClientError::Timeout
            } else if e.is_connect() {
                ClientError::ConnectionRefused
            } else if let Some(status) = e.status() {
                ClientError::Server(status.as_u16(), e.to_string())
            } else {
                ClientError::Unknown(e.to_string())
            });
        }
    }

    if data.connected {
        if let Ok(res) = peers_res {
            if let Ok(p) = res.json::<Vec<String>>().await {
                data.peers = p;
            }
        }

        if let Ok(res) = metrics_res {
            if let Ok(m) = res.json::<NetworkMetrics>().await {
                data.metrics = m;
            }
        }

        if let Ok(res) = pack_res {
            if let Ok(p) = res.json::<WolfPack>().await {
                data.pack = Some(p);
            }
        }

        // Fetch server config
        if let Ok(res) = server_config_res {
            if let Ok(sc) = res.json::<ServerConfig>().await {
                data.server_config = sc;
            }
        }

        // Fetch logs
        if let Ok(res) = logs_res {
            if let Ok(l) = res.json::<Vec<LogEntry>>().await {
                data.logs = l;
            }
        }

        // Fetch Zero Trust Stats
        if let Ok(res) = zero_trust_res {
            if let Ok(val) = res.json::<serde_json::Value>().await {
                if let Some(policy) = val.get("policy_engine") {
                    if let Some(count) = policy.get("active_policy_count").and_then(|v| v.as_u64())
                    {
                        data.zero_trust_stats.active_policy_count = count as usize;
                    }
                    if let Some(stats) = policy.get("stats") {
                        data.zero_trust_stats.policy_violations = stats
                            .get("policy_violations")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        data.zero_trust_stats.enforced_policies = stats
                            .get("policies_enforced")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                    }
                }
                if let Some(microseg) = val.get("microsegmentation") {
                    if let Some(count) = microseg.get("segment_count").and_then(|v| v.as_u64()) {
                        data.zero_trust_stats.active_segments = count as usize;
                    }
                    if let Some(stats) = microseg.get("stats") {
                        data.zero_trust_stats.isolation_events = stats
                            .get("isolation_events")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                    }
                }
            }
        }

        // Enforce Omega Role Restriction
        if let Some(pack) = &data.pack {
            if let Some(member) = pack.members.get(&data.status.peer_id) {
                // "Omega Role is the only role that can access wolf_control"
                if member.rank != "Omega" {
                    data.connected = false;
                    data.last_error = Some(ClientError::Auth(format!(
                        "RESTRICTED ACCESS: Role '{}' is not authorized. only 'Omega' role may access Wolf Control.",
                        member.rank
                    )));
                }
            }
        }
    }

    // Track activity
    let tx_diff = data
        .metrics
        .total_bytes_sent
        .saturating_sub(data.prev_bytes_sent);
    let rx_diff = data
        .metrics
        .total_bytes_received
        .saturating_sub(data.prev_bytes_recv);

    data.prev_bytes_sent = data.metrics.total_bytes_sent;
    data.prev_bytes_recv = data.metrics.total_bytes_received;
    data.tick = data.tick.wrapping_add(1);

    // Update shared state
    {
        let mut app_guard = app.lock().unwrap();
        app_guard.on_network_stats(tx_diff, rx_diff);
        let mut app_data = app_guard.data.lock().unwrap();
        *app_data = data;
        app_data.is_fetching = false;
    }
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: Arc<Mutex<App>>) -> io::Result<()> {
    loop {
        {
            let mut app_guard = app.lock().unwrap();

            // State Transition Logic
            if app_guard.state == AppState::Login {
                {
                    let data = app_guard.data.lock().unwrap();
                    if data.connected {
                        // Successful login
                        drop(data); // Drop the lock before mutating app_guard
                        app_guard.state = AppState::Main;
                        app_guard.login_error = None;
                        app_guard.login_input.clear();
                    } else if let Some(last_error) = &data.last_error {
                        // Show authentication error
                        let error_msg = last_error.to_string();
                        drop(data); // Drop the lock before mutating app_guard
                        app_guard.login_error = Some(error_msg);
                    }
                }
            }

            terminal.draw(|f| ui(f, &app_guard))?;

            if app_guard.should_quit {
                return Ok(());
            }
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                let mut app_guard = app.lock().unwrap();

                // Handle Ctrl+C globally for panic escape / graceful shutdown
                if key.kind == event::KeyEventKind::Press
                    && key.code == KeyCode::Char('c')
                    && key.modifiers.contains(event::KeyModifiers::CONTROL)
                {
                    return Ok(()); // Immediate exit
                }

                match app_guard.state {
                    AppState::Login => {
                        match key.code {
                            KeyCode::Enter => {
                                // Trigger Login
                                app_guard.login_error = Some("Authenticating...".to_string());
                                let password = app_guard.login_input.clone();

                                {
                                    let mut data = app_guard.data.lock().unwrap();
                                    data.config.admin_password = password;
                                    // Reset errors to avoid immediate failure loop
                                    data.last_error = None;
                                }
                                // Force immediate update
                                app_guard.refresh_notify.notify_one();
                            }
                            KeyCode::Esc => {
                                app_guard.login_input.clear();
                                app_guard.login_error = None;
                            }
                            KeyCode::Backspace => {
                                app_guard.login_input.pop();
                            }
                            KeyCode::Char(c) => {
                                app_guard.login_input.push(c);
                            }
                            _ => {}
                        }
                    }
                    AppState::Main => {
                        // Check if we're in command mode
                        if app_guard.command_mode {
                            match key.code {
                                KeyCode::Enter => app_guard.execute_command(),
                                KeyCode::Esc => {
                                    app_guard.command_mode = false;
                                    app_guard.command_input.clear();
                                }
                                KeyCode::Backspace => {
                                    app_guard.command_input.pop();
                                }
                                KeyCode::Char(c) => {
                                    app_guard.command_input.push(c);
                                }
                                _ => {}
                            }
                        } else {
                            match key.code {
                                KeyCode::Char(c) => {
                                    if app_guard.current_tab == Tab::Verify {
                                        let idx = app_guard.active_verify_input;
                                        app_guard.verify_inputs[idx].push(c);
                                    } else {
                                        app_guard.on_key(c);
                                    }
                                }
                                KeyCode::Tab => app_guard.next_tab(),
                                KeyCode::Enter => {
                                    if app_guard.current_tab == Tab::Verify
                                        && !app_guard.is_verifying
                                    {
                                        app_guard.is_verifying = true;
                                        app_guard.verify_result = Some("Verifying...".to_string());

                                        let app_clone = app.clone();
                                        let api_url = app_guard.api_url.clone();
                                        let inputs = app_guard.verify_inputs.clone();

                                        tokio::spawn(async move {
                                            let client = reqwest::Client::builder()
                                                .danger_accept_invalid_certs(true)
                                                .build()
                                                .unwrap();

                                            let admin_password = {
                                                let app_guard = app_clone.lock().unwrap();
                                                let data_guard = app_guard.data.lock().unwrap();
                                                data_guard.config.admin_password.clone()
                                            };

                                            let _ = client
                                                .post(format!("{}/login", api_url))
                                                .form(&[("password", &admin_password)])
                                                .send()
                                                .await;

                                            let req_body = serde_json::json!({
                                                "timestamp": inputs[0],
                                                "score": inputs[1].parse::<f64>().unwrap_or(0.0),
                                                "critical": inputs[2].parse::<u32>().unwrap_or(0),
                                                "total": inputs[3].parse::<u32>().unwrap_or(0),
                                                "signature": inputs[4],
                                            });

                                            let res = client
                                                .post(format!(
                                                    "{}/api/v1/compliance/verify",
                                                    api_url
                                                ))
                                                .json(&req_body)
                                                .send()
                                                .await;

                                            let result_text = match res {
                                                Ok(resp) => {
                                                    if let Ok(val) =
                                                        resp.json::<serde_json::Value>().await
                                                    {
                                                        if val["valid"].as_bool().unwrap_or(false) {
                                                            "✅ SIGNATURE VALID".to_string()
                                                        } else {
                                                            "❌ INVALID SIGNATURE".to_string()
                                                        }
                                                    } else {
                                                        "Error parsing response".to_string()
                                                    }
                                                }
                                                Err(e) => format!("Request failed: {}", e),
                                            };

                                            let mut guard = app_clone.lock().unwrap();
                                            guard.is_verifying = false;
                                            guard.verify_result = Some(result_text);
                                        });
                                    }
                                }
                                KeyCode::Backspace => {
                                    if app_guard.current_tab == Tab::Verify {
                                        let idx = app_guard.active_verify_input;
                                        app_guard.verify_inputs[idx].pop();
                                    }
                                }
                                KeyCode::Up => {
                                    if app_guard.current_tab == Tab::Verify {
                                        app_guard.active_verify_input =
                                            if app_guard.active_verify_input == 0 {
                                                4
                                            } else {
                                                app_guard.active_verify_input - 1
                                            };
                                    } else {
                                        app_guard.on_key('k');
                                    }
                                }
                                KeyCode::Down => {
                                    if app_guard.current_tab == Tab::Verify {
                                        app_guard.active_verify_input =
                                            (app_guard.active_verify_input + 1) % 5;
                                    } else {
                                        app_guard.on_key('j');
                                    }
                                }
                                KeyCode::BackTab => app_guard.prev_tab(),
                                KeyCode::Right => app_guard.next_tab(),
                                KeyCode::Left => app_guard.prev_tab(),
                                KeyCode::Esc => {
                                    app_guard.show_help = false;
                                    app_guard.command_result = None;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    if app.state == AppState::Login {
        draw_login(f, f.size(), app);
        return;
    }

    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Footer
            ]
            .as_ref(),
        )
        .split(size);

    // Wolf Theme Colors
    let (primary_color, secondary_color, text_color) = app.get_theme_colors();

    // Header with wolf pack branding & Dynamic Logo
    let logo_text = if app.theme_mode == ThemeMode::Predator {
        let chars: Vec<char> = "😤@#%&?!*^$".chars().collect();
        "🐺 WOLF PROWLER V2.0 "
            .chars()
            .map(|c| {
                if c != ' ' && rand::random::<f64>() > 0.7 {
                    chars[rand::random::<usize>() % chars.len()]
                } else {
                    c
                }
            })
            .collect::<String>()
    } else {
        "🐺 WOLF PROWLER CONTROL CENTER v2.0 ".to_string()
    };

    let titles: Vec<Line> = [
        "Overview", "Peers", "Pack", "Security", "Logs", "Metrics", "Config", "Verify",
    ]
    .iter()
    .map(|t| {
        let (first, rest) = t.split_at(1);
        Line::from(vec![
            Span::styled(
                first,
                Style::default()
                    .fg(primary_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(rest, Style::default().fg(text_color)),
        ])
    })
    .collect();

    let current_index = match app.current_tab {
        Tab::Overview => 0,
        Tab::Peers => 1,
        Tab::Pack => 2,
        Tab::Security => 3,
        Tab::Logs => 4,
        Tab::Metrics => 5,
        Tab::Config => 6,
        Tab::Verify => 7,
    };

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(secondary_color))
                .title(Span::styled(
                    logo_text,
                    Style::default()
                        .fg(primary_color)
                        .add_modifier(Modifier::BOLD),
                )),
        )
        .select(current_index)
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Yellow),
        );

    f.render_widget(tabs, chunks[0]);

    // Data Snapshot
    let data = app.data.lock().unwrap();

    // Connection Status
    let status_color = if data.connected {
        Color::Green
    } else {
        Color::Red
    };
    let status_text = if data.connected {
        "CONNECTED"
    } else {
        "DISCONNECTED"
    };

    // Content
    let content_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(
            "{} | API: {} | Status: {}{}",
            app.current_tab.title(),
            app.api_url,
            status_text,
            if data.is_fetching { " [SYNC]" } else { "" }
        ))
        .border_style(Style::default().fg(status_color));

    f.render_widget(content_block, chunks[1]);

    // ... [Content logic remains similar, handled by inner area render] ...

    // Inner Content Area
    let inner_area = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([Constraint::Min(0)].as_ref())
        .split(chunks[1])[0];

    if !data.connected {
        let err = data
            .last_error
            .clone()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Unknown error".to_string());
        let warning = Paragraph::new(format!("Could not connect to Wolf Server at {}.\nError: {}\n\nPossible causes:\n1. Server is not running (Check './docker-manager.sh logs')\n2. Build failed (Check build_error.txt)\n3. Wrong API URL in config", app.api_url, err))
            .style(Style::default().fg(Color::Red))
            .wrap(Wrap { trim: true });
        f.render_widget(warning, inner_area);
        return;
    }

    match app.current_tab {
        Tab::Overview => draw_overview(f, inner_area, &data, &app.sparkline_data), // Added sparkline data
        Tab::Peers => draw_peers(f, inner_area, &data, app.selected_peer_index),
        Tab::Pack => draw_pack(f, inner_area, &data),
        Tab::Security => draw_security(f, inner_area, &data),
        Tab::Logs => draw_logs(f, inner_area, &data, app.log_filter),
        Tab::Metrics => draw_metrics(f, inner_area, &data, &app.sparkline_data), // Added sparkline data
        Tab::Config => draw_config(f, inner_area, &data),
        Tab::Verify => draw_verify(f, inner_area, app),
    }

    // Footer
    if app.command_mode {
        let cmd_text = format!(":{}_", app.command_input);
        let cmd_bar = Paragraph::new(cmd_text)
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Command Palette (Enter to run, Esc to cancel)"),
            );
        f.render_widget(cmd_bar, chunks[2]);
    } else if let Some(result) = &app.command_result {
        let result_bar = Paragraph::new(result.as_str())
            .style(Style::default().fg(Color::Cyan))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Result (press Esc to dismiss, : for new command)"),
            );
        f.render_widget(result_bar, chunks[2]);
    } else {
        let footer_text = format!(
            "Last Update: {} | [q] Quit | [?] Help | [:] Command | [Tab] Next | [t] Theme | [h] Hex Inspector | [l] Filter Logs",
            data.last_update
        );
        let footer = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(footer, chunks[2]);
    }

    // Hex Inspector Overlay
    if app.show_hex_inspector {
        let area = centered_rect(60, 40, size);
        f.render_widget(Clear, area); // Clear background

        let hex_content = if let Some(packet) = &app.last_packet {
            // Create hex dump
            let mut hex_lines = Vec::new();
            for (i, chunk) in packet.chunks(16).enumerate() {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| if b >= 32 && b <= 126 { b as char } else { '.' })
                    .collect();
                hex_lines.push(ListItem::new(format!(
                    "{:04X}: {:<48} |{}",
                    i * 16,
                    hex.join(" "),
                    ascii
                )));
            }
            hex_lines
        } else {
            vec![ListItem::new("No packet data captured yet.")]
        };

        let block = Block::default()
            .title("🔍 Hex Dump Inspector")
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::Black).fg(Color::Green));

        let list = List::new(hex_content).block(block);
        f.render_widget(list, area);
    }

    // Help Overlay
    if app.show_help {
        let help_text = "\
╔══════════════════════════════════════════════════════════════╗
║                    🐺 WOLF CONTROL HELP                      ║
╠══════════════════════════════════════════════════════════════╣
║  NAVIGATION                                                   ║
║    Tab / n     Next tab                                       ║
║    Shift+Tab   Previous tab                                   ║
║    ← / →       Navigate tabs                                  ║
║    j / k / ↑↓  Navigate lists                                 ║
║                                                               ║
║  GENERAL                                                      ║
║    q           Quit application                               ║
║    ?           Toggle this help                               ║
║    Esc         Close help/dialogs                             ║
║                                                               ║
║  CONFIG TAB                                                   ║
║    v           Toggle verbose logging                         ║
║    t           Toggle theme (dark/light)                      ║
║    + / -       Adjust poll interval                           ║
║    c           Reload config from file                        ║
║    s           Save config to file                            ║
║                                                               ║
║  SERVER CONFIG                                                ║
║    e           Toggle encryption                              ║
║    a           Toggle auto-alpha                              ║
║    m / M       Adjust max connections                         ║
║    S           Save config to server                          ║
║                                                               ║
║                 Press ESC or ? to close                       ║
╚══════════════════════════════════════════════════════════════╝";

        // Center the help overlay
        let help_area = centered_rect(70, 60, size);

        let help_widget = Paragraph::new(help_text)
            .style(Style::default().fg(Color::Cyan))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow))
                    .style(Style::default().bg(Color::Black)),
            );

        // Clear the area first
        f.render_widget(Clear, help_area);
        f.render_widget(help_widget, help_area);
    }
}

// Helper to create centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn draw_overview(f: &mut Frame, area: Rect, data: &AppData, sparkline_data: &[u64]) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(6), // Identity + Activity
                Constraint::Length(5), // Pack Status
                Constraint::Length(7), // Zero Trust Stats
                Constraint::Min(0),    // Network Graph
            ]
            .as_ref(),
        )
        .split(area);

    // Format uptime nicely
    let uptime = data.status.uptime_seconds;
    let uptime_str = if uptime >= 3600 {
        format!(
            "{}h {}m {}s",
            uptime / 3600,
            (uptime % 3600) / 60,
            uptime % 60
        )
    } else if uptime >= 60 {
        format!("{}m {}s", uptime / 60, uptime % 60)
    } else {
        format!("{}s", uptime)
    };

    // Live activity pulse
    let pulse_frames = ["◐", "◓", "◑", "◒"];
    let pulse = pulse_frames[(data.tick % 4) as usize];

    // Connection quality indicator
    let conn_quality = match data.metrics.active_connections {
        0 => ("○○○○○", Color::Red),
        1..=5 => ("●○○○○", Color::Yellow),
        6..=15 => ("●●○○○", Color::Yellow),
        16..=30 => ("●●●○○", Color::Green),
        31..=45 => ("●●●●○", Color::Green),
        _ => ("●●●●●", Color::Green),
    };

    // Network activity visualization - ASCII Arrow
    let activity_char = if data.metrics.total_bytes_sent > data.prev_bytes_sent {
        "▲"
    } else if data.metrics.total_bytes_received > data.prev_bytes_recv {
        "▼"
    } else {
        "─"
    };

    let id_text = format!(
        "{}  Node: {} | v{}\n\
         ⏱  Uptime: {} | Signal: {}\n\
         📡 Activity: {} TX/RX | Conn: {}",
        pulse,
        if data.status.peer_id.len() > 20 {
            format!("{}...", &data.status.peer_id[..20])
        } else {
            data.status.peer_id.clone()
        },
        data.status.version,
        uptime_str,
        conn_quality.0,
        activity_char,
        data.metrics.active_connections
    );

    // Split chunk[0] to add sparkline next to ID
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(chunks[0]);

    let id_widget = Paragraph::new(id_text).block(
        Block::default()
            .title("🐺 WOLF NODE STATUS")
            .borders(Borders::ALL),
    );
    f.render_widget(id_widget, header_chunks[0]);

    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title("Network Activity")
                .borders(Borders::ALL),
        )
        .data(sparkline_data)
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(sparkline, header_chunks[1]);

    // Wolf Pack Status
    let pack_name = &data.server_config.pack_name;
    let alpha_id = data
        .pack
        .as_ref()
        .and_then(|p| p.alpha_id.as_ref())
        .map(|id| {
            let s = id.to_string();
            if s.len() > 12 {
                format!("{}...", &s[..12])
            } else {
                s
            }
        })
        .unwrap_or_else(|| "Searching...".to_string());
    let member_count = data.pack.as_ref().map(|p| p.members.len()).unwrap_or(0);
    let security_icon = if data.server_config.encryption_enabled {
        "🔒 ENCRYPTED"
    } else {
        "🔓 OPEN"
    };

    let pack_text = format!(
        "📦 Pack: {} | Members: {}\n\
         👑 Alpha: {}\n\
         🛡  Security: {} | Trust Threshold: {:.0}%",
        pack_name,
        member_count,
        alpha_id,
        security_icon,
        data.server_config.trust_threshold * 100.0
    );
    let pack_widget = Paragraph::new(pack_text).block(
        Block::default()
            .title("🐺 WOLF PACK HIERARCHY")
            .borders(Borders::ALL),
    );
    f.render_widget(pack_widget, chunks[1]);

    // Zero Trust Statistics Widget
    let zt = &data.zero_trust_stats;
    let critical_violations_threshold = 10;

    // Base block for the widget
    let mut zt_block = Block::default()
        .title("🛡️ Zero Trust Stats")
        .borders(Borders::ALL);

    // Apply color coding and flashing effect for violations
    if zt.policy_violations >= critical_violations_threshold {
        // Critical: Flashing red background
        if data.tick % 2 == 0 {
            zt_block = zt_block.style(Style::default().bg(Color::Red).fg(Color::White));
        } else {
            zt_block = zt_block.border_style(Style::default().fg(Color::Red));
        }
    } else {
        // Normal color coding
        let zt_color = if zt.policy_violations == 0 {
            Color::Green
        } else if zt.policy_violations < 5 {
            Color::Yellow
        } else {
            Color::Red
        };
        zt_block = zt_block.border_style(Style::default().fg(zt_color));
    }

    let zt_text = format!(
        "Policies: {} Active | {} Enforced\n\
         Violations:       {}\n\
         Segments:         {}\n\
         Isolation Events: {}",
        zt.active_policy_count,
        zt.enforced_policies,
        zt.policy_violations,
        zt.active_segments,
        zt.isolation_events
    );
    let zt_widget = Paragraph::new(zt_text).block(zt_block);
    f.render_widget(zt_widget, chunks[2]);

    // Network Graph Visualization
    let mut graph_lines = vec![
        "".to_string(),
        "                    Network Topology".to_string(),
        "".to_string(),
    ];

    // Get alpha node info
    let alpha_id = data
        .pack
        .as_ref()
        .and_then(|p| p.alpha_id.clone())
        .map(|id| id.to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    let short_alpha = if alpha_id.len() > 8 {
        &alpha_id[..8]
    } else {
        &alpha_id
    };

    graph_lines.push(format!("                    ┌─────────────┐"));
    graph_lines.push(format!("                    │  🐺 ALPHA   │"));
    graph_lines.push(format!("                    │  {}...  │", short_alpha));
    graph_lines.push(format!("                    └──────┬──────┘"));

    if !data.peers.is_empty() {
        graph_lines.push("           ┌──────────┴──────────┐".to_string());

        // Show up to 4 peers
        let show_peers: Vec<_> = data.peers.iter().take(4).collect();
        let mut peer_boxes = String::new();
        for (i, peer) in show_peers.iter().enumerate() {
            let short_id = if peer.len() > 6 { &peer[..6] } else { peer };
            if i > 0 {
                peer_boxes.push_str("    ");
            }
            peer_boxes.push_str(&format!("│{}...│", short_id));
        }
        graph_lines.push(format!("      {}", peer_boxes));

        if data.peers.len() > 4 {
            graph_lines.push(format!(
                "                    + {} more peers...",
                data.peers.len() - 4
            ));
        }
    } else {
        graph_lines.push("                         │".to_string());
        graph_lines.push("                    (no peers)".to_string());
    }

    let graph_text = graph_lines.join("\n");
    let graph_widget = Paragraph::new(graph_text).block(
        Block::default()
            .title("🌐 Network Graph")
            .borders(Borders::ALL),
    );
    f.render_widget(graph_widget, chunks[3]);
}

fn draw_peers(f: &mut Frame, area: Rect, data: &AppData, selected_index: usize) {
    // Split into list and details
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);

    // Left: Peer list with selection
    let items: Vec<ListItem> = data
        .peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let style = if i == selected_index {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let marker = if i == selected_index { "▶ " } else { "  " };
            ListItem::new(format!("{}📡 {}", marker, p)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(format!(
                "Peers ({}) [j/k or ↑/↓ to navigate]",
                data.peers.len()
            ))
            .borders(Borders::ALL),
    );

    f.render_widget(list, chunks[0]);

    // Right: Peer details
    let details_text = if data.peers.is_empty() {
        "No peers connected.\n\nWaiting for peer discovery...".to_string()
    } else if let Some(peer_id) = data.peers.get(selected_index) {
        // Get pack member info if available
        let rank_info = data
            .pack
            .as_ref()
            .and_then(|p| p.members.get(peer_id))
            .map(|m| format!("Rank: {}\nTrust Score: {:.2}", m.rank, m.trust_score))
            .unwrap_or_else(|| "Rank: Unknown\nTrust Score: N/A".to_string());

        format!(
            "Peer Details:\n\n\
             Peer ID:\n  {}\n\n\
             {}\n\n\
             ─────────────────────────\n\
             Actions:\n\n\
             [b] Block Peer\n\
             [r] Promote Rank\n\
             [d] Demote Rank",
            peer_id, rank_info
        )
    } else {
        "Select a peer".to_string()
    };

    let details = Paragraph::new(details_text)
        .block(
            Block::default()
                .title("📋 Peer Details")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(details, chunks[1]);
}

fn draw_login(f: &mut Frame, area: Rect, app: &App) {
    // Center the login box
    let block = Block::default()
        .borders(Borders::ALL)
        .title("🔐 Locked")
        .style(Style::default().fg(Color::Red));

    let area = centered_rect(60, 20, area);
    f.render_widget(Clear, area); // Clear background
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3), // Header
                Constraint::Length(3), // Input
                Constraint::Length(3), // Message
                Constraint::Min(0),
            ]
            .as_ref(),
        )
        .split(area);

    let title = Paragraph::new("🐺 WOLF PROWLER SECURITY SYSTEM")
        .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Red))
        .alignment(ratatui::layout::Alignment::Center);
    f.render_widget(title, chunks[0]);

    let input_display: String = app.login_input.chars().map(|_| '*').collect();
    let input = Paragraph::new(input_display)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Enter Password"),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(input, chunks[1]);

    // Set cursor to the end of the input text
    // +1 for the border offset
    f.set_cursor(
        chunks[1].x + 1 + app.login_input.len() as u16,
        chunks[1].y + 1,
    );

    if let Some(err) = &app.login_error {
        let msg = Paragraph::new(format!("❌ {}", err))
            .style(Style::default().fg(Color::Red))
            .wrap(Wrap { trim: true })
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(msg, chunks[2]);
    } else {
        let msg = Paragraph::new("Press Enter to Login")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(msg, chunks[2]);
    }
}

fn draw_pack(f: &mut Frame, area: Rect, data: &AppData) {
    if let Some(pack) = &data.pack {
        let text = format!(
            "Pack: {}\nAlpha: {:?}\n\nMembers: {}\n\n",
            pack.pack_name,
            pack.alpha_id,
            pack.members.len()
        );

        let members: Vec<ListItem> = pack
            .members
            .values()
            .map(|m| {
                ListItem::new(format!(
                    "{:?} - {} (Trust: {:.1})",
                    m.rank, m.peer_id, m.trust_score
                ))
            })
            .collect();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(5), Constraint::Min(0)].as_ref())
            .split(area);

        let info =
            Paragraph::new(text).block(Block::default().title("Pack Info").borders(Borders::ALL));

        let list = List::new(members)
            .block(
                Block::default()
                    .title("Pack Hierarchy")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));

        f.render_widget(info, chunks[0]);
        f.render_widget(list, chunks[1]);
    } else {
        let text = "No Pack Data Available";
        let widget =
            Paragraph::new(text).block(Block::default().title("Pack Info").borders(Borders::ALL));
        f.render_widget(widget, area);
    }
}

fn draw_security(f: &mut Frame, area: Rect, data: &AppData) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(12), // Security Status & Stats
                Constraint::Min(0),     // Alerts
            ]
            .as_ref(),
        )
        .split(area);

    // Security Status Panel
    let encryption_status = if data.server_config.encryption_enabled {
        "🔒 ENABLED"
    } else {
        "🔓 DISABLED"
    };

    let trust_bar = {
        let threshold = (data.server_config.trust_threshold * 10.0) as usize;
        let filled = "█".repeat(threshold);
        let empty = "░".repeat(10 - threshold);
        format!("{}{}", filled, empty)
    };

    let status_text = format!(
        "Security Status:\n\
         Encryption:      {}\n\
         Trust Threshold: {} ({:.0}%)\n\n\
         Zero Trust Engine:\n\
         - Active Policies:   {}\n\
         - Policies Enforced: {}\n\
         - Violations:        {}\n\
         - Segments:          {}\n\
         - Isolation Events:  {}",
        encryption_status,
        trust_bar,
        data.server_config.trust_threshold * 100.0,
        data.zero_trust_stats.active_policy_count,
        data.zero_trust_stats.enforced_policies,
        data.zero_trust_stats.policy_violations,
        data.zero_trust_stats.active_segments,
        data.zero_trust_stats.isolation_events
    );

    let status_widget = Paragraph::new(status_text).block(
        Block::default()
            .title("🛡️ Security Status")
            .borders(Borders::ALL),
    );
    f.render_widget(status_widget, chunks[0]);

    // Alerts Panel - filter ERROR and WARN logs as security alerts
    let alerts: Vec<ListItem> = data
        .logs
        .iter()
        .filter(|log| {
            if log.level == "ERROR" {
                return true;
            }
            // Only show security-relevant warnings in the Security tab
            if log.level == "WARN" {
                let msg = log.message.to_lowercase();
                return msg.contains("security")
                    || msg.contains("encrypt")
                    || msg.contains("auth")
                    || msg.contains("policy")
                    || msg.contains("trust")
                    || msg.contains("violation");
            }
            false
        })
        .rev()
        .map(|log| {
            let level_color = if log.level == "ERROR" {
                Color::Red
            } else {
                Color::Yellow
            };
            let icon = if log.level == "ERROR" {
                "🚨"
            } else {
                "⚠️"
            };

            ListItem::new(Line::from(vec![
                Span::raw(icon),
                Span::styled(
                    format!(" [{}] ", log.timestamp),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(&log.message, Style::default().fg(level_color)),
            ]))
        })
        .collect();

    let alert_count = alerts.len();
    let alert_list = List::new(alerts).block(
        Block::default()
            .title(format!("⚠️ Security Alerts ({})", alert_count))
            .borders(Borders::ALL),
    );

    f.render_widget(alert_list, chunks[1]);
}

fn draw_logs(f: &mut Frame, area: Rect, data: &AppData, filter: LogFilter) {
    let items: Vec<ListItem> = data
        .logs
        .iter()
        .rev() // Show newest first
        .filter(|log| match filter {
            LogFilter::All => true,
            LogFilter::Debug => true,
            LogFilter::Info => log.level == "INFO" || log.level == "WARN" || log.level == "ERROR",
            LogFilter::Warn => log.level == "WARN" || log.level == "ERROR",
            LogFilter::Error => log.level == "ERROR",
        })
        .map(|log| {
            let level_color = match log.level.as_str() {
                "ERROR" => Color::Red,
                "WARN" => Color::Yellow,
                "INFO" => Color::Green,
                "DEBUG" => Color::Blue,
                _ => Color::Gray,
            };
            let level_span = Span::styled(
                format!("[{}]", log.level),
                Style::default()
                    .fg(level_color)
                    .add_modifier(Modifier::BOLD),
            );
            let time_span = Span::styled(
                format!(" {} ", log.timestamp),
                Style::default().fg(Color::DarkGray),
            );
            let msg_span = Span::raw(&log.message);

            ListItem::new(Line::from(vec![level_span, time_span, msg_span]))
        })
        .collect();

    let count = items.len();
    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(
                    "📜 Server Logs ({} entries) [Filter: {}]",
                    count,
                    filter.as_str()
                ))
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(list, area);
}

fn draw_metrics(f: &mut Frame, area: Rect, data: &AppData, sparkline_data: &[u64]) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(8), // Stats
                Constraint::Min(0),    // Sparklines
            ]
            .as_ref(),
        )
        .split(area);

    // Format bytes nicely
    fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_000_000_000 {
            format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
        } else if bytes >= 1_000_000 {
            format!("{:.2} MB", bytes as f64 / 1_000_000.0)
        } else if bytes >= 1_000 {
            format!("{:.2} KB", bytes as f64 / 1_000.0)
        } else {
            format!("{} B", bytes)
        }
    }

    let text = format!(
        "📊 Traffic Analysis:\n\n\
         ▲ Total Sent:      {}\n\
         ▼ Total Received:  {}\n\
         📤 Messages Sent:     {}\n\
         📥 Messages Received: {}",
        format_bytes(data.metrics.total_bytes_sent),
        format_bytes(data.metrics.total_bytes_received),
        data.metrics.messages_sent,
        data.metrics.messages_received
    );

    let widget = Paragraph::new(text).block(
        Block::default()
            .title("📈 Detailed Metrics")
            .borders(Borders::ALL),
    );
    f.render_widget(widget, chunks[0]);

    // ASCII Sparkline Visualization
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title("Live Bandwidth Usage")
                .borders(Borders::ALL),
        )
        .data(sparkline_data)
        .style(Style::default().fg(Color::Cyan));

    f.render_widget(sparkline, chunks[1]);
}

fn draw_config(f: &mut Frame, area: Rect, data: &AppData) {
    let cfg = &data.config;
    let sc = &data.server_config;

    // Split into two columns
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);

    // Left: TUI Config
    let tui_text = format!(
        "TUI Settings:\n\n\
         API URL:         {}\n\
         Poll Interval:   {} sec\n\
         Verbose:         {}\n\
         Theme:           {}\n\
         Timestamps:      {}\n\
         Auto-scroll:     {}\n\n\
         ─────────────────────────\n\
         TUI Controls:\n\n\
         [v] Toggle Verbose\n\
         [+] Poll Interval +\n\
         [-] Poll Interval -\n\
         [t] Toggle Theme\n\
         [c] Reload Config\n\
         [s] Save Config",
        cfg.api_url,
        cfg.poll_interval_secs,
        if cfg.verbose { "ON" } else { "OFF" },
        cfg.theme,
        if cfg.show_timestamps { "ON" } else { "OFF" },
        if cfg.auto_scroll_logs { "ON" } else { "OFF" },
    );

    let tui_widget = Paragraph::new(tui_text)
        .block(Block::default().title("⚙ TUI Config").borders(Borders::ALL));
    f.render_widget(tui_widget, chunks[0]);

    // Right: Server Config
    let server_text = format!(
        "Server Settings:\n\n\
         P2P Port:        {}\n\
         API Port:        {}\n\
         Max Connections: {}\n\
         Pack Name:       {}\n\
         Default Rank:    {}\n\
         Encryption:      {}\n\
         Trust Threshold: {:.2}\n\
         Auto-Alpha:      {}\n\n\
         ─────────────────────────\n\
         Server Controls:\n\n\
         [e] Toggle Encryption\n\
         [a] Toggle Auto-Alpha\n\
         [m] Max Connections +\n\
         [M] Max Connections -\n\
         [S] Save to Server",
        sc.p2p_port,
        sc.api_port,
        sc.max_connections,
        sc.pack_name,
        sc.default_rank,
        if sc.encryption_enabled { "ON" } else { "OFF" },
        sc.trust_threshold,
        if sc.auto_alpha { "ON" } else { "OFF" },
    );

    let server_widget = Paragraph::new(server_text).block(
        Block::default()
            .title("🌐 Server Config")
            .borders(Borders::ALL),
    );
    f.render_widget(server_widget, chunks[1]);
}

fn draw_verify(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Instructions
            Constraint::Length(3), // Timestamp
            Constraint::Length(3), // Score
            Constraint::Length(3), // Critical
            Constraint::Length(3), // Total
            Constraint::Length(3), // Signature
            Constraint::Length(3), // Result
            Constraint::Min(0),
        ])
        .split(area);

    f.render_widget(
        Paragraph::new("Enter report details to verify cryptographic integrity:")
            .style(Style::default().fg(Color::Cyan)),
        chunks[0],
    );

    let labels = [
        "Timestamp (ISO)",
        "Overall Score (%)",
        "Critical Findings",
        "Total Issues",
        "Digital Signature (Hex)",
    ];
    for i in 0..5 {
        let block = Block::default().borders(Borders::ALL).title(labels[i]);
        let block = if app.active_verify_input == i {
            block.border_style(Style::default().fg(Color::Yellow))
        } else {
            block
        };
        f.render_widget(
            Paragraph::new(app.verify_inputs[i].as_str()).block(block),
            chunks[i + 1],
        );
    }

    if let Some(result) = &app.verify_result {
        let color = if result.contains("VALID") {
            Color::Green
        } else if result.contains("INVALID") {
            Color::Red
        } else {
            Color::Yellow
        };
        f.render_widget(
            Paragraph::new(result.as_str())
                .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Result")),
            chunks[6],
        );
    }

    f.render_widget(
        Paragraph::new("Press [Tab/Arrows] to switch fields, [Enter] to verify.")
            .style(Style::default().fg(Color::DarkGray)),
        chunks[7],
    );
}

// --- Boot Sequence ---
async fn run_boot_sequence<B: Backend>(terminal: &mut Terminal<B>) -> io::Result<()> {
    let wolf_logo = r#"
                     ╔═══════════════════════════════════════╗
                     ║                                       ║
                     ║     ██╗    ██╗ ██████╗ ██╗     ███████╗║
                     ║     ██║    ██║██╔═══██╗██║     ██╔════╝║
                     ║     ██║ █╗ ██║██║   ██║██║     █████╗  ║
                     ║     ██║███╗██║██║   ██║██║     ██╔══╝  ║
                     ║     ╚███╔███╔╝╚██████╔╝███████╗██║     ║
                     ║      ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝     ║
                     ║                                       ║
                     ║     ██████╗ ██████╗  ██████╗ ██╗    ██╗║
                     ║     ██╔══██╗██╔══██╗██╔═══██╗██║    ██║║
                     ║     ██████╔╝██████╔╝██║   ██║██║ █╗ ██║║
                     ║     ██╔═══╝ ██╔══██╗██║   ██║██║███╗██║║
                     ║     ██║     ██║  ██║╚██████╔╝╚███╔███╔╝║
                     ║     ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ║
                     ║                                       ║
                     ║           🐺 CONTROL v2.0 🐺           ║
                     ╚═══════════════════════════════════════╝
    "#;

    let boot_messages = [
        ("[ INIT ]", "Initializing Wolf Control Interface...", 180),
        ("[ CORE ]", "Loading configuration...", 220),
        ("[ API  ]", "Connecting to Wolf Node API...", 250),
        ("[ SEC  ]", "Establishing secure session...", 200),
        ("[ SYNC ]", "Synchronizing pack hierarchy...", 230),
        ("[ PEERS]", "Discovering active peers...", 200),
        ("[ MESH ]", "Mapping network topology...", 220),
        ("[ CRYPT]", "Verifying encryption keys...", 200),
        ("[ DATA ]", "Hydrating metrics dashboard...", 180),
        ("[ READY]", "🐺 Wolf Control Online. Awaiting input.", 400),
    ];

    // Matrix rain characters
    let matrix_chars = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789";
    let matrix_vec: Vec<char> = matrix_chars.chars().collect();

    for (i, (_tag, _msg, delay_ms)) in boot_messages.iter().enumerate() {
        terminal.draw(|f| {
            let size = f.size();

            // Full black background
            let block = Block::default().style(Style::default().bg(Color::Black));
            f.render_widget(block, size);

            // Generate matrix rain effect on sides
            let mut matrix_lines: Vec<Line> = Vec::new();
            for row in 0..size.height {
                let mut spans = Vec::new();
                // Left matrix column
                for _ in 0..3 {
                    let ch = matrix_vec[(row as usize + i * 7) % matrix_vec.len()];
                    let brightness = if (row as usize + i) % 3 == 0 {
                        Color::Green
                    } else {
                        Color::DarkGray
                    };
                    spans.push(Span::styled(
                        ch.to_string(),
                        Style::default().fg(brightness),
                    ));
                }
                matrix_lines.push(Line::from(spans));
            }
            let left_matrix = Paragraph::new(matrix_lines.clone());
            f.render_widget(left_matrix, Rect::new(0, 0, 3, size.height));

            // Right matrix column
            let right_matrix = Paragraph::new(matrix_lines);
            f.render_widget(
                right_matrix,
                Rect::new(size.width.saturating_sub(3), 0, 3, size.height),
            );

            // Center area for content
            let area = centered_rect(75, 85, size);
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(
                    [
                        Constraint::Length(22), // Logo
                        Constraint::Min(10),    // Messages
                        Constraint::Length(3),  // Progress
                    ]
                    .as_ref(),
                )
                .split(area);

            // Wolf logo with green glow
            let logo = Paragraph::new(wolf_logo)
                .style(Style::default().fg(Color::Green))
                .alignment(ratatui::layout::Alignment::Center);
            f.render_widget(logo, chunks[0]);

            // Boot messages
            let mut lines: Vec<Line> = Vec::new();
            for j in 0..=i {
                let (t, m, _) = boot_messages[j];
                let tag_color = if j == i && j < boot_messages.len() - 1 {
                    Color::Yellow
                } else if t == "[ READY]" {
                    Color::Green
                } else {
                    Color::DarkGray
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{} ", t),
                        Style::default().fg(tag_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(m.to_string(), Style::default().fg(Color::White)),
                ]));
            }

            let messages = Paragraph::new(lines).style(Style::default()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(Span::styled(
                        " SYSTEM BOOT ",
                        Style::default().fg(Color::Cyan),
                    )),
            );
            f.render_widget(messages, chunks[1]);

            // Progress bar
            let progress = (i + 1) as f64 / boot_messages.len() as f64;
            let bar_width = (chunks[2].width as f64 * progress) as usize;
            let bar = format!(
                "[{}{}] {:.0}%",
                "█".repeat(bar_width.min(chunks[2].width as usize - 10)),
                "░".repeat((chunks[2].width as usize - 10).saturating_sub(bar_width)),
                progress * 100.0
            );
            let progress_widget = Paragraph::new(bar)
                .style(Style::default().fg(Color::Green))
                .alignment(ratatui::layout::Alignment::Center);
            f.render_widget(progress_widget, chunks[2]);
        })?;

        time::sleep(Duration::from_millis(*delay_ms as u64)).await;
    }

    // Final flash
    time::sleep(Duration::from_millis(300)).await;

    Ok(())
}
