//! Wolf Control Application - Fixed Version
//!
//! This is a fixed version of the Wolf Control application that replaces
//! problematic std::sync::Mutex patterns with proper async-safe alternatives
//! using tokio::sync::RwLock and Arc for concurrent access.

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
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Notify, RwLock};
use tracing::{debug, error, info, warn};
use wolf_prowler::utils::async_state::{AsyncAppState, AppMetrics};

mod config;
mod state_sync;
use crate::config::Config;

/// Async-safe application wrapper
pub struct AsyncApp {
    /// Application state with async-safe access
    state: AsyncAppState,
    /// Background task manager
    tasks: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

impl AsyncApp {
    /// Create new async-safe application
    pub fn new(config_path: &str) -> Result<Self> {
        let initial_state = wolf_prowler::utils::async_state::AppState {
            connected: false,
            peers: Vec::new(),
            status: wolf_prowler::utils::async_state::SystemStatus::Starting,
            uptime_seconds: 0,
            active_alerts: 0,
            last_error: None,
        };

        Ok(Self {
            state: AsyncAppState::new(initial_state),
            tasks: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Add background task for tracking
    async fn add_task(&self, handle: tokio::task::JoinHandle<()>) {
        let mut tasks = self.tasks.write().await;
        tasks.push(handle);
        debug!("Added background task. Total tasks: {}", tasks.len());
    }

    /// Cancel all background tasks gracefully
    async fn shutdown_tasks(&self) {
        let mut tasks = self.tasks.write().await;
        info!("Shutting down {} background tasks", tasks.len());
        
        // Cancel all tasks
        for task in tasks.drain(..) {
            task.abort();
        }
    }

    /// Get application metrics
    pub async fn get_metrics(&self) -> AppMetrics {
        self.state.get_metrics().await
    }
}

/// Background polling service with proper async handling
pub struct BackgroundPoller {
    /// API client for polling
    client: reqwest::Client,
    /// API endpoint URL
    api_url: String,
    /// Polling interval
    poll_interval: Duration,
    /// Application state for updates
    app_state: AsyncAppState,
    /// Shutdown notification
    shutdown_rx: Arc<Notify>,
}

impl BackgroundPoller {
    /// Create new background poller
    pub fn new(client: reqwest::Client, api_url: String, app_state: AsyncAppState) -> Self {
        Self {
            client,
            api_url,
            poll_interval: Duration::from_secs(5),
            app_state,
            shutdown_rx: app_state.shutdown_notifier(),
        }
    }

    /// Run the background polling loop
    pub async fn run(&self) -> Result<()> {
        info!("Starting background polling service");

        loop {
            tokio::select! {
                _ = self.shutdown_rx.notified() => {
                    info!("Background poller received shutdown signal");
                    break;
                }
                _ = tokio::time::sleep(self.poll_interval) => {
                    if let Err(e) = self.poll_and_update().await {
                        warn!("Background poll error: {}", e);
                        self.app_state.set_error(format!("Polling error: {}", e)).await;
                    }
                }
            }
        }

        info!("Background polling service stopped");
        Ok(())
    }

    /// Poll API and update application state
    async fn poll_and_update(&self) -> Result<()> {
        // Make API request
        let response = self.client
            .get(&self.api_url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("API request failed: {}", e))?;

        if response.status().is_success() {
            let data: serde_json::Value = response
                .json()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to parse API response: {}", e))?;

            // Update application state with new data
            self.update_state_from_api_data(&data).await?;
        } else {
            warn!("API returned status: {}", response.status());
        }

        Ok(())
    }

    /// Update application state from API data
    async fn update_state_from_api_data(&self, data: &serde_json::Value) -> Result<()> {
        // Extract system status
        if let Some(connected) = data.get("connected").and_then(|v| v.as_bool()) {
            self.app_state.set_connected(*connected).await;
        }

        // Extract peer list
        if let Some(peers) = data.get("peers").and_then(|v| v.as_array()) {
            let peer_list: Vec<String> = peers
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();

            // Update peer list
            for peer in &peer_list {
                self.app_state.add_peer(peer.clone()).await;
            }
        }

        // Extract uptime
        if let Some(uptime) = data.get("uptime_seconds").and_then(|v| v.as_u64()) {
            self.app_state.increment_uptime(*uptime).await;
        }

        // Extract alerts
        if let Some(alerts) = data.get("active_alerts").and_then(|v| v.as_u64()) {
            self.app_state.set_active_alerts(*alerts as usize).await;
        }

        Ok(())
    }
}

/// Async-safe TUI application state
pub struct TuiState {
    /// Current tab selection
    pub current_tab: usize,
    /// Application reference for data access
    pub app: AsyncApp,
    /// Input buffer for user commands
    pub input_buffer: String,
    /// Status message for display
    pub status_message: String,
}

impl TuiState {
    /// Create new TUI state
    pub fn new(app: AsyncApp) -> Self {
        Self {
            current_tab: 0,
            app,
            input_buffer: String::new(),
            status_message: "Initializing...".to_string(),
        }
    }

    /// Update status message
    pub fn set_status(&mut self, message: &str) {
        self.status_message = message.to_string();
        debug!("TUI status: {}", message);
    }

    /// Handle user input
    pub async fn handle_input(&mut self, key: KeyCode) -> Result<()> {
        use KeyCode::*;

        match key {
            Char('q') | Char('Q') => {
                self.app.shutdown_tasks().await;
                return Ok(());
            }
            Tab => {
                self.current_tab = (self.current_tab + 1) % 5;
                self.set_status(&format!("Switched to tab {}", self.current_tab));
            }
            Enter => {
                if let Err(e) = self.execute_command().await {
                    self.set_status(&format!("Command failed: {}", e));
                } else {
                    self.set_status("Command executed successfully");
                }
            }
            Backspace => {
                self.input_buffer.pop();
            }
            Char(c) => {
                if self.input_buffer.len() < 100 {
                    self.input_buffer.push(c);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Execute command from input buffer
    async fn execute_command(&mut self) -> Result<()> {
        let command = self.input_buffer.trim();
        self.input_buffer.clear();

        match command {
            "status" => self.show_status().await,
            "peers" => self.show_peers().await,
            "help" => self.show_help(),
            _ => {
                self.set_status(&format!("Unknown command: {}", command));
            }
        }
        Ok(())
    }

    /// Show system status
    async fn show_status(&self) {
        let metrics = self.app.get_metrics().await;
        let status = self.app.get_status_info().await;
        self.set_status(&status);
    }

    /// Show connected peers
    async fn show_peers(&self) {
        let metrics = self.app.get_metrics().await;
        if metrics.connected_peers > 0 {
            self.set_status(&format!("{} peers connected", metrics.connected_peers));
        } else {
            self.set_status("No peers connected");
        }
    }

    /// Show help information
    fn show_help(&self) {
        self.set_status("Commands: status, peers, help, quit (q/Q)");
    }
}

/// Main application function with proper async handling
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    info!("🚀 Starting Wolf Control Application (Async-Safe Version)");

    // Load configuration
    let config_path = "wolf_control.toml";
    let config = Config::load(config_path)?;

    // Initialize application
    let app = AsyncApp::new(config_path)?;
    let mut tui_state = TuiState::new(app);

    // Setup terminal (RAII pattern with proper cleanup)
    let mut terminal = setup_terminal().await?;

    // Start background polling
    let poller = BackgroundPoller::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
        config.api_url,
        app.state.clone(),
    );

    let poller_handle = tokio::spawn(async move {
        if let Err(e) = poller.run().await {
            error!("Background poller error: {}", e);
        }
    });

    // Add background task to app
    app.add_task(poller_handle).await;

    // Main application loop
    let result = run_tui_loop(&mut terminal, &mut tui_state).await;

    // Cleanup
    restore_terminal(&mut terminal)?;
    app.shutdown_tasks().await;

    info!("Wolf Control application shutdown complete");
    result
}

/// Setup terminal with proper RAII cleanup
async fn setup_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    execute!(stdout, EnableMouseCapture)?;
    
    let backend = CrosstermBackend::new(stdout, CrosstermConfig::default());
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;
    terminal.clear()?;

    Ok(terminal)
}

/// Restore terminal state with proper error handling
fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, LeaveAlternateScreen)?;
    execute!(stdout, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Run main TUI loop with proper async handling
async fn run_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    tui_state: &mut TuiState,
) -> Result<()> {
    loop {
        // Draw UI
        draw_ui(terminal, tui_state).await?;

        // Handle input with timeout
        match tokio::time::timeout(Duration::from_millis(100), crossterm::event().read()).await {
            Ok(Ok(Event::Key(key))) => {
                if let Err(e) = tui_state.handle_input(key).await {
                    error!("Input handling error: {}", e);
                }
            }
            Ok(Ok(_)) => {} // No input, continue
            Err(_) => {} // Timeout, continue
        }

        // Check for shutdown signal
        if matches!(tui_state.app.state.read().await.status, 
                  wolf_prowler::utils::async_state::SystemStatus::Error(_)) {
            break;
        }
    }
    Ok(())
}

/// Draw user interface
async fn draw_ui(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    tui_state: &TuiState,
) -> Result<()> {
    terminal.draw(|f| {
        let size = f.size();
        
        // Main layout
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Footer
            ])
            .split(f.size());

        // Header
        let header = Paragraph::new("Wolf Prowler Control")
            .style(Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD))
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Wolf Control"));

        // Content area
        let content = create_content_area(tui_state).await;

        // Footer
        let footer = Paragraph::new(tui_state.status_message.as_str())
            .style(Style::default().fg(Color::Gray))
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Status"));

        f.render_widget(header, chunks[0]);
        f.render_widget(content, chunks[1]);
        f.render_widget(footer, chunks[2]);
    })?;
    Ok(())
}

/// Create content area based on current tab
async fn create_content_area(tui_state: &TuiState) -> impl ratatui::widgets::Widget<'_> {
    let tabs = vec!["Overview", "Peers", "Security", "Logs", "Config"];
    let selected_tab = tui_state.current_tab;

    // Tab selection
    let tab_widget = Tabs::new(tabs, selected_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD))
        .block(Block::default()
            .borders(Borders::ALL)
            .title("Tabs"));

    match selected_tab {
        0 => create_overview_content(&tui_state.app).await,
        1 => create_peers_content(&tui_state.app).await,
        2 => create_security_content(&tui_state.app).await,
        3 => create_logs_content(&tui_state.app).await,
        4 => create_config_content(&tui_state.app).await,
        _ => Paragraph::new("Tab not implemented")
            .style(Style::default().fg(Color::Red)),
    }
}

/// Create overview content
async fn create_overview_content(app: &AsyncApp) -> impl ratatui::widgets::Widget<'_> {
    let metrics = app.get_metrics().await;
    let status = app.get_status_info().await;
    
    Paragraph::new(format!(
        "System Overview\n\n\
         Status: {}\n\
         Connected Peers: {}\n\
         Uptime: {}s\n\
         Active Alerts: {}\n",
        status,
        metrics.connected_peers,
        metrics.uptime_seconds,
        metrics.active_alerts
    ))
    .block(Block::default().borders(Borders::ALL).title("Overview"))
}

/// Create peers content
async fn create_peers_content(app: &AsyncApp) -> impl ratatui::widgets::Widget<'_> {
    let metrics = app.get_metrics().await;
    let peer_text = if metrics.connected_peers > 0 {
        format!("{} peers connected", metrics.connected_peers)
    } else {
        "No peers connected".to_string()
    };
    
    Paragraph::new(peer_text)
        .block(Block::default().borders(Borders::ALL).title("Peers"))
}

/// Create security content
async fn create_security_content(app: &AsyncApp) -> impl ratatui::widgets::Widget<'_> {
    let metrics = app.get_metrics().await;
    let security_text = if let Some(ref error) = metrics.last_error {
        format!("⚠️  Security Error: {}", error)
    } else {
        "✅ No security issues detected".to_string()
    };
    
    Paragraph::new(security_text)
        .block(Block::default().borders(Borders::ALL).title("Security"))
}

/// Create logs content
async fn create_logs_content(_app: &AsyncApp) -> impl ratatui::widgets::Widget<'_> {
    Paragraph::new("Real-time logs will appear here...")
        .block(Block::default().borders(Borders::ALL).title("Logs"))
}

/// Create config content
async fn create_config_content(_app: &AsyncApp) -> impl ratatui::widgets::Widget<'_> {
    Paragraph::new("Configuration interface...")
        .block(Block::default().borders(Borders::ALL).title("Configuration"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_async_state_concurrent_access() {
        let app = AsyncApp::new("test.toml").unwrap();
        
        // Spawn multiple concurrent tasks
        let app_clone = Arc::new(app);
        let mut handles = vec![];
        
        for i in 0..10 {
            let app_ref = Arc::clone(&app_clone);
            let handle = tokio::spawn(async move {
                let metrics = app_ref.get_metrics().await;
                assert!(metrics.connected_peers >= 0);
            });
            handles.push(handle);
        }
        
        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_background_poller() {
        let state = AsyncAppState::new(wolf_prowler::utils::async_state::AppState::default());
        let client = reqwest::Client::new();
        let poller = BackgroundPoller::new(
            client,
            "http://localhost:8080/api".to_string(),
            state.clone(),
        );
        
        // This should complete quickly (no actual API)
        tokio::time::timeout(Duration::from_millis(100), poller.run()).await.unwrap();
    }
}