use notify::{
    Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher,
};
use std::collections::HashSet;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

/// File system event types that the watcher can handle
#[derive(Debug, Clone)]
pub enum FileSystemEvent {
    /// A new file was created
    Created(String),
    /// An existing file was modified
    Modified(String),
    /// A file was deleted
    Deleted(String),
    /// An error occurred while watching
    Error(String),
}

/// Configuration for the file watcher
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Directory to watch for changes
    pub watch_dir: String,
    /// File pattern to filter events (e.g., "cmd_*")
    pub file_pattern: Option<String>,
    /// Whether to watch recursively
    pub recursive: bool,
    /// Debounce delay to avoid processing the same event multiple times
    pub debounce_delay_ms: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            watch_dir: ".".to_string(),
            file_pattern: None,
            recursive: false,
            debounce_delay_ms: 100,
        }
    }
}

/// Async file watcher that uses notify crate for real-time file system events
pub struct FileWatcher {
    /// Configuration for the watcher
    config: WatchConfig,
    /// Channel to send events to the main loop
    event_sender: UnboundedSender<FileSystemEvent>,
    /// Channel to send shutdown signal
    shutdown_sender: Arc<Mutex<Option<Sender<()>>>>,
    /// Internal state to track recent events for debouncing
    recent_events: Arc<Mutex<HashSet<String>>>,
}

impl FileWatcher {
    /// Create a new file watcher with the given configuration
    #[must_use]
    pub fn new(config: WatchConfig, event_sender: UnboundedSender<FileSystemEvent>) -> Self {
        Self {
            config,
            event_sender,
            shutdown_sender: Arc::new(Mutex::new(None)),
            recent_events: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Start the file watcher in a separate thread
    pub fn start(&self) -> NotifyResult<()> {
        // Channel for watcher events
        let (watch_tx, watch_rx) = channel();

        // Channel for shutdown signal
        let (shutdown_tx, shutdown_rx) = channel();

        let mut watcher: RecommendedWatcher = Watcher::new(watch_tx, Config::default())?;

        // Watch the directory
        let watch_path = Path::new(&self.config.watch_dir);
        if !watch_path.exists() {
            std::fs::create_dir_all(watch_path)?;
        }

        watcher.watch(
            watch_path,
            if self.config.recursive {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            },
        )?;

        // Store the shutdown sender
        {
            let mut shutdown_guard = self.shutdown_sender.lock().unwrap();
            *shutdown_guard = Some(shutdown_tx);
        }

        // Clone necessary values for the thread
        let config = self.config.clone();
        let event_sender = self.event_sender.clone();
        let recent_events = self.recent_events.clone();
        let runtime_handle = tokio::runtime::Handle::current();

        // Start the event processing thread
        std::thread::spawn(move || {
            Self::process_events(
                watcher,
                watch_rx,
                shutdown_rx,
                config,
                event_sender,
                recent_events,
                runtime_handle,
            );
        });

        Ok(())
    }

    /// Stop the file watcher
    pub fn stop(&self) {
        if let Some(shutdown_tx) = &*self.shutdown_sender.lock().unwrap() {
            let _ = shutdown_tx.send(());
        }
    }

    /// Process file system events in a loop
    fn process_events(
        mut _watcher: RecommendedWatcher,
        event_receiver: Receiver<NotifyResult<Event>>,
        shutdown_rx: Receiver<()>,
        config: WatchConfig,
        event_sender: UnboundedSender<FileSystemEvent>,
        recent_events: Arc<Mutex<HashSet<String>>>,
        runtime_handle: tokio::runtime::Handle,
    ) {
        loop {
            // Check for shutdown signal
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            // Process file system events
            match event_receiver.try_recv() {
                Ok(Ok(event)) => {
                    if let Err(e) = Self::handle_event(
                        event,
                        &config,
                        &event_sender,
                        &recent_events,
                        &runtime_handle,
                    ) {
                        tracing::info!("Error handling file system event: {e}");
                        let _ = event_sender.send(FileSystemEvent::Error(e.to_string()));
                    }
                }
                Ok(Err(e)) => {
                    tracing::info!("Watch error: {e:?}");
                }
                Err(TryRecvError::Empty) => {
                    // No events available, sleep briefly
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
    }

    /// Handle a single file system event
    fn handle_event(
        event: Event,
        config: &WatchConfig,
        event_sender: &UnboundedSender<FileSystemEvent>,
        recent_events: &Arc<Mutex<HashSet<String>>>,
        runtime_handle: &tokio::runtime::Handle,
    ) -> NotifyResult<()> {
        match event.kind {
            EventKind::Create(_) => {
                for path in event.paths {
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if Self::matches_pattern(file_name, &config.file_pattern) {
                            Self::send_event_with_debounce(
                                FileSystemEvent::Created(file_name.to_string()),
                                event_sender,
                                recent_events,
                                runtime_handle,
                            )?;
                        }
                    }
                }
            }
            EventKind::Modify(_) => {
                for path in event.paths {
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if Self::matches_pattern(file_name, &config.file_pattern) {
                            Self::send_event_with_debounce(
                                FileSystemEvent::Modified(file_name.to_string()),
                                event_sender,
                                recent_events,
                                runtime_handle,
                            )?;
                        }
                    }
                }
            }
            EventKind::Remove(_) => {
                for path in event.paths {
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if Self::matches_pattern(file_name, &config.file_pattern) {
                            Self::send_event_with_debounce(
                                FileSystemEvent::Deleted(file_name.to_string()),
                                event_sender,
                                recent_events,
                                runtime_handle,
                            )?;
                        }
                    }
                }
            }
            _ => {} // Ignore other event types
        }
        Ok(())
    }

    /// Check if a file name matches the configured pattern
    fn matches_pattern(file_name: &str, pattern: &Option<String>) -> bool {
        match pattern {
            Some(pattern) => file_name.starts_with(pattern),
            None => true,
        }
    }

    /// Send an event with debouncing to avoid duplicate events
    fn send_event_with_debounce(
        event: FileSystemEvent,
        event_sender: &UnboundedSender<FileSystemEvent>,
        recent_events: &Arc<Mutex<HashSet<String>>>,
        runtime_handle: &tokio::runtime::Handle,
    ) -> NotifyResult<()> {
        let mut recent_guard = recent_events.lock().unwrap();

        // Create a unique key for this event
        let event_key = match &event {
            FileSystemEvent::Created(name)
            | FileSystemEvent::Modified(name)
            | FileSystemEvent::Deleted(name) => {
                format!("{event:?}_{name}")
            }
            FileSystemEvent::Error(_) => return Ok(()), // Don't debounce errors
        };

        // Check if we've seen this event recently
        if !recent_guard.contains(&event_key) {
            // Add to recent events
            recent_guard.insert(event_key.clone());

            // Send the event
            if event_sender.send(event).is_err() {
                return Err(notify::Error::generic("Failed to send event"));
            }

            // Schedule removal of the event key after debounce delay
            let recent_events_clone = recent_events.clone();

            // Use runtime handle to spawn thecleanup task
            runtime_handle.spawn(async move {
                sleep(Duration::from_millis(1000)).await;
                let mut guard = recent_events_clone.lock().unwrap();
                guard.remove(&event_key);
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::sync::mpsc::{error::TryRecvError as TokioTryRecvError, unbounded_channel};

    #[tokio::test]
    async fn test_file_watcher_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = WatchConfig {
            watch_dir: temp_dir.path().to_string_lossy().to_string(),
            file_pattern: Some("test_".to_string()),
            recursive: false,
            debounce_delay_ms: 100,
        };

        let (event_sender, mut event_receiver) = unbounded_channel();
        let watcher = FileWatcher::new(config, event_sender);

        // Start the watcher
        assert!(watcher.start().is_ok());

        // Create a test file
        let test_file = temp_dir.path().join("test_file.txt");
        fs::write(&test_file, "test content").unwrap();

        // Wait for the event
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Check if we received the event
        let mut received = false;
        while let Ok(event) = event_receiver.try_recv() {
            match event {
                FileSystemEvent::Created(name) => {
                    if name == "test_file.txt" {
                        received = true;
                    }
                }
                _ => {}
            }
        }

        if !received {
            // Try waiting a bit more
            tokio::time::sleep(Duration::from_millis(500)).await;
            while let Ok(event) = event_receiver.try_recv() {
                if let FileSystemEvent::Created(name) = event {
                    if name == "test_file.txt" {
                        received = true;
                    }
                }
            }
        }

        assert!(
            received,
            "Expected to receive a Created event for test_file.txt"
        );

        // Stop the watcher
        watcher.stop();
    }

    #[tokio::test]
    async fn test_file_watcher_pattern_filtering() {
        let temp_dir = TempDir::new().unwrap();
        let config = WatchConfig {
            watch_dir: temp_dir.path().to_string_lossy().to_string(),
            file_pattern: Some("cmd_".to_string()),
            recursive: false,
            debounce_delay_ms: 100,
        };

        let (event_sender, mut event_receiver) = unbounded_channel();
        let watcher = FileWatcher::new(config, event_sender);

        // Start the watcher
        assert!(watcher.start().is_ok());

        // Create files that should and shouldn't match
        let matching_file = temp_dir.path().join("cmd_test.txt");
        let non_matching_file = temp_dir.path().join("other_test.txt");

        fs::write(&matching_file, "test content").unwrap();
        fs::write(&non_matching_file, "test content").unwrap();

        // Wait for events
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Should receive event for matching file
        let mut received_events = Vec::new();
        loop {
            match event_receiver.try_recv() {
                Ok(event) => received_events.push(event),
                Err(TokioTryRecvError::Empty) => break,
                Err(TokioTryRecvError::Disconnected) => break,
            }
        }

        // We expect at least one event (Created/Modified) for the matching file
        let found = received_events.iter().any(|e| match e {
            FileSystemEvent::Created(name) | FileSystemEvent::Modified(name) => {
                name == "cmd_test.txt"
            }
            _ => false,
        });

        assert!(found, "Expected to receive event for cmd_test.txt");

        // Should NOT receive event for non-matching file
        let found_other = received_events.iter().any(|e| match e {
            FileSystemEvent::Created(name) | FileSystemEvent::Modified(name) => {
                name == "other_test.txt"
            }
            _ => false,
        });

        assert!(!found_other, "Should not receive event for other_test.txt");

        // Stop the watcher
        watcher.stop();
    }
}
