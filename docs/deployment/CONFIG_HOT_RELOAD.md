# Configuration Hot Reload Documentation

## 🎯 **Overview**

The Configuration Hot Reload feature enables zero-downtime configuration updates for Wolf Prowler. This allows administrators to modify application configuration without requiring a full restart, making it ideal for production environments where uptime is critical.

## 🚀 **Features**

### **Core Capabilities**
- **File System Monitoring**: Real-time watching of configuration files
- **Change Detection**: Intelligent detection of specific configuration changes
- **Callback System**: Event-driven notifications for configuration updates
- **Debouncing**: Prevents excessive reloads from rapid file changes
- **Type Safety**: Strongly typed change notifications
- **Async Support**: Fully async/await compatible API

### **Supported Configuration Changes**
- **Web Server**: Port changes, server settings
- **P2P Network**: Peer limits, discovery intervals, heartbeat settings
- **Application**: Node name, logging levels, feature flags
- **Crypto**: Algorithm settings, security levels (requires restart for full effect)
- **Full Reload**: Complete configuration replacement

## 📋 **Usage Examples**

### **Basic Setup**
```rust
use wolf_prowler::{ConfigManager, ConfigChange};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create config manager
    let mut config_manager = ConfigManager::new("config.toml")?;
    
    // Enable hot reload
    config_manager.enable_hot_reload().await?;
    
    // Application continues running...
    Ok(())
}
```

### **Advanced Setup with Callbacks**
```rust
use wolf_prowler::{ConfigManager, ConfigChange, ConfigChangeCallback};
use std::sync::Arc;

async fn setup_callbacks(config_manager: &ConfigManager) {
    // Web server callback
    let web_callback: ConfigChangeCallback = Arc::new(|change| {
        match change {
            ConfigChange::WebServer { old_port, new_port } => {
                println!("Web port changed: {} → {}", old_port, new_port);
                // Restart web server on new port
            }
            _ => {}
        }
    });
    
    config_manager.add_callback(web_callback).await;
}
```

### **Programmatic Configuration Updates**
```rust
// Update configuration programmatically
config_manager.update_config(|config| {
    config.web_port = 9090;
    config.max_peers = 100;
    config.log_level = "debug".to_string();
}).await?;
```

## 🔧 **API Reference**

### **ConfigManager**
```rust
pub struct ConfigManager {
    // Internal fields
}

impl ConfigManager {
    /// Create a new config manager
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, io::Error>;
    
    /// Get current configuration
    pub async fn get_config(&self) -> Config;
    
    /// Update configuration programmatically
    pub async fn update_config<F>(&self, updater: F) -> Result<bool, io::Error>
    where F: FnOnce(&mut Config);
    
    /// Add configuration change callback
    pub async fn add_callback(&self, callback: ConfigChangeCallback);
    
    /// Enable hot reload functionality
    pub async fn enable_hot_reload(&mut self) -> Result<(), io::Error>;
    
    /// Disable hot reload functionality
    pub async fn disable_hot_reload(&mut self) -> Result<(), io::Error>;
    
    /// Check if hot reload is enabled
    pub fn is_hot_reload_enabled(&self) -> bool;
    
    /// Get configuration file path
    pub fn config_path(&self) -> &PathBuf;
    
    /// Save current configuration to file
    pub async fn save_config(&self) -> Result<(), io::Error>;
}
```

### **ConfigChange Enum**
```rust
#[derive(Debug, Clone)]
pub enum ConfigChange {
    /// Web server configuration changed
    WebServer { old_port: u16, new_port: u16 },
    
    /// P2P network configuration changed
    P2PNetwork { field: String, old_value: String, new_value: String },
    
    /// Application configuration changed
    Application { field: String, old_value: String, new_value: String },
    
    /// Crypto configuration changed
    Crypto { field: String, old_value: String, new_value: String },
    
    /// Full configuration reload
    FullReload { old_config: Config, new_config: Config },
}
```

### **ConfigChangeCallback Type**
```rust
pub type ConfigChangeCallback = Arc<dyn Fn(ConfigChange) + Send + Sync>;
```

## 📁 **Configuration File Format**

The hot reload system works with standard TOML configuration files:

```toml
# Wolf Prowler Configuration
web_port = 8080
p2p_port = 0
max_peers = 50
discovery_interval_secs = 30
heartbeat_interval_secs = 10

node_name = "wolf-node-12345"
enable_logging = true
log_level = "info"

save_state = true
state_file = "wolf_prowler_state.json"

[crypto]
enable_metrics = true
enable_audit_logging = true
performance_optimization = true
cipher_suite = "ChaCha20Poly1305"
hash_function = "Blake3"
security_level = "Maximum"
memory_protection = "Strict"
```

## 🔄 **Implementation Details**

### **File System Watching**
- Uses the `notify` crate for cross-platform file system monitoring
- Watches the directory containing the configuration file
- Non-recursive watching to prevent performance issues
- Automatic error handling and logging

### **Change Detection**
- Compares old and new configuration values
- Detects specific field changes for targeted callbacks
- Falls back to full reload for complex changes
- Debounced to prevent excessive reloads (500ms delay)

### **Callback System**
- Multiple callbacks can be registered
- All callbacks are executed for each detected change
- Callbacks are executed in the order they were added
- Errors in callbacks don't affect other callbacks

### **Thread Safety**
- Uses `Arc<RwLock<Config>>` for thread-safe configuration access
- Callbacks are protected by `Arc<Mutex<Vec<Callback>>>`
- File system events are handled in background tasks
- All operations are async-friendly

## 🧪 **Testing**

### **Unit Tests**
```bash
# Run all config tests
cargo test config::tests

# Run specific hot reload tests
cargo test test_hot_reload_enable_disable
cargo test test_hot_reload_file_change
```

### **Integration Tests**
```bash
# Run the example
cargo run --example config_hot_reload

# Test with manual file editing
# 1. Start the example
cargo run --example config_hot_reload

# 2. Edit the config file in another terminal
vim example_config.toml

# 3. Observe the hot reload notifications
```

## ⚠️ **Best Practices**

### **Production Usage**
1. **Validate Configuration**: Always validate configuration before applying
2. **Graceful Degradation**: Handle configuration errors gracefully
3. **Logging**: Log all configuration changes for audit trails
4. **Security**: Restrict file permissions on configuration files
5. **Backup**: Keep configuration backups for rollback

### **Performance Considerations**
1. **Debouncing**: The system includes automatic debouncing
2. **Callback Efficiency**: Keep callbacks fast and non-blocking
3. **File Size**: Keep configuration files reasonably small
4. **Watch Paths**: Only watch necessary directories

### **Error Handling**
```rust
match config_manager.enable_hot_reload().await {
    Ok(()) => info!("Hot reload enabled"),
    Err(e) => {
        error!("Failed to enable hot reload: {}", e);
        // Continue without hot reload or exit gracefully
    }
}
```

## 🔍 **Troubleshooting**

### **Common Issues**

#### **Hot Reload Not Working**
- **Check File Permissions**: Ensure the application can read the config file
- **Verify Path**: Make sure the config path is correct
- **File System Events**: Some file systems don't support all events
- **Debouncing**: Changes may be delayed due to debouncing

#### **Excessive Reloads**
- **File Editors**: Some editors create temporary files causing multiple events
- **Sync Tools**: Cloud sync tools can cause frequent changes
- **Solution**: Increase debounce delay or use atomic file writes

#### **Callback Errors**
- **Panics**: Callback panics are caught and logged
- **Blocking Operations**: Avoid blocking operations in callbacks
- **Resource Leaks**: Clean up resources properly in callbacks

### **Debug Logging**
Enable debug logging to troubleshoot issues:
```rust
// In your application setup
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

## 🚀 **Future Enhancements**

### **Planned Features**
1. **Remote Configuration**: Support for remote config sources
2. **Configuration Templates**: Template-based configuration generation
3. **Validation Rules**: Custom validation rules for configuration
4. **Rollback Support**: Automatic rollback on invalid configurations
5. **Metrics Integration**: Configuration change metrics and monitoring

### **Performance Improvements**
1. **Incremental Parsing**: Only parse changed sections
2. **Memory Optimization**: Reduce memory usage for large configs
3. **Batch Updates**: Group multiple changes together
4. **Caching**: Cache frequently accessed configuration values

## 📚 **Examples**

See the `examples/config_hot_reload.rs` file for a complete working example that demonstrates:
- Setting up the ConfigManager
- Registering callbacks for different change types
- Handling configuration changes gracefully
- Error handling and logging

## 🎉 **Summary**

The Configuration Hot Reload feature provides a robust, production-ready solution for zero-downtime configuration updates. With its comprehensive callback system, intelligent change detection, and strong type safety, it enables seamless configuration management in production environments.

**Key Benefits:**
- ✅ **Zero Downtime**: No restarts required for most configuration changes
- ✅ **Type Safe**: Strongly typed change notifications prevent errors
- ✅ **Flexible**: Extensible callback system for custom handling
- ✅ **Reliable**: Comprehensive error handling and logging
- ✅ **Performant**: Efficient file system monitoring and debouncing
